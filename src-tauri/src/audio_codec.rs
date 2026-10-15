use rusty_opus::{Application, OpusDecoder, OpusEncoder, repacketizer::samples_per_frame};
use std::collections::HashMap;
use std::sync::Mutex;

const SAMPLE_RATE: u32 = 48_000;
const FRAME_SAMPLES: usize = 960;
const SILENCE_FADE_SAMPLES: usize = SAMPLE_RATE as usize / 200;
const MAX_PACKET_BYTES: usize = 1276;
const MAX_SESSIONS: usize = 4;

struct CodecSession {
    encoder: OpusEncoder,
    decoder: OpusDecoder,
    silent: bool,
    last_output_sample: f32,
}

pub struct AudioCodecState {
    sessions: Mutex<HashMap<String, CodecSession>>,
}

impl AudioCodecState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn start(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        let mut encoder = OpusEncoder::new(SAMPLE_RATE as i32, 1, Application::RestrictedLowDelay)
            .map_err(|_| "failed to initialize Opus encoder".to_string())?;
        encoder.bitrate_bps = 48_000;
        encoder.complexity = 10;
        encoder.use_cbr = false;
        encoder.use_dtx = false;
        encoder.packet_loss_perc = 10;
        let decoder = OpusDecoder::new(SAMPLE_RATE as i32, 1)
            .map_err(|_| "failed to initialize Opus decoder".to_string())?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "audio codec unavailable".to_string())?;
        if !sessions.contains_key(session_id) && sessions.len() >= MAX_SESSIONS {
            return Err("audio codec session limit reached".to_string());
        }
        sessions.insert(
            session_id.to_string(),
            CodecSession {
                encoder,
                decoder,
                silent: false,
                last_output_sample: 0.0,
            },
        );
        Ok(())
    }

    pub fn stop(&self, session_id: &str) -> Result<(), String> {
        validate_session_id(session_id)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| "audio codec unavailable".to_string())?;
        sessions.remove(session_id);
        Ok(())
    }

    pub fn encode(&self, session_id: &str, input: &[u8]) -> Result<Vec<u8>, String> {
        validate_session_id(session_id)?;
        if input.len() != FRAME_SAMPLES * std::mem::size_of::<f32>() {
            return Err("invalid Opus PCM frame".to_string());
        }
        let mut pcm = vec![0.0f32; FRAME_SAMPLES];
        for (sample, bytes) in pcm.iter_mut().zip(input.chunks_exact(4)) {
            *sample = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if !sample.is_finite() {
                pcm.fill(0.0);
                return Err("invalid Opus PCM sample".to_string());
            }
            *sample = sample.clamp(-1.0, 1.0);
        }
        let mut packet = vec![0u8; MAX_PACKET_BYTES];
        let result = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "audio codec unavailable".to_string())?;
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| "audio codec session unavailable".to_string())?;
            session
                .encoder
                .encode(&pcm, FRAME_SAMPLES, &mut packet)
                .map_err(|_| "Opus encoding failed".to_string())
        };
        pcm.fill(0.0);
        let encoded = result?;
        if encoded == 0 || encoded > MAX_PACKET_BYTES {
            packet.fill(0);
            return Err("invalid Opus packet length".to_string());
        }
        packet.truncate(encoded);
        Ok(packet)
    }

    pub fn decode(&self, session_id: &str, packet: &[u8], fec: bool) -> Result<Vec<u8>, String> {
        validate_session_id(session_id)?;
        if packet.len() > MAX_PACKET_BYTES || (fec && packet.is_empty()) {
            return Err("invalid Opus packet".to_string());
        }
        if !packet.is_empty()
            && packet.len() <= 2
            && (packet[0] & 7 != 0
                || samples_per_frame(packet[0], SAMPLE_RATE as i32) != FRAME_SAMPLES as i32)
        {
            return Err("invalid Opus silence frame".to_string());
        }
        let mut pcm = vec![0.0f32; FRAME_SAMPLES];
        let decoded = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "audio codec unavailable".to_string())?;
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| "audio codec session unavailable".to_string())?;
            let decoded = if fec && packet.len() > 2 {
                session
                    .decoder
                    .decode_fec(packet, FRAME_SAMPLES, &mut pcm)
                    .map_err(|_| "Opus FEC decoding failed".to_string())?
            } else {
                session
                    .decoder
                    .decode(
                        if packet.len() <= 2 { &[] } else { packet },
                        FRAME_SAMPLES,
                        &mut pcm,
                    )
                    .map_err(|_| "Opus decoding failed".to_string())?
            };
            if decoded == 0 || decoded > FRAME_SAMPLES {
                pcm.fill(0.0);
                return Err("invalid decoded Opus frame".to_string());
            }
            let explicit_silence = !fec && !packet.is_empty() && packet.len() <= 2;
            if explicit_silence {
                let last = if session.silent {
                    0.0
                } else {
                    session.last_output_sample
                };
                for (index, sample) in pcm.iter_mut().take(decoded).enumerate() {
                    *sample =
                        last * (1.0 - (index + 1) as f32 / SILENCE_FADE_SAMPLES as f32).max(0.0);
                }
                session.silent = true;
            } else if !fec && !packet.is_empty() {
                session.silent = false;
            } else if session.silent {
                pcm.fill(0.0);
            }
            let last = pcm[decoded - 1];
            session.last_output_sample = if last.is_finite() {
                last.clamp(-1.0, 1.0)
            } else {
                0.0
            };
            decoded
        };
        pcm.truncate(decoded);
        let mut output = Vec::with_capacity(pcm.len() * 4);
        for sample in &mut pcm {
            if !sample.is_finite() {
                *sample = 0.0;
            }
            *sample = sample.clamp(-1.0, 1.0);
            output.extend_from_slice(&sample.to_le_bytes());
        }
        pcm.fill(0.0);
        Ok(output)
    }
}

impl Default for AudioCodecState {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if (16..=64).contains(&session_id.len())
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid audio codec session".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{AudioCodecState, FRAME_SAMPLES};
    use rusty_opus::OpusDecoder;

    fn pcm_bytes(phase: f32) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_SAMPLES * 4);
        for index in 0..FRAME_SAMPLES {
            let sample = ((index as f32 * 0.06) + phase).sin() * 0.2;
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        bytes
    }

    fn silence_bytes() -> Vec<u8> {
        vec![0; FRAME_SAMPLES * 4]
    }

    fn voice_samples(frame: usize) -> Vec<f32> {
        (0..FRAME_SAMPLES)
            .map(|index| {
                let n = frame * FRAME_SAMPLES + index;
                let t = n as f32 / 48_000.0;
                let phase = std::f32::consts::TAU * 125.0 * t + 0.5 * (t * 7.0).sin();
                let voiced = phase.sin() * 0.08
                    + (phase * 2.0).sin() * 0.04
                    + (phase * 3.0).sin() * 0.025
                    + (phase * 5.0).sin() * 0.02
                    + (phase * 9.0).sin() * 0.015
                    + (phase * 15.0).sin() * 0.01
                    + (phase * 32.0).sin() * 0.005;
                let hash = (n as u32).wrapping_mul(747796405).wrapping_add(2891336453);
                let noise = ((hash ^ (hash >> 16)) as f64 / u32::MAX as f64 * 2.0 - 1.0) as f32;
                voiced * (0.7 + 0.3 * (t * 11.0).sin()) + noise * 0.004
            })
            .collect()
    }

    fn voice_error_db(reference: &[f32], decoded: &[f32]) -> f64 {
        let start = FRAME_SAMPLES * 10;
        let end = reference.len() - FRAME_SAMPLES;
        let lag = (0..=480)
            .min_by(|left, right| {
                let error = |lag: usize| {
                    (start..end)
                        .step_by(16)
                        .map(|i| (f64::from(reference[i]) - f64::from(decoded[i + lag])).powi(2))
                        .sum::<f64>()
                };
                error(*left).total_cmp(&error(*right))
            })
            .unwrap();
        let signal = reference[start..end]
            .iter()
            .map(|value| f64::from(*value).powi(2))
            .sum::<f64>();
        let noise = (start..end)
            .map(|i| (f64::from(reference[i]) - f64::from(decoded[i + lag])).powi(2))
            .sum::<f64>();
        10.0 * (signal / noise).log10()
    }

    #[test]
    fn opus_session_encodes_decodes_and_conceals_twenty_ms_frames() {
        let state = AudioCodecState::new();
        let session = "0123456789abcdef0123456789abcdef";
        state.start(session).unwrap();
        let first = state.encode(session, &pcm_bytes(0.0)).unwrap();
        let second = state.encode(session, &pcm_bytes(0.3)).unwrap();
        assert!(first.len() <= 1276);
        assert!(second.len() <= 1276);
        assert_eq!(
            state.decode(session, &first, false).unwrap().len(),
            FRAME_SAMPLES * 4
        );
        assert_eq!(
            state.decode(session, &second, true).unwrap().len(),
            FRAME_SAMPLES * 4
        );
        assert_eq!(
            state.decode(session, &[], false).unwrap().len(),
            FRAME_SAMPLES * 4
        );
        state.stop(session).unwrap();
        assert!(state.encode(session, &pcm_bytes(0.0)).is_err());
    }

    #[test]
    fn silence_is_encoded_continuously_without_activity_based_suppression() {
        let state = AudioCodecState::new();
        let session = "fedcba9876543210fedcba9876543210";
        state.start(session).unwrap();
        for _ in 0..100 {
            let packet = state.encode(session, &silence_bytes()).unwrap();
            assert!(packet.len() > 2);
            state.decode(session, &packet, false).unwrap();
        }
    }

    #[test]
    fn toc_only_silence_advances_decoder_history_without_playing_comfort_noise() {
        let state = AudioCodecState::new();
        let sender = "00112233445566778899aabbccddeeff";
        let reference = "ffeeddccbbaa99887766554433221100";
        state.start(sender).unwrap();
        state.start(reference).unwrap();
        for frame in 0..50 {
            let packet = state
                .encode(sender, &pcm_bytes(frame as f32 * 57.6))
                .unwrap();
            state.decode(sender, &packet, false).unwrap();
            state.decode(reference, &packet, false).unwrap();
        }
        let mut checked = 0;
        for _ in 0..3 {
            for frame in 0..150 {
                let actual = state.decode(sender, &[0xf8], false).unwrap();
                state.decode(reference, &[], false).unwrap();
                let start = if frame == 0 { 240 } else { 0 };
                assert!(
                    actual.chunks_exact(4).skip(start).all(|bytes| {
                        f32::from_le_bytes(bytes.try_into().unwrap()).abs() < 1e-7
                    }),
                    "TOC-only silence must not play synthesized comfort noise"
                );
                checked += 1;
            }
            for frame in 0..25 {
                let packet = state
                    .encode(sender, &pcm_bytes(frame as f32 * 57.6))
                    .unwrap();
                let actual = state.decode(sender, &packet, false).unwrap();
                let expected = state.decode(reference, &packet, false).unwrap();
                assert!(
                    actual == expected,
                    "speech must resume from the correct decoder history after silence"
                );
            }
        }
        assert!(checked > 150);
    }

    #[test]
    fn resumed_speech_does_not_produce_amplitude_spikes() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        for frame in 0..50 {
            let packet = state
                .encode(session, &pcm_bytes(frame as f32 * 57.6))
                .unwrap();
            let output = state.decode(session, &packet, false).unwrap();
            assert!(
                packet[0] & 0x80 != 0,
                "call audio must remain in the CELT profile"
            );
            assert!(
                output
                    .chunks_exact(4)
                    .all(|bytes| f32::from_le_bytes(bytes.try_into().unwrap()).abs() < 0.6),
                "test speech must not produce full-scale codec spikes"
            );
        }
        for _ in 0..3 {
            for _ in 0..150 {
                let packet = state.encode(session, &silence_bytes()).unwrap();
                let output = state.decode(session, &packet, false).unwrap();
                assert!(
                    output.chunks_exact(4).all(|bytes| f32::from_le_bytes(
                        bytes.try_into().unwrap()
                    )
                    .abs()
                        < 0.6),
                    "test silence must not produce codec spikes"
                );
            }
            for frame in 0..25 {
                let packet = state
                    .encode(session, &pcm_bytes(frame as f32 * 57.6))
                    .unwrap();
                let output = state.decode(session, &packet, false).unwrap();
                assert!(
                    packet[0] & 0x80 != 0,
                    "resuming speech must not switch codec profiles"
                );
                assert!(
                    output.chunks_exact(4).all(|bytes| f32::from_le_bytes(
                        bytes.try_into().unwrap()
                    )
                    .abs()
                        < 0.6),
                    "resumed test speech must not produce amplitude spikes"
                );
            }
        }
    }

    #[test]
    fn short_frames_distinguish_received_silence_from_missing_speech() {
        for packet in [vec![0x48], vec![0x48, 0]] {
            for fec in [false, true] {
                let state = AudioCodecState::new();
                let actual = "0123456789abcdef0123456789abcdef";
                let reference = "fedcba9876543210fedcba9876543210";
                state.start(actual).unwrap();
                state.start(reference).unwrap();
                for frame in 0..50 {
                    let packet = state
                        .encode(actual, &pcm_bytes(frame as f32 * 57.6))
                        .unwrap();
                    state.decode(actual, &packet, false).unwrap();
                    state.decode(reference, &packet, false).unwrap();
                }
                let output = state.decode(actual, &packet, fec).unwrap();
                let expected = state.decode(reference, &[], false).unwrap();
                if fec {
                    assert_eq!(output, expected);
                } else {
                    assert!(
                        output
                            .chunks_exact(4)
                            .skip(240)
                            .all(|bytes| { f32::from_le_bytes(bytes.try_into().unwrap()) == 0.0 })
                    );
                }
                let resumed = state.encode(actual, &pcm_bytes(1.0)).unwrap();
                assert_eq!(
                    state.decode(actual, &resumed, false).unwrap(),
                    state.decode(reference, &resumed, false).unwrap(),
                );
            }
        }
    }

    #[test]
    fn short_frames_reject_wrong_channels_duration_and_framing() {
        let state = AudioCodecState::new();
        let session = "0123456789abcdef0123456789abcdef";
        state.start(session).unwrap();
        for toc in 0u8..=255 {
            let valid = [0x08, 0x28, 0x48, 0x68, 0x78, 0x98, 0xb8, 0xd8, 0xf8].contains(&toc);
            for packet in [vec![toc], vec![toc, 0]] {
                assert_eq!(state.decode(session, &packet, false).is_ok(), valid);
            }
        }
    }

    #[test]
    fn explicit_silence_does_not_replay_the_end_of_a_sound() {
        for kind in 0..2 {
            let state = AudioCodecState::new();
            let session = "00112233445566778899aabbccddeeff";
            state.start(session).unwrap();
            for frame in 0..50 {
                let pcm = if kind == 0 {
                    pcm_bytes(frame as f32 * 57.6)
                } else {
                    voice_samples(frame)
                        .iter()
                        .flat_map(|sample| sample.to_le_bytes())
                        .collect()
                };
                let packet = state.encode(session, &pcm).unwrap();
                state.decode(session, &packet, false).unwrap();
            }
            for frame in 0..10 {
                let output = state.decode(session, &[0xf8], false).unwrap();
                let start = if frame == 0 { 240 } else { 0 };
                let tail = output
                    .chunks_exact(4)
                    .skip(start)
                    .map(|bytes| f32::from_le_bytes(bytes.try_into().unwrap()).abs())
                    .fold(0.0f32, f32::max);
                assert!(
                    tail < 1e-7,
                    "explicit silence must stop synthesized sound after 5 ms; kind={kind}, frame={frame}, peak={tail}"
                );
            }
        }
    }

    #[test]
    fn real_packet_loss_still_conceals_speech_instead_of_muting_it() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        for frame in 0..50 {
            let packet = state
                .encode(session, &pcm_bytes(frame as f32 * 57.6))
                .unwrap();
            state.decode(session, &packet, false).unwrap();
        }
        let output = state.decode(session, &[], false).unwrap();
        let energy = output
            .chunks_exact(4)
            .map(|bytes| f64::from(f32::from_le_bytes(bytes.try_into().unwrap())).powi(2))
            .sum::<f64>();
        assert!(energy / FRAME_SAMPLES as f64 > 0.001);
    }

    #[test]
    fn loss_during_explicit_silence_cannot_restart_synthesized_speech() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        for frame in 0..50 {
            let packet = state
                .encode(session, &pcm_bytes(frame as f32 * 57.6))
                .unwrap();
            state.decode(session, &packet, false).unwrap();
        }
        state.decode(session, &[0xf8], false).unwrap();
        for (packet, fec) in [(&[][..], false), (&[0xf8][..], true)] {
            let output = state.decode(session, packet, fec).unwrap();
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn explicit_silence_ramps_continuously_from_the_last_played_sample() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        let mut last = 0.0;
        for frame in 0..50 {
            let packet = state
                .encode(session, &pcm_bytes(frame as f32 * 57.6))
                .unwrap();
            let output = state.decode(session, &packet, false).unwrap();
            last = f32::from_le_bytes(output[output.len() - 4..].try_into().unwrap());
        }
        assert!(last.abs() > 0.01);
        let output = state.decode(session, &[0xf8], false).unwrap();
        let samples = output
            .chunks_exact(4)
            .map(|bytes| f32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!((samples[0] - last * (239.0 / 240.0)).abs() < 1e-7);
        assert!(
            samples
                .windows(2)
                .all(|pair| { (pair[1] - pair[0]).abs() <= last.abs() / 240.0 + 1e-7 })
        );
        assert!(samples[239..].iter().all(|sample| *sample == 0.0));
    }

    #[test]
    fn digital_silence_does_not_generate_audible_codec_noise() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        for frame in 0..50 {
            let packet = state
                .encode(session, &pcm_bytes(frame as f32 * 57.6))
                .unwrap();
            state.decode(session, &packet, false).unwrap();
        }
        for frame in 0..250 {
            let packet = state.encode(session, &silence_bytes()).unwrap();
            let output = state.decode(session, &packet, false).unwrap();
            if frame >= 5 {
                assert!(
                    output.chunks_exact(4).all(|bytes| f32::from_le_bytes(
                        bytes.try_into().unwrap()
                    )
                    .abs()
                        < 1e-7),
                    "digital silence must not generate audible synthesized audio"
                );
            }
        }
    }

    #[test]
    fn configured_voice_fidelity_matches_the_higher_quality_profile() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        let mut input = Vec::new();
        let mut output = Vec::new();
        for frame in 0..100 {
            let samples = voice_samples(frame);
            let pcm = samples
                .iter()
                .flat_map(|sample| sample.to_le_bytes())
                .collect::<Vec<_>>();
            let packet = state.encode(session, &pcm).unwrap();
            let decoded = state.decode(session, &packet, false).unwrap();
            input.extend(samples);
            output.extend(
                decoded
                    .chunks_exact(4)
                    .map(|sample| f32::from_le_bytes(sample.try_into().unwrap())),
            );
        }
        let fidelity = voice_error_db(&input, &output);
        assert!(
            fidelity >= 20.0,
            "configured voice fidelity must reach 20 dB SNR; measured {fidelity}"
        );
    }

    #[test]
    fn ongoing_microphone_audio_does_not_enter_silence_at_changing_volume() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        let gains = [1.0, 0.3, 0.05, 0.003, 0.001, 2.0];
        for frame in 0..600 {
            let gain = gains[(frame / 25) % gains.len()];
            let pcm = voice_samples(frame)
                .iter()
                .flat_map(|sample| (sample * gain).to_le_bytes())
                .collect::<Vec<_>>();
            let packet = state.encode(session, &pcm).unwrap();
            assert!(
                packet.len() > 2,
                "ongoing microphone audio must not be classified as silence; frame={frame}, gain={gain}"
            );
            let decoded = state.decode(session, &packet, false).unwrap();
            let samples = decoded
                .chunks_exact(4)
                .map(|bytes| f32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            assert!(samples.iter().any(|sample| sample.abs() > 1e-7));
            assert!(samples.iter().all(|sample| sample.abs() < 0.6));
        }
    }

    #[test]
    fn silence_handling_leaves_all_coded_microphone_audio_unchanged() {
        for explicit_pause in [false, true] {
            for kind in 0..3 {
                let state = AudioCodecState::new();
                let session = "00112233445566778899aabbccddeeff";
                state.start(session).unwrap();
                let mut reference = OpusDecoder::new(48_000, 1).unwrap();
                let mut silent_frames = 0;
                let mut coded_frames = 0;
                for frame in 0..450 {
                    let position = frame % 150;
                    let pause = (55..80).contains(&position) || (120..123).contains(&position);
                    let pcm = if pause {
                        silence_bytes()
                    } else if kind == 0 {
                        pcm_bytes(frame as f32 * 57.6)
                    } else {
                        let gain = if kind == 1 { 1.0 } else { 0.001 };
                        voice_samples(frame)
                            .iter()
                            .flat_map(|sample| (sample * gain).to_le_bytes())
                            .collect()
                    };
                    let packet = if explicit_pause && pause {
                        vec![0xf8]
                    } else {
                        state.encode(session, &pcm).unwrap()
                    };
                    let actual = state.decode(session, &packet, false).unwrap();
                    let mut expected = [0.0; FRAME_SAMPLES];
                    reference
                        .decode(
                            if packet.len() <= 2 { &[] } else { &packet },
                            FRAME_SAMPLES,
                            &mut expected,
                        )
                        .unwrap();
                    if packet.len() > 2 {
                        let expected = expected
                            .iter()
                            .flat_map(|sample| sample.clamp(-1.0, 1.0).to_le_bytes())
                            .collect::<Vec<_>>();
                        assert_eq!(
                            actual, expected,
                            "coded microphone audio must remain byte-for-byte unchanged, including immediately after pauses; kind={kind}, frame={frame}"
                        );
                        coded_frames += 1;
                    } else {
                        assert!(pause, "active microphone audio cannot enter silence");
                        silent_frames += 1;
                    }
                }
                if explicit_pause {
                    assert!(silent_frames > 10);
                } else {
                    assert_eq!(silent_frames, 0);
                }
                assert!(coded_frames > 300);
            }
        }
    }

    #[test]
    fn quiet_speech_keeps_its_detail_without_being_gated_to_silence() {
        let state = AudioCodecState::new();
        let session = "00112233445566778899aabbccddeeff";
        state.start(session).unwrap();
        let mut input = Vec::new();
        let mut output = Vec::new();
        for frame in 0..100 {
            let samples = voice_samples(frame)
                .into_iter()
                .map(|sample| sample * 0.001)
                .collect::<Vec<_>>();
            let pcm = samples
                .iter()
                .flat_map(|sample| sample.to_le_bytes())
                .collect::<Vec<_>>();
            let packet = state.encode(session, &pcm).unwrap();
            assert!(
                packet.len() > 2,
                "quiet speech must not become a synthesized silence packet"
            );
            let decoded = state.decode(session, &packet, false).unwrap();
            input.extend(samples);
            output.extend(
                decoded
                    .chunks_exact(4)
                    .map(|sample| f32::from_le_bytes(sample.try_into().unwrap())),
            );
        }
        let fidelity = voice_error_db(&input, &output);
        assert!(
            fidelity >= 18.0,
            "quiet voice fidelity must reach 18 dB SNR; measured {fidelity}"
        );
    }
}
