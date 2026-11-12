use rusty_opus::{Application, OpusDecoder, OpusEncoder, repacketizer::samples_per_frame};
use std::collections::HashMap;
use std::sync::Mutex;

const SAMPLE_RATE: u32 = 48_000;
pub(crate) const FRAME_SAMPLES: usize = 960;
const SILENCE_FADE_SAMPLES: usize = SAMPLE_RATE as usize / 200;
pub(crate) const MAX_PACKET_BYTES: usize = 1276;
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
