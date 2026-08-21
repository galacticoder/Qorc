use rusty_opus::{Application, OpusDecoder, OpusEncoder};
use std::collections::HashMap;
use std::sync::Mutex;

const SAMPLE_RATE: u32 = 48_000;
const FRAME_SAMPLES: usize = 960;
const MAX_PACKET_BYTES: usize = 1276;
const MAX_SESSIONS: usize = 4;

struct CodecSession {
    encoder: OpusEncoder,
    decoder: OpusDecoder,
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
        let mut encoder = OpusEncoder::new(SAMPLE_RATE as i32, 1, Application::Voip)
            .map_err(|_| "failed to initialize Opus encoder".to_string())?;
        encoder.bitrate_bps = 24_000;
        encoder.complexity = 8;
        encoder.use_cbr = false;
        encoder.use_inband_fec = true;
        encoder.use_dtx = true;
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
        sessions.insert(session_id.to_string(), CodecSession { encoder, decoder });
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
        let mut pcm = vec![0.0f32; FRAME_SAMPLES];
        let decoded = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| "audio codec unavailable".to_string())?;
            let session = sessions
                .get_mut(session_id)
                .ok_or_else(|| "audio codec session unavailable".to_string())?;
            if fec {
                session
                    .decoder
                    .decode_fec(packet, FRAME_SAMPLES, &mut pcm)
                    .map_err(|_| "Opus FEC decoding failed".to_string())?
            } else {
                session
                    .decoder
                    .decode(packet, FRAME_SAMPLES, &mut pcm)
                    .map_err(|_| "Opus decoding failed".to_string())?
            }
        };
        if decoded == 0 || decoded > FRAME_SAMPLES {
            pcm.fill(0.0);
            return Err("invalid decoded Opus frame".to_string());
        }
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
    fn opus_session_enters_discontinuous_transmission_for_silence() {
        let state = AudioCodecState::new();
        let session = "fedcba9876543210fedcba9876543210";
        state.start(session).unwrap();
        let mut entered_dtx = false;
        for _ in 0..100 {
            let packet = state.encode(session, &silence_bytes()).unwrap();
            if packet.len() == 1 {
                entered_dtx = true;
                break;
            }
        }
        assert!(entered_dtx);
    }
}
