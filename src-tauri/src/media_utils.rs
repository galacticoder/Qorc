#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::media::{PCM_SESSION_ID_BYTES, SESSION_ID_MAX_BYTES, SESSION_ID_MIN_BYTES};
use crate::validation::is_lowercase_hex;

pub(crate) enum MediaSession {
    AudioCodec,
    AudioPlayback,
    Camera,
    Microphone,
    Screen,
}

impl MediaSession {
    pub(crate) fn validate_id(self, id: &str) -> Result<(), String> {
        let (lengths, error) = match self {
            Self::AudioCodec => (
                SESSION_ID_MIN_BYTES..=SESSION_ID_MAX_BYTES,
                "invalid audio codec session",
            ),
            Self::AudioPlayback => (
                PCM_SESSION_ID_BYTES..=PCM_SESSION_ID_BYTES,
                "invalid audio playback session",
            ),
            Self::Camera => (
                SESSION_ID_MIN_BYTES..=SESSION_ID_MAX_BYTES,
                "invalid camera capture session",
            ),
            Self::Microphone => (
                PCM_SESSION_ID_BYTES..=PCM_SESSION_ID_BYTES,
                "invalid microphone capture session",
            ),
            Self::Screen => (
                SESSION_ID_MIN_BYTES..=SESSION_ID_MAX_BYTES,
                "invalid screen capture session",
            ),
        };
        if lengths.contains(&id.len()) && is_lowercase_hex(id) {
            Ok(())
        } else {
            Err(error.to_owned())
        }
    }
}

pub(crate) fn validate_device_id(id: &str, max_bytes: usize, error: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > max_bytes || id.chars().any(char::is_control) {
        Err(error.to_owned())
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
