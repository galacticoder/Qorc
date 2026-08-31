//! System integration
//!
//! Platform-specific system integration

use crate::error::{QorcError, QorcResult};

pub mod notification;
pub mod power;
pub mod screen_capture;
pub mod tray;

const DEFAULT_INSTANCE_ID: &str = "1";
const MAX_INSTANCE_ID_BYTES: usize = 64;

fn valid_instance_id(value: &str) -> Option<&str> {
    let value = value.trim();
    if !value.is_empty()
        && value.len() <= MAX_INSTANCE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Some(value)
    } else {
        None
    }
}

pub fn get_instance_id() -> QorcResult<String> {
    match std::env::var("QORC_INSTANCE_ID") {
        Ok(value) => valid_instance_id(&value)
            .map(str::to_owned)
            .ok_or_else(|| QorcError::InvalidArgument("Invalid instance identifier".to_string())),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_INSTANCE_ID.to_string()),
        Err(std::env::VarError::NotUnicode(_)) => Err(QorcError::InvalidArgument(
            "Invalid instance identifier".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::valid_instance_id;

    #[test]
    fn accepts_only_bounded_path_safe_instance_ids() {
        assert_eq!(valid_instance_id("test-2"), Some("test-2"));
        assert_eq!(valid_instance_id("  alpha_3  "), Some("alpha_3"));
        assert_eq!(valid_instance_id("../escape"), None);
        assert_eq!(valid_instance_id("a/b"), None);
        assert_eq!(valid_instance_id("."), None);
        assert_eq!(valid_instance_id(&"a".repeat(65)), None);
    }
}
