//! Error types for Qor-Chat

use thiserror::Error;

/// Main error type
#[derive(Error, Debug)]
pub enum QorError {
    // ============================================
    // Cryptographic Errors
    // ============================================
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("MAC verification failed: data may be tampered")]
    MacVerificationFailed,

    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Signal Protocol error: {0}")]
    SignalProtocol(String),

    #[error("ML-KEM encapsulation failed")]
    KemEncapsulationFailed,

    #[error("ML-KEM decapsulation failed")]
    KemDecapsulationFailed,

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Storage initialization failed: {0}")]
    StorageInitFailed(String),

    #[error("Tor control error: {0}")]
    TorControl(String),

    #[error("Tor process error: {0}")]
    TorProcess(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("File operation failed: {0}")]
    FileOperationFailed(String),

    #[error("File system error: {0}")]
    FileSystem(String),

    #[error("Unsupported platform: {0}")]
    NotSupported(String),

    #[error("System error: {0}")]
    SystemError(String),

    #[error("Notification failed: {0}")]
    NotificationFailed(String),

    #[error("Not initialized: {0}")]
    NotInitialized(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Tauri error: {0}")]
    Tauri(#[from] tauri::Error),
}

/// Result type alias for Qor operations
pub type QorResult<T> = Result<T, QorError>;

/// Convert QorError to a serializable error response
impl QorError {
    fn safe_signal_message(message: &str) -> String {
        let normalized = message.to_ascii_lowercase();
        if normalized.contains("untrusted") || normalized.contains("identity mismatch") {
            "Untrusted Signal identity".to_string()
        } else if normalized.contains("old counter") || normalized.contains("duplicate") {
            "Duplicate Signal message".to_string()
        } else if normalized.contains("pre-key") || normalized.contains("prekey") {
            "Signal prekey operation failed".to_string()
        } else if normalized.contains("session") {
            "Signal session unavailable".to_string()
        } else if normalized.contains("store") || normalized.contains("serializ") {
            "Signal state operation failed".to_string()
        } else {
            "Signal operation failed".to_string()
        }
    }

    fn safe_network_message(message: &str) -> String {
        let normalized = message.to_ascii_lowercase();
        if normalized.contains("timeout")
            || normalized.contains("timed out")
            || normalized.contains("did not respond")
        {
            "Network timeout".to_string()
        } else if normalized.contains("connection in progress") {
            "Connection in progress".to_string()
        } else if normalized.contains("queue full") || normalized.contains("in progress") {
            "Network busy".to_string()
        } else if normalized.contains("invalid endpoint")
            || normalized.contains("endpoint must")
            || normalized.contains("endpoint length")
        {
            "Invalid network endpoint".to_string()
        } else if normalized.contains("unavailable")
            || normalized.contains("unreachable")
            || normalized.contains("socks")
            || normalized.contains("resolve")
            || normalized.contains("refused")
            || normalized.contains("reset")
        {
            "Host unreachable".to_string()
        } else {
            "Network operation failed".to_string()
        }
    }

    /// Check if error requires key refresh
    pub fn requires_key_refresh(&self) -> bool {
        match self {
            QorError::SignalProtocol(e) => {
                e.contains("untrusted")
                    || e.contains("Untrusted")
                    || e.contains("identity mismatch")
            }
            _ => false,
        }
    }

    pub fn safe_message(&self) -> String {
        match self {
            QorError::EncryptionFailed(_) => "Encryption failed".to_string(),
            QorError::DecryptionFailed(_) => "Decryption failed".to_string(),
            QorError::MacVerificationFailed => "Data verification failed".to_string(),
            QorError::InvalidKeyLength { .. } => "Invalid key length".to_string(),
            QorError::SignalProtocol(message) => Self::safe_signal_message(message),
            QorError::KemEncapsulationFailed => "ML-KEM encapsulation failed".to_string(),
            QorError::KemDecapsulationFailed => "ML-KEM decapsulation failed".to_string(),
            QorError::Verification(_) => "Verification failed".to_string(),
            QorError::StorageInitFailed(_) => "Storage operation failed".to_string(),
            QorError::TorControl(_) | QorError::TorProcess(_) => "Tor operation failed".to_string(),
            QorError::Network(message) => Self::safe_network_message(message),
            QorError::FileOperationFailed(_) | QorError::FileSystem(_) | QorError::Io(_) => {
                "File operation failed".to_string()
            }
            QorError::NotSupported(_) => "Operation is not supported".to_string(),
            QorError::SystemError(_) => "System operation failed".to_string(),
            QorError::NotificationFailed(_) => "Notification failed".to_string(),
            QorError::NotInitialized(message) => format!("Not initialized: {message}"),
            QorError::InvalidArgument(message) => format!("Invalid argument: {message}"),
            QorError::Internal(_) => "Internal operation failed".to_string(),
            QorError::Json(_) => "Invalid data".to_string(),
            QorError::Reqwest(_) => "Network operation failed".to_string(),
            QorError::Url(_) => "Invalid URL".to_string(),
            QorError::Tauri(_) => "Application operation failed".to_string(),
        }
    }
}

impl serde::Serialize for QorError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.safe_message())
    }
}

#[cfg(test)]
mod tests {
    use super::QorError;

    #[test]
    fn safe_messages_do_not_expose_internal_details() {
        assert_eq!(
            QorError::StorageInitFailed("/home/alice/private.db: locked".to_string())
                .safe_message(),
            "Storage operation failed"
        );
        assert_eq!(
            QorError::Network("SOCKS5 failed for secret.onion: refused".to_string()).safe_message(),
            "Host unreachable"
        );
        assert_eq!(
            QorError::Internal("task panicked at /home/alice/src.rs".to_string()).safe_message(),
            "Internal operation failed"
        );
        assert_eq!(
            QorError::Network("connection in progress for secret.onion".to_string()).safe_message(),
            "Connection in progress"
        );
    }

    #[test]
    fn signal_messages_keep_only_required_recovery_classes() {
        assert_eq!(
            QorError::SignalProtocol("untrusted identity for alice".to_string()).safe_message(),
            "Untrusted Signal identity"
        );
        assert_eq!(
            QorError::SignalProtocol("old counter with internal details".to_string())
                .safe_message(),
            "Duplicate Signal message"
        );
        assert_eq!(
            QorError::SignalProtocol("session decode failed for alice".to_string()).safe_message(),
            "Signal session unavailable"
        );
    }
}
