//! Error types for qorc

use thiserror::Error;

/// Main error type
#[derive(Error, Debug)]
pub enum QorcError {
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

/// Result type alias for qorc operations
pub type QorcResult<T> = Result<T, QorcError>;

/// Convert QorcError to a serializable error response
impl QorcError {
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
            QorcError::SignalProtocol(e) => {
                e.contains("untrusted")
                    || e.contains("Untrusted")
                    || e.contains("identity mismatch")
            }
            _ => false,
        }
    }

    pub fn safe_message(&self) -> String {
        match self {
            QorcError::EncryptionFailed(_) => "Encryption failed".to_string(),
            QorcError::DecryptionFailed(_) => "Decryption failed".to_string(),
            QorcError::MacVerificationFailed => "Data verification failed".to_string(),
            QorcError::InvalidKeyLength { .. } => "Invalid key length".to_string(),
            QorcError::SignalProtocol(message) => Self::safe_signal_message(message),
            QorcError::KemEncapsulationFailed => "ML-KEM encapsulation failed".to_string(),
            QorcError::KemDecapsulationFailed => "ML-KEM decapsulation failed".to_string(),
            QorcError::Verification(_) => "Verification failed".to_string(),
            QorcError::StorageInitFailed(_) => "Storage operation failed".to_string(),
            QorcError::TorControl(_) | QorcError::TorProcess(_) => "Tor operation failed".to_string(),
            QorcError::Network(message) => Self::safe_network_message(message),
            QorcError::FileOperationFailed(_) | QorcError::FileSystem(_) | QorcError::Io(_) => {
                "File operation failed".to_string()
            }
            QorcError::NotSupported(_) => "Operation is not supported".to_string(),
            QorcError::SystemError(_) => "System operation failed".to_string(),
            QorcError::NotificationFailed(_) => "Notification failed".to_string(),
            QorcError::NotInitialized(message) => format!("Not initialized: {message}"),
            QorcError::InvalidArgument(message) => format!("Invalid argument: {message}"),
            QorcError::Internal(_) => "Internal operation failed".to_string(),
            QorcError::Json(_) => "Invalid data".to_string(),
            QorcError::Reqwest(_) => "Network operation failed".to_string(),
            QorcError::Url(_) => "Invalid URL".to_string(),
            QorcError::Tauri(_) => "Application operation failed".to_string(),
        }
    }
}

impl serde::Serialize for QorcError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.safe_message())
    }
}

#[cfg(test)]
mod tests {
    use super::QorcError;

    #[test]
    fn safe_messages_do_not_expose_internal_details() {
        assert_eq!(
            QorcError::StorageInitFailed("/home/alice/private.db: locked".to_string())
                .safe_message(),
            "Storage operation failed"
        );
        assert_eq!(
            QorcError::Network("SOCKS5 failed for secret.onion: refused".to_string()).safe_message(),
            "Host unreachable"
        );
        assert_eq!(
            QorcError::Internal("task panicked at /home/alice/src.rs".to_string()).safe_message(),
            "Internal operation failed"
        );
        assert_eq!(
            QorcError::Network("connection in progress for secret.onion".to_string()).safe_message(),
            "Connection in progress"
        );
    }

    #[test]
    fn signal_messages_keep_only_required_recovery_classes() {
        assert_eq!(
            QorcError::SignalProtocol("untrusted identity for alice".to_string()).safe_message(),
            "Untrusted Signal identity"
        );
        assert_eq!(
            QorcError::SignalProtocol("old counter with internal details".to_string())
                .safe_message(),
            "Duplicate Signal message"
        );
        assert_eq!(
            QorcError::SignalProtocol("session decode failed for alice".to_string()).safe_message(),
            "Signal session unavailable"
        );
    }
}
