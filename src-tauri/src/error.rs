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

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    // ============================================
    // Signal Protocol Errors
    // ============================================
    #[error("Signal Protocol error: {0}")]
    SignalProtocol(String),

    // ============================================
    // Post-Quantum Errors
    // ============================================
    #[error("ML-KEM encapsulation failed")]
    KemEncapsulationFailed,

    #[error("ML-KEM decapsulation failed")]
    KemDecapsulationFailed,

    #[error("Dilithium signing failed")]
    SigningFailed,

    #[error("Verification failed: {0}")]
    Verification(String),

    // ============================================
    // Storage Errors
    // ============================================
    #[error("Storage initialization failed: {0}")]
    StorageInitFailed(String),


    // ============================================
    // Tor Errors
    // ============================================
    #[error("Tor control error: {0}")]
    TorControl(String),

    #[error("Tor process error: {0}")]
    TorProcess(String),

    // ============================================
    // Network Errors
    // ============================================
    #[error("Network error: {0}")]
    Network(String),

    // ============================================
    // File Errors
    // ============================================
    #[error("File operation failed: {0}")]
    FileOperationFailed(String),

    #[error("File system error: {0}")]
    FileSystem(String),

    // ============================================
    // System Errors
    // ============================================
    #[error("Unsupported platform: {0}")]
    NotSupported(String),

    #[error("System error: {0}")]
    #[allow(dead_code)]
    SystemError(String),

    #[error("Notification failed: {0}")]
    NotificationFailed(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    // ============================================
    // General Errors
    // ============================================
    #[error("Not initialized: {0}")]
    NotInitialized(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Not found: {0}")]
    NotFound(String),

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
    /// Check if error requires key refresh
    pub fn requires_key_refresh(&self) -> bool {
        match self {
            QorError::SignalProtocol(e) => e.contains("untrusted") || e.contains("Untrusted") || e.contains("identity mismatch"),
            _ => false,
        }
    }

    /// Get a safe error message
    pub fn safe_message(&self) -> String {
        match self {
            // Mask internal details for sensitive errors
            QorError::EncryptionFailed(_) => "Encryption failed".to_string(),
            QorError::DecryptionFailed(_) => "Decryption failed".to_string(),
            QorError::MacVerificationFailed => "Data verification failed".to_string(),

            // For other errors use display message
            _ => self.to_string(),
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
