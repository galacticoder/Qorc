//! Secure random number generation

use crate::error::{QorError, QorResult};

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> QorResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes)
        .map_err(|_| QorError::Internal("Operating-system entropy unavailable".to_string()))?;
    Ok(bytes)
}
