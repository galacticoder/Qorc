//! Secure random number generation

use crate::error::{QorcError, QorcResult};

/// Generate cryptographically secure random bytes
pub fn random_bytes(len: usize) -> QorcResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes)
        .map_err(|_| QorcError::Internal("Operating-system entropy unavailable".to_string()))?;
    Ok(bytes)
}
