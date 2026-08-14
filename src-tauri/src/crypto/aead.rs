//! AEAD encryption primitives

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use crate::error::{QorError, QorResult};

/// Encrypt with XChaCha20-Poly1305
pub fn xchacha_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> QorResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| QorError::EncryptionFailed("XChaCha key init failed".to_string()))?;

    let nonce_obj = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce_obj,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| QorError::EncryptionFailed("XChaCha20-Poly1305 encryption failed".to_string()))
}

/// Decrypt with XChaCha20-Poly1305
pub fn xchacha_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> QorResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| QorError::DecryptionFailed("XChaCha key init failed".to_string()))?;

    let nonce_obj = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce_obj,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| QorError::DecryptionFailed("XChaCha20-Poly1305 decryption failed".to_string()))
}
