//! AEAD encryption primitives

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{QorError, QorResult};

/// Encrypt with AES-256-GCM
pub fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> QorResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| QorError::EncryptionFailed("AES key init failed".to_string()))?;
    
    let nonce_obj = AesNonce::from_slice(nonce);
    cipher
        .encrypt(nonce_obj, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|_| QorError::EncryptionFailed("AES-GCM encryption failed".to_string()))
}

/// Decrypt with AES-256-GCM
pub fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> QorResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| QorError::DecryptionFailed("AES key init failed".to_string()))?;
    
    let nonce_obj = AesNonce::from_slice(nonce);
    cipher
        .decrypt(nonce_obj, aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| QorError::DecryptionFailed("AES-GCM decryption failed".to_string()))
}

/// Encrypt with XChaCha20-Poly1305
pub fn xchacha_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> QorResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| QorError::EncryptionFailed("XChaCha key init failed".to_string()))?;
    
    let nonce_obj = XNonce::from_slice(nonce);
    cipher
        .encrypt(nonce_obj, chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|_| QorError::EncryptionFailed("XChaCha20-Poly1305 encryption failed".to_string()))
}

/// Decrypt with XChaCha20-Poly1305
pub fn xchacha_decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> QorResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| QorError::DecryptionFailed("XChaCha key init failed".to_string()))?;
    
    let nonce_obj = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce_obj, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| QorError::DecryptionFailed("XChaCha20-Poly1305 decryption failed".to_string()))
}
