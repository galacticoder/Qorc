//! Secure Storage Module

use std::path::PathBuf;
use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use blake3::Hasher as Blake3Hasher;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::error::{QorError, QorResult};
use crate::state::AppState;

mod file;
mod machine_entropy;

const NONCE_SIZE: usize = 36;
const MAC_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;
const XCHACHA_NONCE_SIZE: usize = 24;

/// Secure storage handler
pub struct SecureStorage {
    aes_key: Zeroizing<[u8; 32]>,
    xchacha_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
    store_dir: PathBuf,
}

impl SecureStorage {
    /// Initialize secure storage with machine-specific key derivation
    pub async fn new(config_dir: PathBuf, install_path: &str) -> QorResult<Self> {
        let store_dir = config_dir.join("secure-store");
        let master_key_path = config_dir.join("master.key");

        // Ensure directories exist with secure permissions
        file::ensure_dir(&config_dir, 0o700).await?;
        file::ensure_dir(&store_dir, 0o700).await?;

        // Load or generate master key
        let master_key = Self::load_or_generate_master_key(&master_key_path).await?;

        // Get machine context for key binding
        let machine_context = machine_entropy::get_machine_context(install_path).await?;

        // Derive root key using SHA3-512
        let root_key = Self::derive_root_key(&master_key, &machine_context);

        // Derive individual keys
        let aes_key = Self::derive_key(root_key.as_ref(), b"QSSv1/AES-256-GCM");
        let xchacha_key = Self::derive_key(root_key.as_ref(), b"QSSv1/XCHACHA20-POLY1305");
        let mac_key = Self::derive_key(root_key.as_ref(), b"QSSv1/BLAKE3-MAC");

        // Zeroize intermediate keys
        drop(root_key);
        drop(machine_context);

        Ok(Self {
            aes_key: Zeroizing::new(aes_key),
            xchacha_key: Zeroizing::new(xchacha_key),
            mac_key: Zeroizing::new(mac_key),
            store_dir,
        })
    }

    /// Load existing master key or generate new one
    async fn load_or_generate_master_key(path: &PathBuf) -> QorResult<Zeroizing<Vec<u8>>> {
        match file::read_file(path).await {
            Ok(data) => {
                if data.len() != 64 {
                    return Err(QorError::StorageInitFailed(
                        "Invalid master key length".to_string(),
                    ));
                }
                Ok(Zeroizing::new(data))
            }
            Err(e) if e.to_string().contains("not found") || e.to_string().contains("ENOENT") => {
                // Generate new master key
                let master_key: Zeroizing<Vec<u8>> =
                    Zeroizing::new(crate::crypto::random::random_bytes(64));
                file::atomic_write(path, &master_key, 0o600).await?;
                Ok(master_key)
            }
            Err(e) => Err(e),
        }
    }

    /// Derive root key from master key and machine context
    fn derive_root_key(master_key: &[u8], machine_context: &[u8]) -> Zeroizing<[u8; 64]> {
        let mut hasher = Sha3_512::new();
        hasher.update(b"QSSv1/ROOT");
        hasher.update(master_key);
        hasher.update(machine_context);
        let result = hasher.finalize();

        let mut key = [0u8; 64];
        key.copy_from_slice(&result);
        Zeroizing::new(key)
    }

    /// Derive a 32-byte key
    fn derive_key(root_key: &[u8], context: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_512::new();
        hasher.update(context);
        hasher.update(root_key);
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    }

    /// Get file path for a key
    fn file_path_for_key(&self, key: &str) -> PathBuf {
        let safe_name = file::to_safe_filename(key);
        self.store_dir.join(format!("{}.bin", safe_name))
    }

    /// Compute BLAKE3 keyed MAC
    fn compute_mac(&self, data: &[u8]) -> [u8; MAC_SIZE] {
        let mut hasher = Blake3Hasher::new_keyed(&self.mac_key);
        hasher.update(data);
        let result = hasher.finalize();

        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(result.as_ref());
        mac
    }

    /// Encrypt and store a value
    pub async fn set_item(&self, key: &str, value: &[u8]) -> QorResult<()> {
        // Generate random nonce
        let nonce = crate::crypto::random::random_bytes(NONCE_SIZE);
        let aes_nonce: &[u8; AES_NONCE_SIZE] = nonce[..AES_NONCE_SIZE].try_into().unwrap();
        let xchacha_nonce: &[u8; XCHACHA_NONCE_SIZE] =
            nonce[AES_NONCE_SIZE..].try_into().unwrap();

        // Build AAD for each layer
        let mut aad1 = Vec::with_capacity(8 + XCHACHA_NONCE_SIZE);
        aad1.extend_from_slice(b"QSSv1 L1");
        aad1.extend_from_slice(xchacha_nonce);

        let mut aad2 = Vec::with_capacity(8 + AES_NONCE_SIZE);
        aad2.extend_from_slice(b"QSSv1 L2");
        aad2.extend_from_slice(aes_nonce);

        // AES-256-GCM encryption
        let aes_cipher = Aes256Gcm::new_from_slice(&*self.aes_key)
            .map_err(|_| QorError::EncryptionFailed("AES key init failed".to_string()))?;

        let aes_nonce_obj = AesNonce::from_slice(aes_nonce);
        let layer1_ciphertext = aes_cipher
            .encrypt(aes_nonce_obj, aes_gcm::aead::Payload { msg: value, aad: &aad1 })
            .map_err(|_| QorError::EncryptionFailed("AES-GCM encryption failed".to_string()))?;

        // XChaCha20-Poly1305 encryption
        let xchacha_cipher = XChaCha20Poly1305::new_from_slice(&*self.xchacha_key)
            .map_err(|_| QorError::EncryptionFailed("XChaCha key init failed".to_string()))?;

        let xchacha_nonce_obj = XNonce::from_slice(xchacha_nonce);
        let layer2_ciphertext = xchacha_cipher
            .encrypt(
                xchacha_nonce_obj,
                chacha20poly1305::aead::Payload {
                    msg: &layer1_ciphertext,
                    aad: &aad2,
                },
            )
            .map_err(|_| {
                QorError::EncryptionFailed("XChaCha20-Poly1305 encryption failed".to_string())
            })?;

        // BLAKE3 MAC
        let mut mac_input = Vec::with_capacity(5 + NONCE_SIZE + layer2_ciphertext.len());
        mac_input.extend_from_slice(b"QSSv1");
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&layer2_ciphertext);
        let mac = self.compute_mac(&mac_input);

        let mut file_data = Vec::with_capacity(NONCE_SIZE + layer2_ciphertext.len() + MAC_SIZE);
        file_data.extend_from_slice(&nonce);
        file_data.extend_from_slice(&layer2_ciphertext);
        file_data.extend_from_slice(&mac);

        // Write 
        let file_path = self.file_path_for_key(key);
        file::atomic_write(&file_path, &file_data, 0o600).await?;

        Ok(())
    }

    /// Retrieve and decrypt a value
    pub async fn get_item(&self, key: &str) -> QorResult<Option<Vec<u8>>> {
        let file_path = self.file_path_for_key(key);

        // Read file
        let file_data = match file::read_file(&file_path).await {
            Ok(data) => data,
            Err(e) if e.to_string().contains("not found") => return Ok(None),
            Err(e) => return Err(e),
        };

        // Minimum size check
        let min_size = NONCE_SIZE + 16 + MAC_SIZE;
        if file_data.len() < min_size {
            return Err(QorError::DecryptionFailed(
                "Invalid encrypted file: too small".to_string(),
            ));
        }

        // Parse file structure
        let nonce = &file_data[..NONCE_SIZE];
        let mac = &file_data[file_data.len() - MAC_SIZE..];
        let layer2_ciphertext = &file_data[NONCE_SIZE..file_data.len() - MAC_SIZE];

        let aes_nonce = &nonce[..AES_NONCE_SIZE];
        let xchacha_nonce = &nonce[AES_NONCE_SIZE..];

        // Verify MAC
        let mut mac_input = Vec::with_capacity(5 + NONCE_SIZE + layer2_ciphertext.len());
        mac_input.extend_from_slice(b"QSSv1");
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(layer2_ciphertext);
        let computed_mac = self.compute_mac(&mac_input);

        if !crate::crypto::utils::constant_time_eq(mac, &computed_mac) {
            return Err(QorError::MacVerificationFailed);
        }

        // Build AAD
        let mut aad1 = Vec::with_capacity(8 + XCHACHA_NONCE_SIZE);
        aad1.extend_from_slice(b"QSSv1 L1");
        aad1.extend_from_slice(xchacha_nonce);

        let mut aad2 = Vec::with_capacity(8 + AES_NONCE_SIZE);
        aad2.extend_from_slice(b"QSSv1 L2");
        aad2.extend_from_slice(aes_nonce);

        // XChaCha20-Poly1305 decryption
        let xchacha_cipher = XChaCha20Poly1305::new_from_slice(&*self.xchacha_key)
            .map_err(|_| QorError::DecryptionFailed("XChaCha key init failed".to_string()))?;

        let xchacha_nonce_obj = XNonce::from_slice(xchacha_nonce);
        let layer1_ciphertext = xchacha_cipher
            .decrypt(
                xchacha_nonce_obj,
                chacha20poly1305::aead::Payload {
                    msg: layer2_ciphertext,
                    aad: &aad2,
                },
            )
            .map_err(|_| {
                QorError::DecryptionFailed("XChaCha20-Poly1305 decryption failed".to_string())
            })?;

        // AES-256-GCM decryption
        let aes_cipher = Aes256Gcm::new_from_slice(&*self.aes_key)
            .map_err(|_| QorError::DecryptionFailed("AES key init failed".to_string()))?;

        let aes_nonce_obj = AesNonce::from_slice(aes_nonce);
        let plaintext = aes_cipher
            .decrypt(
                aes_nonce_obj,
                aes_gcm::aead::Payload {
                    msg: &layer1_ciphertext,
                    aad: &aad1,
                },
            )
            .map_err(|_| QorError::DecryptionFailed("AES-GCM decryption failed".to_string()))?;

        Ok(Some(plaintext))
    }

    /// Remove a stored value
    pub async fn remove_item(&self, key: &str) -> QorResult<()> {
        let file_path = self.file_path_for_key(key);
        file::remove_file(&file_path).await
    }

    /// List all stored keys
    pub async fn list_keys(&self) -> QorResult<Vec<String>> {
        let files = file::list_files(&self.store_dir).await?;
        Ok(files
            .into_iter()
            .filter(|f| f.ends_with(".bin"))
            .map(|f| file::from_safe_filename(&f[..f.len() - 4]))
            .collect())
    }

    /// Alias for set_item
    pub async fn set(&self, key: &str, value: &str) -> QorResult<()> {
        self.set_item(key, value.as_bytes()).await
    }

    /// Alias for get_item
    pub async fn get(&self, key: &str) -> QorResult<Option<String>> {
        match self.get_item(key).await? {
            Some(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).to_string())),
            None => Ok(None),
        }
    }

    /// Alias for remove_item
    pub async fn remove(&self, key: &str) -> QorResult<()> {
        self.remove_item(key).await
    }

    /// Check if item exists
    pub async fn has(&self, key: &str) -> QorResult<bool> {
        let file_path = self.file_path_for_key(key);
        Ok(file_path.exists())
    }

    /// Alias for list_keys
    pub async fn keys(&self) -> QorResult<Vec<String>> {
        self.list_keys().await
    }

    /// Clear all items
    pub async fn clear(&self) -> QorResult<()> {
        let keys = self.list_keys().await?;
        for key in keys {
            self.remove_item(&key).await?;
        }
        Ok(())
    }
}

impl Drop for SecureStorage {
    fn drop(&mut self) {
        // Keys auto zeroized
    }
}

/// Initialize secure storage
pub async fn init(state: &AppState, config_dir: PathBuf) -> QorResult<()> {
    let install_path = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .to_string_lossy()
        .to_string();

    let storage = SecureStorage::new(config_dir, &install_path).await?;
    *state.storage.write() = Some(Arc::new(storage));
    Ok(())
}
