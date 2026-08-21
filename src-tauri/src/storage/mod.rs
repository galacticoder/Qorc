//! Secure Storage Module

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::{
    Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit},
};
use blake3::Hasher as Blake3Hasher;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use sha3::{Digest, Sha3_512};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::error::{QorError, QorResult};
use crate::state::AppState;

pub(crate) mod file;
mod machine_entropy;

const NONCE_SIZE: usize = 36;
const MAC_SIZE: usize = 32;
const AES_NONCE_SIZE: usize = 12;
const XCHACHA_NONCE_SIZE: usize = 24;
pub const SECURE_VALUE_MAX_BYTES: usize = 8 * 1024 * 1024;
const ENCRYPTED_ITEM_MAX_BYTES: usize = SECURE_VALUE_MAX_BYTES + NONCE_SIZE + MAC_SIZE + 64;
const SECURE_STORE_MAX_ITEMS: u64 = 4096;
const SECURE_STORE_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Default)]
struct StoreUsage {
    item_count: u64,
    total_bytes: u64,
}

/// Secure storage handler
pub struct SecureStorage {
    aes_key: Zeroizing<[u8; 32]>,
    xchacha_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
    name_key: Zeroizing<[u8; 32]>,
    store_dir: PathBuf,
    usage: Mutex<StoreUsage>,
}

impl SecureStorage {
    pub async fn new(config_dir: PathBuf) -> QorResult<Self> {
        let store_dir = config_dir.join("secure-store");
        let master_key_path = config_dir.join("master.key");

        file::ensure_dir(&config_dir, 0o700).await?;
        file::ensure_dir(&store_dir, 0o700).await?;
        file::remove_stale_temp_files(&config_dir).await?;
        file::remove_stale_temp_files(&store_dir).await?;

        let master_key = Self::load_or_generate_master_key(&master_key_path).await?;

        let machine_context = machine_entropy::get_machine_context().await?;

        let root_key = Self::derive_root_key(&master_key, &machine_context);

        let aes_key = Self::derive_key(
            root_key.as_ref(),
            crate::protocol_keys::SECURE_STORAGE_AES_KEY,
        );
        let xchacha_key = Self::derive_key(
            root_key.as_ref(),
            crate::protocol_keys::SECURE_STORAGE_XCHACHA_KEY,
        );
        let mac_key = Self::derive_key(
            root_key.as_ref(),
            crate::protocol_keys::SECURE_STORAGE_MAC_KEY,
        );
        let name_key = Self::derive_key(
            root_key.as_ref(),
            crate::protocol_keys::SECURE_STORAGE_FILENAME_KEY,
        );
        let usage = Self::scan_store_usage(&store_dir).await?;

        // Zeroize intermediate keys
        drop(root_key);
        drop(machine_context);

        Ok(Self {
            aes_key: Zeroizing::new(aes_key),
            xchacha_key: Zeroizing::new(xchacha_key),
            mac_key: Zeroizing::new(mac_key),
            name_key: Zeroizing::new(name_key),
            store_dir,
            usage: Mutex::new(usage),
        })
    }

    async fn scan_store_usage(store_dir: &Path) -> QorResult<StoreUsage> {
        let mut entries = tokio::fs::read_dir(store_dir).await?;
        let mut usage = StoreUsage::default();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("bin") {
                continue;
            }
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            file::validate_private_file_metadata(&metadata)?;
            if metadata.len() > ENCRYPTED_ITEM_MAX_BYTES as u64 {
                return Err(QorError::StorageInitFailed(
                    "Secure storage contains an oversized item".to_string(),
                ));
            }
            usage.item_count = usage.item_count.saturating_add(1);
            usage.total_bytes = usage.total_bytes.saturating_add(metadata.len());
            if usage.item_count > SECURE_STORE_MAX_ITEMS
                || usage.total_bytes > SECURE_STORE_MAX_TOTAL_BYTES
            {
                return Err(QorError::StorageInitFailed(
                    "Secure storage exceeds its capacity limit".to_string(),
                ));
            }
        }
        Ok(usage)
    }

    async fn load_or_generate_master_key(path: &Path) -> QorResult<Zeroizing<Vec<u8>>> {
        match file::read_file_bounded(path, 64).await {
            Ok(data) => {
                if data.len() != 64 {
                    return Err(QorError::StorageInitFailed(
                        "Invalid master key length".to_string(),
                    ));
                }
                Ok(Zeroizing::new(data))
            }
            Err(QorError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                let candidate: Zeroizing<Vec<u8>> =
                    Zeroizing::new(crate::crypto::random::random_bytes(64)?);
                if file::atomic_write_if_absent(path, &candidate, 0o600).await? {
                    return Ok(candidate);
                }

                let data = file::read_file_bounded(path, 64).await?;
                if data.len() != 64 {
                    return Err(QorError::StorageInitFailed(
                        "Invalid master key length".to_string(),
                    ));
                }
                Ok(Zeroizing::new(data))
            }
            Err(e) => Err(e),
        }
    }

    fn derive_root_key(master_key: &[u8], machine_context: &[u8]) -> Zeroizing<[u8; 64]> {
        let mut hasher = Sha3_512::new();
        hasher.update(crate::protocol_keys::SECURE_STORAGE_ROOT);
        hasher.update(master_key);
        hasher.update(machine_context);
        let result = hasher.finalize();

        let mut key = [0u8; 64];
        key.copy_from_slice(&result);
        Zeroizing::new(key)
    }

    fn derive_key(root_key: &[u8], context: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_512::new();
        hasher.update(context);
        hasher.update(root_key);
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result[..32]);
        key
    }

    fn file_path_for_key(&self, key: &str) -> PathBuf {
        let mut hasher = Blake3Hasher::new_keyed(&self.name_key);
        hasher.update(crate::protocol_keys::SECURE_STORAGE_FILENAME);
        hasher.update(key.as_bytes());
        let safe_name = blake3::Hasher::finalize(&hasher).to_hex().to_string();
        self.store_dir.join(format!("{}.bin", safe_name))
    }

    fn compute_mac(&self, data: &[u8]) -> [u8; MAC_SIZE] {
        let mut hasher = Blake3Hasher::new_keyed(&self.mac_key);
        hasher.update(data);
        let result = hasher.finalize();

        let mut mac = [0u8; MAC_SIZE];
        mac.copy_from_slice(result.as_ref());
        mac
    }

    pub async fn set_item(&self, key: &str, value: &[u8]) -> QorResult<()> {
        if value.len() > SECURE_VALUE_MAX_BYTES {
            return Err(QorError::InvalidArgument(
                "Secure storage value exceeds its size limit".to_string(),
            ));
        }
        // Generate random nonce
        let nonce = crate::crypto::random::random_bytes(NONCE_SIZE)?;
        let aes_nonce: &[u8; AES_NONCE_SIZE] = nonce[..AES_NONCE_SIZE].try_into().unwrap();
        let xchacha_nonce: &[u8; XCHACHA_NONCE_SIZE] = nonce[AES_NONCE_SIZE..].try_into().unwrap();

        let mut aad1 = Vec::with_capacity(8 + key.len() + XCHACHA_NONCE_SIZE);
        aad1.extend_from_slice(crate::protocol_keys::SECURE_STORAGE_AAD_LAYER_1);
        aad1.extend_from_slice(key.as_bytes());
        aad1.extend_from_slice(xchacha_nonce);

        let mut aad2 = Vec::with_capacity(8 + key.len() + AES_NONCE_SIZE);
        aad2.extend_from_slice(crate::protocol_keys::SECURE_STORAGE_AAD_LAYER_2);
        aad2.extend_from_slice(key.as_bytes());
        aad2.extend_from_slice(aes_nonce);

        let aes_cipher = Aes256Gcm::new_from_slice(&*self.aes_key)
            .map_err(|_| QorError::EncryptionFailed("AES key init failed".to_string()))?;

        let aes_nonce_obj = AesNonce::from_slice(aes_nonce);
        let layer1_ciphertext = aes_cipher
            .encrypt(
                aes_nonce_obj,
                aes_gcm::aead::Payload {
                    msg: value,
                    aad: &aad1,
                },
            )
            .map_err(|_| QorError::EncryptionFailed("AES-GCM encryption failed".to_string()))?;

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

        let mut mac_input =
            Vec::with_capacity(5 + key.len() + NONCE_SIZE + layer2_ciphertext.len());
        mac_input.extend_from_slice(crate::protocol_keys::SECURE_STORAGE_MAC);
        mac_input.extend_from_slice(key.as_bytes());
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&layer2_ciphertext);
        let mac = self.compute_mac(&mac_input);

        let mut file_data = Vec::with_capacity(NONCE_SIZE + layer2_ciphertext.len() + MAC_SIZE);
        file_data.extend_from_slice(&nonce);
        file_data.extend_from_slice(&layer2_ciphertext);
        file_data.extend_from_slice(&mac);

        let file_path = self.file_path_for_key(key);
        let mut usage = self.usage.lock().await;
        let existing_bytes = match tokio::fs::symlink_metadata(&file_path).await {
            Ok(metadata) => {
                file::validate_private_file_metadata(&metadata)?;
                Some(metadata.len())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let next_item_count = usage.item_count + u64::from(existing_bytes.is_none());
        let next_total_bytes = usage
            .total_bytes
            .saturating_sub(existing_bytes.unwrap_or(0))
            .saturating_add(file_data.len() as u64);
        if next_item_count > SECURE_STORE_MAX_ITEMS
            || next_total_bytes > SECURE_STORE_MAX_TOTAL_BYTES
        {
            return Err(QorError::FileOperationFailed(
                "Secure storage capacity exceeded".to_string(),
            ));
        }
        file::atomic_write(&file_path, &file_data, 0o600).await?;
        usage.item_count = next_item_count;
        usage.total_bytes = next_total_bytes;

        Ok(())
    }

    /// Retrieve and decrypt a value
    pub async fn get_item(&self, key: &str) -> QorResult<Option<Vec<u8>>> {
        let file_path = self.file_path_for_key(key);

        let file_data = match file::read_file_bounded(&file_path, ENCRYPTED_ITEM_MAX_BYTES).await {
            Ok(data) => data,
            Err(QorError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let min_size = NONCE_SIZE + 16 + MAC_SIZE;
        if file_data.len() < min_size {
            return Err(QorError::DecryptionFailed(
                "Invalid encrypted file: too small".to_string(),
            ));
        }

        let nonce = &file_data[..NONCE_SIZE];
        let mac = &file_data[file_data.len() - MAC_SIZE..];
        let layer2_ciphertext = &file_data[NONCE_SIZE..file_data.len() - MAC_SIZE];

        let aes_nonce = &nonce[..AES_NONCE_SIZE];
        let xchacha_nonce = &nonce[AES_NONCE_SIZE..];

        let mut mac_input =
            Vec::with_capacity(5 + key.len() + NONCE_SIZE + layer2_ciphertext.len());
        mac_input.extend_from_slice(crate::protocol_keys::SECURE_STORAGE_MAC);
        mac_input.extend_from_slice(key.as_bytes());
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(layer2_ciphertext);
        let computed_mac = self.compute_mac(&mac_input);

        if !crate::crypto::utils::constant_time_eq(mac, &computed_mac) {
            return Err(QorError::MacVerificationFailed);
        }

        let mut aad1 = Vec::with_capacity(8 + key.len() + XCHACHA_NONCE_SIZE);
        aad1.extend_from_slice(crate::protocol_keys::SECURE_STORAGE_AAD_LAYER_1);
        aad1.extend_from_slice(key.as_bytes());
        aad1.extend_from_slice(xchacha_nonce);

        let mut aad2 = Vec::with_capacity(8 + key.len() + AES_NONCE_SIZE);
        aad2.extend_from_slice(crate::protocol_keys::SECURE_STORAGE_AAD_LAYER_2);
        aad2.extend_from_slice(key.as_bytes());
        aad2.extend_from_slice(aes_nonce);

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
        let mut usage = self.usage.lock().await;
        let existing_bytes = match tokio::fs::symlink_metadata(&file_path).await {
            Ok(metadata) => {
                file::validate_private_file_metadata(&metadata)?;
                Some(metadata.len())
            }

            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        file::remove_file(&file_path).await?;
        if let Some(existing_bytes) = existing_bytes {
            usage.item_count = usage.item_count.saturating_sub(1);
            usage.total_bytes = usage.total_bytes.saturating_sub(existing_bytes);
        }
        Ok(())
    }

    /// Alias for set_item
    pub async fn set(&self, key: &str, value: &str) -> QorResult<()> {
        self.set_item(key, value.as_bytes()).await
    }

    /// Alias for get_item
    pub async fn get(&self, key: &str) -> QorResult<Option<String>> {
        match self.get_item(key).await? {
            Some(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let value = std::str::from_utf8(&bytes).map_err(|_| {
                    QorError::DecryptionFailed("Stored value is not valid UTF-8".to_string())
                })?;
                Ok(Some(value.to_owned()))
            }
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
        file::private_file_exists(&file_path).await
    }
}

impl Drop for SecureStorage {
    fn drop(&mut self) {}
}

pub async fn init(state: &AppState, config_dir: PathBuf) -> QorResult<()> {
    let storage = SecureStorage::new(config_dir).await?;
    *state.storage.write() = Some(Arc::new(storage));
    Ok(())
}
