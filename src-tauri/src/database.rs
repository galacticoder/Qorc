//! Native Encrypted Database Module

use parking_lot::Mutex;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

use crate::crypto::aead::{xchacha_decrypt, xchacha_encrypt};
use crate::crypto::hash::{hkdf_sha3_derive_32, shake256};
use crate::crypto::random::random_bytes;
use crate::error::{QorcError, QorcResult};
use crate::state::AppState;

const NATIVE_MESSAGE_CONTENT_MAX_BYTES: usize = 66 * 1024;
const NATIVE_MESSAGE_ID_MAX_BYTES: usize = 256;

pub struct DatabaseManager {
    conn: Mutex<Connection>,
    k_sym: Zeroizing<[u8; 32]>,
    k_quant: Zeroizing<[u8; 32]>,
    store_prefix: String,
    account_owner: String,
    quota_usage: Mutex<QuotaUsageCache>,
}

#[derive(Default)]
struct QuotaUsageCache {
    initialized: bool,
    data_version: i64,
    account_total: i64,
    store_totals: HashMap<String, i64>,

}

fn database_managed_paths(db_path: &Path) -> [PathBuf; 4] {
    let sidecar = |suffix: &str| {
        let mut value = db_path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    };
    [
        db_path.to_path_buf(),
        sidecar("-wal"),
        sidecar("-shm"),
        sidecar("-journal"),
    ]
}

async fn validate_existing_database_paths(paths: &[PathBuf]) -> QorcResult<()> {
    for path in paths {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) => crate::storage::file::validate_private_file_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn secure_database_paths(paths: &[PathBuf]) -> QorcResult<()> {
    for path in paths {
        let metadata = match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() {
            return Err(QorcError::FileOperationFailed(
                "Database path is not a regular file".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(QorcError::FileOperationFailed(
                    "Database file has an invalid owner".to_string(),
                ));
            }
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
        }
        let secured = tokio::fs::symlink_metadata(path).await?;
        crate::storage::file::validate_private_file_metadata(&secured)?;
    }
    Ok(())
}

fn database_initialization_error(stage: &'static str, error: rusqlite::Error) -> QorcError {
    tracing::error!(stage, sqlite_extended_code = error.sqlite_error().map(|error| error.extended_code),
        "Encrypted database initialization failed");
    QorcError::StorageInitFailed(format!("{stage}: {error}"))
}

impl DatabaseManager {
    pub(crate) fn close_for_local_deletion(&self) -> QorcResult<()> {
        let replacement = Connection::open_in_memory().map_err(|error| database_initialization_error("close replacement", error))?;
        let connection = std::mem::replace(&mut *self.conn.lock(), replacement);
        connection.close().map_err(|(_, error)| database_initialization_error("close account database", error))
    }

    /// Initialize a new native encrypted database
    pub fn new(db_path: PathBuf, master_key: &[u8]) -> QorcResult<Self> {
        Self::open_impl(db_path, master_key)
    }

    fn open_impl(db_path: PathBuf, master_key: &[u8]) -> QorcResult<Self> {
        // Derive triple keys from master key
        let k_disk = Zeroizing::new(hkdf_sha3_derive_32(
            master_key,
            crate::storage_keys::NATIVE_DATABASE_SALT_DISK,
            crate::protocol_keys::DATABASE_DISK,
        )?);
        let k_sym_raw = Zeroizing::new(hkdf_sha3_derive_32(
            master_key,
            crate::storage_keys::NATIVE_DATABASE_SALT_SYMMETRIC,
            crate::protocol_keys::DATABASE_SYMMETRIC,
        )?);
        let k_quant_raw = Zeroizing::new(hkdf_sha3_derive_32(
            master_key,
            crate::storage_keys::NATIVE_DATABASE_SALT_QUANTUM,
            crate::protocol_keys::DATABASE_QUANTUM,
        )?);

        let mut k_sym = [0u8; 32];
        k_sym.copy_from_slice(k_sym_raw.as_slice());
        let mut k_quant = [0u8; 32];
        k_quant.copy_from_slice(k_quant_raw.as_slice());

        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| database_initialization_error("Failed to open DB", e))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|e| database_initialization_error("DB timeout setup failed", e))?;

        // Apply SQLCipher key
        let key_hex = Zeroizing::new(hex::encode(k_disk.as_slice()));
        let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\"", key_hex.as_str()));
        conn.execute_batch(key_pragma.as_str())
            .map_err(|e| database_initialization_error("DB key setup failed", e))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| database_initialization_error("DB journal setup failed", e))?;

        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| database_initialization_error("DB sync setup failed", e))?;

        conn.pragma_update(None, "temp_store", "MEMORY")
            .map_err(|e| database_initialization_error("DB temp setup failed", e))?;

        // Initialize schema
        Self::validate_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            k_sym: Zeroizing::new(k_sym),
            k_quant: Zeroizing::new(k_quant),
            store_prefix: String::new(),
            account_owner: String::new(),
            quota_usage: Mutex::new(QuotaUsageCache::default()),
        })
    }

    /// Bind the active users store namespace and lifecycle owner
    pub fn set_account_context(&mut self, prefix: String, account_owner: String) {
        self.store_prefix = prefix;
        self.account_owner = account_owner;
    }

    pub fn account_owner(&self) -> &str {
        self.account_owner.as_str()
    }

    fn in_namespace(&self, name: &str) -> bool {
        !self.store_prefix.is_empty() && name.starts_with(self.store_prefix.as_str())
    }

    fn native_message_content_store(&self) -> String {
        format!(
            "{}{}",
            self.store_prefix,
            crate::storage_keys::NATIVE_MESSAGE_CONTENT_STORE_SUFFIX
        )
    }

    fn is_native_only_store(&self, store: &str) -> bool {
        !self.store_prefix.is_empty() && store == self.native_message_content_store()
    }

    fn renderer_store_allowed(&self, store: &str) -> bool {
        self.in_namespace(store) && !self.is_native_only_store(store)
    }

    fn is_renderer_file_store(&self, store: &str) -> bool {
        store.strip_prefix(self.store_prefix.as_str()) == Some("files")
    }

    fn validate_native_message_id(message_id: &str) -> QorcResult<()> {
        if message_id.is_empty()
            || message_id.len() > NATIVE_MESSAGE_ID_MAX_BYTES
            || message_id.trim() != message_id
            || !message_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'~' | b':' | b'+' | b'/' | b'=' | b'-')
            })
        {
            return Err(QorcError::InvalidArgument(
                "Invalid native message identifier".to_string(),
            ));
        }
        Ok(())
    }

    /// Store private text in a native-only row
    pub(crate) fn set_native_message_content(
        &self,
        message_id: &str,
        content: &[u8],
    ) -> QorcResult<()> {
        Self::validate_native_message_id(message_id)?;
        if content.is_empty() || content.len() > NATIVE_MESSAGE_CONTENT_MAX_BYTES {
            return Err(QorcError::InvalidArgument(
                "Invalid native message content".to_string(),
            ));
        }
        self.set_secure(&self.native_message_content_store(), message_id, content)
    }

    pub(crate) fn get_native_message_content(
        &self,
        message_id: &str,
    ) -> QorcResult<Option<Zeroizing<Vec<u8>>>> {
        Self::validate_native_message_id(message_id)?;
        self.get_secure(&self.native_message_content_store(), message_id)
    }

    pub(crate) fn delete_native_message_content(&self, message_id: &str) -> QorcResult<()> {
        Self::validate_native_message_id(message_id)?;
        self.delete(&self.native_message_content_store(), message_id)
    }

    fn validate_schema(conn: &Connection) -> QorcResult<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kv_data (
                store TEXT NOT NULL,
                key TEXT NOT NULL,
                value BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(store, key)
            );",
            [],
        )
        .map_err(|e| database_initialization_error("Schema init failed", e))?;

        Ok(())
    }

    fn invalidate_quota_usage(&self) {
        let mut usage = self.quota_usage.lock();
        usage.initialized = false;
        usage.account_total = 0;
        usage.store_totals.clear();
    }

    fn refresh_quota_usage(
        transaction: &Transaction<'_>,
        usage: &mut QuotaUsageCache,
    ) -> QorcResult<()> {
        let data_version: i64 = transaction
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(|e| {
                QorcError::EncryptionFailed(format!("DB quota version query failed: {e}"))
            })?;
        if usage.initialized && usage.data_version == data_version {
            return Ok(());
        }

        let mut store_totals = HashMap::new();
        let mut account_total = 0i64;
        {
            let mut statement = transaction
                .prepare(
                    "SELECT store, COALESCE(SUM(LENGTH(value)), 0)
                     FROM kv_data GROUP BY store",
                )
                .map_err(|e| QorcError::EncryptionFailed(format!("DB quota query failed: {e}")))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|e| QorcError::EncryptionFailed(format!("DB quota query failed: {e}")))?;
            for row in rows {
                let (store, total) = row.map_err(|e| {
                    QorcError::EncryptionFailed(format!("DB quota query failed: {e}"))
                })?;
                if total < 0 {
                    return Err(QorcError::InvalidArgument(
                        "Database quota total is invalid".to_string(),
                    ));
                }
                account_total = account_total.checked_add(total).ok_or_else(|| {
                    QorcError::InvalidArgument("Database quota overflow".to_string())
                })?;
                store_totals.insert(store, total);
            }
        }

        usage.initialized = true;
        usage.data_version = data_version;
        usage.account_total = account_total;
        usage.store_totals = store_totals;

        Ok(())
    }

    fn row_context(store: &str, key: &str) -> Zeroizing<Vec<u8>> {
        let mut context = Zeroizing::new(Vec::with_capacity(24 + store.len() + key.len()));
        context.extend_from_slice(crate::protocol_keys::DATABASE_ROW);
        context.extend_from_slice(&(store.len() as u32).to_be_bytes());
        context.extend_from_slice(store.as_bytes());
        context.extend_from_slice(&(key.len() as u32).to_be_bytes());
        context.extend_from_slice(key.as_bytes());
        context
    }

    fn encrypt_bundle(&self, store: &str, key: &str, value: &[u8]) -> QorcResult<Vec<u8>> {
        let nonce_bytes = Zeroizing::new(random_bytes(24)?);
        let nonce: &[u8; 24] = nonce_bytes.as_slice().try_into().unwrap();
        let row_context = Self::row_context(store, key);

        let mut masked = Zeroizing::new(value.to_vec());
        let mut shake_input = Zeroizing::new(Vec::with_capacity(
            self.k_quant.len() + nonce.len() + row_context.len(),
        ));
        shake_input.extend_from_slice(&self.k_quant[..]);
        shake_input.extend_from_slice(nonce);
        shake_input.extend_from_slice(&row_context);
        let keystream = Zeroizing::new(shake256(&shake_input, value.len()));
        for i in 0..value.len() {
            masked[i] ^= keystream[i];
        }

        // Encrypt with XChaCha20-Poly1305
        let ciphertext = xchacha_encrypt(&self.k_sym, nonce, &masked, &row_context)?;

        let mut bundle = Vec::with_capacity(24 + ciphertext.len());
        bundle.extend_from_slice(nonce);
        bundle.extend_from_slice(&ciphertext);
        Ok(bundle)
    }

    /// Write
    pub fn set_secure(&self, store: &str, key: &str, value: &[u8]) -> QorcResult<()> {
        let bundle = self.encrypt_bundle(store, key, value)?;

        // Save
        let conn = self.conn.lock();
        let now = chrono::Utc::now().timestamp_millis();
        conn.execute(
            "INSERT INTO kv_data (store, key, value, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?) 
             ON CONFLICT(store, key) DO UPDATE SET 
                value = excluded.value, 
                updated_at = excluded.updated_at",
            params![store, key, bundle, now, now],
        )
        .map_err(|e| QorcError::EncryptionFailed(format!("DB save failed: {}", e)))?;
        drop(conn);
        self.invalidate_quota_usage();

        Ok(())
    }

    pub fn set_secure_with_store_quota(
        &self,
        store: &str,
        key: &str,
        value: &[u8],
        max_store_bytes: u64,
    ) -> QorcResult<bool> {
        let bundle = self.encrypt_bundle(store, key, value)?;
        let bundle_len = i64::try_from(bundle.len())
            .map_err(|_| QorcError::InvalidArgument("Database value too large".to_string()))?;
        let max_bytes = i64::try_from(max_store_bytes)
            .map_err(|_| QorcError::InvalidArgument("Database quota too large".to_string()))?;

        let mut conn = self.conn.lock();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| QorcError::EncryptionFailed(format!("DB transaction failed: {}", e)))?;
        let mut usage = self.quota_usage.lock();
        Self::refresh_quota_usage(&transaction, &mut usage)?;
        let total_bytes = *usage.store_totals.get(store).unwrap_or(&0);
        let account_total_bytes = usage.account_total;
        let existing_bytes: i64 = transaction
            .query_row(
                "SELECT COALESCE(LENGTH(value), 0) FROM kv_data WHERE store = ? AND key = ?",
                params![store, key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| QorcError::EncryptionFailed(format!("DB quota query failed: {}", e)))?
            .unwrap_or(0);
        let next_total = total_bytes
            .saturating_sub(existing_bytes)
            .checked_add(bundle_len)
            .ok_or_else(|| QorcError::InvalidArgument("Database quota overflow".to_string()))?;
        let account_max_bytes = i64::try_from(DB_ACCOUNT_QUOTA_MAX_BYTES)
            .map_err(|_| QorcError::InvalidArgument("Database quota too large".to_string()))?;
        let next_account_total = account_total_bytes
            .saturating_sub(existing_bytes)
            .checked_add(bundle_len)
            .ok_or_else(|| QorcError::InvalidArgument("Database quota overflow".to_string()))?;
        if (next_total > max_bytes && next_total > total_bytes)
            || (next_account_total > account_max_bytes && next_account_total > account_total_bytes)
        {
            return Ok(false);
        }

        let now = chrono::Utc::now().timestamp_millis();
        transaction
            .execute(
                "INSERT INTO kv_data (store, key, value, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(store, key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at",
                params![store, key, bundle, now, now],
            )
            .map_err(|e| QorcError::EncryptionFailed(format!("DB quota save failed: {}", e)))?;
        transaction
            .commit()
            .map_err(|e| QorcError::EncryptionFailed(format!("DB commit failed: {}", e)))?;
        usage.account_total = next_account_total;
        if next_total == 0 {
            usage.store_totals.remove(store);
        } else {
            usage.store_totals.insert(store.to_string(), next_total);
        }
        Ok(true)
    }

    pub fn set_secure_batch(&self, entries: &[(&str, &str, &[u8])]) -> QorcResult<()> {
        self.mutate_secure_batch(entries, &[])
    }

    pub fn mutate_secure_batch(
        &self,
        entries: &[(&str, &str, &[u8])],
        deletions: &[(&str, &str)],
    ) -> QorcResult<()> {
        let encrypted = entries
            .iter()
            .map(|(store, key, value)| {
                self.encrypt_bundle(store, key, value)
                    .map(|bundle| ((*store).to_string(), (*key).to_string(), bundle))
            })
            .collect::<QorcResult<Vec<_>>>()?;
        let mut conn = self.conn.lock();
        let transaction = conn
            .transaction()
            .map_err(|e| QorcError::EncryptionFailed(format!("DB transaction failed: {}", e)))?;
        let now = chrono::Utc::now().timestamp_millis();
        for (store, key, bundle) in encrypted {
            transaction
                .execute(
                    "INSERT INTO kv_data (store, key, value, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT(store, key) DO UPDATE SET
                       value = excluded.value,
                       updated_at = excluded.updated_at",
                    params![store, key, bundle, now, now],
                )
                .map_err(|e| QorcError::EncryptionFailed(format!("DB batch save failed: {}", e)))?;
        }
        for (store, key) in deletions {
            transaction
                .execute(
                    "DELETE FROM kv_data WHERE store = ? AND key = ?",
                    params![store, key],
                )
                .map_err(|e| {
                    QorcError::EncryptionFailed(format!("DB batch delete failed: {}", e))
                })?;
        }
        transaction
            .commit()
            .map_err(|e| QorcError::EncryptionFailed(format!("DB commit failed: {}", e)))?;
        drop(conn);
        self.invalidate_quota_usage();
        Ok(())
    }

    pub fn mutate_secure_batch_with_quotas(
        &self,
        entries: &[(&str, &str, &[u8])],
        deletions: &[(&str, &str)],
    ) -> QorcResult<bool> {
        let mut mutation_targets = HashSet::with_capacity(entries.len() + deletions.len());
        for target in entries
            .iter()
            .map(|(store, key, _)| (*store, *key))
            .chain(deletions.iter().copied())
        {
            if !mutation_targets.insert(target) {
                return Err(QorcError::InvalidArgument(
                    "Duplicate database mutation target".to_string(),
                ));
            }
        }
        let encrypted = entries
            .iter()
            .map(|(store, key, value)| {
                self.encrypt_bundle(store, key, value)
                    .map(|bundle| ((*store).to_string(), (*key).to_string(), bundle))
            })
            .collect::<QorcResult<Vec<_>>>()?;
        let mut conn = self.conn.lock();
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| QorcError::EncryptionFailed(format!("DB transaction failed: {}", e)))?;
        let mut usage = self.quota_usage.lock();
        Self::refresh_quota_usage(&transaction, &mut usage)?;
        let account_total = usage.account_total;
        let mut stores = HashSet::new();
        for (store, _, _) in &encrypted {
            stores.insert(store.as_str());
        }
        for (store, _) in deletions {
            stores.insert(*store);
        }

        let mut removed_by_store = HashMap::<String, i64>::new();
        let mut removed_total = 0i64;
        for (store, key) in encrypted
            .iter()
            .map(|(store, key, _)| (store.as_str(), key.as_str()))
            .chain(deletions.iter().copied())
        {
            let existing: i64 = transaction
                .query_row(
                    "SELECT LENGTH(value) FROM kv_data WHERE store = ? AND key = ?",
                    params![store, key],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| QorcError::EncryptionFailed(format!("DB quota query failed: {}", e)))?
                .unwrap_or(0);
            removed_total = removed_total
                .checked_add(existing)
                .ok_or_else(|| QorcError::InvalidArgument("Database quota overflow".to_string()))?;
            *removed_by_store.entry(store.to_string()).or_default() += existing;
        }

        let mut added_by_store = HashMap::<String, i64>::new();
        let mut added_total = 0i64;
        for (store, _, bundle) in &encrypted {
            let length = i64::try_from(bundle.len())
                .map_err(|_| QorcError::InvalidArgument("Database value too large".to_string()))?;
            added_total = added_total
                .checked_add(length)
                .ok_or_else(|| QorcError::InvalidArgument("Database quota overflow".to_string()))?;
            *added_by_store.entry(store.clone()).or_default() += length;
        }

        let next_account_total = account_total
            .saturating_sub(removed_total)
            .checked_add(added_total)
            .ok_or_else(|| QorcError::InvalidArgument("Database quota overflow".to_string()))?;
        if next_account_total > DB_ACCOUNT_QUOTA_MAX_BYTES as i64
            && next_account_total > account_total
        {
            return Ok(false);
        }
        let mut next_store_totals = HashMap::with_capacity(stores.len());
        for store in stores {
            let current = *usage.store_totals.get(store).unwrap_or(&0);
            let removed = *removed_by_store.get(store).unwrap_or(&0);
            let added = *added_by_store.get(store).unwrap_or(&0);
            let next = current
                .saturating_sub(removed)
                .checked_add(added)
                .ok_or_else(|| QorcError::InvalidArgument("Database quota overflow".to_string()))?;
            let quota = if self.is_renderer_file_store(store) {
                DB_FILE_STORE_QUOTA_BYTES
            } else {
                DB_RENDERER_STORE_QUOTA_BYTES
            } as i64;
            if next > quota && next > current {
                return Ok(false);
            }
            next_store_totals.insert(store.to_string(), next);
        }

        let now = chrono::Utc::now().timestamp_millis();
        for (store, key, bundle) in encrypted {
            transaction
                .execute(
                    "INSERT INTO kv_data (store, key, value, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT(store, key) DO UPDATE SET
                       value = excluded.value,
                       updated_at = excluded.updated_at",
                    params![store, key, bundle, now, now],
                )
                .map_err(|e| QorcError::EncryptionFailed(format!("DB batch save failed: {}", e)))?;
        }
        for (store, key) in deletions {
            transaction
                .execute(
                    "DELETE FROM kv_data WHERE store = ? AND key = ?",
                    params![store, key],
                )
                .map_err(|e| {
                    QorcError::EncryptionFailed(format!("DB batch delete failed: {}", e))
                })?;
        }
        transaction
            .commit()
            .map_err(|e| QorcError::EncryptionFailed(format!("DB commit failed: {}", e)))?;
        usage.account_total = next_account_total;
        for (store, total) in next_store_totals {
            if total == 0 {
                usage.store_totals.remove(&store);
            } else {
                usage.store_totals.insert(store, total);
            }
        }
        Ok(true)
    }

    /// Read
    pub fn get_secure(&self, store: &str, key: &str) -> QorcResult<Option<Zeroizing<Vec<u8>>>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT value FROM kv_data WHERE store = ? AND key = ?")
            .map_err(|e| QorcError::DecryptionFailed(format!("DB query failed: {}", e)))?;

        let bundle: Option<Vec<u8>> = stmt
            .query_row(params![store, key], |row| row.get(0))
            .optional()
            .map_err(|e| QorcError::DecryptionFailed(format!("DB read failed: {}", e)))?;

        bundle
            .map(|bundle| self.decrypt_bundle(store, key, &bundle))
            .transpose()
    }

    /// Check whether an encrypted row exists without decrypting or copying its value
    pub fn has_secure(&self, store: &str, key: &str) -> QorcResult<bool> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM kv_data WHERE store = ? AND key = ?)",
            params![store, key],
            |row| row.get(0),
        )
        .map_err(|e| QorcError::DecryptionFailed(format!("DB existence query failed: {}", e)))
    }

    /// Decrypt bundle
    fn decrypt_bundle(
        &self,
        store: &str,
        key: &str,
        bundle: &[u8],
    ) -> QorcResult<Zeroizing<Vec<u8>>> {
        if bundle.len() < 24 + 16 {
            return Err(QorcError::DecryptionFailed(
                "Invalid bundle size".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = bundle.split_at(24);
        let nonce: &[u8; 24] = nonce_bytes.try_into().unwrap();
        let row_context = Self::row_context(store, key);

        // Decrypt XChaCha20
        let masked = Zeroizing::new(xchacha_decrypt(
            &self.k_sym,
            nonce,
            ciphertext,
            &row_context,
        )?);

        let mut plaintext = Zeroizing::new(masked.to_vec());
        let mut shake_input = Zeroizing::new(Vec::with_capacity(
            self.k_quant.len() + nonce.len() + row_context.len(),
        ));
        shake_input.extend_from_slice(&self.k_quant[..]);
        shake_input.extend_from_slice(nonce);
        shake_input.extend_from_slice(&row_context);
        let keystream = Zeroizing::new(shake256(&shake_input, masked.len()));
        for i in 0..masked.len() {
            plaintext[i] ^= keystream[i];
        }

        Ok(plaintext)
    }

    /// Enumerate only record selectors
    pub fn list_keys(&self, store: &str, max_entries: usize) -> QorcResult<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT key FROM kv_data WHERE store = ? ORDER BY key LIMIT ?")
            .map_err(|e| QorcError::DecryptionFailed(format!("DB query failed: {}", e)))?;

        let rows = stmt
            .query_map(params![store, max_entries.saturating_add(1)], |row| {
                row.get(0)
            })
            .map_err(|e| QorcError::DecryptionFailed(format!("DB read failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| QorcError::DecryptionFailed(e.to_string()))?);
        }
        if results.len() > max_entries {
            return Err(QorcError::InvalidArgument(
                "Database enumeration limit exceeded".to_string(),
            ));
        }
        Ok(results)
    }

    pub fn scan_keys(
        &self,
        store_prefix: &str,
        max_entries: usize,
    ) -> QorcResult<Vec<(String, String)>> {
        let conn = self.conn.lock();
        let pattern = format!("{}%", escape_like(store_prefix));
        let mut stmt = conn
            .prepare(
                "SELECT store, key FROM kv_data
                 WHERE store LIKE ? ESCAPE '\\'
                 ORDER BY store, key LIMIT ?",
            )
            .map_err(|e| QorcError::DecryptionFailed(format!("DB query failed: {}", e)))?;

        let rows = stmt
            .query_map(params![pattern, max_entries.saturating_add(1)], |row| {
                let store: String = row.get(0)?;
                let key: String = row.get(1)?;
                Ok((store, key))
            })
            .map_err(|e| QorcError::DecryptionFailed(format!("DB read failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| QorcError::DecryptionFailed(e.to_string()))?);
        }
        if results.len() > max_entries {
            return Err(QorcError::InvalidArgument(
                "Database enumeration limit exceeded".to_string(),
            ));
        }
        Ok(results)
    }

    /// Delete a key
    pub fn delete(&self, store: &str, key: &str) -> QorcResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM kv_data WHERE store = ? AND key = ?",
            params![store, key],
        )
        .map_err(|e| QorcError::StorageInitFailed(format!("DB delete failed: {}", e)))?;
        drop(conn);
        self.invalidate_quota_usage();
        Ok(())
    }
}

// Tauri Commands --

pub(crate) async fn prepare_native_account_database(
    app_handle: AppHandle,
    account_owner: &str,
    master_key: &[u8; 32],
) -> Result<Arc<DatabaseManager>, String> {
    if account_owner.len() != 64
        || !account_owner
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("Invalid database account owner".to_string());
    }
    let account_namespace = account_namespace(account_owner);
    let account_file_id = account_file_id(master_key, account_owner);

    let mut app_config_dir = app_handle
        .path()
        .app_config_dir()
        .map_err(|_| "Application storage path unavailable".to_string())?;
    let instance_id = crate::system::get_instance_id().map_err(|error| error.safe_message())?;
    #[cfg(target_os = "android")]
    {
        app_config_dir = tokio::fs::canonicalize(app_config_dir).await
            .map_err(|_| "Application storage path unavailable".to_string())?;
        app_config_dir = app_config_dir.join("instances").join(&instance_id).join("config");
    }
    #[cfg(not(target_os = "android"))]
    {
        let suffix = format!("-instance-{}", instance_id);
        let config_name = app_config_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "Application storage path is invalid".to_string())?
            .to_owned();
        app_config_dir.set_file_name(format!("{}{}", config_name, suffix));
    }
    crate::storage::file::check_dir(&app_config_dir, 0o700)
        .await
        .map_err(|error| error.safe_message())?;

    let db_path = app_config_dir.join(format!("qorc_{}.db", account_file_id));
    let managed_paths = database_managed_paths(&db_path);
    validate_existing_database_paths(&managed_paths)
        .await
        .map_err(|error| error.safe_message())?;
    let owned_master = Zeroizing::new(*master_key);
    let mut db_manager =
        tokio::task::spawn_blocking(move || DatabaseManager::new(db_path, owned_master.as_slice()))
            .await
            .map_err(|_| "Database initialization task failed".to_string())?
            .map_err(|error| error.safe_message())?;
    secure_database_paths(&managed_paths)
        .await
        .map_err(|error| error.safe_message())?;
    db_manager.set_account_context(format!("{}_", account_namespace), account_owner.to_string());

    Ok(Arc::new(db_manager))
}

#[tauri::command]
pub async fn db_lock(account_owner: String, state: State<'_, AppState>) -> Result<bool, String> {
    if account_owner.len() != 64
        || !account_owner
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("Invalid database account owner".to_string());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let owner_matches = state
        .inner()
        .database()
        .is_some_and(|database| database.account_owner() == account_owner);
    if !owner_matches {
        return Ok(false);
    }

    let signal_handler = state.inner().signal_handler();
    let _signal_lifecycle_guard = if let Some(handler) = signal_handler.as_ref() {
        Some(handler.acquire_lifecycle_lock().await)
    } else {
        None
    };
    if let Some(handler) = signal_handler.as_ref() {
        handler.clear_all();
    }
    let mut db_state = state.inner().database.write();
    *db_state = None;
    Ok(true)
}

const DB_NAME_MAX_LEN: usize = 256;
const DB_VALUE_MAX_BYTES: usize = 128 * 1024 * 1024;
const DB_FILE_STORE_QUOTA_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const DB_RENDERER_STORE_QUOTA_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DB_ACCOUNT_QUOTA_MAX_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const DB_ENUMERATION_MAX_ENTRIES: usize = 10_000;
const DB_MUTATION_MAX_WRITES: usize = 512;
const DB_MUTATION_MAX_DELETIONS: usize = 2_048;
const DB_MUTATION_MAX_TOTAL_VALUE_BYTES: usize = 128 * 1024 * 1024;
const DB_MUTATION_MAX_JSON_BYTES: usize = 180 * 1024 * 1024;
const DB_MUTATION_MAX_STRUCTURAL_TOKENS: usize = 14_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbMutationWrite {
    store: String,
    key: String,
    value_b64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbMutationDelete {
    store: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DbMutationRequest {
    writes: Vec<DbMutationWrite>,
    deletions: Vec<DbMutationDelete>,
}

fn parse_db_mutation_request(mutation_json: &str) -> Result<DbMutationRequest, String> {
    if mutation_json.len() > DB_MUTATION_MAX_JSON_BYTES {
        return Err("Database mutation limit exceeded".to_string());
    }
    crate::json_bounds::enforce_bounded_json_structure(
        mutation_json.as_bytes(),
        3,
        DB_MUTATION_MAX_STRUCTURAL_TOKENS,
        DB_VALUE_MAX_BYTES.div_ceil(3) * 4,
    )
    .map_err(|_| "Invalid database mutation".to_string())?;
    serde_json::from_str(mutation_json).map_err(|_| "Invalid database mutation".to_string())
}

fn decode_db_value(value_b64: String) -> Result<Zeroizing<Vec<u8>>, String> {
    use base64::Engine as _;

    let value_b64 = Zeroizing::new(value_b64);
    let max_chars = DB_VALUE_MAX_BYTES.div_ceil(3) * 4;
    if value_b64.is_empty()
        || value_b64.len() > max_chars
        || !value_b64.len().is_multiple_of(4)
        || !value_b64.is_ascii()
    {
        return Err("Invalid database value encoding".to_string());
    }
    let value = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(value_b64.as_bytes())
            .map_err(|_| "Invalid database value encoding".to_string())?,
    );
    if value.len() > DB_VALUE_MAX_BYTES
        || base64::engine::general_purpose::STANDARD.encode(value.as_slice()) != value_b64.as_str()
    {
        return Err("Invalid database value encoding".to_string());
    }
    Ok(value)
}

fn account_namespace(username: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::protocol_keys::DATABASE_OWNER);
    hasher.update(username.as_bytes());
    hasher.finalize().to_hex().to_string()
}

pub(crate) fn account_file_id(master_key: &[u8], username: &str) -> String {
    let key: &[u8; 32] = master_key
        .try_into()
        .expect("account master key was validated before filename derivation");
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(crate::protocol_keys::NATIVE_DATABASE_FILENAME);
    hasher.update(username.as_bytes());
    blake3::Hasher::finalize(&hasher).to_hex().to_string()
}

fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c == '\\' || c == '%' || c == '_' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn db_name_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= DB_NAME_MAX_LEN && !name.chars().any(|c| c.is_control())
}

fn reject_db_name() -> String {
    log::warn!("[database] rejected invalid store/key name");
    "Invalid store or key name".to_string()
}

async fn run_database_task<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> QorcResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|_| "Database operation task failed".to_string())?
        .map_err(|error| error.safe_message())
}

/// Set a secure key
#[tauri::command]
pub async fn db_set_secure(
    state: State<'_, AppState>,
    store: String,
    key: String,
    value_b64: String,
) -> Result<bool, String> {
    let value = decode_db_value(value_b64)?;
    if !db_name_valid(&store) || !db_name_valid(&key) {
        return Err(reject_db_name());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if !db.renderer_store_allowed(&store) {
        return Err(reject_db_name());
    }
    let store_quota = if db.is_renderer_file_store(&store) {
        DB_FILE_STORE_QUOTA_BYTES
    } else {
        DB_RENDERER_STORE_QUOTA_BYTES
    };
    let stored = run_database_task(move || {
        db.set_secure_with_store_quota(&store, &key, &value, store_quota)
    })
    .await?;
    if !stored {
        return Err("Database quota exceeded".to_string());
    }
    Ok(true)
}

/// Get a secure key
#[tauri::command]
pub async fn db_get_secure(
    state: State<'_, AppState>,
    store: String,
    key: String,
) -> Result<Option<String>, String> {
    if !db_name_valid(&store) || !db_name_valid(&key) {
        return Err(reject_db_name());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if !db.renderer_store_allowed(&store) {
        return Err(reject_db_name());
    }
    let value = run_database_task(move || db.get_secure(&store, &key)).await?;
    Ok(value.map(|bytes| {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes.as_slice())
    }))
}

/// Check whether a secure key exists without returning or decrypting its value.
#[tauri::command]
pub async fn db_has_secure(
    state: State<'_, AppState>,
    store: String,
    key: String,
) -> Result<bool, String> {
    if !db_name_valid(&store) || !db_name_valid(&key) {
        return Err(reject_db_name());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if !db.renderer_store_allowed(&store) {
        return Err(reject_db_name());
    }
    run_database_task(move || db.has_secure(&store, &key)).await
}

/// List bounded key selectors without decrypting or returning every value.
#[tauri::command]
pub async fn db_list_secure_keys(
    state: State<'_, AppState>,
    store: String,
) -> Result<Vec<String>, String> {
    if !db_name_valid(&store) {
        return Err(reject_db_name());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if !db.renderer_store_allowed(&store) {
        return Err(reject_db_name());
    }
    run_database_task(move || db.list_keys(&store, DB_ENUMERATION_MAX_ENTRIES)).await
}

#[tauri::command]
pub async fn db_scan_secure_keys(
    state: State<'_, AppState>,
    prefix: String,
) -> Result<Vec<(String, String)>, String> {
    if !db_name_valid(&prefix) {
        return Err(reject_db_name());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if !db.in_namespace(&prefix) {
        return Err(reject_db_name());
    }
    run_database_task(move || {
        let mut selectors = db.scan_keys(&prefix, DB_ENUMERATION_MAX_ENTRIES)?;
        selectors.retain(|(store, _)| db.renderer_store_allowed(store));
        Ok(selectors)
    })
    .await
}

#[tauri::command]
pub async fn db_mutate_secure(
    state: State<'_, AppState>,
    mutation_json: String,
) -> Result<bool, String> {
    let DbMutationRequest { writes, deletions } = parse_db_mutation_request(&mutation_json)?;
    if writes.is_empty() && deletions.is_empty() {
        return Err("Empty database mutation".to_string());
    }
    if writes.len() > DB_MUTATION_MAX_WRITES || deletions.len() > DB_MUTATION_MAX_DELETIONS {
        return Err("Database mutation limit exceeded".to_string());
    }

    let mut targets = HashSet::with_capacity(writes.len() + deletions.len());
    let mut decoded_writes = Vec::with_capacity(writes.len());
    let mut total_value_bytes = 0usize;
    for write in writes {
        if !db_name_valid(&write.store) || !db_name_valid(&write.key) {
            return Err(reject_db_name());
        }
        if !targets.insert((write.store.clone(), write.key.clone())) {
            return Err("Duplicate database mutation target".to_string());
        }
        let value = decode_db_value(write.value_b64)?;
        total_value_bytes = total_value_bytes
            .checked_add(value.len())
            .ok_or_else(|| "Database mutation limit exceeded".to_string())?;
        if total_value_bytes > DB_MUTATION_MAX_TOTAL_VALUE_BYTES {
            return Err("Database mutation limit exceeded".to_string());
        }
        decoded_writes.push((write.store, write.key, value));
    }

    let mut decoded_deletions = Vec::with_capacity(deletions.len());
    for deletion in deletions {
        if !db_name_valid(&deletion.store) || !db_name_valid(&deletion.key) {
            return Err(reject_db_name());
        }
        if !targets.insert((deletion.store.clone(), deletion.key.clone())) {
            return Err("Duplicate database mutation target".to_string());
        }
        decoded_deletions.push((deletion.store, deletion.key));
    }

    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if decoded_writes
        .iter()
        .any(|(store, _, _)| !db.renderer_store_allowed(store))
        || decoded_deletions
            .iter()
            .any(|(store, _)| !db.renderer_store_allowed(store))
    {
        return Err(reject_db_name());
    }

    let committed = run_database_task(move || {
        let write_refs = decoded_writes
            .iter()
            .map(|(store, key, value)| (store.as_str(), key.as_str(), value.as_slice()))
            .collect::<Vec<_>>();
        let deletion_refs = decoded_deletions
            .iter()
            .map(|(store, key)| (store.as_str(), key.as_str()))
            .collect::<Vec<_>>();
        db.mutate_secure_batch_with_quotas(&write_refs, &deletion_refs)
    })
    .await?;
    Ok(committed)
}

/// Delete a key
#[tauri::command]
pub async fn db_delete(
    state: State<'_, AppState>,
    store: String,
    key: String,
) -> Result<bool, String> {
    if !db_name_valid(&store) || !db_name_valid(&key) {
        return Err(reject_db_name());
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    if !db.renderer_store_allowed(&store) {
        return Err(reject_db_name());
    }
    run_database_task(move || db.delete(&store, &key)).await?;
    Ok(true)
}
