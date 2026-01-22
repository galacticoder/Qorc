//! Native Encrypted Database Module
//!
//! Triple Hybrid Encryption
//! 1. SQLCipher (AES-256) - Page Layer
//! 2. XChaCha20-Poly1305 - Symmetric Layer
//! 3. SHAKE256 - Quantum Masking Layer

use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;
use tauri::{Manager, State, AppHandle};

use crate::error::{QorError, QorResult};
use crate::state::AppState;
use crate::crypto::aead::{xchacha_encrypt, xchacha_decrypt};
use crate::crypto::hash::{shake256, hkdf_sha3_derive};
use crate::crypto::random::random_bytes;

pub struct DatabaseManager {
    /// SQLite connection
    conn: Mutex<Connection>,
    /// Independent key for XChaCha20 layer
    k_sym: Zeroizing<[u8; 32]>,
    /// Independent key for SHAKE256 layer
    k_quant: Zeroizing<[u8; 32]>,
}

impl DatabaseManager {
    /// Initialize a new native encrypted database
    pub fn new(db_path: PathBuf, master_key: &[u8]) -> QorResult<Self> {
        Self::open_impl(db_path, master_key, 0)
    }

    fn open_impl(db_path: PathBuf, master_key: &[u8], retry_count: u8) -> QorResult<Self> {
        // Derive triple keys from master key
        let k_disk = hkdf_sha3_derive(master_key, b"db_salt_disk", b"QDBv1/DISK", 32);
        let k_sym_raw = hkdf_sha3_derive(master_key, b"db_salt_sym", b"QDBv1/SYM", 32);
        let k_quant_raw = hkdf_sha3_derive(master_key, b"db_salt_quant", b"QDBv1/QUANT", 32);

        let mut k_sym = [0u8; 32];
        k_sym.copy_from_slice(&k_sym_raw);
        let mut k_quant = [0u8; 32];
        k_quant.copy_from_slice(&k_quant_raw);

        // Open connection


        let conn = Connection::open(&db_path)
            .map_err(|e| QorError::StorageInitFailed(format!("Failed to open DB: {}", e)))?;

        // Apply SQLCipher key
        let key_hex = hex::encode(k_disk);
        if let Err(e) = conn.execute_batch(&format!("PRAGMA key = \"x'{}'\"", key_hex)) {
             return Self::handle_init_error(conn, db_path, master_key, retry_count, e.to_string());
        }

        if let Err(e) = conn.pragma_update(None, "journal_mode", &"WAL") {
             return Self::handle_init_error(conn, db_path, master_key, retry_count, e.to_string());
        }

        if let Err(e) = conn.pragma_update(None, "synchronous", &"NORMAL") {
             return Self::handle_init_error(conn, db_path, master_key, retry_count, e.to_string());
        }

        // Initialize schema
        if let Err(e) = Self::ensure_schema(&conn) {
             return Self::handle_init_error(conn, db_path, master_key, retry_count, e.to_string());
        }

        Ok(Self {
            conn: Mutex::new(conn),
            k_sym: Zeroizing::new(k_sym),
            k_quant: Zeroizing::new(k_quant),
        })
    }

    /// Handle initialization errors by isolating unreadable files and retrying
    fn handle_init_error(
        conn: Connection, 
        db_path: PathBuf, 
        master_key: &[u8], 
        retry_count: u8, 
        err_msg: String
    ) -> QorResult<Self> {
        if err_msg.contains("file is not a database") && retry_count < 2 {
            // Close connection
            drop(conn);
            
            let timestamp = chrono::Utc::now().timestamp();
            let corrupt_path = db_path.with_extension(format!("db.corrupt.{}", timestamp));
            
            if let Err(rename_err) = std::fs::rename(&db_path, &corrupt_path) {
                return Err(QorError::StorageInitFailed(format!("Recovery failed: {}", rename_err)));
            }
            
            // Retry opening
            return Self::open_impl(db_path, master_key, retry_count + 1);
        }

        Err(QorError::StorageInitFailed(format!("DB Init failed: {}", err_msg)))
    }

    fn ensure_schema(conn: &Connection) -> QorResult<()> {
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
        ).map_err(|e| QorError::StorageInitFailed(format!("Schema init failed: {}", e)))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS secure_keys (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
            [],
        ).map_err(|e| QorError::StorageInitFailed(format!("Schema init failed: {}", e)))?;

        Ok(())
    }

    /// Write
    pub fn set_secure(&self, store: &str, key: &str, value: &[u8]) -> QorResult<()> {
        // Generate Nonce
        let nonce_bytes = random_bytes(24);
        let nonce: &[u8; 24] = nonce_bytes.as_slice().try_into().unwrap();

        // Generate keystream of same length as value
        let mut masked = value.to_vec();
        let keystream = shake256(&[&self.k_quant[..], &nonce[..]].concat(), value.len());
        for i in 0..value.len() {
            masked[i] ^= keystream[i];
        }

        // Encrypt with XChaCha20-Poly1305
        let ciphertext = xchacha_encrypt(&*self.k_sym, nonce, &masked, b"QDBv1/LAYER2")?;

        let mut bundle = Vec::with_capacity(24 + ciphertext.len());
        bundle.extend_from_slice(nonce);
        bundle.extend_from_slice(&ciphertext);

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
        ).map_err(|e| QorError::EncryptionFailed(format!("DB save failed: {}", e)))?;

        Ok(())
    }

    /// Read
    pub fn get_secure(&self, store: &str, key: &str) -> QorResult<Option<Vec<u8>>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT value FROM kv_data WHERE store = ? AND key = ?")
            .map_err(|e| QorError::DecryptionFailed(format!("DB query failed: {}", e)))?;
        
        let bundle: Option<Vec<u8>> = stmt.query_row(params![store, key], |row| row.get(0))
            .optional()
            .map_err(|e| QorError::DecryptionFailed(format!("DB read failed: {}", e)))?;

        bundle.map(|b| self.decrypt_bundle(&b)).transpose()
    }

    /// Decrypt bundle
    fn decrypt_bundle(&self, bundle: &[u8]) -> QorResult<Vec<u8>> {
        if bundle.len() < 24 + 16 {
            return Err(QorError::DecryptionFailed("Invalid bundle size".to_string()));
        }

        let (nonce_bytes, ciphertext) = bundle.split_at(24);
        let nonce: &[u8; 24] = nonce_bytes.try_into().unwrap();

        // Decrypt XChaCha20
        let masked = xchacha_decrypt(&*self.k_sym, nonce, ciphertext, b"QDBv1/LAYER2")?;

        // SHAKE256 unmasking
        let mut plaintext = masked.clone();
        let keystream = shake256(&[&self.k_quant[..], &nonce[..]].concat(), masked.len());
        for i in 0..masked.len() {
            plaintext[i] ^= keystream[i];
        }

        Ok(plaintext)
    }

    /// List all keys in a store
    pub fn list_secure(&self, store: &str) -> QorResult<Vec<(String, Vec<u8>)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key, value FROM kv_data WHERE store = ?")
            .map_err(|e| QorError::DecryptionFailed(format!("DB query failed: {}", e)))?;
        
        let rows = stmt.query_map(params![store], |row| {
            let key: String = row.get(0)?;
            let bundle: Vec<u8> = row.get(1)?;
            Ok((key, bundle))
        }).map_err(|e| QorError::DecryptionFailed(format!("DB read failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            let (key, bundle) = row.map_err(|e| QorError::DecryptionFailed(e.to_string()))?;
            if let Ok(plaintext) = self.decrypt_bundle(&bundle) {
                results.push((key, plaintext));
            }
        }
        Ok(results)
    }

    /// Scan all keys in a store
    pub fn scan_secure(&self, store_prefix: &str) -> QorResult<Vec<(String, String, Vec<u8>)>> {
        let conn = self.conn.lock();
        let pattern = format!("{}%", store_prefix);
        let mut stmt = conn.prepare("SELECT store, key, value FROM kv_data WHERE store LIKE ?")
            .map_err(|e| QorError::DecryptionFailed(format!("DB query failed: {}", e)))?;
        
        let rows = stmt.query_map(params![pattern], |row| {
            let store: String = row.get(0)?;
            let key: String = row.get(1)?;
            let bundle: Vec<u8> = row.get(2)?;
            Ok((store, key, bundle))
        }).map_err(|e| QorError::DecryptionFailed(format!("DB read failed: {}", e)))?;

        let mut results = Vec::new();
        for row in rows {
            let (store, key, bundle) = row.map_err(|e| QorError::DecryptionFailed(e.to_string()))?;
            if let Ok(plaintext) = self.decrypt_bundle(&bundle) {
                results.push((store, key, plaintext));
            }
        }
        Ok(results)
    }

    /// Delete a key
    pub fn delete(&self, store: &str, key: &str) -> QorResult<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM kv_data WHERE store = ? AND key = ?", params![store, key])
            .map_err(|e| QorError::StorageInitFailed(format!("DB delete failed: {}", e)))?;
        Ok(())
    }

}

// Tauri Commands --

/// Initialize database
#[tauri::command]
pub async fn db_init(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    username: String,
    master_key_b64: String,
) -> Result<bool, String> {
    let master_key = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, master_key_b64)
        .map_err(|_| "Invalid master key encoding".to_string())?;

    let app_config_dir = app_handle.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&app_config_dir).map_err(|e| e.to_string())?;
    
    let sanitized_user = username.replace(|c: char| !c.is_alphanumeric(), "_");
    let db_path = app_config_dir.join(format!("qor_{}.db", sanitized_user));

    let db_manager = DatabaseManager::new(db_path, &master_key)
        .map_err(|e| e.to_string())?;

    let mut db_state = state.inner().database.write();
    *db_state = Some(Arc::new(db_manager));

    Ok(true)
}

/// Set a secure key
#[tauri::command]
pub async fn db_set_secure(
    state: State<'_, AppState>,
    store: String,
    key: String,
    value: Vec<u8>,
) -> Result<bool, String> {
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    db.set_secure(&store, &key, &value).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Get a secure key
#[tauri::command]
pub async fn db_get_secure(
    state: State<'_, AppState>,
    store: String,
    key: String,
) -> Result<Option<Vec<u8>>, String> {
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    db.get_secure(&store, &key).map_err(|e| e.to_string()).map(Ok)?
}

/// List all keys in a store
#[tauri::command]
pub async fn db_list_secure(
    state: State<'_, AppState>,
    store: String,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    db.list_secure(&store).map_err(|e| e.to_string())
}

/// Scan all keys in a store
#[tauri::command]
pub async fn db_scan_secure(
    state: State<'_, AppState>,
    prefix: String,
) -> Result<Vec<(String, String, Vec<u8>)>, String> {
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    db.scan_secure(&prefix).map_err(|e| e.to_string())
}

/// Delete a key
#[tauri::command]
pub async fn db_delete(
    state: State<'_, AppState>,
    store: String,
    key: String,
) -> Result<bool, String> {
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    db.delete(&store, &key).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Clear a store
#[tauri::command]
pub async fn db_clear_store(
    state: State<'_, AppState>,
    store: String,
) -> Result<bool, String> {
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let conn = db.conn.lock();
    conn.execute("DELETE FROM kv_data WHERE store = ?", params![store])
        .map_err(|e| e.to_string())?;
    Ok(true)
}
