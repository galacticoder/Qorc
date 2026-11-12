//! Secure Storage Commands

use tauri::State;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::state::AppState;
use crate::local_account_data::AccountStorageOwnership;

const SECURE_KEY_MAX_LEN: usize = 512;
static SECURE_MUTATION_LOCK: Mutex<()> = Mutex::const_new(());

fn has_hex_256_suffix(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn secure_key_allowed(key: &str) -> bool {
    if key.is_empty() || key.len() > SECURE_KEY_MAX_LEN {
        return false;
    }
    if crate::storage_keys::RENDERER_EXACT_KEYS.contains(&key) {
        return true;
    }
    crate::storage_keys::RENDERER_SCOPED_PREFIXES
        .iter()
        .any(|prefix| has_hex_256_suffix(key, prefix))
}

fn reject_secure_key(_key: &str) -> String {
    log::warn!("[storage] rejected disallowed secure-storage key");
    "Disallowed storage key".to_string()
}

/// Get value from secure storage
#[tauri::command]
pub async fn secure_get(key: String, ownership: Option<AccountStorageOwnership>, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let key = Zeroizing::new(key);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
    let _account_guard = crate::local_account_data::cache_guard(state.inner(), &key, ownership.as_ref()).await?;
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    storage.get_text(&key).await.map_err(|e| e.safe_message())
}

/// Set value in secure storage
#[tauri::command]
pub async fn secure_set(
    key: String,
    value: String,
    ownership: Option<AccountStorageOwnership>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let key = Zeroizing::new(key);
    let value = Zeroizing::new(value);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
    if value.len() > crate::storage::SECURE_VALUE_MAX_BYTES {
        return Err("Storage value exceeds its size limit".to_string());
    }
    let _account_guard = crate::local_account_data::cache_guard(state.inner(), &key, ownership.as_ref()).await?;
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    let _mutation_guard = SECURE_MUTATION_LOCK.lock().await;
    storage
        .set_text(&key, &value)
        .await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}

/// Remove value from secure storage
#[tauri::command]
pub async fn secure_remove(key: String, ownership: Option<AccountStorageOwnership>, state: State<'_, AppState>) -> Result<bool, String> {
    let key = Zeroizing::new(key);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
    let _account_guard = crate::local_account_data::cache_guard(state.inner(), &key, ownership.as_ref()).await?;
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    let _mutation_guard = SECURE_MUTATION_LOCK.lock().await;
    storage
        .remove_item(&key)
        .await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}

/// Check if key exists in secure storage
#[tauri::command]
pub async fn secure_has(key: String, ownership: Option<AccountStorageOwnership>, state: State<'_, AppState>) -> Result<bool, String> {
    let key = Zeroizing::new(key);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
    let _account_guard = crate::local_account_data::cache_guard(state.inner(), &key, ownership.as_ref()).await?;
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    storage.has(&key).await.map_err(|e| e.safe_message())
}
