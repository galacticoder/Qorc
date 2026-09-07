//! Secure Storage Commands

use tauri::State;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::state::AppState;

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
pub async fn secure_get(key: String, state: State<'_, AppState>) -> Result<Option<String>, String> {
    let key = Zeroizing::new(key);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
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
pub async fn secure_remove(key: String, state: State<'_, AppState>) -> Result<bool, String> {
    let key = Zeroizing::new(key);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
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
pub async fn secure_has(key: String, state: State<'_, AppState>) -> Result<bool, String> {
    let key = Zeroizing::new(key);
    if !secure_key_allowed(&key) {
        return Err(reject_secure_key(&key));
    }
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    storage.has(&key).await.map_err(|e| e.safe_message())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_known_exact_and_prefixed_keys() {
        assert!(!secure_key_allowed("last_authenticated_username"));
        assert!(!secure_key_allowed(&format!(
            "qorc_token_vault:{}",
            "a".repeat(64)
        )));
        assert!(!secure_key_allowed(&format!(
            "qorc_token_vault:{}",
            "A".repeat(64)
        )));
        assert!(!secure_key_allowed("qorc_token_vault"));
        assert!(!secure_key_allowed("vault:alice"));
        assert!(!secure_key_allowed(&format!("vault:{}", "a".repeat(64))));
        assert!(!secure_key_allowed(&format!("wmk:{}", "a".repeat(64))));
        assert!(!secure_key_allowed(&format!("key_meta:{}", "a".repeat(64))));
        assert!(!secure_key_allowed(&format!(
            "key_bundle:{}",
            "a".repeat(64)
        )));
        assert!(secure_key_allowed(&format!(
            "{}{}",
            crate::storage_keys::PRIVACY_PASS_TOKEN_PREFIX,
            "a".repeat(64)
        )));
        for prefix in [
            crate::storage_keys::KEY_TRANSPARENCY_HEAD_PREFIX,
            crate::storage_keys::KEY_TRANSPARENCY_INCIDENT_PREFIX,
            crate::storage_keys::KEY_TRANSPARENCY_CONTACT_PREFIX,
            crate::storage_keys::KEY_TRANSPARENCY_WARNING_PREFIX,
            crate::storage_keys::KEY_TRANSPARENCY_MONITOR_PREFIX,
            crate::storage_keys::SPOOL_CONSUMED_PROBES_PREFIX,
            crate::storage_keys::SPOOL_DETECTION_PREFIX,
            crate::storage_keys::SPOOL_PEER_DETECTION_PREFIX,
            crate::storage_keys::DISCOVERY_MATERIAL_PREFIX,
        ] {
            assert!(secure_key_allowed(&format!("{prefix}{}", "a".repeat(64))));
            assert!(!secure_key_allowed(&format!("{prefix}{}", "A".repeat(64))));
            assert!(!secure_key_allowed(&format!("{prefix}{}", "a".repeat(63))));
        }
        assert!(secure_key_allowed(&format!(
            "{}{}",
            crate::storage_keys::LAST_AUTH_USER_PREFIX,
            "a".repeat(64)
        )));
        assert!(secure_key_allowed(&format!(
            "{}{}",
            crate::storage_keys::LAST_AUTH_DISPLAY_PREFIX,
            "a".repeat(64)
        )));
        assert!(secure_key_allowed(&format!(
            "{}{}",
            crate::storage_keys::PEER_CERTIFICATE_PREFIX,
            "a".repeat(64)
        )));
        assert!(secure_key_allowed(&format!(
            "{}{}",
            crate::storage_keys::PRIVATE_AUTH_SLOT_PREFIX,
            "a".repeat(64)
        )));
        assert!(secure_key_allowed(&format!(
            "{}{}",
            crate::storage_keys::REGISTRATION_ATTEMPT_PREFIX,
            "a".repeat(64)
        )));
        assert!(!secure_key_allowed(&format!(
            "{}0123456789abcdef",
            crate::storage_keys::PRIVATE_AUTH_SLOT_PREFIX
        )));
        assert!(secure_key_allowed(crate::storage_keys::SERVER_PQ_PIN));
        assert!(!secure_key_allowed(
            crate::storage_keys::PRIVACY_PASS_TOKEN_PREFIX
        ));
        assert!(!secure_key_allowed("vault:"));
        assert!(!secure_key_allowed("vault:../../escape"));
        assert!(!secure_key_allowed("rtc:alice"));
    }

    #[test]
    fn rejects_unknown_empty_and_oversized_keys() {
        assert!(!secure_key_allowed(""));
        assert!(!secure_key_allowed("arbitrary_attacker_key"));
        assert!(!secure_key_allowed("../escape"));
        assert!(!secure_key_allowed(&"x".repeat(SECURE_KEY_MAX_LEN + 1)));
    }
}
