//! Signal Protocol Commands
//!
//! Tauri commands for Signal Protocol operations

use tauri::State;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::signal_protocol::{
    IdentityBundle, PreKey, SignedPreKey, KyberPreKey, PQKyberPreKey,
    PreKeyBundle, PreKeyBundleInput, EncryptedMessage,
};

/// Helper to run non Send futures
fn run_local<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::task::block_in_place(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create temporary runtime");
        rt.block_on(fut)
    })
}

/// Generate identity keys
#[tauri::command]
pub async fn signal_generate_identity(
    username: String,
    state: State<'_, AppState>,
) -> Result<IdentityBundle, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    let res = run_local(handler.generate_identity(&username))
        .map_err(|e| e.safe_message())?;

    // Save to DB if available
    if let Some(db) = state.inner().database() {
        let _ = run_local(handler.persist_to_db(db.as_ref(), &username));
    }

    Ok(res)
}

/// Generate pre-keys
#[tauri::command]
pub async fn signal_generate_prekeys(
    username: String,
    start_id: u32,
    count: u32,
    state: State<'_, AppState>,
) -> Result<Vec<PreKey>, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    let res = run_local(handler.generate_prekeys(&username, start_id, count))
        .map_err(|e| e.safe_message())?;

    if let Some(db) = state.inner().database() {
        let _ = run_local(handler.persist_to_db(db.as_ref(), &username));
    }

    Ok(res)
}

/// Generate signed pre-key
#[tauri::command]
pub async fn signal_generate_signed_prekey(
    username: String,
    key_id: u32,
    state: State<'_, AppState>,
) -> Result<SignedPreKey, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    let res = run_local(handler.generate_signed_prekey(&username, key_id))
        .map_err(|e| e.safe_message())?;

    if let Some(db) = state.inner().database() {
        let _ = run_local(handler.persist_to_db(db.as_ref(), &username));
    }

    Ok(res)
}

/// Generate Kyber pre-key
#[tauri::command]
pub async fn signal_generate_kyber_prekey(
    username: String,
    key_id: u32,
    state: State<'_, AppState>,
) -> Result<KyberPreKey, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.generate_kyber_prekey(&username, key_id))
        .map_err(|e| e.safe_message())
}

/// Generate PQ Kyber pre-key ML-KEM-1024
#[tauri::command]
pub async fn signal_generate_pq_kyber_prekey(
    username: String,
    key_id: u32,
    state: State<'_, AppState>,
) -> Result<PQKyberPreKey, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.generate_pq_kyber_prekey(&username, key_id))
        .map_err(|e| e.safe_message())
}

/// Create pre-key bundle for key exchange
#[tauri::command]
pub async fn signal_create_prekey_bundle(
    username: String,
    state: State<'_, AppState>,
) -> Result<PreKeyBundle, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.create_prekey_bundle(&username))
        .map_err(|e| e.safe_message())
}

/// Process received pre-key bundle to establish session
#[tauri::command]
pub async fn signal_process_prekey_bundle(
    self_username: String,
    peer_username: String,
    bundle: PreKeyBundleInput,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    let res = run_local(handler.process_prekey_bundle(&self_username, &peer_username, bundle))
        .map_err(|e| e.safe_message())?;

    if let Some(db) = state.inner().database() {
        let _ = run_local(handler.persist_to_db(db.as_ref(), &self_username));
    }

    Ok(res)
}

/// Check if session exists with peer
#[tauri::command]
pub async fn signal_has_session(
    self_username: String,
    peer_username: String,
    device_id: Option<u32>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.has_session(&self_username, &peer_username, device_id.unwrap_or(1)))
        .map_err(|e| e.safe_message())
}

/// Encrypt message
#[tauri::command]
pub async fn signal_encrypt(
    from_username: String,
    to_username: String,
    plaintext: String,
    state: State<'_, AppState>,
) -> Result<EncryptedMessage, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.encrypt(&from_username, &to_username, plaintext.as_bytes()))
        .map_err(|e| e.safe_message())
}

/// Decrypt response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResult {
    pub success: bool,
    pub plaintext: Option<String>,
    pub error: Option<String>,
    pub requires_key_refresh: Option<bool>,
}

/// Decrypt message
#[tauri::command]
pub async fn signal_decrypt(
    from_username: String,
    to_username: String,
    encrypted: EncryptedMessage,
    state: State<'_, AppState>,
) -> Result<DecryptResult, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    match run_local(handler.decrypt(&from_username, &to_username, &encrypted)) {
        Ok(plaintext) => Ok(DecryptResult {
            success: true,
            plaintext: Some(String::from_utf8_lossy(&plaintext).to_string()),
            error: None,
            requires_key_refresh: None,
        }),
        Err(e) => {
            log::warn!("[signal_decrypt] Decryption failed for {}: {}", to_username, e);
            Ok(DecryptResult {
                success: false,
                plaintext: None,
                error: Some(e.safe_message()),
                requires_key_refresh: Some(e.requires_key_refresh()),
            })
        },
    }
}

/// Delete session with peer
#[tauri::command]
pub async fn signal_delete_session(
    self_username: String,
    peer_username: String,
    device_id: Option<u32>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.delete_session(&self_username, &peer_username, device_id.unwrap_or(1)))
        .map_err(|e| e.safe_message())
}

/// Delete all sessions with peer
#[tauri::command]
pub async fn signal_delete_all_sessions(
    self_username: String,
    peer_username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.delete_all_sessions(&self_username, &peer_username))
        .map_err(|e| e.safe_message())
}

/// Set peers Kyber public key for PQ envelope encryption
#[tauri::command]
pub async fn signal_set_peer_kyber_key(
    peer_username: String,
    public_key: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    let mut key_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &public_key,
    ).map_err(|e| format!("Invalid base64: {}", e))?;
    
    // libsignal potential 1 byte header for Kyber keys
    if key_bytes.len() == 1569 {
        key_bytes = key_bytes[1..].to_vec();
    }

    handler.set_peer_kyber_key(&peer_username, key_bytes);
    Ok(true)
}

/// Check if peer Kyber key exists
#[tauri::command]
pub async fn signal_has_peer_kyber_key(
    peer_username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    Ok(handler.has_peer_kyber_key(&peer_username))
}

/// Trust peer identity
#[tauri::command]
pub async fn signal_trust_peer_identity(
    self_username: String,
    peer_username: String,
    device_id: Option<u32>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    run_local(handler.trust_peer_identity(&self_username, &peer_username, device_id.unwrap_or(1)))
        .map_err(|e| e.safe_message())
}

/// Set ML-KEM keys for user
#[tauri::command]
pub async fn signal_set_static_mlkem_keys(
    username: String,
    public_key: String,
    secret_key: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    
    let mut pub_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &public_key,
    ).map_err(|e| format!("Invalid public key base64: {}", e))?;
    
    let mut sec_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &secret_key,
    ).map_err(|e| format!("Invalid secret key base64: {}", e))?;
    
    // potential 1 byte header for Kyber keys
    if pub_bytes.len() == 1569 {
        pub_bytes = pub_bytes[1..].to_vec();
    }
    if sec_bytes.len() == 3169 {
        sec_bytes = sec_bytes[1..].to_vec();
    }
    
    run_local(handler.set_static_mlkem_keys(&username, pub_bytes, sec_bytes))
        .map_err(|e| e.safe_message())
}

/// Initialize Signal storage from database
#[tauri::command]
pub async fn signal_init_storage(
    username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state.inner().signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let db = state.inner().database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    
    run_local(handler.load_from_db(db.as_ref(), &username))
        .map_err(|e| e.to_string())?;
    
    Ok(true)
}

/// Set Signal storage encryption key
#[tauri::command]
pub async fn signal_set_storage_key(
    _key: String,
    _state: State<'_, AppState>,
) -> Result<bool, String> {
    Ok(true)
}
