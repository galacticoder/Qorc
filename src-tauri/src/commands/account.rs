//! Narrow renderer commands for the native persistent account boundary

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::account_vault::{self, AccountPublicKeys};
use crate::state::AppState;

const SIGN_INPUT_MAX_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountOpenResult {
    created: bool,
    public_keys: AccountPublicKeys,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct P2pHandshakeSecrets {
    pq_secret_base64: String,
    x25519_secret_base64: String,
}

async fn activate_session(
    app_handle: &AppHandle,
    state: &AppState,
    session: std::sync::Arc<account_vault::AccountSession>,
) -> Result<(), String> {
    crate::database::activate_native_account_database(
        app_handle.clone(),
        state,
        session.account_owner(),
        session.master_key(),
    )
    .await?;

    let signal_handler = state
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let private_key = session.ml_kem_private_key();
    let public_key = BASE64
        .decode(&session.public_keys().kyber_public_base64)
        .map_err(|_| "Native account public key is invalid".to_string())?;
    let database = state
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    crate::commands::signal::initialize_native_account_signal(
        signal_handler,
        database,
        session.username(),
        public_key,
        private_key.to_vec(),
    )?;

    *state.account_session.write() = Some(session);
    Ok(())
}

#[tauri::command]
pub async fn account_open(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    account_owner: String,
    username: String,
    password: String,
    passphrase: String,
) -> Result<AccountOpenResult, String> {
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    let created = !account_vault::exists(storage.as_ref(), &account_owner)
        .await
        .map_err(|error| error.safe_message())?;
    let session = if created {
        account_vault::create(
            storage,
            account_owner,
            username,
            Zeroizing::new(password),
            Zeroizing::new(passphrase),
        )
        .await
    } else {
        account_vault::unlock(
            storage,
            account_owner,
            username,
            Zeroizing::new(password),
            Zeroizing::new(passphrase),
        )
        .await
    }
    .map_err(|error| error.safe_message())?;
    let public_keys = session.public_keys();
    activate_session(&app_handle, state.inner(), session).await?;
    Ok(AccountOpenResult {
        created,
        public_keys,
    })
}

#[tauri::command]
pub async fn account_public_keys(state: State<'_, AppState>) -> Result<AccountPublicKeys, String> {
    state
        .inner()
        .account_session()
        .map(|session| session.public_keys())
        .ok_or_else(|| "Native account is locked".to_string())
}

#[tauri::command]
pub async fn account_is_unlocked(
    account_owner: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state
        .inner()
        .account_session()
        .is_some_and(|session| session.account_owner() == account_owner))
}

#[tauri::command]
pub async fn account_sign(
    purpose: String,
    message_base64: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let message = BASE64
        .decode(&message_base64)
        .map_err(|_| "Invalid signing input".to_string())?;
    if message.is_empty()
        || message.len() > SIGN_INPUT_MAX_BYTES
        || BASE64.encode(&message) != message_base64
    {
        return Err("Invalid signing input".to_string());
    }
    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    let signature = match purpose.as_str() {
        crate::protocol_keys::DEVICE_ENVELOPE_SIGNING
        | crate::protocol_keys::DEVICE_CERTIFICATE_SIGNING
        | crate::protocol_keys::P2P_TRANSCRIPT_SIGNING => session.sign_device(&message),
        crate::protocol_keys::ACCOUNT_ROOT_CERTIFICATE_SIGNING
        | crate::protocol_keys::KEY_TRANSPARENCY_SIGNING => session.sign_account_root(&message),
        crate::protocol_keys::KEY_TRANSPARENCY_RECOVERY_SIGNING => session.sign_recovery(&message),
        _ => return Err("Unsupported native signing purpose".to_string()),
    }
    .map_err(|error| error.safe_message())?;
    Ok(BASE64.encode(signature))
}

#[tauri::command]
pub async fn account_p2p_handshake_secrets(
    kem_ciphertext_base64: String,
    peer_x25519_public_base64: String,
    state: State<'_, AppState>,
) -> Result<P2pHandshakeSecrets, String> {
    let kem_ciphertext = BASE64
        .decode(&kem_ciphertext_base64)
        .map_err(|_| "Invalid P2P KEM ciphertext".to_string())?;
    if kem_ciphertext.len() != crate::crypto::post_quantum::ML_KEM_CIPHERTEXT_SIZE
        || BASE64.encode(&kem_ciphertext) != kem_ciphertext_base64
    {
        return Err("Invalid P2P KEM ciphertext".to_string());
    }

    let peer_public = BASE64
        .decode(&peer_x25519_public_base64)
        .map_err(|_| "Invalid P2P X25519 public key".to_string())?;
    let peer_public: [u8; 32] = peer_public
        .try_into()
        .map_err(|_| "Invalid P2P X25519 public key".to_string())?;
    if BASE64.encode(peer_public) != peer_x25519_public_base64 {
        return Err("Invalid P2P X25519 public key".to_string());
    }

    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    let pq_secret = session
        .ml_kem_decapsulate(&kem_ciphertext)
        .map_err(|error| error.safe_message())?;
    let x25519_secret = session
        .x25519_shared_secret(&peer_public)
        .map_err(|error| error.safe_message())?;
    Ok(P2pHandshakeSecrets {
        pq_secret_base64: BASE64.encode(pq_secret.as_slice()),
        x25519_secret_base64: BASE64.encode(x25519_secret.as_slice()),
    })
}

#[tauri::command]
pub async fn account_discovery_publication(
    server_scope: String,
    publication_window: u64,
    purpose: String,
    counter: u16,
    state: State<'_, AppState>,
) -> Result<String, String> {
    state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?
        .discovery_publication_hex(&server_scope, publication_window, &purpose, counter)
        .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn account_decrypt_hybrid(
    envelope_json: String,
    expected_sender_public: String,
    state: State<'_, AppState>,
) -> Result<crate::hybrid_native::NativeHybridPlaintext, String> {
    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    crate::hybrid_native::decrypt(&session, &envelope_json, &expected_sender_public)
        .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn account_open_sealed_envelope(
    envelope_json: String,
    state: State<'_, AppState>,
) -> Result<Option<serde_json::Value>, String> {
    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    crate::hybrid_native::decrypt_sealed(&session, &envelope_json)
        .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn account_token_vault_load(
    server_scope: String,
    vault_kind: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    let key = session
        .token_vault_storage_key(&server_scope, &vault_kind)
        .map_err(|error| error.safe_message())?;
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    let Some(encoded) = storage
        .get(&key)
        .await
        .map_err(|error| error.safe_message())?
    else {
        return Ok(None);
    };
    let plaintext = session
        .open_token_vault(&server_scope, &vault_kind, &encoded)
        .map_err(|error| error.safe_message())?;
    String::from_utf8(plaintext.to_vec())
        .map(Some)
        .map_err(|_| "Invalid token-vault plaintext".to_string())
}

#[tauri::command]
pub async fn account_token_vault_store(
    server_scope: String,
    vault_kind: String,
    plaintext_json: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let plaintext_json = Zeroizing::new(plaintext_json);
    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    let key = session
        .token_vault_storage_key(&server_scope, &vault_kind)
        .map_err(|error| error.safe_message())?;
    let encoded = Zeroizing::new(
        session
            .seal_token_vault(&server_scope, &vault_kind, plaintext_json.as_bytes())
            .map_err(|error| error.safe_message())?,
    );
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    storage
        .set(&key, &encoded)
        .await
        .map_err(|error| error.safe_message())?;
    Ok(true)
}

#[tauri::command]
pub async fn account_token_vault_remove(
    server_scope: String,
    vault_kind: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let session = state
        .inner()
        .account_session()
        .ok_or_else(|| "Native account is locked".to_string())?;
    let key = session
        .token_vault_storage_key(&server_scope, &vault_kind)
        .map_err(|error| error.safe_message())?;
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    storage
        .remove(&key)
        .await
        .map_err(|error| error.safe_message())?;
    Ok(true)
}

#[tauri::command]
pub async fn account_lock(
    account_owner: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _guard = lifecycle_lock.lock_owned().await;
    let matches = state
        .inner()
        .account_session()
        .is_some_and(|session| session.account_owner() == account_owner);
    if !matches {
        return Ok(false);
    }
    if let Some(handler) = state.inner().signal_handler() {
        let _signal_guard = handler.acquire_lifecycle_lock().await;
        handler.clear_all();
    }
    *state.inner().database.write() = None;
    *state.inner().account_session.write() = None;
    Ok(true)
}
