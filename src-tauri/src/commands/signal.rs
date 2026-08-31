//! Signal Protocol Commands
//!
//! Tauri commands for Signal Protocol operations

use serde::{Serialize, de::DeserializeOwned};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

use crate::signal_protocol::{EncryptedMessage, PreKeyBundle};
use crate::state::AppState;

const MAX_SIGNAL_PREKEY_BUNDLE_JSON_BYTES: usize = 16 * 1024;
const MAX_SIGNAL_PREKEY_BUNDLE_STRING_BYTES: usize = 4 * 1024;
const MAX_SIGNAL_ENCRYPTED_JSON_BYTES: usize = 768 * 1024;
const MAX_SIGNAL_ENCRYPTED_STRING_BYTES: usize = 700 * 1024;
const MAX_SIGNAL_ACK_JSON_BYTES: usize = 1024;

fn parse_bounded_signal_json<T: DeserializeOwned>(
    body: &str,
    max_body_bytes: usize,
    max_depth: usize,
    max_structural_tokens: usize,
    max_string_bytes: usize,
) -> Result<T, ()> {
    if body.len() > max_body_bytes {
        return Err(());
    }
    crate::json_bounds::enforce_bounded_json_structure(
        body.as_bytes(),
        max_depth,
        max_structural_tokens,
        max_string_bytes,
    )
    .map_err(|_| ())?;
    serde_json::from_str(body).map_err(|_| ())
}

fn parse_encrypted_message(encrypted_json: &str) -> Result<EncryptedMessage, ()> {
    parse_bounded_signal_json(
        encrypted_json,
        MAX_SIGNAL_ENCRYPTED_JSON_BYTES,
        4,
        64,
        MAX_SIGNAL_ENCRYPTED_STRING_BYTES,
    )
}

fn shared_signal_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build shared signal runtime")
    })
}

fn run_local<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::task::block_in_place(|| shared_signal_runtime().block_on(fut))
}

fn restore_signal_snapshot(
    handler: &std::sync::Arc<crate::signal_protocol::SignalHandler>,
    db: &crate::database::DatabaseManager,
    username: &str,
) {
    if let Err(rollback_error) = run_local(handler.load_from_db(db, username)) {
        let _ = rollback_error;
        log::error!("[signal] persistence rollback failed; clearing in-memory account state");
        handler.clear_account_state(username, db.account_owner());
    }
}

fn persist_full_or_restore(
    handler: &std::sync::Arc<crate::signal_protocol::SignalHandler>,
    db: &crate::database::DatabaseManager,
    username: &str,
) -> Result<(), String> {
    run_local(handler.persist_to_db(db, username)).map_err(|error| {
        log::error!("[signal] atomic full-state persistence failed");
        restore_signal_snapshot(handler, db, username);
        error.safe_message()
    })
}

fn persist_messaging_or_restore(
    handler: &std::sync::Arc<crate::signal_protocol::SignalHandler>,
    db: &crate::database::DatabaseManager,
    username: &str,
    full: bool,
) -> Result<(), String> {
    run_local(handler.persist_messaging_state(db, username, full)).map_err(|error| {
        log::error!("[signal] atomic messaging-state persistence failed");
        restore_signal_snapshot(handler, db, username);
        error.safe_message()
    })
}

fn operation_or_restore<T>(
    handler: &std::sync::Arc<crate::signal_protocol::SignalHandler>,
    db: &crate::database::DatabaseManager,
    username: &str,
    result: crate::error::QorcResult<T>,
) -> Result<T, String> {
    result.map_err(|error| {
        restore_signal_snapshot(handler, db, username);
        error.safe_message()
    })
}

/// Create prekey bundle for key exchange
#[tauri::command]
pub async fn signal_create_prekey_bundle(
    username: String,
    state: State<'_, AppState>,
) -> Result<PreKeyBundle, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let result = run_local(handler.create_prekey_bundle(&username));
    let res = operation_or_restore(&handler, db.as_ref(), &username, result)?;

    persist_full_or_restore(&handler, db.as_ref(), &username)?;

    Ok(res)
}

/// Process received prekey bundle to establish session
#[tauri::command]
pub async fn signal_process_prekey_bundle(
    self_username: String,
    peer_username: String,
    bundle_json: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let bundle: PreKeyBundle = parse_bounded_signal_json(
        &bundle_json,
        MAX_SIGNAL_PREKEY_BUNDLE_JSON_BYTES,
        3,
        64,
        MAX_SIGNAL_PREKEY_BUNDLE_STRING_BYTES,
    )
    .map_err(|_| "Invalid Signal pre-key bundle".to_string())?;
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &self_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let result = run_local(handler.process_prekey_bundle(&self_username, &peer_username, bundle));
    let res = operation_or_restore(&handler, db.as_ref(), &self_username, result)?;

    persist_full_or_restore(&handler, db.as_ref(), &self_username)?;

    Ok(res)
}

/// Check if session exists with peer
#[tauri::command]
pub async fn signal_has_session(
    self_username: String,
    peer_username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &self_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.has_session(&self_username, &peer_username)).map_err(|e| e.safe_message())
}

#[tauri::command]
pub async fn signal_has_peer_static_mlkem_key(
    self_username: String,
    peer_username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &self_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.has_peer_static_ml_kem_key(&self_username, &peer_username))
        .map_err(|error| error.safe_message())
}

/// Encrypt message
#[tauri::command]
pub async fn signal_encrypt(
    from_username: String,
    to_username: String,
    plaintext: String,
    state: State<'_, AppState>,
) -> Result<EncryptedMessage, String> {
    let plaintext = Zeroizing::new(plaintext);
    if plaintext.len() > crate::signal_protocol::MAX_SIGNAL_PLAINTEXT_BYTES {
        return Err("Signal plaintext exceeds size limit".to_string());
    }
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &from_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let result = run_local(handler.encrypt(&from_username, &to_username, plaintext.as_bytes()));
    let res = operation_or_restore(&handler, db.as_ref(), &from_username, result)?;

    persist_messaging_or_restore(&handler, db.as_ref(), &from_username, false)?;

    Ok(res)
}

#[tauri::command]
pub async fn signal_encrypt_content_ref(
    from_username: String,
    to_username: String,
    plaintext_template: String,
    content_ref: String,
    state: State<'_, AppState>,
) -> Result<EncryptedMessage, String> {
    let plaintext_template = Zeroizing::new(plaintext_template);
    if plaintext_template.len() > crate::signal_protocol::MAX_SIGNAL_PLAINTEXT_BYTES {
        return Err("Signal plaintext exceeds size limit".to_string());
    }
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &from_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let record = crate::message_content::load_native_content_record(db.as_ref(), &content_ref)
        .map_err(|error| error.safe_message())?
        .ok_or_else(|| "Native message content is unavailable".to_string())?;
    let binding = record
        .outbound
        .as_ref()
        .ok_or_else(|| "Native message content is not authorized for sending".to_string())?;
    if binding.recipient != to_username {
        return Err("Native message recipient binding mismatch".to_string());
    }

    crate::json_bounds::enforce_bounded_json_structure(
        plaintext_template.as_bytes(),
        12,
        1024,
        64 * 1024,
    )
    .map_err(|_| "Invalid Signal private-message template".to_string())?;
    let mut payload: serde_json::Value = serde_json::from_str(plaintext_template.as_str())
        .map_err(|_| "Invalid Signal private-message template".to_string())?;
    {
        let object = payload
            .as_object_mut()
            .ok_or_else(|| "Invalid Signal private-message template".to_string())?;
        if object.get("type").and_then(serde_json::Value::as_str)
            != Some(binding.application_type.as_str())
            || object.get("messageId").and_then(serde_json::Value::as_str)
                != Some(binding.wire_message_id.as_str())
            || object.contains_key("nativeContentRef")
            || object
                .get("content")
                .is_some_and(|value| value.as_str() != Some(""))
        {
            return Err("Native message metadata binding mismatch".to_string());
        }
        let content = String::from_utf8(record.content.as_slice().to_vec())
            .map_err(|_| "Native message content is invalid".to_string())?;
        object.insert("content".to_string(), serde_json::Value::String(content));
    }
    let plaintext = Zeroizing::new(
        serde_json::to_string(&payload)
            .map_err(|_| "Invalid Signal private-message template".to_string())?,
    );
    if let Some(serde_json::Value::String(mut sensitive)) = payload
        .as_object_mut()
        .and_then(|object| object.remove("content"))
    {
        sensitive.zeroize();
    }
    drop(payload);
    if plaintext.len() > crate::signal_protocol::MAX_SIGNAL_PLAINTEXT_BYTES {
        return Err("Signal plaintext exceeds size limit".to_string());
    }

    let result = run_local(handler.encrypt(&from_username, &to_username, plaintext.as_bytes()));
    let res = operation_or_restore(&handler, db.as_ref(), &from_username, result)?;
    persist_messaging_or_restore(&handler, db.as_ref(), &from_username, false)?;
    Ok(res)
}

/// Decrypt response structure
#[derive(Debug, Serialize)]
pub struct DecryptResult {
    pub success: bool,
    pub plaintext: Option<String>,
    pub content_ref: Option<String>,
    pub error: Option<String>,
    pub requires_key_refresh: Option<bool>,
    pub pending_id: Option<String>,
}

fn redacted_decrypt_success(
    plaintext: &str,
    application_type: &str,
    pending_id: &str,
) -> Result<DecryptResult, String> {
    let redacted = match crate::message_content::redact_application_plaintext(
        plaintext,
        application_type,
        pending_id,
    ) {
        Ok(redacted) => redacted,
        Err(_) => {
            log::warn!("[signal] authenticated application payload was not renderer-safe");
            crate::message_content::RedactedApplicationPlaintext {
                plaintext: "{}".to_string(),
                content_ref: None,
            }
        }
    };
    Ok(DecryptResult {
        success: true,
        plaintext: Some(redacted.plaintext),
        content_ref: redacted.content_ref,
        error: None,
        requires_key_refresh: None,
        pending_id: Some(pending_id.to_string()),
    })
}

impl Drop for DecryptResult {
    fn drop(&mut self) {
        if let Some(plaintext) = self.plaintext.as_mut() {
            plaintext.zeroize();
        }
    }
}

/// Decrypt message
#[tauri::command]
pub async fn signal_decrypt(
    from_username: String,
    to_username: String,
    transport_message_id: String,
    application_type: String,
    identity_root_fingerprint: String,
    identity_bundle_fingerprint: String,
    encrypted_json: String,
    state: State<'_, AppState>,
) -> Result<DecryptResult, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let encrypted = match parse_encrypted_message(&encrypted_json) {
        Ok(encrypted) => encrypted,
        Err(_) => {
            return Ok(DecryptResult {
                success: false,
                plaintext: None,
                content_ref: None,
                error: Some("Invalid encrypted message".to_string()),
                requires_key_refresh: Some(false),
                pending_id: None,
            });
        }
    };

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &to_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let sender_identity_key =
        run_local(handler.get_peer_identity_key(&to_username, &from_username))
            .map_err(|error| error.safe_message())?;
    let pending_id = crate::signal_protocol::SignalHandler::pending_decrypt_id(
        &from_username,
        &to_username,
        &transport_message_id,
        &application_type,
        &sender_identity_key,
        &identity_root_fingerprint,
        &identity_bundle_fingerprint,
        &encrypted,
    )
    .map_err(|e| e.safe_message())?;
    let mut pending =
        crate::signal_protocol::SignalHandler::load_pending_decrypts(db.as_ref(), &to_username)
            .map_err(|e| e.safe_message())?;
    if let Some(existing) = pending.iter().find(|entry| entry.pending_id == pending_id) {
        if existing.from_username != from_username
            || existing.sender_identity_key != sender_identity_key
            || existing.identity_root_fingerprint != identity_root_fingerprint
            || existing.identity_bundle_fingerprint != identity_bundle_fingerprint
            || existing.transport_message_id != transport_message_id
            || existing.application_type != application_type
        {
            return Err("Pending Signal plaintext metadata binding mismatch".to_string());
        }
        return redacted_decrypt_success(
            &existing.plaintext,
            &existing.application_type,
            &existing.pending_id,
        );
    }

    let (decrypt_result, state_may_have_changed) =
        run_local(handler.decrypt_with_mutation_status(&from_username, &to_username, &encrypted));
    match decrypt_result {
        Ok(crate::signal_protocol::SignalDecryptOutput::Plaintext(plaintext)) => {
            let plaintext = match String::from_utf8(plaintext) {
                Ok(plaintext) => plaintext,
                Err(error) => {
                    let mut invalid_plaintext = error.into_bytes();
                    invalid_plaintext.zeroize();
                    persist_messaging_or_restore(&handler, db.as_ref(), &to_username, true)?;
                    return Ok(DecryptResult {
                        success: false,
                        plaintext: None,
                        content_ref: None,
                        error: Some("Invalid authenticated Signal plaintext".to_string()),
                        requires_key_refresh: Some(false),
                        pending_id: None,
                    });
                }
            };
            pending.push(crate::signal_protocol::PendingDecryptedMessage {
                pending_id: pending_id.clone(),
                from_username: from_username.clone(),
                sender_identity_key,
                identity_root_fingerprint,
                identity_bundle_fingerprint,
                transport_message_id,
                application_type,
                plaintext,
            });
            let pending_blob =
                match crate::signal_protocol::SignalHandler::serialize_pending_decrypts(&pending) {
                    Ok(blob) => blob,
                    Err(error) => {
                        restore_signal_snapshot(&handler, db.as_ref(), &to_username);
                        return Err(error.safe_message());
                    }
                };
            run_local(handler.persist_decrypt_state(
                db.as_ref(),
                &to_username,
                pending_blob.as_slice(),
            ))
            .map_err(|error| {
                log::error!("[signal] atomic decrypt-state persistence failed");
                restore_signal_snapshot(&handler, db.as_ref(), &to_username);
                error.safe_message()
            })?;
            let staged = pending
                .last()
                .ok_or_else(|| "Native pending message staging failed".to_string())?;
            redacted_decrypt_success(
                &staged.plaintext,
                &staged.application_type,
                &staged.pending_id,
            )
        }
        Ok(crate::signal_protocol::SignalDecryptOutput::AuthenticatedPlaintextRejected) => {
            persist_messaging_or_restore(&handler, db.as_ref(), &to_username, true)?;
            Ok(DecryptResult {
                success: false,
                plaintext: None,
                content_ref: None,
                error: Some("Invalid authenticated Signal plaintext".to_string()),
                requires_key_refresh: Some(false),
                pending_id: None,
            })
        }
        Err(e) => {
            if state_may_have_changed {
                restore_signal_snapshot(&handler, db.as_ref(), &to_username);
            }
            Ok(DecryptResult {
                success: false,
                plaintext: None,
                content_ref: None,
                error: Some(e.safe_message()),
                requires_key_refresh: Some(e.requires_key_refresh()),
                pending_id: None,
            })
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RendererPendingDecryptedMessage {
    pub pending_id: String,
    pub from_username: String,
    pub sender_identity_key: String,
    pub identity_root_fingerprint: String,
    pub identity_bundle_fingerprint: String,
    pub transport_message_id: String,
    pub application_type: String,
    pub plaintext: String,
    pub content_ref: Option<String>,
}

#[tauri::command]
pub async fn signal_list_pending_decrypts(
    username: String,
    state: State<'_, AppState>,
) -> Result<Vec<RendererPendingDecryptedMessage>, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let _account_lock = run_local(handler.acquire_account_state_lock(
        &username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let pending =
        crate::signal_protocol::SignalHandler::load_pending_decrypts(db.as_ref(), &username)
            .map_err(|error| error.safe_message())?;
    pending
        .iter()
        .map(|entry| {
            let redacted = crate::message_content::redact_application_plaintext(
                &entry.plaintext,
                &entry.application_type,
                &entry.pending_id,
            )
            .unwrap_or_else(|_| crate::message_content::RedactedApplicationPlaintext {
                plaintext: "{}".to_string(),
                content_ref: None,
            });
            Ok(RendererPendingDecryptedMessage {
                pending_id: entry.pending_id.clone(),
                from_username: entry.from_username.clone(),
                sender_identity_key: entry.sender_identity_key.clone(),
                identity_root_fingerprint: entry.identity_root_fingerprint.clone(),
                identity_bundle_fingerprint: entry.identity_bundle_fingerprint.clone(),
                transport_message_id: entry.transport_message_id.clone(),
                application_type: entry.application_type.clone(),
                plaintext: redacted.plaintext,
                content_ref: redacted.content_ref,
            })
        })
        .collect()
}

#[tauri::command]
pub async fn signal_ack_pending_decrypts(
    username: String,
    pending_ids_json: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let pending_ids: Vec<String> =
        parse_bounded_signal_json(&pending_ids_json, MAX_SIGNAL_ACK_JSON_BYTES, 2, 32, 64)
            .map_err(|_| "Invalid pending decrypt acknowledgement batch".to_string())?;
    if pending_ids.is_empty() || pending_ids.len() > 16 {
        return Err("Invalid pending decrypt acknowledgement batch".to_string());
    }
    for pending_id in &pending_ids {
        crate::signal_protocol::SignalHandler::validate_pending_decrypt_id(pending_id)
            .map_err(|error| error.safe_message())?;
    }
    let requested_count = pending_ids.len();
    let requested = pending_ids
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    if requested.len() != requested_count {
        return Err("Invalid pending decrypt acknowledgement batch".to_string());
    }
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let _account_lock = run_local(handler.acquire_account_state_lock(
        &username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let mut pending =
        crate::signal_protocol::SignalHandler::load_pending_decrypts(db.as_ref(), &username)
            .map_err(|error| error.safe_message())?;
    let before = pending.len();
    pending.retain(|entry| !requested.contains(&entry.pending_id));
    if pending.len() == before {
        return Ok(true);
    }
    let pending_blob = crate::signal_protocol::SignalHandler::serialize_pending_decrypts(&pending)
        .map_err(|error| error.safe_message())?;
    db.set_secure(
        "signal_pending_decrypt_store_v4",
        &username,
        pending_blob.as_slice(),
    )
    .map_err(|error| error.safe_message())?;
    Ok(true)
}

/// Delete all sessions with peer
#[tauri::command]
pub async fn signal_delete_all_sessions(
    self_username: String,
    peer_username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &self_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    let result = run_local(handler.delete_all_sessions(&self_username, &peer_username));
    let res = operation_or_restore(&handler, db.as_ref(), &self_username, result)?;

    persist_messaging_or_restore(&handler, db.as_ref(), &self_username, true)?;

    Ok(res)
}

/// Install an identity already authorized by key-transparency verifier
#[tauri::command]
pub async fn signal_install_transparency_verified_peer_identity(
    self_username: String,
    peer_username: String,
    new_identity_key: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();

    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let _account_lock = run_local(handler.acquire_account_state_lock(
        &self_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.install_transparency_verified_peer_identity(
        db.as_ref(),
        &self_username,
        &peer_username,
        &new_identity_key,
    ))
    .map_err(|e| e.safe_message())
}

/// Revoke a peer identity after the active key-transparency root changes
#[tauri::command]
pub async fn signal_revoke_transparency_peer_identity(
    self_username: String,
    peer_username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let _account_lock = run_local(handler.acquire_account_state_lock(
        &self_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.revoke_transparency_peer_identity(
        db.as_ref(),
        &self_username,
        &peer_username,
    ))
    .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn signal_peek_prekey_identity(
    from_username: String,
    to_username: String,
    encrypted_json: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let encrypted = parse_encrypted_message(&encrypted_json)
        .map_err(|_| "Invalid encrypted message".to_string())?;
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_state_lock(
        &to_username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.peek_prekey_identity(&from_username, &to_username, &encrypted))
        .map_err(|e| e.safe_message())
}

/// Initialize Signal storage from database
#[tauri::command]
pub async fn signal_init_storage(
    username: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;

    let _account_lock = run_local(handler.acquire_account_initialization_lock(
        &username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.load_from_db(db.as_ref(), &username)).map_err(|e| e.safe_message())?;
    handler
        .activate_account(&username, db.account_owner())
        .map_err(|error| error.safe_message())?;

    Ok(true)
}

pub(crate) fn initialize_native_account_signal(
    handler: std::sync::Arc<crate::signal_protocol::SignalHandler>,
    db: std::sync::Arc<crate::database::DatabaseManager>,
    username: &str,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<(), String> {
    let lifecycle_epoch = handler.lifecycle_epoch();
    let _account_lock = run_local(handler.acquire_account_initialization_lock(
        username,
        db.account_owner(),
        lifecycle_epoch,
    ))
    .map_err(|error| error.safe_message())?;
    run_local(handler.load_from_db(db.as_ref(), username)).map_err(|error| error.safe_message())?;
    handler
        .activate_account(username, db.account_owner())
        .map_err(|error| error.safe_message())?;
    run_local(handler.set_static_mlkem_keys(username, public_key, secret_key))
        .map_err(|error| error.safe_message())?;
    persist_full_or_restore(&handler, db.as_ref(), username)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_SIGNAL_ACK_JSON_BYTES, parse_bounded_signal_json, parse_encrypted_message};

    #[test]
    fn signal_ipc_json_rejects_tree_and_size_amplification() {
        assert!(parse_encrypted_message(r#"[[[[[]]]]]"#).is_err());
        assert!(parse_encrypted_message(r#"{"messageType":3,"unknown":true}"#).is_err());

        let oversized = format!(r#"["{}"]"#, "a".repeat(MAX_SIGNAL_ACK_JSON_BYTES));
        assert!(
            parse_bounded_signal_json::<Vec<String>>(
                &oversized,
                MAX_SIGNAL_ACK_JSON_BYTES,
                2,
                32,
                64,
            )
            .is_err()
        );
    }
}
