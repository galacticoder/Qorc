//! Renderer entry points for opaque native message content operations

use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use zeroize::Zeroizing;

use crate::message_content::{
    ContentCommitResult, RenderedMessageContent, clone_content_for_display, commit_pending_content,
    load_native_content_record, render_private_message, revoke_outbound_binding,
    store_outgoing_content,
};
use crate::state::AppState;

#[tauri::command]
pub async fn message_content_store_outgoing(
    storage_id: String,
    content: String,
    recipient: String,
    application_type: String,
    wire_message_id: String,
    overwrite: bool,
    state: State<'_, AppState>,
) -> Result<ContentCommitResult, String> {
    let content = Zeroizing::new(content);
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let result = tokio::task::spawn_blocking(move || {
        store_outgoing_content(
            db.as_ref(),
            &storage_id,
            content.as_str(),
            &recipient,
            &application_type,
            &wire_message_id,
            overwrite,
        )
    })
    .await
    .map_err(|_| "Native message operation failed".to_string())?
    .map_err(|error| error.safe_message())?;
    Ok(result)
}

#[tauri::command]
pub async fn message_content_commit_pending(
    username: String,
    pending_id: String,
    expected_wire_message_id: String,
    storage_id: String,
    overwrite: bool,
    state: State<'_, AppState>,
) -> Result<ContentCommitResult, String> {
    crate::signal_protocol::SignalHandler::validate_pending_decrypt_id(&pending_id)
        .map_err(|error| error.safe_message())?;
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let handler = state
        .inner()
        .signal_handler()
        .ok_or_else(|| "Signal handler not initialized".to_string())?;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    let lifecycle_epoch = handler.lifecycle_epoch();
    let _account_lock = handler
        .acquire_account_state_lock(&username, db.account_owner(), lifecycle_epoch)
        .await
        .map_err(|error| error.safe_message())?;
    let pending =
        crate::signal_protocol::SignalHandler::load_pending_decrypts(db.as_ref(), &username)
            .map_err(|error| error.safe_message())?;
    let record = pending
        .iter()
        .find(|entry| entry.pending_id == pending_id)
        .ok_or_else(|| "Staged private message content is unavailable".to_string())?;
    commit_pending_content(
        db.as_ref(),
        record,
        &expected_wire_message_id,
        &storage_id,
        overwrite,
    )
    .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn message_content_has(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    tokio::task::spawn_blocking(move || load_native_content_record(db.as_ref(), &storage_id))
        .await
        .map_err(|_| "Native message operation failed".to_string())?
        .map(|content| content.is_some())
        .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn message_content_render(
    storage_id: String,
    max_width: u32,
    font_size: f32,
    color: String,
    state: State<'_, AppState>,
) -> Result<RenderedMessageContent, String> {
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    tokio::task::spawn_blocking(move || {
        let record = load_native_content_record(db.as_ref(), &storage_id)?.ok_or_else(|| {
            crate::error::QorError::NotInitialized(
                "Native message content is unavailable".to_string(),
            )
        })?;
        let plaintext = std::str::from_utf8(record.content.as_slice()).map_err(|_| {
            crate::error::QorError::DecryptionFailed(
                "Native message content is not valid UTF-8".to_string(),
            )
        })?;
        render_private_message(plaintext, max_width, font_size, &color)
    })
    .await
    .map_err(|_| "Native message rendering failed".to_string())?
    .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn message_content_clone_for_display(
    source_id: String,
    target_id: String,
    overwrite: bool,
    state: State<'_, AppState>,
) -> Result<ContentCommitResult, String> {
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    tokio::task::spawn_blocking(move || {
        clone_content_for_display(db.as_ref(), &source_id, &target_id, overwrite)
    })
    .await
    .map_err(|_| "Native message operation failed".to_string())?
    .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn message_content_copy(
    storage_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .message("This exposes the selected private message to the system clipboard, where other applications may read it.")
        .title("Copy private message?")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Copy".to_string(),
            "Cancel".to_string(),
        ))
        .show(move |confirmed| {
            let _ = response_tx.send(confirmed);
        });
    if !response_rx.await.unwrap_or(false) {
        return Ok(false);
    }
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    tokio::task::spawn_blocking(move || {
        let record = load_native_content_record(db.as_ref(), &storage_id)?.ok_or_else(|| {
            crate::error::QorError::NotInitialized(
                "Native message content is unavailable".to_string(),
            )
        })?;
        let plaintext = std::str::from_utf8(record.content.as_slice()).map_err(|_| {
            crate::error::QorError::DecryptionFailed(
                "Native message content is not valid UTF-8".to_string(),
            )
        })?;
        let mut clipboard = arboard::Clipboard::new().map_err(|_| {
            crate::error::QorError::Internal("System clipboard is unavailable".to_string())
        })?;
        clipboard.set_text(plaintext).map_err(|_| {
            crate::error::QorError::Internal("System clipboard write failed".to_string())
        })?;
        Ok::<bool, crate::error::QorError>(true)
    })
    .await
    .map_err(|_| "Native clipboard operation failed".to_string())?
    .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn message_content_revoke_send(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    tokio::task::spawn_blocking(move || revoke_outbound_binding(db.as_ref(), &storage_id))
        .await
        .map_err(|_| "Native message operation failed".to_string())?
        .map_err(|error| error.safe_message())
}

#[tauri::command]
pub async fn message_content_delete(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let lifecycle_lock = state.inner().database_lifecycle_lock.clone();
    let _lifecycle_guard = lifecycle_lock.lock_owned().await;
    let db = state
        .inner()
        .database()
        .ok_or_else(|| "Database not initialized".to_string())?;
    tokio::task::spawn_blocking(move || db.delete_native_message_content(&storage_id))
        .await
        .map_err(|_| "Native message operation failed".to_string())?
        .map_err(|error| error.safe_message())?;
    Ok(true)
}
