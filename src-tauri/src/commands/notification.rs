//! Notification Commands

use crate::state::AppState;
use tauri::State;

/// Show a system notification
#[tauri::command]
pub async fn notification_show(state: State<'_, AppState>) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler.show().map_err(|e| e.safe_message())
    } else {
        Err("Notification handler not initialized".to_string())
    }
}

/// Set notifications enabled/disabled
#[tauri::command]
pub async fn notification_set_enabled(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler.set_enabled(enabled);
        Ok(true)
    } else {
        Err("Notification handler not initialized".to_string())
    }
}
