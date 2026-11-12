//! Notification Commands

use crate::state::AppState;
use tauri::State;

async fn dispatch_notification(
    show: impl FnOnce() -> Result<bool, String> + Send + 'static,
) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(show)
        .await
        .map_err(|_| "Notification worker failed".to_string())?
}

/// Show a system notification
#[tauri::command]
pub async fn notification_show(state: State<'_, AppState>) -> Result<bool, String> {
    let handler = state
        .notification_handler
        .read()
        .clone()
        .ok_or_else(|| "Notification handler not initialized".to_string())?;
    dispatch_notification(move || handler.show().map_err(|e| e.safe_message())).await
}

/// Set notifications enabled/disabled
#[tauri::command]
pub async fn notification_set_enabled(
    enabled: bool,
    _app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    if enabled {
        use tauri_plugin_notification::NotificationExt;
        let granted = dispatch_notification(move || {
            _app.notification()
                .request_permission()
                .map(|permission| permission == tauri::plugin::PermissionState::Granted)
                .map_err(|_| "Notification permission request failed".to_string())
        })
        .await?;
        if !granted {
            return Err("Notification permission was not granted".to_string());
        }
    }
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler.set_enabled(enabled);
        Ok(true)
    } else {
        Err("Notification handler not initialized".to_string())
    }
}
