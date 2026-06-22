//! Notification Commands

use crate::state::AppState;
use tauri::{AppHandle, Manager, State};

fn apply_badge_count(app_handle: &AppHandle, count: Option<i64>) -> Result<(), String> {
    let window = app_handle
        .get_webview_window("main")
        .ok_or_else(|| "Main window not found".to_string())?;

    match window.set_badge_count(count) {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if cfg!(target_os = "linux") {
                tracing::warn!("OS badge update unavailable on this Linux desktop: {}", msg);
                Ok(())
            } else {
                Err(msg)
            }
        }
    }
}

/// Show a system notification
#[tauri::command]
pub async fn notification_show(
    title: String,
    body: Option<String>,
    _icon: Option<String>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler
            .show(&title, body.as_deref(), false)
            .map_err(|e| e.to_string())
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

/// Check if notifications are enabled
#[tauri::command]
pub async fn notification_is_enabled(state: State<'_, AppState>) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        Ok(handler.is_enabled())
    } else {
        Err("Notification handler not initialized".to_string())
    }
}

/// Set app badge count
#[tauri::command]
pub async fn notification_set_badge(
    count: u32,
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler.set_badge_count(count).map_err(|e| e.to_string())?;
        apply_badge_count(&app_handle, Some(i64::from(count)))?;
        Ok(true)
    } else {
        Err("Notification handler not initialized".to_string())
    }
}

/// Clear app badge
#[tauri::command]
pub async fn notification_clear_badge(
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler.clear_badge().map_err(|e| e.to_string())?;
        apply_badge_count(&app_handle, None)?;
        Ok(true)
    } else {
        Err("Notification handler not initialized".to_string())
    }
}

/// Get current badge count
#[tauri::command]
pub async fn notification_get_badge(state: State<'_, AppState>) -> Result<u32, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        Ok(handler.get_badge_count())
    } else {
        Err("Notification handler not initialized".to_string())
    }
}
