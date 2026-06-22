//! Session Commands

use crate::state::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;

/// Background session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundSessionState {
    pub active: bool,
    pub last_activity: Option<u64>,
    pub pending_messages: u32,
}

/// Get background session state
#[tauri::command]
pub async fn session_get_background_state(
    state: State<'_, AppState>,
) -> Result<BackgroundSessionState, String> {
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    let active = storage
        .get("bg_session_active")
        .await
        .map_err(|e| e.safe_message())?
        .map(|s| s == "true")
        .unwrap_or(false);

    let last_activity = storage
        .get("bg_session_last_activity")
        .await
        .map_err(|e| e.safe_message())?
        .and_then(|s| s.parse().ok());

    let pending = storage
        .get("bg_session_pending")
        .await
        .map_err(|e| e.safe_message())?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(BackgroundSessionState {
        active,
        last_activity,
        pending_messages: pending,
    })
}

/// Set background session state
#[tauri::command]
pub async fn session_set_background_state(
    active: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    storage
        .set("bg_session_active", if active { "true" } else { "false" })
        .await
        .map_err(|e| e.safe_message())?;

    if active {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        storage
            .set("bg_session_last_activity", &now.to_string())
            .await
            .map_err(|e| e.safe_message())?;
    }

    Ok(true)
}

/// Update pending message count
#[tauri::command]
pub async fn session_update_pending_count(
    count: u32,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    storage
        .set("bg_session_pending", &count.to_string())
        .await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}
