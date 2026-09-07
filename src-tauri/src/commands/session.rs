//! Session Commands

use crate::state::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;

/// Background session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackgroundSessionState {
    pub active: bool,
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

    let active = match storage
        .get_text(crate::storage_keys::BACKGROUND_SESSION_ACTIVE)
        .await
        .map_err(|e| e.safe_message())?
        .as_deref()
    {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err("Invalid background session state".to_string()),
    };

    Ok(BackgroundSessionState { active })
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
        .set_text(
            crate::storage_keys::BACKGROUND_SESSION_ACTIVE,
            if active { "true" } else { "false" },
        )
        .await
        .map_err(|e| e.safe_message())?;

    Ok(true)
}
