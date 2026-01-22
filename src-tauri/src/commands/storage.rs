//! Secure Storage Commands

use tauri::{Manager, State};

use crate::state::AppState;

/// Initialize secure storage
#[tauri::command]
pub async fn secure_init(app_handle: tauri::AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    let mut config_dir = app_handle.path().app_config_dir().map_err(|e| e.to_string())?;
    
    if let Some(instance_id) = crate::system::get_instance_id() {
        let suffix = format!("-instance-{}", instance_id);
        let config_name = config_dir.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "Qor-chat-client".to_string());
        config_dir.set_file_name(format!("{}{}", config_name, suffix));
    }

    crate::storage::init(&state, config_dir).await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}

/// Get value from secure storage
#[tauri::command]
pub async fn secure_get(
    key: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.get(&key).await
        .map_err(|e| e.safe_message())
}

/// Set value in secure storage
#[tauri::command]
pub async fn secure_set(
    key: String,
    value: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.set(&key, &value).await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}

/// Remove value from secure storage
#[tauri::command]
pub async fn secure_remove(
    key: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.remove(&key).await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}

/// Check if key exists in secure storage
#[tauri::command]
pub async fn secure_has(
    key: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.has(&key).await
        .map_err(|e| e.safe_message())
}

/// List all keys in secure storage
#[tauri::command]
pub async fn secure_keys(
    state: State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.keys().await
        .map_err(|e| e.safe_message())
}

/// Clear all secure storage
#[tauri::command]
pub async fn secure_clear(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.clear().await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}
