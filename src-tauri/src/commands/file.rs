//! File Commands

use tauri::{State, AppHandle};
use tauri_plugin_dialog::DialogExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

use crate::state::AppState;

/// File save result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveResult {
    pub success: bool,
    pub path: Option<String>,
    pub error: Option<String>,
}

/// Download settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadSettings {
    pub download_path: Option<String>,
    pub ask_where_to_save: bool,
}

/// Save file to disk
#[tauri::command]
pub async fn file_save(
    filename: String,
    data: String, 
    _mime_type: Option<String>,
    _app: AppHandle,
    _state: State<'_, AppState>,
) -> Result<SaveResult, String> {
    // Validate filename
    if filename.is_empty() || filename.len() > 255 {
        return Ok(SaveResult {
            success: false,
            path: None,
            error: Some("Invalid filename".to_string()),
        });
    }
    
    // Check for path traversal
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Ok(SaveResult {
            success: false,
            path: None,
            error: Some("Invalid filename characters".to_string()),
        });
    }
    
    // Decode data
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &data,
    ).map_err(|e| format!("Invalid base64: {}", e))?;
    
    // Get download path
    let download_dir = dirs::download_dir()
        .or_else(|| dirs::home_dir())
        .unwrap_or_else(|| PathBuf::from("."));
    
    let file_path = download_dir.join(&filename);
    
    // Write file
    fs::write(&file_path, &bytes).await
        .map_err(|e| format!("Failed to write file: {}", e))?;
    
    Ok(SaveResult {
        success: true,
        path: Some(file_path.to_string_lossy().to_string()),
        error: None,
    })
}

/// Get download settings
#[tauri::command]
pub async fn file_get_download_settings(
    state: State<'_, AppState>,
) -> Result<DownloadSettings, String> {
    let storage = state.storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    let path = storage.get("download_path").await
        .map_err(|e| e.safe_message())?;
    
    let ask_where = storage.get("ask_where_to_save").await
        .map_err(|e| e.safe_message())?
        .map(|s| s == "true")
        .unwrap_or(false);
    
    Ok(DownloadSettings {
        download_path: path,
        ask_where_to_save: ask_where,
    })
}

/// Set download path
#[tauri::command]
pub async fn file_set_download_path(
    path: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    // Validate path
    let path_buf = PathBuf::from(&path);
    if !path_buf.is_absolute() {
        return Err("Path must be absolute".to_string());
    }
    
    let storage = state.storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.set("download_path", &path).await
        .map(|_| true)
        .map_err(|e| e.safe_message())
}

/// Choose download path via dialog
#[tauri::command]
pub async fn file_choose_download_path(
    app: AppHandle,
) -> Result<Option<String>, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();

    app.dialog()
        .file()
        .set_title("Choose Download Folder")
        .pick_folder(move |res| {
            let path = res.map(|p| p.to_string());
            let _ = tx.send(path);
        });
    
    match rx.await {
        Ok(path) => Ok(path),
        Err(_) => Err("Dialog closed".to_string()),
    }
}

/// Read file as base64
#[tauri::command]
pub async fn file_read_base64(
    path: String,
) -> Result<String, String> {
    let path_buf = PathBuf::from(&path);
    
    let home = dirs::home_dir().unwrap_or_default();
    if !path_buf.starts_with(&home) {
        return Err("Access denied".to_string());
    }
    
    let bytes = fs::read(&path_buf).await
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &bytes,
    ))
}

/// Get file info
#[tauri::command]
pub async fn file_get_info(
    path: String,
) -> Result<FileInfo, String> {
    let path_buf = PathBuf::from(&path);
    
    let metadata = fs::metadata(&path_buf).await
        .map_err(|e| format!("Failed to get file info: {}", e))?;
    
    Ok(FileInfo {
        exists: true,
        is_file: metadata.is_file(),
        is_directory: metadata.is_dir(),
        size: metadata.len(),
        name: path_buf.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
    })
}

/// File info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub exists: bool,
    pub is_file: bool,
    pub is_directory: bool,
    pub size: u64,
    pub name: String,
}
