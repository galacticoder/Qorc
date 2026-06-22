//! System Commands

use crate::state::AppState;
use crate::system::power::BlockerType;
use crate::system::screen_capture::{CaptureOptions, ScreenSource};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

/// Platform information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub platform: String,
    pub arch: String,
    pub version: String,
    pub hostname: String,
}

/// Get platform info
#[tauri::command]
pub fn get_platform_info() -> PlatformInfo {
    PlatformInfo {
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: std::env::consts::OS.to_string(),
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    }
}

/// Get platform
#[tauri::command]
pub fn get_platform() -> String {
    std::env::consts::OS.to_string()
}

/// Get architecture
#[tauri::command]
pub fn get_arch() -> String {
    std::env::consts::ARCH.to_string()
}

/// Get the runtime qor instance id used for per instance storage paths
#[tauri::command]
pub fn get_instance_id() -> String {
    crate::system::get_instance_id()
}

/// Open URL in default browser
#[tauri::command]
pub async fn open_external(url: String) -> Result<bool, String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Only HTTP(S) URLs allowed".to_string());
    }

    open::that(&url)
        .map(|_| true)
        .map_err(|e| format!("Failed to open URL: {}", e))
}

/// Get screen capture sources
#[tauri::command]
pub async fn get_screen_sources(
    options: Option<CaptureOptions>,
) -> Result<Vec<ScreenSource>, String> {
    crate::system::screen_capture::get_sources(options)
        .await
        .map_err(|e| e.safe_message())
}

/// Capture a screen source
#[tauri::command]
pub async fn capture_source(source_id: String) -> Result<Vec<u8>, String> {
    crate::system::screen_capture::capture_source(&source_id)
        .await
        .map_err(|e| e.safe_message())
}

/// Start power save blocker
#[tauri::command]
pub async fn power_save_blocker_start(
    blocker_type: Option<String>,
    state: State<'_, AppState>,
) -> Result<u32, String> {
    let blocker = state
        .power_blocker()
        .ok_or_else(|| "Power blocker not initialized".to_string())?;

    let bt = match blocker_type.as_deref() {
        Some("prevent-app-suspension") | Some("system") => BlockerType::PreventSystemSleep,
        _ => BlockerType::PreventDisplaySleep,
    };

    blocker.start(bt).map_err(|e| e.safe_message())
}

/// Stop power save blocker
#[tauri::command]
pub async fn power_save_blocker_stop(id: u32, state: State<'_, AppState>) -> Result<bool, String> {
    let blocker = state
        .power_blocker()
        .ok_or_else(|| "Power blocker not initialized".to_string())?;

    blocker.stop(id).map_err(|e| e.safe_message())
}

/// Check if power save blocker is active
#[tauri::command]
pub async fn power_save_blocker_is_started(
    id: u32,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let blocker = state
        .power_blocker()
        .ok_or_else(|| "Power blocker not initialized".to_string())?;

    Ok(blocker.is_started(id))
}

/// Get app version
#[tauri::command]
pub fn get_app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
}

/// Get app name
#[tauri::command]
pub fn get_app_name(app: AppHandle) -> String {
    app.package_info().name.clone()
}

/// Check if running in Tauri
#[tauri::command]
pub fn is_tauri() -> bool {
    true
}

/// Get user data path
#[tauri::command]
pub fn get_user_data_path(app: AppHandle) -> Result<String, String> {
    app.path()
        .app_data_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Failed to get app data path: {}", e))
}

/// Get close to tray setting
#[tauri::command]
pub fn get_close_to_tray(state: State<'_, AppState>) -> bool {
    state.get_close_to_tray()
}

/// Set close to tray setting
#[tauri::command]
pub fn set_close_to_tray(enabled: bool, state: State<'_, AppState>) -> bool {
    state.set_close_to_tray(enabled);
    true
}

/// Set tray unread badge count
#[tauri::command]
pub fn tray_set_unread_count(app: AppHandle, count: u32) {
    crate::system::tray::set_unread_count(&app, count);
}

/// Increment tray unread badge count
#[tauri::command]
pub fn tray_increment_unread(app: AppHandle) {
    crate::system::tray::increment_unread(&app);
}

/// Clear tray unread badge count
#[tauri::command]
pub fn tray_clear_unread(app: AppHandle) {
    crate::system::tray::clear_unread(&app);
}

/// Forward  frontend log line into rust terminal
#[tauri::command]
pub fn frontend_log(level: String, line: String) {
    match level.as_str() {
        "warn" => tracing::warn!(target: "qor_chat::frontend", "{}", line),
        "error" => tracing::error!(target: "qor_chat::frontend", "{}", line),
        _ => tracing::info!(target: "qor_chat::frontend", "{}", line),
    }
}
