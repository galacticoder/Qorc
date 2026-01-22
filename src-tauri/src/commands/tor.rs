//! Tor Commands
//!
//! Tauri commands for Tor process management

use tauri::State;

use crate::state::AppState;
use crate::tor::{
    TorConfig, TorInstallStatus, TorStatus, TorInfo,
    TorStartResult, TorDownloadResult, TorVerifyResult, CircuitRotationResult,
};

/// Check Tor installation status
#[tauri::command]
pub async fn tor_check_installation(
    state: State<'_, AppState>,
) -> Result<TorInstallStatus, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.check_installation().await
        .map_err(|e| e.safe_message())
}

/// Download Tor bundle
#[tauri::command]
pub async fn tor_download(
    state: State<'_, AppState>,
) -> Result<TorDownloadResult, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.download().await
        .map_err(|e| e.safe_message())
}

/// Install Tor
#[tauri::command]
pub async fn tor_install(
    state: State<'_, AppState>,
) -> Result<TorDownloadResult, String> {
    tor_download(state).await
}

/// Configure Tor
#[tauri::command]
pub async fn tor_configure(
    config: TorConfig,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.configure(&config).await
        .map_err(|e| e.safe_message())
}

/// Start Tor process
#[tauri::command]
pub async fn tor_start(
    state: State<'_, AppState>,
) -> Result<TorStartResult, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.start().await
        .map_err(|e| e.safe_message())
}

/// Stop Tor process
#[tauri::command]
pub async fn tor_stop(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.stop().await
        .map_err(|e| e.safe_message())
}

/// Get Tor status
#[tauri::command]
pub async fn tor_status(
    state: State<'_, AppState>,
) -> Result<TorStatus, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    Ok(tor.status())
}

/// Get Tor info
#[tauri::command]
pub async fn tor_info(
    state: State<'_, AppState>,
) -> Result<TorInfo, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.get_info().await
        .map_err(|e| e.safe_message())
}

/// Verify Tor connection
#[tauri::command]
pub async fn tor_verify_connection(
    state: State<'_, AppState>,
) -> Result<TorVerifyResult, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.verify_connection().await
        .map_err(|e| e.safe_message())
}

/// Test Tor connection
#[tauri::command]
pub async fn tor_test_connection(
    state: State<'_, AppState>,
) -> Result<TorVerifyResult, String> {
    tor_verify_connection(state).await
}

/// Rotate Tor circuit
#[tauri::command]
pub async fn tor_rotate_circuit(
    state: State<'_, AppState>,
) -> Result<CircuitRotationResult, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    tor.rotate_circuit().await
        .map_err(|e| e.safe_message())
}

/// Alias for rotate_circuit
#[tauri::command]
pub async fn tor_new_circuit(
    state: State<'_, AppState>,
) -> Result<CircuitRotationResult, String> {
    tor_rotate_circuit(state).await
}

/// Initialize Tor with default configuration
#[tauri::command]
pub async fn tor_initialize(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let config = TorConfig {
        config: "SocksPort 9150\nControlPort 9151\nLog notice stdout".to_string(),
    };
    
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    // Configure and start
    tor.configure(&config).await
        .map_err(|e| e.safe_message())?;
    
    tor.start().await
        .map(|r| r.success)
        .map_err(|e| e.safe_message())
}

/// Uninstall Tor
#[tauri::command]
pub async fn tor_uninstall(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let tor = state.inner().tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    // Stop tor first
    let _ = tor.stop().await;
    
    // Remove tor directory
    let tor_dir = tor.get_tor_dir();
    if tor_dir.exists() {
        std::fs::remove_dir_all(&tor_dir)
            .map_err(|e| format!("Failed to remove Tor directory: {}", e))?;
    }
    
    Ok(true)
}
