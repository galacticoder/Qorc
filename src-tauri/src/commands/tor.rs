//! Tor Commands
//!
//! Tauri commands for Tor process management

use tauri::State;
use tracing::warn;

use crate::state::AppState;
use crate::tor::{TorConfig, TorInfo, TorStartResult, TorStatus, TorVerifyResult};

/// Configure Tor
#[tauri::command]
pub async fn tor_configure(config: TorConfig, state: State<'_, AppState>) -> Result<bool, String> {
    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;

    let configured = tor.configure(&config).await.map_err(|e| e.safe_message())?;
    if let Some(pir_tor) = state.inner().pir_tor_manager() {
        pir_tor
            .configure(&config)
            .await
            .map_err(|e| e.safe_message())?;
    }
    Ok(configured)
}

/// Start Tor process
#[tauri::command]
pub async fn tor_start(state: State<'_, AppState>) -> Result<TorStartResult, String> {
    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;

    let result = tor.start().await.map_err(|e| e.safe_message())?;
    if result.success
        && let Some(pir_tor) = state.inner().pir_tor_manager()
    {
        match pir_tor.mirror_configuration_from(&tor).await {
            Ok(_) => match pir_tor.start().await {
                Ok(pir_result) if !pir_result.success => {
                    warn!("[TOR-PIR] dedicated process did not start")
                }
                Err(_) => warn!("[TOR-PIR] dedicated process start failed"),
                _ => {}
            },
            Err(_) => warn!("[TOR-PIR] dedicated process configuration failed"),
        }
    }
    Ok(result)
}

/// Stop Tor process
#[tauri::command]
pub async fn tor_stop(state: State<'_, AppState>) -> Result<bool, String> {
    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;

    let stopped = tor.stop().await.map_err(|e| e.safe_message())?;
    if let Some(pir_tor) = state.inner().pir_tor_manager() {
        pir_tor.stop().await.map_err(|e| e.safe_message())?;
    }
    if let Some(ws) = state.inner().websocket() {
        let _control_guard = ws.lock_control().await;
        ws.set_tor_ready(false);
        let _ = ws.disconnect(ws.get_state().connection_token).await;
    }
    Ok(stopped)
}

/// Get Tor status
#[tauri::command]
pub async fn tor_status(state: State<'_, AppState>) -> Result<TorStatus, String> {
    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;

    Ok(tor.status())
}

/// Get Tor info
#[tauri::command]
pub async fn tor_info(state: State<'_, AppState>) -> Result<TorInfo, String> {
    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;

    let info = tor.get_info().await.map_err(|e| e.safe_message())?;
    if let Some(ws) = state.inner().websocket() {
        ws.set_tor_ready(info.bootstrapped);
        if info.bootstrapped {
            ws.update_tor_config(info.socks_port);
        }
    }
    Ok(info)
}

/// Verify Tor connection
#[tauri::command]
pub async fn tor_verify_connection(state: State<'_, AppState>) -> Result<TorVerifyResult, String> {
    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;

    tor.verify_connection().await.map_err(|e| e.safe_message())
}
