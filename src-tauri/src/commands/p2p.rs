//! P2P Transport Commands

use crate::network::p2p::{P2PConnectResult, P2PSendResult};
use crate::state::AppState;
use tauri::State;

/// Connect to a P2P endpoint iroh NodeId
#[tauri::command]
pub async fn p2p_connect(
    connection_id: String,
    endpoint_url: String,
    state: State<'_, AppState>,
) -> Result<P2PConnectResult, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.connect(&connection_id, &endpoint_url)
        .await
        .map_err(|e| e.safe_message())
}

/// Disconnect from a direct P2P endpoint
#[tauri::command]
pub async fn p2p_disconnect(
    connection_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.disconnect(&connection_id)
        .await
        .map_err(|e| e.safe_message())
}

/// Send message
#[tauri::command]
pub async fn p2p_send(
    connection_id: String,
    message: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<P2PSendResult, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.send(&connection_id, message)
        .await
        .map_err(|e| e.safe_message())
}

/// Get P2P transport status
#[tauri::command]
pub async fn p2p_status(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    Ok(p2p.status())
}

/// Get locally advertised iroh endpoint URL
#[tauri::command]
pub async fn p2p_local_endpoint(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    Ok(p2p.local_endpoint())
}

/// Set P2P background mode
#[tauri::command]
pub async fn p2p_set_background_mode(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.set_background_mode(enabled);
    Ok(true)
}
