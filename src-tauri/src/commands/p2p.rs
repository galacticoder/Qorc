//! P2P Transport Commands

use crate::network::p2p::{P2PConnectResult, P2PSendResult};
use crate::state::AppState;
use tauri::State;

/// Connect to a peers published onion endpoint URL
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
    connection_token: Option<u64>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.disconnect(&connection_id, connection_token)
        .await
        .map_err(|e| e.safe_message())
}

/// Rotate the native endpoint key between renderer account lifecycles
#[tauri::command]
pub async fn p2p_rotate_identity(state: State<'_, AppState>) -> Result<String, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.rotate_identity().await.map_err(|e| e.safe_message())
}

/// Send message
#[tauri::command]
pub async fn p2p_send(
    connection_id: String,
    connection_token: u64,
    message_json: String,
    state: State<'_, AppState>,
) -> Result<P2PSendResult, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.send(&connection_id, connection_token, message_json)
        .await
        .map_err(|e| e.safe_message())
}

/// Mark native connection as authenticated after PQ peer handshake
#[tauri::command]
pub async fn p2p_authenticate_connection(
    connection_id: String,
    connection_token: u64,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.authenticate(&connection_id, connection_token)
        .await
        .map_err(|e| e.safe_message())
}

/// Get clients locally advertised onion endpoint URL
#[tauri::command]
pub async fn p2p_local_endpoint(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    Ok(p2p.local_endpoint())
}
