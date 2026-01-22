//! P2P Signaling Commands

use tauri::State;
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::network::p2p::{P2PConnectResult, P2PSendResult};

/// P2P connection options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConnectOptions {
    pub username: Option<String>,
    pub registration_payload: Option<serde_json::Value>,
}

/// Connect to P2P signaling server
#[tauri::command]
pub async fn p2p_signaling_connect(
    connection_id: String,
    server_url: String,
    options: Option<P2PConnectOptions>,
    state: State<'_, AppState>,
) -> Result<P2PConnectResult, String> {
    let p2p = state.inner().p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;
    
    // Auto sync Tor status if manager is ready
    if let Some(tor) = state.inner().tor() {
        if let Ok(info) = tor.get_info().await {
            if info.bootstrapped {
                p2p.update_tor_config(info.socks_port);
                p2p.set_tor_ready(true);
            }
        }
    }

    let opts = options.unwrap_or_default();
    
    p2p.connect(
        &connection_id,
        &server_url,
        opts.username,
        opts.registration_payload,
    ).await
        .map_err(|e| e.safe_message())
}

impl Default for P2PConnectOptions {
    fn default() -> Self {
        Self {
            username: None,
            registration_payload: None,
        }
    }
}

/// Disconnect from P2P signaling server
#[tauri::command]
pub async fn p2p_signaling_disconnect(
    connection_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state.inner().p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;
    
    p2p.disconnect(&connection_id).await
        .map_err(|e| e.safe_message())
}

/// Send message
#[tauri::command]
pub async fn p2p_signaling_send(
    connection_id: String,
    message: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<P2PSendResult, String> {
    let p2p = state.inner().p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;
    
    p2p.send(&connection_id, message).await
        .map_err(|e| e.safe_message())
}

/// Get P2P signaling status
#[tauri::command]
pub async fn p2p_signaling_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let p2p = state.inner().p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;
    
    Ok(p2p.status())
}

/// Set P2P background mode
#[tauri::command]
pub async fn p2p_set_background_mode(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state.inner().p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;
    
    p2p.set_background_mode(enabled);
    Ok(true)
}

/// Set Tor ready for P2P
#[tauri::command]
pub async fn p2p_set_tor_ready(
    ready: bool,
    socks_port: Option<u16>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let p2p = state.inner().p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;
    
    p2p.set_tor_ready(ready);
    if let Some(port) = socks_port {
        p2p.update_tor_config(port);
    }
    
    Ok(true)
}
