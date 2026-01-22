//! WebSocket Commands

use tauri::State;
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::network::websocket::{ConnectResult, SendResult, WebSocketState};

/// Connect to WebSocket server
#[tauri::command]
pub async fn ws_connect(
    state: State<'_, AppState>,
) -> Result<ConnectResult, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    // Auto-sync Tor status if manager is ready
    if let Some(tor) = state.inner().tor() {
        if let Ok(info) = tor.get_info().await {
            if info.bootstrapped {
                ws.update_tor_config(info.socks_port);
                ws.set_tor_ready(true);
            }
        }
    }
    
    ws.connect().await
        .map_err(|e| e.safe_message())
}

/// Disconnect from WebSocket server
#[tauri::command]
pub async fn ws_disconnect(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    ws.disconnect().await
        .map_err(|e| e.safe_message())
}

/// Send message over WebSocket
#[tauri::command]
pub async fn ws_send(
    payload: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<SendResult, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    ws.send(payload).await
        .map_err(|e| e.safe_message())
}

/// Set server URL
#[tauri::command]
pub async fn ws_set_server_url(
    url: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    ws.set_server_url(&url).await
        .map_err(|e| e.safe_message())?;
    
    // Explicitly persist to secure storage
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    if let Err(_) = storage.set("server_url", &url).await {}

    Ok(())
}

/// Get stored server URL
#[tauri::command]
pub async fn ws_get_server_url(
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    storage.get("server_url").await
        .map_err(|e| e.safe_message())
}

/// Probe server connectivity
#[tauri::command]
pub async fn ws_probe_connect(
    url: String,
    _timeout_ms: Option<u64>,
    state: State<'_, AppState>,
) -> Result<ProbeResult, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    // Auto-sync Tor status if manager is ready
    if let Some(tor) = state.inner().tor() {
        if let Ok(info) = tor.get_info().await {
            if info.bootstrapped {
                ws.update_tor_config(info.socks_port);
                ws.set_tor_ready(true);
            }
        }
    }

    let _ = ws.set_server_url(&url).await;
    
    // Try to connect
    match ws.connect().await {
        Ok(result) if result.success => {
            let _ = ws.disconnect().await;
            Ok(ProbeResult {
                success: true,
                error: None,
            })
        }
        Ok(result) => Ok(ProbeResult {
            success: false,
            error: result.error,
        }),
        Err(e) => Ok(ProbeResult {
            success: false,
            error: Some(e.safe_message()),
        }),
    }
}

/// Probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub success: bool,
    pub error: Option<String>,
}

/// Get WebSocket state
#[tauri::command]
pub async fn ws_get_state(
    state: State<'_, AppState>,
) -> Result<WebSocketState, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    Ok(ws.get_state())
}

/// Set background mode
#[tauri::command]
pub async fn ws_set_background_mode(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    ws.set_background_mode(enabled);
    Ok(true)
}

/// Set Tor ready status
#[tauri::command]
pub async fn ws_set_tor_ready(
    ready: bool,
    socks_port: Option<u16>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let ws = state.inner().websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    
    ws.set_tor_ready(ready);
    if let Some(port) = socks_port {
        ws.update_tor_config(port);
    }
    
    Ok(true)
}
