//! WebSocket Commands

use crate::network::websocket::{ConnectResult, SendResult, WebSocketState};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::State;

/// Connect to WebSocket server
#[tauri::command]
pub async fn ws_connect(state: State<'_, AppState>) -> Result<ConnectResult, String> {
    let ws = state
        .inner()
        .websocket()
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

    ws.connect().await.map_err(|e| e.safe_message())
}

/// Disconnect from WebSocket server
#[tauri::command]
pub async fn ws_disconnect(state: State<'_, AppState>) -> Result<bool, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.disconnect().await.map_err(|e| e.safe_message())
}

/// Send message over WebSocket
#[tauri::command]
pub async fn ws_send(
    payload: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<SendResult, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.send(payload).await.map_err(|e| e.safe_message())
}

/// Set server URL
#[tauri::command]
pub async fn ws_set_server_url(url: String, state: State<'_, AppState>) -> Result<(), String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.set_server_url(&url)
        .await
        .map_err(|e| e.safe_message())?;

    // Explicitly persist to secure storage
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    if let Err(_) = storage.set("server_url", &url).await {}

    Ok(())
}

/// Get stored server URL
#[tauri::command]
pub async fn ws_get_server_url(state: State<'_, AppState>) -> Result<Option<String>, String> {
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;

    storage
        .get("server_url")
        .await
        .map_err(|e| e.safe_message())
}

/// Probe server connectivity
#[tauri::command]
pub async fn ws_probe_connect(
    url: String,
    timeout_ms: Option<u64>,
    state: State<'_, AppState>,
) -> Result<ProbeResult, String> {
    let ws = state
        .inner()
        .websocket()
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

    let before_probe = ws.get_state();
    let timeout_ms = timeout_ms.unwrap_or(45_000).clamp(5_000, 120_000);

    ws.set_event_suppressed(true);

    // Try to connect
    let probe_result =
        match tokio::time::timeout(Duration::from_millis(timeout_ms), ws.connect()).await {
            Err(_) => {
                if !before_probe.connected {
                    let _ = ws.disconnect().await;
                }
                Ok(ProbeResult {
                    success: false,
                    error: Some("WebSocket probe timeout".to_string()),
                })
            }
            Ok(Ok(result)) if result.success => {
                if result.new_connection.unwrap_or(false) {
                    let _ = ws.disconnect().await;
                }
                Ok(ProbeResult {
                    success: true,
                    error: None,
                })
            }
            Ok(Ok(result)) => {
                if !before_probe.connected {
                    let _ = ws.disconnect().await;
                }
                Ok(ProbeResult {
                    success: false,
                    error: result.error,
                })
            }
            Ok(Err(e)) => {
                if !before_probe.connected {
                    let _ = ws.disconnect().await;
                }
                Ok(ProbeResult {
                    success: false,
                    error: Some(e.safe_message()),
                })
            }
        };

    ws.set_event_suppressed(false);
    probe_result
}

/// Probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub success: bool,
    pub error: Option<String>,
}

/// Get WebSocket state
#[tauri::command]
pub async fn ws_get_state(state: State<'_, AppState>) -> Result<WebSocketState, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    Ok(ws.get_state())
}

/// Set background mode
#[tauri::command]
pub async fn ws_set_background_mode(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let ws = state
        .inner()
        .websocket()
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
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.set_tor_ready(ready);
    if let Some(port) = socks_port {
        ws.update_tor_config(port);
    }

    Ok(true)
}
