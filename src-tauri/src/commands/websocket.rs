//! WebSocket Commands

use crate::network::websocket::{ConnectResult, SendResult, WebSocketState};
use crate::state::AppState;
use log::{info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::State;

const TOR_RESTART_COOLDOWN_MS: u64 = 20_000;
static LAST_TOR_RESTART_MS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn spawn_tor_restart_if_dead(app: &AppState) {
    let Some(tor) = app.tor_manager() else {
        return;
    };
    if tor.is_running() {
        return;
    }
    let now = now_ms();
    let last = LAST_TOR_RESTART_MS.load(Ordering::Relaxed);
    if now < last.saturating_add(TOR_RESTART_COOLDOWN_MS) {
        return;
    }
    if LAST_TOR_RESTART_MS
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    warn!("[TOR] managed Tor process is not running; starting it again");
    tauri::async_runtime::spawn(async move {
        match tor.start().await {
            Ok(_) => info!("[TOR] supervised restart completed"),
            Err(e) => warn!("[TOR] supervised restart failed: {}", e.safe_message()),
        }
    });
}

async fn sync_native_tor_state(
    app: &AppState,
    ws: &crate::network::websocket::WebSocketHandler,
) -> bool {
    let info = match app.tor_manager() {
        Some(tor) => tor.get_info().await.ok(),
        None => None,
    };
    let ready = info.as_ref().is_some_and(|value| value.bootstrapped);
    if let Some(info) = info.filter(|_| ready) {
        ws.update_tor_config(info.socks_port);
    }
    ws.set_tor_ready(ready);
    if !ready {
        spawn_tor_restart_if_dead(app);
    }
    ready
}

/// Connect to WebSocket server
#[tauri::command]
pub async fn ws_connect(state: State<'_, AppState>) -> Result<ConnectResult, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    let _control_guard = ws.lock_control().await;

    let _ = sync_native_tor_state(state.inner(), ws.as_ref()).await;

    ws.connect().await.map_err(|e| e.safe_message())
}

/// Disconnect from WebSocket server
#[tauri::command]
pub async fn ws_disconnect(
    connection_token: Option<u64>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.disconnect(connection_token)
        .await
        .map_err(|e| e.safe_message())
}

#[tauri::command]
pub async fn ws_rotate_socks_identity(state: State<'_, AppState>) -> Result<(), String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    let _control_guard = ws.lock_control().await;

    ws.rotate_socks_identity().map_err(|e| e.safe_message())
}

/// Send message over WebSocket
#[tauri::command]
pub async fn ws_send(
    payload_json: String,
    connection_token: u64,
    state: State<'_, AppState>,
) -> Result<SendResult, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.send(payload_json, connection_token)
        .await
        .map_err(|e| e.safe_message())
}

/// Set server URL
#[tauri::command]
pub async fn ws_set_server_url(url: String, state: State<'_, AppState>) -> Result<(), String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    let _control_guard = ws.lock_control().await;
    let connection_state = ws.get_state();
    if connection_state.connected || connection_state.connecting {
        return Err("Disconnect before changing servers".to_string());
    }
    let previous_url = ws.get_server_url();

    ws.set_server_url(&url)
        .await
        .map_err(|e| e.safe_message())?;
    let normalized_url = ws
        .get_server_url()
        .ok_or_else(|| "Server URL was not configured".to_string())?;

    if let Err(error) = storage.set("server_url", &normalized_url).await {
        if let Some(previous_url) = previous_url {
            let _ = ws.set_server_url(&previous_url).await;
        } else {
            ws.clear_server_url();
        }
        return Err(error.safe_message());
    }

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

/// Get WebSocket state
#[tauri::command]
pub async fn ws_get_state(state: State<'_, AppState>) -> Result<WebSocketState, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    Ok(ws.get_state())
}

#[tauri::command]
pub async fn ws_sync_tor_state(state: State<'_, AppState>) -> Result<bool, String> {
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;
    let _control_guard = ws.lock_control().await;
    let ready = sync_native_tor_state(state.inner(), ws.as_ref()).await;
    if !ready && ws.get_state().connected {
        let _ = ws.disconnect(ws.get_state().connection_token).await;
    }
    Ok(ready)
}
