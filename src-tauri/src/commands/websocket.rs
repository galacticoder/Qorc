//! WebSocket Commands

use crate::network::websocket::{ConnectResult, SendResult, WebSocketState};
use crate::state::AppState;
use log::{info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{
    State,
    ipc::{InvokeBody, Request, Response},
};

const TOR_RESTART_COOLDOWN_MS: u64 = 20_000;
static LAST_TOR_RESTART_MS: AtomicU64 = AtomicU64::new(0);

struct WsBinaryReceiveGuard<'a>(&'a AppState);

impl Drop for WsBinaryReceiveGuard<'_> {
    fn drop(&mut self) {
        self.0
            .websocket_binary_receive_active
            .store(false, Ordering::Release);
    }
}

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
    warn!("[TOR] managed Tor process not running, starting");
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

/// Send an encrypted fixed-size binary cell over WebSocket.
#[tauri::command]
pub async fn ws_send_binary(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<SendResult, String> {
    let connection_token = request
        .headers()
        .get("x-qorc-ws-token")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "Invalid WebSocket connection token".to_string())?;
    let payload = match request.body() {
        InvokeBody::Raw(body) => body.clone(),
        _ => return Err("Invalid WebSocket binary cell".to_string()),
    };
    let ws = state
        .inner()
        .websocket()
        .ok_or_else(|| "WebSocket handler not initialized".to_string())?;

    ws.send_binary(payload, connection_token)
        .await
        .map_err(|e| e.safe_message())
}

/// Receive one encrypted fixed-size cell as raw IPC bytes. The first eight
/// bytes are the big-endian native connection token and the remainder is the
/// exact WebSocket cell.
#[tauri::command]
pub async fn ws_receive_binary(state: State<'_, AppState>) -> Result<Response, String> {
    if state
        .websocket_binary_receive_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("WebSocket binary receive already in flight".to_string());
    }
    let _guard = WsBinaryReceiveGuard(state.inner());
    let event = {
        let mut receiver_slot = state.websocket_binary_receiver.lock().await;
        let receiver = receiver_slot
            .as_mut()
            .ok_or_else(|| "WebSocket binary receiver not initialized".to_string())?;
        tokio::select! {
            event = receiver.recv() => match event {
                Some(event) => Some(event),
                None => return Err("WebSocket binary receiver closed".to_string()),
            },
            _ = tokio::time::sleep(Duration::from_secs(30)) => None,
        }
    };
    let Some(event) = event else {
        return Ok(Response::new(Vec::new()));
    };
    let reserved_byte_len = event.reserved_byte_len();
    let bytes = event.into_bridge_bytes();
    crate::network::websocket::release_ws_inbound_bytes(reserved_byte_len);
    Ok(Response::new(bytes))
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
