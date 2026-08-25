//! P2P Transport Commands

use crate::network::p2p::{P2PConnectResult, P2PEvent, P2PSendResult, release_inbound_bytes};
use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tauri::{
    State,
    ipc::{InvokeBody, Request, Response},
};

struct P2PReceiveGuard<'a>(&'a AppState);

impl Drop for P2PReceiveGuard<'_> {
    fn drop(&mut self) {
        self.0.p2p_receive_active.store(false, Ordering::Release);
    }
}

fn release_event(event: &P2PEvent) {
    release_inbound_bytes(event.reserved_byte_len());
}

fn drain_events(receiver: &mut tokio::sync::mpsc::Receiver<P2PEvent>) {
    while let Ok(event) = receiver.try_recv() {
        release_event(&event);
    }
}

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
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<P2PSendResult, String> {
    let headers = request.headers();
    let connection_id = headers
        .get("x-qor-p2p-connection")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "Invalid P2P connection identifier".to_string())?;
    let connection_token = headers
        .get("x-qor-p2p-token")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "Invalid P2P connection token".to_string())?;
    let deadline_ms = headers
        .get("x-qor-p2p-deadline")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0);
    let audio_endpoint = headers
        .get("x-qor-p2p-audio-endpoint")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let audio_lane_rtt_ceiling_ms = headers
        .get("x-qor-p2p-audio-rtt-ceiling")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=60_000).contains(value));
    let data = match request.body() {
        InvokeBody::Raw(body) => body.clone(),
        _ => return Err("Invalid P2P frame".to_string()),
    };
    let p2p = state
        .inner()
        .p2p_handler()
        .ok_or_else(|| "P2P handler not initialized".to_string())?;

    p2p.send(
        connection_id,
        connection_token,
        data,
        deadline_ms,
        audio_endpoint,
        audio_lane_rtt_ceiling_ms,
    )
    .await
    .map_err(|e| e.safe_message())
}

#[tauri::command]
pub async fn p2p_subscribe(
    subscription_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    if uuid::Uuid::parse_str(&subscription_id).is_err() {
        return Err("Invalid P2P subscription".to_string());
    }
    let replaced = state.p2p_subscription.write().replace(subscription_id);
    if replaced.is_some() {
        state.p2p_subscription_changed.notify_one();
    }
    let mut receiver_slot = state.p2p_event_receiver.lock().await;
    let Some(receiver) = receiver_slot.as_mut() else {
        *state.p2p_subscription.write() = None;
        return Err("P2P receiver not initialized".to_string());
    };
    drain_events(receiver);
    Ok(true)
}

#[tauri::command]
pub async fn p2p_receive(
    subscription_id: String,
    state: State<'_, AppState>,
) -> Result<Response, String> {
    if state.p2p_subscription.read().as_deref() != Some(subscription_id.as_str()) {
        return Err("Inactive P2P subscription".to_string());
    }
    if state
        .p2p_receive_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("P2P receive already in flight".to_string());
    }
    let _guard = P2PReceiveGuard(state.inner());
    let event = {
        let mut receiver_slot = state.p2p_event_receiver.lock().await;
        let receiver = receiver_slot
            .as_mut()
            .ok_or_else(|| "P2P receiver not initialized".to_string())?;
        let subscription_changed = state.p2p_subscription_changed.notified();
        tokio::pin!(subscription_changed);
        if state.p2p_subscription.read().as_deref() != Some(subscription_id.as_str()) {
            return Err("Inactive P2P subscription".to_string());
        }
        tokio::select! {
            event = receiver.recv() => match event {
                Some(event) => Some(event),
                None => return Err("P2P receiver closed".to_string()),
            },
            _ = &mut subscription_changed => None,
            _ = tokio::time::sleep(Duration::from_secs(30)) => None,
        }
    };
    let Some(event) = event else {
        return Ok(Response::new(Vec::new()));
    };
    if state.p2p_subscription.read().as_deref() != Some(subscription_id.as_str()) {
        release_event(&event);
        return Err("Inactive P2P subscription".to_string());
    }
    let reserved_byte_len = event.reserved_byte_len();
    let bytes = event
        .into_bridge_bytes()
        .ok_or_else(|| "Invalid P2P bridge event".to_string());
    release_inbound_bytes(reserved_byte_len);
    Ok(Response::new(bytes?))
}

#[tauri::command]
pub async fn p2p_unsubscribe(
    subscription_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    {
        let mut active = state.p2p_subscription.write();
        if active.as_deref() != Some(subscription_id.as_str()) {
            return Ok(false);
        }
        *active = None;
    }
    state.p2p_subscription_changed.notify_one();
    let mut receiver_slot = state.p2p_event_receiver.lock().await;
    if let Some(receiver) = receiver_slot.as_mut() {
        drain_events(receiver);
    }
    Ok(true)
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
