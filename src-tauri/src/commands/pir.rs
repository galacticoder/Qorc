//! Client side PIR driven through `qorc-pir-client` sidecar

use std::io::{Read, Write};
use std::process::Child;
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use tauri::Manager;

use crate::error::{QorcError, QorcResult};

const OP_QUERY: u8 = 1;
const OP_DECODE: u8 = 2;
const OP_DISCARD: u8 = 3;
const OP_QUERY_BATCH: u8 = 4;
const OP_DECODE_BATCH: u8 = 5;
const STATUS_OK: u8 = 0;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: u32 = 1 << 20;
const MAX_ENTRY_BYTES: u32 = 1 << 20;
const MAX_BATCH_QUERIES: usize = 16;

static SIDECAR: Mutex<Option<Child>> = Mutex::new(None);

pub(crate) fn stop_for_local_reset() -> Result<(), String> {
    let mut guard = SIDECAR.lock().map_err(|_| "PIR worker lock unavailable")?;
    if let Some(mut child) = guard.take() { let _ = child.kill(); let _ = child.wait(); }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PirQuery {
    pub session_id: u32,
    pub query: String,
    pub pub_params: String,
}

fn validation_started(app: &tauri::AppHandle) -> QorcResult<()> {
    let mut guard = SIDECAR
        .lock()
        .map_err(|_| QorcError::Internal("PIR lock".into()))?;
    if app.state::<crate::state::AppState>().resetting_local_data.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(QorcError::Internal("Local app data is being reset".into()));
    }
    if let Some(child) = guard.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return Ok(());
        }
    }
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|_| QorcError::Internal("App cache directory is unavailable".into()))?;
    let child = crate::pir_runtime::sidecar_command(&cache)?
        .spawn()
        .map_err(|_| QorcError::Internal("PIR sidecar failed to start".to_string()))?;
    *guard = Some(child);
    Ok(())
}

fn call(op: u8, payload: &[u8]) -> QorcResult<Vec<u8>> {
    let mut guard = SIDECAR
        .lock()
        .map_err(|_| QorcError::Internal("PIR lock".into()))?;
    let child = guard
        .as_mut()
        .ok_or_else(|| QorcError::Internal("PIR sidecar is not running".to_string()))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| QorcError::Internal("PIR sidecar stdin closed".to_string()))?;
    let length = (payload.len() + 1) as u32;
    stdin
        .write_all(&length.to_le_bytes())
        .and_then(|_| stdin.write_all(&[op]))
        .and_then(|_| stdin.write_all(payload))
        .and_then(|_| stdin.flush())
        .map_err(|_| QorcError::Internal("PIR sidecar write failed".to_string()))?;

    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| QorcError::Internal("PIR sidecar stdout closed".to_string()))?;
    let mut header = [0u8; 4];
    stdout
        .read_exact(&mut header)
        .map_err(|_| QorcError::Internal("PIR sidecar read failed".to_string()))?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(QorcError::Internal(
            "PIR sidecar sent an invalid frame".to_string(),
        ));
    }
    let mut frame = vec![0u8; length];
    stdout
        .read_exact(&mut frame)
        .map_err(|_| QorcError::Internal("PIR sidecar read failed".to_string()))?;

    if frame[0] != STATUS_OK {
        return Err(QorcError::Internal(
            "PIR sidecar rejected the request".to_string(),
        ));
    }
    Ok(frame[1..].to_vec())
}

#[tauri::command]
pub async fn pir_generate_query(
    app: tauri::AppHandle,
    count: u32,
    entry_bytes: u32,
    target_row: u32,
) -> QorcResult<PirQuery> {
    if count == 0 || count > MAX_RECORDS || entry_bytes == 0 || entry_bytes > MAX_ENTRY_BYTES {
        return Err(QorcError::Internal(
            "Invalid PIR database shape".to_string(),
        ));
    }
    if target_row >= count.next_power_of_two().max(2048) {
        return Err(QorcError::Internal("Invalid PIR row".to_string()));
    }
    validation_started(&app)?;

    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&entry_bytes.to_le_bytes());
    payload.extend_from_slice(&target_row.to_le_bytes());

    parse_query_response(call(OP_QUERY, &payload)?)
}

fn parse_query_response(response: Vec<u8>) -> QorcResult<PirQuery> {
    if response.len() < 12 {
        return Err(QorcError::Internal(
            "PIR sidecar returned a short query".to_string(),
        ));
    }
    let session_id = u32::from_le_bytes(response[0..4].try_into().unwrap());
    let query_len = u32::from_le_bytes(response[4..8].try_into().unwrap()) as usize;
    let params_len = u32::from_le_bytes(response[8..12].try_into().unwrap()) as usize;
    if session_id == 0 || response.len() != 12 + query_len + params_len {
        return Err(QorcError::Internal(
            "PIR sidecar returned a malformed query".to_string(),
        ));
    }
    Ok(PirQuery {
        session_id,
        query: BASE64.encode(&response[12..12 + query_len]),
        pub_params: BASE64.encode(&response[12 + query_len..]),
    })
}

#[tauri::command]
pub async fn pir_generate_batch_query(
    app: tauri::AppHandle,
    count: u32,
    entry_bytes: u32,
    target_rows: Vec<u32>,
) -> QorcResult<PirQuery> {
    if count == 0
        || count > MAX_RECORDS
        || entry_bytes == 0
        || entry_bytes > MAX_ENTRY_BYTES
        || target_rows.is_empty()
        || target_rows.len() > MAX_BATCH_QUERIES
    {
        return Err(QorcError::Internal(
            "Invalid PIR database shape".to_string(),
        ));
    }
    let padded_count = count.next_power_of_two().max(2048);
    if target_rows
        .iter()
        .any(|target_row| *target_row >= padded_count)
    {
        return Err(QorcError::Internal("Invalid PIR row".to_string()));
    }
    validation_started(&app)?;

    let mut payload = Vec::with_capacity(12 + target_rows.len() * 4);
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&entry_bytes.to_le_bytes());
    payload.extend_from_slice(&(target_rows.len() as u32).to_le_bytes());
    for target_row in target_rows {
        payload.extend_from_slice(&target_row.to_le_bytes());
    }
    parse_query_response(call(OP_QUERY_BATCH, &payload)?)
}

fn decode_response(op: u8, response: String, session_id: u32) -> QorcResult<String> {
    if session_id == 0 {
        return Err(QorcError::Internal("Invalid PIR session".to_string()));
    }
    let bytes = BASE64
        .decode(&response)
        .map_err(|_| QorcError::Internal("Invalid PIR response encoding".to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(QorcError::Internal("Invalid PIR response".to_string()));
    }
    let mut payload = Vec::with_capacity(4 + bytes.len());
    payload.extend_from_slice(&session_id.to_le_bytes());
    payload.extend_from_slice(&bytes);
    Ok(BASE64.encode(call(op, &payload)?))
}

#[tauri::command]
pub async fn pir_decode_response(response: String, session_id: u32) -> QorcResult<String> {
    decode_response(OP_DECODE, response, session_id)
}

#[tauri::command]
pub async fn pir_decode_batch_response(response: String, session_id: u32) -> QorcResult<String> {
    decode_response(OP_DECODE_BATCH, response, session_id)
}

#[tauri::command]
pub async fn pir_discard_query(session_id: u32) -> QorcResult<()> {
    if session_id == 0 {
        return Err(QorcError::Internal("Invalid PIR session".to_string()));
    }
    call(OP_DISCARD, &session_id.to_le_bytes())?;
    Ok(())
}
