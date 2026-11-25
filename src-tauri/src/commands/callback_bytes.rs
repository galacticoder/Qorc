use crate::constants::system::CALLBACK_CHUNK_BYTES;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use tauri::{AppHandle, State, ipc::Channel};
use crate::state::AppState;

#[derive(Serialize)]
pub struct ByteChunk {
    offset: usize,
    data: String,
}

pub(super) fn send_bytes(bytes: &[u8], channel: &Channel<ByteChunk>) -> Result<usize, String> {
    send_bytes_in_chunks(bytes, channel, CALLBACK_CHUNK_BYTES)
}

pub(super) fn send_bytes_in_chunks(
    bytes: &[u8],
    channel: &Channel<ByteChunk>,
    chunk_bytes: usize,
) -> Result<usize, String> {
    for (index, chunk) in bytes.chunks(chunk_bytes).enumerate() {
        channel.send(ByteChunk { offset: index * chunk_bytes, data: STANDARD.encode(chunk) })
            .map_err(|_| "Native callback delivery failed".to_string())?;
    }
    Ok(bytes.len())
}

fn send_json<T: Serialize>(value: &T, channel: &Channel<ByteChunk>) -> Result<usize, String> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| "Native response encoding failed".to_string())?);
    send_bytes(&bytes, channel)
}

#[tauri::command]
pub async fn account_open_channel(
    app_handle: AppHandle, state: State<'_, AppState>, account_owner: String,
    username: String, password: String, passphrase: String, on_chunk: Channel<ByteChunk>,
) -> Result<usize, String> {
    let result = super::account::account_open(app_handle, state, account_owner, username, password, passphrase).await?;
    send_json(&result, &on_chunk)
}

#[tauri::command]
pub async fn account_public_keys_channel(state: State<'_, AppState>, on_chunk: Channel<ByteChunk>) -> Result<usize, String> {
    let result = super::account::account_public_keys(state).await?;
    send_json(&result, &on_chunk)
}

#[tauri::command]
pub async fn pir_generate_query_channel(
    app: AppHandle, count: u32, entry_bytes: u32, target_row: u32, on_chunk: Channel<ByteChunk>,
) -> Result<usize, String> {
    let result = super::pir::pir_generate_query(app, count, entry_bytes, target_row).await.map_err(|e| e.safe_message())?;
    let delivered = send_json(&result, &on_chunk);
    if delivered.is_err() { let _ = super::pir::pir_discard_query(result.session_id).await; }
    delivered
}

#[tauri::command]
pub async fn pir_generate_batch_query_channel(
    app: AppHandle, count: u32, entry_bytes: u32, target_rows: Vec<u32>, on_chunk: Channel<ByteChunk>,
) -> Result<usize, String> {
    let result = super::pir::pir_generate_batch_query(app, count, entry_bytes, target_rows).await.map_err(|e| e.safe_message())?;
    let delivered = send_json(&result, &on_chunk);
    if delivered.is_err() { let _ = super::pir::pir_discard_query(result.session_id).await; }
    delivered
}
