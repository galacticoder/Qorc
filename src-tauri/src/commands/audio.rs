use crate::audio_playback::AudioPlaybackInfo;
use crate::constants::audio::{FRAME_BYTES, FRAME_SAMPLES, MAX_OPUS_PACKET_BYTES};
use crate::state::AppState;
use std::borrow::Cow;
use tauri::{
    State,
    ipc::{Request, Response},
};
use zeroize::Zeroizing;

fn session_id<'a>(request: &'a Request<'_>) -> Result<&'a str, String> {
    request
        .headers()
        .get("x-qorc-audio-session")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "invalid audio codec session".to_string())
}

fn raw_body<'a>(request: &'a Request<'_>, max_bytes: usize) -> Result<Cow<'a, [u8]>, String> {
    super::binary_body(request, max_bytes).map_err(|()| "invalid audio codec body".to_string())
}

#[tauri::command]
pub fn audio_opus_start(session_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    state.audio_codec.start(&session_id)?;
    Ok(true)
}

#[tauri::command]
pub fn audio_opus_stop(session_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    state.audio_codec.stop(&session_id)?;
    Ok(true)
}

#[tauri::command]
pub fn audio_opus_encode(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<Response, String> {
    let session_id = session_id(&request)?;
    let input = raw_body(&request, FRAME_BYTES)?;
    let packet = state.audio_codec.encode(session_id, &input)?;
    Ok(Response::new(packet))
}

#[tauri::command]
pub fn audio_opus_decode_playback(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<AudioPlaybackInfo, String> {
    let session_id = session_id(&request)?;
    let fec = request
        .headers()
        .get("x-qorc-opus-fec")
        .and_then(|value| value.to_str().ok())
        == Some("1");
    let packet = raw_body(&request, MAX_OPUS_PACKET_BYTES)?;
    let mut pcm = Zeroizing::new([0.0; FRAME_SAMPLES]);
    let decoded = state
        .audio_codec
        .decode(session_id, &packet, fec, &mut pcm)?;
    state.audio_playback.push(session_id, &pcm[..decoded])?;
    state.audio_playback.info(session_id)
}

#[tauri::command]
pub fn audio_playback_info(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<AudioPlaybackInfo, String> {
    state.audio_playback.info(&session_id)
}

#[tauri::command]
pub async fn audio_playback_start(
    session_id: String,
    device_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let audio_playback = state.audio_playback.clone();
    tauri::async_runtime::spawn_blocking(move || {
        audio_playback.start(&session_id, device_id.as_deref())
    })
    .await
    .map_err(|_| "audio playback failed to start".to_string())??;
    Ok(true)
}

#[tauri::command]
pub async fn audio_playback_stop(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let audio_playback = state.audio_playback.clone();
    tauri::async_runtime::spawn_blocking(move || audio_playback.stop(&session_id))
        .await
        .map_err(|_| "audio playback failed to stop".to_string())??;
    Ok(true)
}
