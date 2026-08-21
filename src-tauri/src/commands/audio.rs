use crate::state::AppState;
use tauri::{
    State,
    ipc::{InvokeBody, Request, Response},
};

fn session_id(request: &Request<'_>) -> Result<String, String> {
    request
        .headers()
        .get("x-qor-audio-session")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| "invalid audio codec session".to_string())
}

fn raw_body(request: &Request<'_>) -> Result<Vec<u8>, String> {
    match request.body() {
        InvokeBody::Raw(body) => Ok(body.clone()),
        _ => Err("invalid audio codec body".to_string()),
    }
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
    let packet = state
        .audio_codec
        .encode(&session_id, &raw_body(&request)?)?;
    Ok(Response::new(packet))
}

#[tauri::command]
pub fn audio_opus_decode(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<Response, String> {
    let session_id = session_id(&request)?;
    let fec = request
        .headers()
        .get("x-qor-opus-fec")
        .and_then(|value| value.to_str().ok())
        == Some("1");
    let pcm = state
        .audio_codec
        .decode(&session_id, &raw_body(&request)?, fec)?;
    Ok(Response::new(pcm))
}
