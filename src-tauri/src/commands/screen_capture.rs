use crate::screen_capture::ScreenFrame;
use crate::state::AppState;
use tauri::{State, ipc::Response};

const SCREEN_FRAME_HEADER_BYTES: usize = 32;

#[tauri::command]
pub async fn screen_capture_start(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    tracing::info!(target: "qor_chat_call_diag", "[CALL-DIAG] native-screen-start-enter");
    state.screen_capture.start(&session_id).await?;
    tracing::info!(target: "qor_chat_call_diag", "[CALL-DIAG] native-screen-start-complete");
    Ok(true)
}

#[tauri::command]
pub async fn screen_capture_pull(
    session_id: String,
    after_sequence: u64,
    state: State<'_, AppState>,
) -> Result<Response, String> {
    let screen_capture = state.screen_capture.clone();
    let frame = tauri::async_runtime::spawn_blocking(move || {
        screen_capture.pull(&session_id, after_sequence)
    })
    .await
    .map_err(|_| "screen frame pull failed".to_string())??;
    Ok(Response::new(encode_frame(frame)?))
}

#[tauri::command]
pub fn screen_capture_stop(session_id: String, state: State<'_, AppState>) -> Result<bool, String> {
    state.screen_capture.stop(&session_id)?;
    Ok(true)
}

fn encode_frame(frame: Option<ScreenFrame>) -> Result<Vec<u8>, String> {
    let Some(frame) = frame else {
        return Ok(vec![0; SCREEN_FRAME_HEADER_BYTES]);
    };
    let payload_len =
        u32::try_from(frame.bytes.len()).map_err(|_| "screen frame is too large".to_string())?;
    let mut output = Vec::with_capacity(SCREEN_FRAME_HEADER_BYTES + frame.bytes.len());
    output.resize(SCREEN_FRAME_HEADER_BYTES, 0);
    output[0] = 2;
    output[1] = 1;
    output[2] = 1;
    output[4..12].copy_from_slice(&frame.sequence.to_be_bytes());
    output[12..20].copy_from_slice(&frame.captured_at.to_be_bytes());
    output[20..22].copy_from_slice(&frame.width.to_be_bytes());
    output[22..24].copy_from_slice(&frame.height.to_be_bytes());
    output[24..28].copy_from_slice(&payload_len.to_be_bytes());
    output[28..30].copy_from_slice(&frame.frame_rate.to_be_bytes());
    output.extend_from_slice(&frame.bytes);
    Ok(output)
}
