use crate::microphone_capture::{MicrophoneDevice, MicrophoneFrame};
use crate::state::AppState;
use tauri::{State, ipc::Response};

const MICROPHONE_FRAME_HEADER_BYTES: usize = 24;
const MICROPHONE_FRAME_SAMPLES: usize = 960;

#[tauri::command]
pub async fn microphone_devices(
    state: State<'_, AppState>,
) -> Result<Vec<MicrophoneDevice>, String> {
    let microphone_capture = state.microphone_capture.clone();
    tauri::async_runtime::spawn_blocking(move || microphone_capture.devices())
        .await
        .map_err(|_| "microphone devices unavailable".to_string())?
}

#[tauri::command]
pub async fn audio_output_devices(
    state: State<'_, AppState>,
) -> Result<Vec<MicrophoneDevice>, String> {
    let microphone_capture = state.microphone_capture.clone();
    tauri::async_runtime::spawn_blocking(move || microphone_capture.output_devices())
        .await
        .map_err(|_| "audio output devices unavailable".to_string())?
}

#[tauri::command]
pub async fn microphone_capture_start(
    session_id: String,
    device_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    tracing::info!(
        selected_device = device_id.is_some(),
        "[CALL-DIAG] native-microphone-start-enter"
    );
    let microphone_capture = state.microphone_capture.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        microphone_capture.start(&session_id, device_id.as_deref())
    })
    .await
    .map_err(|_| "microphone capture failed to start".to_string())?;
    match &result {
        Ok(()) => tracing::info!("[CALL-DIAG] native-microphone-start-complete"),
        Err(error) => {
            tracing::warn!(error = %error, "[CALL-DIAG] native-microphone-start-failed")
        }
    }
    result?;
    Ok(true)
}

#[tauri::command]
pub fn microphone_capture_set_enabled(
    session_id: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    state.microphone_capture.set_enabled(&session_id, enabled)?;
    Ok(true)
}

#[tauri::command]
pub async fn microphone_capture_pull(
    session_id: String,
    after_sequence: u32,
    state: State<'_, AppState>,
) -> Result<Response, String> {
    let microphone_capture = state.microphone_capture.clone();
    let frame = tauri::async_runtime::spawn_blocking(move || {
        microphone_capture.pull(&session_id, after_sequence)
    })
    .await
    .map_err(|_| "microphone frame pull failed".to_string())??;
    Ok(Response::new(encode_frame(frame)?))
}

#[tauri::command]
pub async fn microphone_capture_stop(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let microphone_capture = state.microphone_capture.clone();
    tauri::async_runtime::spawn_blocking(move || microphone_capture.stop(&session_id))
        .await
        .map_err(|_| "microphone capture failed to stop".to_string())??;
    Ok(true)
}

fn encode_frame(frame: Option<MicrophoneFrame>) -> Result<Vec<u8>, String> {
    let Some(mut frame) = frame else {
        return Ok(vec![0; MICROPHONE_FRAME_HEADER_BYTES]);
    };
    if frame.samples.len() != MICROPHONE_FRAME_SAMPLES {
        frame.samples.fill(0.0);
        return Err("invalid microphone frame".to_string());
    }
    let mut output = Vec::with_capacity(
        MICROPHONE_FRAME_HEADER_BYTES + MICROPHONE_FRAME_SAMPLES * std::mem::size_of::<f32>(),
    );
    output.resize(MICROPHONE_FRAME_HEADER_BYTES, 0);
    output[0] = 1;
    output[1] = u8::from(frame.enabled);
    output[4..8].copy_from_slice(&frame.sequence.to_be_bytes());
    output[8..16].copy_from_slice(&frame.captured_at.to_be_bytes());
    output[16..20].copy_from_slice(&48_000u32.to_be_bytes());
    output[20..22].copy_from_slice(&(MICROPHONE_FRAME_SAMPLES as u16).to_be_bytes());
    for sample in &frame.samples {
        output.extend_from_slice(&sample.to_le_bytes());
    }
    frame.samples.fill(0.0);
    Ok(output)
}
