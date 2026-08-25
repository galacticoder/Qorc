use crate::camera_capture::{CameraDevice, CameraFrame};
use crate::state::AppState;
use tauri::{State, ipc::Response};

const CAMERA_FRAME_HEADER_BYTES: usize = 32;

#[tauri::command]
pub async fn camera_devices(state: State<'_, AppState>) -> Result<Vec<CameraDevice>, String> {
    let camera_capture = state.camera_capture.clone();
    tauri::async_runtime::spawn_blocking(move || camera_capture.devices())
        .await
        .map_err(|_| "camera devices unavailable".to_string())?
}

#[tauri::command]
pub async fn camera_capture_start(
    session_id: String,
    device_id: Option<String>,
    width: u32,
    height: u32,
    frame_rate: u32,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    tracing::info!(
        width,
        height,
        frame_rate,
        selected_device = device_id.is_some(),
        "[CALL-DIAG] native-camera-start-enter"
    );
    let camera_capture = state.camera_capture.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        camera_capture.start(&session_id, device_id.as_deref(), width, height, frame_rate)
    })
    .await
    .map_err(|_| {
        tracing::warn!("[CALL-DIAG] native-camera-start-task-failed");
        "camera capture failed to start".to_string()
    })?;
    match &result {
        Ok(()) => tracing::info!("[CALL-DIAG] native-camera-start-complete"),
        Err(error) => {
            tracing::warn!(error = %error, "[CALL-DIAG] native-camera-start-failed")
        }
    }
    result?;
    Ok(true)
}

#[tauri::command]
pub fn camera_capture_set_enabled(
    session_id: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    state.camera_capture.set_enabled(&session_id, enabled)?;
    Ok(true)
}

#[tauri::command]
pub async fn camera_capture_pull(
    session_id: String,
    after_sequence: u64,
    state: State<'_, AppState>,
) -> Result<Response, String> {
    let camera_capture = state.camera_capture.clone();
    let frame = tauri::async_runtime::spawn_blocking(move || {
        camera_capture.pull(&session_id, after_sequence)
    })
    .await
    .map_err(|_| "camera frame pull failed".to_string())??;
    Ok(Response::new(encode_frame(frame)?))
}

#[tauri::command]
pub async fn camera_capture_stop(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let camera_capture = state.camera_capture.clone();
    tauri::async_runtime::spawn_blocking(move || camera_capture.stop(&session_id))
        .await
        .map_err(|_| "camera capture failed to stop".to_string())??;
    Ok(true)
}

fn encode_frame(frame: Option<CameraFrame>) -> Result<Vec<u8>, String> {
    let Some(frame) = frame else {
        return Ok(vec![0; CAMERA_FRAME_HEADER_BYTES]);
    };
    let payload_len =
        u32::try_from(frame.bytes.len()).map_err(|_| "camera frame is too large".to_string())?;
    let mut output = Vec::with_capacity(CAMERA_FRAME_HEADER_BYTES + frame.bytes.len());
    output.resize(CAMERA_FRAME_HEADER_BYTES, 0);
    output[0] = 2;
    output[1] = 1;
    output[2] = u8::from(frame.enabled);
    output[4..12].copy_from_slice(&frame.sequence.to_be_bytes());
    output[12..20].copy_from_slice(&frame.captured_at.to_be_bytes());
    output[20..22].copy_from_slice(&frame.width.to_be_bytes());
    output[22..24].copy_from_slice(&frame.height.to_be_bytes());
    output[24..28].copy_from_slice(&payload_len.to_be_bytes());
    output[28..30].copy_from_slice(&frame.frame_rate.to_be_bytes());
    output.extend_from_slice(&frame.bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{CAMERA_FRAME_HEADER_BYTES, encode_frame};
    use crate::camera_capture::CameraFrame;

    #[test]
    fn camera_frame_response_is_bounded_binary() {
        let output = encode_frame(Some(CameraFrame {
            sequence: 7,
            captured_at: 9,
            width: 640,
            height: 360,
            frame_rate: 60,
            enabled: true,
            bytes: vec![0xff, 0xd8, 0xff, 0xd9],
        }))
        .unwrap();
        assert_eq!(output.len(), CAMERA_FRAME_HEADER_BYTES + 4);
        assert_eq!(output[0..4], [2, 1, 1, 0]);
        assert_eq!(u64::from_be_bytes(output[4..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_be_bytes(output[24..28].try_into().unwrap()), 4);
        assert_eq!(u16::from_be_bytes(output[28..30].try_into().unwrap()), 60);
    }
}
