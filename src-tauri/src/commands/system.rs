//! System Commands

use crate::state::AppState;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use url::Url;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "linux")]
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

const MAX_EXTERNAL_URL_BYTES: usize = 8 * 1024;
const MAX_FRONTEND_LOG_BATCH: usize = 32;
const MAX_FRONTEND_LOG_LINE_BYTES: usize = 128 * 1024;
const MAX_FRONTEND_LOG_BATCH_BYTES: usize = 4 * 1024 * 1024;
static EXTERNAL_DIALOG_ACTIVE: AtomicBool = AtomicBool::new(false);
static MEDIA_DIALOG_ACTIVE: AtomicBool = AtomicBool::new(false);

#[tauri::command]
pub async fn android_runtime_work_begin() -> Result<String, String> {
    #[cfg(target_os = "android")]
    return tokio::task::spawn_blocking(|| {
        tauri_plugin_qorc_media::call::<String>("workBegin", serde_json::json!({}))
    }).await.map_err(|_| "Android work worker failed".to_string())?;
    #[cfg(not(target_os = "android"))]
    Ok(String::new())
}

#[tauri::command]
pub async fn android_runtime_work_end(id: String) -> Result<bool, String> {
    if uuid::Uuid::parse_str(&id).is_err() { return Err("Invalid work lease".into()); }
    #[cfg(target_os = "android")]
    return tokio::task::spawn_blocking(move || {
        tauri_plugin_qorc_media::call::<bool>("workEnd", serde_json::json!({"id": id}))
    }).await.map_err(|_| "Android work worker failed".to_string())?;
    #[cfg(not(target_os = "android"))]
    Ok(true)
}

#[cfg(target_os = "android")]
#[derive(Default)]
struct AndroidClock {
    lease: u64,
    sequence: u64,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(target_os = "android")]
static ANDROID_CLOCK: std::sync::Mutex<AndroidClock> = std::sync::Mutex::new(AndroidClock {
    lease: 0,
    sequence: 0,
    cancel: None,
});

#[tauri::command]
pub async fn android_runtime_wait(
    clock_id: Option<u64>,
    sequence: u64,
    delay_ms: u32,
) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "android")]
    {
        if sequence > 9_007_199_254_740_991 || delay_ms > 2_147_483_647 {
            return Err("Invalid Android clock request".into());
        }
        let (lease, receiver) = {
            let mut clock = ANDROID_CLOCK
                .lock()
                .map_err(|_| "Android clock unavailable")?;
            if clock_id.is_none() {
                clock.lease = clock
                    .lease
                    .checked_add(1)
                    .filter(|id| *id <= 9_007_199_254_740_991)
                    .ok_or("Android clock exhausted")?;
                clock.sequence = 0;
                clock.cancel.take();
                return Ok(serde_json::json!({"clockId": clock.lease, "fired": false}));
            }
            let lease = clock_id.unwrap();
            if lease == 0 || lease != clock.lease || sequence <= clock.sequence {
                return Ok(serde_json::json!({"clockId": lease, "fired": false}));
            }
            clock.sequence = sequence;
            clock.cancel.take();
            if delay_ms == 0 {
                return Ok(serde_json::json!({"clockId": lease, "fired": false}));
            }
            let (cancel, receiver) = tokio::sync::oneshot::channel();
            clock.cancel = Some(cancel);
            (lease, receiver)
        };
        let fired = tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(delay_ms.into())) => true,
            _ = receiver => false,
        };
        if fired {
            let mut clock = ANDROID_CLOCK
                .lock()
                .map_err(|_| "Android clock unavailable")?;
            if clock.lease != lease || clock.sequence != sequence {
                return Ok(serde_json::json!({"clockId": lease, "fired": false}));
            }
            clock.cancel.take();
        }
        Ok(serde_json::json!({"clockId": lease, "fired": fired}))
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (clock_id, sequence, delay_ms);
        Err("Android clock is unavailable on this platform".into())
    }
}

#[cfg(target_os = "linux")]
const MEDIA_PERMISSION_LEASE_TTL: Duration = Duration::from_secs(10);

#[cfg(target_os = "linux")]
struct MediaPermissionLease {
    audio: bool,
    video: bool,
    expires_at: Instant,
}

#[cfg(target_os = "linux")]
static MEDIA_PERMISSION_LEASE: Mutex<Option<MediaPermissionLease>> = Mutex::new(None);

struct ExternalDialogGuard;

impl ExternalDialogGuard {
    fn acquire() -> Result<Self, String> {
        EXTERNAL_DIALOG_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| "Another external-link confirmation is active".to_string())
    }
}

struct MediaDialogGuard;

impl MediaDialogGuard {
    fn acquire() -> Result<Self, String> {
        MEDIA_DIALOG_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| "Another media confirmation is active".to_string())
    }
}

impl Drop for MediaDialogGuard {
    fn drop(&mut self) {
        MEDIA_DIALOG_ACTIVE.store(false, Ordering::Release);
    }
}

#[cfg(target_os = "linux")]
pub fn consume_media_permission_lease(audio: bool, video: bool) -> bool {
    let Ok(mut slot) = MEDIA_PERMISSION_LEASE.lock() else {
        return false;
    };
    let Some(lease) = slot.take() else {
        return false;
    };

    Instant::now() <= lease.expires_at
        && (!audio || lease.audio)
        && (!video || lease.video)
        && (audio || video)
}

async fn confirm_native_dialog(
    app: &AppHandle,
    title: &str,
    message: String,
    confirm_label: &str,
) -> bool {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(message)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            confirm_label.to_string(),
            "Cancel".to_string(),
        ))
        .show(move |confirmed| {
            let _ = response_tx.send(confirmed);
        });
    response_rx.await.unwrap_or(false)
}

impl Drop for ExternalDialogGuard {
    fn drop(&mut self) {
        EXTERNAL_DIALOG_ACTIVE.store(false, Ordering::Release);
    }
}

/// Get the runtime qorc instance id used for per instance storage paths
#[tauri::command]
pub fn get_instance_id() -> Result<String, String> {
    crate::system::get_instance_id().map_err(|error| error.safe_message())
}

#[tauri::command]
pub fn forward_client_logs(entries: Vec<String>) -> Result<bool, String> {
    if entries.is_empty() || entries.len() > MAX_FRONTEND_LOG_BATCH {
        return Err("Invalid client log batch".to_string());
    }
    let mut total_bytes = 0usize;
    for entry in &entries {
        if entry.is_empty() || entry.len() > MAX_FRONTEND_LOG_LINE_BYTES {
            return Err("Invalid client log entry".to_string());
        }
        total_bytes = total_bytes
            .checked_add(entry.len())
            .ok_or_else(|| "Invalid client log batch".to_string())?;
    }
    if total_bytes > MAX_FRONTEND_LOG_BATCH_BYTES {
        return Err("Invalid client log batch".to_string());
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for entry in entries {
        writeln!(output, "{entry}").map_err(|_| "Failed to forward client logs".to_string())?;
    }
    output
        .flush()
        .map_err(|_| "Failed to forward client logs".to_string())?;
    Ok(true)
}

/// Open URL in default browser
#[tauri::command]
pub async fn open_external(url: String, app: AppHandle) -> Result<bool, String> {
    if url.is_empty() || url.len() > MAX_EXTERNAL_URL_BYTES || url.chars().any(char::is_control) {
        return Err("Invalid external URL".to_string());
    }

    let parsed = Url::parse(&url).map_err(|_| "Invalid external URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Only HTTP(S) URLs allowed".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "External URL must include a host".to_string())?;
    if host.len() > 253 {
        return Err("External URL host is too long".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Credentials in external URLs are not allowed".to_string());
    }

    let _dialog_guard = ExternalDialogGuard::acquire()?;
    let destination = parsed
        .port()
        .map(|port| format!("{host}:{port}"))
        .unwrap_or_else(|| host.to_string());
    let confirmed = confirm_native_dialog(
        &app,
        "Open external link",
        format!(
            "Opening this link in your system browser may reveal your network address to {destination}. Continue?"
        ),
        "Open browser",
    )
    .await;
    if !confirmed {
        return Ok(false);
    }

    crate::system::platform::open_url(&app, parsed.as_str()).map(|_| true)
}

#[tauri::command]
pub async fn request_media_access(kind: String, app: AppHandle) -> Result<bool, String> {
    tracing::info!(kind = %kind, "[CALL-DIAG] native-media-request-enter");
    let (audio, video, description, enumeration_only) = match kind.as_str() {
        "audio" => (true, false, "microphone", false),
        "video" => (false, true, "camera or screen/window capture", false),
        "audio-video" => (true, true, "microphone and camera", false),
        "camera" => (false, false, "camera", false),
        "microphone" => (false, false, "microphone", false),
        "microphone-camera" => (false, false, "microphone and camera", false),
        "enumerate" => (false, false, "media device names and identifiers", true),
        _ => return Err("Invalid media access type".to_string()),
    };

    #[cfg(target_os = "android")]
    {
        let _ = (audio, video);
        let _dialog_guard = MediaDialogGuard::acquire()?;
        if enumeration_only {
            return Ok(confirm_native_dialog(
                &app,
                "Show media devices",
                format!("Allow Qorc to list your {description}?"),
                "Show devices",
            )
            .await);
        }
        let requested_kind = kind.clone();
        return tauri::async_runtime::spawn_blocking(move || {
            crate::android_media::permission(&requested_kind)
        })
        .await
        .map_err(|_| "Android media permission request failed".to_string())?;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = (audio, video);
        if !enumeration_only {
            let _ = (description, app);
            tracing::info!(kind = %kind, "[CALL-DIAG] native-media-request-auto-granted");
            return Ok(true);
        }
        let _dialog_guard = MediaDialogGuard::acquire()?;
        tracing::info!(kind = %kind, "[CALL-DIAG] native-media-dialog-before");
        let confirmed = confirm_native_dialog(
            &app,
            "Show media devices",
            format!("Allow Qorc to list your {description}?"),
            "Show devices",
        )
        .await;
        tracing::info!(kind = %kind, confirmed, "[CALL-DIAG] native-media-dialog-after");
        return Ok(confirmed);
    }

    #[cfg(target_os = "linux")]
    {
        let _dialog_guard = MediaDialogGuard::acquire()?;
        tracing::info!(kind = %kind, "[CALL-DIAG] native-media-dialog-before");
        let confirmed = confirm_native_dialog(
            &app,
            if enumeration_only {
                "Show media devices"
            } else {
                "Allow media access"
            },
            if enumeration_only {
                format!("Allow Qorc to list your {description}?")
            } else {
                format!("Allow Qorc to access your {description} for this action?")
            },
            if enumeration_only {
                "Show devices"
            } else {
                "Allow once"
            },
        )
        .await;
        tracing::info!(kind = %kind, confirmed, "[CALL-DIAG] native-media-dialog-after");

        let mut slot = MEDIA_PERMISSION_LEASE
            .lock()
            .map_err(|_| "Media permission state unavailable".to_string())?;
        *slot = if confirmed && !enumeration_only && (audio || video) {
            Some(MediaPermissionLease {
                audio,
                video,
                expires_at: Instant::now() + MEDIA_PERMISSION_LEASE_TTL,
            })
        } else {
            None
        };
        tracing::info!(
            kind = %kind,
            confirmed,
            lease_stored = confirmed && !enumeration_only && (audio || video),
            "[CALL-DIAG] native-media-request-complete"
        );
        Ok(confirmed)
    }
}

/// Start the single call sleep inhibitor.
#[tauri::command]
pub async fn power_save_blocker_start(state: State<'_, AppState>) -> Result<bool, String> {
    let blocker = state.power_blocker();
    tauri::async_runtime::spawn_blocking(move || blocker.start().map_err(|e| e.safe_message()))
        .await
        .map_err(|_| "Call wake lock worker failed".to_string())?
}

/// Stop the call sleep inhibitor.
#[tauri::command]
pub async fn power_save_blocker_stop(state: State<'_, AppState>) -> Result<bool, String> {
    let blocker = state.power_blocker();
    tauri::async_runtime::spawn_blocking(move || blocker.stop().map_err(|e| e.safe_message()))
        .await
        .map_err(|_| "Call wake lock worker failed".to_string())?
}

/// Get close to tray setting
#[tauri::command]
pub async fn get_close_to_tray(state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        let enabled = tokio::task::spawn_blocking(|| {
            tauri_plugin_qorc_media::call::<bool>("backgroundGet", serde_json::json!({}))
        })
        .await
        .map_err(|_| "Android background setting worker failed".to_string())??;
        state.set_close_to_tray(enabled);
        Ok(enabled)
    }
    #[cfg(not(target_os = "android"))]
    Ok(state.get_close_to_tray())
}

#[tauri::command]
pub async fn open_background_notice_settings() -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        tokio::task::spawn_blocking(|| {
            tauri_plugin_qorc_media::call::<bool>("backgroundNoticeSettings", serde_json::json!({}))
        })
        .await
        .map_err(|_| "Android notification settings worker failed".to_string())?
    }
    #[cfg(not(target_os = "android"))]
    Ok(false)
}

/// Set close to tray setting
#[tauri::command]
pub async fn set_close_to_tray(enabled: bool, state: State<'_, AppState>) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        let accepted = tokio::task::spawn_blocking(move || {
            tauri_plugin_qorc_media::call::<bool>(
                "backgroundSet",
                serde_json::json!({ "enabled": enabled }),
            )
        })
        .await
        .map_err(|_| "Android background setting worker failed".to_string())??;
        if !accepted {
            return Ok(false);
        }
    }
    state.set_close_to_tray(enabled);
    Ok(true)
}

/// Increment tray unread badge count
#[tauri::command]
pub fn tray_increment_unread() {
    #[cfg(desktop)]
    crate::system::tray::increment_unread();
}

/// Clear tray unread badge count
#[tauri::command]
pub fn tray_clear_unread() {
    #[cfg(desktop)]
    crate::system::tray::clear_unread();
}
