//! System Commands

use crate::state::AppState;
use crate::system::screen_capture::ScreenSource;
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

    open::that(parsed.as_str())
        .map(|_| true)
        .map_err(|_| "Failed to open URL".to_string())
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

    #[cfg(not(target_os = "linux"))]
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
            format!("Allow qorc to list your {description}?"),
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
                format!("Allow qorc to list your {description}?")
            } else {
                format!("Allow qorc to access your {description} for this action?")
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

#[tauri::command]
pub async fn get_screen_sources(app: AppHandle) -> Result<Vec<ScreenSource>, String> {
    let _dialog_guard = MediaDialogGuard::acquire()?;
    let confirmed = confirm_native_dialog(
        &app,
        "Show screen sources",
        "Show qorc the names of your open windows and displays for the screen-share picker? Nothing is shared until you select a source."
            .to_string(),
        "Show sources",
    )
    .await;
    if !confirmed {
        return Err("Screen source access denied".to_string());
    }

    crate::system::screen_capture::get_sources()
        .await
        .map_err(|e| e.safe_message())
}

/// Start the single call sleep inhibitor.
#[tauri::command]
pub fn power_save_blocker_start(state: State<'_, AppState>) -> Result<bool, String> {
    state.power_blocker().start().map_err(|e| e.safe_message())
}

/// Stop the call sleep inhibitor.
#[tauri::command]
pub fn power_save_blocker_stop(state: State<'_, AppState>) -> Result<bool, String> {
    state.power_blocker().stop().map_err(|e| e.safe_message())
}

/// Get close to tray setting
#[tauri::command]
pub fn get_close_to_tray(state: State<'_, AppState>) -> bool {
    state.get_close_to_tray()
}

/// Set close to tray setting
#[tauri::command]
pub fn set_close_to_tray(enabled: bool, state: State<'_, AppState>) -> bool {
    state.set_close_to_tray(enabled);
    true
}

/// Increment tray unread badge count
#[tauri::command]
pub fn tray_increment_unread(app: AppHandle) {
    crate::system::tray::increment_unread(&app);
}

/// Clear tray unread badge count
#[tauri::command]
pub fn tray_clear_unread(app: AppHandle) {
    crate::system::tray::clear_unread(&app);
}
