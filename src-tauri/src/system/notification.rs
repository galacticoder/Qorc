//! Notification Handler
//!
//! System notifications

#[cfg(not(target_os = "android"))]
use crate::constants::system::{MAX_NOTIFICATIONS_PER_WINDOW, RATE_LIMIT_WINDOW_MS};
use std::sync::Arc;
#[cfg(not(target_os = "android"))]
use std::time::Instant;

use parking_lot::RwLock;

use crate::error::{QorcError, QorcResult};
use crate::state::AppState;

#[cfg(not(target_os = "android"))]
const NOTIFICATION_TITLE: &str = "New Qorc activity";
#[cfg(not(target_os = "android"))]
const NOTIFICATION_BODY: &str = "Open Qorc to view it";

pub struct NotificationHandler {
    enabled: RwLock<bool>,
    #[cfg(not(target_os = "android"))]
    notification_times: RwLock<Vec<Instant>>,
    #[cfg(target_os = "android")]
    app: Option<tauri::AppHandle>,
}

impl NotificationHandler {
    pub fn new() -> Self {
        Self {
            enabled: RwLock::new(true),
            #[cfg(not(target_os = "android"))]
            notification_times: RwLock::new(Vec::new()),
            #[cfg(target_os = "android")]
            app: None,
        }
    }

    #[cfg(not(target_os = "android"))]
    fn try_reserve_notification(&self) -> bool {
        let now = Instant::now();
        let mut times = self.notification_times.write();

        times.retain(|t| now.duration_since(*t).as_millis() < RATE_LIMIT_WINDOW_MS);
        if times.len() >= MAX_NOTIFICATIONS_PER_WINDOW {
            return false;
        }
        times.push(now);
        true
    }

    /// Show notification
    pub fn show(&self) -> QorcResult<bool> {
        if !*self.enabled.read() {
            return Ok(false);
        }

        #[cfg(target_os = "android")]
        {
            use tauri_plugin_notification::NotificationExt;
            let app = self.app.as_ref().ok_or_else(|| {
                QorcError::NotificationFailed("Notification backend is not initialized".to_string())
            })?;
            if app
                .notification()
                .permission_state()
                .map_err(|e| QorcError::NotificationFailed(e.to_string()))?
                != tauri::plugin::PermissionState::Granted
            {
                return Ok(false);
            }
            return tauri_plugin_qorc_media::call("activityNotification", serde_json::json!({}))
                .map_err(QorcError::NotificationFailed);
        }

        #[cfg(not(target_os = "android"))]
        if !self.try_reserve_notification() {
            return Ok(false);
        }

        #[cfg(target_os = "linux")]
        {
            let mut notification = notify_rust::Notification::new();
            notification.summary(NOTIFICATION_TITLE);
            notification.body(NOTIFICATION_BODY);

            notification
                .show()
                .map_err(|e| QorcError::NotificationFailed(e.to_string()))?;
        }

        #[cfg(target_os = "windows")]
        {
            // Windows notifications
            notify_rust::Notification::new()
                .summary(NOTIFICATION_TITLE)
                .body(NOTIFICATION_BODY)
                .show()
                .map_err(|e| QorcError::NotificationFailed(e.to_string()))?;
        }

        #[cfg(not(target_os = "android"))]
        Ok(true)
    }

    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write() = enabled;
    }
}

impl Default for NotificationHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn init(state: &AppState, _app: &tauri::AppHandle) -> QorcResult<()> {
    let handler = NotificationHandler::new();
    #[cfg(target_os = "android")]
    let handler = NotificationHandler {
        app: Some(_app.clone()),
        ..handler
    };
    *state.notification_handler.write() = Some(Arc::new(handler));
    Ok(())
}
