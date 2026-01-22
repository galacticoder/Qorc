//! Notification Handler
//!
//! System notifications with platform-specific implementations.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::error::{QorError, QorResult};
use crate::state::AppState;

// Notification limits
const RATE_LIMIT_WINDOW_MS: u128 = 60_000;
const MAX_NOTIFICATIONS_PER_WINDOW: usize = 5;
const MAX_TITLE_LENGTH: usize = 120;
const MAX_BODY_LENGTH: usize = 500;

/// Notification handler
pub struct NotificationHandler {
    enabled: RwLock<bool>,
    notification_times: RwLock<Vec<Instant>>,
    badge_count: RwLock<u32>,
}

impl NotificationHandler {
    /// Create new handler
    pub fn new() -> Self {
        Self {
            enabled: RwLock::new(true),
            notification_times: RwLock::new(Vec::new()),
            badge_count: RwLock::new(0),
        }
    }

    /// Check if rate limited
    fn is_rate_limited(&self) -> bool {
        let now = Instant::now();
        let mut times = self.notification_times.write();

        // Remove old entries
        times.retain(|t| now.duration_since(*t).as_millis() < RATE_LIMIT_WINDOW_MS);

        times.len() >= MAX_NOTIFICATIONS_PER_WINDOW
    }

    /// Record notification
    fn record_notification(&self) {
        let mut times = self.notification_times.write();
        times.push(Instant::now());

        // Cleanup excess entries
        if times.len() > MAX_NOTIFICATIONS_PER_WINDOW * 2 {
            let drain_count = times.len() - MAX_NOTIFICATIONS_PER_WINDOW;
            times.drain(0..drain_count);
        }
    }

    /// Sanitize text
    fn sanitize_text(text: &str, max_length: usize) -> String {
        text.chars()
            .filter(|c| !c.is_control())
            .take(max_length)
            .collect::<String>()
            .trim()
            .to_string()
    }

    /// Show notification
    pub fn show(&self, title: &str, body: Option<&str>, _silent: bool) -> QorResult<bool> {
        if !*self.enabled.read() {
            return Ok(false);
        }

        if self.is_rate_limited() {
            return Ok(false);
        }

        let sanitized_title = Self::sanitize_text(title, MAX_TITLE_LENGTH);
        let sanitized_body = body
            .map(|b| Self::sanitize_text(b, MAX_BODY_LENGTH))
            .unwrap_or_default();

        #[cfg(not(target_os = "windows"))]
        {
            let mut notification = notify_rust::Notification::new();
            notification.summary(&sanitized_title);
            if !sanitized_body.is_empty() {
                notification.body(&sanitized_body);
            }

            notification.show()
                .map_err(|e| QorError::NotificationFailed(e.to_string()))?;
        }

        #[cfg(target_os = "windows")]
        {
            // Windows notifications
            notify_rust::Notification::new()
                .summary(&sanitized_title)
                .body(&sanitized_body)
                .show()
                .map_err(|e| QorError::NotificationFailed(e.to_string()))?;
        }

        self.record_notification();
        Ok(true)
    }

    /// Set enabled state
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write() = enabled;
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Set badge count
    pub fn set_badge_count(&self, count: u32) -> QorResult<()> {
        *self.badge_count.write() = count;
        
        // Platform-specific badge handling
        // Linux: typically not supported via standard API, but some DEs support it
        // macOS: dock badge
        // Windows: taskbar badge
        
        // NOTE: In a full Tauri app, you'd typically use app_handle.set_badge_count(count)
        // but here we are in a system handler that doesn't have the handle.
        // For now we persist it in state.
        
        Ok(())
    }

    /// Get badge count
    pub fn get_badge_count(&self) -> u32 {
        *self.badge_count.read()
    }

    /// Clear badge
    pub fn clear_badge(&self) -> QorResult<()> {
        self.set_badge_count(0)
    }
}

impl Default for NotificationHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize notification handler
pub async fn init(state: &AppState) -> QorResult<()> {
    let handler = NotificationHandler::new();
    *state.notification_handler.write() = Some(Arc::new(handler));
    Ok(())
}
