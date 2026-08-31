//! Notification Handler
//!
//! System notifications

use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::error::{QorcError, QorcResult};
use crate::state::AppState;

const RATE_LIMIT_WINDOW_MS: u128 = 60_000;
const MAX_NOTIFICATIONS_PER_WINDOW: usize = 5;
const NOTIFICATION_TITLE: &str = "New qorc activity";
const NOTIFICATION_BODY: &str = "Open qorc to view it";

pub struct NotificationHandler {
    enabled: RwLock<bool>,
    notification_times: RwLock<Vec<Instant>>,
}

impl NotificationHandler {
    pub fn new() -> Self {
        Self {
            enabled: RwLock::new(true),
            notification_times: RwLock::new(Vec::new()),
        }
    }

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

        if !self.try_reserve_notification() {
            return Ok(false);
        }

        #[cfg(not(target_os = "windows"))]
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

pub async fn init(state: &AppState) -> QorcResult<()> {
    let handler = NotificationHandler::new();
    *state.notification_handler.write() = Some(Arc::new(handler));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_NOTIFICATIONS_PER_WINDOW, NotificationHandler};
    use std::sync::Arc;

    #[test]
    fn concurrent_reservations_cannot_exceed_rate_limit() {
        let handler = Arc::new(NotificationHandler::new());
        let threads: Vec<_> = (0..64)
            .map(|_| {
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || handler.try_reserve_notification())
            })
            .collect();

        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().expect("notification test thread panicked"))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, MAX_NOTIFICATIONS_PER_WINDOW);
    }
}
