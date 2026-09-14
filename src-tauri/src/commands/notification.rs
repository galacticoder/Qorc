//! Notification Commands

use crate::state::AppState;
use tauri::State;

async fn dispatch_notification(
    show: impl FnOnce() -> Result<bool, String> + Send + 'static,
) -> Result<bool, String> {
    tauri::async_runtime::spawn_blocking(show)
        .await
        .map_err(|_| "Notification worker failed".to_string())?
}

/// Show a system notification
#[tauri::command]
pub async fn notification_show(state: State<'_, AppState>) -> Result<bool, String> {
    let handler = state
        .notification_handler
        .read()
        .clone()
        .ok_or_else(|| "Notification handler not initialized".to_string())?;
    dispatch_notification(move || handler.show().map_err(|e| e.safe_message())).await
}

/// Set notifications enabled/disabled
#[tauri::command]
pub async fn notification_set_enabled(
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    if let Some(handler) = state.notification_handler.read().as_ref() {
        handler.set_enabled(enabled);
        Ok(true)
    } else {
        Err("Notification handler not initialized".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::dispatch_notification;
    use crate::system::notification::NotificationHandler;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn notification_backend_can_enter_its_own_runtime() {
        let caller_thread = std::thread::current().id();
        let result = dispatch_notification(move || {
            assert_ne!(std::thread::current().id(), caller_thread);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .build()
                .unwrap();
            Ok(runtime.block_on(async { true }))
        })
        .await;
        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn notification_backend_errors_reach_the_caller() {
        let result = dispatch_notification(|| Err("Notification failed".to_string())).await;
        assert_eq!(result, Err("Notification failed".to_string()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn linux_notification_backend_can_query_dbus_without_a_runtime_panic() {
        let result = dispatch_notification(|| {
            notify_rust::get_server_information()
                .map(|_| true)
                .map_err(|_| "Notification service unavailable".to_string())
        })
        .await;
        assert!(
            result == Ok(true) || result == Err("Notification service unavailable".to_string())
        );
    }

    #[tokio::test]
    async fn disabled_notifications_remain_suppressed() {
        let handler = NotificationHandler::new();
        handler.set_enabled(false);
        let result =
            dispatch_notification(move || handler.show().map_err(|e| e.safe_message())).await;
        assert_eq!(result, Ok(false));
    }
}
