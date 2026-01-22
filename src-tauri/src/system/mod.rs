//! System integration
//!
//! Platform-specific system integration.

pub mod notification;
pub mod power;
pub mod screen_capture;
pub mod tray;
 
/// Get instance from environment
pub fn get_instance_id() -> Option<String> {
    std::env::var("QOR_INSTANCE_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
}
