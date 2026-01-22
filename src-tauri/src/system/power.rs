//! Power Save Blocker
//!
//! Prevents system sleep during calls

use crate::error::QorResult;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Power save blocker manager
pub struct PowerSaveBlocker {
    blockers: RwLock<HashMap<u32, BlockerHandle>>,
    next_id: AtomicU32,
}

/// Internal blocker handle
struct BlockerHandle {
    #[cfg(target_os = "linux")]
    inhibit_cookie: Option<u32>,
    #[cfg(target_os = "macos")]
    assertion_id: Option<u32>,
    #[cfg(target_os = "windows")]
    thread_state: Option<u32>,
    _blocker_type: BlockerType,
}

/// Type of power save blocking
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BlockerType {
    PreventDisplaySleep,
    PreventSystemSleep,
}

impl Default for BlockerType {
    fn default() -> Self {
        BlockerType::PreventDisplaySleep
    }
}

impl PowerSaveBlocker {
    /// Create new power save blocker manager
    pub fn new() -> Self {
        Self {
            blockers: RwLock::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        }
    }

    /// Start blocking power save
    pub fn start(&self, blocker_type: BlockerType) -> QorResult<u32> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        
        let handle = self.create_blocker(blocker_type)?;
        self.blockers.write().insert(id, handle);
        
        Ok(id)
    }

    /// Stop blocking power save
    pub fn stop(&self, id: u32) -> QorResult<bool> {
        if let Some(handle) = self.blockers.write().remove(&id) {
            self.release_blocker(handle)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if a blocker is active
    pub fn is_started(&self, id: u32) -> bool {
        self.blockers.read().contains_key(&id)
    }

    /// Create platform-specific blocker
    #[cfg(target_os = "linux")]
    fn create_blocker(&self, blocker_type: BlockerType) -> QorResult<BlockerHandle> {
        let cookie = inhibit_sleep_linux(blocker_type)?;
        
        Ok(BlockerHandle {
            inhibit_cookie: Some(cookie),
            _blocker_type: blocker_type,
        })
    }

    #[cfg(target_os = "macos")]
    fn create_blocker(&self, blocker_type: BlockerType) -> QorResult<BlockerHandle> {
        let assertion_id = create_power_assertion_macos(blocker_type)?;
        
        Ok(BlockerHandle {
            assertion_id: Some(assertion_id),
            _blocker_type: blocker_type,
        })
    }

    #[cfg(target_os = "windows")]
    fn create_blocker(&self, blocker_type: BlockerType) -> QorResult<BlockerHandle> {
        set_execution_state_windows(blocker_type, true)?;
        
        Ok(BlockerHandle {
            thread_state: Some(1),
            _blocker_type: blocker_type,
        })
    }

    /// Release platform-specific blocker
    #[cfg(target_os = "linux")]
    fn release_blocker(&self, handle: BlockerHandle) -> QorResult<()> {
        if let Some(cookie) = handle.inhibit_cookie {
            uninhibit_sleep_linux(cookie)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn release_blocker(&self, handle: BlockerHandle) -> QorResult<()> {
        if let Some(assertion_id) = handle.assertion_id {
            release_power_assertion_macos(assertion_id)?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn release_blocker(&self, handle: BlockerHandle) -> QorResult<()> {
        if handle.thread_state.is_some() {
            set_execution_state_windows(handle.blocker_type, false)?;
        }
        Ok(())
    }
}

impl Default for PowerSaveBlocker {
    fn default() -> Self {
        Self::new()
    }
}

// Linux

#[cfg(target_os = "linux")]
fn inhibit_sleep_linux(blocker_type: BlockerType) -> QorResult<u32> {
    use std::process::Command;

    let reason = match blocker_type {
        BlockerType::PreventDisplaySleep => "Qor-Chat call in progress (display)",
        BlockerType::PreventSystemSleep => "Qor-Chat call in progress (system)",
    };
    
    let output = Command::new("gnome-session-inhibit")
        .args(["--inhibit", "idle:suspend", "--reason", reason, "sleep", "infinity"])
        .spawn();
    
    if output.is_ok() {
        return Ok(output.unwrap().id());
    }
    
    // Try xdg-screensaver
    let output = Command::new("xdg-screensaver")
        .arg("suspend")
        .arg("1")
        .output();
    
    if output.is_ok() {
        return Ok(1);
    }
    
    // Fallback return a dummy cookie
    Ok(0)
}

#[cfg(target_os = "linux")]
fn uninhibit_sleep_linux(cookie: u32) -> QorResult<()> {
    use std::process::Command;
    
    if cookie > 0 {
        let _ = Command::new("kill")
            .arg(cookie.to_string())
            .output();
    }
    
    // Resume screensaver
    let _ = Command::new("xdg-screensaver")
        .arg("resume")
        .arg("1")
        .output();
    
    Ok(())
}

// macOS

#[cfg(target_os = "macos")]
fn create_power_assertion_macos(blocker_type: BlockerType) -> QorResult<u32> {
    use std::process::Command;
    
    let args = match blocker_type {
        BlockerType::PreventDisplaySleep => vec!["-d", "-w"],
        BlockerType::PreventSystemSleep => vec!["-i", "-w"],
    };
    
    let child = Command::new("caffeinate")
        .args(args)
        .arg(std::process::id().to_string())
        .spawn()
        .map_err(|e| QorError::SystemError(format!("Failed to start caffeinate: {}", e)))?;
    
    Ok(child.id())
}

#[cfg(target_os = "macos")]
fn release_power_assertion_macos(assertion_id: u32) -> QorResult<()> {
    use std::process::Command;
    
    // Kill caffeinate process
    let _ = Command::new("kill")
        .arg(assertion_id.to_string())
        .output();
    
    Ok(())
}

// Windows

#[cfg(target_os = "windows")]
fn set_execution_state_windows(blocker_type: BlockerType, enable: bool) -> QorResult<()> {
    unsafe {
        let flags = if enable {
            match blocker_type {
                BlockerType::PreventDisplaySleep => {
                    winapi::um::winbase::ES_CONTINUOUS | 
                    winapi::um::winbase::ES_DISPLAY_REQUIRED |
                    winapi::um::winbase::ES_SYSTEM_REQUIRED
                }
                BlockerType::PreventSystemSleep => {
                    winapi::um::winbase::ES_CONTINUOUS | 
                    winapi::um::winbase::ES_SYSTEM_REQUIRED
                }
            }
        } else {
            winapi::um::winbase::ES_CONTINUOUS
        };
        
        let result = winapi::um::winbase::SetThreadExecutionState(flags);
        if result == 0 {
            return Err(QorError::SystemError("SetThreadExecutionState failed".to_string()));
        }
    }
    
    Ok(())
}