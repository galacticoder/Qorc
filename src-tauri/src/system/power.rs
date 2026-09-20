//! Bounded powersave for active calls

use crate::error::{QorcError, QorcResult};
use parking_lot::Mutex;

pub struct PowerSaveBlocker {
    active: Mutex<Option<BlockerHandle>>,
}

struct BlockerHandle {
    #[cfg(target_os = "linux")]
    child: std::process::Child,
    #[cfg(target_os = "windows")]
    worker: WindowsBlocker,
}

impl PowerSaveBlocker {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(None),
        }
    }

    pub fn start(&self) -> QorcResult<bool> {
        let mut active = self.active.lock();
        if active.is_some() {
            return Ok(false);
        }
        *active = Some(create_blocker()?);
        Ok(true)
    }

    pub fn stop(&self) -> QorcResult<bool> {
        let mut active = self.active.lock();
        let Some(handle) = active.take() else {
            return Ok(false);
        };
        release_blocker(handle)?;
        Ok(true)
    }
}

impl Default for PowerSaveBlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PowerSaveBlocker {
    fn drop(&mut self) {
        if let Some(handle) = self.active.get_mut().take() {
            let _ = release_blocker(handle);
        }
    }
}

#[cfg(target_os = "linux")]
fn create_blocker() -> QorcResult<BlockerHandle> {
    use std::path::Path;
    use std::process::{Command, Stdio};

    let sleep = "/usr/bin/sleep";
    let inhibitor = "/usr/bin/systemd-inhibit";
    if !Path::new(sleep).is_file() || !Path::new(inhibitor).is_file() {
        return Err(QorcError::SystemError(
            "Sleep inhibitor is unavailable".to_string(),
        ));
    }
    let child = Command::new(inhibitor)
        .args([
            "--what=idle:sleep",
            "--mode=block",
            "--why=Qorc call in progress",
            sleep,
            "infinity",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| QorcError::SystemError("Failed to start sleep inhibitor".to_string()))?;
    Ok(BlockerHandle { child })
}

#[cfg(target_os = "linux")]
fn release_blocker(mut handle: BlockerHandle) -> QorcResult<()> {
    match handle.child.try_wait() {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            handle.child.kill().map_err(|_| {
                QorcError::SystemError("Failed to stop sleep inhibitor".to_string())
            })?;
            handle.child.wait().map_err(|_| {
                QorcError::SystemError("Failed to reap sleep inhibitor".to_string())
            })?;
            Ok(())
        }
        Err(_) => Err(QorcError::SystemError(
            "Failed to inspect sleep inhibitor".to_string(),
        )),
    }
}

#[cfg(target_os = "windows")]
struct WindowsBlocker {
    stop_tx: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
fn create_blocker() -> QorcResult<BlockerHandle> {
    use std::sync::mpsc;
    use std::time::Duration;

    let (stop_tx, stop_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("qorc-power-inhibitor".to_string())
        .spawn(move || {
            let enabled = set_execution_state_windows(true);
            let ready = enabled.is_ok();
            let _ = ready_tx.send(enabled);
            if ready {
                let _ = stop_rx.recv();
                let _ = set_execution_state_windows(false);
            }
        })
        .map_err(|_| QorcError::SystemError("Failed to start sleep inhibitor".to_string()))?;

    match ready_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(())) => Ok(BlockerHandle {
            worker: WindowsBlocker {
                stop_tx,
                thread: Some(thread),
            },
        }),
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(QorcError::SystemError(error))
        }
        Err(_) => {
            let _ = stop_tx.send(());
            let _ = thread.join();
            Err(QorcError::SystemError(
                "Sleep inhibitor startup timed out".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "windows")]
fn release_blocker(mut handle: BlockerHandle) -> QorcResult<()> {
    let _ = handle.worker.stop_tx.send(());
    if let Some(thread) = handle.worker.thread.take() {
        thread
            .join()
            .map_err(|_| QorcError::SystemError("Sleep inhibitor thread failed".to_string()))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_execution_state_windows(enable: bool) -> Result<(), String> {
    use winapi::um::winbase::SetThreadExecutionState;
    use winapi::um::winnt::{ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED};

    let flags = if enable {
        ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED
    } else {
        ES_CONTINUOUS
    };
    let result = unsafe { SetThreadExecutionState(flags) };
    if result == 0 {
        return Err("SetThreadExecutionState failed".to_string());
    }
    Ok(())
}
