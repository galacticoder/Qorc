//! Bounded native vault opening and cancellation independent of renderer state.

use std::sync::Mutex;

#[derive(Default)]
pub struct AccountLifecycle {
    opening: Mutex<Option<Opening>>,
}

struct Opening {
    owner: String,
    cancelled: bool,
}

pub struct AccountOpenPermit<'a> {
    lifecycle: &'a AccountLifecycle,
}

impl AccountLifecycle {
    pub fn cancel_all_open(&self) -> Result<(), String> {
        let mut opening = self.opening.lock().map_err(|_| "Account lifecycle unavailable")?;
        if let Some(attempt) = opening.as_mut() { attempt.cancelled = true; }
        Ok(())
    }
    pub fn begin_open(&self, owner: &str) -> Result<AccountOpenPermit<'_>, String> {
        let mut opening = self
            .opening
            .lock()
            .map_err(|_| "Account lifecycle unavailable")?;
        if opening.is_some() {
            return Err("Native account opening is already in progress".to_string());
        }
        *opening = Some(Opening {
            owner: owner.to_string(),
            cancelled: false,
        });
        Ok(AccountOpenPermit { lifecycle: self })
    }

    pub fn cancel_open(&self, owner: &str) -> Result<(), String> {
        let mut opening = self
            .opening
            .lock()
            .map_err(|_| "Account lifecycle unavailable")?;
        if let Some(attempt) = opening.as_mut().filter(|attempt| attempt.owner == owner) {
            attempt.cancelled = true;
        }
        Ok(())
    }
}

impl AccountOpenPermit<'_> {
    pub fn ensure_current(&self) -> Result<(), String> {
        self.commit(|| Ok(()))
    }

    // Cancellation and the final synchronous installation have one ordering.
    // The callback must not call back into AccountLifecycle.
    pub fn commit<T>(&self, install: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let opening = self
            .lifecycle
            .opening
            .lock()
            .map_err(|_| "Account lifecycle unavailable")?;
        if !opening.as_ref().is_some_and(|attempt| !attempt.cancelled) {
            return Err("Native account opening was cancelled".to_string());
        }
        install()
    }
}

impl Drop for AccountOpenPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut opening) = self.lifecycle.opening.lock() {
            *opening = None;
        }
    }
}
