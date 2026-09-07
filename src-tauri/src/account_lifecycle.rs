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

    // Keep the reservation until the KDF actually finishes: cancelling must not
    // allow an attacker to launch arbitrarily many 512 MiB KDF jobs.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn logout_during_delayed_unlock_cannot_install_secrets() {
        let lifecycle = Arc::new(AccountLifecycle::default());
        let started = Arc::new(Barrier::new(2));
        let finish = Arc::new(Barrier::new(2));
        let installed = Arc::new(AtomicBool::new(false));
        let worker = {
            let (lifecycle, started, finish, installed) = (
                lifecycle.clone(),
                started.clone(),
                finish.clone(),
                installed.clone(),
            );
            std::thread::spawn(move || {
                let permit = lifecycle.begin_open("alice").unwrap();
                started.wait();
                finish.wait();
                assert!(
                    permit
                        .commit(|| {
                            installed.store(true, Ordering::SeqCst);
                            Ok(())
                        })
                        .is_err()
                );
            })
        };
        started.wait();
        lifecycle.cancel_open("alice").unwrap();
        assert!(lifecycle.begin_open("alice").is_err());
        assert!(lifecycle.begin_open("bob").is_err());
        finish.wait();
        worker.join().unwrap();
        assert!(!installed.load(Ordering::SeqCst));
        assert!(
            lifecycle
                .begin_open("alice")
                .unwrap()
                .ensure_current()
                .is_ok()
        );
    }

    #[test]
    fn concurrent_opens_cannot_overwrite_a_vault_or_amplify_kdf_memory() {
        let lifecycle = AccountLifecycle::default();
        let permit = lifecycle.begin_open("alice").unwrap();
        std::thread::scope(|scope| {
            for _ in 0..128 {
                scope.spawn(|| assert!(lifecycle.begin_open("alice").is_err()));
            }
        });
        assert!(permit.ensure_current().is_ok());
        drop(permit);
        assert!(lifecycle.begin_open("bob").is_ok());
    }

    #[test]
    fn cleanup_for_another_account_does_not_cancel_the_current_open() {
        let lifecycle = AccountLifecycle::default();
        let permit = lifecycle.begin_open("bob").unwrap();
        lifecycle.cancel_open("alice").unwrap();
        assert_eq!(permit.commit(|| Ok(42)).unwrap(), 42);
        lifecycle.cancel_open("bob").unwrap();
        assert!(permit.ensure_current().is_err());
    }
}
