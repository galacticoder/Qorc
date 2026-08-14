//! Application state management

use parking_lot::RwLock;
use std::sync::Arc;

use crate::account_vault::AccountSession;
use crate::database::DatabaseManager;
use crate::network::p2p::P2PTransportHandler;
use crate::network::websocket::WebSocketHandler;
use crate::signal_protocol::SignalHandler;
use crate::storage::SecureStorage;
use crate::system::notification::NotificationHandler;
use crate::tor::TorManager;

pub struct AppState {
    pub account_session: RwLock<Option<Arc<AccountSession>>>,
    pub storage: RwLock<Option<Arc<SecureStorage>>>,
    pub signal_handler: RwLock<Option<Arc<SignalHandler>>>,
    pub tor_manager: RwLock<Option<Arc<TorManager>>>,
    pub websocket_handler: RwLock<Option<Arc<WebSocketHandler>>>,
    pub p2p_handler: RwLock<Option<Arc<P2PTransportHandler>>>,
    pub notification_handler: RwLock<Option<Arc<NotificationHandler>>>,
    pub database: RwLock<Option<Arc<DatabaseManager>>>,
    pub database_lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    pub power_blocker: Arc<crate::system::power::PowerSaveBlocker>,
    pub close_to_tray: RwLock<bool>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            account_session: RwLock::new(None),
            storage: RwLock::new(None),
            signal_handler: RwLock::new(None),
            tor_manager: RwLock::new(None),
            websocket_handler: RwLock::new(None),
            p2p_handler: RwLock::new(None),
            notification_handler: RwLock::new(None),
            database: RwLock::new(None),
            database_lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            power_blocker: Arc::new(crate::system::power::PowerSaveBlocker::new()),
            close_to_tray: RwLock::new(true),
        }
    }

    /// Get the currently unlocked native account session
    pub fn account_session(&self) -> Option<Arc<AccountSession>> {
        self.account_session.read().clone()
    }

    /// Get storage handler
    pub fn storage(&self) -> Option<Arc<SecureStorage>> {
        self.storage.read().clone()
    }

    /// Get Signal handler
    pub fn signal_handler(&self) -> Option<Arc<SignalHandler>> {
        self.signal_handler.read().clone()
    }

    /// Get Tor manager
    pub fn tor_manager(&self) -> Option<Arc<TorManager>> {
        self.tor_manager.read().clone()
    }

    /// Get WebSocket handler
    pub fn websocket(&self) -> Option<Arc<WebSocketHandler>> {
        self.websocket_handler.read().clone()
    }

    /// Get P2P handler
    pub fn p2p_handler(&self) -> Option<Arc<P2PTransportHandler>> {
        self.p2p_handler.read().clone()
    }

    /// Get Database manager
    pub fn database(&self) -> Option<Arc<DatabaseManager>> {
        self.database.read().clone()
    }

    /// Get the call sleep inhibitor.
    pub fn power_blocker(&self) -> Arc<crate::system::power::PowerSaveBlocker> {
        self.power_blocker.clone()
    }

    /// Get close to tray setting
    pub fn get_close_to_tray(&self) -> bool {
        *self.close_to_tray.read()
    }

    /// Set close to tray setting
    pub fn set_close_to_tray(&self, enabled: bool) {
        *self.close_to_tray.write() = enabled;
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Some(tor) = self.tor_manager.get_mut().as_ref().cloned() {
            tor.shutdown_now();
        }
    }
}
