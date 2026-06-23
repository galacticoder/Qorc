//! Application state management
//!
//! Centralized state for all application services.

use parking_lot::RwLock;
use std::sync::Arc;

use crate::database::DatabaseManager;
use crate::network::p2p::P2PTransportHandler;
use crate::network::websocket::WebSocketHandler;
use crate::signal_protocol::SignalHandler;
use crate::storage::SecureStorage;
use crate::system::notification::NotificationHandler;
use crate::tor::TorManager;

/// Central application state
pub struct AppState {
    /// Secure storage handler
    pub storage: RwLock<Option<Arc<SecureStorage>>>,

    /// Signal Protocol handler
    pub signal_handler: RwLock<Option<Arc<SignalHandler>>>,

    /// Tor manager
    pub tor_manager: RwLock<Option<Arc<TorManager>>>,

    /// WebSocket handler
    pub websocket_handler: RwLock<Option<Arc<WebSocketHandler>>>,

    /// P2P transport handler
    pub p2p_handler: RwLock<Option<Arc<P2PTransportHandler>>>,

    /// Notification handler
    pub notification_handler: RwLock<Option<Arc<NotificationHandler>>>,

    /// Native Encrypted Database
    pub database: RwLock<Option<Arc<DatabaseManager>>>,

    /// Whether window is currently destroyed background mode
    pub is_window_destroyed: RwLock<bool>,

    /// Power save blocker manager
    pub power_blocker: RwLock<Option<Arc<crate::system::power::PowerSaveBlocker>>>,

    /// Close to tray setting
    pub close_to_tray: RwLock<bool>,
}

impl AppState {
    /// Create new application state
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(None),
            signal_handler: RwLock::new(None),
            tor_manager: RwLock::new(None),
            websocket_handler: RwLock::new(None),
            p2p_handler: RwLock::new(None),
            notification_handler: RwLock::new(None),
            database: RwLock::new(None),
            is_window_destroyed: RwLock::new(false),
            power_blocker: RwLock::new(Some(Arc::new(
                crate::system::power::PowerSaveBlocker::new(),
            ))),
            close_to_tray: RwLock::new(true),
        }
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
    pub fn tor(&self) -> Option<Arc<TorManager>> {
        self.tor_manager.read().clone()
    }

    /// Get Tor manager alias
    pub fn tor_manager(&self) -> Option<Arc<TorManager>> {
        self.tor_manager.read().clone()
    }

    /// Get WebSocket handler
    pub fn websocket(&self) -> Option<Arc<WebSocketHandler>> {
        self.websocket_handler.read().clone()
    }

    /// Get P2P handler
    pub fn p2p(&self) -> Option<Arc<P2PTransportHandler>> {
        self.p2p_handler.read().clone()
    }

    /// Get P2P handler alias
    pub fn p2p_handler(&self) -> Option<Arc<P2PTransportHandler>> {
        self.p2p_handler.read().clone()
    }


    /// Get Database manager
    pub fn database(&self) -> Option<Arc<DatabaseManager>> {
        self.database.read().clone()
    }

    /// Get power blocker
    pub fn power_blocker(&self) -> Option<Arc<crate::system::power::PowerSaveBlocker>> {
        self.power_blocker.read().clone()
    }

    /// Set background mode
    pub fn set_background_mode(&self, enabled: bool) {
        // Notify handlers
        if let Some(ws) = self.websocket() {
            ws.set_background_mode(enabled);
        }
        if let Some(p2p) = self.p2p() {
            p2p.set_background_mode(enabled);
        }

        *self.is_window_destroyed.write() = enabled;
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
