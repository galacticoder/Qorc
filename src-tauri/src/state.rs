//! Application state management
//!
//! Centralized state for all application services.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::database::DatabaseManager;
use crate::network::p2p::P2PSignalingHandler;
use crate::network::websocket::WebSocketHandler;
use crate::signal_protocol::SignalHandler;
use crate::storage::SecureStorage;
use crate::system::notification::NotificationHandler;
use crate::tor::TorManager;

/// Background session state for when the window is hidden
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct BackgroundSessionState {
    pub is_background_mode: bool,
    pub timestamp: i64,
    pub ws_connected: bool,
    pub p2p_signaling_connected: bool,
    pub session_id: Option<String>,
    pub username: Option<String>,
    pub pq_session_keys: Option<PQSessionKeys>,
}

/// Post-quantum session keys for background persistence
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PQSessionKeys {
    pub session_id: String,
    pub send_key: String,
    pub recv_key: String,
    pub fingerprint: String,
    pub established_at: i64,
}

/// Pending message for delivery after window restore
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PendingMessage {
    pub message: serde_json::Value,
    pub timestamp: i64,
}

/// Central application state
#[allow(dead_code)]
pub struct AppState {
    /// Secure storage handler
    pub storage: RwLock<Option<Arc<SecureStorage>>>,

    /// Signal Protocol handler
    pub signal_handler: RwLock<Option<Arc<SignalHandler>>>,

    /// Tor manager
    pub tor_manager: RwLock<Option<Arc<TorManager>>>,

    /// WebSocket handler
    pub websocket_handler: RwLock<Option<Arc<WebSocketHandler>>>,

    /// P2P signaling handler
    pub p2p_handler: RwLock<Option<Arc<P2PSignalingHandler>>>,

    /// Notification handler
    pub notification_handler: RwLock<Option<Arc<NotificationHandler>>>,
    
    /// Native Encrypted Database
    pub database: RwLock<Option<Arc<DatabaseManager>>>,
    
    /// Background session state
    pub background_state: RwLock<Option<BackgroundSessionState>>,

    /// Pending server messages for background mode
    pub pending_messages: RwLock<Vec<PendingMessage>>,

    /// Power save blocker ID
    pub power_save_blocker_id: RwLock<Option<u32>>,

    /// Whether window is currently destroyed background mode
    pub is_window_destroyed: RwLock<bool>,

    /// Cached peer Kyber public keys
    pub peer_kyber_keys: RwLock<HashMap<String, String>>,

    /// Download settings
    pub download_path: RwLock<Option<String>>,
    pub auto_save: RwLock<bool>,

    /// Power save blocker manager
    pub power_blocker: RwLock<Option<Arc<crate::system::power::PowerSaveBlocker>>>,

    /// Close to tray setting
    pub close_to_tray: RwLock<bool>,
}

#[allow(dead_code)]
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
            background_state: RwLock::new(None),
            pending_messages: RwLock::new(Vec::new()),
            power_save_blocker_id: RwLock::new(None),
            is_window_destroyed: RwLock::new(false),
            peer_kyber_keys: RwLock::new(HashMap::new()),
            download_path: RwLock::new(None),
            auto_save: RwLock::new(true),
            power_blocker: RwLock::new(Some(Arc::new(crate::system::power::PowerSaveBlocker::new()))),
            close_to_tray: RwLock::new(true),
        }
    }

    /// Get storage handler
    pub fn storage(&self) -> Option<Arc<SecureStorage>> {
        self.storage.read().clone()
    }

    /// Get Signal handler
    pub fn signal(&self) -> Option<Arc<SignalHandler>> {
        self.signal_handler.read().clone()
    }

    /// Get Signal handler alias
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
    pub fn p2p(&self) -> Option<Arc<P2PSignalingHandler>> {
        self.p2p_handler.read().clone()
    }

    /// Get P2P handler alias
    pub fn p2p_handler(&self) -> Option<Arc<P2PSignalingHandler>> {
        self.p2p_handler.read().clone()
    }

    /// Get notification handler
    pub fn notifications(&self) -> Option<Arc<NotificationHandler>> {
        self.notification_handler.read().clone()
    }

    /// Get Database manager
    pub fn database(&self) -> Option<Arc<DatabaseManager>> {
        self.database.read().clone()
    }

    /// Get power blocker
    pub fn power_blocker(&self) -> Option<Arc<crate::system::power::PowerSaveBlocker>> {
        self.power_blocker.read().clone()
    }

    /// Add pending message
    pub fn add_pending_message(&self, message: serde_json::Value) {
        let mut pending = self.pending_messages.write();
        pending.push(PendingMessage {
            message,
            timestamp: chrono::Utc::now().timestamp_millis(),
        });
    }

    /// Take all pending messages
    pub fn take_pending_messages(&self) -> Vec<PendingMessage> {
        let mut pending = self.pending_messages.write();
        std::mem::take(&mut *pending)
    }

    /// Set background mode
    pub fn set_background_mode(&self, enabled: bool) {
        let mut state = self.background_state.write();
        if enabled {
            *state = Some(BackgroundSessionState {
                is_background_mode: true,
                timestamp: chrono::Utc::now().timestamp_millis(),
                ws_connected: self
                    .websocket()
                    .map(|ws| ws.is_connected())
                    .unwrap_or(false),
                p2p_signaling_connected: self
                    .p2p()
                    .map(|p2p| p2p.has_active_connections())
                    .unwrap_or(false),
                session_id: None,
                username: None,
                pq_session_keys: None,
            });
        } else {
            *state = None;
        }

        // Notify handlers
        if let Some(ws) = self.websocket() {
            ws.set_background_mode(enabled);
        }
        if let Some(p2p) = self.p2p() {
            p2p.set_background_mode(enabled);
        }

        *self.is_window_destroyed.write() = enabled;
    }

    /// Get background state
    pub fn get_background_state(&self) -> Option<BackgroundSessionState> {
        self.background_state.read().clone()
    }

    /// Store peer Kyber key
    pub fn set_peer_kyber_key(&self, peer: String, key: String) {
        self.peer_kyber_keys.write().insert(peer, key);
    }

    /// Check if peer Kyber key exists
    pub fn has_peer_kyber_key(&self, peer: &str) -> bool {
        self.peer_kyber_keys.read().contains_key(peer)
    }

    /// Get peer Kyber key
    pub fn get_peer_kyber_key(&self, peer: &str) -> Option<String> {
        self.peer_kyber_keys.read().get(peer).cloned()
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
