//! WebSocket Handler
//!
//! WebSocket connections through Tor SOCKS5 proxy

use log::{error, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard, mpsc, watch};
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::protocol::{CloseFrame, Message, WebSocketConfig, frame::coding::CloseCode},
};
use url::Url;
use uuid::Uuid;

use crate::error::{QorError, QorResult};
use crate::json_bounds::enforce_bounded_json_structure;

// Constants
const WEBSOCKET_UPGRADE_TIMEOUT_SECS: u64 = 30;
const SOCKS_CONNECT_TIMEOUT_SECS: u64 = 150;
const SERVER_CONNECTION_TIMEOUT_SECS: u64 = 10;
const _: () = assert!(
    SOCKS_CONNECT_TIMEOUT_SECS > 120,
    "must outlast Tor's own SocksTimeout so Tor owns the give-up decision"
);
const WEBSOCKET_WRITE_TIMEOUT_SECS: u64 = 30;
const STALE_CONNECTING_SECS: u64 = 180;
const MAX_WS_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WS_JSON_DEPTH: usize = 32;
const MAX_WS_JSON_STRUCTURAL_TOKENS: usize = 16 * 1024;
const MAX_WS_WRITE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const MAX_WS_PENDING_WRITES: usize = 1024;
const MAX_WS_PENDING_WRITE_BYTES: usize = 64 * 1024 * 1024;
const PQ_WS_FIXED_CELL_BYTES: usize = 64 * 1024;

fn connection_failure_diagnostic(error: &QorError) -> (&'static str, &'static str) {
    let QorError::Network(message) = error else {
        return ("validation", "invalid-input");
    };
    let normalized = message.to_ascii_lowercase();

    if normalized.contains("connection timeout") {
        ("tor-socks", "timeout")
    } else if normalized.contains("socks5 connection failed") {
        if normalized.contains("refused") {
            ("tor-socks", "listener-refused")
        } else if normalized.contains("not allowed") || normalized.contains("permission") {
            ("tor-socks", "proxy-denied")
        } else if normalized.contains("host unreachable")
            || normalized.contains("network unreachable")
        {
            ("tor-socks", "onion-unreachable")
        } else {
            ("tor-socks", "proxy-failure")
        }
    } else if normalized.contains("failed to build pq tls connector") {
        ("pq-tls-config", "configuration")
    } else if normalized.contains("websocket upgrade timeout") {
        ("pq-tls-websocket", "timeout")
    } else if normalized.contains("websocket upgrade failed") {
        if normalized.contains("tls")
            || normalized.contains("certificate")
            || normalized.contains("handshake")
            || normalized.contains("peer is incompatible")
        {
            ("pq-tls", "handshake")
        } else if normalized.contains("http") || normalized.contains("status") {
            ("websocket-upgrade", "http-rejected")
        } else {
            ("websocket-upgrade", "protocol-failure")
        }
    } else if normalized.contains("cancelled") {
        ("connection-state", "cancelled")
    } else {
        ("network", "unknown")
    }
}

#[derive(Default)]
struct PendingWriteBudget {
    frames: AtomicUsize,
    bytes: AtomicUsize,
}

impl PendingWriteBudget {
    fn try_reserve(&self, byte_len: usize) -> bool {
        if self
            .frames
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |pending| {
                (pending < MAX_WS_PENDING_WRITES).then_some(pending + 1)
            })
            .is_err()
        {
            return false;
        }

        let mut current = self.bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(byte_len) else {
                self.release_frame_only();
                return false;
            };
            if next > MAX_WS_PENDING_WRITE_BYTES {
                self.release_frame_only();
                return false;
            }
            match self.bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release_frame_only(&self) {
        let _ = self
            .frames
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |pending| {
                Some(pending.saturating_sub(1))
            });
    }

    fn release(&self, byte_len: usize) {
        self.release_frame_only();
        let _ = self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |pending| {
                Some(pending.saturating_sub(byte_len))
            });
    }
}

fn try_reserve_ws_inbound(byte_len: usize) -> bool {
    if WS_INBOUND_BUFFERED_FRAMES
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
            (pending < MAX_WS_INBOUND_BUFFERED_FRAMES).then_some(pending + 1)
        })
        .is_err()
    {
        return false;
    }

    let mut current = WS_INBOUND_BUFFERED_BYTES.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(byte_len) else {
            let _ = WS_INBOUND_BUFFERED_FRAMES.fetch_sub(1, Ordering::AcqRel);
            return false;
        };
        if next > MAX_WS_INBOUND_BUFFERED_BYTES {
            let _ = WS_INBOUND_BUFFERED_FRAMES.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        match WS_INBOUND_BUFFERED_BYTES.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

static WS_INBOUND_BUFFERED_BYTES: AtomicUsize = AtomicUsize::new(0);
static WS_INBOUND_BUFFERED_FRAMES: AtomicUsize = AtomicUsize::new(0);
const MAX_WS_INBOUND_BUFFERED_BYTES: usize = 64 * 1024 * 1024;
const MAX_WS_INBOUND_BUFFERED_FRAMES: usize = 4096;
pub const WS_EVENT_CHANNEL_CAPACITY: usize = MAX_WS_INBOUND_BUFFERED_FRAMES + 16;

pub fn release_ws_inbound_bytes(n: usize) {
    if n > 0 {
        let _ = WS_INBOUND_BUFFERED_FRAMES.fetch_update(
            Ordering::AcqRel,
            Ordering::Relaxed,
            |pending| Some(pending.saturating_sub(1)),
        );
        let _ = WS_INBOUND_BUFFERED_BYTES.fetch_update(
            Ordering::AcqRel,
            Ordering::Relaxed,
            |pending| Some(pending.saturating_sub(n)),
        );
    }
}

/// WebSocket connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

/// WebSocket handler state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketState {
    pub connected: bool,
    pub connecting: bool,
    pub queue_size: usize,
    #[serde(rename = "connectionToken")]
    pub connection_token: Option<u64>,
}

/// WebSocket connection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResult {
    pub success: bool,
    pub already_connected: Option<bool>,
    pub new_connection: Option<bool>,
    #[serde(rename = "connectionToken")]
    pub connection_token: Option<u64>,
    pub error: Option<String>,
}

/// WebSocket send result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub success: bool,
    pub queued: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsEvent {
    #[serde(rename = "__ws_connection_opened")]
    ConnectionOpened {
        #[serde(rename = "connectionToken")]
        connection_token: u64,
    },
    #[serde(rename = "__ws_connection_closed")]
    ConnectionClosed {
        #[serde(rename = "connectionToken")]
        connection_token: u64,
    },
    #[serde(rename = "__ws_connection_error")]
    ConnectionError {
        #[serde(rename = "connectionToken")]
        connection_token: u64,
        error: String,
    },
    #[serde(rename = "message")]
    Message {
        #[serde(rename = "connectionToken")]
        connection_token: u64,
        data: serde_json::Value,
        #[serde(skip)]
        byte_len: usize,
    },
}

pub struct WsBinaryMessage {
    connection_token: u64,
    data: Vec<u8>,
    byte_len: usize,
}

impl WsBinaryMessage {
    pub fn reserved_byte_len(&self) -> usize {
        self.byte_len
    }

    pub fn into_bridge_bytes(mut self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.data.len());
        bytes.extend_from_slice(&self.connection_token.to_be_bytes());
        bytes.append(&mut self.data);
        bytes
    }
}

type WsSink = futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

struct QueuedWsMessage {
    message: Option<Message>,
    reservation: Option<(Arc<PendingWriteBudget>, usize)>,
}

impl QueuedWsMessage {
    fn reserved(message: Message, budget: Arc<PendingWriteBudget>) -> Option<Self> {
        let byte_len = message.len();
        budget.try_reserve(byte_len).then_some(Self {
            message: Some(message),
            reservation: Some((budget, byte_len)),
        })
    }

    fn control(message: Message) -> Self {
        Self {
            message: Some(message),
            reservation: None,
        }
    }
}

impl Drop for QueuedWsMessage {
    fn drop(&mut self) {
        if let Some((budget, byte_len)) = self.reservation.take() {
            budget.release(byte_len);
        }
    }
}

#[derive(Clone)]
struct WsSenderEntry {
    connection_token: u64,
    sender: mpsc::UnboundedSender<QueuedWsMessage>,
    pending_writes: Arc<PendingWriteBudget>,
    cancel_tx: watch::Sender<bool>,
    local_closing: Arc<AtomicBool>,
}

#[derive(Clone)]
struct ConnectingAttempt {
    attempt_id: u64,
    cancel_tx: watch::Sender<bool>,
}

/// WebSocket Handler
pub struct WebSocketHandler {
    server_url: RwLock<Option<String>>,
    state: Arc<RwLock<ConnectionState>>,
    tor_ready: AtomicBool,
    tor_socks_port: AtomicU16,
    socks_isolation_username: RwLock<String>,
    tx: Arc<RwLock<Option<WsSenderEntry>>>,
    event_tx: Arc<RwLock<Option<mpsc::Sender<WsEvent>>>>,
    binary_tx: Arc<RwLock<Option<mpsc::Sender<WsBinaryMessage>>>>,
    connecting_started_at: RwLock<Option<Instant>>,
    connecting_attempt: RwLock<Option<ConnectingAttempt>>,
    connect_attempt_id: AtomicU64,
    control_lock: Mutex<()>,
}

impl WebSocketHandler {
    fn queue_connection_error(
        event_tx: &Arc<RwLock<Option<mpsc::Sender<WsEvent>>>>,
        connection_token: u64,
    ) {
        warn!(
            "[WS] queueing connection error for token={}",
            connection_token
        );
        if let Some(ref tx) = *event_tx.read() {
            let _ = tx.try_send(WsEvent::ConnectionError {
                connection_token,
                error: "WebSocket transport failed".to_string(),
            });
        }
    }

    /// Create new WebSocket handler
    pub fn new() -> Self {
        Self {
            server_url: RwLock::new(None),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            tor_ready: AtomicBool::new(false),
            tor_socks_port: AtomicU16::new(9150),
            socks_isolation_username: RwLock::new(Self::new_socks_isolation_username()),
            tx: Arc::new(RwLock::new(None)),
            event_tx: Arc::new(RwLock::new(None)),
            binary_tx: Arc::new(RwLock::new(None)),
            connecting_started_at: RwLock::new(None),
            connecting_attempt: RwLock::new(None),
            connect_attempt_id: AtomicU64::new(0),
            control_lock: Mutex::new(()),
        }
    }

    pub async fn lock_control(&self) -> MutexGuard<'_, ()> {
        self.control_lock.lock().await
    }

    /// Set server URL
    pub async fn set_server_url(&self, url: &str) -> QorResult<bool> {
        if url.is_empty() || url.len() > 2048 {
            return Err(QorError::InvalidArgument("Invalid server URL".to_string()));
        }

        let parsed = Url::parse(url)
            .map_err(|e| QorError::InvalidArgument(format!("Invalid URL format: {}", e)))?;

        if parsed.scheme() != "wss" {
            return Err(QorError::InvalidArgument(
                "Only secure WebSocket (wss://) allowed".to_string(),
            ));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| QorError::InvalidArgument("Invalid hostname".to_string()))?;
        if host.len() > 253 {
            return Err(QorError::InvalidArgument("Invalid hostname".to_string()));
        }

        if parsed.username() != "" || parsed.password().is_some() {
            return Err(QorError::InvalidArgument(
                "Credentials in URL not allowed".to_string(),
            ));
        }

        if parsed.fragment().is_some() {
            return Err(QorError::InvalidArgument(
                "URL fragments are not allowed".to_string(),
            ));
        }

        if parsed.query().is_some() || parsed.path() != "/" {
            return Err(QorError::InvalidArgument(
                "Server URL must not contain a path or query".to_string(),
            ));
        }

        *self.server_url.write() = Some(parsed.to_string());
        Ok(true)
    }

    pub fn clear_server_url(&self) {
        *self.server_url.write() = None;
    }

    pub fn get_server_url(&self) -> Option<String> {
        self.server_url.read().clone()
    }

    /// Set Tor ready status
    pub fn set_tor_ready(&self, ready: bool) {
        self.tor_ready.store(ready, Ordering::Relaxed);
    }

    /// Update Tor config
    pub fn update_tor_config(&self, socks_port: u16) {
        self.tor_socks_port.store(socks_port, Ordering::Relaxed);
    }

    fn new_socks_isolation_username() -> String {
        format!(
            "{}{}",
            crate::protocol_keys::WEBSOCKET_CONNECTION_ID_PREFIX,
            Uuid::new_v4().simple()
        )
    }

    pub fn rotate_socks_identity(&self) -> QorResult<()> {
        if *self.state.read() != ConnectionState::Disconnected
            || self.connecting_attempt.read().is_some()
            || self.tx.read().is_some()
        {
            return Err(QorError::InvalidArgument(
                "Disconnect before rotating the Tor stream identity".to_string(),
            ));
        }

        *self.socks_isolation_username.write() = Self::new_socks_isolation_username();
        Ok(())
    }

    /// Set event handler
    pub fn set_event_handler(&self, tx: mpsc::Sender<WsEvent>) {
        *self.event_tx.write() = Some(tx);
    }

    pub fn set_binary_handler(&self, tx: mpsc::Sender<WsBinaryMessage>) {
        *self.binary_tx.write() = Some(tx);
    }

    fn abort_transport_now(&self) {
        self.connect_attempt_id.fetch_add(1, Ordering::AcqRel);
        self.cancel_connecting_attempt();
        if let Some(entry) = self.tx.write().take() {
            let _ = entry.cancel_tx.send(true);
        }
        *self.state.write() = ConnectionState::Disconnected;
        *self.connecting_started_at.write() = None;
    }

    fn clear_transport_state(&self) {
        self.connect_attempt_id.fetch_add(1, Ordering::Relaxed);
        self.cancel_connecting_attempt();
        *self.tx.write() = None;
        *self.state.write() = ConnectionState::Disconnected;
        *self.connecting_started_at.write() = None;
    }

    fn cancel_connecting_attempt(&self) -> bool {
        let attempt = self.connecting_attempt.write().take();
        if let Some(attempt) = attempt {
            let _ = attempt.cancel_tx.send(true);
            true
        } else {
            false
        }
    }

    fn clear_connecting_attempt(&self, attempt_id: u64) {
        let mut current = self.connecting_attempt.write();
        if current
            .as_ref()
            .is_some_and(|attempt| attempt.attempt_id == attempt_id)
        {
            *current = None;
        }
    }

    async fn wait_for_connect_cancellation(cancel_rx: &mut watch::Receiver<bool>) {
        loop {
            if *cancel_rx.borrow() {
                return;
            }
            if cancel_rx.changed().await.is_err() {
                return;
            }
        }
    }

    fn connection_cancelled_error() -> QorError {
        QorError::Network("Connection attempt cancelled".to_string())
    }

    fn publish_connection(
        &self,
        attempt_id: u64,
        connect_cancel_rx: &watch::Receiver<bool>,
        entry: WsSenderEntry,
    ) -> QorResult<()> {
        let mut connecting_attempt = self.connecting_attempt.write();
        let attempt_is_current = connecting_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.attempt_id == attempt_id);
        if !attempt_is_current
            || self.connect_attempt_id.load(Ordering::Relaxed) != attempt_id
            || *connect_cancel_rx.borrow()
        {
            return Err(Self::connection_cancelled_error());
        }

        *self.tx.write() = Some(entry);
        *self.state.write() = ConnectionState::Connected;
        *self.connecting_started_at.write() = None;
        *connecting_attempt = None;
        Ok(())
    }

    /// Connect to server
    pub async fn connect(&self) -> QorResult<ConnectResult> {
        let server_url = self.server_url.read().clone();
        let url_str = match server_url {
            Some(url) => url,
            None => {
                error!("[WS] connect aborted: server URL not configured");
                return Ok(ConnectResult {
                    success: false,
                    already_connected: None,
                    new_connection: None,
                    connection_token: None,
                    error: Some("Server URL not configured".to_string()),
                });
            }
        };

        let should_clear_stale_connecting = {
            let state = *self.state.read();
            if state == ConnectionState::Connecting {
                let stale = self
                    .connecting_started_at
                    .read()
                    .map(|started| started.elapsed() > Duration::from_secs(STALE_CONNECTING_SECS))
                    .unwrap_or(true);
                if !stale {
                    return Ok(ConnectResult {
                        success: false,
                        already_connected: None,
                        new_connection: None,
                        connection_token: None,
                        error: Some("Connection in progress".to_string()),
                    });
                }
                true
            } else {
                false
            }
        };

        if should_clear_stale_connecting {
            warn!("[WS-BRIDGE] clearing stale websocket connection attempt");
            self.clear_transport_state();
        }

        {
            let state = *self.state.read();
            if state == ConnectionState::Connected {
                let connection_token = self.tx.read().as_ref().map(|entry| entry.connection_token);
                if connection_token.is_some() {
                    return Ok(ConnectResult {
                        success: true,
                        already_connected: Some(true),
                        new_connection: Some(false),
                        connection_token,
                        error: None,
                    });
                }
            }
        }

        if !self.tor_ready.load(Ordering::Relaxed) {
            error!("[WS] connect aborted: Tor setup not complete");
            return Ok(ConnectResult {
                success: false,
                already_connected: None,
                new_connection: None,
                connection_token: None,
                error: Some("Tor setup not complete".to_string()),
            });
        }

        let attempt_id = self
            .connect_attempt_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let (connect_cancel_tx, connect_cancel_rx) = watch::channel(false);
        *self.connecting_attempt.write() = Some(ConnectingAttempt {
            attempt_id,
            cancel_tx: connect_cancel_tx,
        });
        *self.state.write() = ConnectionState::Connecting;
        *self.connecting_started_at.write() = Some(Instant::now());

        let connection_result = match tokio::time::timeout(
            Duration::from_secs(SERVER_CONNECTION_TIMEOUT_SECS),
            self.create_connection(&url_str, attempt_id, connect_cancel_rx),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(QorError::Network(
                "Server connection timed out after 10 seconds".to_string(),
            )),
        };
        self.clear_connecting_attempt(attempt_id);
        match connection_result {
            Ok(_) => Ok(ConnectResult {
                success: true,
                already_connected: Some(false),
                new_connection: Some(true),
                connection_token: Some(attempt_id),
                error: None,
            }),
            Err(e) => {
                let (stage, cause) = connection_failure_diagnostic(&e);
                error!(
                    "[WS-CONNECT] connection attempt failed stage={} cause={}",
                    stage, cause
                );
                if self.connect_attempt_id.load(Ordering::Relaxed) == attempt_id {
                    *self.state.write() = ConnectionState::Disconnected;
                    *self.connecting_started_at.write() = None;
                }
                Ok(ConnectResult {
                    success: false,
                    already_connected: None,
                    new_connection: None,
                    connection_token: None,
                    error: Some(e.safe_message()),
                })
            }
        }
    }

    /// Create WebSocket connection through Tor SOCKS5
    async fn create_connection(
        &self,
        url_input: &str,
        attempt_id: u64,
        mut connect_cancel_rx: watch::Receiver<bool>,
    ) -> QorResult<()> {
        let url_str = url_input.trim();
        let url = Url::parse(url_str)
            .map_err(|e| QorError::InvalidArgument(format!("Invalid URL: {}", e)))?;

        let host = url
            .host_str()
            .ok_or_else(|| QorError::InvalidArgument("No host in URL".to_string()))?;
        let port = url.port().unwrap_or(443);

        let socks_port = self.tor_socks_port.load(Ordering::Relaxed);

        // Connect through SOCKS5 proxy
        let socks_addr = format!("127.0.0.1:{}", socks_port);
        const ISOLATION_PASSWORD: &str = "isolate";
        let isolation_username = self.socks_isolation_username.read().clone();
        let tcp_stream = tokio::select! {
            _ = Self::wait_for_connect_cancellation(&mut connect_cancel_rx) => {
                return Err(Self::connection_cancelled_error());
            }
            result = tokio::time::timeout(
                Duration::from_secs(SOCKS_CONNECT_TIMEOUT_SECS),
                Socks5Stream::connect_with_password(
                    socks_addr.as_str(),
                    (host.to_string(), port),
                    &isolation_username,
                    ISOLATION_PASSWORD,
                ),
            ) => match result {
                Err(_) => {
                    error!(
                        "[WS] SOCKS connect timed out after {}s",
                        SOCKS_CONNECT_TIMEOUT_SECS
                    );
                    return Err(QorError::Network("Tor SOCKS connection timeout".to_string()));
                }
                Ok(inner) => inner.map_err(|error| {
                    QorError::Network(format!("SOCKS5 connection failed: {error}"))
                })?,
            },
        };

        let tcp = tcp_stream.into_inner();
        let tls_config = crate::crypto::tls::controlled_client_config(host.ends_with(".onion"))
            .map_err(|error| {
                QorError::Network(format!("Failed to build PQ TLS connector: {error}"))
            })?;
        let connector = tokio_tungstenite::Connector::Rustls(tls_config);

        let ws_config = WebSocketConfig {
            max_message_size: Some(MAX_WS_MESSAGE_BYTES),
            max_frame_size: Some(MAX_WS_MESSAGE_BYTES),
            max_write_buffer_size: MAX_WS_WRITE_BUFFER_BYTES,
            ..Default::default()
        };
        let upgrade = tokio::select! {
            _ = Self::wait_for_connect_cancellation(&mut connect_cancel_rx) => {
                return Err(Self::connection_cancelled_error());
            }
            result = tokio::time::timeout(
                Duration::from_secs(WEBSOCKET_UPGRADE_TIMEOUT_SECS),
                tokio_tungstenite::client_async_tls_with_config(
                    url_str,
                    tcp,
                    Some(ws_config),
                    Some(connector),
                ),
            ) => result,
        };
        let (ws_stream, _response) = match upgrade {
            Err(_) => {
                error!(
                    "[WS] TLS/WebSocket upgrade timed out after {}s",
                    WEBSOCKET_UPGRADE_TIMEOUT_SECS
                );
                return Err(QorError::Network("WebSocket upgrade timeout".to_string()));
            }
            Ok(Err(e)) => {
                error!("[WS] TLS/WebSocket upgrade failed: {}", e);
                return Err(QorError::Network(format!(
                    "WebSocket upgrade failed: {}",
                    e
                )));
            }
            Ok(Ok(pair)) => pair,
        };

        // Split the stream
        let (write, read) = ws_stream.split();

        // Create message channel
        let (tx, rx) = mpsc::unbounded_channel::<QueuedWsMessage>();
        let pending_writes = Arc::new(PendingWriteBudget::default());
        let (cancel_tx, _) = watch::channel(false);
        let local_closing = Arc::new(AtomicBool::new(false));

        self.publish_connection(
            attempt_id,
            &connect_cancel_rx,
            WsSenderEntry {
                connection_token: attempt_id,
                sender: tx,
                pending_writes: pending_writes.clone(),
                cancel_tx: cancel_tx.clone(),
                local_closing: local_closing.clone(),
            },
        )?;

        // Send connected event
        if let Some(event_tx) = self.event_tx.read().as_ref() {
            let _ = event_tx.try_send(WsEvent::ConnectionOpened {
                connection_token: attempt_id,
            });
        }

        // Spawn tasks
        let event_tx = self.event_tx.clone();
        let binary_tx = self.binary_tx.clone();
        let state = self.state.clone();
        let tx_handle = self.tx.clone();

        // Spawn read task
        let event_tx_read = event_tx.clone();
        let state_read = state.clone();
        let tx_handle_read = tx_handle.clone();
        let pending_writes_read = pending_writes.clone();
        let cancel_tx_read = cancel_tx.clone();
        let cancel_rx_read = cancel_tx.subscribe();
        tokio::spawn(async move {
            Self::read_task(
                read,
                attempt_id,
                event_tx_read,
                binary_tx,
                state_read,
                tx_handle_read,
                pending_writes_read,
                local_closing,
                cancel_tx_read,
                cancel_rx_read,
            )
            .await;
        });

        // Spawn write task
        let state_write = state.clone();
        let tx_handle_write = tx_handle.clone();
        let event_tx_write = event_tx.clone();
        let pending_writes_write = pending_writes.clone();
        let cancel_tx_write = cancel_tx.clone();
        let cancel_rx_write = cancel_tx.subscribe();
        tokio::spawn(async move {
            Self::write_task(
                write,
                rx,
                attempt_id,
                state_write,
                tx_handle_write,
                event_tx_write,
                pending_writes_write,
                cancel_tx_write,
                cancel_rx_write,
            )
            .await;
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_task(
        mut read: WsStream,
        connection_token: u64,
        event_tx: Arc<RwLock<Option<mpsc::Sender<WsEvent>>>>,
        binary_tx: Arc<RwLock<Option<mpsc::Sender<WsBinaryMessage>>>>,
        state: Arc<RwLock<ConnectionState>>,
        tx_handle: Arc<RwLock<Option<WsSenderEntry>>>,
        pending_writes: Arc<PendingWriteBudget>,
        local_closing: Arc<AtomicBool>,
        cancel_tx: watch::Sender<bool>,
        mut cancel_rx: watch::Receiver<bool>,
    ) {
        let mut notify_closed = false;
        'read_loop: loop {
            if *cancel_rx.borrow()
                || tx_handle
                    .read()
                    .as_ref()
                    .map(|entry| entry.connection_token != connection_token)
                    .unwrap_or(true)
            {
                break;
            }
            let next_message = tokio::select! {
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break 'read_loop;
                    }
                    continue;
                }
                message = read.next() => message,
            };
            match next_message {
                Some(Ok(msg)) => {
                    if tx_handle
                        .read()
                        .as_ref()
                        .map(|entry| entry.connection_token != connection_token)
                        .unwrap_or(true)
                    {
                        break;
                    }
                    match msg {
                        Message::Text(text) => {
                            if enforce_bounded_json_structure(
                                text.as_bytes(),
                                MAX_WS_JSON_DEPTH,
                                MAX_WS_JSON_STRUCTURAL_TOKENS,
                                MAX_WS_MESSAGE_BYTES,
                            )
                            .is_ok()
                                && let Ok(parsed) =
                                    serde_json::from_str::<serde_json::Value>(text.as_str())
                            {
                                // Handle heartbeat responses
                                if let Some(ref tx) = *event_tx.read() {
                                    let byte_len = text.len();
                                    if !try_reserve_ws_inbound(byte_len) {
                                        warn!(
                                            "[WS-BRIDGE] inbound buffer budget exhausted; dropping frame"
                                        );
                                        Self::queue_connection_error(&event_tx, connection_token);
                                        break 'read_loop;
                                    } else if let Err(e) = tx.try_send(WsEvent::Message {
                                        connection_token,
                                        data: parsed,
                                        byte_len,
                                    }) {
                                        release_ws_inbound_bytes(byte_len);
                                        warn!(
                                            "[WS-BRIDGE] failed to forward ws-message event: {}",
                                            e
                                        );
                                        break 'read_loop;
                                    }
                                }
                            } else {
                                warn!("[WS-BRIDGE] received non-json text message");
                                Self::queue_connection_error(&event_tx, connection_token);
                                break 'read_loop;
                            }
                        }
                        Message::Binary(data) => {
                            let byte_len = data.len();
                            if byte_len != PQ_WS_FIXED_CELL_BYTES {
                                warn!("[WS-BRIDGE] received invalid binary cell size");
                                Self::queue_connection_error(&event_tx, connection_token);
                                break 'read_loop;
                            }
                            if let Some(ref tx) = *binary_tx.read() {
                                if !try_reserve_ws_inbound(byte_len) {
                                    warn!(
                                        "[WS-BRIDGE] inbound buffer budget exhausted; dropping frame"
                                    );
                                    Self::queue_connection_error(&event_tx, connection_token);
                                    break 'read_loop;
                                }
                                if let Err(e) = tx.try_send(WsBinaryMessage {
                                    connection_token,
                                    data: data.to_vec(),
                                    byte_len,
                                }) {
                                    release_ws_inbound_bytes(byte_len);
                                    warn!(
                                        "[WS-BRIDGE] failed to forward binary ws-message event: {}",
                                        e
                                    );
                                    break 'read_loop;
                                }
                            }
                        }
                        Message::Ping(payload) => {
                            let pong = Message::Pong(payload);
                            let Some(queued_pong) =
                                QueuedWsMessage::reserved(pong, pending_writes.clone())
                            else {
                                warn!("[WS-BRIDGE] dropping protocol pong: outbound queue full");
                                continue;
                            };
                            if let Some(entry) = tx_handle.read().as_ref() {
                                if entry.connection_token != connection_token {
                                    break;
                                }
                                if !Arc::ptr_eq(&entry.pending_writes, &pending_writes) {
                                    break;
                                }
                                if let Err(e) = entry.sender.send(queued_pong) {
                                    warn!("[WS-BRIDGE] failed to queue protocol pong: {}", e);
                                }
                            } else {
                                warn!(
                                    "[WS-BRIDGE] cannot answer protocol ping: writer unavailable"
                                );
                            }
                        }
                        Message::Pong(_) => {}
                        Message::Close(_frame) => {
                            notify_closed = true;
                            break;
                        }
                        _ => {
                            warn!("[WS-BRIDGE] unsupported WebSocket message rejected");
                            Self::queue_connection_error(&event_tx, connection_token);
                            break 'read_loop;
                        }
                    }
                }
                Some(Err(read_error)) => {
                    if tx_handle
                        .read()
                        .as_ref()
                        .map(|entry| entry.connection_token != connection_token)
                        .unwrap_or(true)
                    {
                        break;
                    }

                    error!(
                        "[WS] read failed for token={}: {}",
                        connection_token, read_error
                    );
                    Self::queue_connection_error(&event_tx, connection_token);
                    break;
                }
                None => {
                    notify_closed = true;
                    break;
                }
            }
        }

        // Cleanup
        if !local_closing.load(Ordering::Acquire) {
            let _ = cancel_tx.send(true);
        }
        let was_current = {
            let mut current = tx_handle.write();
            if current
                .as_ref()
                .map(|entry| entry.connection_token == connection_token)
                .unwrap_or(false)
            {
                *current = None;
                true
            } else {
                false
            }
        };
        if was_current {
            *state.write() = ConnectionState::Disconnected;
            if notify_closed && let Some(ref tx) = *event_tx.read() {
                let _ = tx.try_send(WsEvent::ConnectionClosed { connection_token });
            }
        }
    }

    /// Write task for outgoing messages
    #[allow(clippy::too_many_arguments)]
    async fn write_task(
        mut write: WsSink,
        mut rx: mpsc::UnboundedReceiver<QueuedWsMessage>,
        connection_token: u64,
        state: Arc<RwLock<ConnectionState>>,
        tx_handle: Arc<RwLock<Option<WsSenderEntry>>>,
        event_tx: Arc<RwLock<Option<mpsc::Sender<WsEvent>>>>,
        _pending_writes: Arc<PendingWriteBudget>,
        cancel_tx: watch::Sender<bool>,
        mut cancel_rx: watch::Receiver<bool>,
    ) {
        loop {
            if *cancel_rx.borrow() {
                break;
            }
            let next_message = tokio::select! {
                changed = cancel_rx.changed() => {
                    if changed.is_err() || *cancel_rx.borrow() {
                        break;
                    }
                    continue;
                }
                message = rx.recv() => message,
            };
            match next_message {
                Some(mut queued) => {
                    let generation_is_current = tx_handle
                        .read()
                        .as_ref()
                        .map(|entry| entry.connection_token == connection_token)
                        .unwrap_or(false);

                    if !generation_is_current && queued.reservation.is_some() {
                        break;
                    }
                    let Some(message) = queued.message.take() else {
                        continue;
                    };
                    let send_result = tokio::select! {
                        changed = cancel_rx.changed() => {
                            if changed.is_err() || *cancel_rx.borrow() {
                                drop(queued);
                                break;
                            }
                            continue;
                        }
                        result = tokio::time::timeout(
                            Duration::from_secs(WEBSOCKET_WRITE_TIMEOUT_SECS),
                            write.send(message),
                        ) => result,
                    };
                    drop(queued);

                    if !matches!(send_result, Ok(Ok(()))) {
                        error!("WebSocket write failed");
                        Self::queue_connection_error(&event_tx, connection_token);
                        break;
                    }
                }
                None => break,
            }
        }

        let _ = cancel_tx.send(true);
        let was_current = {
            let mut current = tx_handle.write();
            if current
                .as_ref()
                .map(|entry| entry.connection_token == connection_token)
                .unwrap_or(false)
            {
                *current = None;
                true
            } else {
                false
            }
        };
        if was_current {
            *state.write() = ConnectionState::Disconnected;
        }
    }

    /// Send message
    pub async fn send(
        &self,
        payload: String,
        expected_connection_token: u64,
    ) -> QorResult<SendResult> {
        let state = *self.state.read();

        if state != ConnectionState::Connected {
            warn!(
                "[WS] send rejected: state={:?} (expected Connected) expected_token={}",
                state, expected_connection_token
            );
            return Ok(SendResult {
                success: false,
                queued: Some(false),
                error: Some("WebSocket not connected".to_string()),
            });
        }

        let tx = self.tx.read().clone();
        if let Some(entry) = tx {
            if entry.connection_token != expected_connection_token
                || *entry.cancel_tx.borrow()
                || entry.local_closing.load(Ordering::Acquire)
            {
                warn!(
                    "[WS] send rejected: generation changed (entry_token={} expected={} cancelled={} closing={})",
                    entry.connection_token,
                    expected_connection_token,
                    *entry.cancel_tx.borrow(),
                    entry.local_closing.load(Ordering::Acquire)
                );
                return Ok(SendResult {
                    success: false,
                    queued: Some(false),
                    error: Some("WebSocket connection generation changed".to_string()),
                });
            }

            if payload.len() > MAX_WS_MESSAGE_BYTES {
                return Ok(SendResult {
                    success: false,
                    queued: None,
                    error: Some(format!(
                        "Message too large: {} bytes (max {})",
                        payload.len(),
                        MAX_WS_MESSAGE_BYTES
                    )),
                });
            }
            enforce_bounded_json_structure(
                payload.as_bytes(),
                MAX_WS_JSON_DEPTH,
                MAX_WS_JSON_STRUCTURAL_TOKENS,
                MAX_WS_MESSAGE_BYTES,
            )
            .map_err(|_| QorError::InvalidArgument("Invalid WebSocket JSON".to_string()))?;
            let mut deserializer = serde_json::Deserializer::from_str(&payload);
            serde::de::IgnoredAny::deserialize(&mut deserializer)
                .map_err(|_| QorError::InvalidArgument("Invalid WebSocket JSON".to_string()))?;
            deserializer
                .end()
                .map_err(|_| QorError::InvalidArgument("Invalid WebSocket JSON".to_string()))?;

            let Some(queued) =
                QueuedWsMessage::reserved(Message::Text(payload), entry.pending_writes)
            else {
                return Ok(SendResult {
                    success: false,
                    queued: None,
                    error: Some("Outbound WebSocket queue full".to_string()),
                });
            };
            if entry.sender.send(queued).is_err() {
                return Ok(SendResult {
                    success: false,
                    queued: None,
                    error: Some("Failed to queue message (channel closed)".to_string()),
                });
            }

            return Ok(SendResult {
                success: true,
                queued: Some(false),
                error: None,
            });
        }

        Ok(SendResult {
            success: false,
            queued: None,
            error: Some("Not connected".to_string()),
        })
    }

    pub async fn send_binary(
        &self,
        payload: Vec<u8>,
        expected_connection_token: u64,
    ) -> QorResult<SendResult> {
        if payload.len() != PQ_WS_FIXED_CELL_BYTES {
            return Ok(SendResult {
                success: false,
                queued: None,
                error: Some("Invalid encrypted WebSocket cell size".to_string()),
            });
        }
        if *self.state.read() != ConnectionState::Connected {
            return Ok(SendResult {
                success: false,
                queued: Some(false),
                error: Some("WebSocket not connected".to_string()),
            });
        }
        let Some(entry) = self.tx.read().clone() else {
            return Ok(SendResult {
                success: false,
                queued: None,
                error: Some("Not connected".to_string()),
            });
        };
        if entry.connection_token != expected_connection_token
            || *entry.cancel_tx.borrow()
            || entry.local_closing.load(Ordering::Acquire)
        {
            return Ok(SendResult {
                success: false,
                queued: Some(false),
                error: Some("WebSocket connection generation changed".to_string()),
            });
        }
        let Some(queued) =
            QueuedWsMessage::reserved(Message::Binary(payload.into()), entry.pending_writes)
        else {
            return Ok(SendResult {
                success: false,
                queued: None,
                error: Some("Outbound WebSocket queue full".to_string()),
            });
        };
        if entry.sender.send(queued).is_err() {
            return Ok(SendResult {
                success: false,
                queued: None,
                error: Some("Failed to queue message (channel closed)".to_string()),
            });
        }
        Ok(SendResult {
            success: true,
            queued: Some(false),
            error: None,
        })
    }

    pub async fn disconnect(&self, expected_connection_token: Option<u64>) -> QorResult<bool> {
        let (close_entry, cancelled_connect) = {
            let mut connecting_attempt = self.connecting_attempt.write();

            if expected_connection_token.is_none() && self.tx.read().is_some() {
                return Ok(false);
            }

            let mut current = self.tx.write();
            if let Some(expected) = expected_connection_token
                && current
                    .as_ref()
                    .map(|entry| entry.connection_token != expected)
                    .unwrap_or(true)
            {
                return Ok(false);
            }
            if let Some(entry) = current.as_ref() {
                entry.local_closing.store(true, Ordering::Release);
            }
            let close_entry = current.take();
            let cancelled_connect = connecting_attempt.take().is_some_and(|attempt| {
                let _ = attempt.cancel_tx.send(true);
                true
            });
            *self.state.write() = ConnectionState::Disconnected;
            *self.connecting_started_at.write() = None;
            self.connect_attempt_id.fetch_add(1, Ordering::Relaxed);
            (close_entry, cancelled_connect)
        };
        let closed_connection = close_entry.is_some();

        // send the close frame
        if let Some(entry) = close_entry {
            let _ = entry
                .sender
                .send(QueuedWsMessage::control(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "".into(),
                }))));

            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = entry.cancel_tx.send(true);
        }

        Ok(closed_connection || cancelled_connect || expected_connection_token.is_none())
    }

    pub fn is_connected(&self) -> bool {
        *self.state.read() == ConnectionState::Connected
    }

    pub fn get_state(&self) -> WebSocketState {
        WebSocketState {
            connected: self.is_connected(),
            connecting: *self.state.read() == ConnectionState::Connecting,
            queue_size: self
                .tx
                .read()
                .as_ref()
                .map(|entry| entry.pending_writes.frames.load(Ordering::Relaxed))
                .unwrap_or(0),
            connection_token: self.tx.read().as_ref().map(|entry| entry.connection_token),
        }
    }
}

impl Default for WebSocketHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WebSocketHandler {
    fn drop(&mut self) {
        self.abort_transport_now();
        *self.event_tx.write() = None;
    }
}

pub async fn init() -> QorResult<Arc<WebSocketHandler>> {
    let handler = WebSocketHandler::new();
    Ok(Arc::new(handler))
}
