//! WebSocket Handler
//!
//! WebSocket connections through Tor SOCKS5 proxy

use log::{error, info, warn};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use native_tls::TlsConnector;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::protocol::{CloseFrame, Message, frame::coding::CloseCode},
};
use url::Url;

use crate::error::{QorError, QorResult};

// Constants
const CONNECTION_TIMEOUT_SECS: u64 = 30;
const WEBSOCKET_UPGRADE_TIMEOUT_SECS: u64 = 30;
const STALE_CONNECTING_SECS: u64 = CONNECTION_TIMEOUT_SECS + WEBSOCKET_UPGRADE_TIMEOUT_SECS + 10;

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
    pub reconnect_attempts: u32,
    pub queue_size: usize,
    pub connection_duration_ms: u64,
}

/// WebSocket connection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResult {
    pub success: bool,
    pub already_connected: Option<bool>,
    pub new_connection: Option<bool>,
    pub error: Option<String>,
}

/// WebSocket send result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub success: bool,
    pub queued: Option<bool>,
    pub error: Option<String>,
}

/// Incoming WebSocket message event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsEvent {
    #[serde(rename = "__ws_connection_opened")]
    ConnectionOpened { timestamp: u64 },
    #[serde(rename = "__ws_connection_closed")]
    ConnectionClosed { duration: u64 },
    #[serde(rename = "__ws_connection_error")]
    ConnectionError { error: String },
    #[serde(rename = "message")]
    Message { data: serde_json::Value },
}

type WsSink = futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

fn is_ws_debug_type(msg_type: &str) -> bool {
    matches!(
        msg_type,
        "server-public-key"
            | "pq-envelope"
            | "pq-handshake-init"
            | "pq-handshake-ack"
            | "pq-heartbeat-ping"
            | "pq-heartbeat-pong"
            | "server-entry-request"
            | "server-entry-challenge"
            | "server-entry-token-issuance"
            | "privacy-pass-redemption"
            | "auth-error"
            | "error"
            | "ok"
            | "__ws_connection_opened"
            | "__ws_connection_closed"
            | "__ws_connection_error"
    )
}

/// WebSocket Handler
pub struct WebSocketHandler {
    server_url: RwLock<Option<String>>,
    state: Arc<RwLock<ConnectionState>>,
    tor_ready: AtomicBool,
    tor_socks_port: AtomicU16,
    reconnect_attempts: AtomicU32,
    message_queue: RwLock<Vec<String>>,
    connection_established_at: RwLock<Option<Instant>>,
    missed_heartbeats: Arc<AtomicU32>,
    session_id: Arc<RwLock<Option<String>>>,
    is_background_mode: AtomicBool,
    tx: Arc<RwLock<Option<mpsc::UnboundedSender<Message>>>>,
    event_tx: Arc<RwLock<Option<mpsc::UnboundedSender<WsEvent>>>>,
    suppress_events: Arc<AtomicBool>,
    pending_writes: Arc<AtomicUsize>,
    connecting_started_at: RwLock<Option<Instant>>,
    connect_attempt_id: AtomicU64,
    shutdown: Arc<AtomicBool>,
}

impl WebSocketHandler {
    /// Create new WebSocket handler
    pub fn new() -> Self {
        Self {
            server_url: RwLock::new(None),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            tor_ready: AtomicBool::new(false),
            tor_socks_port: AtomicU16::new(9150),
            reconnect_attempts: AtomicU32::new(0),
            message_queue: RwLock::new(Vec::new()),
            connection_established_at: RwLock::new(None),
            missed_heartbeats: Arc::new(AtomicU32::new(0)),
            session_id: Arc::new(RwLock::new(None)),
            is_background_mode: AtomicBool::new(false),
            tx: Arc::new(RwLock::new(None)),
            event_tx: Arc::new(RwLock::new(None)),
            suppress_events: Arc::new(AtomicBool::new(false)),
            pending_writes: Arc::new(AtomicUsize::new(0)),
            connecting_started_at: RwLock::new(None),
            connect_attempt_id: AtomicU64::new(0),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
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

        if parsed.has_host() && parsed.host_str().map(|h| h.len()).unwrap_or(0) > 253 {
            return Err(QorError::InvalidArgument("Invalid hostname".to_string()));
        }

        if parsed.username() != "" || parsed.password().is_some() {
            return Err(QorError::InvalidArgument(
                "Credentials in URL not allowed".to_string(),
            ));
        }

        *self.server_url.write() = Some(parsed.to_string());
        Ok(true)
    }

    /// Set Tor ready status
    pub fn set_tor_ready(&self, ready: bool) {
        self.tor_ready.store(ready, Ordering::Relaxed);
    }

    /// Update Tor config
    pub fn update_tor_config(&self, socks_port: u16) {
        self.tor_socks_port.store(socks_port, Ordering::Relaxed);
    }

    /// Set event handler
    pub fn set_event_handler(&self, tx: mpsc::UnboundedSender<WsEvent>) {
        *self.event_tx.write() = Some(tx);
    }

    /// Suppress bridge events during transient probe only connections
    pub fn set_event_suppressed(&self, suppressed: bool) {
        self.suppress_events.store(suppressed, Ordering::Relaxed);
    }

    fn clear_transport_state(&self) {
        self.connect_attempt_id.fetch_add(1, Ordering::Relaxed);
        *self.tx.write() = None;
        *self.state.write() = ConnectionState::Disconnected;
        *self.connection_established_at.write() = None;
        *self.session_id.write() = None;
        *self.connecting_started_at.write() = None;
        self.pending_writes.store(0, Ordering::Relaxed);
    }

    /// Connect to server
    pub async fn connect(&self) -> QorResult<ConnectResult> {
        let server_url = self.server_url.read().clone();
        let url_str = match server_url {
            Some(url) => url,
            None => {
                return Ok(ConnectResult {
                    success: false,
                    already_connected: None,
                    new_connection: None,
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
                let has_sender = self.tx.read().is_some();
                if has_sender {
                    return Ok(ConnectResult {
                        success: true,
                        already_connected: Some(true),
                        new_connection: Some(false),
                        error: None,
                    });
                }
            }
        }

        if !self.tor_ready.load(Ordering::Relaxed) {
            return Ok(ConnectResult {
                success: false,
                already_connected: None,
                new_connection: None,
                error: Some("Tor setup not complete".to_string()),
            });
        }

        self.shutdown.store(false, Ordering::Relaxed);
        let attempt_id = self
            .connect_attempt_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        *self.state.write() = ConnectionState::Connecting;
        *self.connecting_started_at.write() = Some(Instant::now());

        match self.create_connection(&url_str, attempt_id).await {
            Ok(_) => Ok(ConnectResult {
                success: true,
                already_connected: Some(false),
                new_connection: Some(true),
                error: None,
            }),
            Err(e) => {
                error!("Failed to establish WebSocket connection: {}", e);
                if self.connect_attempt_id.load(Ordering::Relaxed) == attempt_id {
                    *self.state.write() = ConnectionState::Disconnected;
                    *self.connecting_started_at.write() = None;
                    self.pending_writes.store(0, Ordering::Relaxed);
                }
                Ok(ConnectResult {
                    success: false,
                    already_connected: None,
                    new_connection: None,
                    error: Some(e.safe_message()),
                })
            }
        }
    }

    /// Create WebSocket connection through Tor SOCKS5
    async fn create_connection(&self, url_input: &str, attempt_id: u64) -> QorResult<()> {
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
        let tcp_stream = tokio::time::timeout(
            Duration::from_secs(CONNECTION_TIMEOUT_SECS),
            Socks5Stream::connect(socks_addr.as_str(), (host.to_string(), port)),
        )
        .await
        .map_err(|_| QorError::Network("Connection timeout".to_string()))?
        .map_err(|e| QorError::Network(format!("SOCKS5 connection failed: {}", e)))?;

        let tcp = tcp_stream.into_inner();

        // Set TCP keepalive to prevent Tor relays from dropping idle connections
        {
            let raw_fd = tcp.as_raw_fd();
            let dup_fd = unsafe { libc::dup(raw_fd) };
            if dup_fd >= 0 {
                let sock = socket2::Socket::from(unsafe { OwnedFd::from_raw_fd(dup_fd) });
                let keepalive = socket2::TcpKeepalive::new()
                    .with_time(Duration::from_secs(30))
                    .with_interval(Duration::from_secs(10));
                let _ = sock.set_tcp_keepalive(&keepalive);
                let _ = sock.set_keepalive(true);
            }
        }

        // Create a custom TLS connector for .onion addresses
        let mut builder = TlsConnector::builder();
        if host.ends_with(".onion") {
            builder.danger_accept_invalid_hostnames(true);
            builder.danger_accept_invalid_certs(true);
        }

        let native_connector = builder
            .build()
            .map_err(|e| QorError::Network(format!("Failed to build TLS connector: {}", e)))?;

        let connector = tokio_tungstenite::Connector::NativeTls(native_connector);

        // WebSocket upgrade with TLS
        let (ws_stream, _response) = tokio::time::timeout(
            Duration::from_secs(WEBSOCKET_UPGRADE_TIMEOUT_SECS),
            tokio_tungstenite::client_async_tls_with_config(url_str, tcp, None, Some(connector)),
        )
        .await
        .map_err(|_| QorError::Network("WebSocket upgrade timeout".to_string()))?
        .map_err(|e| QorError::Network(format!("WebSocket upgrade failed: {}", e)))?;

        if self.connect_attempt_id.load(Ordering::Relaxed) != attempt_id
            || self.shutdown.load(Ordering::Relaxed)
        {
            return Err(QorError::Network(
                "Connection attempt cancelled".to_string(),
            ));
        }

        // Split the stream
        let (write, read) = ws_stream.split();

        // Create message channel
        let (tx, rx) = mpsc::unbounded_channel::<Message>();
        *self.tx.write() = Some(tx);

        // Update state
        *self.state.write() = ConnectionState::Connected;
        *self.connection_established_at.write() = Some(Instant::now());
        *self.connecting_started_at.write() = None;
        self.reconnect_attempts.store(0, Ordering::Relaxed);
        self.missed_heartbeats.store(0, Ordering::Relaxed);
        self.pending_writes.store(0, Ordering::Relaxed);

        // Send connected event
        if !self.suppress_events.load(Ordering::Relaxed) {
            if let Some(event_tx) = self.event_tx.read().as_ref() {
                let _ = event_tx.send(WsEvent::ConnectionOpened {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                });
            }
        }

        // Process queued messages
        self.process_message_queue().await;

        // Spawn tasks
        let event_tx = self.event_tx.clone();
        let session_id = self.session_id.clone();
        let missed_heartbeats = self.missed_heartbeats.clone();
        let shutdown = self.shutdown.clone();
        let state = self.state.clone();
        let tx_handle = self.tx.clone();
        let suppress_events = self.suppress_events.clone();
        let pending_writes = self.pending_writes.clone();

        // Spawn read task
        let event_tx_read = event_tx.clone();
        let state_read = state.clone();
        let tx_handle_read = tx_handle.clone();
        let suppress_events_read = suppress_events.clone();
        tokio::spawn(async move {
            Self::read_task(
                read,
                event_tx_read,
                session_id,
                missed_heartbeats,
                shutdown,
                state_read,
                tx_handle_read,
                suppress_events_read,
            )
            .await;
        });

        // Spawn write task
        let shutdown_write = self.shutdown.clone();
        let state_write = state.clone();
        let tx_handle_write = tx_handle.clone();
        let event_tx_write = event_tx.clone();
        let suppress_events_write = suppress_events.clone();
        let pending_writes_write = pending_writes.clone();
        tokio::spawn(async move {
            Self::write_task(
                write,
                rx,
                shutdown_write,
                state_write,
                tx_handle_write,
                event_tx_write,
                suppress_events_write,
                pending_writes_write,
            )
            .await;
        });

        Ok(())
    }

    /// Read task for incoming messages
    async fn read_task(
        mut read: WsStream,
        event_tx: Arc<RwLock<Option<mpsc::UnboundedSender<WsEvent>>>>,
        session_id: Arc<RwLock<Option<String>>>,
        missed_heartbeats: Arc<AtomicU32>,
        shutdown: Arc<AtomicBool>,
        state: Arc<RwLock<ConnectionState>>,
        tx_handle: Arc<RwLock<Option<mpsc::UnboundedSender<Message>>>>,
        suppress_events: Arc<AtomicBool>,
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            match read.next().await {
                Some(Ok(msg)) => {
                    match msg {
                        Message::Text(text) => {
                            if let Ok(parsed) =
                                serde_json::from_str::<serde_json::Value>(text.as_str())
                            {
                                // Handle heartbeat responses
                                if let Some(msg_type) = parsed.get("type").and_then(|t| t.as_str())
                                {
                                    if is_ws_debug_type(msg_type) {
                                        info!(
                                            "[WS-BRIDGE] received text message type={} bytes={}",
                                            msg_type,
                                            text.len()
                                        );
                                    }

                                    if msg_type == "pong"
                                        || msg_type == "heartbeat-response"
                                        || msg_type == "pq-heartbeat-pong"
                                    {
                                        missed_heartbeats.store(0, Ordering::Relaxed);
                                    }

                                    // Update session ID
                                    if let Some(sid) =
                                        parsed.get("sessionId").and_then(|s| s.as_str())
                                    {
                                        *session_id.write() = Some(sid.to_string());
                                    }
                                }

                                if !suppress_events.load(Ordering::Relaxed) {
                                    if let Some(ref tx) = *event_tx.read() {
                                        if let Err(e) = tx.send(WsEvent::Message { data: parsed }) {
                                            warn!(
                                                "[WS-BRIDGE] failed to forward ws-message event: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                            } else {
                                warn!(
                                    "[WS-BRIDGE] received non-json text message bytes={}",
                                    text.len()
                                );
                            }
                        }
                        Message::Ping(payload) => {
                            missed_heartbeats.store(0, Ordering::Relaxed);
                            info!("[WS-BRIDGE] received protocol ping bytes={}", payload.len());
                            
                            if let Some(ref tx) = *tx_handle.read() {
                                if let Err(e) = tx.send(Message::Pong(payload)) {
                                    warn!("[WS-BRIDGE] failed to queue protocol pong: {}", e);
                                }
                            } else {
                                warn!(
                                    "[WS-BRIDGE] cannot answer protocol ping: writer unavailable"
                                );
                            }
                        }
                        Message::Pong(_) => {
                            missed_heartbeats.store(0, Ordering::Relaxed);
                            info!("[WS-BRIDGE] received protocol pong");
                        }
                        Message::Close(_frame) => {
                            if !suppress_events.load(Ordering::Relaxed) {
                                if let Some(ref tx) = *event_tx.read() {
                                    let _ = tx.send(WsEvent::ConnectionClosed { duration: 0 });
                                }
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                Some(Err(e)) => {
                    error!("WebSocket read error: {}", e);
                    if !suppress_events.load(Ordering::Relaxed) {
                        if let Some(ref tx) = *event_tx.read() {
                            let _ = tx.send(WsEvent::ConnectionError {
                                error: e.to_string(),
                            });
                        }
                    }
                    break;
                }
                None => {
                    break;
                }
            }
        }

        // Cleanup
        *state.write() = ConnectionState::Disconnected;
        *tx_handle.write() = None;
    }

    /// Write task for outgoing messages
    async fn write_task(
        mut write: WsSink,
        mut rx: mpsc::UnboundedReceiver<Message>,
        shutdown: Arc<AtomicBool>,
        state: Arc<RwLock<ConnectionState>>,
        tx_handle: Arc<RwLock<Option<mpsc::UnboundedSender<Message>>>>,
        event_tx: Arc<RwLock<Option<mpsc::UnboundedSender<WsEvent>>>>,
        suppress_events: Arc<AtomicBool>,
        pending_writes: Arc<AtomicUsize>,
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            match rx.recv().await {
                Some(msg) => {
                    match &msg {
                        Message::Text(text) => {
                            if let Ok(parsed) =
                                serde_json::from_str::<serde_json::Value>(text.as_str())
                            {
                                if let Some(msg_type) = parsed.get("type").and_then(|t| t.as_str())
                                {
                                    if is_ws_debug_type(msg_type) {
                                        info!(
                                            "[WS-BRIDGE] sending text message type={} bytes={}",
                                            msg_type,
                                            text.len()
                                        );
                                    }
                                }
                            }
                        }
                        Message::Pong(payload) => {
                            info!("[WS-BRIDGE] sending protocol pong bytes={}", payload.len());
                        }
                        Message::Ping(payload) => {
                            info!("[WS-BRIDGE] sending protocol ping bytes={}", payload.len());
                        }
                        _ => {}
                    }

                    let send_result = write.send(msg).await;
                    pending_writes
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                            Some(n.saturating_sub(1))
                        })
                        .ok();

                    if let Err(e) = send_result {
                        error!("WebSocket write error: {}", e);
                        if !suppress_events.load(Ordering::Relaxed) {
                            if let Some(ref tx) = *event_tx.read() {
                                let _ = tx.send(WsEvent::ConnectionError {
                                    error: e.to_string(),
                                });
                            }
                        }
                        break;
                    }
                }
                None => {
                    break;
                }
            }
        }

        // Cleanup
        *state.write() = ConnectionState::Disconnected;
        *tx_handle.write() = None;
    }

    /// Send message
    pub async fn send(&self, payload: serde_json::Value) -> QorResult<SendResult> {
        let state = *self.state.read();

        if state != ConnectionState::Connected {
            return Ok(SendResult {
                success: false,
                queued: Some(false),
                error: Some("WebSocket not connected".to_string()),
            });
        }

        let tx = self.tx.read().clone();
        if let Some(sender) = tx {
            let msg = match payload {
                serde_json::Value::String(s) => s,
                _ => serde_json::to_string(&payload)?,
            };
            self.pending_writes.fetch_add(1, Ordering::Relaxed);
            if let Err(_) = sender.send(Message::Text(msg.into())) {
                self.pending_writes
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        Some(n.saturating_sub(1))
                    })
                    .ok();
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

    /// Process message queue
    async fn process_message_queue(&self) {
        let dropped_count = {
            let mut queue = self.message_queue.write();
            let len = queue.len();
            queue.clear();
            len
        };

        if dropped_count > 0 {
            warn!(
                "[WS-BRIDGE] dropped stale serialized websocket messages instead of replaying encrypted frames count={}",
                dropped_count
            );
        }
    }

    /// Disconnect
    pub async fn disconnect(&self) -> QorResult<bool> {
        let close_sender = self.tx.write().take();
        *self.state.write() = ConnectionState::Disconnected;
        *self.connecting_started_at.write() = None;
        self.connect_attempt_id.fetch_add(1, Ordering::Relaxed);
        self.shutdown.store(true, Ordering::Relaxed);
        self.pending_writes.store(0, Ordering::Relaxed);

        // send the close frame
        if let Some(sender) = close_sender {
            let _ = sender.send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "".into(),
            })));
            
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        *self.connection_established_at.write() = None;
        *self.session_id.write() = None;
        self.is_background_mode.store(false, Ordering::Relaxed);
        self.reconnect_attempts.store(0, Ordering::Relaxed);

        // Small delay then reset shutdown for future connections
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.shutdown.store(false, Ordering::Relaxed);

        Ok(true)
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        *self.state.read() == ConnectionState::Connected
    }

    /// Get current state
    pub fn get_state(&self) -> WebSocketState {
        let duration = self
            .connection_established_at
            .read()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        WebSocketState {
            connected: self.is_connected(),
            connecting: *self.state.read() == ConnectionState::Connecting,
            reconnect_attempts: self.reconnect_attempts.load(Ordering::Relaxed),
            queue_size: self
                .message_queue
                .read()
                .len()
                .saturating_add(self.pending_writes.load(Ordering::Relaxed)),
            connection_duration_ms: duration,
        }
    }

    /// Set background mode
    pub fn set_background_mode(&self, enabled: bool) {
        self.is_background_mode.store(enabled, Ordering::Relaxed);
    }
}

impl Default for WebSocketHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize WebSocket handler
pub async fn init() -> QorResult<Arc<WebSocketHandler>> {
    let handler = WebSocketHandler::new();
    Ok(Arc::new(handler))
}
