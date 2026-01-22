//! WebSocket Handler
//!
//! WebSocket connections through Tor SOCKS5 proxy

use log::{ error };
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    tungstenite::protocol::Message,
    MaybeTlsStream, WebSocketStream,
};
use url::Url;
use native_tls::TlsConnector;

use crate::error::{QorError, QorResult};

// Constants
const MAX_QUEUE_SIZE: usize = 100;
const CONNECTION_TIMEOUT_SECS: u64 = 30;


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
    ConnectionClosed { code: u16, reason: String, duration: u64 },
    #[serde(rename = "__ws_connection_error")]
    ConnectionError { error: String },
    #[serde(rename = "message")]
    Message { data: serde_json::Value },
}

type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<MaybeTlsStream<TcpStream>>,
    Message,
>;
type WsStream = futures_util::stream::SplitStream<
    WebSocketStream<MaybeTlsStream<TcpStream>>,
>;

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
    #[allow(dead_code)]
    extra_headers: RwLock<HashMap<String, String>>,
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
            extra_headers: RwLock::new(HashMap::new()),
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
            return Err(QorError::InvalidArgument("Only secure WebSocket (wss://) allowed".to_string()));
        }

        if parsed.has_host() && parsed.host_str().map(|h| h.len()).unwrap_or(0) > 253 {
            return Err(QorError::InvalidArgument("Invalid hostname".to_string()));
        }

        if parsed.username() != "" || parsed.password().is_some() {
            return Err(QorError::InvalidArgument("Credentials in URL not allowed".to_string()));
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

        // Check current state
        {
            let state = *self.state.read();
            if state == ConnectionState::Connecting {
                return Ok(ConnectResult {
                    success: false,
                    already_connected: None,
                    new_connection: None,
                    error: Some("Connection in progress".to_string()),
                });
            }
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

        *self.state.write() = ConnectionState::Connecting;

        match self.create_connection(&url_str).await {
            Ok(_) => {
                Ok(ConnectResult {
                    success: true,
                    already_connected: Some(false),
                    new_connection: Some(true),
                    error: None,
                })
            }
            Err(e) => {
                error!("Failed to establish WebSocket connection: {}", e);
                *self.state.write() = ConnectionState::Disconnected;
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
    async fn create_connection(&self, url_input: &str) -> QorResult<()> {
        let url_str = url_input.trim();
        let url = Url::parse(url_str)
            .map_err(|e| QorError::InvalidArgument(format!("Invalid URL: {}", e)))?;

        let host = url.host_str()
            .ok_or_else(|| QorError::InvalidArgument("No host in URL".to_string()))?;
        let port = url.port().unwrap_or(443);

        let socks_port = self.tor_socks_port.load(Ordering::Relaxed);

        // Connect through SOCKS5 proxy
        let socks_addr = format!("127.0.0.1:{}", socks_port);
        let tcp_stream = tokio::time::timeout(
            Duration::from_secs(CONNECTION_TIMEOUT_SECS),
            Socks5Stream::connect(
                socks_addr.as_str(),
                (host.to_string(), port),
            ),
        )
        .await
        .map_err(|_| QorError::Network("Connection timeout".to_string()))?
        .map_err(|e| QorError::Network(format!("SOCKS5 connection failed: {}", e)))?;

        let tcp = tcp_stream.into_inner();

        // Create a custom TLS connector for .onion addresses
        let mut builder = TlsConnector::builder();
        if host.ends_with(".onion") {
            builder.danger_accept_invalid_hostnames(true);
            builder.danger_accept_invalid_certs(true);
        }
        
        let native_connector = builder.build()
            .map_err(|e| QorError::Network(format!("Failed to build TLS connector: {}", e)))?;
            
        let connector = tokio_tungstenite::Connector::NativeTls(native_connector);

        // WebSocket upgrade with TLS
        let (ws_stream, _response) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::client_async_tls_with_config(url_str, tcp, None, Some(connector)),
        )
        .await
        .map_err(|_| QorError::Network("WebSocket upgrade timeout".to_string()))?
        .map_err(|e| QorError::Network(format!("WebSocket upgrade failed: {}", e)))?;

        // Split the stream
        let (write, read) = ws_stream.split();

        // Create message channel
        let (tx, rx) = mpsc::unbounded_channel::<Message>();
        *self.tx.write() = Some(tx);

        // Update state
        *self.state.write() = ConnectionState::Connected;
        *self.connection_established_at.write() = Some(Instant::now());
        self.reconnect_attempts.store(0, Ordering::Relaxed);
        self.missed_heartbeats.store(0, Ordering::Relaxed);

        // Send connected event
        if let Some(event_tx) = self.event_tx.read().as_ref() {
            let _ = event_tx.send(WsEvent::ConnectionOpened {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            });
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

        // Spawn read task
        let event_tx_read = event_tx.clone();
        let state_read = state.clone();
        let tx_handle_read = tx_handle.clone();
        tokio::spawn(async move {
            Self::read_task(read, event_tx_read, session_id, missed_heartbeats, shutdown, state_read, tx_handle_read).await;
        });

        // Spawn write task
        let shutdown_write = self.shutdown.clone();
        let state_write = state.clone();
        let tx_handle_write = tx_handle.clone();
        let event_tx_write = event_tx.clone();
        tokio::spawn(async move {
            Self::write_task(write, rx, shutdown_write, state_write, tx_handle_write, event_tx_write).await;
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
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            match read.next().await {
                Some(Ok(msg)) => {
                    match msg {
                        Message::Text(text) => {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text.as_str()) {
                                // Handle heartbeat responses
                                if let Some(msg_type) = parsed.get("type").and_then(|t| t.as_str()) {
                                    if msg_type == "pong" || msg_type == "heartbeat-response" || msg_type == "pq-heartbeat-pong" {
                                        missed_heartbeats.store(0, Ordering::Relaxed);
                                        continue;
                                    }
                                    
                                    // Update session ID
                                    if let Some(sid) = parsed.get("sessionId").and_then(|s| s.as_str()) {
                                        *session_id.write() = Some(sid.to_string());
                                    }
                                }

                                if let Some(ref tx) = *event_tx.read() {
                                    let _ = tx.send(WsEvent::Message { data: parsed });
                                }
                            }
                        }
                        Message::Ping(_) => {
                            missed_heartbeats.store(0, Ordering::Relaxed);
                        }
                        Message::Pong(_) => {
                            missed_heartbeats.store(0, Ordering::Relaxed);
                        }
                        Message::Close(frame) => {
                            let (code, reason) = frame.map(|f| (f.code.into(), f.reason.to_string()))
                                .unwrap_or((1000, "Normal closure".to_string()));
                            if let Some(ref tx) = *event_tx.read() {
                                let _ = tx.send(WsEvent::ConnectionClosed { code, reason, duration: 0 });
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                Some(Err(e)) => {
                    error!("WebSocket read error: {}", e);
                    if let Some(ref tx) = *event_tx.read() {
                        let _ = tx.send(WsEvent::ConnectionError { error: e.to_string() });
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
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            match rx.recv().await {
                Some(msg) => {
                    if let Err(e) = write.send(msg).await {
                        error!("WebSocket write error: {}", e);
                        if let Some(ref tx) = *event_tx.read() {
                            let _ = tx.send(WsEvent::ConnectionError { error: e.to_string() });
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
            // Queue message if within limits
            let mut queue = self.message_queue.write();
            if queue.len() < MAX_QUEUE_SIZE {
                let msg = match payload {
                    serde_json::Value::String(s) => s,
                    _ => serde_json::to_string(&payload)?,
                };
                queue.push(msg);
                return Ok(SendResult {
                    success: true,
                    queued: Some(true),
                    error: None,
                });
            } else {
                return Ok(SendResult {
                    success: false,
                    queued: None,
                    error: Some("Queue full".to_string()),
                });
            }
        }

        let tx = self.tx.read().clone();
        if let Some(sender) = tx {
            let msg = match payload {
                serde_json::Value::String(s) => s,
                _ => serde_json::to_string(&payload)?,
            };
            if let Err(_) = sender.send(Message::Text(msg.into())) {
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
        let messages: Vec<String> = {
            let mut queue = self.message_queue.write();
            std::mem::take(&mut *queue)
        };

        if messages.is_empty() {
            return;
        }

        let tx = self.tx.read().clone();
        if let Some(sender) = tx {
            for msg in messages {
                if sender.send(Message::Text(msg.into())).is_err() {
                    break;
                }
            }
        }
    }

    /// Disconnect
    pub async fn disconnect(&self) -> QorResult<bool> {
        self.shutdown.store(true, Ordering::Relaxed);
        *self.state.write() = ConnectionState::Disconnected;
        *self.tx.write() = None;
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
        let duration = self.connection_established_at.read()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        WebSocketState {
            connected: self.is_connected(),
            connecting: *self.state.read() == ConnectionState::Connecting,
            reconnect_attempts: self.reconnect_attempts.load(Ordering::Relaxed),
            queue_size: self.message_queue.read().len(),
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
