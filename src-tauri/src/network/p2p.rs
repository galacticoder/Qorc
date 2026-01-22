//! P2P Signaling Handler
//!
//! Manages P2P signaling WebSocket connection for background mode

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use tokio::time::Duration;
use parking_lot::RwLock;

use futures_util::{SinkExt, StreamExt};
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
const HEARTBEAT_INTERVAL_MS: u64 = 30000;
const CONNECTION_TIMEOUT_SECS: u64 = 20;

/// P2P Signaling connection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConnectResult {
    pub success: bool,
    pub already_connected: Option<bool>,
    pub error: Option<String>,
}

/// P2P Signaling send result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PSendResult {
    pub success: bool,
    pub error: Option<String>,
}

/// P2P signaling event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum P2PEvent {
    #[serde(rename = "__p2p_signaling_connected")]
    Connected { 
        #[serde(rename = "connectionId")]
        connection_id: String 
    },
    #[serde(rename = "__p2p_signaling_closed")]
    Closed { 
        #[serde(rename = "connectionId")]
        connection_id: String,
        code: u16, 
        reason: Option<String> 
    },
    #[serde(rename = "message")]
    Message { 
        #[serde(rename = "connectionId")]
        connection_id: String,
        data: serde_json::Value 
    },
}

/// P2P Connection
pub struct P2PConnection {
    tx: mpsc::UnboundedSender<Message>,
    is_connected: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
}

/// P2P Signaling Handler
pub struct P2PSignalingHandler {
    connections: RwLock<HashMap<String, P2PConnection>>,
    tor_ready: AtomicBool,
    tor_socks_port: AtomicU16,
    is_background_mode: AtomicBool,
    event_tx: RwLock<Option<mpsc::UnboundedSender<P2PEvent>>>,
}

impl P2PSignalingHandler {
    /// Create new handler
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            tor_ready: AtomicBool::new(false),
            tor_socks_port: AtomicU16::new(9150),
            is_background_mode: AtomicBool::new(false),
            event_tx: RwLock::new(None),
        }
    }

    /// Set Tor ready state
    pub fn set_tor_ready(&self, ready: bool) {
        self.tor_ready.store(ready, Ordering::Relaxed);
    }

    /// Update Tor configuration
    pub fn update_tor_config(&self, socks_port: u16) {
        self.tor_socks_port.store(socks_port, Ordering::Relaxed);
    }

    /// Set background mode
    pub fn set_background_mode(&self, enabled: bool) {
        self.is_background_mode.store(enabled, Ordering::Relaxed);
    }

    /// Set event handler
    pub fn set_event_handler(&self, tx: mpsc::UnboundedSender<P2PEvent>) {
        *self.event_tx.write() = Some(tx);
    }

    /// Connect to P2P signaling server
    pub async fn connect(
        &self,
        connection_id: &str,
        server_url: &str,
        username: Option<String>,
        registration_payload: Option<serde_json::Value>,
    ) -> QorResult<P2PConnectResult> {
        if server_url.is_empty() {
            return Ok(P2PConnectResult {
                success: false,
                already_connected: None,
                error: Some("Invalid server URL".to_string()),
            });
        }

        {
            let conns = self.connections.read();
            if let Some(conn) = conns.get(connection_id) {
                if conn.is_connected.load(Ordering::Relaxed) {
                    return Ok(P2PConnectResult {
                        success: true,
                        already_connected: Some(true),
                        error: None,
                    });
                }
            }
        }

        if !self.tor_ready.load(Ordering::Relaxed) {
            return Ok(P2PConnectResult {
                success: false,
                already_connected: None,
                error: Some("Tor not ready".to_string()),
            });
        }

        match self.create_connection(connection_id, server_url, username, registration_payload).await {
            Ok(_) => Ok(P2PConnectResult {
                success: true,
                already_connected: Some(false),
                error: None,
            }),
            Err(e) => {
                Ok(P2PConnectResult {
                    success: false,
                    already_connected: None,
                    error: Some(e.safe_message()),
                })
            }
        }
    }

    /// Create WebSocket connection
    async fn create_connection(
        &self,
        connection_id: &str,
        url_input: &str,
        username: Option<String>,
        registration_payload: Option<serde_json::Value>,
    ) -> QorResult<()> {
        let url_str = url_input.trim();
        let url = Url::parse(url_str)
            .map_err(|e| QorError::InvalidArgument(format!("Invalid URL: {}", e)))?;

        let host = url.host_str()
            .ok_or_else(|| QorError::InvalidArgument("No host in URL".to_string()))?;
        let port = url.port_or_known_default().unwrap_or(443);

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

        // WebSocket upgrade
        let (ws_stream, _) = tokio::time::timeout(
            Duration::from_secs(15),
            tokio_tungstenite::client_async_tls_with_config(url_str, tcp, None, Some(connector)),
        )
        .await
        .map_err(|_| QorError::Network("WebSocket upgrade timeout".to_string()))?
        .map_err(|e| QorError::Network(format!("WebSocket upgrade failed: {}", e)))?;

        let (mut write, read) = ws_stream.split();

        // Create message channel
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let is_connected = Arc::new(AtomicBool::new(true));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Store connection
        {
            let mut conns = self.connections.write();
            conns.insert(connection_id.to_string(), P2PConnection {
                tx: tx.clone(),
                is_connected: is_connected.clone(),
                shutdown: shutdown.clone(),
            });
        }

        // Send registration if provided
        if let (Some(username), Some(payload)) = (username, registration_payload) {
            let register_msg = serde_json::json!({
                "type": "register",
                "from": username,
                "payload": payload
            });
            let msg_str = serde_json::to_string(&register_msg)?;
            let _ = write.send(Message::Text(msg_str.into())).await;
        }

        // Send connected event
        if let Some(event_tx) = self.event_tx.read().as_ref() {
            let _ = event_tx.send(P2PEvent::Connected { connection_id: connection_id.to_string() });
        }

        // Spawn write task
        let shutdown_write = shutdown.clone();
        tokio::spawn(async move {
            while !shutdown_write.load(Ordering::Relaxed) {
                match rx.recv().await {
                    Some(msg) => {
                        if write.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });

        // Spawn read task
        let event_tx = self.event_tx.read().clone();
        let shutdown_read = shutdown.clone();
        let is_connected_read = is_connected.clone();
        let conn_id = connection_id.to_string();

        let read_tx = tx.clone();
        tokio::spawn(async move {
            Self::read_task(&conn_id, read, event_tx, shutdown_read, is_connected_read, read_tx).await;
        });

        // Spawn heartbeat task
        let heartbeat_tx = tx.clone();
        let shutdown_heartbeat = shutdown.clone();
        let is_connected_heartbeat = is_connected.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(HEARTBEAT_INTERVAL_MS));
            while !shutdown_heartbeat.load(Ordering::Relaxed) {
                interval.tick().await;
                if is_connected_heartbeat.load(Ordering::Relaxed) {
                    if heartbeat_tx.send(Message::Ping(vec![].into())).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
        });

        Ok(())
    }

    /// Read task
    async fn read_task(
        connection_id: &str,
        mut read: futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
        event_tx: Option<mpsc::UnboundedSender<P2PEvent>>,
        shutdown: Arc<AtomicBool>,
        is_connected: Arc<AtomicBool>,
        tx: mpsc::UnboundedSender<Message>,
    ) {
        while !shutdown.load(Ordering::Relaxed) {
            match read.next().await {
                Some(Ok(msg)) => {
                    match msg {
                        Message::Text(text) => {
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                                if let Some(ref tx) = event_tx {
                                    let _ = tx.send(P2PEvent::Message { 
                                        connection_id: connection_id.to_string(),
                                        data: parsed 
                                    });
                                }
                            } else {
                                // Not JSON
                                if let Some(ref tx) = event_tx {
                                    let _ = tx.send(P2PEvent::Message { 
                                        connection_id: connection_id.to_string(),
                                        data: serde_json::Value::String(text.to_string())
                                    });
                                }
                            }
                        }
                        Message::Binary(bin) => {
                            // Binary data
                            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bin);
                            if let Some(ref tx) = event_tx {
                                let _ = tx.send(P2PEvent::Message { 
                                    connection_id: connection_id.to_string(),
                                    data: serde_json::Value::String(b64)
                                });
                            }
                        }
                        Message::Ping(payload) => {
                            let _ = tx.send(Message::Pong(payload));
                        }
                        Message::Pong(_) => {}
                        Message::Close(frame) => {
                            let code = frame.as_ref().map(|f| f.code.into()).unwrap_or(1000);
                            let reason = frame.map(|f| f.reason.to_string());
                            if let Some(ref tx) = event_tx {
                                let _ = tx.send(P2PEvent::Closed { 
                                    connection_id: connection_id.to_string(),
                                    code, 
                                    reason 
                                });
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                Some(Err(e)) => {
                    tracing::error!("[P2P] Read error for {}: {}", connection_id, e);
                    if let Some(ref tx) = event_tx {
                        let _ = tx.send(P2PEvent::Closed { 
                            connection_id: connection_id.to_string(),
                            code: 1006, 
                            reason: Some(format!("Read error: {}", e)) 
                        });
                    }
                    break;
                }
                None => {
                    if let Some(ref tx) = event_tx {
                        let _ = tx.send(P2PEvent::Closed { 
                            connection_id: connection_id.to_string(),
                            code: 1000, 
                            reason: Some("Connection closed".to_string()) 
                        });
                    }
                    break;
                }
            }
        }

        is_connected.store(false, Ordering::Relaxed);
    }

    /// Send message
    pub async fn send(&self, connection_id: &str, message: serde_json::Value) -> QorResult<P2PSendResult> {
        let conn = {
            let conns = self.connections.read();
            conns.get(connection_id).cloned()
        };

        if let Some(conn) = conn {
            if !conn.is_connected.load(Ordering::Relaxed) {
                return Ok(P2PSendResult {
                    success: false,
                    error: Some("Not connected".to_string()),
                });
            }

            let msg_str = match message {
                serde_json::Value::String(s) => s,
                _ => serde_json::to_string(&message)?,
            };
            conn.tx.send(Message::Text(msg_str.into()))
                .map_err(|_| QorError::Network("Failed to send".to_string()))?;

            return Ok(P2PSendResult {
                success: true,
                error: None,
            });
        }

        Ok(P2PSendResult {
            success: false,
            error: Some("Connection not found".to_string()),
        })
    }

    /// Disconnect
    pub async fn disconnect(&self, connection_id: &str) -> QorResult<bool> {
        let conn = {
            let mut conns = self.connections.write();
            conns.remove(connection_id)
        };

        if let Some(conn) = conn {
            conn.shutdown.store(true, Ordering::Relaxed);
            conn.is_connected.store(false, Ordering::Relaxed);
            return Ok(true);
        }

        Ok(false)
    }

    /// Check if any connections are active
    pub fn has_active_connections(&self) -> bool {
        let conns = self.connections.read();
        conns.values().any(|c| c.is_connected.load(Ordering::Relaxed))
    }

    /// Get status
    pub fn status(&self) -> serde_json::Value {
        let conns = self.connections.read();
        let connections: Vec<String> = conns.keys().cloned().collect();
        serde_json::json!({
            "activeConnections": connections.len(),
            "connectionIds": connections,
            "torReady": self.tor_ready.load(Ordering::Relaxed),
            "backgroundMode": self.is_background_mode.load(Ordering::Relaxed)
        })
    }
}

impl Clone for P2PConnection {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            is_connected: self.is_connected.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl Default for P2PSignalingHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize P2P signaling handler
pub async fn init() -> QorResult<Arc<P2PSignalingHandler>> {
    let handler = P2PSignalingHandler::new();
    Ok(Arc::new(handler))
}
