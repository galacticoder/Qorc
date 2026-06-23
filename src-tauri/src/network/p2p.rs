//! P2P Transport Handler
//!
//! Iroh based P2P bridge for app level JSON frames

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, endpoint::Connection};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::error::{QorError, QorResult};

// Constants
const ALPN: &[u8] = b"qor-chat/p2p-bridge/1";
const REQUEST_TIMEOUT_SECS: u64 = 30;
const SEND_TIMEOUT_SECS: u64 = 10;
const HEALTH_CHECK_TIMEOUT_SECS: u64 = 1;

fn build_discovery_endpoint_url(addr: &EndpointAddr) -> String {
    let endpoint_id = addr.id.to_string();
    if addr.addrs.is_empty() {
        return format!("iroh://{}", endpoint_id);
    }
    match serde_json::to_vec(addr) {
        Ok(raw) => {
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
            format!("iroh://{}?addr={}", endpoint_id, encoded)
        }
        Err(_) => format!("iroh://{}", endpoint_id),
    }
}

fn parse_discovery_endpoint_url(endpoint_url: &str) -> QorResult<EndpointAddr> {
    let trimmed = endpoint_url.trim();
    if trimmed.is_empty() {
        return Err(QorError::Network("Empty endpoint".to_string()));
    }

    let without_scheme = trimmed.strip_prefix("iroh://").unwrap_or(trimmed);
    let (id_part, query_part) = without_scheme
        .split_once('?')
        .map(|(id, q)| (id, Some(q)))
        .unwrap_or((without_scheme, None));

    let node_id: EndpointId = id_part
        .parse()
        .map_err(|e| QorError::Network(format!("Invalid NodeId: {}", e)))?;

    if let Some(query) = query_part {
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            if key != "addr" || value.is_empty() {
                continue;
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|e| QorError::Network(format!("Invalid endpoint addr payload: {}", e)))?;
            let parsed: EndpointAddr = serde_json::from_slice(&decoded)
                .map_err(|e| QorError::Network(format!("Invalid endpoint addr json: {}", e)))?;
            if parsed.id != node_id {
                return Err(QorError::Network(
                    "Endpoint ID mismatch in addr payload".to_string(),
                ));
            }
            return Ok(parsed);
        }
    }

    Ok(EndpointAddr::from(node_id))
}

/// P2P connection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConnectResult {
    pub success: bool,
    pub already_connected: Option<bool>,
    pub error: Option<String>,
}

/// P2P send result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PSendResult {
    pub success: bool,
    pub error: Option<String>,
}

/// P2P transport event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum P2PEvent {
    #[serde(rename = "__p2p_connected")]
    Connected {
        #[serde(rename = "connectionId")]
        connection_id: String,
    },
    #[serde(rename = "__p2p_closed")]
    Closed {
        #[serde(rename = "connectionId")]
        connection_id: String,
        code: u16,
        reason: Option<String>,
    },
    #[serde(rename = "message")]
    Message {
        #[serde(rename = "connectionId")]
        connection_id: String,
        data: serde_json::Value,
    },
}

// Worker

enum WorkerCommand {
    Dial {
        connection_id: String,
        node_id: EndpointId,
        endpoint_addr: EndpointAddr,
        resp: oneshot::Sender<P2PConnectResult>,
    },
    Send {
        connection_id: String,
        message: serde_json::Value,
        resp: oneshot::Sender<P2PSendResult>,
    },
    Disconnect {
        connection_id: String,
        resp: oneshot::Sender<bool>,
    },
}

#[derive(Debug, Clone)]
enum WorkerEvent {
    Connected {
        connection_id: String,
        connection_token: u64,
    },
    Closed {
        connection_id: String,
        connection_token: u64,
        code: u16,
        reason: Option<String>,
    },
    Message {
        connection_id: String,
        connection_token: u64,
        data: serde_json::Value,
    },
}

/// Write a length prefixed JSON frame to QUIC send stream
async fn write_frame(send: &mut iroh::endpoint::SendStream, data: &[u8]) -> Result<(), String> {
    let len = data.len() as u32;
    debug!("[P2P] Writing frame: {} bytes", len);
    send.write_all(&len.to_le_bytes()).await.map_err(|e| {
        error!("[P2P] Failed to write frame length: {}", e);
        format!("write len: {}", e)
    })?;
    send.write_all(data).await.map_err(|e| {
        error!("[P2P] Failed to write frame data: {}", e);
        format!("write data: {}", e)
    })?;
    Ok(())
}

/// Read a length prefixed JSON frame from a QUIC recv stream
async fn read_frame(recv: &mut iroh::endpoint::RecvStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| {
        debug!(
            "[P2P] Stream read closed or failed while waiting for frame length: {}",
            e
        );
        format!("read len: {}", e)
    })?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        error!("[P2P] Received frame too large: {} bytes", len);
        return Err("Frame too large".to_string());
    }
    debug!("[P2P] Reading frame: {} bytes", len);
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.map_err(|e| {
        error!("[P2P] Failed to read frame body ({} bytes): {}", len, e);
        format!("read data: {}", e)
    })?;
    Ok(buf)
}

struct IrohWorker {
    endpoint: Endpoint,
    connections: HashMap<String, Connection>,
    alias_to_node: HashMap<String, EndpointId>,
    node_to_aliases: HashMap<EndpointId, HashSet<String>>,
    connection_tokens: HashMap<String, u64>,
    next_connection_token: u64,
}

impl IrohWorker {
    async fn new() -> QorResult<Self> {
        // Hard disable public relay/address lookup infrastructure
        let endpoint = Endpoint::empty_builder(RelayMode::Disabled)
            .clear_address_lookup()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| QorError::Network(format!("Failed to bind iroh endpoint: {}", e)))?;

        tracing::info!("[P2P/iroh] Endpoint bound, NodeId: {}", endpoint.id());

        Ok(Self {
            endpoint,
            connections: HashMap::new(),
            alias_to_node: HashMap::new(),
            node_to_aliases: HashMap::new(),
            connection_tokens: HashMap::new(),
            next_connection_token: 1,
        })
    }

    fn issue_connection_token(&mut self, connection_id: &str) -> u64 {
        let token = self.next_connection_token;
        self.next_connection_token = self.next_connection_token.wrapping_add(1);
        if self.next_connection_token == 0 {
            self.next_connection_token = 1;
        }
        self.connection_tokens
            .insert(connection_id.to_string(), token);
        token
    }

    fn bind_alias(&mut self, alias: String, node_id: EndpointId) {
        debug!("[P2P] Binding alias {} to node {}", alias, node_id);
        if let Some(previous_node) = self.alias_to_node.insert(alias.clone(), node_id) {
            if previous_node != node_id {
                info!(
                    "[P2P] Alias {} re-mapped from {} to {}",
                    alias, previous_node, node_id
                );
                if let Some(set) = self.node_to_aliases.get_mut(&previous_node) {
                    set.remove(&alias);
                    if set.is_empty() {
                        self.node_to_aliases.remove(&previous_node);
                    }
                }
            }
        }
        self.node_to_aliases
            .entry(node_id)
            .or_default()
            .insert(alias);
    }

    fn unbind_alias(&mut self, alias: &str) -> Option<EndpointId> {
        let node = self.alias_to_node.remove(alias)?;
        if let Some(set) = self.node_to_aliases.get_mut(&node) {
            set.remove(alias);
            if set.is_empty() {
                self.node_to_aliases.remove(&node);
            }
        }
        Some(node)
    }

    async fn is_connection_alive(conn: &Connection) -> bool {
        match tokio::time::timeout(
            std::time::Duration::from_secs(HEALTH_CHECK_TIMEOUT_SECS),
            conn.open_bi(),
        )
        .await
        {
            Ok(Ok((mut send, _recv))) => {
                let _ = send.finish();
                true
            }
            _ => false,
        }
    }

    async fn run(
        mut self,
        mut command_rx: mpsc::UnboundedReceiver<WorkerCommand>,
        event_tx: mpsc::UnboundedSender<WorkerEvent>,
    ) {
        loop {
            tokio::select! {
                Some(cmd) = command_rx.recv() => {
                    self.handle_command(cmd, &event_tx).await;
                }
                Some(incoming) = self.endpoint.accept() => {
                    self.handle_incoming(incoming, &event_tx).await;
                }
                else => break,
            }
        }
    }

    async fn handle_incoming(
        &mut self,
        incoming: iroh::endpoint::Incoming,
        event_tx: &mpsc::UnboundedSender<WorkerEvent>,
    ) {
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                warn!("[P2P] Failed to accept incoming connection: {}", e);
                return;
            }
        };

        let node_id = conn.remote_id();
        let remote = node_id.to_string();

        info!("[P2P] Accepted QUIC connection from node: {}", remote);

        let alias = if let Some(existing_aliases) = self.node_to_aliases.get(&node_id) {
            let found = existing_aliases
                .iter()
                .find(|candidate| candidate.as_str() != remote.as_str())
                .cloned()
                .or_else(|| existing_aliases.iter().next().cloned())
                .unwrap_or_else(|| remote.clone());
            debug!("[P2P] Resolved incoming node {} to alias {}", remote, found);
            found
        } else {
            debug!(
                "[P2P] No alias found for incoming node {}. Using raw ID.",
                remote
            );
            remote.clone()
        };

        if !self.alias_to_node.contains_key(&alias) {
            info!("[P2P] Auto-binding new alias {} to node {}", alias, remote);
            self.bind_alias(alias.clone(), node_id);
        }

        let connection_token = self.issue_connection_token(&alias);
        debug!(
            "[P2P] Issuing connection token {} for alias {}",
            connection_token, alias
        );

        self.connections.insert(alias.clone(), conn.clone());
        let _ = event_tx.send(WorkerEvent::Connected {
            connection_id: alias.clone(),
            connection_token,
        });

        // Spawn reader for incoming streams
        let etx = event_tx.clone();
        let cid = alias.clone();
        let token = connection_token;
        info!(
            "[P2P] Spawning read_loop for incoming connection from {}",
            cid
        );
        tokio::spawn(async move {
            Self::read_loop(conn, cid, token, etx).await;
        });
    }

    async fn read_loop(
        conn: Connection,
        connection_id: String,
        connection_token: u64,
        event_tx: mpsc::UnboundedSender<WorkerEvent>,
    ) {
        info!(
            "[P2P] Starting read_loop for connection: {} (token: {})",
            connection_id, connection_token
        );
        loop {
            let stream = match conn.accept_bi().await {
                Ok(s) => {
                    info!(
                        "[P2P-RECV] accepted incoming bi-stream for {}",
                        connection_id
                    );
                    s
                }
                Err(e) => {
                    info!(
                        "[P2P-RECV] read_loop ending for {} (accept_bi failed = conn dead): {}",
                        connection_id, e
                    );
                    break;
                }
            };
            let (_, mut recv) = stream;
            match read_frame(&mut recv).await {
                Ok(buf) => {
                    info!(
                        "[P2P-RECV] read frame OK on {} ({} bytes)",
                        connection_id,
                        buf.len()
                    );
                    match serde_json::from_slice::<serde_json::Value>(&buf) {
                        Ok(data) => {
                            info!(
                                "[P2P-RECV] valid JSON frame on {} -> forwarding to bridge (emit p2p-message)",
                                connection_id
                            );
                            let _ = event_tx.send(WorkerEvent::Message {
                                connection_id: connection_id.clone(),
                                connection_token,
                                data,
                            });
                        }
                        Err(e) => {
                            error!(
                                "[P2P-RECV] failed to parse JSON frame from {} ({} bytes): {}",
                                connection_id,
                                buf.len(),
                                e
                            );
                        }
                    }
                }
                
                Err(e) => {
                    info!(
                        "[P2P-RECV] read_frame failed (likely transient/probe) for {}: {}",
                        connection_id, e
                    );
                    continue;
                }
            }
        }

        info!(
            "[P2P] Connection closed for {}. Sending Closed event.",
            connection_id
        );
        let _ = event_tx.send(WorkerEvent::Closed {
            connection_id,
            connection_token,
            code: 1006,
            reason: Some("Connection closed".to_string()),
        });
    }

    async fn handle_command(
        &mut self,
        cmd: WorkerCommand,
        event_tx: &mpsc::UnboundedSender<WorkerEvent>,
    ) {
        match cmd {
            WorkerCommand::Dial {
                connection_id,
                node_id,
                endpoint_addr,
                resp,
            } => {
                info!(
                    "[P2P] Received Dial command: {} (node: {})",
                    connection_id, node_id
                );

                // Pre bind alias
                self.bind_alias(connection_id.clone(), node_id);

                if let Some(existing_conn) = self.connections.get(&connection_id).cloned() {
                    debug!(
                        "[P2P] Checking existing connection for {}...",
                        connection_id
                    );
                    if Self::is_connection_alive(&existing_conn).await {
                        info!(
                            "[P2P] Already connected to {}. Reusing connection.",
                            connection_id
                        );
                        let _ = resp.send(P2PConnectResult {
                            success: true,
                            already_connected: Some(true),
                            error: None,
                        });
                        return;
                    }
                    warn!(
                        "[P2P] Existing connection for {} is dead. Removing.",
                        connection_id
                    );
                    self.connections.remove(&connection_id);
                    self.connection_tokens.remove(&connection_id);
                }

                // If incoming connection exists under node id key then reuse it
                if let Some(mapped_node) = self.alias_to_node.get(&connection_id).cloned() {
                    let mapped_key = mapped_node.to_string();
                    debug!(
                        "[P2P] Checking if node {} is already connected via alias {}...",
                        mapped_key, connection_id
                    );
                    if let Some(existing_conn) = self.connections.get(&mapped_key).cloned() {
                        if Self::is_connection_alive(&existing_conn).await {
                            info!(
                                "[P2P] Node {} already has a live connection. Binding to alias {}.",
                                mapped_key, connection_id
                            );
                            let connection_token = self
                                .connection_tokens
                                .get(&mapped_key)
                                .copied()
                                .unwrap_or_else(|| self.issue_connection_token(&mapped_key));
                            self.connection_tokens
                                .insert(connection_id.clone(), connection_token);
                            self.connections
                                .insert(connection_id.clone(), existing_conn.clone());
                            let _ = event_tx.send(WorkerEvent::Connected {
                                connection_id: connection_id.clone(),
                                connection_token,
                            });
                            let _ = resp.send(P2PConnectResult {
                                success: true,
                                already_connected: Some(true),
                                error: None,
                            });
                            return;
                        }
                        self.connections.remove(&mapped_key);
                        self.connection_tokens.remove(&mapped_key);
                    }
                }

                let addr = endpoint_addr;
                info!("[P2P] Dialing {} via QUIC...", connection_id);
                match tokio::time::timeout(
                    std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
                    self.endpoint.connect(addr, ALPN),
                )
                .await
                {
                    Ok(Ok(conn)) => {
                        info!("[P2P] Successfully connected to {}", connection_id);
                        let connection_token = self.issue_connection_token(&connection_id);
                        self.connections.insert(connection_id.clone(), conn.clone());

                        let _ = event_tx.send(WorkerEvent::Connected {
                            connection_id: connection_id.clone(),
                            connection_token,
                        });

                        // Spawn reader
                        let etx = event_tx.clone();
                        let cid = connection_id.clone();
                        let token = connection_token;
                        tokio::spawn(async move {
                            Self::read_loop(conn, cid, token, etx).await;
                        });

                        let _ = resp.send(P2PConnectResult {
                            success: true,
                            already_connected: Some(false),
                            error: None,
                        });
                    }
                    Ok(Err(e)) => {
                        error!("[P2P] Dial failed for {}: {}", connection_id, e);
                        let _ = resp.send(P2PConnectResult {
                            success: false,
                            already_connected: None,
                            error: Some(format!("Dial failed: {}", e)),
                        });
                    }
                    Err(_) => {
                        error!(
                            "[P2P] Dial timed out ({}s) for {}",
                            REQUEST_TIMEOUT_SECS, connection_id
                        );
                        let _ = resp.send(P2PConnectResult {
                            success: false,
                            already_connected: None,
                            error: Some("Connection timeout".to_string()),
                        });
                    }
                }
            }
            WorkerCommand::Send {
                connection_id,
                message,
                resp,
            } => {
                let mut resolved_key: Option<String> =
                    if self.connections.contains_key(&connection_id) {
                        Some(connection_id.clone())
                    } else {
                        None
                    };

                if resolved_key.is_none() {
                    if let Some(node_id) = self.alias_to_node.get(&connection_id) {
                        let node_key = node_id.to_string();
                        if self.connections.contains_key(&node_key) {
                            resolved_key = Some(node_key);
                        }
                    }
                }

                if resolved_key.is_none() {
                    if let Ok(node_id) = connection_id.parse::<EndpointId>() {
                        if let Some(aliases) = self.node_to_aliases.get(&node_id) {
                            if let Some(alias_key) = aliases
                                .iter()
                                .find(|alias| self.connections.contains_key((*alias).as_str()))
                            {
                                resolved_key = Some(alias_key.clone());
                            }
                        }
                    }
                }

                let Some(connection_key) = resolved_key else {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("Connection not found".to_string()),
                    });
                    return;
                };
                let Some(conn) = self.connections.get(&connection_key) else {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("Connection not found".to_string()),
                    });
                    return;
                };

                let data = match serde_json::to_vec(&message) {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = resp.send(P2PSendResult {
                            success: false,
                            error: Some(format!("Serialize: {}", e)),
                        });
                        return;
                    }
                };

                info!(
                    "[P2P-SEND] opening bi-stream to {} (key={}) for {} bytes",
                    connection_id,
                    connection_key,
                    data.len()
                );
                let send_timeout = std::time::Duration::from_secs(SEND_TIMEOUT_SECS);
                let send_result = tokio::time::timeout(send_timeout, async {
                    let (mut send, _) = conn
                        .open_bi()
                        .await
                        .map_err(|e| format!("Open stream: {}", e))?;
                    write_frame(&mut send, &data)
                        .await
                        .map_err(|e| format!("Write frame: {}", e))?;
                    let _ = send.finish();
                    Ok::<(), String>(())
                })
                .await;

                match send_result {
                    Ok(Ok(())) => {
                        info!(
                            "[P2P-SEND] ✓ wrote {} bytes to {} (stream finished)",
                            data.len(),
                            connection_id
                        );
                        let _ = resp.send(P2PSendResult {
                            success: true,
                            error: None,
                        });
                    }
                    Ok(Err(e)) => {
                        error!("[P2P] Failed to send to {}: {}", connection_id, e);
                        if e.starts_with("Open stream:") {
                            warn!(
                                "[P2P] Removing potentially dead connection for {}",
                                connection_key
                            );
                            self.connections.remove(&connection_key);
                            self.connection_tokens.remove(&connection_key);
                            if connection_key != connection_id {
                                self.connections.remove(&connection_id);
                                self.connection_tokens.remove(&connection_id);
                            }
                        }
                        let _ = resp.send(P2PSendResult {
                            success: false,
                            error: Some(e),
                        });
                    }
                    Err(_) => {
                        error!(
                            "[P2P] Send timed out ({}s) for {}",
                            SEND_TIMEOUT_SECS, connection_id
                        );
                        self.connections.remove(&connection_key);
                        self.connection_tokens.remove(&connection_key);
                        if connection_key != connection_id {
                            self.connections.remove(&connection_id);
                            self.connection_tokens.remove(&connection_id);
                        }
                        let _ = resp.send(P2PSendResult {
                            success: false,
                            error: Some("Send timeout: QUIC stream unresponsive".to_string()),
                        });
                    }
                }
            }
            WorkerCommand::Disconnect {
                connection_id,
                resp,
            } => {
                info!("[P2P] Received Disconnect command for {}", connection_id);
                let mut close_token = self.connection_tokens.remove(&connection_id).unwrap_or(0);
                let mut removed = self.connections.remove(&connection_id);

                if removed.is_none() {
                    if let Some(node_id) = self.alias_to_node.get(&connection_id) {
                        let node_key = node_id.to_string();
                        removed = self.connections.remove(&node_key);
                        if close_token == 0 {
                            close_token = self.connection_tokens.remove(&node_key).unwrap_or(0);
                        } else {
                            self.connection_tokens.remove(&node_key);
                        }
                    }
                }

                self.unbind_alias(&connection_id);

                if let Some(conn) = removed {
                    conn.close(0u32.into(), b"disconnect");
                }

                let _ = event_tx.send(WorkerEvent::Closed {
                    connection_id,
                    connection_token: close_token,
                    code: 1000,
                    reason: Some("Disconnected".to_string()),
                });
                let _ = resp.send(true);
            }
        }
    }
}

// Public Handler

pub struct P2PTransportHandler {
    command_tx: mpsc::UnboundedSender<WorkerCommand>,
    active_connections: Arc<RwLock<HashSet<String>>>,
    event_tx: Arc<RwLock<Option<mpsc::UnboundedSender<P2PEvent>>>>,
    local_node_id: Arc<RwLock<Option<String>>>,
    is_background_mode: AtomicBool,
}

impl P2PTransportHandler {
    fn new(command_tx: mpsc::UnboundedSender<WorkerCommand>) -> Self {
        Self {
            command_tx,
            active_connections: Arc::new(RwLock::new(HashSet::new())),
            event_tx: Arc::new(RwLock::new(None)),
            local_node_id: Arc::new(RwLock::new(None)),
            is_background_mode: AtomicBool::new(false),
        }
    }

    /// Set background mode
    pub fn set_background_mode(&self, enabled: bool) {
        self.is_background_mode.store(enabled, Ordering::Relaxed);
    }

    /// Set event handler
    pub fn set_event_handler(&self, tx: mpsc::UnboundedSender<P2PEvent>) {
        *self.event_tx.write() = Some(tx);
    }

    /// Connect to a peer by iroh NodeId
    pub async fn connect(
        &self,
        connection_id: &str,
        endpoint_url: &str,
    ) -> QorResult<P2PConnectResult> {
        let endpoint_addr = parse_discovery_endpoint_url(endpoint_url)?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(WorkerCommand::Dial {
                connection_id: connection_id.to_string(),
                node_id: endpoint_addr.id,
                endpoint_addr,
                resp: tx,
            })
            .map_err(|_| QorError::Network("P2P worker unavailable".to_string()))?;

        match rx.await {
            Ok(res) => Ok(res),
            Err(_) => Ok(P2PConnectResult {
                success: false,
                already_connected: None,
                error: Some("P2P worker did not respond".to_string()),
            }),
        }
    }

    /// Send message
    pub async fn send(
        &self,
        connection_id: &str,
        message: serde_json::Value,
    ) -> QorResult<P2PSendResult> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(WorkerCommand::Send {
                connection_id: connection_id.to_string(),
                message,
                resp: tx,
            })
            .map_err(|_| QorError::Network("P2P worker unavailable".to_string()))?;

        match rx.await {
            Ok(res) => Ok(res),
            Err(_) => Ok(P2PSendResult {
                success: false,
                error: Some("P2P worker did not respond".to_string()),
            }),
        }
    }

    /// Disconnect
    pub async fn disconnect(&self, connection_id: &str) -> QorResult<bool> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(WorkerCommand::Disconnect {
                connection_id: connection_id.to_string(),
                resp: tx,
            })
            .map_err(|_| QorError::Network("P2P worker unavailable".to_string()))?;

        match rx.await {
            Ok(ok) => Ok(ok),
            Err(_) => Ok(false),
        }
    }


    /// Returns iroh://<node_id> for peer discovery
    pub fn local_endpoint(&self) -> Option<String> {
        self.local_node_id.read().clone()
    }

    /// Get status
    pub fn status(&self) -> serde_json::Value {
        let conns: Vec<String> = self.active_connections.read().iter().cloned().collect();

        serde_json::json!({
            "activeConnections": conns.len(),
            "connectionIds": conns,
            "localEndpoint": self.local_endpoint(),
            "backgroundMode": self.is_background_mode.load(Ordering::Relaxed),
        })
    }
}

impl Default for P2PTransportHandler {
    fn default() -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Self::new(tx)
    }
}

/// Initialize P2P transport handler
pub async fn init() -> QorResult<Arc<P2PTransportHandler>> {
    let worker = IrohWorker::new().await?;
    let mut endpoint_addr = worker.endpoint.addr();
    if endpoint_addr.addrs.is_empty() {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(8), worker.endpoint.online()).await;
        endpoint_addr = worker.endpoint.addr();
    }
    let node_id_str = build_discovery_endpoint_url(&endpoint_addr);

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<WorkerCommand>();
    let (worker_event_tx, mut worker_event_rx) = mpsc::unbounded_channel::<WorkerEvent>();

    let handler = Arc::new(P2PTransportHandler::new(cmd_tx));
    *handler.local_node_id.write() = Some(node_id_str);

    tokio::spawn(async move {
        worker.run(cmd_rx, worker_event_tx).await;
    });

    let active_connections = handler.active_connections.clone();
    let public_event_tx = handler.event_tx.clone();

    tokio::spawn(async move {
        let mut latest_connection_tokens: HashMap<String, u64> = HashMap::new();
        while let Some(evt) = worker_event_rx.recv().await {
            let mapped = match evt {
                WorkerEvent::Connected {
                    connection_id,
                    connection_token,
                } => {
                    latest_connection_tokens.insert(connection_id.clone(), connection_token);
                    active_connections.write().insert(connection_id.clone());
                    P2PEvent::Connected { connection_id }
                }
                WorkerEvent::Closed {
                    connection_id,
                    connection_token,
                    code,
                    reason,
                } => {
                    if let Some(latest) = latest_connection_tokens.get(&connection_id).copied() {
                        if latest != connection_token {
                            continue;
                        }
                    }
                    latest_connection_tokens.remove(&connection_id);
                    active_connections.write().remove(&connection_id);
                    P2PEvent::Closed {
                        connection_id,
                        code,
                        reason,
                    }
                }
                WorkerEvent::Message {
                    connection_id,
                    connection_token,
                    data,
                } => {
                    if let Some(latest) = latest_connection_tokens.get(&connection_id).copied() {
                        if latest != connection_token {
                            continue;
                        }
                    }
                    P2PEvent::Message {
                        connection_id,
                        data,
                    }
                }
            };

            if let Some(tx) = public_event_tx.read().as_ref() {
                let _ = tx.send(mapped);
            }
        }
    });

    Ok(handler)
}
