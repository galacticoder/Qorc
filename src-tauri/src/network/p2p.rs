//! P2P Transport Handler

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use base64::Engine as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tracing::{info, warn};

const ONION_VIRTUAL_PORT: u16 = 9_735;
const ONION_AUDIO_VIRTUAL_PORT: u16 = 9_736;
const ONION_DIAL_TIMEOUT_SECS: u64 = 45;
const ONION_PUBLISH_RETRY_SECS: u64 = 5;
const ONION_PUBLISH_RETRY_MAX_SECS: u64 = 120;
const AUDIO_LANE_OFFER_PREFIX: &[u8] = b"QOR-AUDIO-LANE-OFFER-v2\0";
const AUDIO_LANE_PREAMBLE_PREFIX: &[u8] = b"QOR-AUDIO-LANE-v2\0";
const AUDIO_LANE_TOKEN_BYTES: usize = 32;
const AUDIO_LANE_TARGET_COUNT: usize = 4;
const AUDIO_LANE_ACTIVE_COUNT: usize = 1;
const AUDIO_LANE_SWITCH_MIN_GAIN_MS: u64 = 75;
const AUDIO_LANE_SWITCH_MIN_GAIN_PERCENT: u64 = 10;
const AUDIO_LANE_SWITCH_CONFIRMATIONS: u8 = 3;
const AUDIO_LANE_FRAME_DATA: u8 = 1;
const AUDIO_LANE_FRAME_PING: u8 = 2;
const AUDIO_LANE_FRAME_PONG: u8 = 3;
const AUDIO_LANE_FRAME_READY: u8 = 4;
const AUDIO_LANE_FRAME_HEADER_BYTES: usize = 9;
const AUDIO_LANE_PROBE_INTERVAL_SECS: u64 = 2;
const AUDIO_LANE_PROBE_TIMEOUT_SECS: u64 = 6;
const AUDIO_LANE_BIND_TIMEOUT_SECS: u64 = 10;
const AUDIO_LANE_RETRY_BASE_SECS: u64 = 5;
const AUDIO_LANE_RETRY_MAX_SECS: u64 = 60;
const MAX_PENDING_AUDIO_LANES: usize = 64;

enum AudioLaneFrame<'a> {
    Data { frame_id: u64, data: &'a [u8] },
    Ping(u64),
    Pong(u64),
    Ready,
}

fn encode_audio_lane_frame(kind: u8, id: u64, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(AUDIO_LANE_FRAME_HEADER_BYTES + data.len());
    frame.push(kind);
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(data);
    frame
}

fn parse_audio_lane_frame(frame: &[u8]) -> Option<AudioLaneFrame<'_>> {
    if frame.len() < AUDIO_LANE_FRAME_HEADER_BYTES {
        return None;
    }
    let id = u64::from_be_bytes(frame[1..9].try_into().ok()?);
    if id == 0 {
        return None;
    }
    match frame[0] {
        AUDIO_LANE_FRAME_DATA if frame.len() > AUDIO_LANE_FRAME_HEADER_BYTES => {
            Some(AudioLaneFrame::Data {
                frame_id: id,
                data: &frame[AUDIO_LANE_FRAME_HEADER_BYTES..],
            })
        }
        AUDIO_LANE_FRAME_PING if frame.len() == AUDIO_LANE_FRAME_HEADER_BYTES => {
            Some(AudioLaneFrame::Ping(id))
        }
        AUDIO_LANE_FRAME_PONG if frame.len() == AUDIO_LANE_FRAME_HEADER_BYTES => {
            Some(AudioLaneFrame::Pong(id))
        }
        AUDIO_LANE_FRAME_READY if frame.len() == AUDIO_LANE_FRAME_HEADER_BYTES => {
            Some(AudioLaneFrame::Ready)
        }
        _ => None,
    }
}

#[derive(Default)]
struct AudioReceiveWindow {
    high: u64,
    seen: u128,
}

impl AudioReceiveWindow {
    fn accept(&mut self, frame_id: u64) -> bool {
        if frame_id == 0 {
            return false;
        }
        if self.high == 0 {
            self.high = frame_id;
            self.seen = 1;
            return true;
        }
        if frame_id > self.high {
            let shift = frame_id - self.high;
            self.seen = if shift >= u128::BITS as u64 {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.high = frame_id;
            return true;
        }
        let distance = self.high - frame_id;
        if distance >= u128::BITS as u64 {
            return false;
        }
        let mask = 1u128 << distance;
        if self.seen & mask != 0 {
            return false;
        }
        self.seen |= mask;
        true
    }
}

fn is_valid_onion_host(host: &str) -> bool {
    match host.strip_suffix(".onion") {
        Some(id) => crate::tor::is_valid_onion_service_id(id),
        None => false,
    }
}

struct OnionEndpoint {
    onion_service: crate::tor::PublishedOnionService,
    listener: TcpListener,
    audio_listener: TcpListener,
}

/// One peer connection
struct PeerConnection {
    peer_key: String,
    write: Mutex<WriteHalf<TcpStream>>,
    read: Mutex<ReadHalf<TcpStream>>,
    closed: AtomicBool,
    close_tx: watch::Sender<bool>,
}

static TOR: std::sync::OnceLock<Arc<crate::tor::TorManager>> = std::sync::OnceLock::new();

pub fn set_tor_manager(tor: Arc<crate::tor::TorManager>) {
    let _ = TOR.set(tor);
}

fn tor_manager() -> Result<&'static Arc<crate::tor::TorManager>, QorError> {
    TOR.get()
        .ok_or_else(|| QorError::NotInitialized("Tor manager unavailable for P2P".to_string()))
}

/// Publish onion service
async fn create_onion_endpoint() -> QorResult<OnionEndpoint> {
    let tor = tor_manager()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| QorError::Network(format!("Failed to bind P2P listener: {}", e)))?;
    let local_port = listener
        .local_addr()
        .map_err(|e| QorError::Network(format!("Failed to read P2P listener port: {}", e)))?
        .port();
    let audio_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| QorError::Network(format!("Failed to bind P2P audio listener: {}", e)))?;
    let audio_local_port = audio_listener
        .local_addr()
        .map_err(|e| QorError::Network(format!("Failed to read P2P audio listener port: {}", e)))?
        .port();
    let onion_service = tor
        .publish_onion_service(&[
            (ONION_VIRTUAL_PORT, local_port),
            (ONION_AUDIO_VIRTUAL_PORT, audio_local_port),
        ])
        .await?;
    info!("[P2P] onion service published for inbound peer connections");
    Ok(OnionEndpoint {
        onion_service,
        listener,
        audio_listener,
    })
}

fn tor_socks_port() -> u16 {
    tor_manager().map(|tor| tor.get_socks_port()).unwrap_or(0)
}

fn spawn_onion_endpoint_publisher(
    command_tx: mpsc::UnboundedSender<WorkerCommand>,
    identity_generation: u64,
) {
    tokio::spawn(async move {
        let mut retry_secs = ONION_PUBLISH_RETRY_SECS;
        loop {
            let ready = match tor_manager() {
                Ok(tor) => tor.is_ready().await,
                Err(_) => false,
            };
            if ready {
                match create_onion_endpoint().await {
                    Ok(endpoint) => {
                        let _ = command_tx.send(WorkerCommand::EndpointPublished {
                            identity_generation,
                            endpoint: Arc::new(endpoint),
                        });
                        return;
                    }
                    Err(_) => warn!("[P2P] onion service publish failed; retrying"),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
            if command_tx.is_closed() {
                return;
            }

            retry_secs = (retry_secs * 2).min(ONION_PUBLISH_RETRY_MAX_SECS);
        }
    });
}

enum IncomingConnection {
    Regular(PeerConnection),
    AudioLane([u8; AUDIO_LANE_TOKEN_BYTES], PeerConnection),
}

static INBOUND_CONNECTION_SEQ: AtomicU64 = AtomicU64::new(0);

impl OnionEndpoint {
    fn onion_host(&self) -> &str {
        self.onion_service.onion_host()
    }

    async fn accept(&self) -> Option<IncomingConnection> {
        tokio::select! {
            accepted = self.listener.accept() => {
                let (stream, _peer) = accepted.ok()?;
                let _ = stream.set_nodelay(true);
                let sequence = INBOUND_CONNECTION_SEQ.fetch_add(1, Ordering::Relaxed);
                Some(IncomingConnection::Regular(PeerConnection::new(
                    format!("inbound:{}", sequence),
                    stream,
                )))
            }
            accepted = self.audio_listener.accept() => {
                let (mut stream, _peer) = accepted.ok()?;
                let _ = stream.set_nodelay(true);
                let preamble_len = AUDIO_LANE_PREAMBLE_PREFIX.len() + AUDIO_LANE_TOKEN_BYTES;
                let mut preamble = vec![0u8; preamble_len];
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    stream.read_exact(&mut preamble),
                ).await.ok()?.ok()?;
                if !preamble.starts_with(AUDIO_LANE_PREAMBLE_PREFIX) {
                    return None;
                }
                let mut token = [0u8; AUDIO_LANE_TOKEN_BYTES];
                token.copy_from_slice(&preamble[AUDIO_LANE_PREAMBLE_PREFIX.len()..]);
                let sequence = INBOUND_CONNECTION_SEQ.fetch_add(1, Ordering::Relaxed);
                Some(IncomingConnection::AudioLane(
                    token,
                    PeerConnection::new(format!("audio-inbound:{}", sequence), stream),
                ))
            }
        }
    }
}

impl PeerConnection {
    fn new(peer_key: String, stream: TcpStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        let (close_tx, _close_rx) = watch::channel(false);
        Self {
            peer_key,
            write: Mutex::new(write),
            read: Mutex::new(read),
            closed: AtomicBool::new(false),
            close_tx,
        }
    }

    fn peer_key(&self) -> &str {
        &self.peer_key
    }

    fn close(&self, _code: u32, _reason: &[u8]) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.close_tx.send_replace(true);
    }

    fn close_reason(&self) -> Option<()> {
        self.closed.load(Ordering::Acquire).then_some(())
    }

    async fn send_frame(&self, data: &[u8]) -> Result<(), String> {
        let len = u32::try_from(data.len()).map_err(|_| "frame length overflow".to_string())?;
        let mut write = self.write.lock().await;
        write
            .write_all(&len.to_le_bytes())
            .await
            .map_err(|e| format!("write len: {}", e))?;
        write
            .write_all(data)
            .await
            .map_err(|e| format!("write data: {}", e))?;
        write.flush().await.map_err(|e| format!("flush: {}", e))?;
        Ok(())
    }

    async fn send_preamble(&self, data: &[u8]) -> Result<(), String> {
        let mut write = self.write.lock().await;
        write
            .write_all(data)
            .await
            .map_err(|error| format!("write preamble: {}", error))?;
        write
            .flush()
            .await
            .map_err(|error| format!("flush preamble: {}", error))
    }

    async fn recv_frame<F>(&self, frame_policy: F) -> Result<(Vec<u8>, bool), FrameReadError>
    where
        F: FnOnce() -> (usize, bool),
    {
        self.recv_frame_with_body_timeout(frame_policy, frame_body_timeout)
            .await
    }

    async fn recv_frame_with_body_timeout<F, T>(
        &self,
        frame_policy: F,
        body_timeout_policy: T,
    ) -> Result<(Vec<u8>, bool), FrameReadError>
    where
        F: FnOnce() -> (usize, bool),
        T: FnOnce(usize) -> std::time::Duration,
    {
        let mut close_rx = self.close_tx.subscribe();
        if self.closed.load(Ordering::Acquire) || *close_rx.borrow() {
            return Err(FrameReadError::Closed);
        }

        let mut read = self.read.lock().await;
        let mut len_buf = [0u8; 4];

        let header_result = tokio::select! {
            result = read.read_exact(&mut len_buf) => result,
            _ = close_rx.changed() => return Err(FrameReadError::Closed),
        };
        if let Err(error) = header_result {
            return Err(FrameReadError::Invalid(format!("read len: {}", error)));
        }
        let len = u32::from_le_bytes(len_buf) as usize;

        let (max_frame_bytes, authenticated_at_header) = frame_policy();
        if len == 0 {
            return Err(FrameReadError::Invalid("Empty frame".to_string()));
        }
        if len > max_frame_bytes {
            warn!("[P2P] Oversized inbound frame rejected");
            return Err(FrameReadError::Invalid("Frame too large".to_string()));
        }
        let body_timeout = body_timeout_policy(len);
        if !try_reserve_inbound_bytes(len) {
            let drain_result = tokio::select! {
                result = tokio::time::timeout(body_timeout, async {
                    let mut remaining = len;
                    let mut scratch = [0u8; 8192];
                    while remaining > 0 {
                        let take = remaining.min(scratch.len());
                        read.read_exact(&mut scratch[..take]).await?;
                        remaining -= take;
                    }
                    Ok::<(), std::io::Error>(())
                }) => result,
                _ = close_rx.changed() => return Err(FrameReadError::Closed),
            };
            return match drain_result {
                Ok(Ok(())) => Err(FrameReadError::InboundPressure),
                Ok(Err(error)) => Err(FrameReadError::Invalid(format!("read data: {}", error))),
                Err(_) => Err(FrameReadError::Invalid("read data timeout".to_string())),
            };
        }
        let mut buf = vec![0u8; len];
        let body_result = tokio::select! {
            result = tokio::time::timeout(body_timeout, read.read_exact(&mut buf)) => result,
            _ = close_rx.changed() => {
                release_inbound_bytes(len);
                return Err(FrameReadError::Closed);
            }
        };
        match body_result {
            Ok(Ok(_)) => Ok((buf, authenticated_at_header)),
            Ok(Err(e)) => {
                release_inbound_bytes(len);
                Err(FrameReadError::Invalid(format!("read data: {}", e)))
            }
            Err(_) => {
                release_inbound_bytes(len);
                Err(FrameReadError::Invalid("read data timeout".to_string()))
            }
        }
    }
}

async fn dial_onion_peer(
    socks_port: u16,
    onion_host: &str,
    virtual_port: u16,
) -> Result<TcpStream, String> {
    if !is_valid_onion_host(onion_host) {
        return Err("invalid onion host".to_string());
    }
    let proxy = format!("127.0.0.1:{}", socks_port);
    let target = (onion_host.to_string(), virtual_port);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(ONION_DIAL_TIMEOUT_SECS),
        tokio_socks::tcp::Socks5Stream::connect_with_password(
            proxy.as_str(),
            target,
            &format!("p2p-{}", uuid::Uuid::new_v4().simple()),
            "isolate",
        ),
    )
    .await
    .map_err(|_| "onion dial timeout".to_string())?
    .map_err(|e| format!("onion dial failed: {}", e))?;
    Ok(stream.into_inner())
}

async fn connect_onion_peer(socks_port: u16, onion_host: &str) -> Result<PeerConnection, String> {
    let stream = dial_onion_peer(socks_port, onion_host, ONION_VIRTUAL_PORT).await?;
    let _ = stream.set_nodelay(true);
    Ok(PeerConnection::new(onion_host.to_string(), stream))
}

async fn connect_onion_audio_peer(
    socks_port: u16,
    onion_host: &str,
) -> Result<PeerConnection, String> {
    let stream = dial_onion_peer(socks_port, onion_host, ONION_AUDIO_VIRTUAL_PORT).await?;
    let _ = stream.set_nodelay(true);
    Ok(PeerConnection::new(onion_host.to_string(), stream))
}

use crate::error::{QorError, QorResult};

const REQUEST_TIMEOUT_SECS: u64 = ONION_DIAL_TIMEOUT_SECS + 15;
const _: () = assert!(
    REQUEST_TIMEOUT_SECS > ONION_DIAL_TIMEOUT_SECS,
    "dial command deadline must outlast the dial it waits on"
);
const SEND_TIMEOUT_SECS: u64 = 10;
const FRAME_BODY_BASE_TIMEOUT_SECS: u64 = 15;
const FRAME_BODY_MIN_BYTES_PER_SECOND: usize = 4 * 1024;
const FRAME_BODY_MAX_TIMEOUT_SECS: u64 = 120;

fn frame_body_timeout(frame_bytes: usize) -> std::time::Duration {
    let transfer_seconds = frame_bytes
        .div_ceil(FRAME_BODY_MIN_BYTES_PER_SECOND)
        .try_into()
        .unwrap_or(u64::MAX);
    std::time::Duration::from_secs(
        FRAME_BODY_BASE_TIMEOUT_SECS
            .saturating_add(transfer_seconds)
            .min(FRAME_BODY_MAX_TIMEOUT_SECS),
    )
}
const ENDPOINT_CLOSE_TIMEOUT_SECS: u64 = 5;
const AUTHENTICATION_TIMEOUT_SECS: u64 = 120;
const COMMAND_RESPONSE_GRACE_SECS: u64 = 2;
const ROTATE_RESPONSE_TIMEOUT_SECS: u64 = 30;
const MAX_PROTOCOL_ERRORS: u8 = 3;
const MAX_CONCURRENT_DIALS: usize = 16;
const MAX_PENDING_INCOMING_HANDSHAKES: usize = 32;
const MAX_UNAUTHENTICATED_CONNECTIONS: usize = 16;
const PER_CONNECTION_SEND_QUEUE: usize = 64;
const PER_CONNECTION_REALTIME_SEND_QUEUE: usize = 5;
const MAX_PREAUTH_FRAMES_PER_CONNECTION: usize = 12;
const MAX_PREAUTH_BYTES_PER_CONNECTION: usize = 256 * 1024;
const MAX_PREAUTH_FRAME_BYTES: usize = 24 * 1024;
const ML_KEM_1024_BYTES: usize = 1568;
const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;
const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;
const X25519_PUBLIC_KEY_BYTES: usize = 32;

fn inbound_frame_limit(authenticated: bool) -> usize {
    if authenticated {
        MAX_FRAME_BYTES
    } else {
        MAX_PREAUTH_FRAME_BYTES
    }
}

static INBOUND_BUFFERED_BYTES: AtomicUsize = AtomicUsize::new(0);
static INBOUND_BUFFERED_FRAMES: AtomicUsize = AtomicUsize::new(0);
const MAX_INBOUND_BUFFERED_BYTES: usize = 16 * 1024 * 1024;
const MAX_INBOUND_BUFFERED_FRAMES: usize = 1024;
pub const P2P_EVENT_CHANNEL_CAPACITY: usize = MAX_INBOUND_BUFFERED_FRAMES + (MAX_P2P_ALIASES * 2);
const INBOUND_PRESSURE_RETRY_MS: u64 = 25;

pub fn release_inbound_bytes(n: usize) {
    if n == 0 {
        return;
    }
    let _ = INBOUND_BUFFERED_FRAMES.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
    let _ = INBOUND_BUFFERED_BYTES.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(n))
    });
}

fn try_reserve_inbound_bytes(n: usize) -> bool {
    if INBOUND_BUFFERED_FRAMES
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            (current < MAX_INBOUND_BUFFERED_FRAMES).then_some(current + 1)
        })
        .is_err()
    {
        return false;
    }
    let mut current = INBOUND_BUFFERED_BYTES.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(n) else {
            let _ = INBOUND_BUFFERED_FRAMES.fetch_sub(1, Ordering::AcqRel);
            return false;
        };
        if next > MAX_INBOUND_BUFFERED_BYTES {
            let _ = INBOUND_BUFFERED_FRAMES.fetch_sub(1, Ordering::AcqRel);
            return false;
        }

        match INBOUND_BUFFERED_BYTES.compare_exchange_weak(
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

const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_AUTHENTICATED_PAYLOAD_BYTES: usize = 3 * ((MAX_FRAME_BYTES - 2) / 4);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreauthenticationWireShape {
    version: String,
    #[serde(rename = "type")]
    kind: String,
    from: String,
    to: String,
    #[serde(rename = "sessionId")]
    session_id: String,
    timestamp: Option<u64>,
    #[serde(rename = "ephemeralKyberPublic")]
    ephemeral_kyber_public: Option<String>,
    #[serde(rename = "kemCiphertext")]
    kem_ciphertext: Option<String>,
    #[serde(rename = "ephemeralX25519Public")]
    ephemeral_x25519_public: Option<String>,
    signature: Option<String>,
    #[serde(rename = "signerPublicKey")]
    signer_public_key: Option<String>,
    frame: Option<String>,
}

impl PreauthenticationWireShape {
    fn has_exact_variant_shape(&self) -> bool {
        if self.version.is_empty()
            || self.from.is_empty()
            || self.to.is_empty()
            || self.session_id.is_empty()
        {
            return false;
        }
        match self.kind.as_str() {
            "init" => {
                self.timestamp.is_some()
                    && self.ephemeral_kyber_public.is_some()
                    && self.kem_ciphertext.is_some()
                    && self.ephemeral_x25519_public.is_some()
                    && self.signature.is_some()
                    && self.signer_public_key.is_some()
                    && self.frame.is_none()
            }
            "response" => {
                self.timestamp.is_some()
                    && self.ephemeral_kyber_public.is_none()
                    && self.kem_ciphertext.is_some()
                    && self.ephemeral_x25519_public.is_some()
                    && self.signature.is_some()
                    && self.signer_public_key.is_some()
                    && self.frame.is_none()
            }
            "confirm" => {
                self.timestamp.is_none()
                    && self.ephemeral_kyber_public.is_none()
                    && self.kem_ciphertext.is_none()
                    && self.ephemeral_x25519_public.is_none()
                    && self.signature.is_none()
                    && self.signer_public_key.is_none()
                    && self.frame.is_some()
            }
            _ => false,
        }
    }
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn is_canonical_base64_payload(value: &str) -> bool {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return false;
    }
    let bytes = value.as_bytes();
    let padding = if bytes.ends_with(b"==") {
        2
    } else if bytes.ends_with(b"=") {
        1
    } else {
        0
    };
    if bytes[..bytes.len() - padding]
        .iter()
        .any(|byte| base64_value(*byte).is_none())
        || bytes[..bytes.len() - padding].contains(&b'=')
    {
        return false;
    }
    let decoded_len = (bytes.len() / 4)
        .checked_mul(3)
        .and_then(|length| length.checked_sub(padding));
    if decoded_len.is_none_or(|length| length == 0 || length > MAX_AUTHENTICATED_PAYLOAD_BYTES) {
        return false;
    }
    match padding {
        0 => true,
        1 => base64_value(bytes[bytes.len() - 2]).is_some_and(|value| value & 0b11 == 0),
        2 => base64_value(bytes[bytes.len() - 3]).is_some_and(|value| value & 0b1111 == 0),
        _ => false,
    }
}

fn parse_authenticated_frame(buf: &[u8]) -> Option<Vec<u8>> {
    if buf == br#"{"type":"__keepalive"}"# {
        return Some(buf.to_vec());
    }
    is_valid_authenticated_frame(buf).then(|| buf.to_vec())
}

fn is_valid_authenticated_frame(buf: &[u8]) -> bool {
    if buf == br#"{"type":"__keepalive"}"# {
        return true;
    }
    if buf.len() < 2 {
        return false;
    }
    let id_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if id_len == 0 || id_len > 96 || 2 + id_len >= buf.len() {
        return false;
    }
    let Some(stream_id) = std::str::from_utf8(&buf[2..2 + id_len]).ok() else {
        return false;
    };
    let Some((stream_type, suffix)) = stream_id.split_once(':') else {
        return false;
    };
    matches!(
        stream_type,
        "message" | "call-audio" | "call-video" | "call-telemetry" | "call-screen"
    ) && (16..=64).contains(&suffix.len())
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_realtime_audio_frame(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let id_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    id_len > 0
        && 2 + id_len <= buf.len()
        && std::str::from_utf8(&buf[2..2 + id_len])
            .is_ok_and(|stream_id| stream_id.starts_with("call-audio:"))
}

fn is_realtime_visual_frame(buf: &[u8]) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let id_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    id_len > 0
        && 2 + id_len <= buf.len()
        && std::str::from_utf8(&buf[2..2 + id_len]).is_ok_and(|stream_id| {
            stream_id.starts_with("call-video:") || stream_id.starts_with("call-screen:")
        })
}

fn parse_audio_lane_offer(buf: &[u8]) -> Option<[u8; AUDIO_LANE_TOKEN_BYTES]> {
    if buf.len() != AUDIO_LANE_OFFER_PREFIX.len() + AUDIO_LANE_TOKEN_BYTES
        || !buf.starts_with(AUDIO_LANE_OFFER_PREFIX)
    {
        return None;
    }
    let mut token = [0u8; AUDIO_LANE_TOKEN_BYTES];
    token.copy_from_slice(&buf[AUDIO_LANE_OFFER_PREFIX.len()..]);
    Some(token)
}

fn is_allowed_preauth_frame(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let string_field = |key: &str| object.get(key).and_then(|entry| entry.as_str());

    let Some(kind) = string_field("type") else {
        return false;
    };

    const COMMON: [&str; 5] = ["version", "type", "from", "to", "sessionId"];
    let expected: &[&str] = match kind {
        "init" => &[
            "version",
            "type",
            "from",
            "to",
            "sessionId",
            "timestamp",
            "ephemeralKyberPublic",
            "kemCiphertext",
            "ephemeralX25519Public",
            "signature",
            "signerPublicKey",
        ],
        "response" => &[
            "version",
            "type",
            "from",
            "to",
            "sessionId",
            "timestamp",
            "kemCiphertext",
            "ephemeralX25519Public",
            "signature",
            "signerPublicKey",
        ],
        "confirm" => &["version", "type", "from", "to", "sessionId", "frame"],
        _ => return false,
    };
    if object.len() != expected.len() || !object.keys().all(|key| expected.contains(&key.as_str()))
    {
        return false;
    }
    debug_assert!(COMMON.iter().all(|key| expected.contains(key)));

    if string_field("version") != Some(crate::protocol_keys::NOISE_PROTOCOL_VERSION) {
        return false;
    }

    for key in ["from", "to"] {
        match string_field(key) {
            Some(identity) if validate_handshake_identity(identity).is_ok() => {}
            _ => return false,
        }
    }

    match string_field("sessionId") {
        Some(session_id)
            if session_id.len() == 32
                && session_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
        _ => return false,
    }

    if expected.contains(&"timestamp") && !object.get("timestamp").is_some_and(|t| t.is_u64()) {
        return false;
    }

    let exact_base64 = |key: &str, bytes: usize| -> bool {
        string_field(key).is_some_and(|payload| {
            is_canonical_base64_payload(payload)
                && base64::engine::general_purpose::STANDARD
                    .decode(payload)
                    .is_ok_and(|decoded| decoded.len() == bytes)
        })
    };

    match kind {
        "init" => {
            exact_base64("ephemeralKyberPublic", ML_KEM_1024_BYTES)
                && exact_base64("kemCiphertext", ML_KEM_1024_BYTES)
                && exact_base64("ephemeralX25519Public", X25519_PUBLIC_KEY_BYTES)
                && exact_base64("signature", ML_DSA_87_SIGNATURE_BYTES)
                && exact_base64("signerPublicKey", ML_DSA_87_PUBLIC_KEY_BYTES)
        }
        "response" => {
            exact_base64("kemCiphertext", ML_KEM_1024_BYTES)
                && exact_base64("ephemeralX25519Public", X25519_PUBLIC_KEY_BYTES)
                && exact_base64("signature", ML_DSA_87_SIGNATURE_BYTES)
                && exact_base64("signerPublicKey", ML_DSA_87_PUBLIC_KEY_BYTES)
        }
        "confirm" => string_field("frame").is_some_and(|frame| {
            is_canonical_base64_payload(frame) && frame.len() <= MAX_PREAUTH_FRAME_BYTES
        }),
        _ => false,
    }
}

fn parse_preauthentication_frame(buf: &[u8]) -> Option<Vec<u8>> {
    let shape = serde_json::from_slice::<PreauthenticationWireShape>(buf).ok()?;
    if !shape.has_exact_variant_shape() {
        return None;
    }
    let value = serde_json::from_slice::<serde_json::Value>(buf).ok()?;
    is_allowed_preauth_frame(&value).then(|| buf.to_vec())
}

static OUTBOUND_QUEUED_BYTES: AtomicUsize = AtomicUsize::new(0);
static OUTBOUND_QUEUED_FRAMES: AtomicUsize = AtomicUsize::new(0);
const MAX_OUTBOUND_QUEUED_BYTES: usize = 16 * 1024 * 1024;
const MAX_OUTBOUND_QUEUED_FRAMES: usize = 1024;
static PENDING_CONTROL_COMMANDS: AtomicUsize = AtomicUsize::new(0);
const MAX_PENDING_CONTROL_COMMANDS: usize = 1024;

fn release_outbound_bytes(n: usize) {
    let _ = OUTBOUND_QUEUED_FRAMES.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
    let _ = OUTBOUND_QUEUED_BYTES.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(n))
    });
}

struct OutboundReservation {
    bytes: usize,
}

impl Drop for OutboundReservation {
    fn drop(&mut self) {
        release_outbound_bytes(self.bytes);
    }
}

fn try_reserve_outbound_bytes(n: usize) -> Option<OutboundReservation> {
    if OUTBOUND_QUEUED_FRAMES
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            (current < MAX_OUTBOUND_QUEUED_FRAMES).then_some(current + 1)
        })
        .is_err()
    {
        return None;
    }
    let mut current = OUTBOUND_QUEUED_BYTES.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(n) else {
            let _ = OUTBOUND_QUEUED_FRAMES.fetch_sub(1, Ordering::AcqRel);
            return None;
        };
        if next > MAX_OUTBOUND_QUEUED_BYTES {
            let _ = OUTBOUND_QUEUED_FRAMES.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        match OUTBOUND_QUEUED_BYTES.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(OutboundReservation { bytes: n }),
            Err(observed) => current = observed,
        }
    }
}

struct ControlReservation;

impl Drop for ControlReservation {
    fn drop(&mut self) {
        let _ =
            PENDING_CONTROL_COMMANDS.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
    }
}

fn try_reserve_control_command() -> Option<ControlReservation> {
    PENDING_CONTROL_COMMANDS
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            (current < MAX_PENDING_CONTROL_COMMANDS).then_some(current + 1)
        })
        .ok()
        .map(|_| ControlReservation)
}

static PENDING_INCOMING_HANDSHAKES: AtomicUsize = AtomicUsize::new(0);

struct IncomingHandshakeReservation;

impl Drop for IncomingHandshakeReservation {
    fn drop(&mut self) {
        let _ = PENDING_INCOMING_HANDSHAKES.fetch_update(
            Ordering::AcqRel,
            Ordering::Relaxed,
            |current| Some(current.saturating_sub(1)),
        );
    }
}

fn try_reserve_incoming_handshake() -> Option<IncomingHandshakeReservation> {
    PENDING_INCOMING_HANDSHAKES
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            (current < MAX_PENDING_INCOMING_HANDSHAKES).then_some(current + 1)
        })
        .ok()
        .map(|_| IncomingHandshakeReservation)
}

fn spawn_onion_endpoint_acceptor(
    endpoint: Arc<OnionEndpoint>,
    command_tx: mpsc::UnboundedSender<WorkerCommand>,
    identity_generation: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                if command_tx.is_closed() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                continue;
            };
            match incoming {
                IncomingConnection::Regular(connection) => {
                    let Some(permit) = try_reserve_incoming_handshake() else {
                        connection.close(1013u32, b"handshake capacity");
                        continue;
                    };
                    if command_tx
                        .send(WorkerCommand::IncomingEstablished {
                            identity_generation,
                            result: Ok(connection),
                            _permit: permit,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                IncomingConnection::AudioLane(token, connection) => {
                    if command_tx
                        .send(WorkerCommand::IncomingAudioLane {
                            identity_generation,
                            token,
                            connection,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    })
}

fn validate_handshake_identity(identity: &str) -> QorResult<()> {
    let len = identity.len();
    if !(3..=100).contains(&len)
        || !identity.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(QorError::Network(
            "Invalid P2P handshake identity".to_string(),
        ));
    }
    Ok(())
}

fn validate_connection_id(connection_id: &str) -> QorResult<()> {
    let synthetic_inbound = connection_id
        .strip_prefix("inbound:")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 20
                && suffix.bytes().all(|byte| byte.is_ascii_digit())
                && (suffix == "0" || !suffix.starts_with('0'))
                && suffix.parse::<u64>().is_ok()
        });
    if synthetic_inbound {
        return Ok(());
    }

    let len = connection_id.len();
    if !(3..=100).contains(&len)
        || !connection_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(QorError::Network(
            "Invalid P2P connection identifier".to_string(),
        ));
    }
    Ok(())
}

const MAX_P2P_CONNECTIONS: usize = 64;
const MAX_P2P_ALIASES: usize = MAX_P2P_CONNECTIONS * 4;

fn build_private_endpoint_url(onion_host: &str) -> String {
    format!("onion://{}", onion_host)
}

fn parse_private_endpoint_url(endpoint_url: &str) -> QorResult<String> {
    let trimmed = endpoint_url.trim();
    if trimmed != endpoint_url || trimmed.is_empty() || trimmed.len() > 512 {
        return Err(QorError::Network("Invalid endpoint length".to_string()));
    }
    let host = trimmed
        .strip_prefix("onion://")
        .ok_or_else(|| QorError::Network("Endpoint must use onion://".to_string()))?
        .to_ascii_lowercase();
    if !is_valid_onion_host(&host) {
        return Err(QorError::Network("Invalid onion endpoint".to_string()));
    }
    Ok(host)
}

/// P2P connection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PConnectResult {
    pub success: bool,
    pub already_connected: Option<bool>,
    #[serde(rename = "connectionToken")]
    pub connection_token: Option<u64>,
    pub error: Option<String>,
}

/// P2P send result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PSendResult {
    pub success: bool,
    pub error: Option<String>,
    #[serde(rename = "audioLanes", skip_serializing_if = "Option::is_none")]
    pub audio_lanes: Option<AudioLaneTelemetry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioLaneTelemetry {
    pub ready: usize,
    pub target: usize,
    pub active: usize,
    #[serde(rename = "endpointAvailable")]
    pub endpoint_available: bool,
    pub dialing: usize,
    pub attempts: u64,
    pub failures: u64,
    #[serde(rename = "retryInMs")]
    pub retry_in_ms: Option<u64>,
    #[serde(rename = "lastFailure")]
    pub last_failure: Option<String>,
    #[serde(rename = "selectedLane")]
    pub selected_lane: Option<String>,
    #[serde(rename = "visualLane")]
    pub visual_lane: Option<String>,
    pub lanes: Vec<AudioLaneTelemetryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioLaneTelemetryEntry {
    pub id: String,
    #[serde(rename = "rttMs")]
    pub rtt_ms: Option<u64>,
    #[serde(rename = "degradedSamples")]
    pub degraded_samples: u8,
    pub role: String,
}

/// P2P transport event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum P2PEvent {
    #[serde(rename = "__p2p_connected")]
    Connected {
        #[serde(rename = "connectionId")]
        connection_id: String,
        #[serde(rename = "connectionToken")]
        connection_token: u64,
    },
    #[serde(rename = "__p2p_closed")]
    Closed {
        #[serde(rename = "connectionId")]
        connection_id: String,
        #[serde(rename = "connectionToken")]
        connection_token: u64,
        code: u16,
        reason: Option<String>,
    },
    #[serde(rename = "message")]
    Message {
        #[serde(rename = "connectionId")]
        connection_id: String,
        #[serde(rename = "connectionToken")]
        connection_token: u64,
        data: Vec<u8>,
        #[serde(skip)]
        byte_len: usize,
    },
}

impl P2PEvent {
    pub fn reserved_byte_len(&self) -> usize {
        match self {
            Self::Message { byte_len, .. } => *byte_len,
            _ => 0,
        }
    }

    pub fn into_bridge_bytes(self) -> Option<Vec<u8>> {
        let (kind, connection_id, connection_token, payload) = match self {
            Self::Connected {
                connection_id,
                connection_token,
            } => (1u8, connection_id, connection_token, Vec::new()),
            Self::Closed {
                connection_id,
                connection_token,
                code,
                reason,
            } => {
                let reason = reason.unwrap_or_default();
                let reason_bytes = reason.as_bytes();
                let reason_len = u16::try_from(reason_bytes.len()).ok()?;
                let mut payload = Vec::with_capacity(4 + reason_bytes.len());
                payload.extend_from_slice(&code.to_be_bytes());
                payload.extend_from_slice(&reason_len.to_be_bytes());
                payload.extend_from_slice(reason_bytes);
                (2u8, connection_id, connection_token, payload)
            }
            Self::Message {
                connection_id,
                connection_token,
                data,
                ..
            } => (3u8, connection_id, connection_token, data),
        };
        let id = connection_id.as_bytes();
        let id_len = u16::try_from(id.len()).ok()?;
        let mut output = Vec::with_capacity(15 + id.len() + payload.len());
        output.extend_from_slice(b"QPB1");
        output.push(kind);
        output.extend_from_slice(&connection_token.to_be_bytes());
        output.extend_from_slice(&id_len.to_be_bytes());
        output.extend_from_slice(id);
        output.extend_from_slice(&payload);
        Some(output)
    }
}

// Worker
enum WorkerCommand {
    Shutdown,
    Dial {
        connection_id: String,
        peer_key: String,
        onion_host: String,
        deadline: tokio::time::Instant,
        resp: oneshot::Sender<P2PConnectResult>,
        _permit: ControlReservation,
    },
    DialCompleted {
        connection_id: String,
        peer_key: String,
        dial_token: u64,
        identity_generation: u64,
        deadline: tokio::time::Instant,
        result: Result<PeerConnection, String>,
        resp: oneshot::Sender<P2PConnectResult>,
        _permit: ControlReservation,
    },
    Send {
        connection_id: String,
        connection_token: u64,
        data: Vec<u8>,
        audio_onion_host: Option<String>,
        audio_lane_rtt_ceiling_ms: Option<u64>,
        deadline: tokio::time::Instant,
        resp: oneshot::Sender<P2PSendResult>,
        _permit: OutboundReservation,
    },
    Disconnect {
        connection_id: String,
        connection_token: Option<u64>,
        resp: oneshot::Sender<bool>,
        _permit: ControlReservation,
    },
    RotateIdentity {
        resp: oneshot::Sender<Result<String, String>>,
        _permit: ControlReservation,
    },

    EndpointPublished {
        identity_generation: u64,
        endpoint: Arc<OnionEndpoint>,
    },
    Authenticate {
        connection_id: String,
        connection_token: u64,
        resp: oneshot::Sender<bool>,
        _permit: ControlReservation,
    },
    IncomingEstablished {
        identity_generation: u64,
        result: Result<PeerConnection, String>,
        _permit: IncomingHandshakeReservation,
    },
    IncomingAudioLane {
        identity_generation: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
        connection: PeerConnection,
    },
    AudioLaneOffer {
        identity_generation: u64,
        connection_id: String,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
    },
    AudioLaneDialCompleted {
        identity_generation: u64,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
        result: Result<PeerConnection, String>,
    },
    AudioLaneRtt {
        identity_generation: u64,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
        rtt_ms: u64,
    },
    AudioLaneFailed {
        identity_generation: u64,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
    },
    InboundAudioLaneClosed {
        identity_generation: u64,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
    },
    ExpirePendingAudioLane {
        identity_generation: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
    },
    AuthenticationExpired {
        connection_id: String,
        connection_token: u64,
        identity_generation: u64,
    },

    ConnectionLost {
        connection_id: String,
        connection_token: u64,
        reason: &'static str,
    },
}

struct QueuedSend {
    data: Vec<u8>,
    deadline: tokio::time::Instant,
    audio_lanes: Option<AudioLaneTelemetry>,
    resp: oneshot::Sender<P2PSendResult>,
    _permit: OutboundReservation,
}

struct SendQueues {
    normal: mpsc::Sender<QueuedSend>,
    realtime: mpsc::Sender<QueuedSend>,
}

#[derive(Clone)]
struct OutboundAudioLane {
    token: [u8; AUDIO_LANE_TOKEN_BYTES],
    connection: Arc<PeerConnection>,
    rtt_ms: Option<u64>,
    degraded_samples: u8,
}

impl OutboundAudioLane {
    fn score(&self) -> u64 {
        self.rtt_ms.unwrap_or(1_500)
    }
}

fn audio_lane_rtt_is_eligible(rtt_ms: Option<u64>, ceiling_ms: u64) -> bool {
    rtt_ms.is_some_and(|rtt| rtt <= ceiling_ms)
}

fn audio_lane_has_meaningful_gain(current_rtt_ms: u64, challenger_rtt_ms: u64) -> bool {
    let gain = current_rtt_ms.saturating_sub(challenger_rtt_ms);
    let percentage_gain = current_rtt_ms
        .saturating_mul(AUDIO_LANE_SWITCH_MIN_GAIN_PERCENT)
        .saturating_add(99)
        / 100;
    gain >= AUDIO_LANE_SWITCH_MIN_GAIN_MS.max(percentage_gain)
}

#[derive(Default)]
struct AudioLaneSelection {
    selected: Option<[u8; AUDIO_LANE_TOKEN_BYTES]>,
    challenger: Option<[u8; AUDIO_LANE_TOKEN_BYTES]>,
    challenger_samples: u8,
}

impl AudioLaneSelection {
    fn select(&mut self, token: [u8; AUDIO_LANE_TOKEN_BYTES]) {
        self.selected = Some(token);
        self.challenger = None;
        self.challenger_samples = 0;
    }

    fn remove(&mut self, token: [u8; AUDIO_LANE_TOKEN_BYTES]) {
        if self.selected == Some(token) {
            self.selected = None;
        }
        if self.challenger == Some(token) {
            self.challenger = None;
            self.challenger_samples = 0;
        }
    }

    fn observe(
        &mut self,
        ranked: &[([u8; AUDIO_LANE_TOKEN_BYTES], u64)],
        updated_token: [u8; AUDIO_LANE_TOKEN_BYTES],
    ) {
        let Some(&(best_token, best_rtt_ms)) = ranked.first() else {
            self.selected = None;
            self.challenger = None;
            self.challenger_samples = 0;
            return;
        };
        let Some(selected_token) = self.selected else {
            self.select(best_token);
            return;
        };
        let Some((_, selected_rtt_ms)) = ranked
            .iter()
            .find(|(token, _)| *token == selected_token)
            .copied()
        else {
            self.select(best_token);
            return;
        };
        if best_token == selected_token {
            self.challenger = None;
            self.challenger_samples = 0;
            return;
        }
        if !audio_lane_has_meaningful_gain(selected_rtt_ms, best_rtt_ms) {
            self.challenger = None;
            self.challenger_samples = 0;
            return;
        }
        if self.challenger.is_some_and(|token| token != best_token) {
            self.challenger = None;
            self.challenger_samples = 0;
        }
        if updated_token != best_token {
            return;
        }
        if self.challenger == Some(best_token) {
            self.challenger_samples = self.challenger_samples.saturating_add(1);
        } else {
            self.challenger = Some(best_token);
            self.challenger_samples = 1;
        }
        if self.challenger_samples >= AUDIO_LANE_SWITCH_CONFIRMATIONS {
            self.select(best_token);
        }
    }
}

struct InboundAudioLane {
    token: [u8; AUDIO_LANE_TOKEN_BYTES],
    connection: Arc<PeerConnection>,
}

#[derive(Default)]
struct AudioLaneSetupStatus {
    attempts: u64,
    failures: u64,
    last_failure: Option<&'static str>,
    consecutive_failed_batches: u8,
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
        data: Vec<u8>,
        byte_len: usize,
    },
}

#[derive(Debug)]
enum FrameReadError {
    Invalid(String),
    InboundPressure,
    Closed,
}

struct IrohWorker {
    endpoint: Option<Arc<OnionEndpoint>>,
    endpoint_accept_task: Option<tokio::task::JoinHandle<()>>,
    local_node_id: Arc<RwLock<Option<String>>>,
    connections: HashMap<String, Arc<PeerConnection>>,
    alias_to_node: HashMap<String, String>,
    node_to_aliases: HashMap<String, HashSet<String>>,
    connection_tokens: HashMap<String, u64>,
    send_queues: HashMap<u64, SendQueues>,
    authenticated_connections: Arc<RwLock<HashSet<u64>>>,
    authentication_timeout_tasks: HashMap<u64, tokio::task::JoinHandle<()>>,
    outbound_audio_lanes: HashMap<u64, Vec<OutboundAudioLane>>,
    inbound_audio_lanes: HashMap<u64, Vec<InboundAudioLane>>,
    audio_receive_windows: HashMap<u64, Arc<parking_lot::Mutex<AudioReceiveWindow>>>,
    pending_audio_offers: HashMap<[u8; AUDIO_LANE_TOKEN_BYTES], (u64, String, u64)>,
    pending_audio_connections: HashMap<[u8; AUDIO_LANE_TOKEN_BYTES], PeerConnection>,
    audio_lane_dials: HashMap<u64, HashSet<[u8; AUDIO_LANE_TOKEN_BYTES]>>,
    audio_lane_next_dial_at: HashMap<u64, tokio::time::Instant>,
    audio_lane_onion_hosts: HashMap<u64, String>,
    audio_lane_setup_status: HashMap<u64, AudioLaneSetupStatus>,
    audio_lane_frame_ids: HashMap<u64, u64>,
    audio_lane_selections: HashMap<u64, AudioLaneSelection>,
    visual_lane_selections: HashMap<u64, [u8; AUDIO_LANE_TOKEN_BYTES]>,
    pending_dials: HashMap<String, u64>,
    next_connection_token: u64,
    next_dial_token: u64,
    identity_generation: Arc<AtomicU64>,
    self_command_tx: mpsc::UnboundedSender<WorkerCommand>,
}

impl IrohWorker {
    async fn new(
        self_command_tx: mpsc::UnboundedSender<WorkerCommand>,
        local_node_id: Arc<RwLock<Option<String>>>,
    ) -> QorResult<Self> {
        let identity_generation = Arc::new(AtomicU64::new(1));
        spawn_onion_endpoint_publisher(self_command_tx.clone(), 1);

        Ok(Self {
            endpoint: None,
            endpoint_accept_task: None,
            local_node_id,
            connections: HashMap::new(),
            alias_to_node: HashMap::new(),
            node_to_aliases: HashMap::new(),
            connection_tokens: HashMap::new(),
            send_queues: HashMap::new(),
            authenticated_connections: Arc::new(RwLock::new(HashSet::new())),
            authentication_timeout_tasks: HashMap::new(),
            outbound_audio_lanes: HashMap::new(),
            inbound_audio_lanes: HashMap::new(),
            audio_receive_windows: HashMap::new(),
            pending_audio_offers: HashMap::new(),
            pending_audio_connections: HashMap::new(),
            audio_lane_dials: HashMap::new(),
            audio_lane_next_dial_at: HashMap::new(),
            audio_lane_onion_hosts: HashMap::new(),
            audio_lane_setup_status: HashMap::new(),
            audio_lane_frame_ids: HashMap::new(),
            audio_lane_selections: HashMap::new(),
            visual_lane_selections: HashMap::new(),
            pending_dials: HashMap::new(),
            next_connection_token: 1,
            next_dial_token: 1,
            identity_generation,
            self_command_tx,
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

    fn bind_alias(&mut self, alias: String, node_id: String) -> bool {
        if !self.alias_to_node.contains_key(&alias) && self.alias_to_node.len() >= MAX_P2P_ALIASES {
            return false;
        }
        let inserted_node = node_id.clone();
        if let Some(previous_node) = self.alias_to_node.insert(alias.clone(), node_id)
            && previous_node != inserted_node
            && let Some(set) = self.node_to_aliases.get_mut(&previous_node)
        {
            set.remove(&alias);
            if set.is_empty() {
                self.node_to_aliases.remove(&previous_node);
            }
        }
        self.node_to_aliases
            .entry(inserted_node)
            .or_default()
            .insert(alias);
        true
    }

    fn unbind_alias(&mut self, alias: &str) -> Option<String> {
        let node = self.alias_to_node.remove(alias)?;
        if let Some(set) = self.node_to_aliases.get_mut(&node) {
            set.remove(alias);
            if set.is_empty() {
                self.node_to_aliases.remove(&node);
            }
        }
        Some(node)
    }

    fn issue_dial_token(&mut self) -> u64 {
        let token = self.next_dial_token;
        self.next_dial_token = self.next_dial_token.wrapping_add(1);
        if self.next_dial_token == 0 {
            self.next_dial_token = 1;
        }
        token
    }

    fn active_connection_count(&self) -> usize {
        self.connection_tokens
            .values()
            .copied()
            .collect::<HashSet<_>>()
            .len()
    }

    fn unauthenticated_connection_count(&self) -> usize {
        let authenticated = self.authenticated_connections.read();
        self.connection_tokens
            .values()
            .copied()
            .filter(|token| !authenticated.contains(token))
            .collect::<HashSet<_>>()
            .len()
    }

    fn resolve_connection_key(&self, connection_id: &str) -> Option<String> {
        if self.connections.contains_key(connection_id) {
            return Some(connection_id.to_string());
        }

        if let Some(node_id) = self.alias_to_node.get(connection_id) {
            let node_key = node_id.to_string();
            if self.connections.contains_key(&node_key) {
                return Some(node_key);
            }
        }

        let node_id = connection_id.to_string();
        self.node_to_aliases.get(&node_id).and_then(|aliases| {
            aliases
                .iter()
                .find(|alias| self.connections.contains_key((*alias).as_str()))
                .cloned()
        })
    }

    fn clear_audio_lanes_for_token(&mut self, connection_token: u64, reason: &[u8]) {
        if let Some(lanes) = self.outbound_audio_lanes.remove(&connection_token) {
            for lane in lanes {
                lane.connection.close(0u32, reason);
            }
        }
        if let Some(lanes) = self.inbound_audio_lanes.remove(&connection_token) {
            for lane in lanes {
                lane.connection.close(0u32, reason);
            }
        }
        self.audio_receive_windows.remove(&connection_token);
        self.audio_lane_dials.remove(&connection_token);
        self.audio_lane_next_dial_at.remove(&connection_token);
        self.audio_lane_onion_hosts.remove(&connection_token);
        self.audio_lane_setup_status.remove(&connection_token);
        self.audio_lane_frame_ids.remove(&connection_token);
        self.audio_lane_selections.remove(&connection_token);
        self.visual_lane_selections.remove(&connection_token);
    }

    async fn close_connection_token(
        &mut self,
        connection_token: u64,
        event_tx: &mpsc::Sender<WorkerEvent>,
        code: u16,
        reason: &str,
    ) -> bool {
        let connection_ids: Vec<String> = self
            .connection_tokens
            .iter()
            .filter_map(|(id, token)| (*token == connection_token).then_some(id.clone()))
            .collect();
        if connection_ids.is_empty() {
            self.send_queues.remove(&connection_token);
            self.clear_audio_lanes_for_token(connection_token, b"primary connection closed");
            self.authenticated_connections
                .write()
                .remove(&connection_token);
            if let Some(task) = self.authentication_timeout_tasks.remove(&connection_token) {
                task.abort();
            }
            return false;
        }

        for connection_id in &connection_ids {
            if let Some(connection) = self.connections.remove(connection_id) {
                connection.close(0u32.into(), b"connection closed");
            }
            self.connection_tokens.remove(connection_id);
            self.unbind_alias(connection_id);
        }
        self.send_queues.remove(&connection_token);
        self.clear_audio_lanes_for_token(connection_token, b"primary connection closed");
        self.pending_audio_offers
            .retain(|_, (token, _, _)| *token != connection_token);
        self.authenticated_connections
            .write()
            .remove(&connection_token);
        if let Some(task) = self.authentication_timeout_tasks.remove(&connection_token) {
            task.abort();
        }

        for connection_id in connection_ids {
            let _ = event_tx.try_send(WorkerEvent::Closed {
                connection_id,
                connection_token,
                code,
                reason: Some(reason.to_string()),
            });
        }
        true
    }

    async fn activate_connection(
        &mut self,
        connection_id: String,
        node_id: String,
        connection: PeerConnection,
        event_tx: &mpsc::Sender<WorkerEvent>,
    ) -> Option<u64> {
        if let Some(previous_token) = self.connection_tokens.get(&connection_id).copied() {
            self.close_connection_token(previous_token, event_tx, 1000, "Connection replaced")
                .await;
        }

        if !self.bind_alias(connection_id.clone(), node_id.clone()) {
            connection.close(1013u32, b"alias limit");
            return None;
        }
        let connection_token = self.issue_connection_token(&connection_id);
        if is_valid_onion_host(&node_id) {
            self.audio_lane_onion_hosts
                .insert(connection_token, node_id.clone());
        }
        let connection = Arc::new(connection);
        self.connections
            .insert(connection_id.clone(), connection.clone());

        let (normal_send_tx, normal_send_rx) = mpsc::channel(PER_CONNECTION_SEND_QUEUE);
        let (realtime_send_tx, realtime_send_rx) =
            mpsc::channel(PER_CONNECTION_REALTIME_SEND_QUEUE);
        self.send_queues.insert(
            connection_token,
            SendQueues {
                normal: normal_send_tx,
                realtime: realtime_send_tx,
            },
        );

        if event_tx
            .try_send(WorkerEvent::Connected {
                connection_id: connection_id.clone(),
                connection_token,
            })
            .is_err()
        {
            self.connections.remove(&connection_id);
            self.connection_tokens.remove(&connection_id);
            self.send_queues.remove(&connection_token);
            self.unbind_alias(&connection_id);
            connection.close(1013u32.into(), b"event queue full");
            return None;
        }

        let identity_generation = self.identity_generation.load(Ordering::Acquire);
        let read_event_tx = event_tx.clone();
        let read_command_tx = self.self_command_tx.clone();
        let read_connection = Arc::clone(&connection);
        let read_connection_id = connection_id.clone();
        let generation_guard = self.identity_generation.clone();
        let authenticated_connections = self.authenticated_connections.clone();
        let connection_lost_notified = Arc::new(AtomicBool::new(false));
        let read_connection_lost_notified = connection_lost_notified.clone();
        tokio::spawn(async move {
            Self::read_loop(
                read_connection,
                read_connection_id,
                connection_token,
                identity_generation,
                generation_guard,
                authenticated_connections,
                read_event_tx,
                read_command_tx,
                read_connection_lost_notified,
            )
            .await;
        });

        let write_command_tx = self.self_command_tx.clone();
        let write_connection_id = connection_id.clone();
        let write_generation_guard = self.identity_generation.clone();
        let write_connection_lost_notified = connection_lost_notified;
        tokio::spawn(async move {
            Self::write_loop(
                connection,
                write_connection_id,
                connection_token,
                identity_generation,
                write_generation_guard,
                normal_send_rx,
                realtime_send_rx,
                write_command_tx,
                write_connection_lost_notified,
            )
            .await;
        });

        let auth_command_tx = self.self_command_tx.clone();
        let authentication_timeout_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(AUTHENTICATION_TIMEOUT_SECS)).await;
            let _ = auth_command_tx.send(WorkerCommand::AuthenticationExpired {
                connection_id,
                connection_token,
                identity_generation,
            });
        });
        self.authentication_timeout_tasks
            .insert(connection_token, authentication_timeout_task);

        Some(connection_token)
    }

    async fn run(
        mut self,
        mut command_rx: mpsc::UnboundedReceiver<WorkerCommand>,
        event_tx: mpsc::Sender<WorkerEvent>,
    ) {
        while let Some(command) = command_rx.recv().await {
            match command {
                WorkerCommand::Shutdown => {
                    self.shutdown().await;
                    break;
                }
                command => self.handle_command(command, &event_tx).await,
            }
        }
    }

    async fn shutdown(&mut self) {
        self.identity_generation.fetch_add(1, Ordering::AcqRel);
        *self.local_node_id.write() = None;

        if let Some(task) = self.endpoint_accept_task.take() {
            task.abort();
        }
        self.endpoint.take();
        self.pending_dials.clear();
        for connection in self.connections.values() {
            connection.close(0u32.into(), b"transport shutdown");
        }
        self.connections.clear();
        for lanes in self.outbound_audio_lanes.values() {
            for lane in lanes {
                lane.connection.close(0u32, b"transport shutdown");
            }
        }
        for lanes in self.inbound_audio_lanes.values() {
            for lane in lanes {
                lane.connection.close(0u32, b"transport shutdown");
            }
        }
        for connection in self.pending_audio_connections.values() {
            connection.close(0u32, b"transport shutdown");
        }
        self.outbound_audio_lanes.clear();
        self.inbound_audio_lanes.clear();
        self.pending_audio_connections.clear();
        self.pending_audio_offers.clear();
        self.audio_lane_dials.clear();
        self.audio_receive_windows.clear();
        self.audio_lane_next_dial_at.clear();
        self.audio_lane_onion_hosts.clear();
        self.audio_lane_setup_status.clear();
        self.audio_lane_frame_ids.clear();
        self.audio_lane_selections.clear();
        self.visual_lane_selections.clear();
        self.connection_tokens.clear();
        self.send_queues.clear();
        self.authenticated_connections.write().clear();
        for (_, task) in self.authentication_timeout_tasks.drain() {
            task.abort();
        }
        self.alias_to_node.clear();
        self.node_to_aliases.clear();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(ENDPOINT_CLOSE_TIMEOUT_SECS),
            async {},
        )
        .await;
    }

    async fn handle_incoming_connection(
        &mut self,
        conn: PeerConnection,
        event_tx: &mpsc::Sender<WorkerEvent>,
    ) {
        let node_id = conn.peer_key().to_string();
        let remote = node_id.clone();

        let alias = if let Some(existing_aliases) = self.node_to_aliases.get(&node_id) {
            existing_aliases
                .iter()
                .find(|candidate| candidate.as_str() != remote.as_str())
                .cloned()
                .or_else(|| existing_aliases.iter().next().cloned())
                .unwrap_or_else(|| remote.clone())
        } else {
            remote.clone()
        };

        if !self.connections.contains_key(&alias)
            && self.active_connection_count() >= MAX_P2P_CONNECTIONS
        {
            warn!("[P2P] Connection cap reached, refusing inbound peer");
            conn.close(1013u32.into(), b"peer limit");
            return;
        }
        if !self.connections.contains_key(&alias)
            && self.unauthenticated_connection_count() >= MAX_UNAUTHENTICATED_CONNECTIONS
        {
            warn!("[P2P] Unauthenticated connection cap reached, refusing inbound peer");
            conn.close(1013u32.into(), b"authentication capacity");
            return;
        }

        let _ = self
            .activate_connection(alias, node_id, conn, event_tx)
            .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_loop(
        conn: Arc<PeerConnection>,
        connection_id: String,
        connection_token: u64,
        identity_generation: u64,
        generation_guard: Arc<AtomicU64>,
        authenticated_connections: Arc<RwLock<HashSet<u64>>>,
        event_tx: mpsc::Sender<WorkerEvent>,
        command_tx: mpsc::UnboundedSender<WorkerCommand>,
        connection_lost_notified: Arc<AtomicBool>,
    ) {
        let mut protocol_errors = 0u8;
        let mut inbound_pressure_warned = false;
        let mut preauth_frames = 0usize;
        let mut preauth_bytes = 0usize;
        loop {
            if generation_guard.load(Ordering::Acquire) != identity_generation {
                break;
            }

            match conn
                .recv_frame(|| {
                    let authenticated =
                        authenticated_connections.read().contains(&connection_token);
                    (inbound_frame_limit(authenticated), authenticated)
                })
                .await
            {
                Ok((buf, authenticated_at_frame_start)) => {
                    if authenticated_at_frame_start
                        && let Some(token) = parse_audio_lane_offer(&buf)
                    {
                        release_inbound_bytes(buf.len());
                        let _ = command_tx.send(WorkerCommand::AudioLaneOffer {
                            identity_generation,
                            connection_id: connection_id.clone(),
                            connection_token,
                            token,
                        });
                        continue;
                    }
                    match if authenticated_at_frame_start {
                        parse_authenticated_frame(&buf)
                    } else {
                        parse_preauthentication_frame(&buf)
                    } {
                        Some(data) => {
                            let authenticated_now =
                                authenticated_connections.read().contains(&connection_token);
                            if authenticated_now != authenticated_at_frame_start {
                                release_inbound_bytes(buf.len());
                                continue;
                            }
                            if !authenticated_now {
                                preauth_frames = preauth_frames.saturating_add(1);
                                preauth_bytes = preauth_bytes.saturating_add(buf.len());
                                if buf.len() > MAX_PREAUTH_FRAME_BYTES
                                    || preauth_frames > MAX_PREAUTH_FRAMES_PER_CONNECTION
                                    || preauth_bytes > MAX_PREAUTH_BYTES_PER_CONNECTION
                                {
                                    release_inbound_bytes(buf.len());
                                    warn!(
                                        "[P2P-RECV] Closing peer after invalid pre-authentication traffic"
                                    );
                                    break;
                                }
                            }
                            protocol_errors = 0;
                            let byte_len = buf.len();
                            if event_tx
                                .send(WorkerEvent::Message {
                                    connection_id: connection_id.clone(),
                                    connection_token,
                                    data,
                                    byte_len,
                                })
                                .await
                                .is_err()
                            {
                                release_inbound_bytes(byte_len);
                                break;
                            }
                        }
                        None => {
                            release_inbound_bytes(buf.len());
                            protocol_errors = protocol_errors.saturating_add(1);
                            if protocol_errors >= MAX_PROTOCOL_ERRORS {
                                break;
                            }
                        }
                    }
                }

                Err(FrameReadError::InboundPressure) => {
                    if !inbound_pressure_warned {
                        warn!("[P2P-RECV] Dropping frames while the inbound bridge is full");
                        inbound_pressure_warned = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(INBOUND_PRESSURE_RETRY_MS))
                        .await;
                }
                Err(FrameReadError::Closed) => break,
                Err(FrameReadError::Invalid(error)) => {
                    protocol_errors = protocol_errors.saturating_add(1);
                    if error.contains("timeout")
                        || error == "Frame too large"
                        || protocol_errors >= MAX_PROTOCOL_ERRORS
                    {
                        warn!("[P2P-RECV] Closing peer after invalid or stalled frame");
                        break;
                    }
                }
            }
        }

        conn.close(0u32.into(), b"read loop ended");
        if !connection_lost_notified.swap(true, Ordering::AcqRel) {
            let _ = command_tx.send(WorkerCommand::ConnectionLost {
                connection_id,
                connection_token,
                reason: "Connection closed",
            });
        }
    }

    fn fail_queued_send(frame: QueuedSend, error: &str) {
        let _ = frame.resp.send(P2PSendResult {
            success: false,
            error: Some(error.to_string()),
            audio_lanes: frame.audio_lanes,
        });
    }

    fn schedule_audio_lane_retry(&mut self, connection_token: u64, failed_batch: bool) {
        let status = self
            .audio_lane_setup_status
            .entry(connection_token)
            .or_default();
        if failed_batch {
            status.consecutive_failed_batches = status.consecutive_failed_batches.saturating_add(1);
        } else {
            status.consecutive_failed_batches = 0;
        }
        let exponent = status.consecutive_failed_batches.saturating_sub(1).min(4);
        let delay_secs = if failed_batch {
            AUDIO_LANE_RETRY_BASE_SECS
                .saturating_mul(1u64 << exponent)
                .min(AUDIO_LANE_RETRY_MAX_SECS)
        } else {
            AUDIO_LANE_RETRY_BASE_SECS
        };
        self.audio_lane_next_dial_at.insert(
            connection_token,
            tokio::time::Instant::now() + std::time::Duration::from_secs(delay_secs),
        );
    }

    fn ensure_audio_lanes(&mut self, connection_token: u64) {
        if !self
            .authenticated_connections
            .read()
            .contains(&connection_token)
        {
            return;
        }
        let Some(onion_host) = self.audio_lane_onion_hosts.get(&connection_token).cloned() else {
            return;
        };
        if self
            .audio_lane_next_dial_at
            .get(&connection_token)
            .is_some_and(|next| tokio::time::Instant::now() < *next)
        {
            return;
        }
        let ready = self
            .outbound_audio_lanes
            .get(&connection_token)
            .map_or(0, Vec::len);
        let dialing = self
            .audio_lane_dials
            .get(&connection_token)
            .map_or(0, HashSet::len);
        if dialing > 0 {
            return;
        }
        let missing = AUDIO_LANE_TARGET_COUNT.saturating_sub(ready);
        if missing == 0 {
            return;
        }
        let Some(primary) = self.connection_tokens.iter().find_map(|(id, token)| {
            (*token == connection_token)
                .then(|| self.connections.get(id).cloned())
                .flatten()
        }) else {
            return;
        };
        let identity_generation = self.identity_generation.load(Ordering::Acquire);
        let status = self
            .audio_lane_setup_status
            .entry(connection_token)
            .or_default();
        status.attempts = status.attempts.saturating_add(missing as u64);
        for _ in 0..missing {
            let token: [u8; AUDIO_LANE_TOKEN_BYTES] = loop {
                let candidate = rand::random();
                let in_use = self
                    .audio_lane_dials
                    .get(&connection_token)
                    .is_some_and(|tokens| tokens.contains(&candidate))
                    || self
                        .outbound_audio_lanes
                        .get(&connection_token)
                        .is_some_and(|lanes| lanes.iter().any(|lane| lane.token == candidate));
                if !in_use {
                    break candidate;
                }
            };
            self.audio_lane_dials
                .entry(connection_token)
                .or_default()
                .insert(token);
            let command_tx = self.self_command_tx.clone();
            let primary = primary.clone();
            let onion_host = onion_host.clone();
            tokio::spawn(async move {
                let result = async {
                    let connection = connect_onion_audio_peer(tor_socks_port(), &onion_host)
                        .await
                        .map_err(|error| {
                            if error.contains("timeout") {
                                "dial-timeout".to_string()
                            } else {
                                "dial-failed".to_string()
                            }
                        })?;
                    let mut preamble = Vec::with_capacity(
                        AUDIO_LANE_PREAMBLE_PREFIX.len() + AUDIO_LANE_TOKEN_BYTES,
                    );
                    preamble.extend_from_slice(AUDIO_LANE_PREAMBLE_PREFIX);
                    preamble.extend_from_slice(&token);
                    connection
                        .send_preamble(&preamble)
                        .await
                        .map_err(|_| "preamble-send".to_string())?;
                    let mut offer =
                        Vec::with_capacity(AUDIO_LANE_OFFER_PREFIX.len() + AUDIO_LANE_TOKEN_BYTES);
                    offer.extend_from_slice(AUDIO_LANE_OFFER_PREFIX);
                    offer.extend_from_slice(&token);
                    primary
                        .send_frame(&offer)
                        .await
                        .map_err(|_| "offer-send".to_string())?;
                    let ready = tokio::time::timeout(
                        std::time::Duration::from_secs(AUDIO_LANE_BIND_TIMEOUT_SECS),
                        connection.recv_frame(|| (AUDIO_LANE_FRAME_HEADER_BYTES, true)),
                    )
                    .await
                    .map_err(|_| "binding-timeout".to_string())?;
                    let (frame, _) = match ready {
                        Ok(frame) => frame,
                        Err(FrameReadError::Closed) => {
                            return Err("binding-closed".to_string());
                        }
                        Err(FrameReadError::InboundPressure) => {
                            return Err("binding-pressure".to_string());
                        }
                        Err(FrameReadError::Invalid(_)) => {
                            return Err("binding-read-invalid".to_string());
                        }
                    };
                    let frame_len = frame.len();
                    let valid =
                        matches!(parse_audio_lane_frame(&frame), Some(AudioLaneFrame::Ready));
                    release_inbound_bytes(frame_len);
                    if !valid {
                        return Err("binding-frame-invalid".to_string());
                    }
                    Ok(connection)
                }
                .await;
                let _ = command_tx.send(WorkerCommand::AudioLaneDialCompleted {
                    identity_generation,
                    connection_token,
                    token,
                    result,
                });
            });
        }
    }

    fn spawn_outbound_audio_lane_tasks(
        &self,
        identity_generation: u64,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
        connection: Arc<PeerConnection>,
    ) {
        let pending_probes = Arc::new(Mutex::new(HashMap::<u64, tokio::time::Instant>::new()));
        let missed_probes = Arc::new(AtomicUsize::new(0));
        let monitor_connection = connection.clone();
        let monitor_pending = pending_probes.clone();
        let monitor_missed = missed_probes.clone();
        let monitor_tx = self.self_command_tx.clone();
        tokio::spawn(async move {
            loop {
                let received = monitor_connection
                    .recv_frame(|| (AUDIO_LANE_FRAME_HEADER_BYTES, true))
                    .await;
                let Ok((frame, _)) = received else {
                    break;
                };
                let frame_len = frame.len();
                let Some(AudioLaneFrame::Pong(probe_id)) = parse_audio_lane_frame(&frame) else {
                    release_inbound_bytes(frame_len);
                    break;
                };
                let started = monitor_pending.lock().await.remove(&probe_id);
                release_inbound_bytes(frame_len);
                if let Some(started) = started {
                    monitor_missed.store(0, Ordering::Release);
                    let rtt_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let _ = monitor_tx.send(WorkerCommand::AudioLaneRtt {
                        identity_generation,
                        connection_token,
                        token,
                        rtt_ms,
                    });
                }
            }
            let _ = monitor_tx.send(WorkerCommand::AudioLaneFailed {
                identity_generation,
                connection_token,
                token,
            });
        });

        let probe_connection = connection;
        let probe_tx = self.self_command_tx.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                AUDIO_LANE_PROBE_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = tokio::time::Instant::now();
                let expired = {
                    let mut pending = pending_probes.lock().await;
                    let before = pending.len();
                    pending.retain(|_, started| {
                        now.duration_since(*started)
                            < std::time::Duration::from_secs(AUDIO_LANE_PROBE_TIMEOUT_SECS)
                    });
                    before.saturating_sub(pending.len())
                };
                if expired > 0 && missed_probes.fetch_add(expired, Ordering::AcqRel) + expired >= 3
                {
                    break;
                }
                let probe_id = loop {
                    let candidate: u64 = rand::random();
                    if candidate != 0 {
                        break candidate;
                    }
                };
                pending_probes.lock().await.insert(probe_id, now);
                let ping = encode_audio_lane_frame(AUDIO_LANE_FRAME_PING, probe_id, &[]);
                let sent = tokio::time::timeout(
                    std::time::Duration::from_secs(AUDIO_LANE_PROBE_INTERVAL_SECS),
                    probe_connection.send_frame(&ping),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                if !sent {
                    break;
                }
            }
            probe_connection.close(0u32, b"audio lane probe failed");
            let _ = probe_tx.send(WorkerCommand::AudioLaneFailed {
                identity_generation,
                connection_token,
                token,
            });
        });
    }

    fn lane_id(token: &[u8; AUDIO_LANE_TOKEN_BYTES]) -> String {
        token[..4]
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    fn ranked_audio_lanes(&self, connection_token: u64) -> Vec<OutboundAudioLane> {
        let mut lanes = self
            .outbound_audio_lanes
            .get(&connection_token)
            .cloned()
            .unwrap_or_default();
        lanes.sort_by_key(OutboundAudioLane::score);
        lanes
    }

    fn audio_lane_candidates(
        &mut self,
        connection_token: u64,
        ceiling_ms: u64,
    ) -> Vec<OutboundAudioLane> {
        let mut lanes: Vec<OutboundAudioLane> = self
            .ranked_audio_lanes(connection_token)
            .into_iter()
            .filter(|lane| audio_lane_rtt_is_eligible(lane.rtt_ms, ceiling_ms))
            .filter(|lane| {
                self.visual_lane_selections
                    .get(&connection_token)
                    .is_none_or(|visual| lane.token != *visual)
            })
            .collect();
        if lanes.is_empty() {
            return lanes;
        }
        let selection = self
            .audio_lane_selections
            .entry(connection_token)
            .or_default();
        let selected_index = selection
            .selected
            .and_then(|token| lanes.iter().position(|lane| lane.token == token))
            .unwrap_or_else(|| {
                selection.select(lanes[0].token);
                0
            });
        if selected_index > 0 {
            let selected = lanes.remove(selected_index);
            lanes.insert(0, selected);
        }
        lanes
    }

    fn visual_lane_candidate(&mut self, connection_token: u64) -> Option<OutboundAudioLane> {
        let audio_lane = self
            .audio_lane_selections
            .get(&connection_token)
            .and_then(|selection| selection.selected);
        let lanes = self.ranked_audio_lanes(connection_token);
        let existing = self.visual_lane_selections.get(&connection_token).copied();
        let selected = existing
            .and_then(|token| {
                lanes
                    .iter()
                    .find(|lane| lane.token == token && Some(token) != audio_lane)
            })
            .or_else(|| lanes.iter().find(|lane| Some(lane.token) != audio_lane))
            .cloned()?;
        self.visual_lane_selections
            .insert(connection_token, selected.token);
        Some(selected)
    }

    fn audio_lane_telemetry(
        &self,
        connection_token: u64,
        selected: Option<[u8; AUDIO_LANE_TOKEN_BYTES]>,
    ) -> AudioLaneTelemetry {
        let lanes = self.ranked_audio_lanes(connection_token);
        let secondary = lanes
            .iter()
            .find(|lane| Some(lane.token) != selected)
            .map(|lane| lane.token);
        let entries = lanes
            .iter()
            .map(|lane| AudioLaneTelemetryEntry {
                id: Self::lane_id(&lane.token),
                rtt_ms: lane.rtt_ms,
                degraded_samples: lane.degraded_samples,
                role: if Some(lane.token) == selected {
                    "active"
                } else if Some(lane.token) == secondary {
                    "secondary"
                } else {
                    "standby"
                }
                .to_string(),
            })
            .collect();
        let status = self.audio_lane_setup_status.get(&connection_token);
        let now = tokio::time::Instant::now();
        let retry_in_ms = self
            .audio_lane_next_dial_at
            .get(&connection_token)
            .and_then(|retry_at| retry_at.checked_duration_since(now))
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX));
        AudioLaneTelemetry {
            ready: lanes.len(),
            target: AUDIO_LANE_TARGET_COUNT,
            active: usize::from(
                selected.is_some_and(|token| lanes.iter().any(|lane| lane.token == token)),
            ),
            endpoint_available: self.audio_lane_onion_hosts.contains_key(&connection_token),
            dialing: self
                .audio_lane_dials
                .get(&connection_token)
                .map_or(0, HashSet::len),
            attempts: status.map_or(0, |value| value.attempts),
            failures: status.map_or(0, |value| value.failures),
            retry_in_ms,
            last_failure: status.and_then(|value| value.last_failure.map(str::to_string)),
            selected_lane: selected.map(|token| Self::lane_id(&token)),
            visual_lane: self
                .visual_lane_selections
                .get(&connection_token)
                .map(Self::lane_id),
            lanes: entries,
        }
    }

    fn remove_outbound_audio_lane(
        &mut self,
        connection_token: u64,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
        reason: &[u8],
    ) -> bool {
        let Some(lanes) = self.outbound_audio_lanes.get_mut(&connection_token) else {
            return false;
        };
        let Some(index) = lanes.iter().position(|lane| lane.token == token) else {
            return false;
        };
        let lane = lanes.remove(index);
        lane.connection.close(0u32, reason);
        if lanes.is_empty() {
            self.outbound_audio_lanes.remove(&connection_token);
        }
        if let Some(selection) = self.audio_lane_selections.get_mut(&connection_token) {
            selection.remove(token);
        }
        if self.visual_lane_selections.get(&connection_token) == Some(&token) {
            self.visual_lane_selections.remove(&connection_token);
        }
        true
    }

    fn attach_inbound_audio_lane(
        &mut self,
        connection_token: u64,
        connection_id: String,
        token: [u8; AUDIO_LANE_TOKEN_BYTES],
        connection: PeerConnection,
        event_tx: &mpsc::Sender<WorkerEvent>,
    ) {
        if self.connection_tokens.get(&connection_id).copied() != Some(connection_token)
            || !self
                .authenticated_connections
                .read()
                .contains(&connection_token)
        {
            connection.close(1008u32, b"invalid audio lane binding");
            return;
        }
        let lanes = self
            .inbound_audio_lanes
            .entry(connection_token)
            .or_default();
        if lanes.iter().any(|lane| lane.token == token) || lanes.len() >= AUDIO_LANE_TARGET_COUNT {
            connection.close(1008u32, b"audio lane capacity");
            return;
        }
        let connection = Arc::new(connection);
        lanes.push(InboundAudioLane {
            token,
            connection: connection.clone(),
        });
        let receive_window = self
            .audio_receive_windows
            .entry(connection_token)
            .or_insert_with(|| Arc::new(parking_lot::Mutex::new(AudioReceiveWindow::default())))
            .clone();
        let identity_generation = self.identity_generation.load(Ordering::Acquire);
        let generation_guard = self.identity_generation.clone();
        let authenticated_connections = self.authenticated_connections.clone();
        let event_tx = event_tx.clone();
        let command_tx = self.self_command_tx.clone();
        tokio::spawn(async move {
            let ready = encode_audio_lane_frame(AUDIO_LANE_FRAME_READY, 1, &[]);
            if connection.send_frame(&ready).await.is_err() {
                connection.close(0u32, b"audio lane binding failed");
                let _ = command_tx.send(WorkerCommand::InboundAudioLaneClosed {
                    identity_generation,
                    connection_token,
                    token,
                });
                return;
            }
            loop {
                if generation_guard.load(Ordering::Acquire) != identity_generation
                    || !authenticated_connections.read().contains(&connection_token)
                {
                    break;
                }
                match connection
                    .recv_frame(|| (MAX_FRAME_BYTES + AUDIO_LANE_FRAME_HEADER_BYTES, true))
                    .await
                {
                    Ok((frame, true)) => {
                        let byte_len = frame.len();
                        match parse_audio_lane_frame(&frame) {
                            Some(AudioLaneFrame::Data { frame_id, data })
                                if is_realtime_audio_frame(data)
                                    || is_realtime_visual_frame(data) =>
                            {
                                if !receive_window.lock().accept(frame_id) {
                                    release_inbound_bytes(byte_len);
                                    continue;
                                }
                                let data = data.to_vec();
                                if event_tx
                                    .send(WorkerEvent::Message {
                                        connection_id: connection_id.clone(),
                                        connection_token,
                                        data,
                                        byte_len,
                                    })
                                    .await
                                    .is_err()
                                {
                                    release_inbound_bytes(byte_len);
                                    break;
                                }
                            }
                            Some(AudioLaneFrame::Ping(probe_id)) => {
                                let pong =
                                    encode_audio_lane_frame(AUDIO_LANE_FRAME_PONG, probe_id, &[]);
                                release_inbound_bytes(byte_len);
                                if connection.send_frame(&pong).await.is_err() {
                                    break;
                                }
                            }
                            _ => {
                                release_inbound_bytes(byte_len);
                                break;
                            }
                        }
                    }
                    Ok((frame, _)) => {
                        release_inbound_bytes(frame.len());
                        break;
                    }
                    Err(_) => break,
                }
            }
            connection.close(0u32, b"audio lane closed");
            let _ = command_tx.send(WorkerCommand::InboundAudioLaneClosed {
                identity_generation,
                connection_token,
                token,
            });
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_loop(
        conn: Arc<PeerConnection>,
        connection_id: String,
        connection_token: u64,
        identity_generation: u64,
        generation_guard: Arc<AtomicU64>,
        mut normal_send_rx: mpsc::Receiver<QueuedSend>,
        mut realtime_send_rx: mpsc::Receiver<QueuedSend>,
        command_tx: mpsc::UnboundedSender<WorkerCommand>,
        connection_lost_notified: Arc<AtomicBool>,
    ) {
        loop {
            let frame = tokio::select! {
                biased;
                frame = realtime_send_rx.recv() => frame,
                frame = normal_send_rx.recv() => frame,
            };
            let Some(frame) = frame else { break };
            if generation_guard.load(Ordering::Acquire) != identity_generation {
                Self::fail_queued_send(frame, "P2P identity changed");
                break;
            }
            if conn.close_reason().is_some() {
                Self::fail_queued_send(frame, "P2P connection closed");
                break;
            }
            if tokio::time::Instant::now() >= frame.deadline {
                Self::fail_queued_send(frame, "P2P send expired in queue");
                continue;
            }

            let QueuedSend {
                data,
                deadline,
                audio_lanes,
                resp,
                _permit,
            } = frame;

            let send_result =
                tokio::time::timeout_at(deadline, async { conn.send_frame(&data).await }).await;

            let generation_is_current =
                generation_guard.load(Ordering::Acquire) == identity_generation;
            match send_result {
                Ok(Ok(())) if generation_is_current => {
                    let _ = resp.send(P2PSendResult {
                        success: true,
                        error: None,
                        audio_lanes,
                    });
                }
                Ok(Ok(())) => {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("P2P identity changed".to_string()),
                        audio_lanes,
                    });
                    break;
                }
                Ok(Err(_)) => {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("P2P send failed".to_string()),
                        audio_lanes,
                    });
                    break;
                }
                Err(_) => {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("P2P send timed out".to_string()),
                        audio_lanes,
                    });
                    break;
                }
            }
        }

        conn.close(0u32.into(), b"writer stopped");
        normal_send_rx.close();
        realtime_send_rx.close();
        while let Ok(frame) = realtime_send_rx.try_recv() {
            Self::fail_queued_send(frame, "P2P connection closed");
        }
        while let Ok(frame) = normal_send_rx.try_recv() {
            Self::fail_queued_send(frame, "P2P connection closed");
        }
        if !connection_lost_notified.swap(true, Ordering::AcqRel) {
            let _ = command_tx.send(WorkerCommand::ConnectionLost {
                connection_id,
                connection_token,
                reason: "Connection closed",
            });
        }
    }

    async fn handle_command(&mut self, cmd: WorkerCommand, event_tx: &mpsc::Sender<WorkerEvent>) {
        match cmd {
            WorkerCommand::Shutdown => {}
            WorkerCommand::Dial {
                connection_id,
                peer_key,
                onion_host,
                deadline,
                resp,
                _permit,
            } => {
                let previous_node = self.alias_to_node.get(&connection_id).cloned();
                if let Some(existing_conn) = self.connections.get(&connection_id).cloned() {
                    if previous_node.as_deref() == Some(peer_key.as_str())
                        && existing_conn.close_reason().is_none()
                        && let Some(connection_token) = self
                            .connection_tokens
                            .get(&connection_id)
                            .copied()
                            .filter(|token| self.send_queues.contains_key(token))
                    {
                        let _ = resp.send(P2PConnectResult {
                            success: true,
                            already_connected: Some(true),
                            connection_token: Some(connection_token),
                            error: None,
                        });
                        return;
                    }
                    if let Some(token) = self.connection_tokens.get(&connection_id).copied() {
                        self.close_connection_token(token, event_tx, 1000, "Endpoint changed")
                            .await;
                    }
                }

                let node_key = peer_key.clone();
                if let Some(existing_conn) = self.connections.get(&node_key).cloned() {
                    let existing_token = self.connection_tokens.get(&node_key).copied();
                    if existing_conn.close_reason().is_none()
                        && existing_token
                            .and_then(|token| self.send_queues.get(&token))
                            .is_some()
                    {
                        let connection_token = existing_token.unwrap_or_default();
                        if !self.bind_alias(connection_id.clone(), peer_key.clone()) {
                            let _ = resp.send(P2PConnectResult {
                                success: false,
                                already_connected: None,
                                connection_token: None,
                                error: Some("P2P alias limit reached".to_string()),
                            });
                            return;
                        }
                        if event_tx
                            .try_send(WorkerEvent::Connected {
                                connection_id: connection_id.clone(),
                                connection_token,
                            })
                            .is_err()
                        {
                            self.unbind_alias(&connection_id);
                            let _ = resp.send(P2PConnectResult {
                                success: false,
                                already_connected: None,
                                connection_token: None,
                                error: Some("P2P event queue full".to_string()),
                            });
                            return;
                        }
                        self.connection_tokens
                            .insert(connection_id.clone(), connection_token);
                        self.connections
                            .insert(connection_id.clone(), existing_conn);
                        let _ = resp.send(P2PConnectResult {
                            success: true,
                            already_connected: Some(true),
                            connection_token: Some(connection_token),
                            error: None,
                        });
                        return;
                    }
                    if let Some(token) = existing_token {
                        self.close_connection_token(token, event_tx, 1006, "Connection stale")
                            .await;
                    }
                }

                if tokio::time::Instant::now() >= deadline {
                    let _ = resp.send(P2PConnectResult {
                        success: false,
                        already_connected: None,
                        connection_token: None,
                        error: Some("P2P connection request expired".to_string()),
                    });
                    return;
                }
                if self.pending_dials.contains_key(&connection_id) {
                    let _ = resp.send(P2PConnectResult {
                        success: false,
                        already_connected: None,
                        connection_token: None,
                        error: Some("P2P connection attempt already pending".to_string()),
                    });
                    return;
                }
                if self.pending_dials.len() >= MAX_CONCURRENT_DIALS
                    || self.active_connection_count() + self.pending_dials.len()
                        >= MAX_P2P_CONNECTIONS
                {
                    let _ = resp.send(P2PConnectResult {
                        success: false,
                        already_connected: None,
                        connection_token: None,
                        error: Some("P2P connection limit reached".to_string()),
                    });
                    return;
                }

                if !self.bind_alias(connection_id.clone(), peer_key.clone()) {
                    let _ = resp.send(P2PConnectResult {
                        success: false,
                        already_connected: None,
                        connection_token: None,
                        error: Some("P2P alias limit reached".to_string()),
                    });
                    return;
                }
                let dial_token = self.issue_dial_token();
                if self.endpoint.is_none() {
                    let _ = resp.send(P2PConnectResult {
                        success: false,
                        already_connected: None,
                        connection_token: None,
                        error: Some("P2P onion service not published yet".to_string()),
                    });
                    return;
                }
                self.pending_dials.insert(connection_id.clone(), dial_token);
                let command_tx = self.self_command_tx.clone();
                let identity_generation = self.identity_generation.load(Ordering::Acquire);
                let socks_port = tor_socks_port();
                tokio::spawn(async move {
                    let result = match tokio::time::timeout_at(
                        deadline,
                        connect_onion_peer(socks_port, &onion_host),
                    )
                    .await
                    {
                        Ok(Ok(connection)) => Ok(connection),
                        Ok(Err(e)) => Err(e.chars().take(200).collect::<String>()),
                        Err(_) => Err("Connection timeout".to_string()),
                    };
                    let _ = command_tx.send(WorkerCommand::DialCompleted {
                        connection_id,
                        peer_key,
                        dial_token,
                        identity_generation,
                        deadline,
                        result,
                        resp,
                        _permit,
                    });
                });
            }
            WorkerCommand::DialCompleted {
                connection_id,
                peer_key,
                dial_token,
                identity_generation,
                deadline,
                result,
                resp,
                _permit,
            } => {
                let token_is_current =
                    self.pending_dials.get(&connection_id).copied() == Some(dial_token);
                let identity_is_current =
                    self.identity_generation.load(Ordering::Acquire) == identity_generation;
                let within_deadline = tokio::time::Instant::now() <= deadline;
                let is_current = token_is_current && identity_is_current && within_deadline;
                if !is_current {
                    if token_is_current {
                        self.pending_dials.remove(&connection_id);
                        if self.alias_to_node.get(&connection_id).map(String::as_str)
                            == Some(peer_key.as_str())
                        {
                            self.unbind_alias(&connection_id);
                        }
                    }
                    if let Ok(connection) = result {
                        connection.close(0u32.into(), b"stale dial");
                    }

                    let error = if !identity_is_current {
                        "P2P identity changed during connection"
                    } else if !within_deadline {
                        "onion dial exceeded its deadline"
                    } else {
                        "P2P dial superseded by a newer attempt"
                    };
                    let _ = resp.send(P2PConnectResult {
                        success: false,
                        already_connected: None,
                        connection_token: None,
                        error: Some(error.to_string()),
                    });
                    return;
                }
                self.pending_dials.remove(&connection_id);

                if let Some(existing) = self.connections.get(&connection_id)
                    && existing.close_reason().is_none()
                    && let Some(connection_token) = self
                        .connection_tokens
                        .get(&connection_id)
                        .copied()
                        .filter(|token| self.send_queues.contains_key(token))
                {
                    if let Ok(connection) = result {
                        connection.close(0u32.into(), b"duplicate connection");
                    }
                    let _ = resp.send(P2PConnectResult {
                        success: true,
                        already_connected: Some(true),
                        connection_token: Some(connection_token),
                        error: None,
                    });
                    return;
                }

                match result {
                    Ok(connection) if self.active_connection_count() < MAX_P2P_CONNECTIONS => {
                        let connection_token = self
                            .activate_connection(connection_id, peer_key, connection, event_tx)
                            .await;
                        let activated = connection_token.is_some();
                        let _ = resp.send(P2PConnectResult {
                            success: activated,
                            already_connected: activated.then_some(false),
                            connection_token,
                            error: (!activated).then(|| "P2P event queue full".to_string()),
                        });
                    }
                    Ok(connection) => {
                        connection.close(1013u32.into(), b"peer limit");
                        self.unbind_alias(&connection_id);
                        let _ = resp.send(P2PConnectResult {
                            success: false,
                            already_connected: None,
                            connection_token: None,
                            error: Some("P2P connection limit reached".to_string()),
                        });
                    }
                    Err(error) => {
                        self.unbind_alias(&connection_id);
                        warn!("[P2P] Dial failed or timed out");
                        let _ = resp.send(P2PConnectResult {
                            success: false,
                            already_connected: None,
                            connection_token: None,
                            error: Some(error),
                        });
                    }
                }
            }
            WorkerCommand::Send {
                connection_id,
                connection_token: expected_connection_token,
                data,
                audio_onion_host,
                audio_lane_rtt_ceiling_ms,
                deadline,
                resp,
                _permit,
            } => {
                let Some(connection_key) = self.resolve_connection_key(&connection_id) else {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("Connection not found".to_string()),
                        audio_lanes: None,
                    });
                    return;
                };
                let Some(connection_token) = self.connection_tokens.get(&connection_key).copied()
                else {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("Connection not found".to_string()),
                        audio_lanes: None,
                    });
                    return;
                };
                if connection_token != expected_connection_token {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("P2P connection generation changed".to_string()),
                        audio_lanes: None,
                    });
                    return;
                }
                let protocol_frame_is_valid = if self
                    .authenticated_connections
                    .read()
                    .contains(&connection_token)
                {
                    is_valid_authenticated_frame(&data)
                } else {
                    parse_preauthentication_frame(&data).is_some()
                };
                if !protocol_frame_is_valid {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("P2P frame is invalid for the connection state".to_string()),
                        audio_lanes: None,
                    });
                    return;
                }

                let realtime_audio = is_realtime_audio_frame(&data);
                let realtime_visual = is_realtime_visual_frame(&data);
                if realtime_audio || realtime_visual {
                    if let Some(onion_host) = audio_onion_host {
                        let endpoint_changed = self
                            .audio_lane_onion_hosts
                            .get(&connection_token)
                            .is_some_and(|current| current != &onion_host);
                        if endpoint_changed {
                            self.clear_audio_lanes_for_token(
                                connection_token,
                                b"peer audio endpoint changed",
                            );
                        }
                        self.audio_lane_onion_hosts
                            .insert(connection_token, onion_host);
                    }
                    self.ensure_audio_lanes(connection_token);
                }
                if realtime_visual {
                    if tokio::time::Instant::now() >= deadline {
                        let _ = resp.send(P2PSendResult {
                            success: false,
                            error: Some("P2P visual send expired in queue".to_string()),
                            audio_lanes: Some(
                                self.audio_lane_telemetry(
                                    connection_token,
                                    self.audio_lane_selections
                                        .get(&connection_token)
                                        .and_then(|selection| selection.selected),
                                ),
                            ),
                        });
                        return;
                    }
                    let Some(lane) = self.visual_lane_candidate(connection_token) else {
                        let _ = resp.send(P2PSendResult {
                            success: false,
                            error: Some("Dedicated visual lane unavailable".to_string()),
                            audio_lanes: Some(
                                self.audio_lane_telemetry(
                                    connection_token,
                                    self.audio_lane_selections
                                        .get(&connection_token)
                                        .and_then(|selection| selection.selected),
                                ),
                            ),
                        });
                        return;
                    };
                    let frame_id = self
                        .audio_lane_frame_ids
                        .entry(connection_token)
                        .or_insert(0);
                    *frame_id = frame_id.wrapping_add(1).max(1);
                    let lane_frame =
                        encode_audio_lane_frame(AUDIO_LANE_FRAME_DATA, *frame_id, &data);
                    let identity_generation = self.identity_generation.load(Ordering::Acquire);
                    let command_tx = self.self_command_tx.clone();
                    let telemetry = self.audio_lane_telemetry(
                        connection_token,
                        self.audio_lane_selections
                            .get(&connection_token)
                            .and_then(|selection| selection.selected),
                    );
                    tokio::spawn(async move {
                        let sent = tokio::time::timeout_at(
                            deadline,
                            lane.connection.send_frame(&lane_frame),
                        )
                        .await
                        .is_ok_and(|result| result.is_ok());
                        if !sent {
                            let _ = command_tx.send(WorkerCommand::AudioLaneFailed {
                                identity_generation,
                                connection_token,
                                token: lane.token,
                            });
                        }
                        let _ = resp.send(P2PSendResult {
                            success: sent,
                            error: (!sent)
                                .then(|| "Visual lane send failed or expired".to_string()),
                            audio_lanes: Some(telemetry),
                        });
                        drop(_permit);
                    });
                    return;
                }
                if realtime_audio {
                    if tokio::time::Instant::now() >= deadline {
                        let _ = resp.send(P2PSendResult {
                            success: false,
                            error: Some("P2P send expired in queue".to_string()),
                            audio_lanes: Some(self.audio_lane_telemetry(connection_token, None)),
                        });
                        return;
                    }
                    let candidates = audio_lane_rtt_ceiling_ms.map_or_else(Vec::new, |ceiling| {
                        self.audio_lane_candidates(connection_token, ceiling)
                    });
                    if !candidates.is_empty() {
                        let frame_id = self
                            .audio_lane_frame_ids
                            .entry(connection_token)
                            .or_insert(0);
                        *frame_id = frame_id.wrapping_add(1).max(1);
                        let lane_frame =
                            encode_audio_lane_frame(AUDIO_LANE_FRAME_DATA, *frame_id, &data);
                        let mut selected = None;
                        let mut removed_any = false;
                        for (attempt, lane) in candidates.into_iter().enumerate() {
                            if tokio::time::Instant::now() >= deadline {
                                break;
                            }
                            let attempt_deadline = if attempt == 0 {
                                deadline.min(
                                    tokio::time::Instant::now()
                                        + std::time::Duration::from_millis(40),
                                )
                            } else {
                                deadline
                            };
                            let sent = tokio::time::timeout_at(
                                attempt_deadline,
                                lane.connection.send_frame(&lane_frame),
                            )
                            .await
                            .is_ok_and(|result| result.is_ok());
                            if sent {
                                selected = Some(lane.token);
                                break;
                            }
                            removed_any |= self.remove_outbound_audio_lane(
                                connection_token,
                                lane.token,
                                b"audio lane send failed",
                            );
                        }
                        if removed_any {
                            let no_ready_lanes = self
                                .outbound_audio_lanes
                                .get(&connection_token)
                                .map_or(true, Vec::is_empty);
                            self.schedule_audio_lane_retry(connection_token, no_ready_lanes);
                        }
                        if let Some(selected) = selected {
                            let selection = self
                                .audio_lane_selections
                                .entry(connection_token)
                                .or_default();
                            if selection.selected != Some(selected) {
                                selection.select(selected);
                            }
                            let _ = resp.send(P2PSendResult {
                                success: true,
                                error: None,
                                audio_lanes: Some(
                                    self.audio_lane_telemetry(connection_token, Some(selected)),
                                ),
                            });
                            return;
                        }
                    }
                }

                let Some(send_queues) = self.send_queues.get(&connection_token) else {
                    let _ = resp.send(P2PSendResult {
                        success: false,
                        error: Some("Connection writer unavailable".to_string()),
                        audio_lanes: None,
                    });
                    return;
                };
                let frame = QueuedSend {
                    data,
                    deadline,
                    audio_lanes: realtime_audio
                        .then(|| self.audio_lane_telemetry(connection_token, None)),
                    resp,
                    _permit,
                };
                let send_tx = if realtime_audio {
                    &send_queues.realtime
                } else {
                    &send_queues.normal
                };
                match send_tx.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(frame)) => {
                        Self::fail_queued_send(frame, "Peer send queue full");
                    }
                    Err(mpsc::error::TrySendError::Closed(frame)) => {
                        Self::fail_queued_send(frame, "Connection writer unavailable");
                    }
                }
            }
            WorkerCommand::Disconnect {
                connection_id,
                connection_token: expected_connection_token,
                resp,
                _permit,
            } => {
                let connection_token = self
                    .resolve_connection_key(&connection_id)
                    .and_then(|key| self.connection_tokens.get(&key).copied());
                if let Some(expected) = expected_connection_token {
                    if connection_token != Some(expected) {
                        let _ = resp.send(false);
                        return;
                    }
                    let closed = self
                        .close_connection_token(expected, event_tx, 1000, "Disconnected")
                        .await;
                    let _ = resp.send(closed);
                } else {
                    let canceled_dial = self.pending_dials.remove(&connection_id).is_some();
                    if canceled_dial {
                        self.unbind_alias(&connection_id);
                    }
                    let _ = resp.send(canceled_dial);
                }
            }
            WorkerCommand::EndpointPublished {
                identity_generation,
                endpoint,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation {
                    drop(endpoint);
                    return;
                }
                if self.endpoint.is_some() {
                    drop(endpoint);
                    return;
                }
                let endpoint_url = build_private_endpoint_url(endpoint.onion_host());
                self.endpoint_accept_task = Some(spawn_onion_endpoint_acceptor(
                    endpoint.clone(),
                    self.self_command_tx.clone(),
                    identity_generation,
                ));
                self.endpoint = Some(endpoint);
                *self.local_node_id.write() = Some(endpoint_url);
            }
            WorkerCommand::RotateIdentity { resp, _permit } => {
                let identity_generation = self
                    .identity_generation
                    .fetch_add(1, Ordering::AcqRel)
                    .wrapping_add(1);
                *self.local_node_id.write() = None;
                self.pending_dials.clear();

                let tokens: HashSet<u64> = self.connection_tokens.values().copied().collect();
                for token in tokens {
                    self.close_connection_token(token, event_tx, 1000, "Identity rotated")
                        .await;
                }
                self.connections.clear();
                self.connection_tokens.clear();
                self.send_queues.clear();
                for connection in self.pending_audio_connections.values() {
                    connection.close(0u32, b"identity rotated");
                }
                self.pending_audio_connections.clear();
                self.pending_audio_offers.clear();
                self.audio_lane_dials.clear();
                self.authenticated_connections.write().clear();
                for (_, task) in self.authentication_timeout_tasks.drain() {
                    task.abort();
                }
                self.alias_to_node.clear();
                self.node_to_aliases.clear();

                let replacement = match create_onion_endpoint().await {
                    Ok(endpoint) => endpoint,
                    Err(error) => {
                        let _ = resp.send(Err(error.safe_message()));
                        return;
                    }
                };
                let replacement = Arc::new(replacement);
                let endpoint_url = build_private_endpoint_url(replacement.onion_host());
                if let Some(task) = self.endpoint_accept_task.take() {
                    task.abort();
                }
                let previous_endpoint = self.endpoint.replace(replacement.clone());
                drop(previous_endpoint);
                self.endpoint_accept_task = Some(spawn_onion_endpoint_acceptor(
                    replacement,
                    self.self_command_tx.clone(),
                    identity_generation,
                ));
                *self.local_node_id.write() = Some(endpoint_url.clone());
                let _ = resp.send(Ok(endpoint_url));
            }

            WorkerCommand::Authenticate {
                connection_id,
                connection_token: expected_connection_token,
                resp,
                _permit,
            } => {
                let authenticated_token = self
                    .resolve_connection_key(&connection_id)
                    .and_then(|key| self.connection_tokens.get(&key).copied())
                    .filter(|token| *token == expected_connection_token)
                    .filter(|token| self.send_queues.contains_key(token));
                let authenticated = if let Some(token) = authenticated_token {
                    self.authenticated_connections.write().insert(token);
                    if let Some(task) = self.authentication_timeout_tasks.remove(&token) {
                        task.abort();
                    }
                    true
                } else {
                    false
                };
                let _ = resp.send(authenticated);
            }

            WorkerCommand::IncomingEstablished {
                identity_generation,
                result,
                _permit,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation {
                    if let Ok(connection) = result {
                        connection.close(0u32.into(), b"stale identity");
                    }
                    return;
                }
                match result {
                    Ok(connection) => {
                        self.handle_incoming_connection(connection, event_tx).await;
                    }
                    Err(_) => warn!("[P2P] Incoming handshake failed or timed out"),
                }
            }
            WorkerCommand::IncomingAudioLane {
                identity_generation,
                token,
                connection,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation {
                    connection.close(0u32, b"stale identity");
                    return;
                }
                if let Some((connection_token, connection_id, offer_generation)) =
                    self.pending_audio_offers.remove(&token)
                {
                    if offer_generation == identity_generation {
                        self.attach_inbound_audio_lane(
                            connection_token,
                            connection_id,
                            token,
                            connection,
                            event_tx,
                        );
                    } else {
                        connection.close(1008u32, b"stale audio lane");
                    }
                } else if self.pending_audio_connections.len() < MAX_PENDING_AUDIO_LANES {
                    self.pending_audio_connections.insert(token, connection);
                    let command_tx = self.self_command_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        let _ = command_tx.send(WorkerCommand::ExpirePendingAudioLane {
                            identity_generation,
                            token,
                        });
                    });
                } else {
                    connection.close(1013u32, b"audio lane capacity");
                }
            }
            WorkerCommand::AudioLaneOffer {
                identity_generation,
                connection_id,
                connection_token,
                token,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation
                    || self.connection_tokens.get(&connection_id).copied() != Some(connection_token)
                    || !self
                        .authenticated_connections
                        .read()
                        .contains(&connection_token)
                {
                    return;
                }
                if let Some(connection) = self.pending_audio_connections.remove(&token) {
                    self.attach_inbound_audio_lane(
                        connection_token,
                        connection_id,
                        token,
                        connection,
                        event_tx,
                    );
                } else if self.pending_audio_offers.len() < MAX_PENDING_AUDIO_LANES {
                    self.pending_audio_offers.insert(
                        token,
                        (connection_token, connection_id, identity_generation),
                    );
                    let command_tx = self.self_command_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        let _ = command_tx.send(WorkerCommand::ExpirePendingAudioLane {
                            identity_generation,
                            token,
                        });
                    });
                }
            }
            WorkerCommand::AudioLaneDialCompleted {
                identity_generation,
                connection_token,
                token,
                result,
            } => {
                if let Some(tokens) = self.audio_lane_dials.get_mut(&connection_token) {
                    tokens.remove(&token);
                    if tokens.is_empty() {
                        self.audio_lane_dials.remove(&connection_token);
                    }
                }
                let batch_complete = !self.audio_lane_dials.contains_key(&connection_token);
                let connection_current = self.identity_generation.load(Ordering::Acquire)
                    == identity_generation
                    && self
                        .authenticated_connections
                        .read()
                        .contains(&connection_token);
                match result {
                    Ok(connection) if connection_current => {
                        let lanes = self
                            .outbound_audio_lanes
                            .entry(connection_token)
                            .or_default();
                        if lanes.len() >= AUDIO_LANE_TARGET_COUNT
                            || lanes.iter().any(|lane| lane.token == token)
                        {
                            connection.close(1008u32, b"audio lane capacity");
                        } else {
                            let connection = Arc::new(connection);
                            lanes.push(OutboundAudioLane {
                                token,
                                connection: connection.clone(),
                                rtt_ms: None,
                                degraded_samples: 0,
                            });
                            if let Some(status) =
                                self.audio_lane_setup_status.get_mut(&connection_token)
                            {
                                status.consecutive_failed_batches = 0;
                            }
                            if lanes.len() == AUDIO_LANE_TARGET_COUNT {
                                self.audio_lane_next_dial_at.remove(&connection_token);
                                if let Some(status) =
                                    self.audio_lane_setup_status.get_mut(&connection_token)
                                {
                                    status.last_failure = None;
                                }
                            }
                            self.spawn_outbound_audio_lane_tasks(
                                identity_generation,
                                connection_token,
                                token,
                                connection,
                            );
                        }
                    }
                    Ok(connection) => connection.close(1008u32, b"stale audio lane"),
                    Err(error) => {
                        let status = self
                            .audio_lane_setup_status
                            .entry(connection_token)
                            .or_default();
                        status.failures = status.failures.saturating_add(1);
                        status.last_failure = Some(match error.as_str() {
                            "offer-send" => "offer-send",
                            "dial-timeout" => "dial-timeout",
                            "preamble-send" => "preamble-send",
                            "binding-timeout" => "binding-timeout",
                            "binding-closed" => "binding-closed",
                            "binding-pressure" => "binding-pressure",
                            "binding-read-invalid" => "binding-read-invalid",
                            "binding-frame-invalid" => "binding-frame-invalid",
                            _ => "dial-failed",
                        });
                    }
                }
                if batch_complete && connection_current {
                    let ready = self
                        .outbound_audio_lanes
                        .get(&connection_token)
                        .map_or(0, Vec::len);
                    if ready < AUDIO_LANE_TARGET_COUNT {
                        self.schedule_audio_lane_retry(connection_token, ready == 0);
                    }
                }
            }
            WorkerCommand::AudioLaneRtt {
                identity_generation,
                connection_token,
                token,
                rtt_ms,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation {
                    return;
                }
                let mut remove_degraded = false;
                if let Some(lanes) = self.outbound_audio_lanes.get_mut(&connection_token) {
                    let fastest_other = lanes
                        .iter()
                        .filter(|lane| lane.token != token)
                        .filter_map(|lane| lane.rtt_ms)
                        .min();
                    if let Some(lane) = lanes.iter_mut().find(|lane| lane.token == token) {
                        lane.rtt_ms = Some(match lane.rtt_ms {
                            Some(previous) => previous.saturating_mul(7).saturating_add(rtt_ms) / 8,
                            None => rtt_ms,
                        });
                        let degraded = fastest_other.is_some_and(|fastest| {
                            rtt_ms > fastest.saturating_mul(2)
                                && rtt_ms > fastest.saturating_add(750)
                        });
                        lane.degraded_samples = if degraded {
                            lane.degraded_samples.saturating_add(1)
                        } else {
                            0
                        };
                        remove_degraded =
                            lane.degraded_samples >= 3 && lanes.len() > AUDIO_LANE_ACTIVE_COUNT;
                    }
                }
                let mut ranked: Vec<([u8; AUDIO_LANE_TOKEN_BYTES], u64)> = self
                    .outbound_audio_lanes
                    .get(&connection_token)
                    .into_iter()
                    .flatten()
                    .filter_map(|lane| lane.rtt_ms.map(|rtt| (lane.token, rtt)))
                    .collect();
                ranked.sort_by_key(|(_, rtt)| *rtt);
                self.audio_lane_selections
                    .entry(connection_token)
                    .or_default()
                    .observe(
                        &ranked
                            .into_iter()
                            .filter(|(candidate, _)| {
                                self.visual_lane_selections
                                    .get(&connection_token)
                                    .is_none_or(|visual| candidate != visual)
                            })
                            .collect::<Vec<_>>(),
                        token,
                    );
                if remove_degraded
                    && self.remove_outbound_audio_lane(
                        connection_token,
                        token,
                        b"audio lane degraded",
                    )
                {
                    let status = self
                        .audio_lane_setup_status
                        .entry(connection_token)
                        .or_default();
                    status.failures = status.failures.saturating_add(1);
                    status.last_failure = Some("rtt-degraded");
                    self.schedule_audio_lane_retry(connection_token, false);
                }
            }
            WorkerCommand::AudioLaneFailed {
                identity_generation,
                connection_token,
                token,
            } => {
                if self.identity_generation.load(Ordering::Acquire) == identity_generation
                    && self.remove_outbound_audio_lane(
                        connection_token,
                        token,
                        b"audio lane failed",
                    )
                {
                    let status = self
                        .audio_lane_setup_status
                        .entry(connection_token)
                        .or_default();
                    status.failures = status.failures.saturating_add(1);
                    status.last_failure = Some("lane-closed");
                    let no_ready_lanes = self
                        .outbound_audio_lanes
                        .get(&connection_token)
                        .map_or(true, Vec::is_empty);
                    self.schedule_audio_lane_retry(connection_token, no_ready_lanes);
                }
            }
            WorkerCommand::InboundAudioLaneClosed {
                identity_generation,
                connection_token,
                token,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation {
                    return;
                }
                if let Some(lanes) = self.inbound_audio_lanes.get_mut(&connection_token) {
                    lanes.retain(|lane| lane.token != token);
                    if lanes.is_empty() {
                        self.inbound_audio_lanes.remove(&connection_token);
                        self.audio_receive_windows.remove(&connection_token);
                    }
                }
            }
            WorkerCommand::ExpirePendingAudioLane {
                identity_generation,
                token,
            } => {
                if self.identity_generation.load(Ordering::Acquire) != identity_generation {
                    return;
                }
                self.pending_audio_offers.remove(&token);
                if let Some(connection) = self.pending_audio_connections.remove(&token) {
                    connection.close(1008u32, b"audio lane binding timeout");
                }
            }
            WorkerCommand::AuthenticationExpired {
                connection_id,
                connection_token,
                identity_generation,
            } => {
                self.authentication_timeout_tasks.remove(&connection_token);
                if self.identity_generation.load(Ordering::Acquire) == identity_generation
                    && self.connection_tokens.get(&connection_id).copied() == Some(connection_token)
                    && !self
                        .authenticated_connections
                        .read()
                        .contains(&connection_token)
                {
                    self.close_connection_token(
                        connection_token,
                        event_tx,
                        1008,
                        "Handshake authentication timeout",
                    )
                    .await;
                }
            }
            WorkerCommand::ConnectionLost {
                connection_id,
                connection_token,
                reason,
            } => {
                if self.connection_tokens.get(&connection_id).copied() == Some(connection_token) {
                    self.close_connection_token(connection_token, event_tx, 1006, reason)
                        .await;
                }
            }
        }
    }
}

pub struct P2PTransportHandler {
    command_tx: mpsc::UnboundedSender<WorkerCommand>,
    event_tx: Arc<RwLock<Option<mpsc::Sender<P2PEvent>>>>,
    local_node_id: Arc<RwLock<Option<String>>>,
    endpoint_exposure_enabled: Arc<AtomicBool>,
    rotation_generation: AtomicU64,
}

impl P2PTransportHandler {
    fn new(
        command_tx: mpsc::UnboundedSender<WorkerCommand>,
        local_node_id: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            command_tx,
            event_tx: Arc::new(RwLock::new(None)),
            local_node_id,
            endpoint_exposure_enabled: Arc::new(AtomicBool::new(true)),
            rotation_generation: AtomicU64::new(0),
        }
    }

    pub fn set_event_handler(&self, tx: mpsc::Sender<P2PEvent>) {
        *self.event_tx.write() = Some(tx);
    }

    fn begin_identity_rotation(&self) -> u64 {
        let generation = self
            .rotation_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        self.endpoint_exposure_enabled
            .store(false, Ordering::Release);
        *self.local_node_id.write() = None;
        generation
    }

    fn publish_completed_rotation(&self, generation: u64, endpoint_url: &str) -> bool {
        if self.rotation_generation.load(Ordering::Acquire) != generation {
            return false;
        }
        *self.local_node_id.write() = Some(endpoint_url.to_string());
        self.endpoint_exposure_enabled
            .store(true, Ordering::Release);
        true
    }

    /// Connect to a peer
    pub async fn connect(
        &self,
        connection_id: &str,
        endpoint_url: &str,
    ) -> QorResult<P2PConnectResult> {
        validate_connection_id(connection_id)?;
        let onion_host = parse_private_endpoint_url(endpoint_url)?;
        let Some(permit) = try_reserve_control_command() else {
            return Ok(P2PConnectResult {
                success: false,
                already_connected: None,
                connection_token: None,
                error: Some("P2P control queue full".to_string()),
            });
        };

        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS);
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(WorkerCommand::Dial {
                connection_id: connection_id.to_string(),
                peer_key: onion_host.clone(),
                onion_host,
                deadline,
                resp: tx,
                _permit: permit,
            })
            .is_err()
        {
            return Err(QorError::Network("P2P worker unavailable".to_string()));
        }

        match tokio::time::timeout_at(
            deadline + std::time::Duration::from_secs(COMMAND_RESPONSE_GRACE_SECS),
            rx,
        )
        .await
        {
            Ok(Ok(res)) => Ok(res),
            Ok(Err(_)) | Err(_) => Ok(P2PConnectResult {
                success: false,
                already_connected: None,
                connection_token: None,
                error: Some("P2P worker did not respond".to_string()),
            }),
        }
    }

    /// Send message
    pub async fn send(
        &self,
        connection_id: &str,
        connection_token: u64,
        data: Vec<u8>,
        deadline_ms: Option<u64>,
        audio_endpoint: Option<String>,
        audio_lane_rtt_ceiling_ms: Option<u64>,
    ) -> QorResult<P2PSendResult> {
        validate_connection_id(connection_id)?;
        if connection_token == 0 {
            return Err(QorError::InvalidArgument(
                "Invalid P2P connection token".to_string(),
            ));
        }
        if data.is_empty() || data.len() > MAX_FRAME_BYTES {
            return Ok(P2PSendResult {
                success: false,
                error: Some(format!(
                    "Frame too large: {} bytes (max {})",
                    data.len(),
                    MAX_FRAME_BYTES
                )),
                audio_lanes: None,
            });
        }

        let Some(permit) = try_reserve_outbound_bytes(data.len()) else {
            return Ok(P2PSendResult {
                success: false,
                error: Some("Outbound P2P queue full".to_string()),
                audio_lanes: None,
            });
        };

        let audio_onion_host = match audio_endpoint {
            Some(endpoint) => Some(parse_private_endpoint_url(&endpoint)?),
            None => None,
        };

        let now = tokio::time::Instant::now();
        let max_duration = std::time::Duration::from_secs(SEND_TIMEOUT_SECS);
        let requested_duration = deadline_ms.map(|deadline| {
            let current = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            std::time::Duration::from_millis(deadline.saturating_sub(current))
        });
        let deadline = now + requested_duration.unwrap_or(max_duration).min(max_duration);
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(WorkerCommand::Send {
                connection_id: connection_id.to_string(),
                connection_token,
                data,
                audio_onion_host,
                audio_lane_rtt_ceiling_ms,
                deadline,
                resp: tx,
                _permit: permit,
            })
            .is_err()
        {
            return Err(QorError::Network("P2P worker unavailable".to_string()));
        }

        match tokio::time::timeout_at(
            deadline + std::time::Duration::from_secs(COMMAND_RESPONSE_GRACE_SECS),
            rx,
        )
        .await
        {
            Ok(Ok(res)) => Ok(res),
            Ok(Err(_)) | Err(_) => Ok(P2PSendResult {
                success: false,
                error: Some("P2P worker did not respond".to_string()),
                audio_lanes: None,
            }),
        }
    }

    /// Disconnect
    pub async fn disconnect(
        &self,
        connection_id: &str,
        connection_token: Option<u64>,
    ) -> QorResult<bool> {
        validate_connection_id(connection_id)?;
        if connection_token == Some(0) {
            return Err(QorError::InvalidArgument(
                "Invalid P2P connection token".to_string(),
            ));
        }
        let Some(permit) = try_reserve_control_command() else {
            return Ok(false);
        };
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(WorkerCommand::Disconnect {
                connection_id: connection_id.to_string(),
                connection_token,
                resp: tx,
                _permit: permit,
            })
            .is_err()
        {
            return Err(QorError::Network("P2P worker unavailable".to_string()));
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS + COMMAND_RESPONSE_GRACE_SECS),
            rx,
        )
        .await
        {
            Ok(Ok(ok)) => Ok(ok),
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    }

    pub async fn rotate_identity(&self) -> QorResult<String> {
        let Some(permit) = try_reserve_control_command() else {
            return Err(QorError::Network("P2P control queue full".to_string()));
        };
        let (tx, rx) = oneshot::channel();
        let rotation_generation = self.begin_identity_rotation();
        if self
            .command_tx
            .send(WorkerCommand::RotateIdentity {
                resp: tx,
                _permit: permit,
            })
            .is_err()
        {
            return Err(QorError::Network("P2P worker unavailable".to_string()));
        }
        match tokio::time::timeout(
            std::time::Duration::from_secs(ROTATE_RESPONSE_TIMEOUT_SECS),
            rx,
        )
        .await
        {
            Ok(Ok(Ok(endpoint_url))) => {
                if !self.publish_completed_rotation(rotation_generation, &endpoint_url) {
                    return Err(QorError::Network(
                        "P2P identity rotation was superseded".to_string(),
                    ));
                }
                Ok(endpoint_url)
            }
            Ok(Ok(Err(error))) => Err(QorError::Network(error)),
            Ok(Err(_)) | Err(_) => Err(QorError::Network("P2P worker did not respond".to_string())),
        }
    }

    pub async fn authenticate(
        &self,
        connection_id: &str,
        connection_token: u64,
    ) -> QorResult<bool> {
        validate_connection_id(connection_id)?;
        if connection_token == 0 {
            return Err(QorError::InvalidArgument(
                "Invalid P2P connection token".to_string(),
            ));
        }
        let Some(permit) = try_reserve_control_command() else {
            return Ok(false);
        };
        let (tx, rx) = oneshot::channel();
        if self
            .command_tx
            .send(WorkerCommand::Authenticate {
                connection_id: connection_id.to_string(),
                connection_token,
                resp: tx,
                _permit: permit,
            })
            .is_err()
        {
            return Err(QorError::Network("P2P worker unavailable".to_string()));
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS + COMMAND_RESPONSE_GRACE_SECS),
            rx,
        )
        .await
        {
            Ok(Ok(authenticated)) => Ok(authenticated),
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    }

    /// onion://<host> for peer discovery
    pub fn local_endpoint(&self) -> Option<String> {
        if !self.endpoint_exposure_enabled.load(Ordering::Acquire) {
            return None;
        }
        self.local_node_id.read().clone()
    }
}

impl Drop for P2PTransportHandler {
    fn drop(&mut self) {
        self.endpoint_exposure_enabled
            .store(false, Ordering::Release);
        *self.local_node_id.write() = None;
        *self.event_tx.write() = None;
        let _ = self.command_tx.send(WorkerCommand::Shutdown);
    }
}

pub async fn init() -> QorResult<Arc<P2PTransportHandler>> {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<WorkerCommand>();
    let local_node_id = Arc::new(RwLock::new(None));
    let worker = IrohWorker::new(cmd_tx.clone(), local_node_id.clone()).await?;

    let (worker_event_tx, mut worker_event_rx) =
        mpsc::channel::<WorkerEvent>(P2P_EVENT_CHANNEL_CAPACITY);

    let handler = Arc::new(P2PTransportHandler::new(cmd_tx, local_node_id));

    tokio::spawn(async move {
        worker.run(cmd_rx, worker_event_tx).await;
    });

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
                    P2PEvent::Connected {
                        connection_id,
                        connection_token,
                    }
                }
                WorkerEvent::Closed {
                    connection_id,
                    connection_token,
                    code,
                    reason,
                } => {
                    if latest_connection_tokens.get(&connection_id).copied()
                        != Some(connection_token)
                    {
                        continue;
                    }
                    latest_connection_tokens.remove(&connection_id);
                    P2PEvent::Closed {
                        connection_id,
                        connection_token,
                        code,
                        reason,
                    }
                }
                WorkerEvent::Message {
                    connection_id,
                    connection_token,
                    data,
                    byte_len,
                } => {
                    if latest_connection_tokens.get(&connection_id).copied()
                        != Some(connection_token)
                    {
                        release_inbound_bytes(byte_len);
                        continue;
                    }
                    P2PEvent::Message {
                        connection_id,
                        connection_token,
                        data,
                        byte_len,
                    }
                }
            };

            let pending_bytes = match &mapped {
                P2PEvent::Message { byte_len, .. } => *byte_len,
                _ => 0,
            };
            let mut delivered = false;
            let event_sender = public_event_tx.read().clone();
            if let Some(tx) = event_sender {
                delivered = tx.send(mapped).await.is_ok();
            }
            if !delivered && pending_bytes > 0 {
                release_inbound_bytes(pending_bytes);
            }
        }
    });

    Ok(handler)
}

#[cfg(test)]
mod tests {
    use super::{
        AUDIO_LANE_ACTIVE_COUNT, AUDIO_LANE_FRAME_DATA, AUDIO_LANE_FRAME_PING,
        AUDIO_LANE_FRAME_PONG, AUDIO_LANE_FRAME_READY, AUDIO_LANE_SWITCH_CONFIRMATIONS,
        AUDIO_LANE_TARGET_COUNT, AudioLaneFrame, AudioLaneSelection, AudioLaneTelemetry,
        AudioLaneTelemetryEntry, AudioReceiveWindow, P2PEvent, P2PSendResult,
        audio_lane_has_meaningful_gain, audio_lane_rtt_is_eligible, encode_audio_lane_frame,
        is_realtime_audio_frame, is_realtime_visual_frame, is_valid_authenticated_frame,
        parse_audio_lane_frame,
    };

    fn stream_frame(id: &str, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(2 + id.len() + payload.len());
        frame.extend_from_slice(&(id.len() as u16).to_be_bytes());
        frame.extend_from_slice(id.as_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn authenticated_binary_audio_frames_are_realtime() {
        let audio = stream_frame("call-audio:0123456789abcdef", &[1, 2, 3]);
        let screen = stream_frame("call-screen:0123456789abcdef", &[1, 2, 3]);
        assert!(is_valid_authenticated_frame(&audio));
        assert!(is_realtime_audio_frame(&audio));
        assert!(is_valid_authenticated_frame(&screen));
        assert!(!is_realtime_audio_frame(&screen));
        assert!(is_realtime_visual_frame(&screen));
        assert!(!is_realtime_visual_frame(&audio));
        assert!(!is_valid_authenticated_frame(b"not-a-frame"));
    }

    #[test]
    fn bridge_message_preserves_raw_payload() {
        let payload = vec![0, 1, 2, 3, 255];
        let bytes = P2PEvent::Message {
            connection_id: "inbound:1".to_string(),
            connection_token: 7,
            data: payload.clone(),
            byte_len: payload.len(),
        }
        .into_bridge_bytes()
        .unwrap();
        assert_eq!(&bytes[..4], b"QPB1");
        assert_eq!(bytes[4], 3);
        assert_eq!(&bytes[15 + "inbound:1".len()..], payload.as_slice());
    }

    #[test]
    fn audio_lane_frames_are_typed_and_bounded() {
        let payload = [4, 5, 6];
        let data = encode_audio_lane_frame(AUDIO_LANE_FRAME_DATA, 41, &payload);
        match parse_audio_lane_frame(&data) {
            Some(AudioLaneFrame::Data { frame_id, data }) => {
                assert_eq!(frame_id, 41);
                assert_eq!(data, payload);
            }
            _ => panic!("expected audio data frame"),
        }
        let ping = encode_audio_lane_frame(AUDIO_LANE_FRAME_PING, 42, &[]);
        assert!(matches!(
            parse_audio_lane_frame(&ping),
            Some(AudioLaneFrame::Ping(42))
        ));
        let pong = encode_audio_lane_frame(AUDIO_LANE_FRAME_PONG, 42, &[]);
        assert!(matches!(
            parse_audio_lane_frame(&pong),
            Some(AudioLaneFrame::Pong(42))
        ));
        let ready = encode_audio_lane_frame(AUDIO_LANE_FRAME_READY, 1, &[]);
        assert!(matches!(
            parse_audio_lane_frame(&ready),
            Some(AudioLaneFrame::Ready)
        ));
        assert!(
            parse_audio_lane_frame(&encode_audio_lane_frame(AUDIO_LANE_FRAME_PING, 0, &[]))
                .is_none()
        );
        assert!(
            parse_audio_lane_frame(&encode_audio_lane_frame(AUDIO_LANE_FRAME_PONG, 1, &[1]))
                .is_none()
        );
    }

    #[test]
    fn audio_receive_window_accepts_reordering_once() {
        let mut window = AudioReceiveWindow::default();
        assert!(window.accept(10));
        assert!(window.accept(12));
        assert!(window.accept(11));
        assert!(!window.accept(11));
        assert!(window.accept(200));
        assert!(!window.accept(12));
    }

    #[test]
    fn donor_lane_requires_a_measured_rtt_below_the_primary_ceiling() {
        assert!(audio_lane_rtt_is_eligible(Some(540), 575));
        assert!(audio_lane_rtt_is_eligible(Some(575), 575));
        assert!(!audio_lane_rtt_is_eligible(Some(576), 575));
        assert!(!audio_lane_rtt_is_eligible(None, 575));
    }

    #[test]
    fn donor_lane_switch_requires_sustained_meaningful_gain() {
        let current = [1u8; 32];
        let challenger = [2u8; 32];
        let mut selection = AudioLaneSelection::default();
        selection.observe(&[(current, 700)], current);
        assert_eq!(selection.selected, Some(current));
        assert!(audio_lane_has_meaningful_gain(700, 600));
        assert!(!audio_lane_has_meaningful_gain(700, 640));
        for sample in 1..AUDIO_LANE_SWITCH_CONFIRMATIONS {
            selection.observe(&[(challenger, 600), (current, 700)], challenger);
            assert_eq!(selection.selected, Some(current), "sample {sample}");
        }
        selection.observe(&[(challenger, 600), (current, 700)], challenger);
        assert_eq!(selection.selected, Some(challenger));
        assert_eq!(selection.challenger, None);
        assert_eq!(selection.challenger_samples, 0);
    }

    #[test]
    fn donor_lane_selection_fails_over_when_selected_lane_disappears() {
        let current = [3u8; 32];
        let fallback = [4u8; 32];
        let mut selection = AudioLaneSelection::default();
        selection.select(current);
        selection.remove(current);
        selection.observe(&[(fallback, 650)], fallback);
        assert_eq!(selection.selected, Some(fallback));
    }

    #[test]
    fn audio_lane_telemetry_uses_the_bridge_schema() {
        assert_eq!(AUDIO_LANE_TARGET_COUNT, 4);
        assert_eq!(AUDIO_LANE_ACTIVE_COUNT, 1);
        let value = serde_json::to_value(P2PSendResult {
            success: true,
            error: None,
            audio_lanes: Some(AudioLaneTelemetry {
                ready: 4,
                target: 4,
                active: 2,
                endpoint_available: true,
                dialing: 0,
                attempts: 4,
                failures: 0,
                retry_in_ms: None,
                last_failure: None,
                selected_lane: Some("00112233".to_string()),
                visual_lane: Some("8899aabb".to_string()),
                lanes: vec![AudioLaneTelemetryEntry {
                    id: "00112233".to_string(),
                    rtt_ms: Some(900),
                    degraded_samples: 0,
                    role: "active".to_string(),
                }],
            }),
        })
        .unwrap();
        assert_eq!(value["audioLanes"]["selectedLane"], "00112233");
        assert_eq!(value["audioLanes"]["visualLane"], "8899aabb");
        assert_eq!(value["audioLanes"]["endpointAvailable"], true);
        assert_eq!(value["audioLanes"]["attempts"], 4);
        assert_eq!(value["audioLanes"]["lanes"][0]["rttMs"], 900);
        assert_eq!(value["audioLanes"]["lanes"][0]["degradedSamples"], 0);
    }
}
