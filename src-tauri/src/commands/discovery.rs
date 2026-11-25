//! Isolated binary transport for discovery, OPRF, and key transparency

use crate::constants::anonymous_http::{
    AVATAR_BODY_TIMEOUT, BODY_IDLE_TIMEOUT, CONNECT_TIMEOUT, DISCOVERY_BODY_TIMEOUT,
    HEADER_TIMEOUT, MIN_BODY_TIMEOUT, MIN_TRANSFER_BYTES_PER_SECOND, REQUEST_LARGE_BYTES,
    REQUEST_PIR_BYTES, REQUEST_SMALL_BYTES, RESPONSE_AVATAR_BYTES, RESPONSE_DISCOVERY_BYTES,
    RESPONSE_KEY_TRANSPARENCY_SYNC_BYTES, RESPONSE_PIR_BYTES, RESPONSE_SMALL_BYTES,
    RESPONSE_TAG_INDEX_BYTES, RESPONSE_TAG_UPDATE_BYTES, WARM_ENTRY_MAX_AGE, WARM_POOL_TARGET,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tauri::{
    State,
    ipc::{Channel, JavaScriptChannelId, Request, Response},
};
use tokio::sync::watch;
use uuid::Uuid;

use crate::state::AppState;

struct WarmEntry {
    isolation_user: String,
    warmed_at: Instant,
    target: String,
    socks_port: u16,
    destination_port: u16,
}

static WARM_POOL: Mutex<VecDeque<WarmEntry>> = Mutex::new(VecDeque::new());
static WARM_REFILL_RUNNING: LazyLock<Mutex<HashSet<(u16, String, u16)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn new_isolation_user() -> String {
    format!(
        "{}{}",
        crate::protocol_keys::ANONYMOUS_CONNECTION_ID_PREFIX,
        Uuid::new_v4().simple()
    )
}

fn take_warm_isolation_user(
    socks_port: u16,
    target: &str,
    destination_port: u16,
) -> Option<String> {
    let mut pool = WARM_POOL.lock().ok()?;
    let now = Instant::now();
    pool.retain(|entry| now.duration_since(entry.warmed_at) < WARM_ENTRY_MAX_AGE);
    let index = pool.iter().position(|entry| {
        entry.socks_port == socks_port
            && entry.target == target
            && entry.destination_port == destination_port
    })?;
    pool.remove(index).map(|entry| entry.isolation_user)
}

async fn warm_one_circuit(socks_port: u16, host: &str, port: u16) -> Option<String> {
    let isolation_user = new_isolation_user();
    let proxy = format!("127.0.0.1:{}", socks_port);
    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_socks::tcp::Socks5Stream::connect_with_password(
            proxy.as_str(),
            (host, port),
            &isolation_user,
            "isolate",
        ),
    )
    .await
    .ok()?
    .ok()?;
    drop(stream);
    Some(isolation_user)
}

fn spawn_warm_refill(socks_port: u16, host: String, port: u16) {
    let refill_key = (socks_port, host.clone(), port);
    {
        let Ok(mut running) = WARM_REFILL_RUNNING.lock() else {
            return;
        };
        if !running.insert(refill_key.clone()) {
            return;
        }
    }

    tauri::async_runtime::spawn(async move {
        loop {
            let needed = {
                let now = Instant::now();
                match WARM_POOL.lock() {
                    Ok(mut pool) => {
                        pool.retain(|entry| {
                            now.duration_since(entry.warmed_at) < WARM_ENTRY_MAX_AGE
                        });
                        let matching = pool
                            .iter()
                            .filter(|entry| {
                                entry.socks_port == socks_port
                                    && entry.target == host
                                    && entry.destination_port == port
                            })
                            .count();
                        WARM_POOL_TARGET
                            .saturating_sub(matching)
                            .min((WARM_POOL_TARGET * 4).saturating_sub(pool.len()))
                    }
                    Err(_) => 0,
                }
            };
            if needed == 0 {
                break;
            }

            match warm_one_circuit(socks_port, &host, port).await {
                Some(isolation_user) => {
                    if let Ok(mut pool) = WARM_POOL.lock() {
                        if pool.len() < WARM_POOL_TARGET * 4 {
                            pool.push_back(WarmEntry {
                                isolation_user,
                                warmed_at: Instant::now(),
                                target: host.clone(),
                                socks_port,
                                destination_port: port,
                            });
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }

        if let Ok(mut running) = WARM_REFILL_RUNNING.lock() {
            running.remove(&refill_key);
        }
    });
}

const REQUEST_ID_HEADER: &str = "x-qorc-anonymous-request-id";
const RESPONSE_BYTES_HEADER: &str = "x-qorc-anonymous-response-bytes";
const PROGRESS_HEADER: &str = "x-qorc-anonymous-progress";

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AnonymousDownloadProgress {
    received_bytes: usize,
    total_bytes: usize,
}

struct RequestCancellation {
    id: Uuid,
    receiver: watch::Receiver<bool>,
}

type CancellationEntries = HashMap<Uuid, (Instant, watch::Sender<bool>)>;
static REQUEST_CANCELLATIONS: LazyLock<Mutex<CancellationEntries>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_cancellations(entries: &mut CancellationEntries) {
    entries.retain(|_, (at, sender)| {
        sender.receiver_count() > 0 || at.elapsed() < Duration::from_secs(60)
    });
}

impl RequestCancellation {
    fn register(id: Uuid) -> Result<Self, String> {
        let mut entries = REQUEST_CANCELLATIONS
            .lock()
            .map_err(|_| "anonymous cancellation unavailable")?;
        prune_cancellations(&mut entries);
        if let Some((_, sender)) = entries.get(&id) {
            if sender.receiver_count() == 0 && *sender.borrow() {
                entries.remove(&id);
                return Err("anonymous request cancelled".to_string());
            }
            return Err("duplicate anonymous request id".to_string());
        }
        if entries.len() >= 128 {
            return Err("anonymous request limit reached".to_string());
        }
        let (sender, receiver) = watch::channel(false);
        entries.insert(id, (Instant::now(), sender));
        Ok(Self { id, receiver })
    }
}

impl Drop for RequestCancellation {
    fn drop(&mut self) {
        if let Ok(mut entries) = REQUEST_CANCELLATIONS.lock() {
            entries.remove(&self.id);
        }
    }
}

#[tauri::command]
pub fn cancel_anonymous_api_fetch(request_id: String) -> Result<(), String> {
    let id = Uuid::parse_str(&request_id).map_err(|_| "invalid anonymous request id")?;
    let mut entries = REQUEST_CANCELLATIONS
        .lock()
        .map_err(|_| "anonymous cancellation unavailable")?;
    prune_cancellations(&mut entries);
    if let Some((_, sender)) = entries.get(&id) {
        sender.send_replace(true);
    } else {
        if entries.len() >= 128 {
            return Err("anonymous cancellation limit reached".to_string());
        }
        let (sender, _) = watch::channel(true);
        entries.insert(id, (Instant::now(), sender));
    }
    Ok(())
}

fn uses_bulk_transport(request_bytes: usize, response_bytes: usize) -> bool {
    request_bytes > REQUEST_SMALL_BYTES || response_bytes > RESPONSE_SMALL_BYTES
}

fn body_timeout(bytes: usize) -> Duration {
    match bytes {
        RESPONSE_AVATAR_BYTES => AVATAR_BODY_TIMEOUT,
        RESPONSE_DISCOVERY_BYTES => DISCOVERY_BODY_TIMEOUT,
        _ => MIN_BODY_TIMEOUT.max(
            BODY_IDLE_TIMEOUT
                + Duration::from_secs(bytes.div_ceil(MIN_TRANSFER_BYTES_PER_SECOND) as u64),
        ),
    }
}

fn anonymous_http_client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .no_gzip()
        .connect_timeout(CONNECT_TIMEOUT);
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let builder = builder.tcp_user_timeout(None);
    builder
}

async fn send_anonymous_request(
    socks_port: u16,
    api_url: url::Url,
    request_body: Vec<u8>,
    header_timeout: Duration,
) -> Result<reqwest::Response, String> {
    let proxy_url = format!("socks5h://127.0.0.1:{socks_port}");
    let request_host = api_url.host_str().ok_or("invalid anonymous request host")?;
    let request_port = api_url
        .port_or_known_default()
        .ok_or("invalid anonymous request port")?;
    let host_is_onion = request_host.to_ascii_lowercase().ends_with(".onion");
    let started_at = Instant::now();
    let deadline = tokio::time::Instant::now() + header_timeout;
    let request_bytes = request_body.len();

    for attempt in 1..=2 {
        let isolation_user = take_warm_isolation_user(socks_port, request_host, request_port)
            .unwrap_or_else(new_isolation_user);
        let proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|_| "failed to configure anonymous transport".to_string())?
            .basic_auth(&isolation_user, "isolate");
        let mut builder = anonymous_http_client_builder().proxy(proxy);
        if host_is_onion {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|_| "failed to create anonymous transport".to_string())?;
        let response = tokio::time::timeout_at(
            deadline,
            client
                .post(api_url.clone())
                .header("Accept", "application/octet-stream")
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .header(reqwest::header::CACHE_CONTROL, "no-store")
                .header(reqwest::header::CONNECTION, "close")
                .body(request_body.clone())
                .send(),
        )
        .await
        .map_err(|_| {
            format!(
                "anonymous response header timeout after {} ms (request bytes: {request_bytes})",
                started_at.elapsed().as_millis(),
            )
        })?;
        match response {
            Ok(response) => return Ok(response),
            Err(error) if attempt == 1 && error.is_connect() => {
                tracing::warn!(
                    elapsed_ms = started_at.elapsed().as_millis(),
                    error = ?error.without_url(),
                    "[ANON-HTTP] connection establishment failed before HTTP delivery; trying another isolated connection"
                );
            }
            Err(error) => {
                return Err(format!(
                    "anonymous request failed before response headers after {} ms (request bytes: {request_bytes}): {:?}",
                    started_at.elapsed().as_millis(),
                    error.without_url(),
                ));
            }
        }
    }
    unreachable!()
}

async fn wait_for_bootstrap(tor: &Arc<crate::tor::TorManager>) -> bool {
    if tor.is_ready().await {
        return true;
    }
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if tor.is_ready().await {
                return true;
            }
            if !tor.is_running() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false)
}

fn valid_request_size(size: usize) -> bool {
    matches!(
        size,
        REQUEST_SMALL_BYTES | REQUEST_LARGE_BYTES | REQUEST_PIR_BYTES
    )
}

fn valid_response_size(size: usize) -> bool {
    matches!(
        size,
        RESPONSE_SMALL_BYTES
            | RESPONSE_TAG_INDEX_BYTES
            | RESPONSE_TAG_UPDATE_BYTES
            | RESPONSE_KEY_TRANSPARENCY_SYNC_BYTES
            | RESPONSE_PIR_BYTES
            | RESPONSE_AVATAR_BYTES
            | RESPONSE_DISCOVERY_BYTES
    )
}

async fn read_capped_body(
    response: &mut reqwest::Response,
    max_bytes: usize,
    progress: Option<&Channel<AnonymousDownloadProgress>>,
) -> Result<Vec<u8>, String> {
    read_capped_body_with_timeouts(
        response,
        max_bytes,
        BODY_IDLE_TIMEOUT,
        body_timeout(max_bytes),
        |received_bytes| {
            if let Some(progress) = progress
                && let Err(error) = progress.send(AnonymousDownloadProgress {
                    received_bytes,
                    total_bytes: max_bytes,
                })
            {
                tracing::debug!(%error, "Anonymous download progress receiver unavailable");
            }
        },
    )
    .await
}

async fn read_capped_body_with_timeouts(
    response: &mut reqwest::Response,
    max_bytes: usize,
    idle_timeout: Duration,
    total_timeout: Duration,
    mut on_progress: impl FnMut(usize),
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err("anonymous response too large".to_string());
    }

    let started_at = Instant::now();
    let deadline = tokio::time::Instant::now() + total_timeout;
    let mut body = Vec::with_capacity(max_bytes);
    let mut last_progress = None;
    on_progress(0);
    loop {
        let chunk = tokio::time::timeout_at(
            deadline.min(tokio::time::Instant::now() + idle_timeout),
            response.chunk(),
        )
        .await
        .map_err(|_| {
            let reason = if tokio::time::Instant::now() >= deadline {
                "transfer deadline"
            } else {
                "read idle timeout"
            };
            format!(
                "anonymous response {reason}: received {}/{} bytes after {} ms",
                body.len(),
                max_bytes,
                started_at.elapsed().as_millis()
            )
        })?
        .map_err(|error| {
            format!(
                "anonymous response read failed: received {}/{} bytes after {} ms: {:?}",
                body.len(),
                max_bytes,
                started_at.elapsed().as_millis(),
                error.without_url()
            )
        })?;
        let Some(chunk) = chunk else { break };
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|next_len| next_len > max_bytes)
        {
            return Err("anonymous response too large".to_string());
        }
        body.extend_from_slice(&chunk);
        let now = Instant::now();
        if body.len() == max_bytes
            || last_progress
                .is_none_or(|at: Instant| now.duration_since(at) >= Duration::from_millis(100))
        {
            on_progress(body.len());
            last_progress = Some(now);
        }
    }
    Ok(body)
}

fn anonymous_api_url(expected_server_url: &str) -> Result<url::Url, String> {
    if expected_server_url.is_empty() || expected_server_url.len() > 2048 {
        return Err("invalid expected server URL".to_string());
    }
    let mut base = url::Url::parse(expected_server_url)
        .map_err(|_| "invalid expected server URL".to_string())?;
    if base.scheme() != "wss"
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.host_str().is_none()
    {
        return Err("invalid expected server URL".to_string());
    }
    base.set_scheme("https")
        .map_err(|_| "invalid expected server URL".to_string())?;
    base.set_path("/");
    base.join("api/anonymous")
        .map_err(|_| "invalid expected server URL".to_string())
}

#[tauri::command]
pub async fn prewarm_anonymous_transport(state: State<'_, AppState>) -> Result<bool, String> {
    let Some(storage) = state.inner().storage() else {
        return Ok(false);
    };
    let Some(server_url) = storage
        .get_text("server_url")
        .await
        .map_err(|error| error.safe_message())?
    else {
        return Ok(false);
    };
    let Ok(api_url) = anonymous_api_url(&server_url) else {
        return Ok(false);
    };
    let Some(tor) = state.inner().tor_manager() else {
        return Ok(false);
    };
    if !tor.is_ready().await {
        return Ok(false);
    }

    let host = api_url.host_str().unwrap_or_default().to_string();
    if host.is_empty() {
        return Ok(false);
    }
    spawn_warm_refill(
        tor.get_socks_port(),
        host.clone(),
        api_url.port_or_known_default().unwrap_or(443),
    );
    if let Some(pir_tor) = state.inner().pir_tor_manager()
        && pir_tor.is_ready().await
    {
        spawn_warm_refill(
            pir_tor.get_socks_port(),
            host,
            api_url.port_or_known_default().unwrap_or(443),
        );
    }
    Ok(true)
}

#[tauri::command]
pub async fn anonymous_api_fetch(
    webview: tauri::Webview,
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<Response, String> {
    anonymous_api_fetch_bytes(webview, state, request).await.map(Response::new)
}

#[tauri::command]
pub async fn anonymous_api_fetch_channel(
    webview: tauri::Webview,
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<usize, String> {
    let channel = request.headers().get("x-qorc-anonymous-response-channel")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<JavaScriptChannelId>().ok())
        .ok_or_else(|| "invalid anonymous response channel".to_string())?
        .channel_on::<_, super::callback_bytes::ByteChunk>(webview.clone());
    let bytes = anonymous_api_fetch_bytes(webview, state, request).await?;
    super::callback_bytes::send_bytes_in_chunks(
        &bytes,
        &channel,
        crate::constants::system::ANONYMOUS_CALLBACK_CHUNK_BYTES,
    )
}

async fn anonymous_api_fetch_bytes(
    webview: tauri::Webview,
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<Vec<u8>, String> {
    let progress = request
        .headers()
        .get(PROGRESS_HEADER)
        .map(|value| {
            value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<JavaScriptChannelId>().ok())
                .map(|channel| channel.channel_on::<_, AnonymousDownloadProgress>(webview))
                .ok_or_else(|| "invalid anonymous progress channel".to_string())
        })
        .transpose()?;
    let id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| "invalid anonymous request id".to_string())?;
    let mut cancellation = RequestCancellation::register(id)?;
    tokio::select! {
        biased;
        _ = cancellation.receiver.wait_for(|cancelled| *cancelled) => Err("anonymous request cancelled".to_string()),
        result = execute_anonymous_api_fetch(state, request, progress.as_ref()) => result,
    }
}

async fn execute_anonymous_api_fetch(
    state: State<'_, AppState>,
    request: Request<'_>,
    progress: Option<&Channel<AnonymousDownloadProgress>>,
) -> Result<Vec<u8>, String> {
    let expected_response_bytes = request
        .headers()
        .get(RESPONSE_BYTES_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|size| valid_response_size(*size) && *size <= RESPONSE_DISCOVERY_BYTES)
        .ok_or_else(|| "invalid expected anonymous response size".to_string())?;
    let request_body = super::binary_body(
        &request,
        REQUEST_SMALL_BYTES.max(REQUEST_LARGE_BYTES).max(REQUEST_PIR_BYTES),
    )
    .map_err(|()| "invalid anonymous request body".to_string())?
    .into_owned();
    if !valid_request_size(request_body.len()) {
        return Err("invalid anonymous request body".to_string());
    }
    let expected_server_url = request
        .headers()
        .get(crate::protocol_keys::EXPECTED_SERVER_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 2048)
        .ok_or_else(|| "invalid expected server URL".to_string())?
        .to_string();
    let use_bulk_tor = uses_bulk_transport(request_body.len(), expected_response_bytes);

    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    let configured_server_url = storage
        .get_text("server_url")
        .await
        .map_err(|error| error.safe_message())?
        .ok_or_else(|| "Server URL not configured".to_string())?;
    if configured_server_url != expected_server_url {
        return Err("server changed before anonymous request".to_string());
    }

    let api_url = anonymous_api_url(&expected_server_url)?;
    let tor = if use_bulk_tor {
        let primary = state
            .inner()
            .tor_manager()
            .ok_or_else(|| "Tor manager not initialized".to_string())?;
        let pir_tor = state
            .inner()
            .pir_tor_manager()
            .ok_or_else(|| "PIR Tor manager not initialized".to_string())?;
        let started = pir_tor
            .ensure_started_from(&primary)
            .await
            .map_err(|_| "Bulk Tor transport failed to start".to_string())?;
        if !started.success {
            return Err("Bulk Tor transport failed to start".to_string());
        }
        if !wait_for_bootstrap(&pir_tor).await {
            return Err("PIR Tor transport unavailable".to_string());
        }
        pir_tor
    } else {
        let primary = state
            .inner()
            .tor_manager()
            .ok_or_else(|| "Tor manager not initialized".to_string())?;
        if !primary.is_ready().await {
            return Err("Tor transport unavailable".to_string());
        }
        primary
    };

    let socks_port = tor.get_socks_port();
    let request_host = api_url.host_str().unwrap_or_default().to_string();
    let request_port = api_url.port_or_known_default().unwrap_or(443);
    if !request_host.is_empty() {
        spawn_warm_refill(socks_port, request_host.clone(), request_port);
    }
    let mut response =
        send_anonymous_request(socks_port, api_url, request_body, HEADER_TIMEOUT).await?;
    if !response.status().is_success() {
        return Err(format!(
            "anonymous request failed with HTTP status {}",
            response.status()
        ));
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value != "application/octet-stream")
    {
        return Err("invalid anonymous response".to_string());
    }

    let response_body = read_capped_body(&mut response, expected_response_bytes, progress).await?;
    if response_body.len() != expected_response_bytes {
        return Err("invalid anonymous response".to_string());
    }
    let current_server_url = storage
        .get_text("server_url")
        .await
        .map_err(|error| error.safe_message())?
        .ok_or_else(|| "Server URL not configured".to_string())?;
    if current_server_url != expected_server_url {
        return Err("server changed during anonymous request".to_string());
    }

    Ok(response_body)
}
