//! Isolated binary transport for discovery, OPRF, and key transparency

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tauri::{
    State,
    ipc::{Channel, InvokeBody, JavaScriptChannelId, Request, Response},
};
use tokio::sync::watch;
use uuid::Uuid;

use crate::state::AppState;

const WARM_POOL_TARGET: usize = 4;
const WARM_ENTRY_MAX_AGE: Duration = Duration::from_secs(240);
const WARM_CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

struct WarmEntry {
    isolation_user: String,
    warmed_at: Instant,
    target: String,
    socks_port: u16,
}

static WARM_POOL: Mutex<VecDeque<WarmEntry>> = Mutex::new(VecDeque::new());
static WARM_REFILL_RUNNING: LazyLock<Mutex<HashSet<(u16, String)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn new_isolation_user() -> String {
    format!(
        "{}{}",
        crate::protocol_keys::ANONYMOUS_CONNECTION_ID_PREFIX,
        Uuid::new_v4().simple()
    )
}

fn take_warm_isolation_user(socks_port: u16, target: &str) -> Option<String> {
    let mut pool = WARM_POOL.lock().ok()?;
    let now = Instant::now();
    pool.retain(|entry| now.duration_since(entry.warmed_at) < WARM_ENTRY_MAX_AGE);
    let index = pool
        .iter()
        .position(|entry| entry.socks_port == socks_port && entry.target == target)?;
    pool.remove(index).map(|entry| entry.isolation_user)
}

async fn warm_one_circuit(socks_port: u16, host: &str, port: u16) -> Option<String> {
    let isolation_user = new_isolation_user();
    let proxy = format!("127.0.0.1:{}", socks_port);
    let stream = tokio::time::timeout(
        WARM_CONNECT_TIMEOUT,
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
    let refill_key = (socks_port, host.clone());
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
                            .filter(|entry| entry.socks_port == socks_port && entry.target == host)
                            .count();
                        WARM_POOL_TARGET.saturating_sub(matching)
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
                            });
                        }
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

const REQUEST_SMALL_BYTES: usize = 64 * 1024;
const REQUEST_LARGE_BYTES: usize = 512 * 1024;

const REQUEST_PIR_BYTES: usize = 2 * 1024 * 1024;
const RESPONSE_SMALL_BYTES: usize = 64 * 1024;
const RESPONSE_TAG_INDEX_BYTES: usize = 512 * 1024;
const RESPONSE_KEY_TRANSPARENCY_SYNC_BYTES: usize = 2 * 1024 * 1024;
const RESPONSE_PIR_BYTES: usize = 1024 * 1024;
const RESPONSE_AVATAR_BYTES: usize = 4 * 1024 * 1024;
const RESPONSE_DISCOVERY_BYTES: usize = 8912896;
const HEADER_TIMEOUT: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(150);
const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const MIN_BODY_TIMEOUT: Duration = Duration::from_secs(300);
const MIN_TRANSFER_BYTES_PER_SECOND: usize = 16 * 1024;
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
    MIN_BODY_TIMEOUT.max(
        BODY_IDLE_TIMEOUT
            + Duration::from_secs(bytes.div_ceil(MIN_TRANSFER_BYTES_PER_SECOND) as u64),
    )
}

fn anonymous_http_client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .no_gzip()
        .connect_timeout(CONNECT_TIMEOUT);
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    let builder = builder.tcp_user_timeout(None);
    builder
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
) -> Result<Response, String> {
    let expected_response_bytes = request
        .headers()
        .get(RESPONSE_BYTES_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|size| valid_response_size(*size) && *size <= RESPONSE_DISCOVERY_BYTES)
        .ok_or_else(|| "invalid expected anonymous response size".to_string())?;
    let request_body = match request.body() {
        InvokeBody::Raw(body) if valid_request_size(body.len()) => body.clone(),
        _ => return Err("invalid anonymous request body".to_string()),
    };
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
    let host_is_onion = api_url
        .host_str()
        .map(|host| host.to_ascii_lowercase().ends_with(".onion"))
        .unwrap_or(false);
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
    let proxy_url = format!("socks5h://127.0.0.1:{}", socks_port);
    let request_host = api_url.host_str().unwrap_or_default().to_string();
    let request_port = api_url.port_or_known_default().unwrap_or(443);
    let isolation_user =
        take_warm_isolation_user(socks_port, &request_host).unwrap_or_else(new_isolation_user);
    if !request_host.is_empty() {
        spawn_warm_refill(socks_port, request_host.clone(), request_port);
    }
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

    let started_at = Instant::now();
    let request_bytes = request_body.len();
    let mut response = tokio::time::timeout(
        HEADER_TIMEOUT,
        client
            .post(api_url)
            .header("Accept", "application/octet-stream")
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .header(reqwest::header::CONNECTION, "close")
            .body(request_body)
            .send(),
    )
    .await
    .map_err(|_| format!(
        "anonymous response header timeout after {} ms (request bytes: {request_bytes})",
        started_at.elapsed().as_millis(),
    ))?
    .map_err(|error| {
        format!(
            "anonymous request failed before response headers after {} ms (request bytes: {request_bytes}): {:?}",
            started_at.elapsed().as_millis(),
            error.without_url()
        )
    })?;
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

    tracing::info!(
        expected_bytes = expected_response_bytes,
        elapsed_ms = started_at.elapsed().as_millis(),
        "[ANON-HTTP] response headers received"
    );
    let response_body = read_capped_body(&mut response, expected_response_bytes, progress).await?;
    if !valid_response_size(response_body.len()) {
        return Err("invalid anonymous response".to_string());
    }
    tracing::info!(
        received_bytes = response_body.len(),
        elapsed_ms = started_at.elapsed().as_millis(),
        "[ANON-HTTP] response body received"
    );
    let current_server_url = storage
        .get_text("server_url")
        .await
        .map_err(|error| error.safe_message())?
        .ok_or_else(|| "Server URL not configured".to_string())?;
    if current_server_url != expected_server_url {
        return Err("server changed during anonymous request".to_string());
    }

    Ok(Response::new(response_body))
}

#[cfg(test)]
mod tests {
    #[test]
    fn bulk_transport_is_selected_from_transfer_size() {
        assert!(!super::uses_bulk_transport(64 * 1024, 64 * 1024));
        for response_bytes in [
            512 * 1024,
            1024 * 1024,
            2 * 1024 * 1024,
            4 * 1024 * 1024,
            8912896,
        ] {
            assert!(super::uses_bulk_transport(64 * 1024, response_bytes));
        }
        assert!(super::uses_bulk_transport(512 * 1024, 64 * 1024));
        assert!(super::uses_bulk_transport(2 * 1024 * 1024, 1024 * 1024));
    }

    use super::{
        REQUEST_CANCELLATIONS, RESPONSE_DISCOVERY_BYTES, RequestCancellation, anonymous_api_url,
        body_timeout, cancel_anonymous_api_fetch, read_capped_body_with_timeouts,
        valid_request_size, valid_response_size,
    };
    #[cfg(target_os = "linux")]
    use super::{REQUEST_PIR_BYTES, anonymous_http_client_builder};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    #[cfg(target_os = "linux")]
    async fn paused_socks_upload(
        builder: reqwest::ClientBuilder,
        pause: Duration,
        deadline: Duration,
    ) -> Result<reqwest::Response, String> {
        crate::install_rustls_provider();
        let listener = tokio::net::TcpSocket::new_v4().unwrap();
        listener.set_recv_buffer_size(16 * 1024).unwrap();
        listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = listener.listen(1).unwrap();
        let address = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&2));
            socket.write_all(&[5, 2]).await.unwrap();
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 1);
            let mut username = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut username).await.unwrap();
            assert_eq!(username, b"isolated-test");
            let password_len = socket.read_u8().await.unwrap() as usize;
            let mut password = vec![0u8; password_len];
            socket.read_exact(&mut password).await.unwrap();
            assert_eq!(password, b"isolate");
            socket.write_all(&[1, 0]).await.unwrap();
            let mut connect = [0u8; 4];
            socket.read_exact(&mut connect).await.unwrap();
            assert_eq!(connect, [5, 1, 0, 3]);
            let target_len = socket.read_u8().await.unwrap() as usize;
            let mut target = vec![0u8; target_len];
            socket.read_exact(&mut target).await.unwrap();
            assert_eq!(target, b"test.onion");
            assert_eq!(socket.read_u16().await.unwrap(), 80);
            socket
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            tokio::time::sleep(pause).await;
            let mut received = Vec::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = socket.read(&mut buffer).await.unwrap();
                if count == 0 {
                    return;
                }
                received.extend_from_slice(&buffer[..count]);
                if let Some(header_end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                {
                    if received.len() >= header_end + 4 + REQUEST_PIR_BYTES {
                        assert_eq!(received.len(), header_end + 4 + REQUEST_PIR_BYTES);
                        assert!(received[header_end + 4..].iter().all(|byte| *byte == 7));
                        break;
                    }
                }
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest")
                .await
                .unwrap();
        });
        let proxy = reqwest::Proxy::all(format!("socks5h://{address}"))
            .unwrap()
            .basic_auth("isolated-test", "isolate");
        let result = tokio::time::timeout(
            deadline,
            builder
                .proxy(proxy)
                .build()
                .unwrap()
                .post("http://test.onion/api/anonymous")
                .body(vec![7u8; REQUEST_PIR_BYTES])
                .send(),
        )
        .await;
        proxy_task.abort();
        if let Err(error) = proxy_task.await {
            assert!(error.is_cancelled(), "{error}");
        }
        result
            .map_err(|_| "request deadline".to_string())?
            .map_err(|error| format!("{:?}", error.without_url()))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tor_backpressure_cannot_trigger_reqwests_hidden_tcp_deadline() {
        let pause = Duration::from_secs(35);
        let deadline = Duration::from_secs(50);
        let (old, current) = tokio::join!(
            paused_socks_upload(reqwest::Client::builder(), pause, deadline),
            paused_socks_upload(anonymous_http_client_builder(), pause, deadline),
        );
        let old_error = old.unwrap_err();
        assert!(old_error.contains("code: 110"), "{old_error}");
        let response = current.expect("a progressing PIR upload survives SOCKS backpressure");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"test");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stalled_socks_upload_remains_bounded_by_the_request_deadline() {
        let result = paused_socks_upload(
            anonymous_http_client_builder(),
            Duration::from_secs(10),
            Duration::from_millis(100),
        )
        .await;
        assert_eq!(result.unwrap_err(), "request deadline");
    }

    async fn streaming_response(
        delay: Duration,
        total_timeout: Option<Duration>,
    ) -> reqwest::Response {
        crate::install_rustls_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            socket.read(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            for byte in b"test" {
                tokio::time::sleep(delay).await;
                if socket.write_all(&[*byte]).await.is_err() {
                    break;
                }
            }
        });
        let mut builder = reqwest::Client::builder().no_proxy();
        if let Some(timeout) = total_timeout {
            builder = builder.timeout(timeout);
        }
        builder
            .build()
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn progressing_body_outlives_old_request_deadline() {
        let mut old =
            streaming_response(Duration::from_millis(50), Some(Duration::from_millis(90))).await;
        let old_error = read_capped_body_with_timeouts(
            &mut old,
            4,
            Duration::from_millis(300),
            Duration::from_secs(2),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(old_error.contains("received"));
        let mut response = streaming_response(Duration::from_millis(50), None).await;
        let mut received = Vec::new();
        let body = read_capped_body_with_timeouts(
            &mut response,
            4,
            Duration::from_millis(300),
            Duration::from_secs(2),
            |bytes| received.push(bytes),
        )
        .await
        .unwrap();
        assert_eq!(body, b"test");
        assert_eq!(received.first(), Some(&0));
        assert_eq!(received.last(), Some(&4));
        assert!(received.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[tokio::test]
    async fn configured_body_idle_budget_admits_a_tor_stall() {
        let mut response = streaming_response(Duration::from_millis(127), None).await;
        let body = read_capped_body_with_timeouts(
            &mut response,
            4,
            super::BODY_IDLE_TIMEOUT / 1000,
            Duration::from_secs(2),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(body, b"test");
    }

    #[tokio::test]
    async fn stalled_body_reports_progress_and_idle_failure() {
        let mut response = streaming_response(Duration::from_secs(2), None).await;
        let error = read_capped_body_with_timeouts(
            &mut response,
            4,
            Duration::from_millis(50),
            Duration::from_secs(2),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(error.contains("read idle timeout"));
        assert!(error.contains("received 0/4 bytes"));
    }

    #[tokio::test]
    async fn trickling_body_still_has_a_finite_transfer_deadline() {
        let mut response = streaming_response(Duration::from_millis(50), None).await;
        let error = read_capped_body_with_timeouts(
            &mut response,
            4,
            Duration::from_millis(300),
            Duration::from_millis(90),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(error.contains("transfer deadline"));
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_reading() {
        let mut response = streaming_response(Duration::from_millis(50), None).await;
        let error = read_capped_body_with_timeouts(
            &mut response,
            3,
            Duration::from_millis(300),
            Duration::from_secs(2),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(error, "anonymous response too large");
    }

    #[test]
    fn discovery_budget_accounts_for_the_padded_response_size() {
        assert_eq!(
            body_timeout(RESPONSE_DISCOVERY_BYTES),
            Duration::from_secs(724)
        );
        assert_eq!(body_timeout(64 * 1024), Duration::from_secs(300));
        assert_eq!(body_timeout(512 * 1024), Duration::from_secs(300));
    }

    #[test]
    fn cancellation_before_registration_prevents_the_request() {
        let id = Uuid::new_v4();
        cancel_anonymous_api_fetch(id.to_string()).unwrap();
        assert!(
            matches!(RequestCancellation::register(id), Err(error) if error == "anonymous request cancelled")
        );
        assert!(!REQUEST_CANCELLATIONS.lock().unwrap().contains_key(&id));
    }

    #[tokio::test]
    async fn cancellation_interrupts_an_active_native_request_and_cleans_up() {
        let id = Uuid::new_v4();
        let mut cancellation = RequestCancellation::register(id).unwrap();
        assert!(RequestCancellation::register(id).is_err());
        cancel_anonymous_api_fetch(id.to_string()).unwrap();
        cancellation
            .receiver
            .wait_for(|cancelled| *cancelled)
            .await
            .unwrap();
        drop(cancellation);
        assert!(!REQUEST_CANCELLATIONS.lock().unwrap().contains_key(&id));
    }

    #[test]
    fn anonymous_url_is_fixed_and_requires_wss() {
        let mapped =
            anonymous_api_url("wss://example.com:8443/private/socket").expect("valid WSS URL");
        assert_eq!(mapped.as_str(), "https://example.com:8443/api/anonymous");

        assert!(anonymous_api_url("ws://example.com/socket").is_err());
        assert!(anonymous_api_url("https://example.com/socket").is_err());
        assert!(anonymous_api_url("wss://user@example.com/socket").is_err());
        assert!(anonymous_api_url("wss://example.com/socket?q=1").is_err());
        assert!(anonymous_api_url("wss://example.com/socket#fragment").is_err());
    }

    #[test]
    fn only_protocol_size_classes_are_accepted() {
        assert!(valid_request_size(64 * 1024));
        assert!(valid_request_size(512 * 1024));
        assert!(!valid_request_size(64 * 1024 - 1));
        assert!(valid_response_size(512 * 1024));
        assert!(valid_response_size(1024 * 1024));
        assert!(valid_response_size(2 * 1024 * 1024));
        assert!(valid_response_size(8912896));
        assert!(!valid_response_size(8912896 - 1));
    }
}
