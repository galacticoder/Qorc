//! Isolated binary transport for discovery, OPRF, and key transparency

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};
use tauri::{
    State,
    ipc::{InvokeBody, Request, Response},
};
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
const MAX_RESPONSE_BYTES: usize = RESPONSE_DISCOVERY_BYTES;
const ANONYMOUS_TRANSPORT_LANE_HEADER: &str = "x-qorc-anonymous-transport-lane";
const PIR_TRANSPORT_LANE: &str = "pir";

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
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err("anonymous response too large".to_string());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "failed to read anonymous response".to_string())?
    {
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|next_len| next_len > max_bytes)
        {
            return Err("anonymous response too large".to_string());
        }
        body.extend_from_slice(&chunk);
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
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<Response, String> {
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
    let use_pir_tor = request
        .headers()
        .get(ANONYMOUS_TRANSPORT_LANE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == PIR_TRANSPORT_LANE);

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
    let tor = if use_pir_tor {
        let primary = state
            .inner()
            .tor_manager()
            .ok_or_else(|| "Tor manager not initialized".to_string())?;
        let pir_tor = state
            .inner()
            .pir_tor_manager()
            .ok_or_else(|| "PIR Tor manager not initialized".to_string())?;
        if !pir_tor.is_running() {
            pir_tor
                .mirror_configuration_from(&primary)
                .await
                .map_err(|_| "PIR Tor configuration unavailable".to_string())?;
            let started = pir_tor
                .start()
                .await
                .map_err(|_| "PIR Tor transport failed to start".to_string())?;
            if !started.success {
                return Err("PIR Tor transport failed to start".to_string());
            }
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
    let mut builder = reqwest::Client::builder()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .no_gzip()
        .timeout(Duration::from_secs(180));
    if host_is_onion {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder
        .build()
        .map_err(|_| "failed to create anonymous transport".to_string())?;

    let mut response = client
        .post(api_url)
        .header("Accept", "application/octet-stream")
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .header(reqwest::header::CONNECTION, "close")
        .body(request_body)
        .send()
        .await
        .map_err(|_| "anonymous request failed".to_string())?;
    if !response.status().is_success() {
        return Err("anonymous request failed".to_string());
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value != "application/octet-stream")
    {
        return Err("invalid anonymous response".to_string());
    }

    let response_body = read_capped_body(&mut response, MAX_RESPONSE_BYTES).await?;
    if !valid_response_size(response_body.len()) {
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

    Ok(Response::new(response_body))
}

#[cfg(test)]
mod tests {
    use super::{anonymous_api_url, valid_request_size, valid_response_size};

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
