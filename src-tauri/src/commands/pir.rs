//! Local discovery PIR client commands

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use tauri::State;
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::state::AppState;

fn candidate_binary_names() -> Vec<&'static str> {
    if cfg!(windows) {
        vec!["qor-pir-client.exe"]
    } else {
        vec!["qor-pir-client"]
    }
}

fn candidate_paths(app: &AppHandle) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(raw) = std::env::var("QOR_PIR_CLIENT_BIN") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            paths.push(PathBuf::from(trimmed));
        }
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        for name in candidate_binary_names() {
            paths.push(resource_dir.join(name));
            paths.push(resource_dir.join("bin").join(name));
            paths.push(resource_dir.join("binaries").join(name));
        }
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            for name in candidate_binary_names() {
                paths.push(dir.join(name));
                paths.push(dir.join("bin").join(name));
                paths.push(dir.join("binaries").join(name));
            }
        }
    }

    paths
}

fn find_pir_client_binary(app: &AppHandle) -> Result<PathBuf, String> {
    for path in candidate_paths(app) {
        if path.is_file() {
            return Ok(path);
        }
    }
    Err("Local PIR client binary is required and was not found".to_string())
}

// PIR client daemon
const PIR_DAEMON_MAX_FRAME_BYTES: u32 = 256 << 20;
const PIR_DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);

struct PirDaemon {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}

static PIR_DAEMON: OnceLock<tokio::sync::Mutex<Option<PirDaemon>>> = OnceLock::new();

fn pir_daemon_slot() -> &'static tokio::sync::Mutex<Option<PirDaemon>> {
    PIR_DAEMON.get_or_init(|| tokio::sync::Mutex::new(None))
}

fn spawn_pir_daemon(app: &AppHandle) -> Result<PirDaemon, String> {
    let binary = find_pir_client_binary(app)?;
    let mut child = Command::new(binary)
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to start local PIR client daemon: {e}"))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "PIR client daemon stdin unavailable".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "PIR client daemon stdout unavailable".to_string())?;

    Ok(PirDaemon {
        child,
        stdin,
        stdout: tokio::io::BufReader::new(stdout),
        next_id: 1,
    })
}

async fn pir_daemon_exchange(daemon: &mut PirDaemon, request: &Value) -> Result<Value, String> {
    let id = daemon.next_id;
    daemon.next_id = daemon.next_id.wrapping_add(1);

    let mut tagged = match request {
        Value::Object(map) => map.clone(),
        _ => return Err("pir_daemon_bad_request".to_string()),
    };
    tagged.insert("id".to_string(), Value::from(id));
    let payload = serde_json::to_vec(&Value::Object(tagged)).map_err(|e| e.to_string())?;
    if payload.len() as u64 > PIR_DAEMON_MAX_FRAME_BYTES as u64 {
        return Err("pir_daemon_request_too_large".to_string());
    }

    daemon
        .stdin
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(|e| format!("pir_daemon_write_failed: {e}"))?;
    daemon
        .stdin
        .write_all(&payload)
        .await
        .map_err(|e| format!("pir_daemon_write_failed: {e}"))?;
    daemon
        .stdin
        .flush()
        .await
        .map_err(|e| format!("pir_daemon_flush_failed: {e}"))?;

    let mut len_buf = [0u8; 4];
    daemon
        .stdout
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("pir_daemon_read_failed: {e}"))?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > PIR_DAEMON_MAX_FRAME_BYTES {
        return Err("pir_daemon_bad_frame".to_string());
    }
    let mut buf = vec![0u8; len as usize];
    daemon
        .stdout
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("pir_daemon_read_failed: {e}"))?;

    let parsed: Value =
        serde_json::from_slice(&buf).map_err(|_| "pir_daemon_invalid_json".to_string())?;
    if parsed.get("id").and_then(Value::as_u64) != Some(id) {
        return Err("pir_daemon_response_mismatch".to_string());
    }
    Ok(parsed)
}

/// Sends one request to the persistent daemon transparently spawning/respawning if is not running or died
async fn pir_daemon_call(app: &AppHandle, request: Value) -> Result<Value, String> {
    let mut guard = pir_daemon_slot().lock().await;
    let mut last_err = String::from("pir_daemon_unavailable");

    for _ in 0..2 {
        if guard.is_none() {
            match spawn_pir_daemon(app) {
                Ok(daemon) => *guard = Some(daemon),
                Err(e) => {
                    last_err = e;
                    continue;
                }
            }
        }

        let daemon = guard.as_mut().expect("daemon present");
        match tokio::time::timeout(
            PIR_DAEMON_REQUEST_TIMEOUT,
            pir_daemon_exchange(daemon, &request),
        )
        .await
        {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(e)) => last_err = e,
            Err(_) => last_err = "pir_daemon_timeout".to_string(),
        }

        if let Some(mut dead) = guard.take() {
            let _ = dead.child.start_kill();
        }
    }

    Err(last_err)
}

fn pir_daemon_unwrap(parsed: Value) -> Result<Value, String> {
    if parsed.get("success").and_then(Value::as_bool) != Some(true) {
        let code = parsed
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("local_pir_client_failed");
        return Err(code.to_string());
    }
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Build an opaque PIR request for one record index
#[tauri::command]
pub async fn pir_query_record(
    app: AppHandle,
    parameter_id: String,
    record_count: u64,
    record_size: u64,
    public_params: String,
    index: u64,
) -> Result<Value, String> {
    let request = json!({
        "operation": "query-record",
        "parameterId": parameter_id,
        "recordCount": record_count,
        "recordSize": record_size,
        "publicParams": public_params,
        "index": index,
    });
    pir_daemon_unwrap(pir_daemon_call(&app, request).await?)
}

/// Recover the record from worker's opaque response using secret kept under handle
#[tauri::command]
pub async fn pir_recover_record(
    app: AppHandle,
    handle: String,
    response: String,
) -> Result<Value, String> {
    let request = json!({
        "operation": "recover-record",
        "handle": handle,
        "response": response,
    });
    pir_daemon_unwrap(pir_daemon_call(&app, request).await?)
}

/// Shared transport for anonymous discovery/avatar ops over dedicated isolated Tor circuit
async fn isolated_tor_post(
    app: &AppState,
    path: &str,
    body: &Value,
    circuit: &str,
) -> Result<Value, String> {
    let storage = app
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    let server_url = storage
        .get("server_url")
        .await
        .map_err(|e| e.safe_message())?
        .ok_or_else(|| "Server URL not configured".to_string())?;

    let mut base = server_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");
    if !base.ends_with('/') {
        base.push('/');
    }
    let api_url = format!("{base}api/{path}");

    let tor = app
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    let proxy_url = format!("socks5h://127.0.0.1:{}", tor.get_socks_port());

    let mut last_err = String::from("discovery request failed");
    for attempt in 0u32..3 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(600 * attempt as u64)).await;
        }

        let attempt_circuit = if attempt == 0 {
            circuit.to_string()
        } else {
            format!("{circuit}-r{attempt}")
        };
        let proxy = match reqwest::Proxy::all(&proxy_url) {
            Ok(p) => p.basic_auth(&attempt_circuit, "isolate"),
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };

        // server identity is authenticated end to end
        let client = match reqwest::Client::builder()
            .proxy(proxy)
            .danger_accept_invalid_certs(true)
            .http1_only()
            .timeout(std::time::Duration::from_secs(45))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                last_err = format!("Failed to create HTTP client: {e}");
                continue;
            }
        };

        match client
            .post(&api_url)
            .header("Accept", "application/json")
            .header(reqwest::header::CONNECTION, "close")
            .json(body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    return Err(format!("discovery request failed ({status})"));
                }
                
                match response.json::<Value>().await {
                    Ok(value) => return Ok(value),
                    Err(e) => {
                        last_err = format!("invalid discovery response: {e}");
                    }
                }
            }
            Err(e) => {
                last_err = format!("discovery request failed: {e}");
            }
        }
    }
    Err(last_err)
}

/// Tier-1 discovery PIR query
#[tauri::command]
pub async fn pir_query_fetch(
    state: State<'_, AppState>,
    epoch_id: String,
    query: String,
) -> Result<Value, String> {
    isolated_tor_post(
        state.inner(),
        "pir/query",
        &serde_json::json!({ "epochId": epoch_id, "query": query }),
        "qor-discovery-pir",
    )
    .await
}

/// discovery control op
#[tauri::command]
pub async fn discovery_api_fetch(
    state: State<'_, AppState>,
    path: String,
    body: String,
) -> Result<Value, String> {
    // Route each concern onto its own isolated circuit so server cant link client's avatar publishing
    let circuit = match path.as_str() {
        "avatar/blob/put" => "qor-avatar-pub",
        "avatar/blob/get" | "avatar/pool" => "qor-avatar-fetch",
        "oprf/evaluate" => "qor-discovery-oprf",
        "pir/manifest" | "discovery/bucket" => "qor-discovery-pir",
        _ => return Err("unsupported_discovery_path".to_string()),
    };
    let body_val: Value =
        serde_json::from_str(&body).map_err(|e| format!("invalid request body json: {e}"))?;
    isolated_tor_post(state.inner(), &path, &body_val, circuit).await
}
