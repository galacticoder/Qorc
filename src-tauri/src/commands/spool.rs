//! Offline message spool snapshot fetch

use serde_json::Value;
use tauri::State;

use crate::state::AppState;

#[tauri::command]
pub async fn fetch_spool_snapshot(state: State<'_, AppState>) -> Result<Value, String> {
    let storage = state
        .inner()
        .storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    let server_url = storage
        .get("server_url")
        .await
        .map_err(|e| e.safe_message())?
        .ok_or_else(|| "Server URL not configured".to_string())?;

    let mut api_url = server_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");
    if !api_url.ends_with('/') {
        api_url.push('/');
    }
    api_url.push_str("api/spool/snapshot");

    let tor = state
        .inner()
        .tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    let proxy_url = format!("socks5h://127.0.0.1:{}", tor.get_socks_port());

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?)
        .danger_accept_invalid_certs(true)
        .http1_only()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(&api_url)
        .header("Accept", "application/json")
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .map_err(|e| format!("Spool snapshot request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Spool snapshot failed ({})", response.status()));
    }

    response
        .json::<Value>()
        .await
        .map_err(|e| format!("Invalid spool snapshot response: {}", e))
}
