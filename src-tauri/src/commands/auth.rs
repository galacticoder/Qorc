//! Auth Commands

use tauri::State;
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::crypto::random;

/// Device credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub device_id: String,
    pub public_key: String,
    pub key_hash: String,
}

/// Signed challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChallenge {
    pub signature: String,
    pub device_id: String,
}



/// Get device credentials
#[tauri::command]
pub async fn device_get_credentials(
    state: State<'_, AppState>,
) -> Result<DeviceCredentials, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    // Try to load existing credentials
    let existing_id = storage.get("device_id").await
        .map_err(|e| e.safe_message())?;
    let existing_key = storage.get("device_mldsa_public_key").await
        .map_err(|e| e.safe_message())?;
    let existing_hash = storage.get("device_mldsa_key_hash").await
        .map_err(|e| e.safe_message())?;
    
    if let (Some(id), Some(key), Some(hash)) = (existing_id, existing_key, existing_hash) {
        return Ok(DeviceCredentials {
            device_id: id,
            public_key: key,
            key_hash: hash,
        });
    }
    
    // Generate new credentials
    let device_id = format!("device-{}", hex::encode(random::random_bytes(16)));
    
    // Generate ML-DSA-87 keypair
    let keypair = crate::crypto::post_quantum::dilithium_generate_keypair()
        .map_err(|e| format!("PQ key generation failed: {}", e))?;
    
    let public_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &keypair.public_key,
    );
    
    let secret_key_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &keypair.secret_key,
    );
    
    // Generate BLAKE3 key hash
    let key_hash = crate::crypto::hash::blake3(&keypair.public_key);
    let key_hash_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &key_hash,
    );
    
    // Store credentials
    storage.set("device_id", &device_id).await
        .map_err(|e| e.safe_message())?;
    storage.set("device_mldsa_public_key", &public_key_b64).await
        .map_err(|e| e.safe_message())?;
    storage.set("device_mldsa_key_hash", &key_hash_b64).await
        .map_err(|e| e.safe_message())?;
    storage.set("device_mldsa_secret_key", &secret_key_b64).await
        .map_err(|e| e.safe_message())?;
    
    Ok(DeviceCredentials {
        device_id,
        public_key: public_key_b64,
        key_hash: key_hash_b64,
    })
}

/// Sign authentication challenge
#[tauri::command]
pub async fn device_sign_challenge(
    challenge: String,
    state: State<'_, AppState>,
) -> Result<SignedChallenge, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    // Load ML-DSA secret key
    let secret_key_b64 = storage.get("device_mldsa_secret_key").await
        .map_err(|e| e.safe_message())?
        .ok_or_else(|| "No device secret key".to_string())?;
    
    let secret_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &secret_key_b64,
    ).map_err(|e| format!("Invalid secret key: {}", e))?;
    
    // Sign challenge using Dilithium-87
    let signature_bytes = crate::crypto::post_quantum::dilithium_sign(
        challenge.as_bytes(),
        &secret_bytes,
    ).map_err(|e| format!("Dilithium signing failed: {}", e))?;
    
    let device_id = storage.get("device_id").await
        .map_err(|e| e.safe_message())?
        .ok_or_else(|| "No device ID".to_string())?;
    
    Ok(SignedChallenge {
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &signature_bytes,
        ),
        device_id,
    })
}

/// Auth tokens response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
}

/// Refresh authentication tokens
#[tauri::command]
pub async fn auth_refresh_tokens(
    refresh_token: String,
    state: State<'_, AppState>,
) -> Result<AuthTokens, String> {
    let storage = state.inner().storage()
        .ok_or_else(|| "Storage not initialized".to_string())?;
    
    // Get server URL from storage
    let server_url = storage.get("server_url").await
        .map_err(|e| e.safe_message())?
        .ok_or_else(|| "Server URL not configured".to_string())?;
    
    // Construct refresh API URL
    // Convert wss://... to https://...
    let mut api_url = server_url.replace("wss://", "https://");
    if !api_url.ends_with('/') {
        api_url.push('/');
    }
    api_url.push_str("api/auth/refresh");
    
    // Get SOCKS proxy from Tor manager
    let proxy_url = if let Some(tor) = state.inner().tor() {
        let socks_port = tor.get_socks_port();
        format!("socks5h://127.0.0.1:{}", socks_port)
    } else {
        return Err("Tor manager not initialized".to_string());
    };
    
    // Execute request via Tor proxy
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).map_err(|e| e.to_string())?)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let response = client.post(&api_url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "refresh_token": refresh_token
        }))
        .send()
        .await
        .map_err(|e| format!("Token refresh request failed: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("Refresh failed ({}): {}", status, error_body));
    }
    
    let tokens = response.json::<AuthTokens>().await
        .map_err(|e| format!("Invalid token response: {}", e))?;
    
    Ok(tokens)
}
