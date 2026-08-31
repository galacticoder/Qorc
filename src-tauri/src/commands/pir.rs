//! Client side PIR driven through `qorc-pir-client` sidecar

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use tauri::Manager;

use crate::error::{QorcError, QorcResult};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_pir_client.rs"));
}

const OP_QUERY: u8 = 1;
const OP_DECODE: u8 = 2;
const OP_DISCARD: u8 = 3;
const OP_QUERY_BATCH: u8 = 4;
const OP_DECODE_BATCH: u8 = 5;
const STATUS_OK: u8 = 0;

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: u32 = 1 << 20;
const MAX_ENTRY_BYTES: u32 = 1 << 20;
const MAX_BATCH_QUERIES: usize = 16;

static SIDECAR: Mutex<Option<Child>> = Mutex::new(None);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PirQuery {
    pub session_id: u32,
    pub query: String,
    pub pub_params: String,
}

fn embedded_file_matches(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file()
        || metadata.len() != embedded::EMBEDDED_PIR_CLIENT.len() as u64
    {
        return false;
    }
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    blake3::hash(&bytes).as_bytes() == &embedded::EMBEDDED_PIR_CLIENT_HASH
}

fn secure_embedded_directory(path: &Path) -> QorcResult<()> {
    fs::create_dir_all(path)
        .map_err(|_| QorcError::Internal("PIR runtime directory is unavailable".to_string()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| QorcError::Internal("PIR runtime directory is unavailable".to_string()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(QorcError::Internal(
            "PIR runtime directory is invalid".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(QorcError::Internal(
                "PIR runtime directory has the wrong owner".to_string(),
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            QorcError::Internal("PIR runtime directory permissions failed".to_string())
        })?;
    }

    Ok(())
}

fn write_embedded_client(path: &Path) -> QorcResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| QorcError::Internal("Invalid PIR runtime path".to_string()))?;
    let temp = parent.join(format!(
        ".qorc-pir-client-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> QorcResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(&temp)
            .map_err(|_| QorcError::Internal("PIR client extraction failed".to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(|_| QorcError::Internal("PIR client permissions failed".to_string()))?;
        }
        file.write_all(embedded::EMBEDDED_PIR_CLIENT)
            .and_then(|_| file.sync_all())
            .map_err(|_| QorcError::Internal("PIR client extraction failed".to_string()))?;
        drop(file);

        if path.exists() && !embedded_file_matches(path) {
            fs::remove_file(path).map_err(|_| {
                QorcError::Internal("Invalid PIR client cannot be replaced".to_string())
            })?;
        }
        match fs::rename(&temp, path) {
            Ok(()) => {}
            Err(_) if embedded_file_matches(path) => {}
            Err(_) => {
                return Err(QorcError::Internal(
                    "PIR client installation failed".to_string(),
                ));
            }
        }
        if !embedded_file_matches(path) {
            return Err(QorcError::Internal(
                "PIR client integrity verification failed".to_string(),
            ));
        }
        Ok(())
    })();
    if temp.exists() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn materialize_embedded_client(directory: &Path) -> QorcResult<PathBuf> {
    secure_embedded_directory(&directory)?;
    let hash_prefix = hex::encode(&embedded::EMBEDDED_PIR_CLIENT_HASH[..8]);
    let base_name = embedded::EMBEDDED_PIR_CLIENT_FILE_NAME;
    let file_name = match base_name.rsplit_once('.') {
        Some((stem, extension)) => format!("{stem}-{hash_prefix}.{extension}"),
        None => format!("{base_name}-{hash_prefix}"),
    };
    let path = directory.join(file_name);
    if !embedded_file_matches(&path) {
        write_embedded_client(&path)?;
    }
    Ok(path)
}

fn sidecar_path(app: &tauri::AppHandle) -> QorcResult<PathBuf> {
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|_| QorcError::Internal("App cache directory is unavailable".to_string()))?;
    materialize_embedded_client(&cache.join("native").join("pir"))
}

fn validation_started(app: &tauri::AppHandle) -> QorcResult<()> {
    let mut guard = SIDECAR
        .lock()
        .map_err(|_| QorcError::Internal("PIR lock".into()))?;
    if let Some(child) = guard.as_mut() {
        if matches!(child.try_wait(), Ok(None)) {
            return Ok(());
        }
    }
    let child = Command::new(sidecar_path(app)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| QorcError::Internal("PIR sidecar failed to start".to_string()))?;
    *guard = Some(child);
    Ok(())
}

fn call(op: u8, payload: &[u8]) -> QorcResult<Vec<u8>> {
    let mut guard = SIDECAR
        .lock()
        .map_err(|_| QorcError::Internal("PIR lock".into()))?;
    let child = guard
        .as_mut()
        .ok_or_else(|| QorcError::Internal("PIR sidecar is not running".to_string()))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| QorcError::Internal("PIR sidecar stdin closed".to_string()))?;
    let length = (payload.len() + 1) as u32;
    stdin
        .write_all(&length.to_le_bytes())
        .and_then(|_| stdin.write_all(&[op]))
        .and_then(|_| stdin.write_all(payload))
        .and_then(|_| stdin.flush())
        .map_err(|_| QorcError::Internal("PIR sidecar write failed".to_string()))?;

    let stdout = child
        .stdout
        .as_mut()
        .ok_or_else(|| QorcError::Internal("PIR sidecar stdout closed".to_string()))?;
    let mut header = [0u8; 4];
    stdout
        .read_exact(&mut header)
        .map_err(|_| QorcError::Internal("PIR sidecar read failed".to_string()))?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(QorcError::Internal(
            "PIR sidecar sent an invalid frame".to_string(),
        ));
    }
    let mut frame = vec![0u8; length];
    stdout
        .read_exact(&mut frame)
        .map_err(|_| QorcError::Internal("PIR sidecar read failed".to_string()))?;

    if frame[0] != STATUS_OK {
        return Err(QorcError::Internal(
            "PIR sidecar rejected the request".to_string(),
        ));
    }
    Ok(frame[1..].to_vec())
}

#[tauri::command]
pub async fn pir_generate_query(
    app: tauri::AppHandle,
    count: u32,
    entry_bytes: u32,
    target_row: u32,
) -> QorcResult<PirQuery> {
    if count == 0 || count > MAX_RECORDS || entry_bytes == 0 || entry_bytes > MAX_ENTRY_BYTES {
        return Err(QorcError::Internal("Invalid PIR database shape".to_string()));
    }
    if target_row >= count.next_power_of_two().max(2048) {
        return Err(QorcError::Internal("Invalid PIR row".to_string()));
    }
    validation_started(&app)?;

    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&entry_bytes.to_le_bytes());
    payload.extend_from_slice(&target_row.to_le_bytes());

    parse_query_response(call(OP_QUERY, &payload)?)
}

fn parse_query_response(response: Vec<u8>) -> QorcResult<PirQuery> {
    if response.len() < 12 {
        return Err(QorcError::Internal(
            "PIR sidecar returned a short query".to_string(),
        ));
    }
    let session_id = u32::from_le_bytes(response[0..4].try_into().unwrap());
    let query_len = u32::from_le_bytes(response[4..8].try_into().unwrap()) as usize;
    let params_len = u32::from_le_bytes(response[8..12].try_into().unwrap()) as usize;
    if session_id == 0 || response.len() != 12 + query_len + params_len {
        return Err(QorcError::Internal(
            "PIR sidecar returned a malformed query".to_string(),
        ));
    }
    Ok(PirQuery {
        session_id,
        query: BASE64.encode(&response[12..12 + query_len]),
        pub_params: BASE64.encode(&response[12 + query_len..]),
    })
}

#[tauri::command]
pub async fn pir_generate_batch_query(
    app: tauri::AppHandle,
    count: u32,
    entry_bytes: u32,
    target_rows: Vec<u32>,
) -> QorcResult<PirQuery> {
    if count == 0
        || count > MAX_RECORDS
        || entry_bytes == 0
        || entry_bytes > MAX_ENTRY_BYTES
        || target_rows.is_empty()
        || target_rows.len() > MAX_BATCH_QUERIES
    {
        return Err(QorcError::Internal("Invalid PIR database shape".to_string()));
    }
    let padded_count = count.next_power_of_two().max(2048);
    if target_rows
        .iter()
        .any(|target_row| *target_row >= padded_count)
    {
        return Err(QorcError::Internal("Invalid PIR row".to_string()));
    }
    validation_started(&app)?;

    let mut payload = Vec::with_capacity(12 + target_rows.len() * 4);
    payload.extend_from_slice(&count.to_le_bytes());
    payload.extend_from_slice(&entry_bytes.to_le_bytes());
    payload.extend_from_slice(&(target_rows.len() as u32).to_le_bytes());
    for target_row in target_rows {
        payload.extend_from_slice(&target_row.to_le_bytes());
    }
    parse_query_response(call(OP_QUERY_BATCH, &payload)?)
}

fn decode_response(op: u8, response: String, session_id: u32) -> QorcResult<String> {
    if session_id == 0 {
        return Err(QorcError::Internal("Invalid PIR session".to_string()));
    }
    let bytes = BASE64
        .decode(&response)
        .map_err(|_| QorcError::Internal("Invalid PIR response encoding".to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(QorcError::Internal("Invalid PIR response".to_string()));
    }
    let mut payload = Vec::with_capacity(4 + bytes.len());
    payload.extend_from_slice(&session_id.to_le_bytes());
    payload.extend_from_slice(&bytes);
    Ok(BASE64.encode(call(op, &payload)?))
}

#[tauri::command]
pub async fn pir_decode_response(response: String, session_id: u32) -> QorcResult<String> {
    decode_response(OP_DECODE, response, session_id)
}

#[tauri::command]
pub async fn pir_decode_batch_response(response: String, session_id: u32) -> QorcResult<String> {
    decode_response(OP_DECODE_BATCH, response, session_id)
}

#[tauri::command]
pub async fn pir_discard_query(session_id: u32) -> QorcResult<()> {
    if session_id == 0 {
        return Err(QorcError::Internal("Invalid PIR session".to_string()));
    }
    call(OP_DISCARD, &session_id.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{embedded, embedded_file_matches, materialize_embedded_client};

    #[test]
    fn embedded_pir_client_extracts_and_repairs_by_hash() {
        let directory = std::env::temp_dir().join(format!(
            "qorc-embedded-pir-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let path = materialize_embedded_client(&directory).expect("extract embedded PIR client");
        assert!(embedded_file_matches(&path));
        assert_eq!(std::fs::read(&path).unwrap(), embedded::EMBEDDED_PIR_CLIENT);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }

        let mut child = std::process::Command::new(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start extracted PIR client");
        drop(child.stdin.take());
        assert!(
            child
                .wait()
                .expect("wait for extracted PIR client")
                .success()
        );

        std::fs::write(&path, b"corrupt").unwrap();
        let repaired = materialize_embedded_client(&directory).expect("repair embedded PIR client");
        assert_eq!(repaired, path);
        assert!(embedded_file_matches(&repaired));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
