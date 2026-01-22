//! Secure file operations

use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::error::{QorError, QorResult};

/// Ensure directory exists with specified permissions
pub async fn ensure_dir(path: &Path, mode: u32) -> QorResult<()> {
    if !path.exists() {
        fs::create_dir_all(path).await?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perms).await?;
    }

    Ok(())
}

/// Atomic write to file
pub async fn atomic_write(path: &Path, data: &[u8], mode: u32) -> QorResult<()> {
    let parent = path.parent().ok_or_else(|| {
        QorError::FileOperationFailed("Cannot determine parent directory".to_string())
    })?;

    // Create temp file in same directory
    let temp_path = parent.join(format!(".tmp_{}", uuid::Uuid::new_v4()));

    // Write to temp file
    let mut file = fs::File::create(&temp_path).await?;
    file.write_all(data).await?;
    file.sync_all().await?;
    drop(file);

    // Set permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(&temp_path, perms).await?;
    }

    // Atomic rename
    fs::rename(&temp_path, path).await?;

    Ok(())
}

/// Read file contents
pub async fn read_file(path: &Path) -> QorResult<Vec<u8>> {
    fs::read(path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            QorError::FileOperationFailed(format!("File not found: {}", path.display()))
        } else {
            QorError::from(e)
        }
    })
}

/// Remove file
pub async fn remove_file(path: &Path) -> QorResult<()> {
    if path.exists() {
        fs::remove_file(path).await?;
    }
    Ok(())
}

/// List files in directory
pub async fn list_files(dir: &Path) -> QorResult<Vec<String>> {
    let mut files = Vec::new();
    let mut entries = fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        if let Some(name) = entry.file_name().to_str() {
            files.push(name.to_string());
        }
    }

    Ok(files)
}

/// Convert key to safe filename
pub fn to_safe_filename(key: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(key.as_bytes())
}

/// Convert safe filename back to key
pub fn from_safe_filename(safe_name: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(safe_name)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| safe_name.to_string())
}
