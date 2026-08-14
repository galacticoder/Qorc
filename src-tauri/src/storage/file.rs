//! Secure file operations

use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{QorError, QorResult};

fn invalid_private_path(message: &str) -> QorError {
    QorError::FileOperationFailed(message.to_string())
}

pub fn validate_private_file_metadata(metadata: &std::fs::Metadata) -> QorResult<()> {
    if !metadata.file_type().is_file() {
        return Err(invalid_private_path(
            "Secure storage path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid_private_path(
                "Secure storage file has an invalid owner",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid_private_path(
                "Secure storage file permissions are too broad",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let mut source: Vec<u16> = temp_path.as_os_str().encode_wide().collect();
    source.push(0);
    let mut destination: Vec<u16> = path.as_os_str().encode_wide().collect();
    destination.push(0);
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
async fn replace_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    fs::rename(temp_path, path).await
}

pub async fn ensure_dir(path: &Path, mode: u32) -> QorResult<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(invalid_private_path(
                "Secure storage path is not a directory",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).await?;
        }
        Err(error) => return Err(error.into()),
    }

    let metadata = fs::symlink_metadata(path).await?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_private_path(
            "Secure storage path is not a directory",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid_private_path(
                "Secure storage directory has an invalid owner",
            ));
        }
        let perms = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perms).await?;
    }

    Ok(())
}

pub async fn atomic_write(path: &Path, data: &[u8], mode: u32) -> QorResult<()> {
    let parent = path.parent().ok_or_else(|| {
        QorError::FileOperationFailed("Cannot determine parent directory".to_string())
    })?;
    ensure_dir(parent, 0o700).await?;

    let temp_path = parent.join(format!(".tmp_{}", uuid::Uuid::new_v4()));

    let result = async {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options
                .mode(mode)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temp_path).await?;

        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);

        match fs::symlink_metadata(path).await {
            Ok(metadata) => validate_private_file_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        #[cfg(target_os = "windows")]
        replace_file(&temp_path, path)?;
        #[cfg(not(target_os = "windows"))]
        replace_file(&temp_path, path).await?;

        #[cfg(unix)]
        {
            let parent_dir = fs::File::open(parent).await?;
            parent_dir.sync_all().await?;
        }

        Ok::<(), QorError>(())
    }
    .await;

    if result.is_err() {
        let _ = fs::remove_file(&temp_path).await;
    }
    result
}

pub async fn atomic_write_if_absent(path: &Path, data: &[u8], mode: u32) -> QorResult<bool> {
    let parent = path.parent().ok_or_else(|| {
        QorError::FileOperationFailed("Cannot determine parent directory".to_string())
    })?;
    ensure_dir(parent, 0o700).await?;

    let temp_path = parent.join(format!(".tmp_{}", uuid::Uuid::new_v4()));
    let result = async {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options
                .mode(mode)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temp_path).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);

        let inserted = match fs::hard_link(&temp_path, path).await {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };

        #[cfg(unix)]
        {
            let parent_dir = fs::File::open(parent).await?;
            parent_dir.sync_all().await?;
        }

        Ok::<bool, QorError>(inserted)
    }
    .await;

    let cleanup = fs::remove_file(&temp_path).await;
    if let Err(error) = cleanup
        && error.kind() != std::io::ErrorKind::NotFound
        && result.is_ok()
    {
        return Err(error.into());
    }
    result
}

pub async fn read_file_bounded(path: &Path, max_bytes: usize) -> QorResult<Vec<u8>> {
    let link_metadata = fs::symlink_metadata(path).await?;
    validate_private_file_metadata(&link_metadata)?;
    if link_metadata.len() > max_bytes as u64 {
        return Err(invalid_private_path(
            "Encrypted storage item exceeds its size limit",
        ));
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).await?;
    let metadata = file.metadata().await?;
    validate_private_file_metadata(&metadata)?;
    if metadata.len() > max_bytes as u64 {
        return Err(invalid_private_path(
            "Encrypted storage item exceeds its size limit",
        ));
    }
    let mut limited = file.take((max_bytes as u64).saturating_add(1));
    let mut data = Vec::with_capacity(max_bytes.min(64 * 1024));
    limited.read_to_end(&mut data).await?;
    if data.len() > max_bytes {
        return Err(QorError::FileOperationFailed(
            "Encrypted storage item exceeds its size limit".to_string(),
        ));
    }
    Ok(data)
}

/// Remove file
pub async fn remove_file(path: &Path) -> QorResult<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) => {
            validate_private_file_metadata(&metadata)?;
            fs::remove_file(path).await?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub async fn private_file_exists(path: &Path) -> QorResult<bool> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) => {
            validate_private_file_metadata(&metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub async fn remove_stale_temp_files(dir: &Path) -> QorResult<()> {
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(name) => name.to_string(),
            None => continue,
        };
        let Some(identifier) = name.strip_prefix(".tmp_") else {
            continue;
        };
        if uuid::Uuid::parse_str(identifier).is_err() {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).await?;
        if metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            fs::remove_file(path).await?;
        } else {
            return Err(invalid_private_path(
                "Secure storage contains an invalid temporary item",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_clobber_write_keeps_one_concurrent_winner() {
        let dir = std::env::temp_dir().join(format!("qor-storage-test-{}", uuid::Uuid::new_v4()));
        ensure_dir(&dir, 0o700).await.unwrap();
        let path = dir.join("master.key");
        let first = [0x11; 64];
        let second = [0x22; 64];

        let (first_result, second_result) = tokio::join!(
            atomic_write_if_absent(&path, &first, 0o600),
            atomic_write_if_absent(&path, &second, 0o600),
        );
        let first_inserted = first_result.unwrap();
        let second_inserted = second_result.unwrap();
        assert_ne!(first_inserted, second_inserted);

        let stored = read_file_bounded(&path, 64).await.unwrap();
        assert_eq!(stored, if first_inserted { first } else { second });
        fs::remove_dir_all(dir).await.unwrap();
    }
}
