//! Platform packaging/launch for isolated PIR client.
use crate::error::{QorcError, QorcResult};
#[cfg(not(target_os = "android"))]
use std::fs::{self, OpenOptions};
#[cfg(not(target_os = "android"))]
use std::io::Write;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_pir_client.rs"));
}

#[cfg(not(target_os = "android"))]
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

#[cfg(not(target_os = "android"))]
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

#[cfg(not(target_os = "android"))]
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

#[cfg(not(target_os = "android"))]
pub(crate) fn materialize_embedded_client(directory: &Path) -> QorcResult<PathBuf> {
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

#[cfg(target_os = "android")]
fn installed_client_path() -> QorcResult<PathBuf> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let path =
        crate::tor::android_native_library_dir()?.join(embedded::EMBEDDED_PIR_CLIENT_FILE_NAME);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(QorcError::Verification(
            "Android PIR executable is not an installed regular file".into(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| QorcError::Verification("Invalid Android PIR path".into()))?;
    if !metadata.is_file()
        || metadata.len() != embedded::EMBEDDED_PIR_CLIENT_LEN
        || metadata.uid() == unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.permissions().mode() & 0o111 == 0
        || unsafe { libc::access(name.as_ptr(), libc::W_OK) } == 0
    {
        return Err(QorcError::Verification(
            "Android PIR executable is writable, app-owned, or invalid".into(),
        ));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(file.take(embedded::EMBEDDED_PIR_CLIENT_LEN + 1))?;
    if hasher.finalize().as_bytes() != &embedded::EMBEDDED_PIR_CLIENT_HASH {
        return Err(QorcError::Verification(
            "Android PIR executable failed BLAKE3 verification".into(),
        ));
    }
    Ok(path)
}

pub(crate) fn sidecar_command(cache_directory: &Path) -> QorcResult<Command> {
    #[cfg(target_os = "android")]
    let path = {
        let _ = cache_directory;
        installed_client_path()?
    };
    #[cfg(not(target_os = "android"))]
    let path = materialize_embedded_client(&cache_directory.join("native").join("pir"))?;
    let mut command = Command::new(&path);
    #[cfg(target_os = "windows")]
    command.creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
    #[cfg(target_os = "android")]
    command.env_clear().env("PATH", "/system/bin").current_dir(
        path.parent()
            .ok_or_else(|| QorcError::Internal("Invalid installed PIR path".into()))?,
    );
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    Ok(command)
}


