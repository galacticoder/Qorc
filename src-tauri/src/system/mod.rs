//! System integration
//!
//! Platform-specific system integration

use crate::constants::system::MAX_INSTANCE_ID_BYTES;
use crate::error::{QorcError, QorcResult};
use fs2::FileExt;
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
};

pub mod notification;
pub mod platform;
pub mod power;
#[cfg(desktop)]
pub mod tray;

const DEFAULT_INSTANCE_ID: &str = "1";

fn valid_instance_id(value: &str) -> Option<&str> {
    let value = value.trim();
    if !value.is_empty()
        && value.len() <= MAX_INSTANCE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Some(value)
    } else {
        None
    }
}

pub fn get_instance_id() -> QorcResult<String> {
    match std::env::var("QORC_INSTANCE_ID") {
        Ok(value) => valid_instance_id(&value)
            .map(str::to_owned)
            .ok_or_else(|| QorcError::InvalidArgument("Invalid instance identifier".to_string())),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_INSTANCE_ID.to_string()),
        Err(std::env::VarError::NotUnicode(_)) => Err(QorcError::InvalidArgument(
            "Invalid instance identifier".to_string(),
        )),
    }
}

pub fn acquire_instance_lock(config_root: &Path, instance_id: &str) -> QorcResult<File> {
    std::fs::create_dir_all(config_root)?;
    let lock_path = config_root.join(format!("instance-{instance_id}.lock"));
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(lock_path)?;
    FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            QorcError::SystemError(format!(
                "Client instance '{instance_id}' is already running"
            ))
        } else {
            QorcError::Io(error)
        }
    })?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    writeln!(file, "{}", std::process::id())?;
    file.sync_data()?;
    Ok(file)
}
