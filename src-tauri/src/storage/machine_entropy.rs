//! Stable machine context for local key binding.

#[cfg(target_os = "linux")]
use crate::constants::storage::MAX_MACHINE_ID_BYTES;
use zeroize::Zeroizing;

use crate::error::QorcResult;
#[cfg(not(target_os = "android"))]
use crate::error::QorcError;

#[cfg(not (target_os = "android"))]
fn valid_machine_id(value: &str) -> Option<&str> {
    let value = value.trim();
    if (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Some(value)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
async fn read_linux_machine_id() -> Option<String> {
    use tokio::io::AsyncReadExt;

    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open("/etc/machine-id").await.ok()?;
    let metadata = file.metadata().await.ok()?;
    if !metadata.is_file() || metadata.len() > MAX_MACHINE_ID_BYTES {
        return None;
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MACHINE_ID_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    if bytes.len() as u64 > MAX_MACHINE_ID_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(target_os = "windows")]
fn read_windows_machine_guid() -> Option<String> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    use windows::core::w;

    let mut value = [0_u16; 129];
    let mut byte_len = u32::try_from(value.len() * std::mem::size_of::<u16>()).ok()?;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Cryptography"),
            w!("MachineGuid"),
            RRF_RT_REG_SZ,
            None,
            Some(value.as_mut_ptr().cast()),
            Some(&mut byte_len),
        )
    };
    if status != ERROR_SUCCESS || byte_len == 0 || byte_len as usize > value.len() * 2 {
        return None;
    }

    let units = byte_len as usize / std::mem::size_of::<u16>();
    let end = value[..units]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units);
    String::from_utf16(&value[..end]).ok()
}

pub async fn get_machine_context(_config_dir: &std::path::Path) -> QorcResult<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "android")]
    return super::android_binding::get_context(_config_dir).await;

    #[cfg(not(target_os = "android"))]
    {
        #[cfg(target_os = "linux")]
        {
            if let Some(machine_id) = read_linux_machine_id().await
                && let Some(machine_id) = valid_machine_id(&machine_id)
            {
                return Ok(Zeroizing::new(
                    [crate::protocol_keys::MACHINE_LINUX, machine_id.as_bytes()].concat(),
                ));
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(machine_guid) = read_windows_machine_guid() {
                if let Some(machine_guid) = valid_machine_id(&machine_guid) {
                    return Ok(Zeroizing::new(
                        [
                            crate::protocol_keys::MACHINE_WINDOWS,
                            machine_guid.as_bytes(),
                        ]
                        .concat(),
                    ));
                }
            }
        }

        Err(QorcError::StorageInitFailed(
            "Stable machine identifier is unavailable".to_string(),
        ))
    }
}
