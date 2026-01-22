//! Machine entropy for key binding
//!
//! Generates machine-specific context to bind encryption keys to this device

use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::error::QorResult;

/// Get machine-specific context for key derivation
pub async fn get_machine_context(install_path: &str) -> QorResult<Zeroizing<Vec<u8>>> {
    let mut hasher = Sha3_256::new();

    // Add install path
    hasher.update(b"install:");
    hasher.update(install_path.as_bytes());

    // Add hostname
    if let Ok(hostname) = hostname::get() {
        hasher.update(b"host:");
        hasher.update(hostname.to_string_lossy().as_bytes());
    }

    // Add OS info
    hasher.update(b"os:");
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(b"arch:");
    hasher.update(std::env::consts::ARCH.as_bytes());

    // Add username
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        hasher.update(b"user:");
        hasher.update(user.as_bytes());
    }

    // Add home directory path
    if let Some(home) = dirs::home_dir() {
        hasher.update(b"home:");
        hasher.update(home.to_string_lossy().as_bytes());
    }

    // Platform-specific machine ID
    #[cfg(target_os = "linux")]
    {
        // Try /etc/machine-id first
        if let Ok(machine_id) = tokio::fs::read_to_string("/etc/machine-id").await {
            hasher.update(b"machine-id:");
            hasher.update(machine_id.trim().as_bytes());
        } else if let Ok(dbus_id) = tokio::fs::read_to_string("/var/lib/dbus/machine-id").await {
            hasher.update(b"dbus-id:");
            hasher.update(dbus_id.trim().as_bytes());
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = tokio::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(uuid_line) = stdout.lines().find(|l| l.contains("IOPlatformUUID")) {
                hasher.update(b"platform-uuid:");
                hasher.update(uuid_line.as_bytes());
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = tokio::process::Command::new("reg")
            .args([
                "query",
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(guid_line) = stdout.lines().find(|l| l.contains("MachineGuid")) {
                hasher.update(b"machine-guid:");
                hasher.update(guid_line.as_bytes());
            }
        }
    }

    let result = hasher.finalize();
    Ok(Zeroizing::new(result.to_vec()))
}
