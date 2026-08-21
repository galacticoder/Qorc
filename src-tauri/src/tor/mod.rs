//! Tor Manager

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{error, info, warn};
use zeroize::Zeroize;

use crate::error::{QorError, QorResult};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_tor_bundle.rs"));
}

const DEFAULT_SOCKS_PORT: u16 = 9050;
const DEFAULT_CONTROL_PORT: u16 = 9051;
const PORT_SCAN_RANGE: u16 = 100;
const MAX_CONFIG_SIZE: usize = 50000;
const MAX_TOR_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOR_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOR_ARCHIVE_ENTRIES: usize = 4096;
const MAX_TOR_ARCHIVE_PATH_BYTES: usize = 1024;
const MAX_TOR_ARCHIVE_DEPTH: usize = 16;
const MAX_CONTROL_LINE_BYTES: usize = 8 * 1024;
const MAX_CONTROL_RESPONSE_LINES: usize = 64;
const CONTROL_COOKIE_FILE: &str = "control_auth_cookie";
const CONTROL_READ_FAILURE_THRESHOLD: u32 = 3;
pub fn is_valid_onion_service_id(id: &str) -> bool {
    id.len() == 56
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

const TOR_KEEPALIVE_PERIOD_SECS: u32 = 60;
const TRANSPORT_DIR: &str = "pluggable_transports";
const DEFAULT_TRANSPORT: &str = "lyrebird";
const BUNDLE_MARKER_FILE: &str = ".bundle-version";
fn invalid_tor_bundle(message: impl Into<String>) -> QorError {
    QorError::Verification(format!("Invalid Tor bundle: {}", message.into()))
}

fn is_tor_bundle_directory(relative: &Path) -> bool {
    matches!(
        relative.components().next(),
        Some(Component::Normal(name))
            if name == OsStr::new("lib")
                || name == OsStr::new("lib64")
                || name == OsStr::new(TRANSPORT_DIR)
    )
}

fn is_managed_tor_top_level_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };

    matches!(
        name,
        "tor"
            | "tor.exe"
            | "geoip"
            | "geoip6"
            | "torrc-defaults"
            | "obfs4proxy"
            | "obfs4proxy.exe"
            | "snowflake-client"
            | "snowflake-client.exe"
            | "lyrebird"
            | "lyrebird.exe"
            | "tor.txt"
            | "lyrebird.txt"
            | "libevent.txt"
            | "lib"
            | "lib64"
            | TRANSPORT_DIR
    ) || name.starts_with("lib")
        || name.ends_with(".dll")
}

fn is_allowed_tor_bundle_path(relative: &Path) -> bool {
    let mut components = relative.components();
    let Some(Component::Normal(first)) = components.next() else {
        return false;
    };

    if components.next().is_some() {
        return first == OsStr::new("lib")
            || first == OsStr::new("lib64")
            || first == OsStr::new(TRANSPORT_DIR);
    }

    is_managed_tor_top_level_name(first)
}

fn normalize_tor_bundle_path(path: &Path) -> QorResult<Option<PathBuf>> {
    let encoded = path
        .to_str()
        .ok_or_else(|| invalid_tor_bundle("entry path is not valid UTF-8"))?;
    if encoded.len() > MAX_TOR_ARCHIVE_PATH_BYTES {
        return Err(invalid_tor_bundle("entry path is too long"));
    }

    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(root)) if root == OsStr::new("tor") => {}
        _ => return Err(invalid_tor_bundle("entry is outside the tor root")),
    }

    let mut relative = PathBuf::new();
    let mut depth = 0usize;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid_tor_bundle("entry path contains traversal"));
        };
        if name.is_empty() {
            return Err(invalid_tor_bundle("entry path contains an empty component"));
        }
        depth = depth
            .checked_add(1)
            .ok_or_else(|| invalid_tor_bundle("entry path is too deep"))?;
        if depth > MAX_TOR_ARCHIVE_DEPTH {
            return Err(invalid_tor_bundle("entry path is too deep"));
        }
        relative.push(name);
    }

    if relative.as_os_str().is_empty() {
        return Ok(None);
    }
    if !is_allowed_tor_bundle_path(&relative) {
        return Err(invalid_tor_bundle(
            "entry is not part of the managed runtime",
        ));
    }

    Ok(Some(relative))
}

fn is_reviewed_ignored_bundle_path(path: &Path) -> QorResult<bool> {
    let encoded = path
        .to_str()
        .ok_or_else(|| invalid_tor_bundle("entry path is not valid UTF-8"))?;
    if encoded.len() > MAX_TOR_ARCHIVE_PATH_BYTES {
        return Err(invalid_tor_bundle("entry path is too long"));
    }

    let mut names = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(invalid_tor_bundle("entry path contains traversal"));
        };
        if name.is_empty() {
            return Err(invalid_tor_bundle("entry path contains an empty component"));
        }
        names.push(name);
        if names.len() > MAX_TOR_ARCHIVE_DEPTH + 1 {
            return Err(invalid_tor_bundle("entry path is too deep"));
        }
    }
    let Some(root) = names.first() else {
        return Err(invalid_tor_bundle("entry path is empty"));
    };
    if matches!(root.to_str(), Some("data" | "debug" | "docs")) {
        return Ok(true);
    }
    if root != &OsStr::new("tor") {
        return Err(invalid_tor_bundle("entry has an unexpected root"));
    }

    let ignored_runtime_file = names.as_slice()
        == [OsStr::new("tor"), OsStr::new("tor-gencert.exe")]
        || names.as_slice()
            == [
                OsStr::new("tor"),
                OsStr::new(TRANSPORT_DIR),
                OsStr::new("README.CONJURE.md"),
            ]
        || names.as_slice()
            == [
                OsStr::new("tor"),
                OsStr::new(TRANSPORT_DIR),
                OsStr::new("conjure-client"),
            ]
        || names.as_slice()
            == [
                OsStr::new("tor"),
                OsStr::new(TRANSPORT_DIR),
                OsStr::new("conjure-client.exe"),
            ]
        || names.as_slice()
            == [
                OsStr::new("tor"),
                OsStr::new(TRANSPORT_DIR),
                OsStr::new("pt_config.json"),
            ];
    Ok(ignored_runtime_file)
}

#[derive(Debug, Eq, PartialEq)]
struct BundleFileDigest {
    relative: String,
    size: u64,
    sha256: [u8; 32],
}

fn bundle_relative_string(path: &Path) -> QorResult<String> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid_tor_bundle("managed path is not valid UTF-8"))?;
    if value.len() > MAX_TOR_ARCHIVE_PATH_BYTES
        || path.components().count() > MAX_TOR_ARCHIVE_DEPTH
        || !is_allowed_tor_bundle_path(path)
    {
        return Err(invalid_tor_bundle("managed path is invalid"));
    }
    Ok(value.replace('\\', "/"))
}

fn digest_reader<R: Read>(
    reader: &mut R,
    expected_size: u64,
    total_bytes: &mut u64,
) -> QorResult<[u8; 32]> {
    *total_bytes = total_bytes
        .checked_add(expected_size)
        .ok_or_else(|| invalid_tor_bundle("expanded data is too large"))?;
    if *total_bytes > MAX_TOR_EXTRACTED_BYTES {
        return Err(invalid_tor_bundle("expanded data is too large"));
    }

    let mut hasher = Sha256::new();
    let mut consumed = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            QorError::FileSystem(format!("Failed to hash Tor bundle file: {}", error))
        })?;
        if read == 0 {
            break;
        }
        consumed = consumed
            .checked_add(read as u64)
            .ok_or_else(|| invalid_tor_bundle("expanded data is too large"))?;
        if consumed > expected_size {
            return Err(invalid_tor_bundle("file exceeds its declared size"));
        }
        hasher.update(&buffer[..read]);
    }
    if consumed != expected_size {
        return Err(invalid_tor_bundle("file size does not match its manifest"));
    }
    Ok(hasher.finalize().into())
}

fn authenticated_archive_manifest_from_reader<R: Read>(
    reader: R,
) -> QorResult<Vec<BundleFileDigest>> {
    let decoder = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;

    for entry in archive
        .entries()
        .map_err(|error| invalid_tor_bundle(format!("cannot read archive entries: {}", error)))?
    {
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid_tor_bundle("too many entries"))?;
        if entry_count > MAX_TOR_ARCHIVE_ENTRIES {
            return Err(invalid_tor_bundle("too many entries"));
        }
        let mut entry = entry
            .map_err(|error| invalid_tor_bundle(format!("cannot read archive entry: {}", error)))?;
        let archive_path = entry
            .path()
            .map_err(|error| invalid_tor_bundle(format!("cannot read entry path: {}", error)))?;
        if is_reviewed_ignored_bundle_path(&archive_path)? {
            continue;
        }
        let Some(relative) = normalize_tor_bundle_path(&archive_path)? else {
            if !entry.header().entry_type().is_dir() {
                return Err(invalid_tor_bundle("tor root is not a directory"));
            }
            continue;
        };
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            if !is_tor_bundle_directory(&relative) {
                return Err(invalid_tor_bundle(
                    "unexpected directory in managed runtime",
                ));
            }
            continue;
        }
        if !entry_type.is_file()
            || relative.components().count() == 1 && is_tor_bundle_directory(&relative)
        {
            return Err(invalid_tor_bundle(
                "links and special entry types are forbidden",
            ));
        }
        let relative = bundle_relative_string(&relative)?;
        if !seen.insert(relative.clone()) {
            return Err(invalid_tor_bundle("duplicate managed file"));
        }
        let size = entry
            .header()
            .size()
            .map_err(|error| invalid_tor_bundle(format!("invalid entry size: {}", error)))?;
        let sha256 = digest_reader(&mut entry, size, &mut total_bytes)?;
        files.push(BundleFileDigest {
            relative,
            size,
            sha256,
        });
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

fn authenticated_embedded_archive_manifest() -> QorResult<Vec<BundleFileDigest>> {
    if embedded::EMBEDDED_TOR_BUNDLE.len() as u64 > MAX_TOR_BUNDLE_BYTES {
        return Err(QorError::Verification(
            "Embedded Tor bundle exceeds its size limit".to_string(),
        ));
    }
    authenticated_archive_manifest_from_reader(Cursor::new(embedded::EMBEDDED_TOR_BUNDLE))
}

fn installed_bundle_manifest(root: &Path) -> QorResult<Vec<BundleFileDigest>> {
    let mut pending = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|error| {
        QorError::FileSystem(format!("Failed to inspect installed Tor bundle: {}", error))
    })? {
        let entry = entry.map_err(|error| {
            QorError::FileSystem(format!("Failed to inspect installed Tor entry: {}", error))
        })?;
        if is_managed_tor_top_level_name(&entry.file_name()) {
            pending.push((PathBuf::from(entry.file_name()), entry.path()));
        }
    }

    let mut files = Vec::new();
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;
    while let Some((relative, path)) = pending.pop() {
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| invalid_tor_bundle("too many installed entries"))?;
        if entry_count > MAX_TOR_ARCHIVE_ENTRIES {
            return Err(invalid_tor_bundle("too many installed entries"));
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            QorError::FileSystem(format!("Failed to inspect installed Tor file: {}", error))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(invalid_tor_bundle("installed bundle contains a link"));
        }
        if metadata.file_type().is_dir() {
            if !is_tor_bundle_directory(&relative) {
                return Err(invalid_tor_bundle(
                    "installed bundle contains an unexpected directory",
                ));
            }
            for entry in std::fs::read_dir(&path).map_err(|error| {
                QorError::FileSystem(format!(
                    "Failed to inspect installed Tor directory: {}",
                    error
                ))
            })? {
                let entry = entry.map_err(|error| {
                    QorError::FileSystem(format!(
                        "Failed to inspect installed Tor entry: {}",
                        error
                    ))
                })?;
                pending.push((relative.join(entry.file_name()), entry.path()));
            }
            continue;
        }
        if !metadata.file_type().is_file() {
            return Err(invalid_tor_bundle(
                "installed bundle contains a special file",
            ));
        }

        let relative = bundle_relative_string(&relative)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path).map_err(|error| {
            QorError::FileSystem(format!("Failed to open installed Tor file: {}", error))
        })?;
        let opened = file.metadata().map_err(|error| {
            QorError::FileSystem(format!("Failed to inspect installed Tor file: {}", error))
        })?;
        if !opened.file_type().is_file() || opened.len() != metadata.len() {
            return Err(invalid_tor_bundle(
                "installed file changed during verification",
            ));
        }
        let size = opened.len();
        let sha256 = digest_reader(&mut file, size, &mut total_bytes)?;
        files.push(BundleFileDigest {
            relative,
            size,
            sha256,
        });
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

fn read_bounded_line<R: BufRead>(reader: &mut R, line: &mut String) -> QorResult<usize> {
    line.clear();
    let mut limited = reader.take((MAX_CONTROL_LINE_BYTES + 1) as u64);
    let read = limited.read_line(line)?;
    if read > MAX_CONTROL_LINE_BYTES {
        line.zeroize();
        return Err(QorError::TorControl(
            "Tor control or log line exceeds the size limit".to_string(),
        ));
    }
    Ok(read)
}

fn is_regular_file_without_links(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn remove_managed_path(path: &Path) -> QorResult<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(QorError::FileSystem(format!(
                "Failed to inspect managed Tor path: {}",
                error
            )));
        }
    };

    let file_type = metadata.file_type();
    let result = if file_type.is_symlink() {
        std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
    } else if file_type.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    result.map_err(|error| {
        QorError::FileSystem(format!("Failed to remove managed Tor path: {}", error))
    })
}

fn ensure_private_directory(path: &Path) -> QorResult<()> {
    std::fs::create_dir_all(path).map_err(|error| {
        QorError::FileSystem(format!("Failed to create private Tor directory: {}", error))
    })?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        QorError::FileSystem(format!(
            "Failed to inspect private Tor directory: {}",
            error
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(QorError::FileSystem(
            "Private Tor path is not a directory".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                QorError::FileSystem(format!("Failed to secure private Tor directory: {}", error))
            },
        )?;
    }
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8]) -> QorResult<()> {
    let parent = path.parent().ok_or_else(|| {
        QorError::FileSystem("Private Tor file has no parent directory".to_string())
    })?;
    ensure_private_directory(parent)?;

    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| QorError::FileSystem("Private Tor file name is invalid".to_string()))?;
    let temporary = parent.join(format!(".{}-{}.tmp", file_name, uuid::Uuid::new_v4()));

    let result = (|| -> QorResult<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temporary).map_err(|error| {
            QorError::FileSystem(format!("Failed to create private Tor file: {}", error))
        })?;
        file.write_all(contents).map_err(|error| {
            QorError::FileSystem(format!("Failed to write private Tor file: {}", error))
        })?;
        file.sync_all().map_err(|error| {
            QorError::FileSystem(format!("Failed to finalize private Tor file: {}", error))
        })?;

        let rename_result = std::fs::rename(&temporary, path);
        #[cfg(windows)]
        let rename_result = match rename_result {
            Ok(()) => Ok(()),
            Err(error) => {
                let existing = std::fs::symlink_metadata(path);
                match existing {
                    Ok(metadata) if metadata.file_type().is_file() => {
                        std::fs::remove_file(path).and_then(|_| std::fs::rename(&temporary, path))
                    }
                    _ => Err(error),
                }
            }
        };
        rename_result.map_err(|error| {
            QorError::FileSystem(format!("Failed to install private Tor file: {}", error))
        })?;
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn read_private_text_file(path: &Path, max_bytes: usize) -> QorResult<String> {
    let link_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        QorError::FileSystem(format!("Failed to inspect private Tor file: {}", error))
    })?;
    if !link_metadata.file_type().is_file() || link_metadata.len() > max_bytes as u64 {
        return Err(QorError::FileSystem(
            "Private Tor file has an invalid format".to_string(),
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        QorError::FileSystem(format!("Failed to open private Tor file: {}", error))
    })?;
    let metadata = file.metadata().map_err(|error| {
        QorError::FileSystem(format!("Failed to inspect private Tor file: {}", error))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes as u64 {
        return Err(QorError::FileSystem(
            "Private Tor file has an invalid format".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(QorError::FileSystem(
                "Private Tor file permissions are too broad".to_string(),
            ));
        }
    }

    let mut bytes = Vec::with_capacity(metadata.len().min(max_bytes as u64) as usize);
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            QorError::FileSystem(format!("Failed to read private Tor file: {}", error))
        })?;
    if bytes.len() > max_bytes {
        bytes.zeroize();
        return Err(QorError::FileSystem(
            "Private Tor file has an invalid format".to_string(),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| QorError::FileSystem("Private Tor file is not valid UTF-8".to_string()))
}

lazy_static::lazy_static! {
    static ref ALLOWED_DIRECTIVES: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("AvoidDiskWrites");
        set.insert("Bridge");
        set.insert("CircuitBuildTimeout");
        set.insert("ClientOnly");
        set.insert("ClientTransportPlugin");
        set.insert("CookieAuthentication");
        set.insert("DataDirectory");
        set.insert("DisableDebuggerAttachment");
        set.insert("DisableNetwork");
        set.insert("EnforceDistinctSubnets");
        set.insert("EntryNodes");
        set.insert("ExitNodes");
        set.insert("ExitPolicy");
        set.insert("ExcludeExitNodes");
        set.insert("ExcludeNodes");
        set.insert("FetchDirInfoEarly");
        set.insert("FetchDirInfoExtraEarly");
        set.insert("FetchUselessDescriptors");
        set.insert("GeoIPFile");
        set.insert("GeoIPv6File");
        set.insert("LearnCircuitBuildTimeout");
        set.insert("KeepalivePeriod");
        set.insert("Log");
        set.insert("MaxCircuitDirtiness");
        set.insert("NewCircuitPeriod");
        set.insert("NumEntryGuards");
        set.insert("ProtocolWarnings");
        set.insert("SafeLogging");
        set.insert("SocksPolicy");
        set.insert("StrictNodes");
        set.insert("TrackHostExits");
        set.insert("TrackHostExitsExpire");
        set.insert("UpdateBridgesFromAuthority");
        set.insert("UseBridges");
        set.insert("ConfluxEnabled");
        set.insert("UseEntryGuards");
        set.insert("UseMicrodescriptors");
        set
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    pub config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStartResult {
    pub success: bool,
    pub starting: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStatus {
    pub is_running: bool,
    pub process_id: Option<u32>,
    pub socks_port: u16,
    pub control_port: u16,
    pub bootstrapped: bool,
    pub bootstrap_progress: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorInfo {
    pub version: String,
    pub socks_port: u16,
    pub control_port: u16,
    pub bootstrapped: bool,
    pub bootstrap_progress: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitRotationResult {
    pub success: bool,
    pub ip_changed: Option<bool>,
    pub before_ip: Option<String>,
    pub after_ip: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorVerifyResult {
    pub success: bool,
    pub ip_address: Option<String>,
    pub error: Option<String>,
}

pub struct ControlConnection {
    pub stream: TcpStream,
    pub reader: BufReader<TcpStream>,
}

impl Drop for ControlConnection {
    fn drop(&mut self) {
        let _ = writeln!(&mut self.stream, "QUIT");
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

pub struct PublishedOnionService {
    onion_host: String,
    _control: ControlConnection,
}

impl PublishedOnionService {
    pub fn onion_host(&self) -> &str {
        &self.onion_host
    }
}

pub struct TorManager {
    _app_data_path: PathBuf,
    tor_dir: PathBuf,
    tor_path: PathBuf,
    config_path: PathBuf,
    tor_process: RwLock<Option<Child>>,
    operation_lock: tokio::sync::Mutex<()>,
    platform: String,
    arch: String,
    effective_socks_port: AtomicU16,
    effective_control_port: AtomicU16,
    bootstrapped: Arc<AtomicBool>,
    bootstrap_progress: Arc<AtomicU16>,
    version_cache: RwLock<Option<String>>,
    configured_data_dir: RwLock<Option<PathBuf>>,
    process_generation: Arc<AtomicU64>,
    control_read_failures: AtomicU32,
}

fn spawn_managed_tor(command: &mut Command) -> std::io::Result<Child> {
    command.spawn()
}

impl TorManager {
    fn pinned_bundle_target(&self) -> QorResult<(&'static str, &'static str)> {
        if self.platform == embedded::EMBEDDED_TOR_PLATFORM
            && self.arch == embedded::EMBEDDED_TOR_ARCH
        {
            Ok((
                embedded::EMBEDDED_TOR_BUNDLE_TARGET,
                embedded::EMBEDDED_TOR_BUNDLE_SHA256_HEX,
            ))
        } else {
            Err(QorError::NotSupported(format!(
                "The embedded Tor bundle targets {}/{}, not {}/{}",
                embedded::EMBEDDED_TOR_PLATFORM,
                embedded::EMBEDDED_TOR_ARCH,
                self.platform,
                self.arch
            )))
        }
    }

    fn find_managed_tor_pids(&self, system: &mut System) -> Vec<u32> {
        let Ok(tor_path) = std::fs::canonicalize(&self.tor_path) else {
            return Vec::new();
        };
        let Ok(config_path) = std::fs::canonicalize(&self.config_path) else {
            return Vec::new();
        };
        let mut pids = Vec::new();

        system.refresh_processes();

        for (pid, process) in system.processes() {
            let executable_matches = process
                .exe()
                .and_then(|path| std::fs::canonicalize(path).ok())
                .is_some_and(|path| path == tor_path);
            let config_matches = process.cmd().windows(2).any(|arguments| {
                arguments[0] == "-f"
                    && std::fs::canonicalize(Path::new(&arguments[1]))
                        .is_ok_and(|path| path == config_path)
            });
            if !executable_matches || !config_matches {
                continue;
            }

            if let Ok(raw_pid) = pid.to_string().parse::<u32>() {
                pids.push(raw_pid);
            }
        }

        pids
    }

    fn process_exists(system: &mut System, pid: u32) -> bool {
        system.refresh_processes();

        for candidate in system.processes().keys() {
            if let Ok(raw_pid) = candidate.to_string().parse::<u32>()
                && raw_pid == pid
            {
                return true;
            }
        }

        false
    }

    fn terminate_pid_sync(system: &mut System, pid: u32) -> bool {
        system.refresh_processes();
        for (candidate, process) in system.processes() {
            if let Ok(raw_pid) = candidate.to_string().parse::<u32>()
                && raw_pid == pid
            {
                let _ = process.kill();
                break;
            }
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !Self::process_exists(system, pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }

        system.refresh_processes();
        for (candidate, process) in system.processes() {
            if let Ok(raw_pid) = candidate.to_string().parse::<u32>()
                && raw_pid == pid
            {
                let _ = process.kill();
                break;
            }
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !Self::process_exists(system, pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }

        !Self::process_exists(system, pid)
    }

    fn terminate_child_sync(mut child: Child) {
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            if kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).is_err() {
                let _ = child.kill();
            }
        }

        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }

        let _ = child.kill();
        let _ = child.wait();
    }

    fn mark_process_stopped(&self) {
        self.process_generation.fetch_add(1, Ordering::AcqRel);
        self.bootstrapped.store(false, Ordering::Relaxed);
        self.bootstrap_progress.store(0, Ordering::Relaxed);
        self.control_read_failures.store(0, Ordering::Relaxed);
    }

    fn reap_exited_process(&self) -> bool {
        let mut process_guard = self.tor_process.write();
        let should_clear = match process_guard.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => {
                    warn!("[TOR] Managed Tor process exited: {}", status);
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    warn!("[TOR] Failed to inspect Tor process state: {}", e);
                    true
                }
            },
            None => false,
        };

        if should_clear {
            *process_guard = None;
            drop(process_guard);
            self.mark_process_stopped();
            return true;
        }

        false
    }

    pub fn cleanup_orphaned_processes_sync(&self) -> usize {
        let tracked_pid = self.tor_process.read().as_ref().map(|c| c.id());
        let mut cleaned = 0usize;
        let mut system = System::new_all();

        for pid in self.find_managed_tor_pids(&mut system) {
            if Some(pid) == tracked_pid {
                continue;
            }
            if pid == std::process::id() {
                continue;
            }
            if Self::terminate_pid_sync(&mut system, pid) {
                cleaned += 1;
            }
        }

        cleaned
    }

    pub fn shutdown_now(&self) {
        let child_opt = {
            let mut process_guard = self.tor_process.write();
            process_guard.take()
        };

        if let Some(child) = child_opt {
            Self::terminate_child_sync(child);
        }

        let _ = self.cleanup_orphaned_processes_sync();

        self.mark_process_stopped();
    }

    pub fn new(app_data_path: PathBuf) -> Self {
        let platform = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let tor_dir = app_data_path.join("tor");
        let config_path = tor_dir.join("torrc");

        let ext = if platform == "windows" { ".exe" } else { "" };
        let tor_path = tor_dir.join(format!("tor{}", ext));

        Self {
            _app_data_path: app_data_path,
            tor_dir,
            tor_path,
            config_path,
            tor_process: RwLock::new(None),
            operation_lock: tokio::sync::Mutex::new(()),
            platform,
            arch,
            effective_socks_port: AtomicU16::new(DEFAULT_SOCKS_PORT),
            effective_control_port: AtomicU16::new(DEFAULT_CONTROL_PORT),
            bootstrapped: Arc::new(AtomicBool::new(false)),
            bootstrap_progress: Arc::new(AtomicU16::new(0)),
            version_cache: RwLock::new(None),
            configured_data_dir: RwLock::new(None),
            process_generation: Arc::new(AtomicU64::new(0)),
            control_read_failures: AtomicU32::new(0),
        }
    }

    pub fn get_socks_port(&self) -> u16 {
        self.effective_socks_port.load(Ordering::Relaxed)
    }

    pub fn get_control_port(&self) -> u16 {
        self.effective_control_port.load(Ordering::Relaxed)
    }

    fn is_valid_port(port: u16) -> bool {
        port >= 1
    }

    async fn is_port_available(&self, port: u16) -> bool {
        if !Self::is_valid_port(port) {
            return false;
        }

        std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok()
    }

    async fn find_available_port(&self, start_port: u16) -> u16 {
        let base = if Self::is_valid_port(start_port) {
            start_port
        } else {
            DEFAULT_SOCKS_PORT
        };

        for offset in 0..PORT_SCAN_RANGE {
            let candidate = base.saturating_add(offset);
            if Self::is_valid_port(candidate) && self.is_port_available(candidate).await {
                return candidate;
            }
        }

        base
    }

    fn get_data_dir(&self) -> PathBuf {
        let configured = self.configured_data_dir.read();
        if let Some(dir) = configured.as_ref() {
            return dir.clone();
        }

        self.tor_dir.join("data")
    }

    fn get_tor_environment(&self) -> Vec<(OsString, OsString)> {
        let mut env = Vec::new();

        for key in [
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "WINDIR",
            "TMPDIR",
            "TMP",
            "TEMP",
            "LANG",
            "LC_ALL",
            "TZ",
        ] {
            if let Some(value) = std::env::var_os(key) {
                env.push((OsString::from(key), value));
            }
        }

        let lib_dirs: Vec<PathBuf> = vec![
            self.tor_dir.join("lib64"),
            self.tor_dir.join("lib"),
            self.tor_dir.clone(),
        ]
        .into_iter()
        .filter(|p| p.exists())
        .collect();

        if !lib_dirs.is_empty()
            && let Ok(lib_path) = std::env::join_paths(&lib_dirs)
        {
            env.push((OsString::from("LD_LIBRARY_PATH"), lib_path));
        }

        let mut path_entries = vec![self.tor_dir.clone(), self.tor_dir.join(TRANSPORT_DIR)];
        if let Some(existing_path) = std::env::var_os("PATH") {
            path_entries.extend(std::env::split_paths(&existing_path));
        }
        if let Ok(path) = std::env::join_paths(path_entries) {
            env.push((OsString::from("PATH"), path));
        }

        env
    }

    fn control_cookie_path(&self) -> PathBuf {
        self.get_data_dir().join(CONTROL_COOKIE_FILE)
    }

    fn read_control_cookie(path: &Path) -> QorResult<[u8; 32]> {
        let link_metadata = std::fs::symlink_metadata(path).map_err(|error| {
            QorError::TorControl(format!("Tor control cookie is unavailable: {}", error))
        })?;
        if !link_metadata.file_type().is_file() {
            return Err(QorError::TorControl(
                "Tor control cookie is not a regular file".to_string(),
            ));
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(path).map_err(|error| {
            QorError::TorControl(format!("Failed to open Tor control cookie: {}", error))
        })?;
        let metadata = file.metadata().map_err(|error| {
            QorError::TorControl(format!("Failed to inspect Tor control cookie: {}", error))
        })?;
        if !metadata.file_type().is_file() || metadata.len() != 32 {
            return Err(QorError::TorControl(
                "Tor control cookie has an invalid format".to_string(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(QorError::TorControl(
                    "Tor control cookie permissions are too broad".to_string(),
                ));
            }
        }

        let mut cookie = [0u8; 32];
        file.read_exact(&mut cookie).map_err(|error| {
            cookie.zeroize();
            QorError::TorControl(format!("Failed to read Tor control cookie: {}", error))
        })?;
        Ok(cookie)
    }

    fn executable_name(&self, name: &str) -> String {
        if self.platform == "windows" && !name.to_ascii_lowercase().ends_with(".exe") {
            format!("{}.exe", name)
        } else {
            name.to_string()
        }
    }

    fn bundle_marker_contents(&self, checksum: &str) -> String {
        format!(
            "{}:{}:{}:{}\n",
            embedded::EMBEDDED_TOR_BUNDLE_VERSION,
            self.platform,
            self.arch,
            checksum
        )
    }

    fn has_current_bundle(&self, checksum: &str) -> bool {
        let marker_path = self.tor_dir.join(BUNDLE_MARKER_FILE);
        if !is_regular_file_without_links(&self.tor_path)
            || !is_regular_file_without_links(&self.managed_transport_path(DEFAULT_TRANSPORT))
            || !is_regular_file_without_links(&marker_path)
        {
            return false;
        }
        if !read_private_text_file(&marker_path, 512)
            .is_ok_and(|marker| marker == self.bundle_marker_contents(checksum))
        {
            return false;
        }

        match (
            authenticated_embedded_archive_manifest(),
            installed_bundle_manifest(&self.tor_dir),
        ) {
            (Ok(authenticated), Ok(installed)) => authenticated == installed,
            _ => false,
        }
    }

    fn managed_transport_path(&self, name: &str) -> PathBuf {
        self.tor_dir
            .join(TRANSPORT_DIR)
            .join(self.executable_name(name))
    }

    fn managed_transport_config_path(&self, name: &str) -> String {
        format!("./{}/{}", TRANSPORT_DIR, self.executable_name(name))
    }

    fn managed_transport_input_path(name: &str) -> String {
        format!("./{}/{}", TRANSPORT_DIR, name)
    }

    fn ensure_executable_path(path: &Path) -> QorResult<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = std::fs::metadata(path)?;
            let mut permissions = metadata.permissions();
            if permissions.mode() & 0o777 != 0o700 {
                permissions.set_mode(0o700);
                std::fs::set_permissions(path, permissions)?;
            }
        }

        Ok(())
    }

    fn ensure_managed_executables(&self) -> QorResult<()> {
        if is_regular_file_without_links(&self.tor_path) {
            Self::ensure_executable_path(&self.tor_path)?;
        }

        let transport = self.managed_transport_path(DEFAULT_TRANSPORT);
        if is_regular_file_without_links(&transport) {
            Self::ensure_executable_path(&transport)?;
        }

        Ok(())
    }

    fn normalize_client_transport_plugin_value_for_path(
        &self,
        value: &str,
        required_path: &str,
    ) -> QorResult<String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 || !parts[1].eq_ignore_ascii_case("exec") {
            return Err(QorError::InvalidArgument(
                "Invalid ClientTransportPlugin directive".to_string(),
            ));
        }

        let methods = parts[0];
        let raw_path = parts[2];
        let supported = methods.split(',').all(|method| {
            matches!(
                method.trim().to_ascii_lowercase().as_str(),
                "meek_lite"
                    | "obfs2"
                    | "obfs3"
                    | "obfs4"
                    | "scramblesuit"
                    | "snowflake"
                    | "webtunnel"
            )
        });
        if methods.is_empty() || !supported {
            return Err(QorError::InvalidArgument(
                "Unsupported bridge transport method".to_string(),
            ));
        }

        if raw_path != required_path {
            return Err(QorError::InvalidArgument(
                "Only the authenticated bundled bridge transport is allowed".to_string(),
            ));
        }
        let resolved = self.managed_transport_path(DEFAULT_TRANSPORT);
        if !is_regular_file_without_links(&resolved) {
            return Err(QorError::InvalidArgument(
                "Authenticated bridge transport binary not found".to_string(),
            ));
        }
        Self::ensure_executable_path(&resolved)?;

        let config_path = self.managed_transport_config_path(DEFAULT_TRANSPORT);
        Ok(format!("{} exec {}", methods, config_path))
    }

    fn normalize_client_transport_plugin_value(&self, value: &str) -> QorResult<String> {
        self.normalize_client_transport_plugin_value_for_path(
            value,
            &Self::managed_transport_input_path(DEFAULT_TRANSPORT),
        )
    }

    fn normalize_stored_transport_plugin_value(&self, value: &str) -> QorResult<String> {
        self.normalize_client_transport_plugin_value_for_path(
            value,
            &self.managed_transport_config_path(DEFAULT_TRANSPORT),
        )
    }

    async fn normalize_configured_runtime(&self) -> QorResult<()> {
        let config = read_private_text_file(&self.config_path, MAX_CONFIG_SIZE)?;
        let (normalized, data_dir) = self.validate_stored_config(&config)?;
        let changed = normalized.trim_end() != config.trim_end();

        if changed {
            write_private_file(&self.config_path, normalized.as_bytes())?;
        }

        if let Some(data_dir) = data_dir {
            *self.configured_data_dir.write() = Some(data_dir);
        }
        Ok(())
    }

    /// Get Tor version
    pub async fn get_tor_version(&self) -> QorResult<String> {
        if let Some(version) = self.version_cache.read().clone() {
            return Ok(version);
        }

        let (_, checksum) = self.pinned_bundle_target()?;
        if !self.has_current_bundle(checksum) {
            return Err(QorError::Verification(
                "Embedded Tor runtime is unavailable".to_string(),
            ));
        }

        let mut child = tokio::process::Command::new(&self.tor_path)
            .arg("--version")
            .env_clear()
            .envs(self.get_tor_environment())
            .current_dir(&self.tor_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| QorError::TorProcess(format!("Failed to get version: {}", e)))?;
        let stdout = child.stdout.take().ok_or_else(|| {
            QorError::TorProcess("Tor version command did not provide stdout".to_string())
        })?;
        let mut output = Vec::with_capacity(256);
        let version_result = tokio::time::timeout(Duration::from_secs(5), async {
            stdout
                .take(4097)
                .read_to_end(&mut output)
                .await
                .map_err(|e| QorError::TorProcess(format!("Failed to read Tor version: {}", e)))?;
            let status = child.wait().await.map_err(|e| {
                QorError::TorProcess(format!("Failed to wait for Tor version: {}", e))
            })?;
            Ok::<_, QorError>(status)
        })
        .await;
        let status = match version_result {
            Ok(result) => result?,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                output.zeroize();
                return Err(QorError::TorProcess(
                    "Tor version command timed out".to_string(),
                ));
            }
        };
        if !status.success() || output.len() > 4096 {
            output.zeroize();
            return Err(QorError::TorProcess(
                "Tor version command returned invalid output".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output);

        if let Some(captures) = regex::Regex::new(r"Tor (?:version )?(\d+\.\d+\.\d+)")
            .ok()
            .and_then(|re| re.captures(&stdout))
            && let Some(version) = captures.get(1)
        {
            let parsed = version.as_str().to_string();
            output.zeroize();
            *self.version_cache.write() = Some(parsed.clone());
            return Ok(parsed);
        }

        output.zeroize();
        *self.version_cache.write() = Some("unknown".to_string());
        Ok("unknown".to_string())
    }

    pub async fn get_info(&self) -> QorResult<TorInfo> {
        self.refresh_bootstrap_from_control().await;

        Ok(TorInfo {
            version: self
                .get_tor_version()
                .await
                .unwrap_or_else(|_| "unknown".to_string()),
            socks_port: self.get_socks_port(),
            control_port: self.get_control_port(),
            bootstrapped: self.bootstrapped.load(Ordering::Relaxed),
            bootstrap_progress: self.bootstrap_progress.load(Ordering::Relaxed),
        })
    }

    async fn materialize_embedded_bundle(&self) -> QorResult<()> {
        let _operation_guard = self.operation_lock.lock().await;
        if self.is_running() {
            return Err(QorError::TorProcess(
                "Cannot replace the embedded Tor runtime while it is running".to_string(),
            ));
        }

        ensure_private_directory(&self.tor_dir)?;
        let (_, expected_checksum) = self.pinned_bundle_target()?;
        if self.has_current_bundle(expected_checksum) {
            return Ok(());
        }

        let actual_checksum = Sha256::digest(embedded::EMBEDDED_TOR_BUNDLE);
        if actual_checksum.as_slice() != embedded::EMBEDDED_TOR_BUNDLE_SHA256 {
            return Err(QorError::Verification(
                "Embedded Tor bundle failed its runtime integrity check".to_string(),
            ));
        }
        self.extract_tor_bundle_bytes(embedded::EMBEDDED_TOR_BUNDLE.to_vec(), expected_checksum)
            .await?;
        self.ensure_managed_executables()?;
        if !self.has_current_bundle(expected_checksum) {
            return Err(QorError::Verification(
                "Materialized Tor runtime does not match its embedded archive".to_string(),
            ));
        }
        Ok(())
    }

    async fn extract_tor_bundle_bytes(
        &self,
        archive_bytes: Vec<u8>,
        checksum: &str,
    ) -> QorResult<()> {
        let tor_dir = self.tor_dir.clone();
        let tor_executable = self.executable_name("tor");
        let transport_executable = self.executable_name(DEFAULT_TRANSPORT);
        let marker_contents = self.bundle_marker_contents(checksum);
        let expected_checksum = checksum.to_string();

        tokio::task::spawn_blocking(move || {
            for entry in std::fs::read_dir(&tor_dir).map_err(|error| {
                QorError::FileSystem(format!("Failed to inspect Tor directory: {}", error))
            })? {
                let entry = entry.map_err(|error| {
                    QorError::FileSystem(format!("Failed to inspect Tor entry: {}", error))
                })?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.starts_with(".bundle-staging-")
                    || name.starts_with(".bundle-version-")
                    || name.starts_with("..bundle-version-")
                {
                    remove_managed_path(&entry.path())?;
                }
            }

            let staging_dir =
                tor_dir.join(format!(".bundle-staging-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir(&staging_dir).map_err(|error| {
                QorError::FileSystem(format!("Failed to create Tor staging directory: {}", error))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&staging_dir, std::fs::Permissions::from_mode(0o700))?;
            }

            let result = (|| -> QorResult<()> {
                if archive_bytes.len() as u64 > MAX_TOR_BUNDLE_BYTES {
                    return Err(QorError::Verification(
                        "Embedded Tor archive exceeds its size limit".to_string(),
                    ));
                }
                if hex::encode(Sha256::digest(&archive_bytes)) != expected_checksum {
                    return Err(QorError::Verification(
                        "Embedded Tor archive failed authentication before extraction".to_string(),
                    ));
                }
                let decoder = flate2::read::GzDecoder::new(Cursor::new(archive_bytes));
                let mut archive = tar::Archive::new(decoder);
                let mut entry_count = 0usize;
                let mut extracted_bytes = 0u64;

                for entry in archive.entries().map_err(|error| {
                    invalid_tor_bundle(format!("cannot read archive entries: {}", error))
                })? {
                    entry_count = entry_count
                        .checked_add(1)
                        .ok_or_else(|| invalid_tor_bundle("too many entries"))?;
                    if entry_count > MAX_TOR_ARCHIVE_ENTRIES {
                        return Err(invalid_tor_bundle("too many entries"));
                    }

                    let mut entry = entry.map_err(|error| {
                        invalid_tor_bundle(format!("cannot read archive entry: {}", error))
                    })?;
                    let archive_path = entry.path().map_err(|error| {
                        invalid_tor_bundle(format!("cannot read entry path: {}", error))
                    })?;
                    if is_reviewed_ignored_bundle_path(&archive_path)? {
                        continue;
                    }
                    let Some(relative) = normalize_tor_bundle_path(&archive_path)? else {
                        if !entry.header().entry_type().is_dir() {
                            return Err(invalid_tor_bundle("tor root is not a directory"));
                        }
                        continue;
                    };
                    let entry_type = entry.header().entry_type();
                    let destination = staging_dir.join(&relative);

                    if entry_type.is_dir() {
                        if !is_tor_bundle_directory(&relative) {
                            return Err(invalid_tor_bundle(
                                "unexpected directory in managed runtime",
                            ));
                        }
                        std::fs::create_dir_all(&destination).map_err(|error| {
                            QorError::FileSystem(format!(
                                "Failed to create Tor bundle directory: {}",
                                error
                            ))
                        })?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &destination,
                                std::fs::Permissions::from_mode(0o700),
                            )?;
                        }
                        continue;
                    }
                    if !entry_type.is_file()
                        || relative.components().count() == 1 && is_tor_bundle_directory(&relative)
                    {
                        return Err(invalid_tor_bundle(
                            "links and special entry types are forbidden",
                        ));
                    }

                    let declared_size = entry.header().size().map_err(|error| {
                        invalid_tor_bundle(format!("invalid entry size: {}", error))
                    })?;
                    extracted_bytes = extracted_bytes
                        .checked_add(declared_size)
                        .ok_or_else(|| invalid_tor_bundle("expanded data is too large"))?;
                    if extracted_bytes > MAX_TOR_EXTRACTED_BYTES {
                        return Err(invalid_tor_bundle("expanded data is too large"));
                    }

                    let parent = destination
                        .parent()
                        .ok_or_else(|| invalid_tor_bundle("entry has no parent directory"))?;
                    std::fs::create_dir_all(parent).map_err(|error| {
                        QorError::FileSystem(format!(
                            "Failed to create Tor bundle parent directory: {}",
                            error
                        ))
                    })?;
                    let mut output = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&destination)
                        .map_err(|error| {
                            QorError::FileSystem(format!(
                                "Failed to create Tor bundle file: {}",
                                error
                            ))
                        })?;
                    let copied = std::io::copy(&mut entry, &mut output).map_err(|error| {
                        QorError::FileSystem(format!(
                            "Failed to extract Tor bundle file: {}",
                            error
                        ))
                    })?;
                    if copied != declared_size {
                        return Err(invalid_tor_bundle("entry size does not match its header"));
                    }
                    output.sync_all().map_err(|error| {
                        QorError::FileSystem(format!(
                            "Failed to finalize Tor bundle file: {}",
                            error
                        ))
                    })?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let executable = relative == Path::new(&tor_executable)
                            || relative == Path::new(TRANSPORT_DIR).join(&transport_executable);
                        let mode = if executable { 0o700 } else { 0o600 };
                        std::fs::set_permissions(
                            &destination,
                            std::fs::Permissions::from_mode(mode),
                        )?;
                    }
                }

                let staged_tor = staging_dir.join(&tor_executable);
                let staged_transport = staging_dir.join(TRANSPORT_DIR).join(&transport_executable);
                if !is_regular_file_without_links(&staged_tor)
                    || !is_regular_file_without_links(&staged_transport)
                {
                    return Err(invalid_tor_bundle(
                        "required Tor or lyrebird executable is missing",
                    ));
                }

                for entry in std::fs::read_dir(&tor_dir).map_err(|error| {
                    QorError::FileSystem(format!("Failed to inspect Tor directory: {}", error))
                })? {
                    let entry = entry.map_err(|error| {
                        QorError::FileSystem(format!("Failed to inspect Tor entry: {}", error))
                    })?;
                    if is_managed_tor_top_level_name(&entry.file_name())
                        || entry.file_name() == OsStr::new(BUNDLE_MARKER_FILE)
                    {
                        remove_managed_path(&entry.path())?;
                    }
                }

                for entry in std::fs::read_dir(&staging_dir).map_err(|error| {
                    QorError::FileSystem(format!("Failed to inspect staged Tor bundle: {}", error))
                })? {
                    let entry = entry.map_err(|error| {
                        QorError::FileSystem(format!("Failed to inspect staged entry: {}", error))
                    })?;
                    let name = entry.file_name();
                    if !is_managed_tor_top_level_name(&name) {
                        return Err(invalid_tor_bundle("unexpected staged top-level entry"));
                    }
                    std::fs::rename(entry.path(), tor_dir.join(&name)).map_err(|error| {
                        QorError::FileSystem(format!(
                            "Failed to install staged Tor entry: {}",
                            error
                        ))
                    })?;
                }

                std::fs::remove_dir(&staging_dir).map_err(|error| {
                    QorError::FileSystem(format!(
                        "Failed to remove Tor staging directory: {}",
                        error
                    ))
                })?;
                write_private_file(
                    &tor_dir.join(BUNDLE_MARKER_FILE),
                    marker_contents.as_bytes(),
                )?;

                Ok(())
            })();

            if result.is_err() {
                let _ = std::fs::remove_dir_all(&staging_dir);
            }
            result
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))??;

        Ok(())
    }

    fn validate_config_with_transport_mode(
        &self,
        config: &str,
        stored: bool,
    ) -> QorResult<(String, Option<PathBuf>)> {
        if config.is_empty() {
            return Err(QorError::InvalidArgument("Empty configuration".to_string()));
        }

        if config.len() > MAX_CONFIG_SIZE {
            return Err(QorError::InvalidArgument(
                "Configuration too large".to_string(),
            ));
        }

        if config
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
        {
            return Err(QorError::InvalidArgument(
                "Configuration contains forbidden characters".to_string(),
            ));
        }

        let mut normalized = Vec::new();
        let managed_data_dir = self.tor_dir.join("data");
        let mut saw_cookie_authentication = false;
        let mut saw_safe_logging = false;
        let mut saw_data_directory = false;
        let mut saw_client_only = false;
        let mut saw_log = false;
        let mut saw_keepalive_period = false;

        for line in config.lines() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                normalized.push(line.to_string());
                continue;
            }

            if trimmed.len() > 1024 {
                return Err(QorError::InvalidArgument(
                    "Configuration line too long".to_string(),
                ));
            }

            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            let directive = parts[0];
            let value = parts.get(1).map(|s| s.trim()).unwrap_or("");

            if !ALLOWED_DIRECTIVES.contains(directive) {
                return Err(QorError::InvalidArgument(format!(
                    "Forbidden directive: {}",
                    directive
                )));
            }

            if directive == "DataDirectory" {
                if saw_data_directory {
                    return Err(QorError::InvalidArgument(
                        "Duplicate DataDirectory directive".to_string(),
                    ));
                }
                saw_data_directory = true;
                let supplied = PathBuf::from(value);
                let resolved = if supplied.is_absolute() {
                    supplied
                } else {
                    self.tor_dir.join(supplied)
                };
                if resolved != managed_data_dir {
                    return Err(QorError::InvalidArgument(
                        "DataDirectory must use the managed Tor data path".to_string(),
                    ));
                }
                normalized.push(format!("DataDirectory {}", managed_data_dir.display()));
            } else if directive == "ClientTransportPlugin" {
                let normalized_value = if stored {
                    self.normalize_stored_transport_plugin_value(value)?
                } else {
                    self.normalize_client_transport_plugin_value(value)?
                };
                normalized.push(format!("ClientTransportPlugin {}", normalized_value));
            } else if directive == "CookieAuthentication" {
                if saw_cookie_authentication || value != "1" {
                    return Err(QorError::InvalidArgument(
                        "CookieAuthentication must appear once with value 1".to_string(),
                    ));
                }
                saw_cookie_authentication = true;
                normalized.push("CookieAuthentication 1".to_string());
            } else if directive == "SafeLogging" {
                if saw_safe_logging || value != "1" {
                    return Err(QorError::InvalidArgument(
                        "SafeLogging must appear once with value 1".to_string(),
                    ));
                }
                saw_safe_logging = true;
                normalized.push("SafeLogging 1".to_string());
            } else if directive == "ClientOnly" {
                if saw_client_only || value != "1" {
                    return Err(QorError::InvalidArgument(
                        "ClientOnly must appear once with value 1".to_string(),
                    ));
                }
                saw_client_only = true;
                normalized.push("ClientOnly 1".to_string());
            } else if directive == "Log" {
                if saw_log || value != "notice stdout" {
                    return Err(QorError::InvalidArgument(
                        "Log must appear once as notice stdout".to_string(),
                    ));
                }
                saw_log = true;
                normalized.push("Log notice stdout".to_string());
            } else if directive == "KeepalivePeriod" {
                saw_keepalive_period = true;
                normalized.push(format!("KeepalivePeriod {}", value));
            } else {
                normalized.push(format!(
                    "{}{}",
                    directive,
                    if value.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", value)
                    }
                ));
            }
        }

        if !saw_cookie_authentication {
            normalized.push("CookieAuthentication 1".to_string());
        }
        if !saw_safe_logging {
            normalized.push("SafeLogging 1".to_string());
        }
        if !saw_data_directory {
            normalized.push(format!("DataDirectory {}", managed_data_dir.display()));
        }
        if !saw_client_only {
            normalized.push("ClientOnly 1".to_string());
        }
        if !saw_log {
            normalized.push("Log notice stdout".to_string());
        }
        if !saw_keepalive_period {
            normalized.push(format!("KeepalivePeriod {}", TOR_KEEPALIVE_PERIOD_SECS));
        }

        Ok((normalized.join("\n"), Some(managed_data_dir)))
    }

    fn validate_config(&self, config: &str) -> QorResult<(String, Option<PathBuf>)> {
        self.validate_config_with_transport_mode(config, false)
    }

    fn validate_stored_config(&self, config: &str) -> QorResult<(String, Option<PathBuf>)> {
        self.validate_config_with_transport_mode(config, true)
    }

    pub async fn configure(&self, config: &TorConfig) -> QorResult<bool> {
        let _operation_guard = self.operation_lock.lock().await;
        if self.is_running() {
            self.shutdown_now();
        }

        let (normalized_config, data_dir) = self.validate_config(&config.config)?;

        ensure_private_directory(&self.tor_dir)?;

        write_private_file(&self.config_path, normalized_config.as_bytes())?;

        if let Some(ref dir) = data_dir {
            ensure_private_directory(dir)?;
            *self.configured_data_dir.write() = Some(dir.clone());
        }

        Ok(true)
    }

    pub async fn mirror_configuration_from(&self, source: &TorManager) -> QorResult<bool> {
        let source_config = fs::read_to_string(&source.config_path).await.map_err(|_| {
            QorError::TorProcess("Primary Tor configuration is unavailable".to_string())
        })?;
        if source_config.len() > MAX_CONFIG_SIZE {
            return Err(QorError::TorProcess(
                "Primary Tor configuration is too large".to_string(),
            ));
        }
        let source_dir = source.tor_dir.to_string_lossy();
        let target_dir = self.tor_dir.to_string_lossy();
        let portable = source_config
            .lines()
            .filter(|line| {
                !matches!(
                    line.split_whitespace().next(),
                    Some("DataDirectory" | "SocksPort" | "ControlPort")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            .replace(source_dir.as_ref(), target_dir.as_ref());
        self.configure(&TorConfig { config: portable }).await
    }

    /// Start Tor process
    pub async fn start(&self) -> QorResult<TorStartResult> {
        let _operation_guard = self.operation_lock.lock().await;
        self.reap_exited_process();

        {
            let process = self.tor_process.read();
            if process.is_some() {
                return Ok(TorStartResult {
                    success: true,
                    starting: Some(false),
                    error: None,
                });
            }
        }

        let cleaned = self.cleanup_orphaned_processes_sync();
        if cleaned > 0 {
            info!(
                "[TOR] Reaped {} stale Tor process(es) before start",
                cleaned
            );
        }

        let current_bundle = self
            .pinned_bundle_target()
            .ok()
            .is_some_and(|(_, checksum)| self.has_current_bundle(checksum));
        if !current_bundle {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some("Embedded Tor runtime is unavailable".to_string()),
            });
        }
        if !self.config_path.exists() {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some("Tor is not configured yet".to_string()),
            });
        }

        if let Err(e) = self.ensure_managed_executables() {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some(e.safe_message()),
            });
        }
        if let Err(e) = self.normalize_configured_runtime().await {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some(e.safe_message()),
            });
        }

        ensure_private_directory(&self.tor_dir)?;
        let data_dir = self.get_data_dir();
        ensure_private_directory(&data_dir)?;

        let lock_file = data_dir.join("lock");
        let _ = fs::remove_file(&lock_file).await;

        let socks_port = self.find_available_port(9150).await;
        let control_port = self.find_available_port(socks_port + 1).await;

        self.effective_socks_port
            .store(socks_port, Ordering::Relaxed);
        self.effective_control_port
            .store(control_port, Ordering::Relaxed);

        let mut command = Command::new(&self.tor_path);
        command
            .args([
                "-f",
                &self.config_path.to_string_lossy(),
                "--DataDirectory",
                &data_dir.to_string_lossy(),
                "--SocksPort",
                &format!(
                    "127.0.0.1:{} IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestAddr IsolateDestPort",
                    socks_port
                ),
                "--ControlPort",
                &format!("127.0.0.1:{}", control_port),
                "--SafeSocks",
                "1",
            ])
            .env_clear()
            .envs(self.get_tor_environment())
            .current_dir(&self.tor_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = spawn_managed_tor(&mut command)
            .map_err(|e| QorError::TorProcess(format!("Failed to start Tor: {}", e)))?;

        tokio::time::sleep(Duration::from_millis(250)).await;
        match child.try_wait() {
            Ok(Some(status)) => {
                self.mark_process_stopped();
                return Ok(TorStartResult {
                    success: false,
                    starting: Some(false),
                    error: Some(format!("Tor exited during startup ({})", status)),
                });
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                self.mark_process_stopped();
                return Err(QorError::TorProcess(format!(
                    "Failed to inspect Tor process state: {error}"
                )));
            }
        }

        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            self.mark_process_stopped();
            return Err(QorError::TorProcess(
                "Tor process did not provide a stdout monitor".to_string(),
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            let _ = child.kill();
            let _ = child.wait();
            self.mark_process_stopped();
            return Err(QorError::TorProcess(
                "Tor process did not provide a stderr monitor".to_string(),
            ));
        };

        *self.tor_process.write() = Some(child);
        self.bootstrapped.store(false, Ordering::Relaxed);
        self.bootstrap_progress.store(0, Ordering::Relaxed);
        let process_generation = self
            .process_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);

        let bootstrapped = self.bootstrapped.clone();
        let bootstrap_progress = self.bootstrap_progress.clone();
        let generation_state = self.process_generation.clone();

        let bootstrapped_clone = bootstrapped.clone();
        let bootstrap_progress_clone = bootstrap_progress.clone();
        let stdout_generation_state = generation_state.clone();
        tokio::task::spawn_blocking(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                if stdout_generation_state.load(Ordering::Acquire) != process_generation {
                    break;
                }
                let Ok(read) = read_bounded_line(&mut reader, &mut line) else {
                    break;
                };
                if read == 0 {
                    break;
                }
                if let Some(pos) = line.find("Bootstrapped ") {
                    let rest = &line[pos + "Bootstrapped ".len()..];
                    if let Some(end_pos) = rest.find('%')
                        && let Ok(progress) = rest[..end_pos].parse::<u16>()
                    {
                        bootstrap_progress_clone.store(progress.min(100), Ordering::Relaxed);
                        if progress >= 100 {
                            bootstrapped_clone.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            line.zeroize();
        });

        let stderr_generation_state = generation_state;
        tokio::task::spawn_blocking(move || {
            let mut reader = std::io::BufReader::new(stderr);
            let mut line = String::new();
            loop {
                if stderr_generation_state.load(Ordering::Acquire) != process_generation {
                    break;
                }
                match read_bounded_line(&mut reader, &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        line.zeroize();
                    }
                }
            }
            line.zeroize();
        });

        Ok(TorStartResult {
            success: true,
            starting: Some(true),
            error: None,
        })
    }

    pub async fn stop(&self) -> QorResult<bool> {
        let _operation_guard = self.operation_lock.lock().await;
        self.shutdown_now();
        Ok(true)
    }

    pub fn is_running(&self) -> bool {
        self.reap_exited_process();
        let process = self.tor_process.read();
        process.is_some()
    }

    pub fn status(&self) -> TorStatus {
        self.reap_exited_process();
        let process = self.tor_process.read();

        TorStatus {
            is_running: process.is_some(),
            process_id: process.as_ref().map(|c| c.id()),
            socks_port: self.get_socks_port(),
            control_port: self.get_control_port(),
            bootstrapped: self.bootstrapped.load(Ordering::Relaxed),
            bootstrap_progress: self.bootstrap_progress.load(Ordering::Relaxed),
        }
    }

    pub async fn is_ready(&self) -> bool {
        if !self.is_running() {
            return false;
        }
        self.refresh_bootstrap_from_control().await;
        self.is_running() && self.bootstrapped.load(Ordering::Relaxed)
    }

    pub async fn rotate_circuit(&self) -> QorResult<CircuitRotationResult> {
        if !self.is_running() {
            return Ok(CircuitRotationResult {
                success: false,
                ip_changed: None,
                before_ip: None,
                after_ip: None,
                error: Some("Tor not running".to_string()),
            });
        }

        self.send_newnym_signal().await?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(CircuitRotationResult {
            success: true,
            ip_changed: None,
            before_ip: None,
            after_ip: None,
            error: None,
        })
    }

    async fn send_newnym_signal(&self) -> QorResult<()> {
        let control_port = self.get_control_port();
        let cookie_path = self.control_cookie_path();

        tokio::task::spawn_blocking(move || {
            let mut conn = Self::control_authenticate(control_port, &cookie_path)?;

            writeln!(conn.stream, "SIGNAL NEWNYM")?;

            let mut line = String::new();
            if read_bounded_line(&mut conn.reader, &mut line)? == 0 {
                return Err(QorError::TorControl(
                    "Tor control closed during circuit rotation".to_string(),
                ));
            }

            if line.trim_end() != "250 OK" {
                return Err(QorError::TorControl(
                    "Circuit not established yet".to_string(),
                ));
            }

            Ok::<_, QorError>(())
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))?
    }

    pub async fn publish_onion_service(
        &self,
        port_mappings: &[(u16, u16)],
    ) -> QorResult<PublishedOnionService> {
        if port_mappings.is_empty()
            || port_mappings.len() > 8
            || port_mappings
                .iter()
                .any(|(virtual_port, local_port)| *virtual_port == 0 || *local_port == 0)
        {
            return Err(QorError::InvalidArgument(
                "Invalid onion service port".to_string(),
            ));
        }
        let control_port = self.get_control_port();
        let cookie_path = self.control_cookie_path();
        let port_mappings = port_mappings.to_vec();

        tokio::task::spawn_blocking(move || {
            let mut conn = Self::control_authenticate(control_port, &cookie_path)?;
            write!(conn.stream, "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK")?;
            for (virtual_port, local_port) in port_mappings {
                write!(
                    conn.stream,
                    " Port={},127.0.0.1:{}",
                    virtual_port, local_port
                )?;
            }
            writeln!(conn.stream)?;

            let mut service_id: Option<String> = None;
            for _ in 0..MAX_CONTROL_RESPONSE_LINES {
                let mut line = String::new();
                if read_bounded_line(&mut conn.reader, &mut line)? == 0 {
                    return Err(QorError::TorControl(
                        "Tor control closed during onion publish".to_string(),
                    ));
                }
                let trimmed = line.trim_end();
                if let Some(rest) = trimmed.strip_prefix("250-ServiceID=") {
                    let candidate = rest.trim().to_ascii_lowercase();
                    if !is_valid_onion_service_id(&candidate) {
                        return Err(QorError::TorControl(
                            "Tor returned a malformed onion service id".to_string(),
                        ));
                    }
                    service_id = Some(candidate);
                } else if trimmed == "250 OK" {
                    break;
                } else if trimmed.starts_with('5') {
                    return Err(QorError::TorControl(
                        "Tor refused the onion service request".to_string(),
                    ));
                }
                line.zeroize();
            }

            match service_id {
                Some(id) => Ok(PublishedOnionService {
                    onion_host: format!("{}.onion", id),
                    _control: conn,
                }),
                None => Err(QorError::TorControl(
                    "Tor did not return an onion service id".to_string(),
                )),
            }
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))?
    }

    fn control_authenticate(control_port: u16, cookie_path: &Path) -> QorResult<ControlConnection> {
        let mut cookie = Self::read_control_cookie(cookie_path)?;
        let mut encoded_cookie = hex::encode(cookie);
        cookie.zeroize();

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", control_port))
            .map_err(|e| QorError::TorControl(format!("Failed to connect control port: {}", e)))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        let write_result = writeln!(stream, "AUTHENTICATE {}", encoded_cookie);
        encoded_cookie.zeroize();
        write_result?;

        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        if read_bounded_line(&mut reader, &mut line)? == 0 || line.trim_end() != "250 OK" {
            return Err(QorError::TorControl(
                "Control port authentication failed".to_string(),
            ));
        }

        Ok(ControlConnection { stream, reader })
    }

    fn control_get_bootstrap_status(
        control_port: u16,
        cookie_path: &Path,
    ) -> QorResult<(u16, bool)> {
        let mut conn = Self::control_authenticate(control_port, cookie_path)?;
        let mut line = String::new();
        let mut progress = 0u16;
        let mut bootstrapped = false;
        let mut saw_status = false;
        let mut saw_terminator = false;

        writeln!(conn.stream, "GETINFO status/bootstrap-phase")?;
        for _ in 0..MAX_CONTROL_RESPONSE_LINES {
            let n = read_bounded_line(&mut conn.reader, &mut line)?;
            if n == 0 {
                break;
            }
            let l = line.trim();
            if l.starts_with("250-status/bootstrap-phase=") {
                saw_status = true;
                if let Some(pos) = l.find("PROGRESS=") {
                    let rest = &l[pos + "PROGRESS=".len()..];
                    let digits = rest
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect::<String>();
                    if let Ok(parsed) = digits.parse::<u16>() {
                        progress = parsed.min(100);
                    }
                }
                if progress == 100 || l.split_whitespace().any(|part| part == "TAG=done") {
                    progress = 100;
                    bootstrapped = true;
                }
            } else if l == "250 OK" {
                saw_terminator = true;
                break;
            } else if l.starts_with('5') {
                return Err(QorError::TorControl(format!(
                    "GETINFO status/bootstrap-phase failed: {}",
                    l
                )));
            } else {
                return Err(QorError::TorControl(
                    "Tor control returned an unexpected bootstrap response".to_string(),
                ));
            }
        }

        if !saw_status || !saw_terminator {
            return Err(QorError::TorControl(
                "Tor control returned an incomplete bootstrap response".to_string(),
            ));
        }

        Ok((progress, bootstrapped))
    }

    async fn refresh_bootstrap_from_control(&self) {
        if !self.is_running() {
            return;
        }

        let control_port = self.get_control_port();
        let cookie_path = self.control_cookie_path();
        let generation = self.process_generation.load(Ordering::Acquire);

        let result = tokio::task::spawn_blocking(move || {
            Self::control_get_bootstrap_status(control_port, &cookie_path)
        })
        .await;
        if self.process_generation.load(Ordering::Acquire) != generation {
            return;
        }

        match result {
            Ok(Ok((progress, bootstrapped))) => {
                self.control_read_failures.store(0, Ordering::Relaxed);
                self.bootstrap_progress
                    .store(progress.min(100), Ordering::Relaxed);
                self.bootstrapped.store(bootstrapped, Ordering::Relaxed);
            }
            _ => {
                let failures = self
                    .control_read_failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if failures >= CONTROL_READ_FAILURE_THRESHOLD {
                    warn!(
                        "[TOR] control bootstrap read failed {} times in a row; marking not bootstrapped",
                        failures
                    );
                    self.bootstrap_progress.store(0, Ordering::Relaxed);
                    self.bootstrapped.store(false, Ordering::Relaxed);
                } else {
                    warn!(
                        "[TOR] transient control bootstrap read failure ({}/{}); keeping last known state (bootstrapped={})",
                        failures,
                        CONTROL_READ_FAILURE_THRESHOLD,
                        self.bootstrapped.load(Ordering::Relaxed)
                    );
                }
            }
        }
    }

    fn control_get_bootstrap_and_circuit_established(
        control_port: u16,
        cookie_path: &Path,
    ) -> QorResult<()> {
        let (_, bootstrapped) = Self::control_get_bootstrap_status(control_port, cookie_path)?;

        if !bootstrapped {
            return Err(QorError::TorControl(
                "Tor control reports bootstrap incomplete".to_string(),
            ));
        }

        Ok(())
    }

    async fn verify_local_connection(&self) -> QorResult<()> {
        let control_port = self.get_control_port();
        let socks_port = self.get_socks_port();
        let cookie_path = self.control_cookie_path();

        tokio::task::spawn_blocking(move || {
            Self::control_get_bootstrap_and_circuit_established(control_port, &cookie_path)
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))??;

        let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port)
            .parse()
            .map_err(|e| QorError::Network(format!("Invalid SOCKS address: {}", e)))?;
        tokio::task::spawn_blocking(move || {
            let stream = TcpStream::connect_timeout(&socks_addr, Duration::from_secs(2))
                .map_err(|e| QorError::Network(format!("SOCKS listener unavailable: {}", e)))?;
            let _ = stream.shutdown(std::net::Shutdown::Both);
            Ok::<_, QorError>(())
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))??;

        Ok(())
    }

    /// Verify Tor connection
    pub async fn verify_connection(&self) -> QorResult<TorVerifyResult> {
        if !self.bootstrapped.load(Ordering::Relaxed) {
            self.refresh_bootstrap_from_control().await;
            if !self.bootstrapped.load(Ordering::Relaxed) {
                return Ok(TorVerifyResult {
                    success: false,
                    ip_address: None,
                    error: Some("Tor not bootstrapped yet".to_string()),
                });
            }
        }

        match tokio::time::timeout(Duration::from_secs(10), self.verify_local_connection()).await {
            Ok(Ok(())) => Ok(TorVerifyResult {
                success: true,
                ip_address: None,
                error: None,
            }),
            Ok(Err(e)) => {
                error!("Tor connection verification failed");
                Ok(TorVerifyResult {
                    success: false,
                    ip_address: None,
                    error: Some(e.safe_message()),
                })
            }
            Err(_) => Ok(TorVerifyResult {
                success: false,
                ip_address: None,
                error: Some("Tor verification timed out".to_string()),
            }),
        }
    }
}

pub async fn init(app_data_path: PathBuf) -> QorResult<Arc<TorManager>> {
    let manager = TorManager::new(app_data_path);
    let _stale = manager.cleanup_orphaned_processes_sync();
    manager.materialize_embedded_bundle().await?;
    Ok(Arc::new(manager))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pir_manager_uses_distinct_runtime_and_mirrored_configuration() {
        let root = std::env::temp_dir().join(format!(
            "qor-pir-tor-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let primary = TorManager::new(root.join("primary"));
        let pir = TorManager::new(root.join("pir"));
        primary
            .configure(&TorConfig {
                config: "ClientOnly 1".to_string(),
            })
            .await
            .unwrap();
        pir.mirror_configuration_from(&primary).await.unwrap();
        let config = std::fs::read_to_string(&pir.config_path).unwrap();
        assert_ne!(primary.tor_path, pir.tor_path);
        assert_ne!(primary.config_path, pir.config_path);
        assert!(config.contains(&pir.tor_dir.join("data").to_string_lossy().to_string()));
        assert!(!config.contains(&primary.tor_dir.to_string_lossy().to_string()));
        let _ = std::fs::remove_dir_all(root);
    }
}
