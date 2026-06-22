//! Tor Manager

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::crypto::{hash, random};
use crate::error::{QorError, QorResult};

const DEFAULT_SOCKS_PORT: u16 = 9050;
const DEFAULT_CONTROL_PORT: u16 = 9051;
const PORT_SCAN_RANGE: u16 = 100;
const MAX_CONFIG_SIZE: usize = 50000;
const BOOTSTRAP_TIMEOUT_MS: u64 = 120000;
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;
const CONTROL_PASSWORD_FILE: &str = ".control_password";
const TRANSPORT_DIR: &str = "pluggable_transports";
const DEFAULT_TRANSPORT: &str = "lyrebird";

// Allowed Tor config directives
lazy_static::lazy_static! {
    static ref ALLOWED_DIRECTIVES: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("AvoidDiskWrites");
        set.insert("Bridge");
        set.insert("CircuitBuildTimeout");
        set.insert("ClientOnly");
        set.insert("ClientTransportPlugin");
        set.insert("ControlPort");
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
        set.insert("HashedControlPassword");
        set.insert("LearnCircuitBuildTimeout");
        set.insert("Log");
        set.insert("MaxCircuitDirtiness");
        set.insert("NewCircuitPeriod");
        set.insert("NumEntryGuards");
        set.insert("ProtocolWarnings");
        set.insert("SafeLogging");
        set.insert("SocksAuth");
        set.insert("SocksListenAddress");
        set.insert("SocksPolicy");
        set.insert("SocksPort");
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

/// Tor installation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorInstallStatus {
    pub is_installed: bool,
    pub version: Option<String>,
    pub path: Option<String>,
}

/// Tor configuration input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    pub config: String,
}

/// Tor start result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStartResult {
    pub success: bool,
    pub starting: Option<bool>,
    pub error: Option<String>,
}

/// Tor status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStatus {
    pub is_running: bool,
    pub process_id: Option<u32>,
    pub socks_port: u16,
    pub control_port: u16,
    pub bootstrapped: bool,
    pub bootstrap_progress: u16,
}

/// Tor info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorInfo {
    pub version: String,
    pub socks_port: u16,
    pub control_port: u16,
    pub bootstrapped: bool,
    pub bootstrap_progress: u16,
}

/// Circuit rotation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitRotationResult {
    pub success: bool,
    pub ip_changed: Option<bool>,
    pub before_ip: Option<String>,
    pub after_ip: Option<String>,
    pub error: Option<String>,
}

/// Tor download result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorDownloadResult {
    pub success: bool,
    pub already_exists: Option<bool>,
    pub error: Option<String>,
}

/// Tor connection verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorVerifyResult {
    pub success: bool,
    pub ip_address: Option<String>,
    pub error: Option<String>,
}

/// Wrapper around Tor control connection
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

/// Tor Manager for managing Tor process lifecycle
pub struct TorManager {
    /// App data directory
    _app_data_path: PathBuf,
    /// Tor installation directory
    tor_dir: PathBuf,
    /// Tor binary path
    tor_path: PathBuf,
    /// Tor config path
    config_path: PathBuf,
    /// Tor process handle
    tor_process: RwLock<Option<Child>>,
    /// Current platform
    platform: String,
    /// Current architecture
    arch: String,
    /// Effective SOCKS port
    effective_socks_port: AtomicU16,
    /// Effective control port
    effective_control_port: AtomicU16,
    /// Bootstrap status
    bootstrapped: Arc<AtomicBool>,
    /// Bootstrap progress (0-100)
    bootstrap_progress: Arc<AtomicU16>,
    /// Control password
    control_password: RwLock<Option<String>>,
    /// Cached Tor version
    version_cache: RwLock<Option<String>>,
    /// Configured data directory
    configured_data_dir: RwLock<Option<PathBuf>>,
    /// Health monitor running
    health_monitor_running: AtomicBool,
}

impl TorManager {
    fn find_managed_tor_pids(&self, system: &mut System) -> Vec<u32> {
        let tor_path = self.tor_path.to_string_lossy().to_string();
        let config_path = self.config_path.to_string_lossy().to_string();
        let mut pids = Vec::new();

        system.refresh_processes();

        for (pid, process) in system.processes() {
            let cmdline = format!("{:?}", process.cmd());
            if !(cmdline.contains(&tor_path) && cmdline.contains(&config_path)) {
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

        for (candidate, _) in system.processes() {
            if let Ok(raw_pid) = candidate.to_string().parse::<u32>() {
                if raw_pid == pid {
                    return true;
                }
            }
        }

        false
    }

    fn terminate_pid_sync(system: &mut System, pid: u32) -> bool {
        system.refresh_processes();
        for (candidate, process) in system.processes() {
            if let Ok(raw_pid) = candidate.to_string().parse::<u32>() {
                if raw_pid == pid {
                    let _ = process.kill();
                    break;
                }
            }
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !Self::process_exists(system, pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }

        // Retry once in case first signal raced with process state refresh
        system.refresh_processes();
        for (candidate, process) in system.processes() {
            if let Ok(raw_pid) = candidate.to_string().parse::<u32>() {
                if raw_pid == pid {
                    let _ = process.kill();
                    break;
                }
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
        self.bootstrapped.store(false, Ordering::Relaxed);
        self.bootstrap_progress.store(0, Ordering::Relaxed);
        self.health_monitor_running.store(false, Ordering::Relaxed);
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

    /// Reap orphaned Tor processes belonging to this app instance
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

    /// Immediate synchronous shutdown used during app teardown
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

    /// Create new Tor Manager
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
            platform,
            arch,
            effective_socks_port: AtomicU16::new(DEFAULT_SOCKS_PORT),
            effective_control_port: AtomicU16::new(DEFAULT_CONTROL_PORT),
            bootstrapped: Arc::new(AtomicBool::new(false)),
            bootstrap_progress: Arc::new(AtomicU16::new(0)),
            control_password: RwLock::new(None),
            version_cache: RwLock::new(None),
            configured_data_dir: RwLock::new(None),
            health_monitor_running: AtomicBool::new(false),
        }
    }

    /// Get SOCKS port
    pub fn get_socks_port(&self) -> u16 {
        self.effective_socks_port.load(Ordering::Relaxed)
    }

    /// Get control port
    pub fn get_control_port(&self) -> u16 {
        self.effective_control_port.load(Ordering::Relaxed)
    }

    /// Check if port is valid
    fn is_valid_port(port: u16) -> bool {
        port >= 1
    }

    /// Check if port is available
    async fn is_port_available(&self, port: u16) -> bool {
        if !Self::is_valid_port(port) {
            return false;
        }

        match std::net::TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Find available port starting from given port
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

    /// Get Tor directory
    pub fn get_tor_dir(&self) -> PathBuf {
        self.tor_dir.clone()
    }

    /// Get data directory
    fn get_data_dir(&self) -> PathBuf {
        let configured = self.configured_data_dir.read();
        if let Some(dir) = configured.as_ref() {
            return dir.clone();
        }

        let username = whoami::username();
        let pid = std::process::id();
        self.tor_dir.join(format!("data-{}-{}", username, pid))
    }

    /// Get Tor environment variables
    fn get_tor_environment(&self) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = std::env::vars().collect();

        // Add library paths
        let lib_dirs: Vec<PathBuf> = vec![
            self.tor_dir.join("lib64"),
            self.tor_dir.join("lib"),
            self.tor_dir.clone(),
        ]
        .into_iter()
        .filter(|p| p.exists())
        .collect();

        if !lib_dirs.is_empty() {
            let lib_path = lib_dirs
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(":");

            env.push(("LD_LIBRARY_PATH".to_string(), lib_path.clone()));

            if self.platform == "macos" {
                env.push(("DYLD_LIBRARY_PATH".to_string(), lib_path));
            }
        }

        // Add to PATH
        let existing_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!(
            "{}:{}:{}",
            self.tor_dir.to_string_lossy(),
            self.tor_dir.join("pluggable_transports").to_string_lossy(),
            existing_path
        );
        env.push(("PATH".to_string(), new_path));

        env
    }

    fn executable_name(&self, name: &str) -> String {
        if self.platform == "windows" && !name.to_ascii_lowercase().ends_with(".exe") {
            format!("{}.exe", name)
        } else {
            name.to_string()
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

    fn push_transport_candidate(&self, candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
        if !candidates.iter().any(|p| p == &candidate) {
            candidates.push(candidate.clone());
        }

        if self.platform == "windows" && candidate.extension().is_none() {
            let mut with_exe = candidate;
            with_exe.set_extension("exe");
            if !candidates.iter().any(|p| p == &with_exe) {
                candidates.push(with_exe);
            }
        }
    }

    fn transport_path_candidates(&self, raw_path: &str) -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        let path = PathBuf::from(raw_path);

        if path.is_absolute() {
            self.push_transport_candidate(&mut candidates, path);
        } else if raw_path.contains('/') || raw_path.contains('\\') {
            self.push_transport_candidate(&mut candidates, self.tor_dir.join(path));
        } else {
            self.push_transport_candidate(&mut candidates, self.tor_dir.join(raw_path));
            self.push_transport_candidate(
                &mut candidates,
                self.tor_dir.join(TRANSPORT_DIR).join(raw_path),
            );

            if let Some(paths) = std::env::var_os("PATH") {
                for dir in std::env::split_paths(&paths) {
                    self.push_transport_candidate(&mut candidates, dir.join(raw_path));
                }
            }
        }

        candidates
    }

    fn first_existing_transport_path(&self, raw_path: &str) -> Option<PathBuf> {
        self.transport_path_candidates(raw_path)
            .into_iter()
            .find(|candidate| candidate.is_file())
    }

    fn transport_methods_need_lyrebird(methods: &str) -> bool {
        methods.split(',').any(|method| {
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
        })
    }

    fn ensure_executable_path(path: &Path) -> QorResult<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = std::fs::metadata(path)?;
            let mut permissions = metadata.permissions();
            let mode = permissions.mode();
            if mode & 0o700 != 0o700 {
                permissions.set_mode(mode | 0o700);
                std::fs::set_permissions(path, permissions)?;
            }
        }

        Ok(())
    }

    fn ensure_managed_executables(&self) -> QorResult<()> {
        if self.tor_path.is_file() {
            Self::ensure_executable_path(&self.tor_path)?;
        }

        for name in [
            DEFAULT_TRANSPORT,
            "snowflake-client",
            "obfs4proxy",
            "conjure-client",
        ] {
            let path = self.managed_transport_path(name);
            if path.is_file() {
                Self::ensure_executable_path(&path)?;
            }
        }

        Ok(())
    }

    fn normalize_client_transport_plugin_value(&self, value: &str) -> QorResult<String> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 || !parts[1].eq_ignore_ascii_case("exec") {
            return Err(QorError::InvalidArgument(
                "Invalid ClientTransportPlugin directive".to_string(),
            ));
        }

        let methods = parts[0];
        let raw_path = parts[2];
        let args = &parts[3..];

        let mut config_path = raw_path.to_string();
        let mut resolved_path = self.first_existing_transport_path(raw_path);

        if resolved_path.is_none() && Self::transport_methods_need_lyrebird(methods) {
            let managed = self.managed_transport_path(DEFAULT_TRANSPORT);
            if managed.is_file() {
                config_path = self.managed_transport_config_path(DEFAULT_TRANSPORT);
                resolved_path = Some(managed);
            }
        }

        let resolved = resolved_path.ok_or_else(|| {
            QorError::InvalidArgument(format!("Bridge transport binary not found: {}", raw_path))
        })?;
        Self::ensure_executable_path(&resolved)?;

        let extra_args = if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        };

        Ok(format!("{} exec {}{}", methods, config_path, extra_args))
    }

    fn normalize_transport_plugin_lines(&self, config: &str) -> QorResult<(String, bool)> {
        let mut changed = false;
        let mut normalized_lines = Vec::new();

        for line in config.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                normalized_lines.push(line.to_string());
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            let directive = parts[0];
            let value = parts.get(1).map(|s| s.trim()).unwrap_or("");

            if directive == "ClientTransportPlugin" {
                let normalized_value = self.normalize_client_transport_plugin_value(value)?;
                let normalized_line = format!("ClientTransportPlugin {}", normalized_value);
                if normalized_line != trimmed {
                    changed = true;
                }
                normalized_lines.push(normalized_line);
            } else {
                normalized_lines.push(line.to_string());
            }
        }

        Ok((normalized_lines.join("\n"), changed))
    }

    async fn normalize_configured_transport_plugins(&self) -> QorResult<()> {
        let config = fs::read_to_string(&self.config_path)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to read config: {}", e)))?;
        let (normalized, changed) = self.normalize_transport_plugin_lines(&config)?;

        if changed {
            fs::write(&self.config_path, normalized)
                .await
                .map_err(|e| QorError::FileSystem(format!("Failed to update config: {}", e)))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&self.config_path, perms).ok();
            }
        }

        Ok(())
    }

    /// Check Tor installation status
    pub async fn check_installation(&self) -> QorResult<TorInstallStatus> {
        let metadata = fs::metadata(&self.tor_path).await;
        let transport_metadata = fs::metadata(self.managed_transport_path(DEFAULT_TRANSPORT)).await;

        match (metadata, transport_metadata) {
            (Ok(meta), Ok(transport_meta)) if meta.is_file() && transport_meta.is_file() => {
                let version = self.get_tor_version().await.ok();
                Ok(TorInstallStatus {
                    is_installed: true,
                    version,
                    path: Some(self.tor_path.to_string_lossy().to_string()),
                })
            }
            _ => Ok(TorInstallStatus {
                is_installed: false,
                version: None,
                path: None,
            }),
        }
    }

    /// Get Tor version
    pub async fn get_tor_version(&self) -> QorResult<String> {
        if let Some(version) = self.version_cache.read().clone() {
            return Ok(version);
        }

        let output = Command::new(&self.tor_path)
            .arg("--version")
            .envs(self.get_tor_environment())
            .current_dir(&self.tor_dir)
            .output()
            .map_err(|e| QorError::TorProcess(format!("Failed to get version: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse version
        if let Some(captures) = regex::Regex::new(r"Tor (?:version )?(\d+\.\d+\.\d+)")
            .ok()
            .and_then(|re| re.captures(&stdout))
        {
            if let Some(version) = captures.get(1) {
                let parsed = version.as_str().to_string();
                *self.version_cache.write() = Some(parsed.clone());
                return Ok(parsed);
            }
        }

        *self.version_cache.write() = Some("unknown".to_string());
        Ok("unknown".to_string())
    }

    /// Get Tor info
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

    /// Get Tor download URL
    pub async fn get_download_url(&self) -> QorResult<String> {
        let arch_map = match self.platform.as_str() {
            "linux" => match self.arch.as_str() {
                "x86_64" => Some("linux-x86_64"),
                "aarch64" => Some("linux-aarch64"),
                _ => None,
            },
            "macos" => match self.arch.as_str() {
                "x86_64" => Some("macos-x86_64"),
                "aarch64" => Some("macos-aarch64"),
                _ => None,
            },
            "windows" => match self.arch.as_str() {
                "x86_64" => Some("windows-x86_64"),
                "x86" => Some("windows-i686"),
                _ => None,
            },
            _ => None,
        };

        let arch = arch_map.ok_or_else(|| {
            QorError::NotSupported(format!(
                "Unsupported platform: {}/{}",
                self.platform, self.arch
            ))
        })?;

        // Fetch latest version if not cached or specified
        let version = self
            .fetch_latest_tor_version()
            .await
            .unwrap_or_else(|_| "15.0.3".to_string());

        // Use Tor Project's official download URL format
        let base_url = format!(
            "https://dist.torproject.org/torbrowser/{}/tor-expert-bundle-{}-{}.tar.gz",
            version, arch, version
        );

        Ok(base_url)
    }

    /// Fetch latest Tor version from dist.torproject.org
    async fn fetch_latest_tor_version(&self) -> QorResult<String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| QorError::Network(format!("Failed to create client: {}", e)))?;

        let response = client
            .get("https://dist.torproject.org/torbrowser/")
            .send()
            .await
            .map_err(|e| QorError::Network(format!("Failed to reach Tor Project: {}", e)))?;

        let html = response
            .text()
            .await
            .map_err(|e| QorError::Network(format!("Failed to read response: {}", e)))?;

        // Simple extraction of the latest version (looks for directories like 14.x.x, 15.x.x)
        let re = regex::Regex::new(r#"href="(\d+\.\d+\.\d+)/""#)
            .map_err(|e| QorError::Internal(format!("Regex error: {}", e)))?;

        let mut versions: Vec<String> = re
            .captures_iter(&html)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect();

        // Sort versions
        versions.sort_by(|a, b| {
            let parse = |s: &str| {
                s.split('.')
                    .map(|v| v.parse::<u32>().unwrap_or(0))
                    .collect::<Vec<u32>>()
            };
            parse(b).cmp(&parse(a))
        });

        versions
            .into_iter()
            .next()
            .ok_or_else(|| QorError::NotFound("Latest version not found".to_string()))
    }

    /// Download Tor
    pub async fn download(&self) -> QorResult<TorDownloadResult> {
        // Create tor directory
        fs::create_dir_all(&self.tor_dir)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to create tor dir: {}", e)))?;

        // Check if already installed with the pluggable transport helper needed for bridges
        if self.tor_path.exists() && self.managed_transport_path(DEFAULT_TRANSPORT).exists() {
            return Ok(TorDownloadResult {
                success: true,
                already_exists: Some(true),
                error: None,
            });
        }

        let download_url = self.get_download_url().await?;
        let archive_filename = download_url
            .split('/')
            .last()
            .ok_or_else(|| QorError::InvalidArgument("Invalid download URL".to_string()))?;
        let archive_path = self.tor_dir.join(archive_filename);

        // Cleanup potential partial downloads
        if archive_path.exists() {
            let _ = fs::remove_file(&archive_path).await;
        }
        let checksum_path = self.tor_dir.join("sha256sums.txt");
        if checksum_path.exists() {
            let _ = fs::remove_file(&checksum_path).await;
        }

        // Download archive
        self.download_file(&download_url, &archive_path).await?;

        // Download and verify checksum
        let version = self
            .fetch_latest_tor_version()
            .await
            .unwrap_or_else(|_| "15.0.3".to_string());
        let checksum_url = format!(
            "https://dist.torproject.org/torbrowser/{}/sha256sums-unsigned-build.txt",
            version
        );
        let checksum_path = self.tor_dir.join("sha256sums.txt");

        if let Err(_) = self.download_file(&checksum_url, &checksum_path).await {
            // Try signed checksums
            let signed_url = checksum_url.replace("unsigned", "signed");
            self.download_file(&signed_url, &checksum_path).await?;
        }

        // Verify SHA256
        self.verify_sha256(&archive_path, &checksum_path).await?;

        // Extract archive
        self.extract_tor_bundle(&archive_path).await?;
        self.ensure_managed_executables()?;

        // Cleanup
        let _ = fs::remove_file(&archive_path).await;
        let _ = fs::remove_file(&checksum_path).await;

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&self.tor_path, perms)
                .map_err(|e| QorError::FileSystem(format!("Failed to set permissions: {}", e)))?;
        }

        Ok(TorDownloadResult {
            success: true,
            already_exists: Some(false),
            error: None,
        })
    }

    /// Download a file
    async fn download_file(&self, url: &str, dest: &PathBuf) -> QorResult<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            .no_gzip()
            .build()
            .map_err(|e| QorError::Network(format!("Failed to create HTTP client: {}", e)))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| QorError::Network(format!("Download failed for {}: {}", url, e)))?;

        if !response.status().is_success() {
            return Err(QorError::Network(format!(
                "HTTP {} fetching {}",
                response.status(),
                url
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| QorError::Network(format!("Failed to read response: {}", e)))?;

        fs::write(dest, &bytes)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to write file: {}", e)))?;

        Ok(())
    }

    /// Verify SHA256 checksum
    async fn verify_sha256(
        &self,
        archive_path: &PathBuf,
        checksum_path: &PathBuf,
    ) -> QorResult<()> {
        let checksum_content = fs::read_to_string(checksum_path)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to read checksums: {}", e)))?;

        let filename = archive_path
            .file_name()
            .ok_or_else(|| QorError::InvalidArgument("Invalid archive path".to_string()))?
            .to_string_lossy();

        // Find checksum for our file
        let expected = checksum_content
            .lines()
            .find_map(|line| {
                if line.contains(&*filename) {
                    line.split_whitespace().next().map(|s| s.to_lowercase())
                } else {
                    None
                }
            })
            .ok_or_else(|| QorError::Verification("Checksum not found".to_string()))?;

        // Calculate actual checksum
        let file_bytes = fs::read(archive_path)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to read archive: {}", e)))?;

        let actual = hex::encode(hash::sha256(&file_bytes));

        if actual != expected {
            return Err(QorError::Verification(format!(
                "SHA256 mismatch for {}: expected {}, got {}",
                filename, expected, actual
            )));
        }

        Ok(())
    }

    /// Extract Tor bundle
    async fn extract_tor_bundle(&self, archive_path: &PathBuf) -> QorResult<()> {
        let archive_path = archive_path.clone();
        let tor_dir = self.tor_dir.clone();

        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&archive_path)
                .map_err(|e| QorError::FileSystem(format!("Failed to open archive: {}", e)))?;

            let decoder = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);

            for entry in archive
                .entries()
                .map_err(|e| QorError::FileSystem(e.to_string()))?
            {
                let mut entry = entry.map_err(|e| QorError::FileSystem(e.to_string()))?;
                let path = entry
                    .path()
                    .map_err(|e| QorError::FileSystem(e.to_string()))?;

                // Filter to only allowed files
                let path_str = path.to_string_lossy();
                let allowed = [
                    "tor",
                    "tor.exe",
                    "lib",
                    "lib64",
                    "obfs4proxy",
                    "snowflake-client",
                    "lyrebird",
                    "geoip",
                    "geoip6",
                    "pluggable_transports",
                ];

                if !allowed.iter().any(|a| path_str.contains(a)) {
                    continue;
                }

                // Strip leading directory
                let stripped = path.components().skip(1).collect::<PathBuf>();
                if stripped.as_os_str().is_empty() {
                    continue;
                }

                let dest = tor_dir.join(&stripped);

                if entry.header().entry_type().is_dir() {
                    std::fs::create_dir_all(&dest).ok();
                } else {
                    if let Some(parent) = dest.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }
                    entry.unpack(&dest).ok();
                }
            }

            Ok::<_, QorError>(())
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))??;

        Ok(())
    }

    /// Validate Tor config
    fn validate_config(&self, config: &str) -> QorResult<(String, Option<PathBuf>)> {
        if config.is_empty() {
            return Err(QorError::InvalidArgument("Empty configuration".to_string()));
        }

        if config.len() > MAX_CONFIG_SIZE {
            return Err(QorError::InvalidArgument(
                "Configuration too large".to_string(),
            ));
        }

        // Check for forbidden characters
        if config
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
        {
            return Err(QorError::InvalidArgument(
                "Configuration contains forbidden characters".to_string(),
            ));
        }

        let mut normalized = Vec::new();
        let mut data_dir = None;

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

            // Parse directive
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
                let resolved = if value.starts_with('/')
                    || (self.platform == "windows" && value.chars().nth(1) == Some(':'))
                {
                    PathBuf::from(value)
                } else {
                    self.tor_dir
                        .join(if value.is_empty() { "data" } else { value })
                };

                let normalized_path = std::fs::canonicalize(&resolved).unwrap_or(resolved.clone());
                let tor_dir_normalized =
                    std::fs::canonicalize(&self.tor_dir).unwrap_or(self.tor_dir.clone());

                if !normalized_path.starts_with(&tor_dir_normalized) {
                    return Err(QorError::InvalidArgument(
                        "DataDirectory outside allowed path".to_string(),
                    ));
                }

                data_dir = Some(normalized_path.clone());
                normalized.push(format!("DataDirectory {}", normalized_path.display()));
            } else if directive == "ClientTransportPlugin" {
                let normalized_value = self.normalize_client_transport_plugin_value(value)?;
                normalized.push(format!("ClientTransportPlugin {}", normalized_value));
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

        // Add default data directory if not specified
        if data_dir.is_none() {
            let default_data_dir = self.tor_dir.join("data");
            data_dir = Some(default_data_dir.clone());
            normalized.push(format!("DataDirectory {}", default_data_dir.display()));
        }

        Ok((normalized.join("\n"), data_dir))
    }

    /// Configure Tor
    pub async fn configure(&self, config: &TorConfig) -> QorResult<bool> {
        let (mut normalized_config, data_dir) = self.validate_config(&config.config)?;

        // Load or generate control password
        let password = match self.load_control_password().await {
            Some(p) => p,
            None => {
                let p = hex::encode(random::random_bytes(32));
                self.persist_control_password(&p).await?;
                p
            }
        };
        *self.control_password.write() = Some(password.clone());

        // Hash the password using Tor
        let output = Command::new(&self.tor_path)
            .args(["--hash-password", &password])
            .envs(self.get_tor_environment())
            .current_dir(&self.tor_dir)
            .output()
            .map_err(|e| QorError::TorProcess(format!("Failed to hash password: {}", e)))?;

        let hashed = String::from_utf8_lossy(&output.stdout)
            .lines()
            .last()
            .unwrap_or("")
            .trim()
            .to_string();

        // Add authentication config
        if !normalized_config.contains("CookieAuthentication") {
            normalized_config.push_str("\nCookieAuthentication 0\n");
        }
        normalized_config.push_str(&format!("\nHashedControlPassword {}\n", hashed));

        // Create directories
        fs::create_dir_all(&self.tor_dir)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to create tor dir: {}", e)))?;

        // Write config file
        fs::write(&self.config_path, &normalized_config)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to write config: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.config_path, perms).ok();
        }

        // Create data directory
        if let Some(ref dir) = data_dir {
            fs::create_dir_all(dir)
                .await
                .map_err(|e| QorError::FileSystem(format!("Failed to create data dir: {}", e)))?;
            *self.configured_data_dir.write() = Some(dir.clone());
        }

        Ok(true)
    }

    /// Save control password
    async fn persist_control_password(&self, password: &str) -> QorResult<()> {
        let key = self.get_credential_encryption_key().await?;
        let nonce_vec = random::random_bytes(12);

        let nonce: [u8; 12] = nonce_vec
            .clone()
            .try_into()
            .map_err(|_| QorError::Internal("Invalid nonce length".to_string()))?;

        let aad = b"tor-control-password";
        let encrypted =
            crate::crypto::aead::aes_gcm_encrypt(&key, &nonce, password.as_bytes(), aad)?;

        let mut data = Vec::with_capacity(12 + encrypted.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&encrypted);

        let file_path = self.tor_dir.join(CONTROL_PASSWORD_FILE);
        fs::write(&file_path, &data)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to persist password: {}", e)))?;

        Ok(())
    }

    /// Load control password
    async fn load_control_password(&self) -> Option<String> {
        let file_path = self.tor_dir.join(CONTROL_PASSWORD_FILE);
        let data = fs::read(&file_path).await.ok()?;

        if data.len() < 12 {
            return None;
        }

        let key = self.get_credential_encryption_key().await.ok()?;
        let nonce: [u8; 12] = data[..12].try_into().ok()?;
        let encrypted = &data[12..];
        let aad = b"tor-control-password";

        let decrypted = crate::crypto::aead::aes_gcm_decrypt(&key, &nonce, encrypted, aad).ok()?;

        String::from_utf8(decrypted).ok()
    }

    /// Get credential encryption key
    async fn get_credential_encryption_key(&self) -> QorResult<[u8; 32]> {
        let key_path = self.tor_dir.join(".cred_key");

        if let Ok(data) = fs::read(&key_path).await {
            if data.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[..32]);
                return Ok(key);
            }
        }

        // Generate from machine info
        let mut input = Vec::new();
        input.extend_from_slice(
            dirs::home_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .as_bytes(),
        );
        input.extend_from_slice(
            hostname::get()
                .unwrap_or_default()
                .to_string_lossy()
                .as_bytes(),
        );
        input.extend_from_slice(std::env::consts::OS.as_bytes());

        let key = hash::sha3_256(&input);

        fs::create_dir_all(&self.tor_dir).await.ok();
        fs::write(&key_path, &key).await.ok();

        Ok(key)
    }

    /// Start Tor process
    pub async fn start(&self) -> QorResult<TorStartResult> {
        self.reap_exited_process();

        // Check if already running
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

        // Check Tor binary exists and is executable
        if !self.tor_path.exists() {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some("Tor binary not found".to_string()),
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
        if let Err(e) = self.normalize_configured_transport_plugins().await {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some(e.safe_message()),
            });
        }

        let data_dir = self.get_data_dir();
        fs::create_dir_all(&data_dir)
            .await
            .map_err(|e| QorError::FileSystem(format!("Failed to create data dir: {}", e)))?;

        // Remove stale lock file only after orphan reaping
        let lock_file = data_dir.join("lock");
        let _ = fs::remove_file(&lock_file).await;

        // Load control password if not already loaded
        if self.control_password.read().is_none() {
            if let Some(pwd) = self.load_control_password().await {
                *self.control_password.write() = Some(pwd);
            }
        }

        // Find available ports
        let socks_port = self.find_available_port(9150).await;
        let control_port = self.find_available_port(socks_port + 1).await;

        self.effective_socks_port
            .store(socks_port, Ordering::Relaxed);
        self.effective_control_port
            .store(control_port, Ordering::Relaxed);

        // Build command
        let mut child = Command::new(&self.tor_path)
            .args([
                "-f",
                &self.config_path.to_string_lossy(),
                "--DataDirectory",
                &data_dir.to_string_lossy(),
                "SocksPort",
                &format!(
                    "{} IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestAddr",
                    socks_port
                ),
                "ControlPort",
                &control_port.to_string(),
            ])
            .envs(self.get_tor_environment())
            .current_dir(&self.tor_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| QorError::TorProcess(format!("Failed to start Tor: {}", e)))?;

        tokio::time::sleep(Duration::from_millis(250)).await;
        if let Ok(Some(status)) = child.try_wait() {
            let mut err_msg = format!("Tor exited during startup: {}", status);
            let mut out_msg = String::new();
            let mut err_out = String::new();

            if let Some(mut stdout) = child.stdout.take() {
                use std::io::Read;
                let mut buf = String::new();
                if stdout.read_to_string(&mut buf).is_ok() && !buf.is_empty() {
                    out_msg = buf.trim().to_string();
                    error!("[TOR-STARTUP-STDOUT] {}", out_msg);
                }
            }
            if let Some(mut stderr) = child.stderr.take() {
                use std::io::Read;
                let mut buf = String::new();
                if stderr.read_to_string(&mut buf).is_ok() && !buf.is_empty() {
                    err_out = buf.trim().to_string();
                    error!("[TOR-STARTUP-STDERR] {}", err_out);
                }
            }

            if !out_msg.is_empty() {
                err_msg.push_str(&format!(" | stdout: {}", out_msg));
            }
            if !err_out.is_empty() {
                err_msg.push_str(&format!(" | stderr: {}", err_out));
            }

            self.mark_process_stopped();
            return Ok(TorStartResult {
                success: false,
                starting: Some(false),
                error: Some(err_msg),
            });
        }

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        *self.tor_process.write() = Some(child);
        self.bootstrapped.store(false, Ordering::Relaxed);
        self.bootstrap_progress.store(0, Ordering::Relaxed);
        self.health_monitor_running.store(true, Ordering::Relaxed);

        // Start bootstrap monitoring in background
        let bootstrapped = self.bootstrapped.clone();
        let bootstrap_progress = self.bootstrap_progress.clone();
        self.health_monitor_running.store(true, Ordering::Relaxed);

        // Standard handles
        use std::io::BufRead;

        // Monitor stdout
        let bootstrapped_clone = bootstrapped.clone();
        let bootstrap_progress_clone = bootstrap_progress.clone();
        tokio::task::spawn_blocking(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(l) = line {
                    info!("[TOR] {}", l);
                    if l.contains("Bootstrapped") {
                        if let Some(pos) = l.find("Bootstrapped ") {
                            let rest = &l[pos + "Bootstrapped ".len()..];
                            if let Some(end_pos) = rest.find('%') {
                                if let Ok(progress) = rest[..end_pos].parse::<u16>() {
                                    bootstrap_progress_clone.store(progress, Ordering::Relaxed);
                                    if progress >= 100 {
                                        bootstrapped_clone.store(true, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        });

        // Monitor stderr
        tokio::task::spawn_blocking(move || {
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(l) = line {
                    error!("[TOR-ERROR] {}", l);
                } else {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            // Wait for bootstrap
            let start = Instant::now();
            while start.elapsed().as_millis() < BOOTSTRAP_TIMEOUT_MS as u128 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if bootstrapped.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        Ok(TorStartResult {
            success: true,
            starting: Some(true),
            error: None,
        })
    }

    /// Stop Tor process
    pub async fn stop(&self) -> QorResult<bool> {
        self.shutdown_now();
        Ok(true)
    }

    /// Check if Tor is running
    pub fn is_running(&self) -> bool {
        self.reap_exited_process();
        let process = self.tor_process.read();
        process.is_some()
    }

    /// Get Tor status
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

    /// Rotate circuit
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

    /// Send NEWNYM signal to control port
    async fn send_newnym_signal(&self) -> QorResult<()> {
        let password = self
            .control_password
            .read()
            .clone()
            .ok_or_else(|| QorError::TorControl("No control password".to_string()))?;

        let control_port = self.get_control_port();

        let result = tokio::task::spawn_blocking(move || {
            let mut conn = Self::control_authenticate(control_port, &password)?;

            writeln!(conn.stream, "SIGNAL NEWNYM")?;

            let mut line = String::new();
            conn.reader.read_line(&mut line)?;

            if !line.starts_with("250") {
                return Err(QorError::TorControl(
                    "Circuit not established yet".to_string(),
                ));
            }

            Ok::<_, QorError>(())
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))?;

        result
    }

    fn control_authenticate(control_port: u16, password: &str) -> QorResult<ControlConnection> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", control_port))
            .map_err(|e| QorError::TorControl(format!("Failed to connect control port: {}", e)))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        writeln!(stream, "AUTHENTICATE \"{}\"", password)?;

        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if !line.starts_with("250") {
            return Err(QorError::TorControl(
                "Control port authentication failed".to_string(),
            ));
        }

        Ok(ControlConnection { stream, reader })
    }

    fn control_get_bootstrap_status(control_port: u16, password: &str) -> QorResult<(u16, bool)> {
        let mut conn = Self::control_authenticate(control_port, password)?;
        let mut line = String::new();
        let mut progress = 0u16;
        let mut bootstrapped = false;

        writeln!(conn.stream, "GETINFO status/bootstrap-phase")?;
        loop {
            line.clear();
            let n = conn.reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let l = line.trim();
            if l.starts_with("250-status/bootstrap-phase=") {
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
                if l.contains("PROGRESS=100") || l.contains("TAG=done") {
                    progress = 100;
                    bootstrapped = true;
                }
            } else if l == "250 OK" {
                break;
            } else if l.starts_with('5') {
                return Err(QorError::TorControl(format!(
                    "GETINFO status/bootstrap-phase failed: {}",
                    l
                )));
            }
        }

        Ok((progress, bootstrapped))
    }

    async fn refresh_bootstrap_from_control(&self) {
        if !self.is_running() {
            return;
        }

        let password = match self.control_password.read().clone() {
            Some(password) => password,
            None => return,
        };
        let control_port = self.get_control_port();

        if let Ok(Ok((progress, bootstrapped))) = tokio::task::spawn_blocking(move || {
            Self::control_get_bootstrap_status(control_port, &password)
        })
        .await
        {
            self.bootstrap_progress
                .store(progress.min(100), Ordering::Relaxed);
            if bootstrapped {
                self.bootstrapped.store(true, Ordering::Relaxed);
            }
        }
    }

    fn control_get_bootstrap_and_circuit_established(
        control_port: u16,
        password: &str,
    ) -> QorResult<()> {
        let (_, bootstrapped) = Self::control_get_bootstrap_status(control_port, password)?;

        if !bootstrapped {
            return Err(QorError::TorControl(
                "Tor control reports bootstrap incomplete".to_string(),
            ));
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn control_add_ephemeral_onion_awaiting_publish(
        control_port: u16,
        password: &str,
        local_port: u16,
    ) -> QorResult<String> {
        let mut conn = Self::control_authenticate(control_port, password)?;
        let mut line = String::new();

        // Subscribe to HS_DESC events
        writeln!(conn.stream, "SETEVENTS HS_DESC")?;
        line.clear();
        conn.reader.read_line(&mut line)?;
        if !line.starts_with("250") {
            warn!("Failed to subscribe to HS_DESC events: {}", line.trim());
        }

        writeln!(
            conn.stream,
            "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,Detach Port=80,127.0.0.1:{}",
            local_port
        )?;

        let mut service_id: Option<String> = None;
        loop {
            line.clear();
            let n = conn.reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("250-ServiceID=") {
                service_id = Some(rest.to_string());
            } else if l == "250 OK" {
                break;
            } else if l.starts_with('5') {
                return Err(QorError::TorControl(format!("ADD_ONION failed: {}", l)));
            }
        }

        let sid = service_id.ok_or_else(|| {
            QorError::TorControl("ADD_ONION did not return ServiceID".to_string())
        })?;

        
        info!("Waiting for onion descriptor publication: {}.onion", sid);
        let upload_deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < upload_deadline {
            line.clear();
            let _ = conn.stream.set_read_timeout(Some(Duration::from_secs(1)));
            if let Ok(n) = conn.reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                let l = line.trim();
                if l.starts_with("650 HS_DESC UPLOADED") && l.contains(&sid) {
                    info!("Onion descriptor uploaded successfully");
                    break;
                }
            }
        }

        let _ = writeln!(conn.stream, "SETEVENTS");

        Ok(sid)
    }

    #[allow(dead_code)]
    fn control_del_ephemeral_onion(
        control_port: u16,
        password: &str,
        service_id: &str,
    ) -> QorResult<()> {
        let mut conn = Self::control_authenticate(control_port, password)?;
        let mut line = String::new();

        writeln!(conn.stream, "DEL_ONION {}", service_id)?;

        loop {
            line.clear();
            let n = conn.reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let l = line.trim();
            if l == "250 OK" {
                break;
            } else if l.starts_with('5') {
                return Err(QorError::TorControl(format!("DEL_ONION failed: {}", l)));
            }
        }

        Ok(())
    }

    async fn verify_local_connection(&self) -> QorResult<()> {
        let control_port = self.get_control_port();
        let socks_port = self.get_socks_port();
        let control_password = self.control_password.read().clone();

        let password = control_password
            .ok_or_else(|| QorError::TorControl("No control password".to_string()))?;

        tokio::task::spawn_blocking({
            let password = password.clone();
            move || Self::control_get_bootstrap_and_circuit_established(control_port, &password)
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

    #[allow(dead_code)]
    async fn verify_ephemeral_onion_canary(
        &self,
        control_port: u16,
        socks_port: u16,
        password: String,
    ) -> QorResult<()> {
        // Local ephemeral HTTP canary endpoint.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| QorError::Network(format!("Failed to bind local canary: {}", e)))?;
        let local_port = listener
            .local_addr()
            .map_err(|e| QorError::Network(format!("Failed to resolve local canary addr: {}", e)))?
            .port();

        let canary_task = tokio::spawn(async move {
            let accept = tokio::time::timeout(Duration::from_secs(50), listener.accept())
                .await
                .map_err(|_| "Local canary accept timeout".to_string())?;
            let (mut socket, _) =
                accept.map_err(|e| format!("Local canary accept failed: {}", e))?;

            let mut buffer = [0u8; 512];
            let _ = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer)).await;
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .map_err(|e| format!("Local canary write failed: {}", e))?;
            Ok::<(), String>(())
        });

        let service_id = tokio::task::spawn_blocking({
            let password = password.clone();
            move || {
                Self::control_add_ephemeral_onion_awaiting_publish(
                    control_port,
                    &password,
                    local_port,
                )
            }
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))??;

        let onion_url = format!("http://{}.onion/health", service_id);
        let proxy_url = format!("socks5h://127.0.0.1:{}", socks_port);
        let probe_result: QorResult<()> = async {
            let client = reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url)?)
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            let mut last_error: Option<String> = None;
            for attempt in 0..10 {
                match client.get(&onion_url).send().await {
                    Ok(response) => {
                        if response.status().as_u16() == 204 {
                            return Ok(());
                        }
                        last_error = Some(format!(
                            "Onion canary unexpected status: {}",
                            response.status()
                        ));
                    }
                    Err(e) => {
                        last_error = Some(format!("Onion canary request failed: {}", e));
                    }
                }

                if attempt < 9 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }

            Err(QorError::Network(
                last_error.unwrap_or_else(|| "Onion canary probe failed".to_string()),
            ))
        }
        .await;

        let _ = tokio::task::spawn_blocking({
            let password = password.clone();
            let service_id = service_id.clone();
            move || Self::control_del_ephemeral_onion(control_port, &password, &service_id)
        })
        .await;

        let _ = canary_task.await;

        probe_result
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
                error!("Tor connection verification failed: {}", e);
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

/// Initialize Tor Manager
pub async fn init(app_data_path: PathBuf) -> QorResult<Arc<TorManager>> {
    let manager = TorManager::new(app_data_path);
    Ok(Arc::new(manager))
}
