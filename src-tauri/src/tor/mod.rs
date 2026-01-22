//! Tor Manager

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{info, error};

use crate::crypto::{hash, random};
use crate::error::{QorError, QorResult};

const DEFAULT_SOCKS_PORT: u16 = 9050;
const DEFAULT_CONTROL_PORT: u16 = 9051;
const PORT_SCAN_RANGE: u16 = 100;
const MAX_CONFIG_SIZE: usize = 50000;
const BOOTSTRAP_TIMEOUT_MS: u64 = 120000;
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;
const CONTROL_PASSWORD_FILE: &str = ".control_password";

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
    /// Configured data directory
    configured_data_dir: RwLock<Option<PathBuf>>,
    /// Health monitor running
    health_monitor_running: AtomicBool,
}

impl TorManager {
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
        let base = if Self::is_valid_port(start_port) { start_port } else { DEFAULT_SOCKS_PORT };
        
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

    /// Check Tor installation status
    pub async fn check_installation(&self) -> QorResult<TorInstallStatus> {
        let metadata = fs::metadata(&self.tor_path).await;
        
        match metadata {
            Ok(meta) if meta.is_file() => {
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
                return Ok(version.as_str().to_string());
            }
        }
        
        Ok("unknown".to_string())
    }

    /// Get Tor info
    pub async fn get_info(&self) -> QorResult<TorInfo> {
        Ok(TorInfo {
            version: self.get_tor_version().await.unwrap_or_else(|_| "unknown".to_string()),
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
            QorError::NotSupported(format!("Unsupported platform: {}/{}", self.platform, self.arch))
        })?;
        
        // Fetch latest version if not cached or specified
        let version = self.fetch_latest_tor_version().await.unwrap_or_else(|_| "15.0.3".to_string());
        
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
            
        let response = client.get("https://dist.torproject.org/torbrowser/")
            .send().await
            .map_err(|e| QorError::Network(format!("Failed to reach Tor Project: {}", e)))?;
            
        let html = response.text().await
            .map_err(|e| QorError::Network(format!("Failed to read response: {}", e)))?;
            
        // Simple extraction of the latest version (looks for directories like 14.x.x, 15.x.x)
        let re = regex::Regex::new(r#"href="(\d+\.\d+\.\d+)/""#)
            .map_err(|e| QorError::Internal(format!("Regex error: {}", e)))?;
            
        let mut versions: Vec<String> = re.captures_iter(&html)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect();
            
        // Sort versions (naive lexicographical sort might fail for 10.x vs 9.x, but okay for major-minor-patch if padded or just reliable enough for current range)
        versions.sort_by(|a, b| {
            let parse = |s: &str| s.split('.').map(|v| v.parse::<u32>().unwrap_or(0)).collect::<Vec<u32>>();
            parse(b).cmp(&parse(a))
        });
        
        versions.into_iter().next().ok_or_else(|| QorError::NotFound("Latest version not found".to_string()))
    }

    /// Download Tor
    pub async fn download(&self) -> QorResult<TorDownloadResult> {
        // Create tor directory
        fs::create_dir_all(&self.tor_dir).await
            .map_err(|e| QorError::FileSystem(format!("Failed to create tor dir: {}", e)))?;
        
        // Check if already installed
        if self.tor_path.exists() {
            return Ok(TorDownloadResult {
                success: true,
                already_exists: Some(true),
                error: None,
            });
        }
        
        let download_url = self.get_download_url().await?;
        let archive_filename = download_url.split('/').last()
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
        let version = self.fetch_latest_tor_version().await.unwrap_or_else(|_| "15.0.3".to_string());
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
            .danger_accept_invalid_certs(true)
            .no_gzip()
            .build()
            .map_err(|e| QorError::Network(format!("Failed to create HTTP client: {}", e)))?;
        
        let response = client.get(url).send().await
            .map_err(|e| QorError::Network(format!("Download failed for {}: {}", url, e)))?;
        
        if !response.status().is_success() {
            return Err(QorError::Network(format!("HTTP {} fetching {}", response.status(), url)));
        }
        
        let bytes = response.bytes().await
            .map_err(|e| QorError::Network(format!("Failed to read response: {}", e)))?;
        
        fs::write(dest, &bytes).await
            .map_err(|e| QorError::FileSystem(format!("Failed to write file: {}", e)))?;
        
        Ok(())
    }

    /// Verify SHA256 checksum
    async fn verify_sha256(&self, archive_path: &PathBuf, checksum_path: &PathBuf) -> QorResult<()> {
        let checksum_content = fs::read_to_string(checksum_path).await
            .map_err(|e| QorError::FileSystem(format!("Failed to read checksums: {}", e)))?;
        
        let filename = archive_path.file_name()
            .ok_or_else(|| QorError::InvalidArgument("Invalid archive path".to_string()))?
            .to_string_lossy();
        
        // Find checksum for our file
        let expected = checksum_content.lines()
            .find_map(|line| {
                if line.contains(&*filename) {
                    line.split_whitespace().next().map(|s| s.to_lowercase())
                } else {
                    None
                }
            })
            .ok_or_else(|| QorError::Verification("Checksum not found".to_string()))?;
        
        // Calculate actual checksum
        let file_bytes = fs::read(archive_path).await
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
            
            for entry in archive.entries().map_err(|e| QorError::FileSystem(e.to_string()))? {
                let mut entry = entry.map_err(|e| QorError::FileSystem(e.to_string()))?;
                let path = entry.path().map_err(|e| QorError::FileSystem(e.to_string()))?;
                
                // Filter to only allowed files
                let path_str = path.to_string_lossy();
                let allowed = ["tor", "tor.exe", "lib", "lib64", "obfs4proxy", 
                    "snowflake-client", "lyrebird", "geoip", "geoip6", "pluggable_transports"];
                
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
            return Err(QorError::InvalidArgument("Configuration too large".to_string()));
        }
        
        // Check for forbidden characters
        if config.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
            return Err(QorError::InvalidArgument("Configuration contains forbidden characters".to_string()));
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
                return Err(QorError::InvalidArgument("Configuration line too long".to_string()));
            }
            
            // Parse directive
            let parts: Vec<&str> = trimmed.splitn(2, char::is_whitespace).collect();
            let directive = parts[0];
            let value = parts.get(1).map(|s| s.trim()).unwrap_or("");
            
            if !ALLOWED_DIRECTIVES.contains(directive) {
                return Err(QorError::InvalidArgument(format!("Forbidden directive: {}", directive)));
            }
            
            if directive == "DataDirectory" {
                let resolved = if value.starts_with('/') || (self.platform == "windows" && value.chars().nth(1) == Some(':')) {
                    PathBuf::from(value)
                } else {
                    self.tor_dir.join(if value.is_empty() { "data" } else { value })
                };
                
                let normalized_path = std::fs::canonicalize(&resolved).unwrap_or(resolved.clone());
                let tor_dir_normalized = std::fs::canonicalize(&self.tor_dir).unwrap_or(self.tor_dir.clone());
                
                if !normalized_path.starts_with(&tor_dir_normalized) {
                    return Err(QorError::InvalidArgument("DataDirectory outside allowed path".to_string()));
                }
                
                data_dir = Some(normalized_path.clone());
                normalized.push(format!("DataDirectory {}", normalized_path.display()));
            } else {
                normalized.push(format!("{}{}", directive, if value.is_empty() { "".to_string() } else { format!(" {}", value) }));
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
        fs::create_dir_all(&self.tor_dir).await
            .map_err(|e| QorError::FileSystem(format!("Failed to create tor dir: {}", e)))?;
        
        // Write config file
        fs::write(&self.config_path, &normalized_config).await
            .map_err(|e| QorError::FileSystem(format!("Failed to write config: {}", e)))?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.config_path, perms).ok();
        }
        
        // Create data directory
        if let Some(ref dir) = data_dir {
            fs::create_dir_all(dir).await
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
        let encrypted = crate::crypto::aead::aes_gcm_encrypt(
            &key,
            &nonce,
            password.as_bytes(),
            aad,
        )?;
        
        let mut data = Vec::with_capacity(12 + encrypted.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&encrypted);
        
        let file_path = self.tor_dir.join(CONTROL_PASSWORD_FILE);
        fs::write(&file_path, &data).await
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
        
        let decrypted = crate::crypto::aead::aes_gcm_decrypt(
            &key,
            &nonce,
            encrypted,
            aad,
        ).ok()?;
        
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
        input.extend_from_slice(dirs::home_dir().unwrap_or_default().to_string_lossy().as_bytes());
        input.extend_from_slice(hostname::get().unwrap_or_default().to_string_lossy().as_bytes());
        input.extend_from_slice(std::env::consts::OS.as_bytes());
        
        let key = hash::sha3_256(&input);
        
        fs::create_dir_all(&self.tor_dir).await.ok();
        fs::write(&key_path, &key).await.ok();
        
        Ok(key)
    }

    /// Start Tor process
    pub async fn start(&self) -> QorResult<TorStartResult> {
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
        
        // Check Tor binary exists and is executable
        if !self.tor_path.exists() {
            return Ok(TorStartResult {
                success: false,
                starting: None,
                error: Some("Tor binary not found".to_string()),
            });
        }
        
        let data_dir = self.get_data_dir();
        fs::create_dir_all(&data_dir).await
            .map_err(|e| QorError::FileSystem(format!("Failed to create data dir: {}", e)))?;
        
        // Remove stale lock file
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
        
        self.effective_socks_port.store(socks_port, Ordering::Relaxed);
        self.effective_control_port.store(control_port, Ordering::Relaxed);
        
        // Build command
        let mut child = Command::new(&self.tor_path)
            .args([
                "-f", &self.config_path.to_string_lossy(),
                "--DataDirectory", &data_dir.to_string_lossy(),
                "SocksPort", &format!("{} IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestAddr", socks_port),
                "ControlPort", &control_port.to_string(),
            ])
            .envs(self.get_tor_environment())
            .current_dir(&self.tor_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| QorError::TorProcess(format!("Failed to start Tor: {}", e)))?;
        
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
        let child_opt = {
            let mut process_guard = self.tor_process.write();
            process_guard.take()
        };
        
        if let Some(mut child) = child_opt {
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                if let Err(_) = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM) {
                    let _ = child.kill();
                }
            }
            
            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }
            
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::task::spawn_blocking(move || child.wait())
            ).await;
            
            self.bootstrapped.store(false, Ordering::Relaxed);
            self.health_monitor_running.store(false, Ordering::Relaxed);
        }
        
        Ok(true)
    }

    /// Check if Tor is running
    pub fn is_running(&self) -> bool {
        let process = self.tor_process.read();
        process.is_some()
    }

    /// Get Tor status
    pub fn status(&self) -> TorStatus {
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
        
        let before_ip = self.get_current_tor_ip().await.ok();

        self.send_newnym_signal().await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Get IP after rotation
        let after_ip = self.get_current_tor_ip().await.ok();
        
        Ok(CircuitRotationResult {
            success: true,
            ip_changed: Some(before_ip != after_ip),
            before_ip,
            after_ip,
            error: None,
        })
    }

    /// Send NEWNYM signal to control port
    async fn send_newnym_signal(&self) -> QorResult<()> {
        let password = self.control_password.read().clone()
            .ok_or_else(|| QorError::TorControl("No control password".to_string()))?;
        
        let control_port = self.get_control_port();
        
        let result = tokio::task::spawn_blocking(move || {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", control_port))
                .map_err(|e| QorError::TorControl(format!("Failed to connect: {}", e)))?;
            
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            
            // Authenticate
            writeln!(stream, "AUTHENTICATE \"{}\"", password)?;
            
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            
            if !line.starts_with("250") {
                return Err(QorError::TorControl("Authentication failed".to_string()));
            }
            
            // Send NEWNYM
            writeln!(stream, "SIGNAL NEWNYM")?;
            
            line.clear();
            reader.read_line(&mut line)?;
            
            if !line.starts_with("250") {
                return Err(QorError::TorControl("NEWNYM failed".to_string()));
            }
            
            writeln!(stream, "QUIT")?;
            
            Ok::<_, QorError>(())
        })
        .await
        .map_err(|e| QorError::Internal(format!("Task failed: {}", e)))?;
        
        result
    }

    /// Get current Tor exit IP
    pub async fn get_current_tor_ip(&self) -> QorResult<String> {
        let socks_port = self.get_socks_port();
        let proxy_url = format!("socks5h://127.0.0.1:{}", socks_port);
        
        info!("Verifying Tor connectivity via {}", proxy_url);
        
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url)?)
            .timeout(Duration::from_secs(15))
            .build()?;
            
        let url = "https://check.torproject.org/api/ip";
        info!("Testing Tor connectivity via {}...", url);
        
        match client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    #[derive(Deserialize)]
                    struct IpResponse {
                        #[serde(rename = "IP")]
                        ip: String,
                    }
                    if let Ok(data) = response.json::<IpResponse>().await {
                        info!("Tor connectivity verified! Exit IP: {}", data.ip);
                        return Ok(data.ip);
                    }
                }
                error!("Failed to parse response from {}", url);
                Err(QorError::Network(format!("Failed to parse response from {}", url)))
            }
            Err(e) => {
                error!("Connectivity check failed for {}: {}", url, e);
                Err(QorError::Network(format!("Connectivity check failed for {}: {}", url, e)))
            }
        }
    }

    /// Verify Tor connection
    pub async fn verify_connection(&self) -> QorResult<TorVerifyResult> {
        if !self.bootstrapped.load(Ordering::Relaxed) {
            return Ok(TorVerifyResult {
                success: false,
                ip_address: None,
                error: Some("Tor not bootstrapped yet".to_string()),
            });
        }

        match self.get_current_tor_ip().await {
            Ok(ip) => Ok(TorVerifyResult {
                success: true,
                ip_address: Some(ip),
                error: None,
            }),
            Err(e) => {
                error!("Tor connection verification failed: {}", e);
                Ok(TorVerifyResult {
                    success: false,
                    ip_address: None,
                    error: Some(e.safe_message()),
                })
            }
        }
    }
}

/// Initialize Tor Manager
pub async fn init(app_data_path: PathBuf) -> QorResult<Arc<TorManager>> {
    let manager = TorManager::new(app_data_path);
    Ok(Arc::new(manager))
}
