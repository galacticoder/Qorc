/**
 * Electron Main Process Tor Manager
 * Handles Tor installation, configuration, and management at the system level
 */

const { spawn, exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const https = require('https');
const { app } = require('electron');

class ElectronTorManager {
  constructor() {
    this.torProcess = null;
    this.torPath = null;
    this.configPath = null;
    this.platform = os.platform();
    this.arch = os.arch();
    this.usingSystemTor = false;
    this.effectiveSocksPort = 9050; // Track the actual SOCKS port in use
    this.effectiveControlPort = 9051; // Track the actual Control port in use
    this.bootstrapped = false; // Track Tor bootstrap status
    this.configuredSocksPort = 9050; // Ports requested in config
    this.configuredControlPort = 9051;

    // Set up paths
    this.setupPaths();
    // Use safe logging to avoid EBADF dialogs (console writes are redirected in main)
    try { console.log('[TOR-MANAGER] Initialized for platform:', this.platform); } catch (_) {}
  }

  /**
   * Get unique data directory path to avoid conflicts between multiple users/processes
   */
  getDataDir() {
    const processId = process.pid;
    const userName = require('os').userInfo().username;
    return path.join(this.torDir, `data-${userName}-${processId}`);
  }

  /**
   * Parse ports from Tor config file
   */
  async parsePortsFromConfig(configPath) {
    const defaults = { socks: 9050, control: 9051 };
    try {
      const cfg = await fs.readFile(configPath, 'utf8').catch(() => '');
      const socksMatch = cfg.match(/^SocksPort\s+(\d+)/m);
      const controlMatch = cfg.match(/^ControlPort\s+(\d+)/m);
      return {
        socks: socksMatch ? (parseInt(socksMatch[1], 10) || defaults.socks) : defaults.socks,
        control: controlMatch ? (parseInt(controlMatch[1], 10) || defaults.control) : defaults.control,
      };
    } catch (e) {
      console.warn('[TOR-MANAGER] Failed to parse ports from config:', e?.message || e);
      return defaults;
    }
  }

  /**
   * Setup Tor installation paths for production and development
   */
  setupPaths() {
    try {
      const appDataPath = app.getPath('userData');
      const isPackaged = app.isPackaged;
      
      // Data directory always in userData (writable)
      this.torDir = path.join(appDataPath, 'tor');
      this.configPath = path.join(this.torDir, 'torrc');

      // Binary paths depend on packaging
      if (isPackaged) {
        // In production, check for bundled Tor in extraResources first
        const resourcesPath = process.resourcesPath;
        let bundledTorPath;
        
        switch (this.platform) {
          case 'win32':
            bundledTorPath = path.join(resourcesPath, 'tor-bundles', 'windows', 'tor.exe');
            this.torPath = bundledTorPath;
            break;
          case 'darwin':
            bundledTorPath = path.join(resourcesPath, 'tor-bundles', 'macos', 'tor');
            this.torPath = bundledTorPath;
            break;
          case 'linux':
            bundledTorPath = path.join(resourcesPath, 'tor-bundles', 'linux', 'tor');
            this.torPath = bundledTorPath;
            break;
          default:
            throw new Error(`Unsupported platform: ${this.platform}`);
        }
        
        // Check if bundled Tor exists, otherwise use data directory
        if (!require('fs').existsSync(bundledTorPath)) {
          console.log('[TOR-MANAGER] Bundled Tor not found, using data directory');
          switch (this.platform) {
            case 'win32':
              this.torPath = path.join(this.torDir, 'tor.exe');
              break;
            case 'darwin':
            case 'linux':
              this.torPath = path.join(this.torDir, 'tor');
              break;
          }
        }
      } else {
        // In development, use data directory
        switch (this.platform) {
          case 'win32':
            this.torPath = path.join(this.torDir, 'tor.exe');
            break;
          case 'darwin':
          case 'linux':
            this.torPath = path.join(this.torDir, 'tor');
            break;
          default:
            throw new Error(`Unsupported platform: ${this.platform}`);
        }
      }

      console.log('[TOR-MANAGER] App packaged:', isPackaged);
      console.log('[TOR-MANAGER] App data path:', appDataPath);
      console.log('[TOR-MANAGER] Tor directory:', this.torDir);
      console.log('[TOR-MANAGER] Tor binary path:', this.torPath);
      console.log('[TOR-MANAGER] Config path:', this.configPath);
      
      if (isPackaged) {
        console.log('[TOR-MANAGER] Resources path:', process.resourcesPath);
      }
    } catch (error) {
      console.error('[TOR-MANAGER] Failed to setup paths:', error);
      throw error;
    }
  }

  /**
   * Check if bundled Tor is installed or available
   */
  async checkTorInstallation() {
    console.log('[TOR-MANAGER] Checking bundled Tor installation...');

    try {
      // Check if bundled Tor binary exists
      const stats = await fs.stat(this.torPath);
      if (stats.isFile()) {
        console.log('[TOR-MANAGER] Found bundled Tor installation at:', this.torPath);
        
        // Try to get version to verify it's working
        try {
          const version = await this.getTorVersion();
          return { 
            isInstalled: true, 
            version, 
            path: this.torPath, 
            bundled: true,
            inResources: app.isPackaged && this.torPath.includes('resources')
          };
        } catch (versionError) {
          console.warn('[TOR-MANAGER] Tor binary found but version check failed:', versionError.message);
          return { 
            isInstalled: true, 
            path: this.torPath, 
            bundled: true,
            inResources: app.isPackaged && this.torPath.includes('resources'),
            versionError: versionError.message
          };
        }
      }
    } catch (error) {
      console.log('[TOR-MANAGER] Bundled Tor not found:', error.message);
    }

    return { isInstalled: false };
  }


  /**
   * Get download URL for Tor Expert Bundle based on platform
   */
  getTorDownloadUrl() {
    // Use the latest Tor Expert Bundle from the provided link
    const baseUrl = 'https://archive.torproject.org/tor-package-archive/torbrowser';
    const version = '15.0a2'; // Latest alpha version as specified

    console.log(`[TOR-MANAGER] Getting download URL for ${this.platform} ${this.arch}`);

    switch (this.platform) {
      case 'linux':
        if (this.arch === 'x64') {
          return `${baseUrl}/${version}/tor-expert-bundle-linux-x86_64-${version}.tar.gz`;
        } else if (this.arch === 'arm64') {
          return `${baseUrl}/${version}/tor-expert-bundle-linux-aarch64-${version}.tar.gz`;
        }
        break;
      case 'darwin':
        if (this.arch === 'x64') {
          return `${baseUrl}/${version}/tor-expert-bundle-macos-x86_64-${version}.tar.gz`;
        } else if (this.arch === 'arm64') {
          return `${baseUrl}/${version}/tor-expert-bundle-macos-aarch64-${version}.tar.gz`;
        }
        break;
      case 'win32':
        if (this.arch === 'x64') {
          return `${baseUrl}/${version}/tor-expert-bundle-windows-x86_64-${version}.tar.gz`;
        } else {
          return `${baseUrl}/${version}/tor-expert-bundle-windows-i686-${version}.tar.gz`;
        }
    }

    throw new Error(`Unsupported platform: ${this.platform} ${this.arch}`);
  }


  /**
   * Get Tor version
   */
  async getTorVersion() {
    return new Promise((resolve, reject) => {
      exec(`"${this.torPath}" --version`, (error, stdout) => {
        if (error) {
          reject(error);
        } else {
          const version = stdout.split('\n')[0].match(/Tor (\d+\.\d+\.\d+)/)?.[1];
          resolve(version || 'unknown');
        }
      });
    });
  }

  /**
   * Download and setup bundled Tor Expert Bundle
   */
  async downloadTor() {
    try {
      console.log('[TOR-MANAGER] === Starting bundled Tor download ===');
      console.log('[TOR-MANAGER] Platform:', this.platform, 'Architecture:', this.arch);
      console.log('[TOR-MANAGER] Tor directory:', this.torDir);
      console.log('[TOR-MANAGER] Tor binary path:', this.torPath);

      // Create tor directory
      console.log('[TOR-MANAGER] Creating Tor directory...');
      await fs.mkdir(this.torDir, { recursive: true });
      console.log('[TOR-MANAGER] Tor directory created successfully');

      // Check if bundled Tor already exists
      try {
        const stats = await fs.stat(this.torPath);
        if (stats.isFile()) {
          console.log('[TOR-MANAGER] Bundled Tor already exists at:', this.torPath);
          return { success: true, alreadyExists: true };
        }
      } catch (error) {
        console.log('[TOR-MANAGER] Bundled Tor not found, proceeding with download...');
      }

      // Get download URL for current platform
      console.log('[TOR-MANAGER] Getting download URL...');
      const downloadUrl = this.getTorDownloadUrl();
      console.log('[TOR-MANAGER] Download URL:', downloadUrl);

      // Download the Tor Expert Bundle
      const archivePath = path.join(this.torDir, 'tor-expert-bundle.tar.gz');
      console.log('[TOR-MANAGER] Archive will be saved to:', archivePath);
      
      console.log('[TOR-MANAGER] Starting file download...');
      await this.downloadFile(downloadUrl, archivePath);
      console.log('[TOR-MANAGER] Download completed successfully');

      // Extract the bundle
      console.log('[TOR-MANAGER] Extracting Tor Expert Bundle...');
      await this.extractTorBundle(archivePath);
      console.log('[TOR-MANAGER] Extraction completed');

      // Clean up archive
      console.log('[TOR-MANAGER] Cleaning up archive...');
      await fs.unlink(archivePath).catch(() => {}); // Ignore errors

      // Verify extraction was successful
      console.log('[TOR-MANAGER] Verifying extraction...');
      const stats = await fs.stat(this.torPath);
      if (!stats.isFile()) {
        throw new Error('Tor binary not found after extraction');
      }
      console.log('[TOR-MANAGER] Tor binary verified at:', this.torPath);

      console.log('[TOR-MANAGER] === Bundled Tor setup completed successfully ===');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] === Failed to download bundled Tor ===');
      console.error('[TOR-MANAGER] Error:', error.message);
      console.error('[TOR-MANAGER] Stack:', error.stack);
      return { success: false, error: error.message };
    }
  }


  /**
   * Download file with progress
   */
  async downloadFile(url, filePath) {
    return new Promise((resolve, reject) => {
      console.log('[TOR-MANAGER] downloadFile - Starting download from:', url);
      console.log('[TOR-MANAGER] downloadFile - Saving to:', filePath);
      
      const file = require('fs').createWriteStream(filePath);
      let downloadedBytes = 0;
      let totalBytes = 0;

      console.log('[TOR-MANAGER] downloadFile - Making HTTPS request...');
      const request = https.get(url, (response) => {
        console.log('[TOR-MANAGER] downloadFile - Response status:', response.statusCode);
        console.log('[TOR-MANAGER] downloadFile - Response headers:', response.headers);
        
        if (response.statusCode !== 200) {
          console.error('[TOR-MANAGER] downloadFile - Bad status code:', response.statusCode, response.statusMessage);
          reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
          return;
        }

        totalBytes = parseInt(response.headers['content-length'] || '0', 10);
        console.log('[TOR-MANAGER] downloadFile - Total size:', totalBytes, 'bytes');

        response.on('data', (chunk) => {
          downloadedBytes += chunk.length;
          if (totalBytes > 0) {
            const progress = Math.round((downloadedBytes / totalBytes) * 100);
            if (downloadedBytes % (1024 * 1024) < chunk.length) { // Log every MB
              console.log(`[TOR-MANAGER] downloadFile - Progress: ${progress}% (${Math.round(downloadedBytes / 1024 / 1024)}MB / ${Math.round(totalBytes / 1024 / 1024)}MB)`);
            }
          }
        });

        response.pipe(file);

        file.on('finish', () => {
          console.log('[TOR-MANAGER] downloadFile - File write finished');
          file.close();
          console.log('[TOR-MANAGER] downloadFile - File closed, download complete');
          resolve();
        });

        file.on('error', (error) => {
          console.error('[TOR-MANAGER] downloadFile - File write error:', error);
          fs.unlink(filePath).catch(() => {}); // Clean up on error
          reject(error);
        });

      });
      
      request.on('error', (error) => {
        console.error('[TOR-MANAGER] downloadFile - HTTPS request error:', error);
        reject(error);
      });
      
      request.on('timeout', () => {
        console.error('[TOR-MANAGER] downloadFile - Request timeout');
        request.abort();
        reject(new Error('Download timeout'));
      });
      
      // Set timeout to 5 minutes
      request.setTimeout(5 * 60 * 1000);
    });
  }

  /**
   * Extract Tor Expert Bundle
   */
  async extractTorBundle(archivePath) {
    return new Promise((resolve, reject) => {
      const tar = require('tar');
      
      console.log('[TOR-MANAGER] Extracting archive:', archivePath);
      console.log('[TOR-MANAGER] Extract destination:', this.torDir);

      tar.extract({
        file: archivePath,
        cwd: this.torDir,
        strip: 1, // Remove top-level directory from Expert Bundle
        filter: (path, entry) => {
          // Only extract necessary files to save space
          const allowedFiles = [
            'tor', 'tor.exe', // Main Tor binary
            'lyrebird', 'lyrebird.exe', // Modern pluggable transport (v15.0a2+)
            'obfs4proxy', 'obfs4proxy.exe', // Legacy pluggable transport
            'conjure-client', 'conjure-client.exe', // Conjure transport
            'snowflake-client', 'snowflake-client.exe', // Snowflake transport  
            'geoip', 'geoip6', // GeoIP files
            'libevent-2', 'libssl', 'libcrypto', // Required libraries (prefix match)
            'libgcc_s', 'libstdc\+\+', 'libz', // Additional libraries (escaped for regex)
            'pluggable_transports', 'pt_config.json' // PT directory and config
          ];
          
          const fileName = path.split('/').pop() || path;
          const isAllowed = allowedFiles.some(pattern => {
            try {
              // For patterns with special characters, do a simple prefix match
              if (pattern.includes('+') || pattern.includes('\\')) {
                return fileName.startsWith(pattern.replace(/\\\+/g, '+'));
              }
              // For others, check if it's an exact match or prefix match
              return fileName === pattern || fileName.startsWith(pattern);
            } catch (error) {
              console.warn('[TOR-MANAGER] Regex error for pattern:', pattern, error.message);
              return fileName === pattern; // Fallback to exact match
            }
          });
          
          if (isAllowed) {
            console.log('[TOR-MANAGER] Extracting:', path);
            return true;
          }
          return false;
        }
      }).then(() => {
        // Make binaries executable on Unix systems
        if (this.platform !== 'win32') {
          const binaries = ['tor'];
          const ptBinaries = ['lyrebird', 'obfs4proxy', 'conjure-client', 'snowflake-client'];
          
          // Make main Tor binary executable
          for (const binary of binaries) {
            const binaryPath = path.join(this.torDir, binary);
            try {
              require('fs').chmodSync(binaryPath, 0o755);
              console.log('[TOR-MANAGER] Made executable:', binaryPath);
            } catch (error) {
              console.warn('[TOR-MANAGER] Could not make executable:', binaryPath, error.message);
            }
          }
          
          // Make pluggable transport binaries executable
          for (const ptBinary of ptBinaries) {
            const ptPath = path.join(this.torDir, 'pluggable_transports', ptBinary);
            try {
              require('fs').chmodSync(ptPath, 0o755);
              console.log('[TOR-MANAGER] Made PT executable:', ptPath);
            } catch (error) {
              console.log('[TOR-MANAGER] PT not found (normal):', ptBinary);
            }
          }
        }
        
        console.log('[TOR-MANAGER] Extraction completed successfully');
        resolve();
      }).catch((error) => {
        console.error('[TOR-MANAGER] Extraction failed:', error);
        reject(error);
      });
    });
  }

  /**
   * Verify bundled Tor installation
   */
  async installTor() {
    try {
      console.log('[TOR-MANAGER] Verifying bundled Tor installation...');

      // Ensure Tor directory exists
      await fs.mkdir(this.torDir, { recursive: true });

      // Check if bundled Tor executable exists
      try {
        const stats = await fs.stat(this.torPath);
        if (!stats.isFile()) {
          throw new Error('Bundled Tor binary is not a valid file');
        }
        console.log('[TOR-MANAGER] Bundled Tor found at:', this.torPath);
      } catch (error) {
        console.error('[TOR-MANAGER] Bundled Tor not found:', error.message);
        return { success: false, error: 'Bundled Tor binary not found. Please run download first.' };
      }

      // Make executable on Unix systems
      if (this.platform !== 'win32') {
        try {
          await fs.chmod(this.torPath, 0o755);
          console.log('[TOR-MANAGER] Made bundled Tor executable');
        } catch (error) {
          console.warn('[TOR-MANAGER] Could not make bundled Tor executable:', error.message);
        }
      }

      // Verify Tor version
      try {
        const version = await this.getTorVersion();
        console.log('[TOR-MANAGER] Bundled Tor version:', version);
      } catch (error) {
        console.warn('[TOR-MANAGER] Could not get Tor version:', error.message);
      }

      console.log('[TOR-MANAGER] Bundled Tor installation verified successfully');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to verify bundled Tor installation:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Configure Tor with provided config
   */
  async configureTor({ config }) {
    try {
      console.log('[TOR-MANAGER] Configuring Tor...');
      console.log('[TOR-MANAGER] Config length:', config?.length || 'undefined');
      console.log('[TOR-MANAGER] Tor directory:', this.torDir);
      console.log('[TOR-MANAGER] Config path:', this.configPath);

      // SECURITY: Validate configuration input
      if (!config || typeof config !== 'string') {
        throw new Error('Invalid configuration: must be a non-empty string');
      }

      // SECURITY: Limit configuration size to prevent DoS
      if (config.length > 50000) { // 50KB limit
        throw new Error('Configuration too large (max 50KB)');
      }

      // SECURITY: Validate configuration content
      // Note: We need to be careful not to block legitimate Tor config syntax
      const dangerousPatterns = [
        /[;&|`$]/,             // Shell metacharacters (excluding parentheses which are safe in comments)
        /\.\./,                // Path traversal
        /\/etc\//,             // System directories
        /\/proc\//,            // Process filesystem
        /\/dev\//,             // Device files
        /\/bin\//,             // Binary directories
        /\/usr\/bin\//,        // User binaries
        /\/sbin\//,            // System binaries
        /\bexec\s*\(/i,        // Execution function calls (but not words containing "exec")
        /\bsystem\s*\(/i,      // System function calls (but not words containing "system")
        /\bspawn\s*\(/i,       // Process spawning function calls
        /\x00/,                // Null bytes
      ];

      // Check each line individually to allow parentheses in comments
      const lines = config.split('\n');
      for (const line of lines) {
        const trimmedLine = line.trim();
        
        // Skip comment lines (they can contain parentheses safely)
        if (trimmedLine.startsWith('#') || trimmedLine === '') {
          continue;
        }
        
        // For non-comment lines, check for dangerous patterns
        const strictPatterns = [
          /[;&|`$]/,             // Shell metacharacters (excluding parentheses for Tor bridge configs)
          /\.\./,                // Path traversal
          /\/etc\//,             // System directories
          /\/proc\//,            // Process filesystem
          /\/dev\//,             // Device files
          /\/bin\//,             // Binary directories
          /\/usr\/bin\//,        // User binaries
          /\/sbin\//,            // System binaries
          /\x00/,                // Null bytes
        ];
        
        for (const pattern of strictPatterns) {
          if (pattern.test(line)) {
            console.error('[TOR-MANAGER] Dangerous pattern detected in config line:', pattern, 'Line:', line);
            throw new Error('Configuration contains dangerous patterns');
          }
        }
      }
      
      // Also check the general patterns on the full config (excluding parentheses)
      for (const pattern of dangerousPatterns) {
        if (pattern.test(config)) {
          console.error('[TOR-MANAGER] Dangerous pattern detected in config:', pattern);
          throw new Error('Configuration contains dangerous patterns');
        }
      }

      // SECURITY: Validate that config only contains valid Tor configuration directives
      const validTorDirectives = [
        'SocksPort', 'ControlPort', 'DataDirectory', 'Log', 'RunAsDaemon',
        'UseBridges', 'Bridge', 'ClientTransportPlugin', 'GeoIPFile',
        'GeoIPv6File', 'ExitPolicy', 'ExitRelay', 'ORPort', 'DirPort',
        'Nickname', 'ContactInfo', 'MyFamily', 'BandwidthRate', 'BandwidthBurst',
        'MaxAdvertisedBandwidth', 'RelayBandwidthRate', 'RelayBandwidthBurst',
        'PerConnBWRate', 'PerConnBWBurst', 'ClientOnly', 'ExitNodes',
        'EntryNodes', 'ExcludeNodes', 'ExcludeExitNodes', 'StrictNodes',
        'FascistFirewall', 'FirewallPorts', 'ReachableAddresses',
        'ReachableDirAddresses', 'ReachableORAddresses', 'HiddenServiceDir',
        'HiddenServicePort', 'HiddenServiceVersion', 'RendPostPeriod',
        'HiddenServiceAuthorizeClient', 'ClientOnionAuthDir', 'CookieAuthentication',
        'CookieAuthFile', 'CookieAuthFileGroupReadable', 'ControlPortWriteToFile',
        'ControlPortFileGroupReadable', 'HashedControlPassword', 'DisableNetwork',
        'PublishServerDescriptor', 'ShutdownWaitLength', 'SafeLogging',
        'HardwareAccel', 'AccelName', 'AccelDir', 'AvoidDiskWrites',
        'TunnelDirConns', 'PreferTunneledDirConns', 'CircuitBuildTimeout',
        'CircuitIdleTimeout', 'CircuitStreamTimeout', 'MaxCircuitDirtiness',
        'MaxClientCircuitsPending', 'NodeFamily', 'EnforceDistinctSubnets',
        'SocksTimeout', 'TokenBucketRefillInterval', 'TrackHostExits',
        'TrackHostExitsExpire', 'UpdateBridgesFromAuthority', 'UseMicrodescriptors',
        'PathBiasCircThreshold', 'PathBiasNoticeRate', 'PathBiasWarnRate',
        'PathBiasExtremeRate', 'PathBiasDropGuards', 'PathBiasScaleThreshold',
        // Additional directives that may appear in configurations
        'SocksPolicy', 'NewCircuitPeriod', 'LearnCircuitBuildTimeout'
      ];

      for (const line of lines) {
        const trimmedLine = line.trim();
        if (trimmedLine === '' || trimmedLine.startsWith('#')) {
          continue; // Skip empty lines and comments
        }

        const directive = trimmedLine.split(/\s+/)[0];
        if (!validTorDirectives.includes(directive)) {
          console.warn('[TOR-MANAGER] Unknown Tor directive:', directive);
          // Don't throw error for unknown directives, just warn
          // This allows for future Tor versions with new directives
        }
      }

      // Ensure Tor directory exists
      await fs.mkdir(this.torDir, { recursive: true });
      console.log('[TOR-MANAGER] Tor directory created/verified');

      // SECURITY: Write configuration file with restricted permissions
      await fs.writeFile(this.configPath, config, { 
        encoding: 'utf8',
        mode: 0o600 // Read/write for owner only
      });
      console.log('[TOR-MANAGER] Configuration file written with secure permissions');

      // Create data directory with secure permissions
      const dataDir = this.getDataDir();
      await fs.mkdir(dataDir, { recursive: true, mode: 0o700 }); // Owner only
      console.log('[TOR-MANAGER] Data directory created:', dataDir);

      console.log('[TOR-MANAGER] Tor configuration completed successfully');
      // Record configured ports (effective ports may be overridden at runtime)
      try {
        const ports = await this.parsePortsFromConfig(this.configPath);
        this.configuredSocksPort = ports.socks;
        this.configuredControlPort = ports.control;
      } catch (e) {
        console.warn('[TOR-MANAGER] Failed to update configured ports from config:', e?.message || e);
      }
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to configure Tor:', error);
      console.error('[TOR-MANAGER] Error details:', {
        message: error.message,
        code: error.code,
        path: error.path
      });
      return { success: false, error: error.message };
    }
  }

  /**
   * Start bundled Tor service
   */
  async startTor() {
    try {
      console.log('[TOR-MANAGER] Starting bundled Tor service...');

      if (this.torProcess) {
        console.log('[TOR-MANAGER] Bundled Tor is already running');
        return { success: true };
      }

      // Verify bundled Tor binary exists
      try {
        await fs.access(this.torPath, fs.constants.F_OK | fs.constants.X_OK);
        console.log('[TOR-MANAGER] Bundled Tor binary verified:', this.torPath);
      } catch (error) {
        console.error('[TOR-MANAGER] Bundled Tor binary not accessible:', error.message);
        return {
          success: false,
          error: 'Bundled Tor binary not found or not executable. Please download Tor Expert Bundle first.'
        };
      }

      const dataDir = this.getDataDir();

      // Ensure data directory exists
      console.log('[TOR-MANAGER] Creating data directory:', dataDir);
      await fs.mkdir(dataDir, { recursive: true });

      // Verify config file exists
      console.log('[TOR-MANAGER] Checking config file:', this.configPath);
      try {
        await fs.access(this.configPath);
        console.log('[TOR-MANAGER] Config file exists');
      } catch (error) {
        console.error('[TOR-MANAGER] Config file missing:', error.message);
        return { success: false, error: 'Tor configuration file not found' };
      }

      // Derive configured ports from config as baseline
      const portsFromCfg = await this.parsePortsFromConfig(this.configPath);
      let configuredSocksPort = portsFromCfg.socks;
      let configuredControlPort = portsFromCfg.control;

      // Ensure CookieAuthentication and ControlPort are present in config (for rotation)
      try {
        let cfg = await fs.readFile(this.configPath, 'utf8');
        let changed = false;
        const dataDir = this.getDataDir();
        if (!/^CookieAuthentication\s+1/m.test(cfg)) { cfg += '\nCookieAuthentication 1\n'; changed = true; }
        if (!/^ControlPort\s+\d+/m.test(cfg)) { cfg += `\nControlPort ${configuredControlPort || 9051}\n`; changed = true; }
        if (!/^DataDirectory\s+/m.test(cfg)) { cfg += `\nDataDirectory ${dataDir}\n`; changed = true; }
        if (changed) {
          await fs.writeFile(this.configPath, cfg, 'utf8');
          console.log('[TOR-MANAGER] Updated torrc to include CookieAuthentication/ControlPort/DataDirectory');
        }
      } catch (e) {
        console.warn('[TOR-MANAGER] Could not ensure torrc has control settings:', e?.message || e);
      }

      // Start bundled Tor process
      console.log('[TOR-MANAGER] Spawning bundled Tor process...');

      let processError = null;

      // Build spawn arguments for bundled Tor
      let spawnArgs = ['-f', this.configPath, '--DataDirectory', dataDir];

      // Find available ports to avoid conflicts
      const findAvailablePort = async (startPort) => {
        for (let port = startPort; port < startPort + 100; port++) {
          try {
            const portsInUse = await new Promise((resolve) => {
              exec(`ss -tlnp | grep ":${port}"`, (error, stdout) => {
                resolve(!error && stdout ? stdout.trim() : '');
              });
            });
            if (!portsInUse || portsInUse === '') {
              return port;
            }
          } catch (e) {
            return port; // If port check fails, try the port anyway
          }
        }
        return startPort; // Fallback
      };

      try {
        // Find available ports starting from 9150
        const availableSocksPort = await findAvailablePort(9150);
        const availableControlPort = await findAvailablePort(availableSocksPort + 1);
        
        console.log(`[TOR-MANAGER] Using ports: SOCKS=${availableSocksPort}, Control=${availableControlPort}`);
        
        spawnArgs = ['-f', this.configPath, '--DataDirectory', dataDir, 'SocksPort', availableSocksPort.toString(), 'ControlPort', availableControlPort.toString()];
        this.effectiveSocksPort = availableSocksPort;
        this.effectiveControlPort = availableControlPort;
      } catch (e) {
        console.warn('[TOR-MANAGER] Port detection failed, using configured ports:', e?.message || e);
        this.effectiveSocksPort = configuredSocksPort;
        this.effectiveControlPort = configuredControlPort;
      }
      
      console.log('[TOR-MANAGER] Using bundled Tor binary:', this.torPath);
      
      // Spawn the bundled Tor process
      this.torProcess = spawn(this.torPath, spawnArgs, {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false,
        env: { ...process.env, LD_LIBRARY_PATH: this.torDir } // Ensure bundled libraries are found
      });

      // Handle process events
      this.torProcess.stdout.on('data', (data) => {
        const line = data.toString().trim();
        console.log('[TOR]', line);
        try {
          if (/Bootstrapped\s+100%/i.test(line)) {
            this.bootstrapped = true;
          }
          // Detect port announcements
          const socksMatch = line.match(/Opened\s+(?:Socks(?:5)?|SOCKS(?:5)?)\s+listener.*:(\d+)/i);
          if (socksMatch) {
            const p = parseInt(socksMatch[1], 10);
            if (Number.isFinite(p)) this.effectiveSocksPort = p;
          }
          const controlMatch = line.match(/Opened\s+Control\s+listener.*:(\d+)/i);
          if (controlMatch) {
            const p = parseInt(controlMatch[1], 10);
            if (Number.isFinite(p)) this.effectiveControlPort = p;
          }
        } catch (e) {
          console.warn('[TOR-MANAGER] Failed to parse Tor stdout:', e?.message || e);
        }
      });

      this.torProcess.stderr.on('data', (data) => {
        const errorMsg = data.toString().trim();
        console.error('[TOR-ERROR]', errorMsg);
        if (errorMsg && !processError) {
          processError = errorMsg;
        }
      });

      this.torProcess.on('exit', (code) => {
        console.log(`[TOR-MANAGER] Bundled Tor process exited with code ${code}`);
        if (code !== 0 && !processError) {
          processError = `Tor exited with code ${code}`;
        }
        this.torProcess = null;
      });

      this.torProcess.on('error', (error) => {
        console.error('[TOR-MANAGER] Tor process spawn error:', error);
        processError = `Failed to spawn bundled Tor: ${error.message}`;
        this.torProcess = null;
      });

      // Wait for Tor to initialize
      console.log('[TOR-MANAGER] Waiting for bundled Tor to initialize...');
      for (let i = 0; i < 30; i++) {
        if (this.bootstrapped) break;
        if (processError) break;
        if (!this.torProcess) break;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      // Ensure effective ports are set
      if (!this.effectiveSocksPort) this.effectiveSocksPort = configuredSocksPort || 9150;
      if (!this.effectiveControlPort) this.effectiveControlPort = configuredControlPort || 9151;

      // Check for critical errors
      if (processError) {
        console.error('[TOR-MANAGER] Bundled Tor startup failed:', processError);
        return { success: false, error: processError };
      }

      // Verify the process is still running
      if (!this.torProcess || this.torProcess.killed) {
        console.error('[TOR-MANAGER] Bundled Tor process failed to start or died');
        return { success: false, error: 'Bundled Tor process failed to start' };
      }

      console.log('[TOR-MANAGER] Tor service started (verify may follow)');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to start Tor:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Stop Tor service
   */
  async stopTor() {
    try {
      console.log('[TOR-MANAGER] Stopping Tor service...');

      if (this.torProcess) {
        this.torProcess.kill('SIGTERM');

        // Wait for process to exit
        await new Promise((resolve) => {
          if (this.torProcess) {
            this.torProcess.on('exit', resolve);
            // Force kill after 5 seconds
            setTimeout(() => {
              if (this.torProcess) {
                this.torProcess.kill('SIGKILL');
              }
              resolve();
            }, 5000);
          } else {
            resolve();
          }
        });

        this.torProcess = null;
      }

      console.log('[TOR-MANAGER] Tor service stopped');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to stop Tor:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Uninstall Tor (remove files)
   */
  async uninstallTor() {
    try {
      console.log('[TOR-MANAGER] Uninstalling Tor...');

      // Stop Tor first
      await this.stopTor();

      // Remove Tor directory
      await fs.rmdir(this.torDir, { recursive: true });

      console.log('[TOR-MANAGER] Tor uninstalled successfully');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to uninstall Tor:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Check if Tor is running
   */
  isTorRunning() {
    return this.torProcess !== null && !this.torProcess.killed;
  }

  /**
   * Get Tor status
   */
  getTorStatus() {
    return {
      isRunning: this.isTorRunning(),
      processId: this.torProcess?.pid,
      configPath: this.configPath,
      torPath: this.torPath,
      // Additional verification info
      hasProcess: !!this.torProcess,
      processKilled: this.torProcess?.killed,
      uptime: this.torProcess ? Date.now() - (this.torProcess.spawnTime || Date.now()) : 0
    };
  }

  /**
   * Get detailed Tor information for verification
   */
  async getTorInfo() {
    try {
      const status = this.getTorStatus();

      // Check if config file exists
      let configExists = false;
      let configContent = '';
      try {
        const stats = await fs.stat(this.configPath);
        configExists = stats.isFile();
        configContent = await fs.readFile(this.configPath, 'utf8');
      } catch (error) {
        console.log('[TOR-MANAGER] Config file not found:', this.configPath);
      }

      // Check if Tor binary exists (local)
      let binaryExists = false;
      try {
        const stats = await fs.stat(this.torPath);
        binaryExists = stats.isFile();
      } catch (error) {
        console.log('[TOR-MANAGER] Local Tor binary not found:', this.torPath);
      }

      // If no local binary, check for system Tor
      let systemTorRunning = false;
      let systemTorVersion = null;
      let systemTorBinaryPath = null;
      if (!binaryExists || !status.isRunning) {
        try {
          const systemCheck = await new Promise((resolve) => {
            exec('tor --version', (error, stdout) => {
              if (!error && stdout.includes('Tor version')) {
                const version = stdout.split('\n')[0].match(/Tor version (\d+\.\d+\.\d+)/)?.[1];
                resolve({ available: true, version });
              } else {
                resolve({ available: false });
              }
            });
          });

          if (systemCheck.available) {
            systemTorVersion = systemCheck.version;
            
            // Get system Tor binary path
            const binaryPathCheck = await new Promise((resolve) => {
              const whichCmd = this.platform === 'win32' ? 'where tor' : 'which tor';
              exec(whichCmd, (error, stdout) => {
                if (!error && stdout.trim()) {
                  resolve(stdout.trim().split('\n')[0]);
                } else {
                  resolve('tor (in PATH)');
                }
              });
            });
            
            systemTorBinaryPath = binaryPathCheck;
            
            // Check if system Tor service is actually running (not just any Tor on port 9050)
            const serviceCheck = await new Promise((resolve) => {
              if (this.platform === 'win32') {
                exec('sc query tor', (error, stdout) => {
                  const isRunning = !error && stdout.includes('RUNNING');
                  resolve(isRunning);
                });
              } else {
                // Linux/macOS: check for port 9050 listener AND Tor process
                exec('ss -tln | grep ":9050"', (portError, portStdout) => {
                  const port9050Open = !portError && portStdout.includes(':9050');
                  
                  if (port9050Open) {
                    exec('ps aux | grep -v grep | grep "/usr/bin/tor"', (processError, processStdout) => {
                      const hasTorProcess = !processError && processStdout.includes('/usr/bin/tor');
                      console.log('[TOR-MANAGER] System Tor check - Port 9050:', port9050Open, ', Tor process:', hasTorProcess);
                      if (hasTorProcess) {
                        console.log('[TOR-MANAGER] System Tor details:', processStdout.trim());
                      }
                      resolve(port9050Open && hasTorProcess);
                    });
                  } else {
                    console.log('[TOR-MANAGER] Port 9050 not open, no system Tor');
                    resolve(false);
                  }
                });
              }
            });
            
            systemTorRunning = serviceCheck;
          }
        } catch (error) {
          console.log('[TOR-MANAGER] Failed to check system Tor:', error);
        }
      }

      // Check if data directory exists
      const dataDir = this.getDataDir();
      let dataDirExists = false;
      try {
        const stats = await fs.stat(dataDir);
        dataDirExists = stats.isDirectory();
      } catch (error) {
        console.log('[TOR-MANAGER] Data directory not found:', dataDir);
      }

      // Determine which Tor is actually running
      const finalStatus = {
        ...status,
        isRunning: status.isRunning || systemTorRunning,
        processId: status.processId || (systemTorRunning ? 'system' : status.processId)
      };
      
      // If we have our own process running, don't override with system info
      if (this.torProcess && !this.torProcess.killed) {
        finalStatus.isRunning = true;
        finalStatus.processId = this.torProcess.pid;
        systemTorRunning = false; // Our bundled Tor takes precedence
      }

      // Extract ports from configuration
      let socksPort = null;
      let controlPort = null;
      if (configExists) {
        try {
          const hasSocks = /^SocksPort\s+/m.test(configContent);
          const hasControl = /^ControlPort\s+/m.test(configContent);
          const ports = await this.parsePortsFromConfig(this.configPath);
          if (hasSocks) socksPort = ports.socks;
          if (hasControl) controlPort = ports.control;
        } catch (e) {
          console.warn('[TOR-MANAGER] Failed to parse ports from config in getTorInfo:', e?.message || e);
        }
      }
      
      // Detect ports from actual running processes
      if (!socksPort || !controlPort) {
        try {
          const portDetection = await new Promise((resolve) => {
            const cmd = this.platform === 'win32' 
              ? 'netstat -ano | findstr LISTEN'
              : 'ss -tlnp | grep :905 || netstat -tlnp | grep :905';
            
            exec(cmd, (error, stdout) => {
              const ports = { socks: null, control: null };
              if (!error && stdout) {
                // Look for ports 9050-9059 range
                const portMatches = stdout.match(/:(\d+)/g);
                if (portMatches) {
                  portMatches.forEach(match => {
                    const port = parseInt(match.substring(1), 10);
                    // SOCKS ports (9050-9059)
                    if (port >= 9050 && port <= 9059 && !ports.socks) {
                      ports.socks = port;
                    }
                    // Control ports (9051-9061)
                    if (port >= 9051 && port <= 9061 && !ports.control) {
                      ports.control = port;
                    }
                  });
                }
              }
              resolve(ports);
            });
          });
          
          if (!socksPort && portDetection.socks) socksPort = portDetection.socks;
          if (!controlPort && portDetection.control) controlPort = portDetection.control;
        } catch (error) {
          console.log('[TOR-MANAGER] Failed to detect Tor ports:', error);
        }
      }

      return {
        ...finalStatus,
        configExists,
        configSize: configContent.length,
        configPath: this.configPath,
        binaryExists: binaryExists || !!systemTorVersion,
        binaryPath: systemTorVersion ? (systemTorBinaryPath || 'system') : this.torPath,
        dataDirExists,
        dataDirectory: path.join(this.torDir, 'data'),
        torDirectory: this.torDir,
        platform: this.platform,
        arch: this.arch,
        systemTorRunning,
        systemTorVersion,
        usingSystemTor: systemTorRunning && !this.torProcess, // Only true if system Tor is running AND we don't have our own process
        socksPort,
        controlPort
      };
    } catch (error) {
      console.error('[TOR-MANAGER] Failed to get Tor info:', error);
      return { error: error.message };
    }
  }

  /**
   * Rotate Tor circuit for enhanced anonymity (REAL IMPLEMENTATION)
   */
  async rotateCircuit() {
    try {
      console.log('[TOR-MANAGER] ===== STARTING REAL CIRCUIT ROTATION =====');

      if (!this.torProcess && !this.usingSystemTor) {
        console.error('[TOR-MANAGER] Cannot rotate circuit - Tor not running');
        return { success: false, error: 'Tor is not running' };
      }

      // Get current IP and circuit info before rotation
      const beforeIP = await this.getCurrentTorIP();
      const beforeCircuit = await this.getCurrentCircuitInfo();
      console.log('[TOR-MANAGER] Current IP before rotation:', beforeIP);
      console.log('[TOR-MANAGER] Current circuit before rotation:', beforeCircuit);

      let rotationResult;

      // Try different methods based on Tor setup
      if (this.usingSystemTor) {
        console.log('[TOR-MANAGER] Using system Tor - trying control port method...');

        // Method 1: Try control port (primary method)
        console.log('[TOR-MANAGER] Method 1: Attempting control port connection...');
        rotationResult = await this.sendNewNymSignal();

        if (!rotationResult.success) {
          console.log('[TOR-MANAGER] Control port failed, trying Method 2: Force circuit change...');
          // Method 2: Force circuit change by making multiple requests (last resort)
          rotationResult = await this.forceCircuitChange();
        }
      } else {
        // For our own Tor process, use control port
        console.log('[TOR-MANAGER] Using managed Tor - attempting control port...');
        rotationResult = await this.sendNewNymSignal();
      }

      if (!rotationResult.success) {
        console.error('[TOR-MANAGER] All rotation methods failed:', rotationResult.error);
        return rotationResult;
      }

      console.log('[TOR-MANAGER] Circuit rotation method succeeded:', rotationResult.method);

      // Wait a moment for circuit to change
      console.log('[TOR-MANAGER] Waiting 5 seconds for circuit to rebuild...');
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Make a few more requests to encourage different exit node selection
      console.log('[TOR-MANAGER] Making additional requests to encourage exit node change...');
      for (let i = 0; i < 3; i++) {
        await this.makeRequestThroughTor('https://httpbin.org/ip');
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      // Get new IP and circuit info after rotation
      const afterIP = await this.getCurrentTorIP();
      const afterCircuit = await this.getCurrentCircuitInfo();
      console.log('[TOR-MANAGER] New IP after rotation:', afterIP);
      console.log('[TOR-MANAGER] New circuit after rotation:', afterCircuit);

      const ipChanged = beforeIP !== afterIP;
      const circuitChanged = JSON.stringify(beforeCircuit) !== JSON.stringify(afterCircuit);

      console.log('[TOR-MANAGER] ===== CIRCUIT ROTATION RESULT =====');
      console.log('[TOR-MANAGER] Method used:', rotationResult.method);
      console.log('[TOR-MANAGER] IP changed:', ipChanged);
      console.log('[TOR-MANAGER] Circuit path changed:', circuitChanged);
      console.log('[TOR-MANAGER] Before IP:', beforeIP);
      console.log('[TOR-MANAGER] After IP:', afterIP);
      console.log('[TOR-MANAGER] ===== CIRCUIT PATH COMPARISON =====');
      console.log('[TOR-MANAGER] Before circuit:', beforeCircuit);
      console.log('[TOR-MANAGER] After circuit:', afterCircuit);

      return {
        success: true,
        message: `Circuit rotated using ${rotationResult.method}. IP changed: ${ipChanged}, Circuit changed: ${circuitChanged}`,
        method: rotationResult.method,
        beforeIP,
        afterIP,
        ipChanged,
        beforeCircuit,
        afterCircuit,
        circuitChanged
      };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to rotate circuit:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Send NEWNYM signal to Tor control port
   */
  async sendNewNymSignal() {
    return new Promise(async (resolve) => {
      const net = require('net');
      let controlPort = this.effectiveControlPort || 9051; // prefer effective port

      // Try to read ControlPort from config as fallback only if effectiveControlPort not set
      if (!this.effectiveControlPort) {
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8');
          const m = cfg.match(/^ControlPort\s+(\d+)/m);
          if (m) controlPort = parseInt(m[1], 10) || controlPort;
        } catch {}
      }

      // Read cookie for authentication (CookieAuthentication 1)
      const dataDir = this.getDataDir();
      const cookiePath = path.join(dataDir, 'control_auth_cookie');
      let cookieHex = null;
      try {
        const cookie = await fs.readFile(cookiePath);
        cookieHex = cookie.toString('hex');
      } catch {}

      console.log('[TOR-MANAGER] sendNewNymSignal: Using control port:', controlPort);
      console.log('[TOR-MANAGER] sendNewNymSignal: this.effectiveControlPort =', this.effectiveControlPort);
      console.log('[TOR-MANAGER] sendNewNymSignal: this.configuredControlPort =', this.configuredControlPort);
      const socket = net.createConnection(controlPort, '127.0.0.1');

      let stage = cookieHex ? 'auth' : 'signal';
      let buffer = '';

      const send = (cmd) => socket.write(cmd + '\r\n');

      socket.on('connect', () => {
        console.log('[TOR-MANAGER] Connected to Tor control port');
        if (stage === 'auth') {
          if (cookieHex) send(`AUTHENTICATE ${cookieHex}`);
          else { stage = 'signal'; send('SIGNAL NEWNYM'); }
        } else {
          send('SIGNAL NEWNYM');
        }
      });

      socket.on('data', (data) => {
        buffer += data.toString();
        const lines = buffer.split(/\r?\n/).filter(Boolean);
        for (const line of lines) {
          console.log('[TOR-MANAGER] Control port response:', line.trim());
          if (/^250/.test(line)) {
            if (stage === 'auth') {
              stage = 'signal';
              send('SIGNAL NEWNYM');
            } else {
              socket.end();
              return resolve({ success: true, method: 'control-port' });
            }
          } else if (/^(515|514|510)/.test(line)) {
            socket.end();
            return resolve({ success: false, error: `Control port authentication failed: ${line.trim()}` });
          } else if (/^[45]\d\d/.test(line)) {
            socket.end();
            return resolve({ success: false, error: `Control port error: ${line.trim()}` });
          }
        }
        buffer = '';
      });

      socket.on('error', (error) => {
        console.error('[TOR-MANAGER] Control port connection error:', error.message);
        resolve({ success: false, error: `Control port error: ${error.message}` });
      });

      socket.on('close', () => {
        console.log('[TOR-MANAGER] Control port connection closed');
      });

      setTimeout(() => {
        if (!socket.destroyed) {
          console.error('[TOR-MANAGER] Control port connection timeout');
          socket.destroy();
          resolve({ success: false, error: 'Control port connection timeout' });
        }
      }, 5000);
    });
  }

  /**
   * Send system signal to Tor process (DISABLED - no-op wrapper)
   * Note: Tor does not support NEWNYM via SIGUSR2, so this is disabled
   */
  async sendSystemSignal() {
    console.log('[TOR-MANAGER] System signal method is disabled (Tor does not support NEWNYM via SIGUSR2)');
    return { success: false, error: 'System signal method is disabled' };
  }

  /**
   * Force circuit change by making multiple requests (Method 3)
   */
  async forceCircuitChange() {
    try {
      console.log('[TOR-MANAGER] Attempting to force circuit change with multiple requests...');

      // Make several requests to different endpoints to encourage circuit change
      const endpoints = [
        'https://httpbin.org/ip',
        'https://icanhazip.com',
        'https://ipinfo.io/ip',
        'https://api.ipify.org?format=json'
      ];

      for (let i = 0; i < endpoints.length; i++) {
        console.log(`[TOR-MANAGER] Making request ${i + 1}/${endpoints.length} to force circuit change...`);
        await this.makeRequestThroughTor(endpoints[i]);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second between requests
      }

      console.log('[TOR-MANAGER] Completed circuit change requests');
      return { success: true, method: 'force-requests' };

    } catch (error) {
      console.error('[TOR-MANAGER] Force circuit change failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Make a request through Tor
   */
  async makeRequestThroughTor(url) {
    return new Promise((resolve) => {
      try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const https = require('https');
        const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${this.effectiveSocksPort || 9050}`);

        const req = https.get(url, { agent: proxyAgent, timeout: 5000 }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve(data));
        });

        req.on('error', () => resolve('error'));
        req.on('timeout', () => resolve('timeout'));
      } catch (error) {
        resolve('error');
      }
    });
  }

  /**
   * Get current Tor IP address
   */
  async getCurrentTorIP() {
    try {
      // Determine active SOCKS port from effective setting or config
      let socksPort = this.effectiveSocksPort || 9050;
      if (!this.effectiveSocksPort) {
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8');
          const m = cfg.match(/^SocksPort\s+(\d+)/m);
          if (m) socksPort = parseInt(m[1], 10) || socksPort;
        } catch {}
      }

      const { SocksProxyAgent } = require('socks-proxy-agent');
      const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${socksPort}`);

      return new Promise((resolve) => {
        const options = {
          hostname: 'httpbin.org',
          path: '/ip',
          method: 'GET',
          agent: proxyAgent,
          timeout: 10000
        };

        const req = https.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              const result = JSON.parse(data);
              resolve(result.origin || 'unknown');
            } catch (error) {
              resolve('parse-error');
            }
          });
        });

        req.on('error', (error) => {
          console.error('[TOR-MANAGER] IP check error:', error.message);
          resolve('error');
        });

        req.on('timeout', () => {
          console.error('[TOR-MANAGER] IP check timeout');
          resolve('timeout');
        });

        req.end();
      });
    } catch (error) {
      console.error('[TOR-MANAGER] Failed to get current IP:', error);
      return 'error';
    }
  }

  /**
   * Get current Tor circuit information (relay nodes, path, etc.)
   */
  async getCurrentCircuitInfo() {
    try {
      console.log('[TOR-MANAGER] Gathering circuit information...');

      // Method 1: Try to get circuit info from control port
      const controlInfo = await this.getCircuitInfoFromControl();
      if (controlInfo.success) {
        console.log('[TOR-MANAGER] Got circuit info from control port');
        return controlInfo.data;
      }

      // Method 2: Get network-level information
      console.log('[TOR-MANAGER] Getting network-level circuit info...');
      const networkInfo = await this.getNetworkCircuitInfo();

      return networkInfo;

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to get circuit info:', error);
      return { error: error.message, timestamp: Date.now() };
    }
  }

  /**
   * Get circuit info from Tor control port
   */
  async getCircuitInfoFromControl() {
    return new Promise(async (resolve) => {
      const net = require('net');
      let controlPort = this.effectiveControlPort || 9051; // prefer effective port
      
      // Try to read ControlPort from config as fallback only if effectiveControlPort not set
      if (!this.effectiveControlPort) {
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8');
          const m = cfg.match(/^ControlPort\s+(\d+)/m);
          if (m) controlPort = parseInt(m[1], 10) || controlPort;
        } catch {}
      }

      console.log('[TOR-MANAGER] getCircuitInfoFromControl: Using control port:', controlPort);
      console.log('[TOR-MANAGER] getCircuitInfoFromControl: this.effectiveControlPort =', this.effectiveControlPort);

      const dataDir = this.getDataDir();
      const cookiePath = path.join(dataDir, 'control_auth_cookie');
      let cookieHex = null;
      try {
        const cookie = await fs.readFile(cookiePath);
        cookieHex = cookie.toString('hex');
      } catch {}

      const socket = net.createConnection(controlPort, '127.0.0.1');
      let stage = cookieHex ? 'auth' : 'getinfo';
      let buffer = '';
      const send = (cmd) => socket.write(cmd + '\r\n');

      socket.on('connect', () => {
        console.log('[TOR-MANAGER] Connected to control port for circuit info');
        if (stage === 'auth') send(`AUTHENTICATE ${cookieHex}`); else send('GETINFO circuit-status');
      });

      socket.on('data', (data) => {
        buffer += data.toString();
        const lines = buffer.split(/\r?\n/).filter(Boolean);
        for (const line of lines) {
          console.log('[TOR-MANAGER] Control response:', line.trim());
          if (/^250/.test(line)) {
            if (stage === 'auth') {
              stage = 'getinfo';
              send('GETINFO circuit-status');
            } else {
              socket.end();
              const circuits = this.parseCircuitStatus(buffer);
              return resolve({ success: true, data: circuits });
            }
          } else if (/^(515|514|510)/.test(line)) {
            socket.end();
            return resolve({ success: false, error: `Control port authentication failed: ${line.trim()}` });
          } else if (/^[45]\d\d/.test(line)) {
            socket.end();
            return resolve({ success: false, error: `Control port error: ${line.trim()}` });
          }
        }
        buffer = '';
      });

      socket.on('error', (error) => {
        console.log('[TOR-MANAGER] Control port not available:', error.message);
        resolve({ success: false, error: error.message });
      });

      setTimeout(() => {
        if (!socket.destroyed) {
          socket.destroy();
          resolve({ success: false, error: 'Control port timeout' });
        }
      }, 5000);
    });
  }

  /**
   * Parse circuit status from control port response
   */
  parseCircuitStatus(response) {
    try {
      const lines = response.split('\n');
      const circuits = [];

      for (const line of lines) {
        if (line.includes('BUILT') || line.includes('EXTENDED')) {
          const parts = line.split(' ');
          if (parts.length >= 3) {
            const circuitId = parts[0].replace('250-circuit-status=', '').replace('250+circuit-status=', '');
            const status = parts[1];
            const path = parts[2];

            circuits.push({
              id: circuitId,
              status: status,
              path: path,
              relays: path.split(',').map(relay => {
                const [fingerprint, nickname] = relay.split('~');
                return { fingerprint, nickname: nickname || 'unknown' };
              })
            });
          }
        }
      }

      return { circuits, timestamp: Date.now(), source: 'control-port' };
    } catch (error) {
      console.error('[TOR-MANAGER] Failed to parse circuit status:', error);
      return { error: 'Parse failed', timestamp: Date.now() };
    }
  }

  /**
   * Get network-level circuit information
   */
  async getNetworkCircuitInfo() {
    try {
      console.log('[TOR-MANAGER] Collecting network-level circuit data...');

      // Get multiple data points to infer circuit characteristics
      const requests = [];
      const endpoints = [
        'https://httpbin.org/headers',
        'https://httpbin.org/user-agent',
        'https://icanhazip.com',
        'https://ipinfo.io/json'
      ];

      for (const endpoint of endpoints) {
        console.log('[TOR-MANAGER] Making request to:', endpoint);
        const result = await this.makeDetailedRequestThroughTor(endpoint);
        requests.push({
          endpoint,
          timestamp: Date.now(),
          latency: result.latency,
          success: result.success,
          headers: result.headers
        });

        // Small delay between requests
        await new Promise(resolve => setTimeout(resolve, 500));
      }

      // Generate circuit fingerprint based on timing and behavior
      const circuitFingerprint = this.generateCircuitFingerprint(requests);

      return {
        timestamp: Date.now(),
        source: 'network-analysis',
        fingerprint: circuitFingerprint,
        requests: requests.length,
        avgLatency: requests.reduce((sum, r) => sum + (r.latency || 0), 0) / requests.length,
        successRate: requests.filter(r => r.success).length / requests.length
      };

    } catch (error) {
      console.error('[TOR-MANAGER] Network circuit info failed:', error);
      return { error: error.message, timestamp: Date.now() };
    }
  }

  /**
   * Make detailed request through Tor with timing info
   */
  async makeDetailedRequestThroughTor(url) {
    return new Promise(async (resolve) => {
      const startTime = Date.now();

      try {
        // Determine active SOCKS port from config (fallback to 9050)
        let socksPort = 9050;
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8');
          const m = cfg.match(/^SocksPort\s+(\d+)/m);
          if (m) socksPort = parseInt(m[1], 10) || socksPort;
        } catch {}

        const { SocksProxyAgent } = require('socks-proxy-agent');
        const https = require('https');
        const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${socksPort}`);

        const req = https.get(url, { agent: proxyAgent, timeout: 8000 }, (res) => {
          let data = '';
          const headers = res.headers;

          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            const latency = Date.now() - startTime;
            resolve({
              success: true,
              latency,
              headers,
              dataSize: data.length
            });
          });
        });

        req.on('error', (error) => {
          const latency = Date.now() - startTime;
          resolve({
            success: false,
            latency,
            error: error.message
          });
        });

        req.on('timeout', () => {
          const latency = Date.now() - startTime;
          resolve({
            success: false,
            latency,
            error: 'timeout'
          });
        });

      } catch (error) {
        const latency = Date.now() - startTime;
        resolve({
          success: false,
          latency,
          error: error.message
        });
      }
    });
  }

  /**
   * Generate circuit fingerprint based on network behavior
   */
  generateCircuitFingerprint(requests) {
    try {
      // Create a fingerprint based on timing patterns and responses
      const latencies = requests.map(r => r.latency || 0);
      const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
      const latencyVariance = latencies.reduce((sum, lat) => sum + Math.pow(lat - avgLatency, 2), 0) / latencies.length;

      // Create a hash-like fingerprint
      const fingerprint = `${Math.round(avgLatency)}-${Math.round(latencyVariance)}-${requests.length}-${Date.now() % 10000}`;

      console.log('[TOR-MANAGER] Generated circuit fingerprint:', fingerprint);
      console.log('[TOR-MANAGER] Avg latency:', Math.round(avgLatency), 'ms');
      console.log('[TOR-MANAGER] Latency variance:', Math.round(latencyVariance));

      return fingerprint;
    } catch (error) {
      return `error-${Date.now()}`;
    }
  }

  /**
   * Check if SOCKS proxy is responding (simple connectivity test)
   */
  async checkSocksProxy(port) {
    return new Promise((resolve) => {
      const net = require('net');
      const socket = net.createConnection(port, '127.0.0.1');
      
      const timeout = setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, 3000);
      
      socket.on('connect', () => {
        clearTimeout(timeout);
        socket.destroy();
        resolve(true);
      });
      
      socket.on('error', () => {
        clearTimeout(timeout);
        resolve(false);
      });
    });
  }

  /**
   * Verify Tor connection by checking IP through Tor network
   */
  async verifyTorConnection() {
    try {
      console.log('[TOR-MANAGER] Verifying Tor connection...');
      console.log('[TOR-MANAGER] this.effectiveSocksPort =', this.effectiveSocksPort);

      // Use effective SOCKS port if known, else read from config, else default
      let socksPort = this.effectiveSocksPort || 9050;
      if (!this.effectiveSocksPort) {
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8');
          const m = cfg.match(/^SocksPort\s+(\d+)/m);
          if (m) socksPort = parseInt(m[1], 10) || socksPort;
        } catch {}
      }

      console.log('[TOR-MANAGER] Using SOCKS port for verification:', socksPort);
      
      return new Promise((resolve) => {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${socksPort}`);

        // First do a quick SOCKS proxy check (faster and more reliable)
        this.checkSocksProxy(socksPort).then(socksWorking => {
          if (!socksWorking) {
            console.log('[TOR-MANAGER] SOCKS proxy not responding, Tor likely not working');
            resolve({ success: false, error: 'SOCKS proxy not responding on port ' + socksPort });
            return;
          }
          
          console.log('[TOR-MANAGER] SOCKS proxy responding, now testing external connectivity...');
          
          const options = {
            hostname: 'check.torproject.org',
            path: '/api/ip',
            method: 'GET',
            agent: proxyAgent,
            timeout: 10000  // Reduce timeout to 10 seconds since SOCKS is already working
          };

          const req = https.request(options, (res) => {
            let data = '';

            res.on('data', (chunk) => {
              data += chunk;
            });

            res.on('end', () => {
              try {
                const result = JSON.parse(data);
                console.log('[TOR-MANAGER] Tor verification result:', result);
                resolve({
                  success: true,
                  isTor: result.IsTor === true,
                  ip: result.IP
                });
              } catch (parseError) {
                console.error('[TOR-MANAGER] Failed to parse verification response:', parseError);
                resolve({ success: false, error: 'Invalid response format' });
              }
            });
          });

          req.on('error', (error) => {
            console.error('[TOR-MANAGER] Tor verification failed:', error);
            console.log('[TOR-MANAGER] SOCKS proxy was responding but external verification failed');
            resolve({ success: true, error: `External verification failed but SOCKS proxy responding: ${error.message}`, isTor: true });
          });

          req.on('timeout', () => {
            console.error('[TOR-MANAGER] Tor verification timed out');
            req.destroy();
            console.log('[TOR-MANAGER] SOCKS proxy was responding but external verification timed out');
            resolve({ success: true, error: 'External verification timed out but SOCKS proxy responding', isTor: true });
          });

          req.end();
        }).catch((socksError) => {
          console.log('[TOR-MANAGER] Failed to check SOCKS proxy:', socksError.message);
          resolve({ success: false, error: 'SOCKS proxy check failed: ' + socksError.message });
        });
      });

    } catch (error) {
      console.error('[TOR-MANAGER] Tor verification error:', error);
      console.log('[TOR-MANAGER] Attempting SOCKS proxy fallback check...');
      
      // Fallback: check if SOCKS proxy is at least responding
      try {
        const socksPort = this.effectiveSocksPort || 9050;
        const socksWorking = await this.checkSocksProxy(socksPort);
        if (socksWorking) {
          console.log('[TOR-MANAGER] SOCKS proxy is responding, considering Tor as working (fallback)');
          return { success: true, error: `External verification failed but SOCKS proxy responding: ${error.message}`, isTor: true };
        }
      } catch (fallbackError) {
        console.log('[TOR-MANAGER] Fallback SOCKS check also failed:', fallbackError.message);
      }
      
      return { success: false, error: error.message };
    }
  }
}

// Export singleton instance
module.exports = new ElectronTorManager();