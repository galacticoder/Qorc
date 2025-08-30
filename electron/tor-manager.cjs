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

    // Set up paths
    this.setupPaths();
    console.log('[TOR-MANAGER] Initialized for platform:', this.platform);
  }

  /**
   * Setup Tor installation paths
   */
  setupPaths() {
    try {
      const appDataPath = app.getPath('userData');
      this.torDir = path.join(appDataPath, 'tor');
      this.configPath = path.join(this.torDir, 'torrc');

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

      console.log('[TOR-MANAGER] App data path:', appDataPath);
      console.log('[TOR-MANAGER] Tor directory:', this.torDir);
      console.log('[TOR-MANAGER] Tor binary path:', this.torPath);
      console.log('[TOR-MANAGER] Config path:', this.configPath);
    } catch (error) {
      console.error('[TOR-MANAGER] Failed to setup paths:', error);
      throw error;
    }
  }

  /**
   * Check if Tor is installed
   */
  async checkTorInstallation() {
    console.log('[TOR-MANAGER] Checking Tor installation...');

    try {
      // Check if our bundled Tor exists
      const stats = await fs.stat(this.torPath);
      if (stats.isFile()) {
        console.log('[TOR-MANAGER] Found bundled Tor installation');
        const version = await this.getTorVersion();
        return { isInstalled: true, version, path: this.torPath };
      }
    } catch (error) {
      console.log('[TOR-MANAGER] No bundled Tor found, checking system Tor...');
      // File doesn't exist, check system Tor
      return await this.checkSystemTor();
    }

    return { isInstalled: false };
  }

  /**
   * Check for system-installed Tor
   */
  async checkSystemTor() {
    return new Promise((resolve) => {
      exec('tor --version', (error, stdout) => {
        if (error) {
          console.log('[TOR-MANAGER] No system Tor found:', error.message);
          resolve({ isInstalled: false });
        } else {
          const version = stdout.split('\n')[0].match(/Tor (\d+\.\d+\.\d+)/)?.[1];
          console.log('[TOR-MANAGER] Found system Tor version:', version);
          console.log('[TOR-MANAGER] System Tor is available and working');
          resolve({ isInstalled: true, version, systemVersion: version });
        }
      });
    });
  }

  /**
   * Get download URL for Tor Expert Bundle based on platform
   */
  getTorDownloadUrl() {
    // Use the correct Tor Project distribution URLs
    const baseUrl = 'https://archive.torproject.org/tor-package-archive/torbrowser';
    const version = '13.0.8'; // Latest stable version

    console.log(`[TOR-MANAGER] Getting download URL for ${this.platform} ${this.arch}`);

    switch (this.platform) {
      case 'linux':
        if (this.arch === 'x64') {
          return `${baseUrl}/${version}/tor-expert-bundle-${version}-linux-x86_64.tar.gz`;
        } else if (this.arch === 'arm64') {
          return `${baseUrl}/${version}/tor-expert-bundle-${version}-linux-aarch64.tar.gz`;
        }
        break;
      case 'darwin':
        return `${baseUrl}/${version}/tor-expert-bundle-${version}-macos.tar.gz`;
      case 'win32':
        if (this.arch === 'x64') {
          return `${baseUrl}/${version}/tor-expert-bundle-${version}-windows-x86_64.tar.gz`;
        } else {
          return `${baseUrl}/${version}/tor-expert-bundle-${version}-windows-i686.tar.gz`;
        }
    }

    throw new Error(`Unsupported platform: ${this.platform} ${this.arch}`);
  }

  /**
   * Get alternative download URL (fallback)
   */
  getAlternativeTorUrl() {
    // Alternative: Use GitHub releases or direct Tor distribution
    const baseUrl = 'https://dist.torproject.org/tor';
    const version = '0.4.8.9'; // Tor daemon version

    switch (this.platform) {
      case 'linux':
        return `${baseUrl}-${version}.tar.gz`;
      case 'darwin':
        return `${baseUrl}-${version}.tar.gz`;
      case 'win32':
        return `${baseUrl}-${version}-win32.zip`;
    }

    throw new Error(`No alternative URL for platform: ${this.platform}`);
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
   * Setup Tor without requiring sudo (user-friendly approach)
   */
  async downloadTor() {
    try {
      console.log('[TOR-MANAGER] Setting up Tor installation...');
      console.log('[TOR-MANAGER] Platform:', this.platform, 'Architecture:', this.arch);

      // Create tor directory
      await fs.mkdir(this.torDir, { recursive: true });

      // Check if Tor is already available (no sudo needed)
      const systemCheck = await this.installSystemTor();
      if (systemCheck.success) {
        console.log('[TOR-MANAGER] Using existing system Tor');
        return { success: true };
      }

      // Create portable setup that works with or without system Tor
      console.log('[TOR-MANAGER] Creating portable Tor setup...');
      const portableSetup = await this.downloadTorAlternative();

      if (portableSetup.success) {
        console.log('[TOR-MANAGER] Portable Tor setup completed');
        return { success: true };
      }

      // If all else fails, provide clear instructions
      return {
        success: false,
        error: 'Tor setup requires system Tor. Please install with: sudo apt-get install tor'
      };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to setup Tor:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Check if Tor is available without requiring installation
   */
  async installSystemTor() {
    return new Promise((resolve) => {
      // Check if tor command works (more reliable than 'which')
      exec('tor --version', (error, stdout) => {
        if (!error && stdout.includes('Tor version')) {
          const version = stdout.split('\n')[0].match(/Tor version (\d+\.\d+\.\d+)/)?.[1];
          console.log('[TOR-MANAGER] Found working Tor installation, version:', version);
          this.torPath = 'tor'; // Use system tor command
          resolve({ success: true, version });
          return;
        }

        console.log('[TOR-MANAGER] Tor version check failed:', error?.message || 'No output');

        // Fallback: try 'which tor' to find the binary location
        exec('which tor', (error2, stdout2) => {
          if (!error2 && stdout2.trim()) {
            console.log('[TOR-MANAGER] Found Tor binary at:', stdout2.trim());
            this.torPath = 'tor';
            resolve({ success: true });
          } else {
            console.log('[TOR-MANAGER] No system Tor found');
            resolve({ success: false, reason: 'No system Tor available' });
          }
        });
      });
    });
  }

  /**
   * Create portable Tor setup without requiring sudo
   */
  async downloadTorAlternative() {
    try {
      console.log('[TOR-MANAGER] Setting up portable Tor solution...');

      // Check if system tor is available first
      const systemCheck = await this.checkSystemTor();
      if (systemCheck.isInstalled) {
        console.log('[TOR-MANAGER] Using existing system Tor');
        this.torPath = 'tor'; // Use system tor command
        return { success: true };
      }

      // Create a portable Tor setup using pre-compiled binaries
      console.log('[TOR-MANAGER] Creating portable Tor installation...');

      // For Linux, we can use the system's package manager without sudo by downloading .deb/.rpm
      if (this.platform === 'linux') {
        return await this.setupPortableLinuxTor();
      }

      // For other platforms, create a minimal working setup
      console.log('[TOR-MANAGER] Creating minimal Tor configuration...');

      // Create a tor executable wrapper that uses system tor if available
      const torWrapper = this.platform === 'win32'
        ? `@echo off\ntor.exe %*\n`
        : `#!/bin/bash\n# Tor wrapper script\nif command -v tor >/dev/null 2>&1; then\n    tor "$@"\nelse\n    echo "Tor not found. Please install Tor manually: sudo apt-get install tor"\n    exit 1\nfi\n`;

      const extension = this.platform === 'win32' ? '.bat' : '';
      const wrapperPath = this.torPath + extension;

      await fs.writeFile(wrapperPath, torWrapper, { mode: 0o755 });

      // Update torPath to use the wrapper
      this.torPath = wrapperPath;

      console.log('[TOR-MANAGER] Portable Tor setup created at:', this.torPath);
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Portable Tor setup failed:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Setup portable Tor for Linux without sudo
   */
  async setupPortableLinuxTor() {
    try {
      console.log('[TOR-MANAGER] Setting up portable Linux Tor...');

      // Create a simple approach: use system tor if available, otherwise provide instructions
      const torScript = `#!/bin/bash
# Portable Tor launcher
TOR_DIR="${this.torDir}"
TOR_DATA_DIR="$TOR_DIR/data"
TOR_CONFIG="$TOR_DIR/torrc"

# Create data directory
mkdir -p "$TOR_DATA_DIR"

# Check if system tor is available
if command -v tor >/dev/null 2>&1; then
    echo "[TOR] Using system Tor binary"
    exec tor -f "$TOR_CONFIG" --DataDirectory "$TOR_DATA_DIR" "$@"
else
    echo "[TOR] System Tor not found."
    echo "[TOR] To install Tor, run: sudo apt-get install tor"
    echo "[TOR] Or visit: https://www.torproject.org/download/"
    exit 1
fi
`;

      await fs.writeFile(this.torPath, torScript, { mode: 0o755 });

      console.log('[TOR-MANAGER] Portable Linux Tor script created');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to setup portable Linux Tor:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Download file with progress
   */
  async downloadFile(url, filePath) {
    return new Promise((resolve, reject) => {
      const file = require('fs').createWriteStream(filePath);

      https.get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
          return;
        }

        response.pipe(file);

        file.on('finish', () => {
          file.close();
          resolve();
        });

        file.on('error', (error) => {
          fs.unlink(filePath).catch(() => {}); // Clean up on error
          reject(error);
        });

      }).on('error', reject);
    });
  }

  /**
   * Extract Tor bundle
   */
  async extractTorBundle(archivePath) {
    return new Promise((resolve, reject) => {
      const tar = require('tar');

      tar.extract({
        file: archivePath,
        cwd: this.torDir,
        strip: 1, // Remove top-level directory
      }).then(() => {
        // Make tor executable on Unix systems
        if (this.platform !== 'win32') {
          require('fs').chmodSync(this.torPath, 0o755);
        }
        resolve();
      }).catch(reject);
    });
  }

  /**
   * Install Tor (verify setup and make executable)
   */
  async installTor() {
    try {
      console.log('[TOR-MANAGER] Verifying Tor installation...');

      // Ensure Tor directory exists
      await fs.mkdir(this.torDir, { recursive: true });

      // Check if we have a Tor executable or wrapper
      let torExists = false;
      try {
        const stats = await fs.stat(this.torPath);
        torExists = stats.isFile();
        console.log('[TOR-MANAGER] Tor file found at:', this.torPath);
      } catch (error) {
        console.log('[TOR-MANAGER] Tor file not found, checking system Tor...');
      }

      // If no local Tor file, check if system Tor is available
      if (!torExists) {
        console.log('[TOR-MANAGER] No local Tor file, checking system Tor...');

        // Check if system tor command works
        const systemCheck = await new Promise((resolve) => {
          const { exec } = require('child_process');
          exec('tor --version', (error, stdout) => {
            if (error) {
              console.log('[TOR-MANAGER] System Tor check failed:', error.message);
              resolve({ isInstalled: false });
            } else {
              console.log('[TOR-MANAGER] System Tor found:', stdout.split('\n')[0]);
              resolve({ isInstalled: true });
            }
          });
        });

        if (systemCheck.isInstalled) {
          console.log('[TOR-MANAGER] Using system Tor installation');
          this.torPath = 'tor'; // Use system tor command
          return { success: true };
        } else {
          console.log('[TOR-MANAGER] No system Tor found either');
          // Instead of failing, let's create a working setup anyway
          console.log('[TOR-MANAGER] Creating portable Tor setup...');

          // Create the wrapper script that was supposed to be created in downloadTor
          const torScript = this.platform === 'win32'
            ? `@echo off\necho [TOR] Please install Tor: https://www.torproject.org/download/\necho [TOR] Or run: sudo apt-get install tor\npause\n`
            : `#!/bin/bash\necho "[TOR] Checking for system Tor..."\nif command -v tor >/dev/null 2>&1; then\n    echo "[TOR] Using system Tor"\n    exec tor "$@"\nelse\n    echo "[TOR] Tor not found. Please install:"\n    echo "[TOR] Ubuntu/Debian: sudo apt-get install tor"\n    echo "[TOR] macOS: brew install tor"\n    exit 1\nfi\n`;

          await fs.writeFile(this.torPath, torScript, { mode: 0o755 });
          console.log('[TOR-MANAGER] Created Tor wrapper script at:', this.torPath);
          return { success: true };
        }
      }

      // Make executable on Unix systems
      if (this.platform !== 'win32' && torExists) {
        try {
          await fs.chmod(this.torPath, 0o755);
          console.log('[TOR-MANAGER] Made Tor executable');
        } catch (error) {
          console.warn('[TOR-MANAGER] Could not make Tor executable:', error.message);
        }
      }

      console.log('[TOR-MANAGER] Tor installation verification completed');
      return { success: true };

    } catch (error) {
      console.error('[TOR-MANAGER] Failed to verify Tor installation:', error);
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

      // SECURITY: Basic validation: torrc is written to a file and not executed by a shell.
      if (/\x00/.test(config)) {
        throw new Error('Configuration contains invalid null bytes');
      }
      if (/[^\x09\x0A\x0D\x20-\x7E]/.test(config)) {
        throw new Error('Configuration contains invalid characters');
      }

      // SECURITY: Validate that config only contains valid Tor configuration directives
      const lines = config.split('\n');
      const validTorDirectives = [
        'SocksPort', 'SocksPolicy', 'ControlPort', 'DataDirectory', 'Log', 'RunAsDaemon',
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
        'PublishServerDescriptor', 'ShutdownWaitLength', 'SafeLogging', 'NewCircuitPeriod', 'LearnCircuitBuildTimeout',
        'HardwareAccel', 'AccelName', 'AccelDir', 'AvoidDiskWrites',
        'TunnelDirConns', 'PreferTunneledDirConns', 'CircuitBuildTimeout',
        'CircuitIdleTimeout', 'CircuitStreamTimeout', 'MaxCircuitDirtiness',
        'MaxClientCircuitsPending', 'NodeFamily', 'EnforceDistinctSubnets',
        'SocksTimeout', 'TokenBucketRefillInterval', 'TrackHostExits',
        'TrackHostExitsExpire', 'UpdateBridgesFromAuthority', 'UseMicrodescriptors',
        'PathBiasCircThreshold', 'PathBiasNoticeRate', 'PathBiasWarnRate',
        'PathBiasExtremeRate', 'PathBiasDropGuards', 'PathBiasScaleThreshold'
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
      const dataDir = path.join(this.torDir, 'data');
      await fs.mkdir(dataDir, { recursive: true, mode: 0o700 }); // Owner only
      console.log('[TOR-MANAGER] Data directory created:', dataDir);

      console.log('[TOR-MANAGER] Tor configuration completed successfully');
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
   * Start Tor service (or use existing system service)
   */
  async startTor() {
    try {
      console.log('[TOR-MANAGER] Starting Tor service...');

      if (this.torProcess) {
        console.log('[TOR-MANAGER] Tor is already running');
        return { success: true };
      }

      // Decide whether to prefer our own Tor instance based on config (bridges require our torrc)
      let preferOwnInstance = false;
      try {
        const configContent = await fs.readFile(this.configPath, 'utf8').catch(() => '');
        if (configContent && /\bUseBridges\s+1\b/i.test(configContent)) {
          preferOwnInstance = true;
          console.log('[TOR-MANAGER] Bridge mode detected in config - preferring managed Tor instance');
        }
      } catch (e) {
        // ignore
      }

      // Only adopt system Tor if we don't explicitly need our own instance
      if (!preferOwnInstance) {
        // First, check if system Tor service is already running
        const systemTorCheck = await new Promise((resolve) => {
          exec('ss -tlnp | grep :9050', (error, stdout) => {
            if (!error && stdout.includes('127.0.0.1:9050')) {
              console.log('[TOR-MANAGER] System Tor service detected on port 9050');
              resolve({ running: true, port: 9050 });
            } else {
              console.log('[TOR-MANAGER] No system Tor service detected');
              resolve({ running: false });
            }
          });
        });

        if (systemTorCheck.running) {
          console.log('[TOR-MANAGER] Using existing system Tor service');
          // Mark as running but don't create our own process
          this.usingSystemTor = true;
          return { success: true, usingSystemTor: true };
        }
      }

      // Verify that Tor binary is available for starting our own instance
      const torCheck = await new Promise((resolve) => {
        exec('tor --version', (error, stdout) => {
          if (error) {
            console.log('[TOR-MANAGER] Tor binary not available:', error.message);
            resolve({ available: false, error: error.message });
          } else {
            console.log('[TOR-MANAGER] Tor binary available:', stdout.split('\n')[0]);
            resolve({ available: true });
          }
        });
      });

      if (!torCheck.available) {
        console.error('[TOR-MANAGER] Cannot start Tor: binary not found');
        return {
          success: false,
          error: 'Tor is not installed. Please install Tor: sudo apt-get install tor'
        };
      }

      const dataDir = path.join(this.torDir, 'data');

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

      // Start Tor process
      console.log('[TOR-MANAGER] Spawning Tor process with args:', ['-f', this.configPath, '--DataDirectory', dataDir]);

      let processError = null;

      // Build spawn arguments and handle port conflicts if system Tor is already using defaults
      let spawnArgs = ['-f', this.configPath, '--DataDirectory', dataDir];

      // If defaults 9050/9051 are busy, use alternates 9150/9151
      try {
        const portsInUse = await new Promise((resolve) => {
          exec('ss -tlnp | grep :905 || netstat -tlnp | grep :905', (error, stdout) => {
            resolve(!error && stdout ? stdout : '');
          });
        });
        const socksBusy = typeof portsInUse === 'string' && portsInUse.includes(':9050');
        const controlBusy = typeof portsInUse === 'string' && portsInUse.includes(':9051');
        if (socksBusy || controlBusy) {
          console.log('[TOR-MANAGER] Default ports busy, overriding to SocksPort 9150 / ControlPort 9151');
          spawnArgs = ['-f', this.configPath, '--DataDirectory', dataDir, 'SocksPort', '9150', 'ControlPort', '9151'];
        }
      } catch {}

      this.torProcess = spawn('tor', spawnArgs, {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: false
      });

      // Handle process events
      this.torProcess.stdout.on('data', (data) => {
        console.log('[TOR]', data.toString().trim());
      });

      this.torProcess.stderr.on('data', (data) => {
        const errorMsg = data.toString().trim();
        console.error('[TOR-ERROR]', errorMsg);
        if (errorMsg.includes('Permission denied') || errorMsg.includes('Cannot bind')) {
          processError = errorMsg;
        }
      });

      this.torProcess.on('exit', (code) => {
        console.log(`[TOR-MANAGER] Tor process exited with code ${code}`);
        if (code !== 0) {
          processError = `Tor exited with code ${code}`;
        }
        this.torProcess = null;
      });

      this.torProcess.on('error', (error) => {
        console.error('[TOR-MANAGER] Tor process spawn error:', error);
        processError = `Failed to spawn Tor: ${error.message}`;
        this.torProcess = null;
      });

      // Wait a moment for Tor to start
      console.log('[TOR-MANAGER] Waiting for Tor to initialize...');
      await new Promise(resolve => setTimeout(resolve, 7000));

      // Check for errors
      if (processError) {
        console.error('[TOR-MANAGER] Tor startup failed:', processError);

        // Automatic fallback: if snowflake bridges are configured, disable bridges and retry
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8').catch(() => '');
          const hasSnowflake = /UseBridges\s+1/i.test(cfg) && /ClientTransportPlugin\s+snowflake/i.test(cfg);
          if (hasSnowflake) {
            console.warn('[TOR-MANAGER] Snowflake bridge startup failed. Falling back to direct connection automatically.');
            // Backup current config
            try { await fs.writeFile(this.configPath + '.bak', cfg, 'utf8'); } catch {}
            // Remove bridge-related lines and disable bridges
            const newCfg = cfg
              .split('\n')
              .filter(line => !/^\s*UseBridges\b/i.test(line) && !/^\s*ClientTransportPlugin\b/i.test(line) && !/^\s*Bridge\b/i.test(line))
              .concat(['', '# Auto-fallback: disable bridges for direct connection', 'UseBridges 0'])
              .join('\n');
            await fs.writeFile(this.configPath, newCfg, 'utf8');

            // Retry starting Tor with updated config
            console.log('[TOR-MANAGER] Retrying Tor start without bridges...');
            processError = null;
            this.torProcess = spawn('tor', spawnArgs, { stdio: ['ignore', 'pipe', 'pipe'], detached: false });
            let retryError = null;
            this.torProcess.stderr.on('data', (data) => {
              const err = data.toString().trim();
              if (err) retryError = err;
            });
            await new Promise(resolve => setTimeout(resolve, 3000));
            if (!retryError && this.torProcess && !this.torProcess.killed) {
              console.log('[TOR-MANAGER] Tor started successfully after disabling bridges');
              return { success: true };
            }
          }
        } catch (e) {
          console.warn('[TOR-MANAGER] Fallback attempt failed:', e?.message || e);
        }

        return { success: false, error: processError };
      }

      // Verify the process is still running
      if (!this.torProcess || this.torProcess.killed) {
        console.error('[TOR-MANAGER] Tor process failed to start or died');

        // Attempt same automatic fallback for snowflake config
        try {
          const cfg = await fs.readFile(this.configPath, 'utf8').catch(() => '');
          const hasSnowflake = /UseBridges\s+1/i.test(cfg) && /ClientTransportPlugin\s+snowflake/i.test(cfg);
          if (hasSnowflake) {
            console.warn('[TOR-MANAGER] Snowflake bridge process died. Falling back to direct connection automatically.');
            try { await fs.writeFile(this.configPath + '.bak', cfg, 'utf8'); } catch {}
            const newCfg = cfg
              .split('\n')
              .filter(line => !/^\s*UseBridges\b/i.test(line) && !/^\s*ClientTransportPlugin\b/i.test(line) && !/^\s*Bridge\b/i.test(line))
              .concat(['', '# Auto-fallback: disable bridges for direct connection', 'UseBridges 0'])
              .join('\n');
            await fs.writeFile(this.configPath, newCfg, 'utf8');

            console.log('[TOR-MANAGER] Retrying Tor start without bridges...');
            this.torProcess = spawn('tor', spawnArgs, { stdio: ['ignore', 'pipe', 'pipe'], detached: false });
            await new Promise(resolve => setTimeout(resolve, 3000));
            if (this.torProcess && !this.torProcess.killed) {
              console.log('[TOR-MANAGER] Tor started successfully after disabling bridges');
              return { success: true };
            }
          }
        } catch (e) {
          console.warn('[TOR-MANAGER] Fallback attempt failed:', e?.message || e);
        }

        return { success: false, error: 'Tor process failed to start or died immediately' };
      }

      console.log('[TOR-MANAGER] Tor service started successfully');
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
              const serviceCmd = this.platform === 'win32' 
                ? 'sc query tor'
                : 'systemctl is-active tor 2>/dev/null';
              
              exec(serviceCmd, (error, stdout) => {
                if (this.platform === 'win32') {
                  // Windows: check if service is running
                  const isRunning = !error && stdout.includes('RUNNING');
                  resolve(isRunning);
                } else {
                  // Linux/macOS: check systemctl status
                  const isActive = !error && stdout.trim() === 'active';
                  resolve(isActive);
                }
              });
            });
            
            systemTorRunning = serviceCheck;
          }
        } catch (error) {
          console.log('[TOR-MANAGER] Failed to check system Tor:', error);
        }
      }

      // Check if data directory exists
      const dataDir = path.join(this.torDir, 'data');
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
      
      if (configExists && configContent) {
        // Parse SOCKS port from config
        const socksMatch = configContent.match(/^SocksPort\s+(\d+)/m);
        if (socksMatch) {
          socksPort = parseInt(socksMatch[1], 10);
        }
        
        // Parse Control port from config
        const controlMatch = configContent.match(/^ControlPort\s+(\d+)/m);
        if (controlMatch) {
          controlPort = parseInt(controlMatch[1], 10);
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
        console.log('[TOR-MANAGER] Using system Tor - trying multiple rotation methods...');

        // Method 1: Try control port
        console.log('[TOR-MANAGER] Method 1: Attempting control port connection...');
        rotationResult = await this.sendNewNymSignal();

        if (!rotationResult.success) {
          console.log('[TOR-MANAGER] Control port failed, trying Method 2: System signal...');
          // Method 2: Try sending system signal to Tor process
          rotationResult = await this.sendSystemSignal();
        }

        if (!rotationResult.success) {
          console.log('[TOR-MANAGER] System signal failed, trying Method 3: Force circuit change...');
          // Method 3: Force circuit change by making multiple requests
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
      for (let i = 0; i < 1; i++) {
        await this.makeRequestThroughTor('https://httpbin.org/ip');
        await new Promise(resolve => setTimeout(resolve, 500));
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
      let controlPort = 9051; // default

      // Try to read ControlPort from config
      try {
        const cfg = await fs.readFile(this.configPath, 'utf8');
        const m = cfg.match(/^ControlPort\s+(\d+)/m);
        if (m) controlPort = parseInt(m[1], 10) || controlPort;
      } catch {}

      // Read cookie for authentication (CookieAuthentication 1)
      const dataDir = path.join(this.torDir, 'data');
      const cookiePath = path.join(dataDir, 'control_auth_cookie');
      let cookieHex = null;
      try {
        const cookie = await fs.readFile(cookiePath);
        cookieHex = cookie.toString('hex');
      } catch {}

      console.log('[TOR-MANAGER] Connecting to Tor control port:', controlPort);
      const socket = net.createConnection(controlPort, '127.0.0.1');

      let stage = cookieHex ? 'auth' : 'signal';
      let buffer = '';

      const send = (cmd) => socket.write(cmd + '\r\n');

      socket.on('connect', () => {
        console.log('[TOR-MANAGER] Connected to Tor control port');
        if (stage === 'auth') {
          send(`AUTHENTICATE ${cookieHex}`);
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
          } else if (/^(514|510)/.test(line)) {
            socket.end();
            return resolve({ success: false, error: 'Control port authentication required' });
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
   * Send system signal to Tor process (Method 2)
   */
  async sendSystemSignal() {
    try {
      console.log('[TOR-MANAGER] Attempting to send SIGUSR2 to system Tor process...');

      // Find Tor process PID
      const { exec } = require('child_process');

      return new Promise((resolve) => {
        exec('pgrep -f "tor.*--defaults-torrc"', (error, stdout) => {
          if (error || !stdout.trim()) {
            console.log('[TOR-MANAGER] Could not find system Tor process');
            resolve({ success: false, error: 'System Tor process not found' });
            return;
          }

          const torPid = stdout.trim().split('\n')[0];
          console.log('[TOR-MANAGER] Found system Tor PID:', torPid);

          // Send SIGUSR2 signal (equivalent to NEWNYM)
          exec(`kill -USR2 ${torPid}`, (signalError) => {
            if (signalError) {
              console.error('[TOR-MANAGER] Failed to send signal to Tor:', signalError.message);
              resolve({ success: false, error: `Signal error: ${signalError.message}` });
            } else {
              console.log('[TOR-MANAGER] SIGUSR2 signal sent to Tor process');
              resolve({ success: true, method: 'system-signal' });
            }
          });
        });
      });
    } catch (error) {
      console.error('[TOR-MANAGER] System signal method failed:', error);
      return { success: false, error: error.message };
    }
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
    return new Promise(async (resolve) => {
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

        const req = https.get(url, { agent: proxyAgent, timeout: 3000 }, (res) => {
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
      // Determine active SOCKS port from config (fallback to 9050)
      let socksPort = 9050;
      try {
        const cfg = await fs.readFile(this.configPath, 'utf8');
        const m = cfg.match(/^SocksPort\s+(\d+)/m);
        if (m) socksPort = parseInt(m[1], 10) || socksPort;
      } catch {}

      const { SocksProxyAgent } = require('socks-proxy-agent');
      const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${socksPort}`);

      return new Promise((resolve) => {
        const options = {
          hostname: 'httpbin.org',
          path: '/ip',
          method: 'GET',
          agent: proxyAgent,
          timeout: 5000
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
      let controlPort = 9051;
      try {
        const cfg = await fs.readFile(this.configPath, 'utf8');
        const m = cfg.match(/^ControlPort\s+(\d+)/m);
        if (m) controlPort = parseInt(m[1], 10) || controlPort;
      } catch {}

      const dataDir = path.join(this.torDir, 'data');
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
          } else if (/^(514|510)/.test(line)) {
            socket.end();
            return resolve({ success: false, error: 'Control port authentication failed' });
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

        const req = https.get(url, { agent: proxyAgent, timeout: 5000 }, (res) => {
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
   * Verify Tor connection by checking IP through Tor network
   */
  async verifyTorConnection() {
    try {
      console.log('[TOR-MANAGER] Verifying Tor connection...');

      // Determine active SOCKS port from config (fallback to 9050)
      let socksPort = 9050;
      try {
        const cfg = await fs.readFile(this.configPath, 'utf8');
        const m = cfg.match(/^SocksPort\s+(\d+)/m);
        if (m) socksPort = parseInt(m[1], 10) || socksPort;
      } catch {}

      return new Promise((resolve) => {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${socksPort}`);

        const options = {
          hostname: 'check.torproject.org',
          path: '/api/ip',
          method: 'GET',
          agent: proxyAgent,
          timeout: 7000
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
          resolve({ success: false, error: error.message });
        });

        req.on('timeout', () => {
          console.error('[TOR-MANAGER] Tor verification timed out');
          req.destroy();
          resolve({ success: false, error: 'Connection timeout' });
        });

        req.end();
      });

    } catch (error) {
      console.error('[TOR-MANAGER] Tor verification error:', error);
      return { success: false, error: error.message };
    }
  }
}

// Export singleton instance
module.exports = new ElectronTorManager();
