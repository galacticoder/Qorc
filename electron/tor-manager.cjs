const { spawn, execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);
const fs = require('fs').promises;
const { constants } = require('fs');
const crypto = require('crypto');
const net = require('net');
const path = require('path');
const os = require('os');
const https = require('https');

const DEFAULT_SOCKS_PORT = 9050;
const DEFAULT_CONTROL_PORT = 9051;
const TOR_VERSION = '15.0a4';
const TOR_BASE_URL = `https://dist.torproject.org/torbrowser/${TOR_VERSION}`;
const PORT_SCAN_RANGE = 100;
const MAX_CONFIG_SIZE = 50000;
const BOOTSTRAP_TIMEOUT = 120000;
const DOWNLOAD_TIMEOUT = 300000;
const HEALTH_CHECK_INTERVAL = 30000;
const CONTROL_PASSWORD_FILE = '.control_password';

const ALLOWED_DIRECTIVES = new Set([
  'AvoidDiskWrites', 'Bridge', 'CircuitBuildTimeout', 'ClientOnly', 'ClientTransportPlugin',
  'ControlPort', 'CookieAuthentication', 'DataDirectory', 'DisableDebuggerAttachment',
  'DisableNetwork', 'EnforceDistinctSubnets', 'EntryNodes', 'ExitNodes', 'ExitPolicy',
  'ExcludeExitNodes', 'ExcludeNodes', 'FetchDirInfoEarly', 'FetchDirInfoExtraEarly',
  'FetchUselessDescriptors', 'GeoIPFile', 'GeoIPv6File', 'HashedControlPassword',
  'LearnCircuitBuildTimeout', 'Log', 'MaxCircuitDirtiness', 'NewCircuitPeriod',
  'NumEntryGuards', 'ProtocolWarnings', 'SafeLogging', 'SocksAuth', 'SocksListenAddress',
  'SocksPolicy', 'SocksPort', 'StrictNodes', 'TrackHostExits', 'TrackHostExitsExpire',
  'UpdateBridgesFromAuthority', 'UseBridges', 'UseEntryGuards', 'UseMicrodescriptors'
]);

class ElectronTorManager {
  constructor({ appInstance } = {}) {
    if (!appInstance?.getPath || appInstance.isPackaged === undefined) {
      throw new Error('TorManager requires valid Electron app instance');
    }
    this.app = appInstance;
    this.torProcess = null;
    this.platform = os.platform();
    this.arch = os.arch();
    this.effectiveSocksPort = DEFAULT_SOCKS_PORT;
    this.effectiveControlPort = DEFAULT_CONTROL_PORT;
    this.bootstrapped = false;
    this.controlPassword = null;
    this.healthInterval = null;
    this._bootstrapTimeout = null;

    this.setupPaths();
    this.app.on('before-quit', () => this.cleanupOnExit());
    process.on('SIGINT', () => this.cleanupOnExit());
    process.on('SIGTERM', () => this.cleanupOnExit());
  }

  setupPaths() {
    const appDataPath = this.app.getPath('userData');
    const resourcesPath = process.resourcesPath;

    this.torDir = path.join(appDataPath, 'tor');
    this.configPath = path.join(this.torDir, 'torrc');

    const ext = this.platform === 'win32' ? '.exe' : '';
    const platformDir = this.platform === 'darwin' ? 'macos' : this.platform === 'win32' ? 'windows' : 'linux';
    const bundledPath = path.join(resourcesPath, 'tor-bundles', platformDir, `tor${ext}`);

    this.torPath = require('fs').existsSync(bundledPath)
      ? bundledPath
      : path.join(this.torDir, `tor${ext}`);
  }

  async cleanupOnExit() {
    if (this._bootstrapTimeout) clearTimeout(this._bootstrapTimeout);
    if (this.healthInterval) clearInterval(this.healthInterval);
    if (this.torProcess && !this.torProcess.killed) await this.stopTor();
  }

  isValidPort(port) {
    return Number.isInteger(port) && port >= 1 && port <= 65535;
  }

  async isPortAvailable(port) {
    if (!this.isValidPort(port)) return false;
    return new Promise((resolve) => {
      const tester = net.createServer()
        .once('error', () => { tester.close(); resolve(false); })
        .once('listening', () => { tester.close(() => resolve(true)); })
        .listen(port, '127.0.0.1');
    });
  }

  async findAvailablePort(startPort) {
    let base = this.isValidPort(startPort) ? startPort : DEFAULT_SOCKS_PORT;
    for (let offset = 0; offset < PORT_SCAN_RANGE; offset++) {
      const candidate = base + offset;
      if (this.isValidPort(candidate) && await this.isPortAvailable(candidate)) {
        return candidate;
      }
    }
    return base;
  }

  getDataDir() {
    return path.join(this.torDir, `data-${os.userInfo().username}-${process.pid}`);
  }

  async parsePortsFromConfig(configPath) {
    try {
      const cfg = await fs.readFile(configPath, 'utf8').catch(() => '');
      const socksMatch = cfg.match(/^SocksPort\s+(\d+)/m);
      const controlMatch = cfg.match(/^ControlPort\s+(\d+)/m);
      return {
        socks: socksMatch ? parseInt(socksMatch[1], 10) : DEFAULT_SOCKS_PORT,
        control: controlMatch ? parseInt(controlMatch[1], 10) : DEFAULT_CONTROL_PORT,
      };
    } catch {
      return { socks: DEFAULT_SOCKS_PORT, control: DEFAULT_CONTROL_PORT };
    }
  }

  validateTorConfig(config) {
    if (typeof config !== 'string' || !config.trim()) {
      throw new Error('Invalid Tor configuration');
    }
    if (Buffer.byteLength(config, 'utf8') > MAX_CONFIG_SIZE) {
      throw new Error('Configuration exceeds maximum size');
    }
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(config)) {
      throw new Error('Configuration contains forbidden characters');
    }

    const lines = config.split(/\r?\n/);
    const normalized = [];
    let dataDirFound = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) {
        normalized.push(line);
        continue;
      }
      if (trimmed.length > 1024) throw new Error('Configuration line too long');

      const match = trimmed.match(/^([A-Za-z][A-Za-z0-9_]*)\b(.*)$/);
      if (!match) throw new Error('Invalid configuration syntax');

      const [, directive, value] = match;
      if (!ALLOWED_DIRECTIVES.has(directive)) {
        throw new Error(`Forbidden directive: ${directive}`);
      }

      if (directive === 'DataDirectory') {
        const resolved = path.isAbsolute(value.trim()) ? value.trim() : path.join(this.torDir, value.trim() || 'data');
        const normalized_path = path.normalize(resolved);
        if (!normalized_path.startsWith(path.normalize(this.torDir))) {
          throw new Error('DataDirectory outside allowed path');
        }
        this.configuredDataDirectory = normalized_path;
        normalized.push(`${directive} ${normalized_path}`);
        dataDirFound = true;
      } else {
        normalized.push(`${directive}${value ? ` ${value.trim()}` : ''}`);
      }
    }

    if (!dataDirFound) {
      this.configuredDataDirectory = path.join(this.torDir, 'data');
      normalized.push(`DataDirectory ${this.configuredDataDirectory}`);
    }

    return normalized.join('\n');
  }

  getTorEnvironment() {
    const env = { ...process.env };
    const libDirs = [
      path.join(this.torDir, 'lib64'),
      path.join(this.torDir, 'lib'),
      this.torDir
    ].filter(d => require('fs').existsSync(d));

    if (libDirs.length > 0) {
      const libPath = libDirs.join(path.delimiter);
      env.LD_LIBRARY_PATH = libPath;
      if (this.platform === 'darwin') env.DYLD_LIBRARY_PATH = libPath;
    }
    // Ensure pluggable transport binaries (snowflake-client, obfs4proxy, etc.) are discoverable
    env.PATH = `${this.torDir}${path.delimiter}${path.join(this.torDir, 'pluggable_transports')}${path.delimiter}${env.PATH || ''}`;
    return env;
  }

  async checkTorInstallation() {
    try {
      const stats = await fs.stat(this.torPath).catch(() => null);
      if (!stats || !stats.isFile()) {
        return { isInstalled: false };
      }

      await fs.access(this.torPath, constants.F_OK | constants.X_OK);
      const version = await this.getTorVersion();
      return { isInstalled: true, version, path: this.torPath };
    } catch (error) {
      return { isInstalled: false };
    }
  }

  getTorDownloadUrl() {
    const archMap = {
      linux: { x64: 'linux-x86_64', arm64: 'linux-aarch64' },
      darwin: { x64: 'macos-x86_64', arm64: 'macos-aarch64' },
      win32: { x64: 'windows-x86_64', ia32: 'windows-i686' }
    };
    const arch = archMap[this.platform]?.[this.arch];
    if (!arch) throw new Error(`Unsupported platform: ${this.platform}/${this.arch}`);
    return `${TOR_BASE_URL}/tor-expert-bundle-${arch}-${TOR_VERSION}.tar.gz`;
  }

  async getTorVersion() {
    try {
      const { stdout } = await execFileAsync(this.torPath, ['--version'], {
        env: this.getTorEnvironment(),
        cwd: this.torDir,
        timeout: 5000
      });
      return stdout.split('\n')[0].match(/Tor (?:version )?(\d+\.\d+\.\d+)/i)?.[1] || 'unknown';
    } catch {
      throw new Error('Failed to get Tor version');
    }
  }

  async downloadTor() {
    await fs.mkdir(this.torDir, { recursive: true });

    try {
      if ((await fs.stat(this.torPath)).isFile()) {
        return { success: true, alreadyExists: true };
      }
    } catch { }

    const downloadUrl = this.getTorDownloadUrl();
    const archiveFilename = path.basename(new URL(downloadUrl).pathname);
    const archivePath = path.join(this.torDir, archiveFilename);
    const signaturePath = `${archivePath}.asc`;
    const checksumPath = path.join(this.torDir, 'sha256sums.txt');

    // Download archive and per-file .asc signature
    await this.downloadFile(downloadUrl, archivePath);
    await this.downloadFile(`${downloadUrl}.asc`, signaturePath);

    // Download checksums file (try unsigned first, then signed)
    const unsignedChecksums = `${TOR_BASE_URL}/sha256sums-unsigned-build.txt`;
    const signedChecksums = `${TOR_BASE_URL}/sha256sums-signed-build.txt`;
    try {
      await this.downloadFile(unsignedChecksums, checksumPath);
    } catch (_) {
      await this.downloadFile(signedChecksums, checksumPath);
    }

    await this.verifySha256(archivePath, checksumPath);
    await this.extractTorBundle(archivePath);

    await fs.unlink(archivePath).catch(() => { });
    await fs.unlink(signaturePath).catch(() => { });
    await fs.unlink(checksumPath).catch(() => { });

    if (this.platform !== 'win32') {
      await fs.chmod(this.torPath, 0o755);
    }

    return { success: true };
  }

  downloadFile(url, filePath) {
    return new Promise((resolve, reject) => {
      const file = require('fs').createWriteStream(filePath);
      const request = https.get(url, { timeout: DOWNLOAD_TIMEOUT }, (response) => {
        if (response.statusCode === 301 || response.statusCode === 302) {
          const location = response.headers.location;
          if (location) {
            const redirectUrl = location.startsWith('http') ? location : new URL(location, url).toString();
            return resolve(this.downloadFile(redirectUrl, filePath));
          }
        }
        if (response.statusCode !== 200) {
          reject(new Error(`HTTP ${response.statusCode}`));
          return;
        }
        response.pipe(file);
        file.on('finish', () => { file.close(); resolve(); });
        file.on('error', (err) => { require('fs').unlink(filePath).catch(() => { }); reject(err); });
      });
      request.on('error', reject);
      request.on('timeout', () => { request.abort(); reject(new Error('Download timeout')); });
    });
  }

  async verifySha256(archivePath, checksumPath) {
    const checksumContent = await fs.readFile(checksumPath, 'utf8');
    const filename = path.basename(archivePath);

    // Try GNU coreutils sha256sum format: "<hash>  <filename>"
    const escaped = filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let match = checksumContent.match(new RegExp(`^([a-fA-F0-9]{64})\\s+\\*?${escaped}$`, 'm'));

    // Try BSD shasum format: "SHA256 (<filename>) = <hash>"
    if (!match) {
      const alt = new RegExp(`^SHA256 \\(${escaped}\\) = ([a-fA-F0-9]{64})$`, 'm');
      const m2 = checksumContent.match(alt);
      if (m2) match = m2;
    }

    if (!match) {
      throw new Error('Checksum for archive not found in checksum list');
    }

    const expected = match[1].toLowerCase();
    const fileBuffer = await fs.readFile(archivePath);
    const actual = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    if (actual !== expected) {
      throw new Error('SHA256 checksum mismatch');
    }
  }

  async extractTorBundle(archivePath) {
    const { extract } = await import('tar');

    await extract({
      file: archivePath,
      cwd: this.torDir,
      strip: 1,
      filter: (path) => {
        const allowed = ['tor', 'tor.exe', 'lib', 'lib64', 'obfs4proxy', 'obfs4proxy.exe',
          'snowflake-client', 'snowflake-client.exe', 'conjure-client', 'conjure-client.exe',
          'lyrebird', 'lyrebird.exe', 'geoip', 'geoip6', 'libevent', 'libssl', 'libcrypto',
          'libgcc', 'libstdc', 'libz', 'pluggable_transports'];
        return allowed.some(p => path.includes(p));
      }
    });

    if (this.platform !== 'win32') {
      const binaries = ['tor', 'obfs4proxy', 'snowflake-client', 'conjure-client', 'lyrebird'];
      for (const bin of binaries) {
        // Check root dir
        let binPath = path.join(this.torDir, bin);
        await fs.chmod(binPath, 0o755).catch(() => { });

        // Check pluggable_transports dir
        binPath = path.join(this.torDir, 'pluggable_transports', bin);
        await fs.chmod(binPath, 0o755).catch(() => { });
      }
    }
  }

  async installTor() {
    await fs.mkdir(this.torDir, { recursive: true });
    const stats = await fs.stat(this.torPath);
    if (!stats.isFile()) {
      return { success: false, error: 'Tor binary not found' };
    }
    if (this.platform !== 'win32') {
      await fs.chmod(this.torPath, 0o755);
    }
    return { success: true };
  }

  async configureTor({ config }) {
    const normalizedConfig = this.validateTorConfig(config);
    let cfg = normalizedConfig;

    const existing = await this.loadControlPassword();
    this.controlPassword = existing || crypto.randomBytes(32).toString('hex');

    let hashed;
    try {
      const { stdout } = await execFileAsync(this.torPath, ['--hash-password', this.controlPassword], {
        env: this.getTorEnvironment(),
        cwd: this.torDir,
        timeout: 10000
      });
      hashed = stdout.trim().split('\n').pop();
    } catch (e) {
      throw e;
    }

    if (!/CookieAuthentication/i.test(cfg)) {
      cfg += `\nCookieAuthentication 0\n`;
    }
    cfg += `\nHashedControlPassword ${hashed}\n`;

    await fs.mkdir(this.torDir, { recursive: true });
    await fs.writeFile(this.configPath, cfg, { encoding: 'utf8', mode: 0o600 });

    const dataDir = this.configuredDataDirectory || this.getDataDir();
    await fs.mkdir(dataDir, { recursive: true, mode: 0o700 });

    const ports = await this.parsePortsFromConfig(this.configPath);
    this.configuredSocksPort = ports.socks;
    this.configuredControlPort = ports.control;

    setImmediate(async () => {
      try {
        await this.persistControlPassword(this.controlPassword);
      } catch (e) {
      }
    });

    return { success: true };
  }

  async persistControlPassword(password) {
    try {
      const key = await this.getCredentialEncryptionKey();
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

      let encrypted = cipher.update(password, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag();

      const result = Buffer.concat([iv, authTag, Buffer.from(encrypted, 'hex')]);
      const filePath = path.join(this.torDir, CONTROL_PASSWORD_FILE);
      await fs.writeFile(filePath, result, { mode: 0o600 });
    } catch (error) {
      throw new Error('Failed to persist control password');
    }
  }

  async loadControlPassword() {
    try {
      const filePath = path.join(this.torDir, CONTROL_PASSWORD_FILE);
      const data = await fs.readFile(filePath);
      const key = await this.getCredentialEncryptionKey();
      const iv = data.slice(0, 16);
      const authTag = data.slice(16, 32);
      const encrypted = data.slice(32);

      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encrypted, null, 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (e) {
      return null;
    }
  }

  async getCredentialEncryptionKey() {
    const keyPath = path.join(this.torDir, '.cred_key');
    try {
      return await fs.readFile(keyPath);
    } catch (error) {
      if (error.code === 'ENOENT') {
        const machineId = crypto.createHash('sha256')
          .update(os.homedir())
          .update(os.hostname())
          .update(os.platform())
          .digest();
        await fs.mkdir(this.torDir, { recursive: true, mode: 0o700 });
        await fs.writeFile(keyPath, machineId, { mode: 0o600 });
        return machineId;
      }
      throw error;
    }
  }

  async persistSocksCredentials(credentials) {
    const key = await this.getCredentialEncryptionKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(JSON.stringify(credentials), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    const result = Buffer.concat([iv, authTag, Buffer.from(encrypted, 'hex')]);
    await fs.writeFile(path.join(this.torDir, '.socks_credentials'), result, { mode: 0o600 });
  }

  async loadSocksCredentials() {
    try {
      const data = await fs.readFile(path.join(this.torDir, '.socks_credentials'));
      const key = await this.getCredentialEncryptionKey();
      const iv = data.slice(0, 16);
      const authTag = data.slice(16, 32);
      const encrypted = data.slice(32);

      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encrypted, null, 'utf8');
      decrypted += decipher.final('utf8');

      return JSON.parse(decrypted);
    } catch {
      return null;
    }
  }

  async startTor() {
    if (this.torProcess && !this.torProcess.killed) {
      return { success: true };
    }

    await fs.access(this.torPath, constants.F_OK | constants.X_OK);

    const dataDir = this.configuredDataDirectory || this.getDataDir();
    await fs.mkdir(dataDir, { recursive: true, mode: 0o700 });

    const lockFile = path.join(dataDir, 'lock');
    await fs.unlink(lockFile).catch(() => { });

    if (!this.controlPassword) {
      this.controlPassword = await this.loadControlPassword();
    }

    const availableSocksPort = await this.findAvailablePort(9150);
    const availableControlPort = await this.findAvailablePort(availableSocksPort + 1);

    this.effectiveSocksPort = availableSocksPort;
    this.effectiveControlPort = availableControlPort;

    const args = [
      '-f', this.configPath,
      '--DataDirectory', dataDir,
      'SocksPort', `${availableSocksPort} IsolateClientAddr IsolateSOCKSAuth IsolateClientProtocol IsolateDestAddr`,
      'ControlPort', availableControlPort.toString()
    ];

    this.torProcess = spawn(this.torPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
      env: this.getTorEnvironment(),
      cwd: this.torDir
    });

    let processError = null;

    this.torProcess.stdout.on('data', (data) => {
      const line = data.toString().trim();
      if (line) {
        const m = line.match(/Bootstrapped\s+(\d+)%/i);
        if (m) {
          const pct = parseInt(m[1], 10);
          if (Number.isFinite(pct) && pct >= 100) this.bootstrapped = true;
        }
      }
    });

    this.torProcess.stderr.on('data', (data) => {
      const line = data.toString().trim();
      if (line) {
        if (/\[err\]/i.test(line)) {
          processError = line;
        }

        const m = line.match(/Bootstrapped\s+(\d+)%/i);
        if (m) {
          const pct = parseInt(m[1], 10);
          if (Number.isFinite(pct) && pct >= 100) this.bootstrapped = true;
        }
      }
    });

    this.torProcess.on('exit', (code) => {
      if (code !== 0 && !processError) {
        processError = `Tor exited with code ${code}`;
      }
      this.torProcess = null;
    });

    this.torProcess.on('error', (error) => {
      processError = error.message;
      this.torProcess = null;
    });

    this._bootstrapTimeout = setTimeout(() => {
      if (!this.bootstrapped && this.torProcess) {
        processError = 'Bootstrap timeout';
      }
    }, BOOTSTRAP_TIMEOUT);

    if (processError) {
      return { success: false, error: processError };
    }

    if (!this.torProcess || this.torProcess.killed) {
      return { success: false, error: 'Tor process failed to start' };
    }

    (async () => {
      const bootstrapped = await this.waitUntilBootstrapped(BOOTSTRAP_TIMEOUT);
      if (bootstrapped) {
        this.startHealthMonitor();
      }
    })().catch(() => { });

    return { success: true, starting: true };
  }

  async waitUntilBootstrapped(timeoutMs = 30000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (this.bootstrapped) {
        return true;
      }

      await new Promise((res) => setImmediate(res));
      await new Promise((res) => setTimeout(res, 100));
    }
    return false;
  }

  startHealthMonitor() {
    if (this.healthInterval) clearInterval(this.healthInterval);
    this.healthInterval = setInterval(async () => {
      if (!this.isTorRunning()) return;
      const result = await this.verifyTorConnection();
      if (!result.success) {
        await this.restartTor();
      }
    }, HEALTH_CHECK_INTERVAL);
  }

  async restartTor() {
    await this.stopTor();
    await this.startTor();
  }

  async stopTor() {
    if (this.torProcess) {
      const proc = this.torProcess;

      // Clear health monitor
      if (this.healthInterval) {
        clearInterval(this.healthInterval);
        this.healthInterval = null;
      }

      // Clear bootstrap timeout
      if (this._bootstrapTimeout) {
        clearTimeout(this._bootstrapTimeout);
        this._bootstrapTimeout = null;
      }

      return new Promise((resolve) => {
        const exitHandler = () => {
          this.torProcess = null;
          this.bootstrapped = false;
          resolve({ success: true });
        };

        proc.once('exit', exitHandler);

        // Force kill after 5 seconds if SIGTERM doesn't work
        const killTimeout = setTimeout(() => {
          if (proc && !proc.killed) {
            proc.kill('SIGKILL');
          }
        }, 5000);

        // Clear the timeout if process exits normally
        proc.once('exit', () => clearTimeout(killTimeout));

        // Send SIGTERM
        proc.kill('SIGTERM');
      });
    }
    return { success: true };
  }

  async uninstallTor() {
    await this.stopTor();
    await fs.rm(this.torDir, { recursive: true, force: true });
    return { success: true };
  }

  isTorRunning() {
    return this.torProcess !== null && !this.torProcess.killed;
  }

  getTorStatus() {
    return {
      isRunning: this.isTorRunning(),
      processId: this.torProcess?.pid,
      socksPort: this.effectiveSocksPort,
      controlPort: this.effectiveControlPort,
      bootstrapped: this.bootstrapped
    };
  }

  async rotateCircuit() {
    if (!this.torProcess) {
      return { success: false, error: 'Tor not running' };
    }

    const beforeIP = await this.getCurrentTorIP();
    const result = await this.sendNewNymSignal();

    if (!result.success) {
      return { success: false, error: result.error };
    }

    await new Promise(resolve => setTimeout(resolve, 2000));
    const afterIP = await this.getCurrentTorIP();

    return {
      success: true,
      ipChanged: beforeIP !== afterIP,
      beforeIP,
      afterIP
    };
  }

  async sendNewNymSignal() {
    return new Promise((resolve) => {
      const socket = net.createConnection(this.effectiveControlPort, '127.0.0.1');
      let authenticated = false;

      socket.on('connect', () => {
        socket.write(`AUTHENTICATE "${this.controlPassword}"\r\n`);
      });

      socket.on('data', (data) => {
        const response = data.toString();
        if (/^250/.test(response)) {
          if (!authenticated) {
            authenticated = true;
            socket.write('SIGNAL NEWNYM\r\n');
          } else {
            socket.end();
            resolve({ success: true });
          }
        } else if (/^[45]\d\d/.test(response)) {
          socket.end();
          resolve({ success: false, error: response.trim() });
        }
      });

      socket.on('error', (error) => {
        resolve({ success: false, error: error.message });
      });

      setTimeout(() => {
        if (!socket.destroyed) {
          socket.destroy();
          resolve({ success: false, error: 'Timeout' });
        }
      }, 5000);
    });
  }

  async getCurrentTorIP() {
    try {
      const { SocksProxyAgent } = await import('socks-proxy-agent');
      const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${this.effectiveSocksPort}`);

      return new Promise((resolve) => {
        const req = https.request({
          hostname: 'httpbin.org',
          path: '/ip',
          method: 'GET',
          agent: proxyAgent,
          timeout: 15000
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              resolve(JSON.parse(data).origin || 'unknown');
            } catch {
              resolve('error');
            }
          });
        });
        req.on('error', () => resolve('error'));
        req.on('timeout', () => resolve('timeout'));
        req.end();
      });
    } catch {
      return 'error';
    }
  }

  async verifyTorConnection() {
    try {
      const socksWorking = await new Promise((resolve) => {
        const socket = net.createConnection(this.effectiveSocksPort, '127.0.0.1');
        const timeout = setTimeout(() => { socket.destroy(); resolve(false); }, 3000);
        socket.on('connect', () => { clearTimeout(timeout); socket.destroy(); resolve(true); });
        socket.on('error', () => { clearTimeout(timeout); resolve(false); });
      });

      if (!socksWorking) {
        return { success: false, error: 'SOCKS proxy not responding' };
      }

      // Check if bridges are configured
      const bridgesConfigured = await this.areBridgesConfigured();

      const { SocksProxyAgent } = await import('socks-proxy-agent');
      const proxyAgent = new SocksProxyAgent(`socks5h://127.0.0.1:${this.effectiveSocksPort}`);

      const torCheckResult = await new Promise((resolve) => {
        const req = https.request({
          hostname: 'check.torproject.org',
          path: '/api/ip',
          method: 'GET',
          agent: proxyAgent,
          timeout: 30000
        }, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              const result = JSON.parse(data);
              resolve({ success: true, isTor: result.IsTor === true, ip: result.IP });
            } catch {
              resolve({ success: false, error: 'Invalid response' });
            }
          });
        });
        req.on('error', (err) => {
          resolve({ success: false, error: 'Connection failed' });
        });
        req.on('timeout', () => {
          req.destroy();
          resolve({ success: false, error: 'Timeout' });
        });
        req.end();
      });

      if (!torCheckResult.success || !torCheckResult.isTor) {
        return torCheckResult;
      }

      // If bridges are configured, verify they're actually being used
      if (bridgesConfigured) {
        const bridgesInUse = await this.verifyBridgesInUse();
        if (!bridgesInUse) {
          return { success: false, error: 'Bridges configured but not in use' };
        }
      }

      return torCheckResult;
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async areBridgesConfigured() {
    try {
      const cfg = await fs.readFile(this.configPath, 'utf8').catch(() => '');
      return /^UseBridges\s+1/m.test(cfg);
    } catch {
      return false;
    }
  }

  async getBridgeFingerprints() {
    try {
      const cfg = await fs.readFile(this.configPath, 'utf8').catch(() => '');
      const lines = cfg.split('\n');
      const fingerprints = [];

      for (const line of lines) {
        const trimmed = line.trim();
        const match = trimmed.match(/^Bridge\s+(?:\S+\s+)?(?:\S+:\d+\s+)?([A-F0-9]{40})/i);
        if (match) {
          fingerprints.push(match[1].toUpperCase());
        }
      }

      return fingerprints;
    } catch {
      return [];
    }
  }

  async verifyBridgesInUse() {
    return new Promise(async (resolve) => {
      const bridgeFingerprints = await this.getBridgeFingerprints();

      if (bridgeFingerprints.length === 0) {
        resolve(false);
        return;
      }

      const socket = net.createConnection(this.effectiveControlPort, '127.0.0.1');
      let authenticated = false;
      let response = '';

      socket.on('connect', () => {
        socket.write(`AUTHENTICATE "${this.controlPassword}"\r\n`);
      });

      socket.on('data', (data) => {
        response += data.toString();

        if (/^250/.test(response) && !authenticated) {
          authenticated = true;
          response = '';
          // Get entry guard information
          socket.write('GETINFO entry-guards\r\n');
        } else if (authenticated && /^250/.test(response)) {
          socket.end();

          const entryGuardMatches = response.matchAll(/\$([A-F0-9]{40})/gi);
          const activeGuards = Array.from(entryGuardMatches).map(m => m[1].toUpperCase());

          // Check if any active guard matches a configured bridge
          const bridgeInUse = activeGuards.some(guard =>
            bridgeFingerprints.includes(guard)
          );

          resolve(bridgeInUse);
        } else if (/^[45]\d\d/.test(response)) {
          socket.end();
          resolve(false);
        }
      });

      socket.on('error', (err) => {
        resolve(false);
      });

      setTimeout(() => {
        if (!socket.destroyed) {
          socket.destroy();
          resolve(false);
        }
      }, 5000);
    });
  }
}

module.exports = ElectronTorManager;