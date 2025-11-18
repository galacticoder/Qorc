#!/usr/bin/env node
/*
 * Server launcher with robust TUI
 * - Starts the Node server with configured environment
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync, execFileSync } = require('child_process');
const { URL } = require('url');

const repoRoot = path.resolve(__dirname, '..');

// Load .env. Does not override existing env vars.
function loadDotEnv(filePath) {
  try {
    if (!fs.existsSync(filePath)) return;
    const text = fs.readFileSync(filePath, 'utf8');
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      let val = line.slice(eq + 1);
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (!(key in process.env)) {
        process.env[key] = val;
      }
    }
  } catch {}
}

// Read project .env before computing CONFIG
loadDotEnv(path.join(repoRoot, '.env'));

// Utility: file exists (absolute or relative to repoRoot)
function fileExistsMaybeRelative(p) {
  if (!p) return false;
  const abs = path.isAbsolute(p) ? p : path.join(repoRoot, p);
  try { return fs.existsSync(abs); } catch { return false; }
}

// Editable defaults (override via environment)
const CONFIG = {
  PORT: process.env.PORT || '', // Auto-allocate if empty
  BIND_ADDRESS: process.env.BIND_ADDRESS || '127.0.0.1',
  REDIS_URL: process.env.REDIS_URL || 'rediss://127.0.0.1:6379',
  ENABLE_CLUSTERING: process.env.ENABLE_CLUSTERING || 'true',
  CLUSTER_WORKERS: process.env.CLUSTER_WORKERS || '1',
  CLUSTER_PRIMARY: process.env.CLUSTER_PRIMARY || '', // '', 'true', or 'false'
  AUTO_APPROVE: process.env.CLUSTER_AUTO_APPROVE || 'true',
  ALLOWED_CORS_ORIGINS: process.env.ALLOWED_CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173',
  TLS_CERT_PATH: process.env.TLS_CERT_PATH || '',
  TLS_KEY_PATH: process.env.TLS_KEY_PATH || '',
  NO_GUI: (process.env.NO_GUI || 'false').toLowerCase() === 'true',
  SERVER_HOST: process.env.SERVER_HOST || '',
  SERVER_ID: process.env.SERVER_ID || '',
  USE_REDIS: process.env.USE_REDIS || 'true',
  DISABLE_CONNECTION_LIMIT: process.env.DISABLE_CONNECTION_LIMIT || 'true',
  KEY_ENCRYPTION_SECRET: process.env.KEY_ENCRYPTION_SECRET || '',
};

const serverDir = path.join(repoRoot, 'server');

// Prefer a project-local TLS-enabled Redis binary if configured.
const REDIS_SERVER_BIN = process.env.TLS_REDIS_SERVER || process.env.REDIS_SERVER_BIN || 'redis-server';

function log(...args) { console.log('[START]', ...args); }
function logErr(...args) { console.error('[START]', ...args); }

// Circular buffer for logs
class CircularBuffer {
  constructor(maxSize = 1000) {
    this.buffer = [];
    this.maxSize = maxSize;
  }
  push(item) {
    this.buffer.push(item);
    if (this.buffer.length > this.maxSize) {
      this.buffer.shift();
    }
  }
  getAll() { return this.buffer; }
  length() { return this.buffer.length; }
}

// Debouncer for reducing render calls
class Debouncer {
  constructor(fn, delay = 50) {
    this.fn = fn;
    this.delay = delay;
    this.timer = null;
    this.pending = false;
  }
  call() {
    this.pending = true;
    if (this.timer) return;
    this.timer = setTimeout(() => {
      if (this.pending) {
        this.fn();
        this.pending = false;
      }
      this.timer = null;
    }, this.delay);
  }
  flush() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.pending) {
      this.fn();
      this.pending = false;
    }
  }
}

// Rate limiter for metrics polling
class RateLimiter {
  constructor(minInterval = 1000) {
    this.minInterval = minInterval;
    this.lastCall = 0;
  }
  canCall() {
    const now = Date.now();
    if (now - this.lastCall >= this.minInterval) {
      this.lastCall = now;
      return true;
    }
    return false;
  }
}

// Cross-platform port checking
function isPortInUse(port) {
  try {
    let cmd, args;
    if (process.platform === 'win32') {
      cmd = 'netstat';
      args = ['-an'];
    } else {
      // Try ss first (modern), fallback to netstat
      if (fs.existsSync('/usr/bin/ss') || fs.existsSync('/bin/ss')) {
        cmd = 'ss';
        args = ['-tuln'];
      } else {
        cmd = 'netstat';
        args = ['-tuln'];
      }
    }
    
    const result = execSync(`${cmd} ${args.join(' ')} 2>/dev/null || true`, { encoding: 'utf8' });
    const portRegex = new RegExp(`:${port}[\s\]]`, 'm');
    if (portRegex.test(result)) return true;
    
    // Also check lsof if available
    if (process.platform !== 'win32') {
      try {
        const lsofResult = execSync(`lsof -i :${port} 2>/dev/null | grep LISTEN || true`, { encoding: 'utf8' });
        if (lsofResult.trim()) return true;
      } catch {}
    }
    
    return false;
  } catch {
    return false;
  }
}

// Find available port starting from base
async function findAvailablePort(basePort = 8443, maxAttempts = 100) {
  for (let i = 0; i < maxAttempts; i++) {
    const candidatePort = basePort + i;
    if (!isPortInUse(candidatePort)) {
      return candidatePort;
    }
  }
  throw new Error(`No available ports found in range ${basePort}-${basePort + maxAttempts}`);
}

// Validate TLS certificates and attempt to fix permissions if unreadable
function validateTLSCertificates() {
  if (!CONFIG.TLS_CERT_PATH || !CONFIG.TLS_KEY_PATH) {
    logErr('ERROR: TLS_CERT_PATH and TLS_KEY_PATH must be set');
    logErr('Generate certificates with: node scripts/generate_ts_tls.cjs');
    process.exit(1);
  }
  
  const certPath = path.isAbsolute(CONFIG.TLS_CERT_PATH) 
    ? CONFIG.TLS_CERT_PATH 
    : path.join(repoRoot, CONFIG.TLS_CERT_PATH);
  const keyPath = path.isAbsolute(CONFIG.TLS_KEY_PATH)
    ? CONFIG.TLS_KEY_PATH
    : path.join(repoRoot, CONFIG.TLS_KEY_PATH);
  
  if (!fs.existsSync(certPath)) {
    logErr(`ERROR: TLS cert not found: ${certPath}`);
    logErr('Generate certificates with: node scripts/generate_ts_tls.cjs');
    process.exit(1);
  }
  
  if (!fs.existsSync(keyPath)) {
    logErr(`ERROR: TLS key not found: ${keyPath}`);
    logErr('Generate certificates with: node scripts/generate_ts_tls.cjs');
    process.exit(1);
  }

  // Ensure readable; if not, try to fix with sudo chown/chmod
  try { fs.accessSync(certPath, fs.constants.R_OK); } catch (e) { tryFixTlsPerms(certPath, 0o644); }
  try { fs.accessSync(keyPath, fs.constants.R_OK); } catch (e) { tryFixTlsPerms(keyPath, 0o600); }
  // Re-check after fix
  try { fs.accessSync(certPath, fs.constants.R_OK); } catch (e) {
    logErr(`ERROR: Cannot read TLS cert: ${certPath}`);
    logErr('Try: sudo chown $USER:$USER <cert> && chmod 644 <cert>');
    process.exit(1);
  }
  try { fs.accessSync(keyPath, fs.constants.R_OK); } catch (e) {
    logErr(`ERROR: Cannot read TLS key: ${keyPath}`);
    logErr('Try: sudo chown $USER:$USER <key> && chmod 600 <key>');
    process.exit(1);
  }
  
  // Update config with absolute paths
  CONFIG.TLS_CERT_PATH = certPath;
  CONFIG.TLS_KEY_PATH = keyPath;
}

function tryFixTlsPerms(p, mode) {
  try {
    // If file owned by root, attempt sudo chown to current user
    const needSudo = process.platform !== 'win32' && !isWritableBySelf(p);
    if (needSudo && findSudo()) {
      const uid = process.getuid ? process.getuid() : null;
      const gid = process.getgid ? process.getgid() : null;
      const chownSpec = uid !== null && gid !== null ? `${uid}:${gid}` : '';
      const cmds = [];
      if (chownSpec) cmds.push(`chown ${chownSpec} '${p}'`);
      cmds.push(`chmod ${mode.toString(8)} '${p}'`);
      const cmd = cmds.join(' && ');
      execSync(`sudo bash -lc ${JSON.stringify(cmd)}`, { stdio: 'inherit' });
    } else {
      try { fs.chmodSync(p, mode); } catch {}
    }
  } catch {}
}

function isWritableBySelf(p) {
  try {
    const st = fs.statSync(p);
    return process.getuid && st.uid === process.getuid();
  } catch { return false; }
}

function findSudo() {
  try { execSync('command -v sudo >/dev/null 2>&1'); return true; } catch { return false; }
}

// Shared helper to generate a strong random secret (base64) using OpenSSL when
// available, otherwise Node crypto.
function generateStrongSecret(bytes = 48) {
  try {
    return execSync(`openssl rand -base64 ${bytes}`, { encoding: 'utf8' }).trim();
  } catch {
    const crypto = require('crypto');
    return crypto.randomBytes(bytes).toString('base64');
  }
}

// Ensure KEY_ENCRYPTION_SECRET exists
async function ensureKeyEncryptionSecret() {
  const secretFile = path.join(serverDir, 'config', 'secrets', 'KEY_ENCRYPTION_SECRET');
  const secretDir = path.dirname(secretFile);
  
  // If already set and strong enough, keep it
  if (CONFIG.KEY_ENCRYPTION_SECRET && CONFIG.KEY_ENCRYPTION_SECRET.length >= 32) {
    return CONFIG.KEY_ENCRYPTION_SECRET;
  }
  
  // Load from persisted file if available
  try {
    if (fs.existsSync(secretFile)) {
      const content = fs.readFileSync(secretFile, 'utf8').trim();
      if (content.length >= 32) {
        CONFIG.KEY_ENCRYPTION_SECRET = content;
        return content;
      }
    }
  } catch {}
  
  // Generate new secret
  log('Generating KEY_ENCRYPTION_SECRET...');
  const secret = generateStrongSecret(48);
  
  // Persist to file
  try {
    if (!fs.existsSync(secretDir)) {
      fs.mkdirSync(secretDir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(secretFile, secret, { mode: 0o600 });
    log(`KEY_ENCRYPTION_SECRET saved to ${secretFile}`);
  } catch (err) {
    logErr(`Warning: Could not save secret to file: ${err.message}`);
  }
  
  CONFIG.KEY_ENCRYPTION_SECRET = secret;
  return secret;
}

// Ensure SESSION_STORE_KEY exists for PQ session key encryption.
async function ensureSessionStoreKey() {
  const secretFile = path.join(serverDir, 'config', 'secrets', 'SESSION_STORE_KEY');
  const secretDir = path.dirname(secretFile);

  // If already set and strong enough, keep it
  if (process.env.SESSION_STORE_KEY && process.env.SESSION_STORE_KEY.trim().length >= 32) {
    return process.env.SESSION_STORE_KEY.trim();
  }

  // Load from persisted file if available
  try {
    if (fs.existsSync(secretFile)) {
      const content = fs.readFileSync(secretFile, 'utf8').trim();
      if (content.length >= 32) {
        process.env.SESSION_STORE_KEY = content;
        return content;
      }
    }
  } catch {}

  // Generate new secret (≥32 bytes when decoded)
  log('Generating SESSION_STORE_KEY for PQ session storage...');
  const secret = generateStrongSecret(48);

  // Persist to file
  try {
    if (!fs.existsSync(secretDir)) {
      fs.mkdirSync(secretDir, { recursive: true, mode: 0o700 });
    }
    fs.writeFileSync(secretFile, secret, { mode: 0o600 });
    log(`SESSION_STORE_KEY saved to ${secretFile}`);
  } catch (err) {
    logErr(`Warning: Could not save SESSION_STORE_KEY to file: ${err.message}`);
  }

  process.env.SESSION_STORE_KEY = secret;
  return secret;
}

async function ensureServerDeps() {
  const nm = path.join(serverDir, 'node_modules');
  const hasNm = fs.existsSync(nm);
  const pkgLock = fs.existsSync(path.join(serverDir, 'package-lock.json'));
  const ciArgs = pkgLock ? ['ci', '--omit=dev'] : ['install', '--omit=dev'];
  if (!hasNm) {
    log('Installing server dependencies ...');
    await new Promise((resolve, reject) => {
      const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
      const child = spawn(npmCmd, ciArgs, { cwd: serverDir, stdio: 'inherit', shell: process.platform === 'win32' });
      child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`npm ${ciArgs[0]} failed: ${code}`)));
    });
  }
}

async function ensurePostgresBootstrap() {
  const dbName = process.env.PGDATABASE || 'endtoend';
  const host = process.env.DB_CONNECT_HOST || process.env.PGHOST || '127.0.0.1';
  const port = process.env.PGPORT || '5432';
  const user = process.env.DATABASE_USER || process.env.PGUSER || process.env.USER;
  const password = process.env.DATABASE_PASSWORD || process.env.PGPASSWORD;

  if (!user || !password || !dbName) {
    return;
  }

  try {
    const env = { ...process.env, PGPASSWORD: password };
    execFileSync('psql', [
      '-h', host,
      '-p', String(port),
      '-U', user,
      '-d', dbName,
      '-c', 'SELECT 1'
    ], {
      env,
      stdio: 'ignore',
    });
    return;
  } catch (err) {
    if (err && err.code === 'ENOENT') { 
      logErr('psql not found in PATH; skipping Postgres bootstrap.');
      return;
    }
  }

  if (!process.stdin.isTTY) {
    logErr('Cannot auto-create Postgres DB: no TTY available for sudo password prompt.');
    return;
  }

  log('[DB] Postgres not reachable; attempting sudo bootstrap (you may be prompted for your password)...');

  const safeUser = String(user).replace(/"/g, '""');
  const safeDb = String(dbName).replace(/"/g, '""');
  const safePassword = String(password).replace(/'/g, "''");

  try {
    execFileSync('sudo', [
      '-u', 'postgres',
      'psql',
      '-c',
      `CREATE USER "${safeUser}" WITH PASSWORD '${safePassword}' CREATEDB;`,
    ], { stdio: 'inherit' });
  } catch (err) {
    logErr('[DB] CREATE USER via sudo psql failed (may already exist).');
  }

  try {
    execFileSync('sudo', [
      '-u', 'postgres',
      'psql',
      '-c',
      `CREATE DATABASE "${safeDb}" OWNER "${safeUser}";`,
    ], { stdio: 'inherit' });
  } catch (err) {
    logErr('[DB] CREATE DATABASE via sudo psql failed (may already exist).');
  }
}

class ServerUI {
  constructor(serverPid, config) {
    this.serverPid = serverPid;
    this.config = config;
    this.logBuffer = new CircularBuffer(1000);
    this.scrollOffset = 0;
    this.running = true;
    this.startTime = Date.now();
    this.lastMetrics = null;
    this.metricsLimiter = new RateLimiter(1000);
    this.selfServerId = null;
    this.tlsCache = null;
    this.lastTlsCheck = 0;
    
    // Setup terminal
    this.width = process.stdout.columns || 80;
    this.height = process.stdout.rows || 24;
    
    // Debounced render to prevent flickering
    this.renderDebouncer = new Debouncer(() => this._doRender(), 50);
    
    // Handle terminal resize
    process.stdout.on('resize', () => {
      this.width = process.stdout.columns || 80;
      this.height = process.stdout.rows || 24;
      this.renderDebouncer.call();
    });
    
    // Setup input handling
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (key) => this._handleInput(key));
    }
    
    // Enter alternate screen, disable line wrap, clear, hide cursor
    process.stdout.write('\x1b[?1049h\x1b[?7l\x1b[2J\x1b[H\x1b[?25l');
  }
  
  _handleInput(key) {
    const code = key.charCodeAt(0);
    
    // q or Ctrl+C to quit
    if (key === 'q' || key === 'Q' || code === 3) {
      this.stop();
      return;
    }
    
    const visibleLines = Math.max(1, this.height - 6);
    const maxOffset = Math.max(0, this.logBuffer.length() - visibleLines);
    
    // Arrow keys and scrolling
    if (key === '\x1b[A') { // Up arrow
      this.scrollOffset = Math.min(this.scrollOffset + 1, maxOffset);
      this.renderDebouncer.call();
    } else if (key === '\x1b[B') { // Down arrow
      this.scrollOffset = Math.max(this.scrollOffset - 1, 0);
      this.renderDebouncer.call();
    } else if (key === '\x1b[5~') { // Page Up
      this.scrollOffset = Math.min(this.scrollOffset + visibleLines, maxOffset);
      this.renderDebouncer.call();
    } else if (key === '\x1b[6~') { // Page Down
      this.scrollOffset = Math.max(this.scrollOffset - visibleLines, 0);
      this.renderDebouncer.call();
    } else if (key === '\x1b[H') { // Home
      this.scrollOffset = maxOffset;
      this.renderDebouncer.call();
    } else if (key === '\x1b[F') { // End
      this.scrollOffset = 0;
      this.renderDebouncer.call();
    } else if (key === 'g') {
      this.scrollOffset = maxOffset;
      this.renderDebouncer.call();
    } else if (key === 'G') {
      this.scrollOffset = 0;
      this.renderDebouncer.call();
    } else if (key === 'k') {
      this.scrollOffset = Math.min(this.scrollOffset + 1, maxOffset);
      this.renderDebouncer.call();
    } else if (key === 'j') {
      this.scrollOffset = Math.max(this.scrollOffset - 1, 0);
      this.renderDebouncer.call();
    } else if (code === 21) { // Ctrl-U
      this.scrollOffset = Math.min(this.scrollOffset + Math.floor(visibleLines / 2), maxOffset);
      this.renderDebouncer.call();
    } else if (code === 4) { // Ctrl-D
      this.scrollOffset = Math.max(this.scrollOffset - Math.floor(visibleLines / 2), 0);
      this.renderDebouncer.call();
    }
  }
  
  addLog(line) {
    this.logBuffer.push(line);
    this.renderDebouncer.call();
  }
  
  async updateMetrics() {
    if (!this.metricsLimiter.canCall()) return;
    
    try {
      const metrics = {};
      
      // CPU and memory usage
      try {
        const cmd = process.platform === 'win32'
          ? `wmic process where processid=${this.serverPid} get WorkingSetSize,UserModeTime`
          : `ps -p ${this.serverPid} -o %cpu=,%mem=`;
        const out = execSync(cmd, { encoding: 'utf8', timeout: 500 }).trim();
        if (process.platform === 'win32') {
          const lines = out.split('\n').filter(l => l.trim());
          if (lines.length > 1) {
            const parts = lines[1].trim().split(/\s+/);
            metrics.cpu = '?';
            metrics.mem = parts[0] ? (parseInt(parts[0]) / 1024 / 1024).toFixed(1) : '?';
          }
        } else {
          const parts = out.split(/\s+/);
          if (parts.length >= 2) {
            metrics.cpu = parts[0];
            metrics.mem = parts[1];
          }
        }
      } catch {}
      
      // Connection count
      try {
        const port = this.config.PORT;
        let cmd;
        if (process.platform === 'win32') {
          cmd = `netstat -an | findstr :${port} | findstr ESTABLISHED | find /c /v \"\"`;
        } else if (fs.existsSync('/usr/bin/ss') || fs.existsSync('/bin/ss')) {
          // Robust ss filter across versions; suppress parser errors
          cmd = `ss -Htan 2>/dev/null | awk -v p=":${port}$" '$1 ~ /ESTAB/ && $4 ~ p {c++} END{print c+0}'`;
        } else {
          cmd = `netstat -tan 2>/dev/null | awk '$4 ~ /:${port}$/ && $6==\"ESTABLISHED\"' | wc -l`;
        }
        const out = execSync(cmd, { encoding: 'utf8', timeout: 500, shell: true }).trim();
        metrics.connections = parseInt(out) || 0;
      } catch {}
      
      // Redis cluster info
      try {
        if (!this.selfServerId) {
          const keys = execSync(`redis-cli -u "${this.config.REDIS_URL}" hkeys cluster:servers`, 
            { encoding: 'utf8', timeout: 700 }).trim().split('\n');
          for (const key of keys) {
            const val = execSync(`redis-cli -u "${this.config.REDIS_URL}" hget cluster:servers "${key}"`,
              { encoding: 'utf8', timeout: 700 }).trim();
            try {
              const data = JSON.parse(val);
              if (data.port == this.config.PORT || data.pid == this.serverPid) {
                this.selfServerId = key;
                break;
              }
            } catch {}
          }
        }
        
        if (this.selfServerId) {
          const val = execSync(`redis-cli -u "${this.config.REDIS_URL}" hget cluster:servers "${this.selfServerId}"`,
            { encoding: 'utf8', timeout: 700 }).trim();
          const data = JSON.parse(val);
          metrics.heartbeatAge = Math.floor((Date.now() - (data.lastHeartbeat || 0)) / 1000);
          metrics.registered = true;
        } else {
          metrics.registered = false;
        }
      } catch {}
      
      // TLS info (check every 10s)
      if (Date.now() - this.lastTlsCheck > 10000) {
        this.lastTlsCheck = Date.now();
        try {
          if (this.config.TLS_CERT_PATH && fs.existsSync(this.config.TLS_CERT_PATH)) {
            const subj = execSync(`openssl x509 -in "${this.config.TLS_CERT_PATH}" -noout -subject`,
              { encoding: 'utf8', timeout: 600 }).trim();
            const end = execSync(`openssl x509 -in "${this.config.TLS_CERT_PATH}" -noout -enddate`,
              { encoding: 'utf8', timeout: 600 }).trim();
            
            let cn = null;
            const cnMatch = subj.match(/CN\s*=\s*([^,/]+)/);
            if (cnMatch) cn = cnMatch[1].trim();
            
            let days = null;
            const dateMatch = end.match(/notAfter=(.+)/);
            if (dateMatch) {
              const expiry = new Date(dateMatch[1]);
              days = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
            }
            
            this.tlsCache = { cn, days };
          }
        } catch {}
      }
      
      this.lastMetrics = metrics;
    } catch {}
  }
  
  _truncate(str, maxLen) {
    if (!str) return 'unknown';
    str = String(str);
    if (str.length <= maxLen) return str;
    const head = Math.floor(maxLen / 2);
    const tail = maxLen - head - 1;
    return str.substring(0, head) + '…' + str.substring(str.length - tail);
  }
  
  _doRender() {
    if (!this.running) return;
    
    const lines = [];
    const w = this.width;
    const h = this.height;
    
    // Check if server is alive
    let alive = false;
    try {
      process.kill(this.serverPid, 0);
      alive = true;
    } catch {}
    
    if (!alive && this.running) {
      this.stop();
      return;
    }
    
    const m = this.lastMetrics || {};
    const cpu = m.cpu || '?';
    const mem = m.mem || '?';
    const conns = m.connections !== undefined ? m.connections : '?';
    const uptime = Math.floor((Date.now() - this.startTime) / 1000);
    const hbAge = m.heartbeatAge !== undefined ? m.heartbeatAge : null;
    const registered = m.registered || false;

    const dbDisplay = (() => {
      try {
        const rawUrl = process.env.DATABASE_URL;
        let display = null;
        if (rawUrl && typeof rawUrl === 'string') {
          try {
            const u = new URL(rawUrl);
            const protocol = u.protocol || 'postgres:';
            const user = u.username || '';
            const hostName = u.hostname || 'localhost';
            const port = u.port || '';
            const dbName = u.pathname ? u.pathname.replace(/^\//, '') : '';
            const proto = protocol.replace(/:$/, '');
            const auth = user ? `${user}@` : '';
            const hostPort = port ? `${hostName}:${port}` : hostName;
            display = `${proto}://${auth}${hostPort}${dbName ? '/' + dbName : ''}`;
          } catch {
            display = rawUrl;
          }
        }
        if (!display) {
          const hostName = process.env.PGHOST || '127.0.0.1';
          const port = process.env.PGPORT || '5432';
          const dbName = process.env.PGDATABASE || 'endtoend';
          const user = process.env.DATABASE_USER || process.env.PGUSER || '';
          const auth = user ? `${user}@` : '';
          display = `postgres://${auth}${hostName}:${port}/${dbName}`;
        }
        const maxLen = Math.max(16, Math.floor(w / 2));
        return this._truncate(display, maxLen);
      } catch {
        return 'postgres://unknown';
      }
    })();
    
    // Format uptime
    const fmtTime = (s) => {
      const d = Math.floor(s / 86400);
      const h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      if (d) return `${d}d ${h}h ${m}m`;
      if (h) return `${h}h ${m}m ${sec}s`;
      if (m) return `${m}m ${sec}s`;
      return `${sec}s`;
    };
    
    // Header (cyan background like HAProxy)
    const serverId = this._truncate(this.selfServerId || this.config.SERVER_ID || 'unknown', 24);
    const host = this.config.SERVER_HOST || '127.0.0.1';
    const port = this.config.PORT;
    const leftTxt = ` Server: ${serverId} `;
    const centerTxt = ` PID ${this.serverPid} | CPU ${cpu}% | MEM ${mem}% `;
    const rightTxt = ` Host: ${host}:${port} `;
    
    let headerLine = '';
    const leftLen = leftTxt.length;
    const rightLen = rightTxt.length;
    const centerLen = centerTxt.length;
    const centerStart = Math.max(leftLen + 1, Math.floor((w - centerLen) / 2));
    const rightStart = Math.max(centerStart + centerLen + 1, w - rightLen);
    
    headerLine += leftTxt;
    headerLine += ' '.repeat(Math.max(0, centerStart - leftLen));
    if (centerStart + centerLen < rightStart) {
      headerLine += centerTxt;
      headerLine += ' '.repeat(Math.max(0, rightStart - centerStart - centerLen));
    }
    if (rightStart + rightLen <= w) {
      headerLine += rightTxt.substring(0, w - rightStart);
    }
    headerLine = headerLine.substring(0, w);
    headerLine += ' '.repeat(Math.max(0, w - headerLine.length));
    lines.push('\x1b[30;46;1m' + headerLine + '\x1b[0m'); // black on cyan, bold
    
    // Stats line
    const uptimeTxt = `UP ${fmtTime(uptime)}`;
    const connTxt = `CONN ${conns}`;
    const hbPlain = hbAge !== null ? `HB ${hbAge}s` : 'HB ?';
    const rightStatsPlain = `${hbPlain}   ${uptimeTxt}   ${connTxt}`;
    const rightStatsStart = Math.max(1, w - rightStatsPlain.length - 1);
    
    let statsLine = '';
    // Redis
    statsLine += `\x1b[36mRedis: ${this.config.REDIS_URL}\x1b[0m`;
    statsLine += '\x1b[36m  •  \x1b[0m';
    statsLine += '\x1b[36mDB: \x1b[0m';
    statsLine += `\x1b[36m${dbDisplay}\x1b[0m`;
    statsLine += '\x1b[36m  •  \x1b[0m';
    statsLine += '\x1b[36mStatus: \x1b[0m';
    if (registered) {
      statsLine += '\x1b[32mregistered\x1b[0m';
    } else {
      statsLine += '\x1b[33mpending\x1b[0m';
    }
    statsLine += '\x1b[36m  •  \x1b[0m';
    // TLS
    if (this.tlsCache) {
      const cn = this.tlsCache.cn || '';
      const days = this.tlsCache.days;
      const tlsColor = days >= 14 ? '32' : (days >= 3 ? '33' : '31');
      statsLine += `\x1b[${tlsColor}mTLS ${cn} (${days}d)\x1b[0m`;
    } else {
      statsLine += '\x1b[33mTLS none\x1b[0m';
    }
    
    // Strip ANSI for length calculation
    const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]+m/g, '');
    const statsPlain = stripAnsi(statsLine);
    if (statsPlain.length < rightStatsStart) {
      statsLine += ' '.repeat(rightStatsStart - statsPlain.length);
      let hbColored;
      if (hbAge !== null) {
        const hbColor = hbAge < 5 ? '32' : (hbAge < 15 ? '33' : '31');
        hbColored = `HB \x1b[${hbColor}m${hbAge}s\x1b[36m`;
      } else {
        hbColored = 'HB \x1b[33m?\x1b[36m';
      }
      const rightStatsColored = `\x1b[36m${hbColored}   ${uptimeTxt}   ${connTxt}\x1b[0m`;
      statsLine += rightStatsColored;
    }
    lines.push(statsLine);
    
    // Box top
    lines.push('┌' + '─'.repeat(w - 2) + '┐');
    
    // Log content
    const logHeight = Math.max(1, h - 5); // header + stats + box borders + footer = total h lines
    const visibleLines = Math.max(1, logHeight);
    const logs = this.logBuffer.getAll();
    const maxOffset = Math.max(0, logs.length - visibleLines);
    if (this.scrollOffset > maxOffset) this.scrollOffset = maxOffset;
    
    const startIdx = Math.max(0, logs.length - visibleLines - this.scrollOffset);
    const endIdx = logs.length - this.scrollOffset;
    const visibleLogs = logs.slice(startIdx, endIdx);
    
    for (let i = 0; i < logHeight; i++) {
      const line = visibleLogs[i] || '';
      const truncated = line.substring(0, w - 4);
      const padded = truncated + ' '.repeat(Math.max(0, w - 4 - truncated.length));
      const scrollbar = i === 0 && this.scrollOffset > 0 ? '▲' : 
                        i === logHeight - 1 && this.scrollOffset < maxOffset ? '▼' : '│';
      lines.push('│ ' + padded + ' ' + scrollbar);
    }
    
    // Box bottom
    lines.push('└' + '─'.repeat(w - 2) + '┘');
    
    // Footer
    const scrollIndicator = this.scrollOffset > 0 ? ' [SCROLL]' : '';
    const footerTxt = ' q: quit  Arrows PgUp/PgDn Home/End' + scrollIndicator;
    const footerPadded = footerTxt + ' '.repeat(Math.max(0, w - footerTxt.length));
    lines.push('\x1b[30;46m' + footerPadded.substring(0, w) + '\x1b[0m');
    
    // Render atomically with double buffering to prevent flicker
    const output = '\x1b[?25l' + '\x1b[H' + lines.join('\n');
    try {
      process.stdout.write(output);
    } catch {}
  }
  
  render() {
    this.renderDebouncer.call();
  }
  
  stop(preserve = false) {
    if (!this.running) return;
    this.running = false;
    this.renderDebouncer.flush();
    
    // Stop metrics polling
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
      this.metricsInterval = null;
    }
    
    // Restore terminal
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }
    // Restore terminal modes and leave alt screen
    if (!preserve) {
      // leave alt screen then clear previous buffer line
      process.stdout.write('\x1b[?7h\x1b[?25h\x1b[?1049l');
    } else {
      process.stdout.write('\x1b[?7h\x1b[?25h\x1b[?1049l');
    }
    
    // Kill server if still running
    try {
      process.kill(this.serverPid, 'SIGTERM');
      setTimeout(() => {
        try { process.kill(this.serverPid, 'SIGKILL'); } catch {}
      }, 2000);
    } catch {}
  }
  
  start() {
    // Initial render
    this.render();
    
    // Update metrics periodically
    this.metricsInterval = setInterval(() => {
      this.updateMetrics().then(() => this.render());
    }, 1000);
    
    // Handle signals
    process.on('SIGINT', () => this.stop());
    process.on('SIGTERM', () => this.stop());
  }
}

async function ensureTLSIfMissing() {
  // If TLS paths not set or files missing, prompt to generate
  const hasCert = CONFIG.TLS_CERT_PATH && fileExistsMaybeRelative(CONFIG.TLS_CERT_PATH);
  const hasKey = CONFIG.TLS_KEY_PATH && fileExistsMaybeRelative(CONFIG.TLS_KEY_PATH);
  if (hasCert && hasKey) return;

  const canPrompt = process.stdin.isTTY;
  if (!canPrompt) {
    logErr('TLS not configured and no TTY to prompt. Run: node scripts/generate_ts_tls.cjs');
    process.exit(1);
  }

  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => {
    rl.question('TLS cert/key not found. Generate now with Tailscale? (Y/n): ', (ans) => { rl.close(); resolve(ans); });
  });
  if (String(answer).trim().match(/^(|y|yes)$/i)) {
    const child = spawn(process.execPath, [path.join(repoRoot, 'scripts', 'generate_ts_tls.cjs')], { cwd: repoRoot, stdio: 'inherit' });
    const code = await new Promise((r) => child.on('exit', (c) => r(c || 0)));
    if (code !== 0) {
      logErr('TLS generation failed. Aborting.');
      process.exit(code);
    }
    // Reload .env and update CONFIG
    loadDotEnv(path.join(repoRoot, '.env'));
    if (process.env.TLS_CERT_PATH) CONFIG.TLS_CERT_PATH = process.env.TLS_CERT_PATH;
    if (process.env.TLS_KEY_PATH) CONFIG.TLS_KEY_PATH = process.env.TLS_KEY_PATH;
  } else {
    logErr('TLS is required. You can run: node scripts/generate_ts_tls.cjs');
    process.exit(1);
  }
}

async function ensureDbCaBundleEnv() {
  // If caller already pinned a CA bundle and the file exists, respect that.
  const pinnedPath = process.env.DB_CA_CERT_PATH || process.env.PGSSLROOTCERT;
  if (pinnedPath) {
    try {
      const resolved = path.resolve(pinnedPath);
      if (fs.existsSync(resolved)) {
        return;
      }
      logErr(`[START] WARN: DB_CA_CERT_PATH/PGSSLROOTCERT points to missing file '${resolved}'; regenerating CA bundle`);
    } catch {
      // Fall through to regeneration
    }
  }

  // Derive DB host/port either from DATABASE_URL or PGHOST/PGPORT.
  let dbHost = '127.0.0.1';
  let dbPort = '5432';
  try {
    if (process.env.DATABASE_URL) {
      const u = new URL(process.env.DATABASE_URL);
      if (u.hostname) dbHost = u.hostname;
      if (u.port) dbPort = String(u.port);
    } else {
      if (process.env.PGHOST) dbHost = process.env.PGHOST;
      if (process.env.PGPORT) dbPort = String(process.env.PGPORT);
    }
  } catch {
    // Fall back to defaults on parse errors
  }

  // Basic sanitization to avoid nonsense values in commands
  if (!/^[-A-Za-z0-9_.]+$/.test(dbHost)) {
    logErr(`[START] WARN: PGHOST/DATABASE_URL host '${dbHost}' is not a simple hostname/IP; cannot auto-generate DB_CA_CERT_PATH`);
    return;
  }
  const portNum = parseInt(dbPort, 10);
  if (!Number.isFinite(portNum) || portNum <= 0 || portNum > 65535) {
    logErr(`[START] WARN: PGPORT/DATABASE_URL port '${dbPort}' is invalid; cannot auto-generate DB_CA_CERT_PATH`);
    return;
  }

  const caOutDir = path.join(serverDir, 'config', 'certs');
  const caOutPath = path.join(caOutDir, 'postgres-root-cas.pem');

  try {
    if (!fs.existsSync(caOutDir)) {
      fs.mkdirSync(caOutDir, { recursive: true, mode: 0o755 });
    }

    const serverName = dbHost;
    const connectHosts = [dbHost];
    if (dbHost !== '127.0.0.1' && dbHost !== 'localhost') {
      connectHosts.push('127.0.0.1', 'localhost');
    }

    let stdout;
    let usedConnectHost = null;
    let lastErr = null;

    for (const connectHost of connectHosts) {
      const args = [
        's_client',
        '-starttls', 'postgres',
        '-servername', serverName,
        '-connect', `${connectHost}:${portNum}`,
        '-showcerts'
      ];
      try {
        stdout = execFileSync('openssl', args, { encoding: 'utf8' });
        usedConnectHost = connectHost;
        break;
      } catch (e) {
        lastErr = e;
      }
    }

    if (!stdout) {
      logErr('[START] WARN: Failed to probe Postgres TLS chain with openssl via any host; DB_CA_CERT_PATH not auto-generated: ' + (lastErr?.message || lastErr));
      // Avoid leaving a stale, unreadable CA path in-process; fall back to system CAs.
      delete process.env.DB_CA_CERT_PATH;
      delete process.env.PGSSLROOTCERT;
      return;
    }

    const matches = stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    if (!matches.length) {
      logErr('[START] WARN: openssl s_client returned no certificates; DB_CA_CERT_PATH not auto-generated');
      return;
    }

    const pemBundle = matches.join('\n') + '\n';
    fs.writeFileSync(caOutPath, pemBundle, { mode: 0o644 });
    log('[START] Generated Postgres CA bundle from remote TLS chain:', caOutPath);

    // Try to extract CN from the inspected certificate output
    let cn = null;
    try {
      const cnMatch = stdout.match(/CN\s*=\s*([^\n]+)/);
      if (cnMatch) {
        cn = cnMatch[1].trim();
      }
    } catch {}

    if (cn && /^[-A-Za-z0-9_.]+$/.test(cn)) {
      // Use DB_TLS_SERVERNAME for certificate hostname verification; the actual
      // TCP connect host may be a loopback address (e.g. 127.0.0.1).
      process.env.DB_TLS_SERVERNAME = cn;
      log(`[START] Using DB_TLS_SERVERNAME to match Postgres certificate CN: ${cn}`);
    }

    // Remember which host was successfully probed for TLS so we can reuse it
    // for the actual TCP connection. This may differ from the certificate
    // hostname when Postgres only listens on loopback.
    const connectHost = usedConnectHost || dbHost;
    process.env.DB_CONNECT_HOST = connectHost;
    process.env.DB_CA_CERT_PATH = caOutPath;

    // Persist into .env so future runs don’t need regeneration
    try {
      const envPath = path.join(repoRoot, '.env');
      let envText = '';
      try {
        envText = fs.readFileSync(envPath, 'utf8');
      } catch {}
      const lines = envText ? envText.split(/\r?\n/) : [];

      const upsert = (key, value) => {
        const line = `${key}=${value}`;
        const idx = lines.findIndex(l => l.trim().startsWith(key + '='));
        if (idx >= 0) {
          lines[idx] = line;
        } else {
          lines.push(line);
        }
      };

      upsert('DB_CA_CERT_PATH', caOutPath);
      upsert('DB_CONNECT_HOST', connectHost);
      if (process.env.DB_TLS_SERVERNAME === cn) {
        upsert('DB_TLS_SERVERNAME', cn);
      }

      const newEnv = lines.filter(Boolean).join('\n') + '\n';
      fs.writeFileSync(envPath, newEnv, 'utf8');
    } catch (e) {
      logErr('[START] WARN: Failed to persist DB_CA_CERT_PATH/PGHOST to .env: ' + e.message);
    }
  } catch (e) {
    logErr('[START] WARN: Failed to generate Postgres CA bundle: ' + e.message);
  }
}

async function ensureRedisTls() {
  const rawUrl = CONFIG.REDIS_URL;
  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch (e) {
    logErr(`ERROR: Invalid REDIS_URL '${rawUrl}': ${e.message}`);
    process.exit(1);
  }

  if (urlObj.protocol !== 'rediss:') {
    logErr('ERROR: REDIS_URL must use rediss:// and TLS; plaintext redis:// is not supported.');
    process.exit(1);
  }

  const host = urlObj.hostname || '127.0.0.1';
  let port = urlObj.port ? parseInt(urlObj.port, 10) : 6379;
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    logErr(`ERROR: Invalid Redis port in REDIS_URL: '${urlObj.port || ''}'`);
    process.exit(1);
  }

  // Only auto-manage a local Redis instance; remote Redis must be provisioned externally.
  const isLoopback = host === '127.0.0.1' || host === 'localhost';
  if (!isLoopback) {
    return;
  }

  // If a TLS Redis instance is already reachable at REDIS_URL, reuse it instead of
  // auto-selecting a new port or starting a second local instance.
  try {
    const pingCmd = `redis-cli -u "${rawUrl}" PING`;
    const out = execSync(pingCmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 1500 }).trim();
    if (/PONG/i.test(out)) {
      log(`Detected existing TLS Redis at ${rawUrl}; reusing.`);
      return;
    }
  } catch (_e) {
  }

  // If using a project-local TLS Redis binary (TLS_REDIS_SERVER), trust the build
  // performed by install-deps.cjs and skip further TLS capability checks.
  const usingLocalTlsRedis = !!process.env.TLS_REDIS_SERVER;
  if (!usingLocalTlsRedis) {
    // Ensure system redis-server supports TLS before attempting to auto-start.
    let helpOutput = '';
    try {
      helpOutput = execSync(REDIS_SERVER_BIN + ' --help', { encoding: 'utf8' });
    } catch (e) {
      const out = `${e.stdout || ''}${e.stderr || ''}`;
      if (!out) {
        logErr(`ERROR: ${REDIS_SERVER_BIN} not found or not executable; TLS Redis is required.`);
        process.exit(1);
      }
      helpOutput = out;
    }
    if (!/tls/i.test(helpOutput)) {
      logErr('ERROR: Local redis-server binary does not appear to support TLS.');
      logErr('Plaintext Redis is not supported. Install a TLS-capable redis-server (v6+ built with TLS)');
      logErr('or configure an external TLS Redis instance and set REDIS_URL=rediss://host:port.');
      process.exit(1);
    }
  }

  // Derive TLS servername for Redis from the HTTPS certificate CN if not already set.
  if (!process.env.REDIS_TLS_SERVERNAME && CONFIG.TLS_CERT_PATH && fs.existsSync(CONFIG.TLS_CERT_PATH)) {
    try {
      const subj = execSync(`openssl x509 -in "${CONFIG.TLS_CERT_PATH}" -noout -subject`, { encoding: 'utf8' }).trim();
      const cnMatch = subj.match(/CN\s*=\s*([^,/]+)/);
      if (cnMatch) {
        process.env.REDIS_TLS_SERVERNAME = cnMatch[1].trim();
        log(`[START] Using REDIS_TLS_SERVERNAME derived from TLS cert CN: ${process.env.REDIS_TLS_SERVERNAME}`);
      }
    } catch (e) {
      logErr('[START] WARN: Failed to derive REDIS_TLS_SERVERNAME from TLS cert: ' + e.message);
    }
  }

  if (isLoopback && port === 6379) {
    try {
      const altPort = await findAvailablePort(6380, 100);
      log(`[START] Avoiding default Redis port 6379; using dedicated TLS Redis port ${altPort}`);
      port = altPort;
    } catch (e) {
      logErr('[START] ERROR: No available port found for Redis TLS: ' + e.message);
      process.exit(1);
    }
  } else if (isPortInUse(port)) {
    // For non-default ports, respect explicit REDIS_URL but avoid collision
    try {
      const altPort = await findAvailablePort(port + 1, 100);
      log(`[START] Port ${port} already in use; auto-selecting Redis TLS port ${altPort}`);
      port = altPort;
    } catch (e) {
      logErr('[START] ERROR: No available port found for Redis TLS: ' + e.message);
      process.exit(1);
    }
  }

  if (!CONFIG.TLS_CERT_PATH || !CONFIG.TLS_KEY_PATH) {
    logErr('ERROR: TLS_CERT_PATH and TLS_KEY_PATH must be set before auto-starting Redis TLS.');
    process.exit(1);
  }

  // Ensure redis-server is available
  try {
    execSync(`${REDIS_SERVER_BIN} --version`, { stdio: 'ignore', shell: true });
  } catch {
    logErr(`ERROR: ${REDIS_SERVER_BIN} not found or not executable; install Redis with TLS support or set TLS_REDIS_SERVER to a TLS-capable binary.`);
    process.exit(1);
  }

  const args = [
    '--port', '0',
    '--tls-port', String(port),
    '--tls-cert-file', CONFIG.TLS_CERT_PATH,
    '--tls-key-file', CONFIG.TLS_KEY_PATH,
    // Do not require client certificates; we still rely on hostname
    // verification on the client side for security.
    '--tls-auth-clients', 'no',
  ];

  log('[START] Auto-starting local TLS Redis:', `${REDIS_SERVER_BIN} ${args.join(' ')}`);
  const child = spawn(REDIS_SERVER_BIN, args, { cwd: repoRoot, stdio: 'ignore' });

  // Update CONFIG.REDIS_URL and process.env, and persist to .env
  const newUrl = `rediss://${host}:${port}`;
  CONFIG.REDIS_URL = newUrl;
  process.env.REDIS_URL = newUrl;

  try {
    const envPath = path.join(repoRoot, '.env');
    let envText = '';
    try { envText = fs.readFileSync(envPath, 'utf8'); } catch {}
    const lines = envText ? envText.split(/\r?\n/) : [];
    const upsert = (key, value) => {
      const line = `${key}=${value}`;
      const idx = lines.findIndex(l => l.trim().startsWith(key + '='));
      if (idx >= 0) lines[idx] = line; else lines.push(line);
    };
    upsert('REDIS_URL', newUrl);
    if (process.env.REDIS_TLS_SERVERNAME) {
      upsert('REDIS_TLS_SERVERNAME', process.env.REDIS_TLS_SERVERNAME);
    }
    const newEnv = lines.filter(Boolean).join('\n') + '\n';
    fs.writeFileSync(envPath, newEnv, 'utf8');
  } catch (e) {
    logErr('[START] WARN: Failed to persist REDIS_URL/REDIS_TLS_SERVERNAME to .env: ' + e.message);
  }
}

async function main() {
  // Show banner
  if (!CONFIG.NO_GUI) {
    console.log('\x1b[34m╔════════════════════════════════════════════╗\x1b[0m');
    console.log('\x1b[34m║\x1b[32m           End2End Chat Server              \x1b[34m║\x1b[0m');
    console.log('\x1b[34m╚════════════════════════════════════════════╝\x1b[0m');
  }
  
  // Ensure TLS exists (interactive if missing), then validate
  await ensureTLSIfMissing();
  validateTLSCertificates();
  
  // Ensure encryption secret
  await ensureKeyEncryptionSecret();

  // Ensure PQ session store key (SESSION_STORE_KEY) exists for Redis-encrypted PQ sessions
  await ensureSessionStoreKey();

  // Ensure Postgres CA bundle is available and DB_CA_CERT_PATH is set
  await ensureDbCaBundleEnv();

  // Ensure Postgres user/database exist before starting server (works for TUI)
  await ensurePostgresBootstrap();
  
  await ensureServerDeps();

  // Auto-detect server host if not set
  if (!CONFIG.SERVER_HOST) {
    try {
      if (process.platform === 'win32') {
        const out = execSync('ipconfig', { encoding: 'utf8' });
        const match = out.match(/IPv4[^:]+:\s*([0-9.]+)/);
        CONFIG.SERVER_HOST = match ? match[1] : '127.0.0.1';
      } else {
        const out = execSync("hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'", { encoding: 'utf8', shell: true }).trim();
        CONFIG.SERVER_HOST = out || '127.0.0.1';
      }
    } catch {
      CONFIG.SERVER_HOST = '127.0.0.1';
    }
  }
  
  // Auto-generate server ID if not set
  if (!CONFIG.SERVER_ID) {
    CONFIG.SERVER_ID = `server-${os.hostname()}-${Date.now()}`;
  }
  
  // Auto-allocate port if not set
  if (!CONFIG.PORT) {
    log('Auto-allocating port...');
    try {
      CONFIG.PORT = String(await findAvailablePort(8443, 100));
      log(`Allocated port: ${CONFIG.PORT}`);
    } catch (err) {
      logErr(err.message);
      process.exit(1);
    }
  } else {
    // Validate specified port is available
    if (isPortInUse(CONFIG.PORT)) {
      logErr(`ERROR: Port ${CONFIG.PORT} is already in use`);
      logErr('Try specifying a different port: PORT=<number> node scripts/start-server.cjs');
      process.exit(1);
    }
  }

  if (typeof CONFIG.REDIS_URL !== 'string' || !CONFIG.REDIS_URL.startsWith('rediss://')) {
    logErr('ERROR: REDIS_URL must use rediss:// and TLS; plaintext redis:// is not supported.');
    process.exit(1);
  }

  // Ensure a local TLS Redis is running (for loopback URLs)
  await ensureRedisTls();

  // Print effective config
  log('Configuration:');
  log(`  Server ID: ${CONFIG.SERVER_ID}`);
  log(`  Server Host: ${CONFIG.SERVER_HOST}:${CONFIG.PORT}`);
  log(`  Redis: ${CONFIG.REDIS_URL}`);
  log(`  Clustering: ${CONFIG.ENABLE_CLUSTERING}`);
  log(`  Auto-Approve: ${CONFIG.AUTO_APPROVE}`);
  log(`  TLS Cert: ${CONFIG.TLS_CERT_PATH}`);
  log(`  TLS Key: ${CONFIG.TLS_KEY_PATH}`);

  // Environment for the server
  const env = {
    ...process.env,
    PORT: String(CONFIG.PORT),
    BIND_ADDRESS: CONFIG.BIND_ADDRESS,
    REDIS_URL: CONFIG.REDIS_URL,
    ENABLE_CLUSTERING: CONFIG.ENABLE_CLUSTERING,
    CLUSTER_WORKERS: CONFIG.CLUSTER_WORKERS,
    CLUSTER_PRIMARY: CONFIG.CLUSTER_PRIMARY,
    CLUSTER_AUTO_APPROVE: CONFIG.AUTO_APPROVE,
    ALLOWED_CORS_ORIGINS: CONFIG.ALLOWED_CORS_ORIGINS,
    SERVER_HOST: CONFIG.SERVER_HOST,
    SERVER_ID: CONFIG.SERVER_ID,
    USE_REDIS: CONFIG.USE_REDIS,
    DISABLE_CONNECTION_LIMIT: CONFIG.DISABLE_CONNECTION_LIMIT,
    KEY_ENCRYPTION_SECRET: CONFIG.KEY_ENCRYPTION_SECRET,
    TLS_CERT_PATH: CONFIG.TLS_CERT_PATH,
    TLS_KEY_PATH: CONFIG.TLS_KEY_PATH,
  };

  const serverJs = path.join(serverDir, 'server.js');
  if (!fs.existsSync(serverJs)) {
    logErr('server/server.js not found');
    process.exit(1);
  }

  log('Starting server ...');
  
  if (CONFIG.NO_GUI) {
    const child = spawn(process.execPath, [serverJs], {
      cwd: repoRoot,
      env,
      stdio: 'inherit',
    });

    let seenFirstSigint = false;

    const forwardSignal = (signal) => {
      if (!child || child.killed) return;
      try {
        child.kill(signal);
      } catch {}
    };

    const onSigint = () => {
      if (!seenFirstSigint) {
        seenFirstSigint = true;
        forwardSignal('SIGINT');
      } else {
        try {
          child.kill('SIGKILL');
        } catch {}
        process.exit(130);
      }
    };

    const onSigterm = () => {
      forwardSignal('SIGTERM');
    };

    process.on('SIGINT', onSigint);
    process.on('SIGTERM', onSigterm);

    child.on('exit', (code, signal) => {
      process.removeListener('SIGINT', onSigint);
      process.removeListener('SIGTERM', onSigterm);

      if (signal === 'SIGINT') {
        process.exit(130);
      }
      if (typeof code === 'number') {
        process.exit(code);
      }
      process.exit(0);
    });

    return;
  }
  
  // Start server with TUI
  const tmpDir = os.tmpdir();
  const logFile = path.join(tmpDir, `server-ui-${Date.now()}.log`);
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  
  const child = spawn(process.execPath, [serverJs], {
    cwd: repoRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  
  // Setup UI
  const ui = new ServerUI(child.pid, CONFIG);
  
  // Tail server output and capture last lines for error display
  const lastLines = [];
  const MAX_LAST = 80;
  const pushLast = (line) => {
    lastLines.push(line);
    if (lastLines.length > MAX_LAST) lastLines.shift();
  };
  const processOutput = (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) {
        logStream.write(line + '\n');
        ui.addLog(line);
        pushLast(line);
      }
    }
  };
  
  child.stdout.on('data', processOutput);
  child.stderr.on('data', processOutput);
  
  child.on('exit', (code) => {
    ui.stop(false);
    logStream.end();
    
    // Show errors if server crashed
    if (code !== 0) {
      console.error(`\n[ERROR] Server exited with code ${code}`);
      if (lastLines.length) {
        console.error('[ERROR] Last server log lines:');
        for (const l of lastLines) console.error('  ' + l);
      } else {
        console.error('[ERROR] No logs captured. Re-run with NO_GUI=true for raw output.');
      }
    }
    
    setTimeout(() => process.exit(code || 0), 200);
  });
  
  ui.start();
}

main().catch((e) => { logErr(e.message); process.exit(1); });
