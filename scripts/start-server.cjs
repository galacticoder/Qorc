#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execFileSync } = require('child_process');
const { URL } = require('url');

const repoRoot = path.resolve(__dirname, '..');

if (process.platform !== 'linux') {
  console.error('[ERROR] Native server deployment supports only Linux. Use Docker instead:');
  console.error('[ERROR]   node scripts/start-docker.cjs server');
  process.exit(1);
}

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
  } catch { }
}

loadDotEnv(path.join(repoRoot, '.env'));

function safeUpdateEnv(updates) {
  try {
    const envPath = path.join(repoRoot, '.env');
    let envText = '';
    try {
      envText = fs.readFileSync(envPath, 'utf8');
    } catch { }
    const lines = envText ? envText.split(/\r?\n/) : [];

    for (const [key, value] of Object.entries(updates)) {
      const line = `${key}=${value}`;
      const idx = lines.findIndex(l => l.trim().startsWith(key + '='));
      if (idx >= 0) {
        lines[idx] = line;
      } else {
        lines.push(line);
      }
      
      process.env[key] = value;
      if (key in CONFIG) CONFIG[key] = value;
    }

    const newEnv = lines.filter(Boolean).join('\n') + '\n';
    fs.writeFileSync(envPath, newEnv, 'utf8');
    log(`[OK] Updated .env: ${Object.keys(updates).join(', ')}`);
  } catch (e) {
    logErr(`[WARN] Failed to persist updates to .env: ${e.message}`);
    log(`[INFO] Current in-memory configuration is still valid.`);
  }
}

function fileExistsMaybeRelative(p) {
  if (!p) return false;
  const abs = path.isAbsolute(p) ? p : path.join(repoRoot, p);
  try { return fs.existsSync(abs); } catch { return false; }
}

const CONFIG = {
  PORT: process.env.PORT || '',
  BIND_ADDRESS: process.env.BIND_ADDRESS || '127.0.0.1',
  REDIS_URL: process.env.REDIS_URL || 'rediss://127.0.0.1:6379',
  ENABLE_CLUSTERING: process.env.ENABLE_CLUSTERING || 'true',
  CLUSTER_WORKERS: process.env.CLUSTER_WORKERS || '1',
  CLUSTER_PRIMARY: process.env.CLUSTER_PRIMARY || '',
  AUTO_APPROVE: process.env.CLUSTER_AUTO_APPROVE || 'true',
  ALLOWED_CORS_ORIGINS: process.env.ALLOWED_CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173',
  TLS_CERT_PATH: process.env.TLS_CERT_PATH || '',
  TLS_KEY_PATH: process.env.TLS_KEY_PATH || '',
  NO_GUI: (process.env.NO_GUI || 'false').toLowerCase() === 'true',
  SERVER_HOST: process.env.SERVER_HOST || '',
  SERVER_ID: process.env.SERVER_ID || '',
};

const serverDir = path.join(repoRoot, 'server');
const CERT_DIR = path.join(serverDir, 'config', 'certs');
const localRedisTls = path.join(repoRoot, 'server', 'bin', 'redis-server-tls');
const REDIS_SERVER_BIN = process.env.TLS_REDIS_SERVER ||
  (fs.existsSync(localRedisTls) ? localRedisTls : null) ||
  process.env.REDIS_SERVER_BIN ||
  'redis-server';

function log(...args) { console.log('[START]', ...args); }
function logErr(...args) { console.error('[START]', ...args); }

function safeUrlEndpointForDisplay(rawUrl, label) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) return `[unconfigured ${label}]`;
  try {
    const url = new URL(rawUrl);
    if (!url.protocol || !url.hostname) return `[invalid ${label}]`;
    return `${url.protocol}//${url.host}`;
  } catch {
    return `[invalid ${label}]`;
  }
}

function buildRedisCliInvocation(redisUrl, args) {
  let url;
  try {
    url = new URL(redisUrl);
  } catch {
    throw new Error('REDIS_URL is invalid');
  }
  if (url.protocol !== 'rediss:' || !url.hostname) {
    throw new Error('REDIS_URL must use rediss:// and include a host');
  }
  if (url.search || url.hash) {
    throw new Error('REDIS_URL must not contain query parameters or a fragment');
  }

  const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname;
  const port = url.port || '6379';
  if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
    throw new Error('REDIS_URL contains an invalid port');
  }

  const env = {};
  if (url.password) {
    try {
      env.REDISCLI_AUTH = decodeURIComponent(url.password);
    } catch {
      throw new Error('REDIS_URL contains an invalid password encoding');
    }
    url.password = '';
  } else if (process.env.REDIS_PASSWORD) {
    env.REDISCLI_AUTH = process.env.REDIS_PASSWORD;
  }

  const cliArgs = ['-h', hostname, '-p', port, '--tls'];

  if (url.username) {
    try {
      cliArgs.push('--user', decodeURIComponent(url.username));
    } catch {
      throw new Error('REDIS_URL contains an invalid username encoding');
    }
  }

  if (url.pathname && url.pathname !== '/') {
    let database;
    try {
      database = decodeURIComponent(url.pathname.slice(1));
    } catch {
      throw new Error('REDIS_URL contains an invalid database encoding');
    }
    if (!/^\d+$/.test(database)) {
      throw new Error('REDIS_URL contains an invalid database index');
    }
    cliArgs.push('-n', database);
  }

  cliArgs.push('--sni', process.env.REDIS_TLS_SERVERNAME || hostname);

  if (process.env.REDIS_CA_CERT_PATH) {
    cliArgs.push('--cacert', process.env.REDIS_CA_CERT_PATH);
  }
  if (process.env.REDIS_CLIENT_CERT_PATH) {
    cliArgs.push('--cert', process.env.REDIS_CLIENT_CERT_PATH);
  }
  if (process.env.REDIS_CLIENT_KEY_PATH) {
    cliArgs.push('--key', process.env.REDIS_CLIENT_KEY_PATH);
  }

  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    throw new Error('Invalid redis-cli arguments');
  }
  cliArgs.push(...args);

  return { cliArgs, env };
}

function runRedisCli(redisUrl, args, options = {}) {
  const { cliArgs, env } = buildRedisCliInvocation(redisUrl, args);
  const { env: optionEnv, ...execOptions } = options;
  return execFileSync('redis-cli', cliArgs, {
    ...execOptions,
    env: { ...process.env, ...optionEnv, ...env }
  });
}

function countEstablishedTcpConnections(portValue) {
  const port = Number(portValue);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return 0;

  const countOutput = (output, source) => {
    let count = 0;
    for (const line of output.split(/\r?\n/)) {
      const columns = line.trim().split(/\s+/);
      if (columns.length < 4) continue;

      const state = columns[columns.length - 1];
      const isEstablished = source === 'ss'
        ? columns[0] === 'ESTAB'
        : /^tcp/i.test(columns[0]) && state === 'ESTABLISHED';
      if (!isEstablished) continue;

      const localEndpoint = columns[3];
      if (localEndpoint.endsWith(`:${port}`) || localEndpoint.endsWith(`.${port}`)) {
        count += 1;
      }
    }
    return count;
  };

  try {
    const output = execFileSync('ss', ['-H', '-t', '-a', '-n'], {
      encoding: 'utf8',
      timeout: 500,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return countOutput(output, 'ss');
  } catch { }

  try {
    const output = execFileSync('netstat', ['-t', '-a', '-n'], {
      encoding: 'utf8',
      timeout: 500,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    return countOutput(output, 'netstat');
  } catch {
    return 0;
  }
}

function detectServerHost() {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses || []) {
      if (address.family === 'IPv4' && !address.internal) return address.address;
    }
  }
  return '127.0.0.1';
}

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

// Port checking
async function isPortInUse(port) {
  return new Promise((resolve) => {
    const server = require('net').createServer();
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        resolve(true);
      } else {
        resolve(false);
      }
    });
    server.once('listening', () => {
      server.close();
      resolve(false);
    });
    server.listen(port, '0.0.0.0');
  });
}

// Find available port starting from base
async function findAvailablePort(basePort = 8443, maxAttempts = 100) {
  for (let i = 0; i < maxAttempts; i++) {
    const candidatePort = basePort + i;
    if (!(await isPortInUse(candidatePort))) {
      return candidatePort;
    }
  }
  throw new Error(`No available ports found in range ${basePort}-${basePort + maxAttempts}`);
}

// Validate TLS certificates and attempt to fix permissions if unreadable
function validateTLSCertificates() {
  if (!CONFIG.TLS_CERT_PATH || !CONFIG.TLS_KEY_PATH) {
    logErr('ERROR: TLS_CERT_PATH and TLS_KEY_PATH must be set');
    logErr('Generate certificates with: node scripts/generate_tls.cjs');
    process.exit(1);
  }

  const certPath = path.isAbsolute(CONFIG.TLS_CERT_PATH)
    ? CONFIG.TLS_CERT_PATH
    : path.join(repoRoot, CONFIG.TLS_CERT_PATH);
  const keyPath = path.isAbsolute(CONFIG.TLS_KEY_PATH)
    ? CONFIG.TLS_KEY_PATH
    : path.join(repoRoot, CONFIG.TLS_KEY_PATH);

  if (!fs.existsSync(certPath)) {
    // If in Docker try to see if host path that we can Dockerize
    if (require('fs').existsSync('/.dockerenv') && certPath.startsWith('/')) {
      // find 'server/config/certs'
      const parts = certPath.split(path.sep);
      const certIdx = parts.indexOf('certs');
      if (certIdx > 0 && parts[certIdx - 1] === 'config' && parts[certIdx - 2] === 'server') {
        const guessedRel = path.join('server', 'config', 'certs', parts.slice(certIdx + 1).join(path.sep));
        const guessedAbs = path.join(repoRoot, guessedRel);
        if (fs.existsSync(guessedAbs)) {
          log(`[DOCKER] Resolving host cert path ${certPath} -> ${guessedAbs}`);
          CONFIG.TLS_CERT_PATH = guessedAbs;
          return validateTLSCertificates();
        }
      }
      // 2. try to find the filename anywhere in CERT_DIR
      const fileName = path.basename(certPath);
      const possible = path.join(CERT_DIR, fileName);
      if (fs.existsSync(possible)) {
        log(`[DOCKER] Correcting cert path to found file: ${possible}`);
        CONFIG.TLS_CERT_PATH = possible;
        return validateTLSCertificates();
      }
    }
    logErr(`ERROR: TLS cert not found: ${certPath}`);
    logErr('Generate certificates with: node scripts/generate_tls.cjs');
    process.exit(1);
  }

  if (!fs.existsSync(keyPath)) {
    if (require('fs').existsSync('/.dockerenv') && keyPath.startsWith('/')) {
      const parts = keyPath.split(path.sep);
      const certIdx = parts.indexOf('certs');
      if (certIdx > 0 && parts[certIdx - 1] === 'config' && parts[certIdx - 2] === 'server') {
        const guessedRel = path.join('server', 'config', 'certs', parts.slice(certIdx + 1).join(path.sep));
        const guessedAbs = path.join(repoRoot, guessedRel);
        if (fs.existsSync(guessedAbs)) {
          log(`[DOCKER] Resolving host key path ${keyPath} -> ${guessedAbs}`);
          CONFIG.TLS_KEY_PATH = guessedAbs;
          return validateTLSCertificates();
        }
      }
      const fileName = path.basename(keyPath);
      const possible = path.join(CERT_DIR, fileName);
      if (fs.existsSync(possible)) {
        log(`[DOCKER] Correcting key path to found file: ${possible}`);
        CONFIG.TLS_KEY_PATH = possible;
        return validateTLSCertificates();
      }
    }
    logErr(`ERROR: TLS key not found: ${keyPath}`);
    logErr('Generate certificates with: node scripts/generate_tls.cjs');
    process.exit(1);
  }

  try { fs.accessSync(certPath, fs.constants.R_OK); } catch (e) { tryFixTlsPerms(certPath, 0o644); }
  try { fs.accessSync(keyPath, fs.constants.R_OK); } catch (e) { tryFixTlsPerms(keyPath, 0o600); }

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

  CONFIG.TLS_CERT_PATH = certPath;
  CONFIG.TLS_KEY_PATH = keyPath;
}

function tryFixTlsPerms(p, mode) {
  try {
    const needSudo = !isWritableBySelf(p);
    if (needSudo && findSudo()) {
      const uid = process.getuid ? process.getuid() : null;
      const gid = process.getgid ? process.getgid() : null;
      const chownSpec = uid !== null && gid !== null ? `${uid}:${gid}` : '';
      if (chownSpec) {
        execFileSync('sudo', ['chown', chownSpec, p], { stdio: 'inherit' });
      }
      execFileSync('sudo', ['chmod', mode.toString(8), p], { stdio: 'inherit' });
    } else {
      try { fs.chmodSync(p, mode); } catch { }
    }
  } catch { }
}

function isWritableBySelf(p) {
  try {
    const st = fs.statSync(p);
    return process.getuid && st.uid === process.getuid();
  } catch { return false; }
}

function findSudo() {
  try {
    execFileSync('sudo', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

async function ensureServerDeps() {
  const nm = path.join(serverDir, 'node_modules');
  const hasNm = fs.existsSync(nm);
  const pkgLock = fs.existsSync(path.join(serverDir, 'package-lock.json'));
  const ciArgs = pkgLock ? ['ci', '--omit=dev'] : ['install', '--omit=dev'];
  if (!hasNm) {
    log('Installing server dependencies ...');
    await new Promise((resolve, reject) => {
      const child = spawn('npm', ciArgs, { cwd: serverDir, stdio: 'inherit' });
      child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`npm ${ciArgs[0]} failed: ${code}`)));
    });
  }
}

async function ensurePostgresBootstrap() {
  const dbName = process.env.PGDATABASE || 'Qor';
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
    logErr('Cannot auto-create Postgres DB: no TTY available for password prompt.');
    return;
  }

  log('[DB] Postgres not reachable; attempting auto-bootstrap...');

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

    this.width = process.stdout.columns || 80;
    this.height = (process.stdout.rows || 24) - 1;

    this.renderDebouncer = new Debouncer(() => this._doRender(), 100);

    process.stdout.on('resize', () => {
      this.width = process.stdout.columns || 80;
      this.height = (process.stdout.rows || 24) - 1;
      this.renderDebouncer.call();
    });

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (key) => this._handleInput(key));
    }

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
    if (line.includes('\r')) {
      const parts = line.split('\r');
      line = parts[parts.length - 1];
    }
    this.logBuffer.push(line);
    this.renderDebouncer.call();
  }

  async updateMetrics() {
    if (!this.metricsLimiter.canCall()) return;

    try {
      const metrics = {};

      try {
        const out = execFileSync(
          'ps',
          ['-p', String(this.serverPid), '-o', '%cpu=,%mem='],
          { encoding: 'utf8', timeout: 500 }
        ).trim();
        const parts = out.split(/\s+/);
        if (parts.length >= 2) {
          metrics.cpu = parts[0];
          metrics.mem = parts[1];
        }
      } catch { }
      // Connection count
      try {
        metrics.connections = countEstablishedTcpConnections(this.config.PORT);
      } catch { }

      // Redis cluster info
      try {
        if (!this.selfServerId) {
          const keys = runRedisCli(this.config.REDIS_URL, ['hkeys', 'cluster:servers'], {
            encoding: 'utf8',
            timeout: 700
          }).trim().split('\n');

          for (const key of keys) {
            const val = runRedisCli(this.config.REDIS_URL, ['hget', 'cluster:servers', key], {
              encoding: 'utf8',
              timeout: 700
            }).trim();
            try {
              const data = JSON.parse(val);
              if (data.port == this.config.PORT || data.pid == this.serverPid) {
                this.selfServerId = key;
                break;
              }
            } catch { }
          }
        }

        if (this.selfServerId) {
          const val = runRedisCli(this.config.REDIS_URL, ['hget', 'cluster:servers', this.selfServerId], {
            encoding: 'utf8',
            timeout: 700
          }).trim();
          const data = JSON.parse(val);
          metrics.heartbeatAge = Math.floor((Date.now() - (data.lastHeartbeat || 0)) / 1000);
          metrics.registered = true;
        } else {
          metrics.registered = false;
        }
      } catch { }

      if (Date.now() - this.lastTlsCheck > 10000) {
        this.lastTlsCheck = Date.now();
        try {
          if (this.config.TLS_CERT_PATH && fs.existsSync(this.config.TLS_CERT_PATH)) {
            const subj = execFileSync(
              'openssl',
              ['x509', '-in', this.config.TLS_CERT_PATH, '-noout', '-subject'],
              { encoding: 'utf8', timeout: 600 }
            ).trim();
            const end = execFileSync(
              'openssl',
              ['x509', '-in', this.config.TLS_CERT_PATH, '-noout', '-enddate'],
              { encoding: 'utf8', timeout: 600 }
            ).trim();

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
        } catch { }
      }

      this.lastMetrics = metrics;
    } catch { }
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

    let alive = false;
    try {
      process.kill(this.serverPid, 0);
      alive = true;
    } catch { }

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
            display = '[invalid DATABASE_URL]';
          }
        }
        if (!display) {
          const hostName = process.env.PGHOST || '127.0.0.1';
          const port = process.env.PGPORT || '5432';
          const dbName = process.env.PGDATABASE || 'Qor';
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

    // Header
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
    lines.push('\x1b[30;46;1m' + headerLine + '\x1b[0m');

    // Stats line
    const uptimeTxt = `UP ${fmtTime(uptime)}`;
    const connTxt = `CONN ${conns}`;
    const hbPlain = hbAge !== null ? `HB ${hbAge}s` : 'HB ?';
    const rightStatsPlain = `${hbPlain}   ${uptimeTxt}   ${connTxt}`;
    const rightStatsStart = Math.max(1, w - rightStatsPlain.length - 1);

    let statsLine = '';
    // Redis
    statsLine += `\x1b[36mRedis: ${safeUrlEndpointForDisplay(this.config.REDIS_URL, 'REDIS_URL')}\x1b[0m`;
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

    const output = '\x1b[?25l' + '\x1b[H' + lines.join('\n');
    try {
      process.stdout.write(output);
    } catch { }
  }

  render() {
    this.renderDebouncer.call();
  }

  stop(preserve = false) {
    if (!this.running) return;
    this.running = false;
    this.renderDebouncer.flush();

    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
      this.metricsInterval = null;
    }

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }
    if (!preserve) {
      process.stdout.write('\x1b[?7h\x1b[?25h\x1b[?1049l');
    } else {
      process.stdout.write('\x1b[?7h\x1b[?25h\x1b[?1049l');
    }

    try {
      process.kill(this.serverPid, 'SIGTERM');
      setTimeout(() => {
        try { process.kill(this.serverPid, 'SIGKILL'); } catch { }
      }, 2000);
    } catch { }
  }

  start() {
    this.render();
    this.metricsInterval = setInterval(() => {
      this.updateMetrics().then(() => this.render());
    }, 1000);
    process.on('SIGINT', () => this.stop());
    process.on('SIGTERM', () => this.stop());
  }
}

async function ensureTLSIfMissing() {
  const hasCert = CONFIG.TLS_CERT_PATH && fileExistsMaybeRelative(CONFIG.TLS_CERT_PATH);
  const hasKey = CONFIG.TLS_KEY_PATH && fileExistsMaybeRelative(CONFIG.TLS_KEY_PATH);
  if (hasCert && hasKey) return;

  log('TLS certificates not found. Generating new certificates...');

  const child = spawn(process.execPath, [path.join(repoRoot, 'scripts', 'generate_tls.cjs')], { cwd: repoRoot, stdio: ['inherit', 'pipe', 'inherit'] });

  let capturedOutput = '';
  child.stdout.on('data', (data) => {
    const str = data.toString();
    process.stdout.write(str);
    capturedOutput += str;
  });

  const code = await new Promise((r) => child.on('exit', (c) => r(c || 0)));

  if (code !== 0) {
    logErr('TLS generation failed. Aborting.');
    process.exit(code);
  }

  loadDotEnv(path.join(repoRoot, '.env'));

  // 1. Try output from child
  let capturedPaths = null;
  const jsonMatch = capturedOutput.match(/\[JSON_PATHS\] (.+)/);
  if (jsonMatch) {
    try {
      capturedPaths = JSON.parse(jsonMatch[1]);
      log(`[START] Captured TLS paths from generator: ${JSON.stringify(capturedPaths)}`);
    } catch { }
  }

  if (capturedPaths) {
    if (capturedPaths.TLS_CERT_PATH) CONFIG.TLS_CERT_PATH = capturedPaths.TLS_CERT_PATH;
    if (capturedPaths.TLS_KEY_PATH) CONFIG.TLS_KEY_PATH = capturedPaths.TLS_KEY_PATH;
  }

  // 2. If reload or capture didnt work try to guess by scanning CERT_DIR
  try {
    if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });
    const dnsMatch = fs.readdirSync(CERT_DIR).find(f => f.endsWith('.crt'));
    if (dnsMatch) {
      const dns = dnsMatch.replace('.crt', '');
      const relCert = `server/config/certs/${dns}.crt`;
      const relKey = `server/config/certs/${dns}.key`;

      const absCert = path.join(repoRoot, relCert);
      if (!CONFIG.TLS_CERT_PATH || !fs.existsSync(path.isAbsolute(CONFIG.TLS_CERT_PATH) ? CONFIG.TLS_CERT_PATH : path.join(repoRoot, CONFIG.TLS_CERT_PATH))) {
        if (fs.existsSync(absCert)) {
          log(`[START] Found generated certificate via scan: ${relCert}`);
          CONFIG.TLS_CERT_PATH = relCert;
        }
      }
      const absKey = path.join(repoRoot, relKey);
      if (!CONFIG.TLS_KEY_PATH || !fs.existsSync(path.isAbsolute(CONFIG.TLS_KEY_PATH) ? CONFIG.TLS_KEY_PATH : path.join(repoRoot, CONFIG.TLS_KEY_PATH))) {
        if (fs.existsSync(absKey)) {
          log(`[START] Found generated key via scan: ${relKey}`);
          CONFIG.TLS_KEY_PATH = relKey;
        }
      }
    }
  } catch (e) {
    logErr(`[START] Warning: Failed to scan ${CERT_DIR} for certs: ${e.message}`);
  }

  if (process.env.TLS_CERT_PATH && !CONFIG.TLS_CERT_PATH) {
    CONFIG.TLS_CERT_PATH = process.env.TLS_CERT_PATH;
  }
  if (process.env.TLS_KEY_PATH && !CONFIG.TLS_KEY_PATH) {
    CONFIG.TLS_KEY_PATH = process.env.TLS_KEY_PATH;
  }
  log('');
}

async function ensureDbCaBundleEnv() {
  if (process.env.DATABASE_CA_CERT) return;

  const pinnedPath = process.env.PGSSLROOTCERT;
  if (!pinnedPath) {
    throw new Error('PGSSLROOTCERT or DATABASE_CA_CERT is required');
  }
  const resolved = path.resolve(pinnedPath);
  let certificate;
  try {
    certificate = fs.readFileSync(resolved, 'utf8');
  } catch (error) {
    throw new Error(`PGSSLROOTCERT is unreadable at '${resolved}': ${error.message}`);
  }
  if (!certificate.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error(`PGSSLROOTCERT is not a PEM certificate bundle: '${resolved}'`);
  }
  process.env.PGSSLROOTCERT = resolved;
}

async function ensureRedisTls() {
  const rawUrl = CONFIG.REDIS_URL;
  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch {
    logErr('ERROR: REDIS_URL is invalid.');
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

  // Only auto manage a local Redis instance
  const isLoopback = host === '127.0.0.1' || host === 'localhost';
  if (!isLoopback) {
    return;
  }

  try {
    const out = runRedisCli(rawUrl, ['PING'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 1500
    }).trim();
    if (/PONG/i.test(out)) {
      log(`Detected existing TLS Redis at ${safeUrlEndpointForDisplay(rawUrl, 'REDIS_URL')}; reusing.`);
      return;
    }
  } catch (_e) {
  }

  const usingLocalTlsRedis = !!process.env.TLS_REDIS_SERVER;
  if (!usingLocalTlsRedis) {
    let helpOutput = '';
    try {
      helpOutput = execFileSync(REDIS_SERVER_BIN, ['--help'], { encoding: 'utf8' });
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

  if (!process.env.REDIS_TLS_SERVERNAME && CONFIG.TLS_CERT_PATH && fs.existsSync(CONFIG.TLS_CERT_PATH)) {
    try {
      const subj = execFileSync(
        'openssl',
        ['x509', '-in', CONFIG.TLS_CERT_PATH, '-noout', '-subject'],
        { encoding: 'utf8' }
      ).trim();
      const cnMatch = subj.match(/CN\s*=\s*([^,/]+)/);
      if (cnMatch) {
        process.env.REDIS_TLS_SERVERNAME = cnMatch[1].trim();
        log(`[START] Using REDIS_TLS_SERVERNAME derived from TLS cert CN: ${process.env.REDIS_TLS_SERVERNAME}`);
      }
    } catch (e) {
      logErr('[START] WARN: Failed to derive REDIS_TLS_SERVERNAME from TLS cert: ' + e.message);
    }
  }

  if (!process.env.REDIS_CA_CERT_PATH && CONFIG.TLS_CERT_PATH) {
    const absCert = path.isAbsolute(CONFIG.TLS_CERT_PATH) ? CONFIG.TLS_CERT_PATH : path.join(repoRoot, CONFIG.TLS_CERT_PATH);
    if (fs.existsSync(absCert)) {
      process.env.REDIS_CA_CERT_PATH = absCert;
      log(`[START] Using REDIS_CA_CERT_PATH from local TLS cert: ${absCert}`);
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
    logErr('ERROR: TLS_CERT_PATH and TLS_KEY_PATH must be set before starting Redis.');
    process.exit(1);
  }

  try {
    execFileSync(REDIS_SERVER_BIN, ['--version'], { stdio: 'ignore' });
  } catch {
    logErr(`ERROR: ${REDIS_SERVER_BIN} not found or not executable; install Redis with TLS support or set TLS_REDIS_SERVER to a TLS-capable binary.`);
    process.exit(1);
  }

  const redisArgs = [
    '--port', '0',
    '--tls-port', String(port),
    '--tls-cert-file', CONFIG.TLS_CERT_PATH,
    '--tls-key-file', CONFIG.TLS_KEY_PATH,
    '--tls-auth-clients', 'no',
  ];

  try {
    log('[START] Auto-starting local TLS Redis:', `${REDIS_SERVER_BIN} ${redisArgs.join(' ')}`);
    spawn(REDIS_SERVER_BIN, redisArgs, { cwd: repoRoot, stdio: 'ignore' });

    const newUrl = `rediss://${host}:${port}`;
    CONFIG.REDIS_URL = newUrl;
    process.env.REDIS_URL = newUrl;

    safeUpdateEnv({
      'REDIS_URL': newUrl,
      ...(process.env.REDIS_TLS_SERVERNAME ? { 'REDIS_TLS_SERVERNAME': process.env.REDIS_TLS_SERVERNAME } : {})
    });
  } catch (e) {
    logErr('[START] WARN: Failed to handle local TLS Redis: ' + e.message);
  }
}


async function main() {
  if (!CONFIG.NO_GUI) {
    console.log("Starting Server...");
  }

  await ensureTLSIfMissing();
  validateTLSCertificates();
  await ensureDbCaBundleEnv();
  await ensurePostgresBootstrap();
  await ensureServerDeps();
  try {
    if (!process.env.REDIS_CA_CERT_PATH || !process.env.REDIS_CLIENT_CERT_PATH || !process.env.REDIS_CLIENT_KEY_PATH) {
      const dockerCertsDir = '/app/redis-certs';
      const isDocker = fs.existsSync(dockerCertsDir);

      const certsDir = isDocker ? dockerCertsDir : path.join(repoRoot, 'redis-certs');

      const redisCaCert = path.join(certsDir, 'redis-ca.crt');
      const redisClientCert = path.join(certsDir, 'redis-client.crt');
      const redisClientKey = path.join(certsDir, 'redis-client.key');

      let certsExist = false;
      const maxWaitTime = 30000;
      const checkInterval = 500;
      const startTime = Date.now();

      if (isDocker) {
        log('[START] Waiting for Redis SSL certificates to be ready...');
        while (!certsExist && (Date.now() - startTime) < maxWaitTime) {
          if (fs.existsSync(redisCaCert) && fs.existsSync(redisClientCert) && fs.existsSync(redisClientKey)) {
            try {
              const caCert = fs.readFileSync(redisCaCert, 'utf8');
              const clientCert = fs.readFileSync(redisClientCert, 'utf8');
              const clientKey = fs.readFileSync(redisClientKey, 'utf8');
              if (caCert && caCert.includes('BEGIN CERTIFICATE') &&
                clientCert && clientCert.includes('BEGIN CERTIFICATE') &&
                clientKey && (clientKey.includes('BEGIN') && clientKey.includes('KEY'))) {
                certsExist = true;
                break;
              }
            } catch (e) {
            }
          }
          await new Promise(resolve => setTimeout(resolve, checkInterval));
        }

        if (!certsExist) {
          logErr(`[START] WARN: Redis certificates not found in ${certsDir} after ${maxWaitTime}ms`);
        }
      } else {
        certsExist = fs.existsSync(redisCaCert) && fs.existsSync(redisClientCert) && fs.existsSync(redisClientKey);
      }

      if (certsExist) {
        if (!process.env.REDIS_CA_CERT_PATH) {
          process.env.REDIS_CA_CERT_PATH = redisCaCert;
          log(`[START] Set REDIS_CA_CERT_PATH=${redisCaCert}`);
        }
        if (!process.env.REDIS_CLIENT_CERT_PATH) {
          process.env.REDIS_CLIENT_CERT_PATH = redisClientCert;
          log(`[START] Set REDIS_CLIENT_CERT_PATH=${redisClientCert}`);
        }
        if (!process.env.REDIS_CLIENT_KEY_PATH) {
          process.env.REDIS_CLIENT_KEY_PATH = redisClientKey;
          log(`[START] Set REDIS_CLIENT_KEY_PATH=${redisClientKey}`);
        }

        safeUpdateEnv({
          'REDIS_CA_CERT_PATH': path.relative(repoRoot, redisCaCert),
          'REDIS_CLIENT_CERT_PATH': path.relative(repoRoot, redisClientCert),
          'REDIS_CLIENT_KEY_PATH': path.relative(repoRoot, redisClientKey)
        });
      }
    }
  } catch (e) {
    logErr('[START] WARN: Failed to handle Redis certificates: ' + e.message);
  }

  // Auto-detect server host if not set
  if (!CONFIG.SERVER_HOST) {
    CONFIG.SERVER_HOST = detectServerHost();
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
    if (await isPortInUse(CONFIG.PORT)) {
      logErr(`ERROR: Port ${CONFIG.PORT} is already in use`);
      logErr('Try specifying a different port: PORT=<number> node scripts/start-server.cjs');
      process.exit(1);
    }
  }

  if (typeof CONFIG.REDIS_URL !== 'string' || !CONFIG.REDIS_URL.startsWith('rediss://')) {
    logErr('ERROR: REDIS_URL must use rediss:// and TLS; plaintext redis:// is not supported.');
    process.exit(1);
  }

  await ensureRedisTls();

  log('Configuration:');
  log(`  Server ID: ${CONFIG.SERVER_ID}`);
  log(`  Server Host: ${CONFIG.SERVER_HOST}:${CONFIG.PORT}`);
  log(`  Redis: ${safeUrlEndpointForDisplay(CONFIG.REDIS_URL, 'REDIS_URL')}`);
  log(`  Clustering: ${CONFIG.ENABLE_CLUSTERING}`);
  log(`  Auto-Approve: ${CONFIG.AUTO_APPROVE}`);
  log(`  TLS Cert: ${CONFIG.TLS_CERT_PATH}`);
  log(`  TLS Key: ${CONFIG.TLS_KEY_PATH}`);

  const serverEnv = {
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
      env: serverEnv,
      stdio: 'inherit',
    });

    let seenFirstSigint = false;

    const forwardSignal = (signal) => {
      if (!child || child.killed) return;
      try {
        child.kill(signal);
      } catch { }
    };

    const onSigint = () => {
      if (!seenFirstSigint) {
        seenFirstSigint = true;
        forwardSignal('SIGINT');
      } else {
        try {
          child.kill('SIGKILL');
        } catch { }
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

  const tmpD = os.tmpdir();
  const logF = path.join(tmpD, `server-ui-${Date.now()}.log`);
  const logS = fs.createWriteStream(logF, { flags: 'a' });

  const childServer = spawn(process.execPath, [serverJs], {
    cwd: repoRoot,
    env: serverEnv,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  // Setup TUI
  const uiTui = new ServerUI(childServer.pid, CONFIG);

  const lastLinesArr = [];
  const MAX_LAST_LOG = 80;
  const pushLastLog = (line) => {
    lastLinesArr.push(line);
    if (lastLinesArr.length > MAX_LAST_LOG) lastLinesArr.shift();
  };
  const processOutputLog = (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.trim()) {
        logS.write(line + '\n');
        uiTui.addLog(line);
        pushLastLog(line);
      }
    }
  };

  childServer.stdout.on('data', processOutputLog);
  childServer.stderr.on('data', processOutputLog);

  childServer.on('exit', (code) => {
    uiTui.stop(false);
    logS.end();

    if (code !== 0) {
      console.error(`\n[ERROR] Server exited with code ${code}`);
      if (lastLinesArr.length) {
        console.error('[ERROR] Last server log lines:');
        for (const l of lastLinesArr) console.error('  ' + l);
      } else {
        console.error('[ERROR] No logs captured. Re-run with NO_GUI=true for raw output.');
      }
    }

    setTimeout(() => process.exit(code || 0), 200);
  });

  uiTui.start();
}

main().catch((e) => { logErr(e.message); process.exit(1); });
