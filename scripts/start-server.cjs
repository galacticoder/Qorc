#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { X509Certificate } = require('crypto');
const { spawn, execFile, execFileSync } = require('child_process');
const { URL, pathToFileURL } = require('url');
const {
  parseRegistration,
} = require('./server-tui-state.cjs');

const repoRoot = path.resolve(__dirname, '..');
const redisKeysModuleUrl = pathToFileURL(
  path.join(repoRoot, 'server', 'config', 'redis-keys.js')
).href;
let redisKeysPromise = null;

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
  if ((process.env.REDIS_CLUSTER_NODES || '').trim().length > 0) {
    cliArgs.push('-c');
  }

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

function execFileOutput(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {
      encoding: 'utf8',
      timeout: 1000,
      maxBuffer: 1024 * 1024,
      ...options,
    }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(String(stdout || ''));
    });
  });
}

async function runRedisCliAsync(redisUrl, args, options = {}) {
  const { cliArgs, env } = buildRedisCliInvocation(redisUrl, args);
  return execFileOutput('redis-cli', cliArgs, {
    ...options,
    env: { ...process.env, ...(options.env || {}), ...env },
  });
}

async function getRedisKeys() {
  if (!redisKeysPromise) {
    redisKeysPromise = import(redisKeysModuleUrl)
      .then((module) => module.REDIS_KEYS)
      .catch((error) => {
        redisKeysPromise = null;
        throw error;
      });
  }
  return redisKeysPromise;
}

async function readProcessMetrics(pid) {
  try {
    const output = await execFileOutput(
      'ps',
      ['-p', String(pid), '-o', '%cpu=,%mem='],
      { timeout: 500 }
    );
    const values = output.trim().split(/\s+/);
    return values.length >= 2 ? { cpu: values[0], mem: values[1] } : null;
  } catch {
    return null;
  }
}

async function readTlsCertificate(certPath) {
  if (!certPath) return { state: 'missing', cn: null, days: null };
  try {
    const pem = await fs.promises.readFile(certPath);
    const certificate = new X509Certificate(pem);
    const expiresAt = Date.parse(certificate.validTo);
    const cnMatch = certificate.subject.match(/(?:^|\n)CN\s*=\s*([^\n,]+)/);
    const days = Number.isFinite(expiresAt)
      ? Math.ceil((expiresAt - Date.now()) / (1000 * 60 * 60 * 24))
      : null;
    return {
      state: days !== null && days < 0 ? 'expired' : 'valid',
      cn: cnMatch ? cnMatch[1].trim() : null,
      days,
    };
  } catch {
    return { state: 'unavailable', cn: null, days: null };
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

const ANSI_SEQUENCE = /\x1b\[[0-?]*[ -/]*[@-~]/g;
const NON_SGR_ANSI_SEQUENCE = /\x1b\[(?![0-9;]*m)[0-?]*[ -/]*[@-~]/g;

function sanitizeTerminalLog(value) {
  return String(value)
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(NON_SGR_ANSI_SEQUENCE, '')
    .replace(/\t/g, '  ')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/g, '');
}

function createLineCollector(onLine) {
  let pending = '';
  return {
    push(chunk) {
      const parts = (pending + String(chunk)).split(/\r\n|\n|\r/);
      pending = parts.pop() || '';
      for (const line of parts) onLine(line);
    },
    flush() {
      if (pending.length > 0) onLine(pending);
      pending = '';
    },
  };
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

async function validateServerDeps() {
  const nm = path.join(serverDir, 'node_modules');
  const hasNm = fs.existsSync(nm);
  const requiredPackages = [
    'express',
    'ioredis',
    'pg',
  ];
  if (!CONFIG.NO_GUI) requiredPackages.push('@rezi-ui/core', '@rezi-ui/node');
  const hasRequiredPackages = requiredPackages.every((packageName) => {
    try {
      require.resolve(packageName, { paths: [serverDir] });
      return true;
    } catch {
      return false;
    }
  });
  const pkgLock = fs.existsSync(path.join(serverDir, 'package-lock.json'));
  const installArgs = pkgLock && !hasNm
    ? ['ci', '--omit=dev']
    : ['install', '--omit=dev'];
  if (!hasRequiredPackages) {
    log('Installing server dependencies ...');
    await new Promise((resolve, reject) => {
      const child = spawn('npm', installArgs, { cwd: serverDir, stdio: 'inherit' });
      child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`npm ${installArgs[0]} failed: ${code}`)));
    });
  }
}

async function validatePostgresBootstrap() {
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

class ReziServerUI {
  constructor(serverProcess, config) {
    this.serverProcess = serverProcess;
    this.serverPid = serverProcess.pid;
    this.config = config;
    this.clusteringEnabled = String(config.ENABLE_CLUSTERING).toLowerCase() === 'true';
    this.logBuffer = new CircularBuffer(1000);
    this.logSequence = 0;
    this.running = true;
    this.shutdownRequested = false;
    this.startTime = Date.now();
    this.lastMetrics = {
      cpu: null,
      mem: null,
      registration: this.clusteringEnabled ? 'checking' : 'standalone',
      heartbeatAge: null,
      redisState: 'checking',
      updatedAt: null,
    };
    this.metricsLimiter = new RateLimiter(1000);
    this.metricsInFlight = null;
    this.lastRegistrationCheck = 0;
    this.registrationCheckInterval = 2000;
    this.tlsCache = { state: 'checking', cn: null, days: null };
    this.lastTlsCheck = 0;
    this.dashboard = null;
    this.stopPromise = null;
  }

  addLog(line) {
    if (line.includes('\r')) {
      const parts = line.split('\r');
      line = parts[parts.length - 1];
    }
    const cleanLine = sanitizeTerminalLog(line);
    const entry = this.logEntryFactory
      ? this.logEntryFactory(cleanLine, ++this.logSequence, 'server')
      : {
          id: `server-${++this.logSequence}`,
          timestamp: Date.now(),
          level: /\b(error|fatal|panic|failed)\b/i.test(cleanLine) ? 'error' : (/\bwarn/i.test(cleanLine) ? 'warn' : 'info'),
          source: 'server',
          message: cleanLine.replace(ANSI_SEQUENCE, ''),
        };
    this.logBuffer.push(entry);
    this.render();
  }

  updateMetrics() {
    if (this.metricsInFlight || !this.metricsLimiter.canCall()) return this.metricsInFlight;
    this.metricsInFlight = this._updateMetricsOnce().finally(() => {
      this.metricsInFlight = null;
      if (this.running) this.render();
    });
    return this.metricsInFlight;
  }

  async _updateMetricsOnce() {
    const now = Date.now();
    const tasks = [
      readProcessMetrics(this.serverPid).then((metrics) => {
        if (!metrics) return;
        this.lastMetrics.cpu = metrics.cpu;
        this.lastMetrics.mem = metrics.mem;
      }),
    ];

    if (now - this.lastRegistrationCheck >= this.registrationCheckInterval) {
      this.lastRegistrationCheck = now;
      tasks.push(this.clusteringEnabled ? this._refreshRegistration() : this._refreshRedisStatus());
    }
    if (now - this.lastTlsCheck >= 60000) {
      this.lastTlsCheck = now;
      tasks.push(readTlsCertificate(this.config.TLS_CERT_PATH).then((tls) => {
        this.tlsCache = tls;
      }));
    }

    await Promise.allSettled(tasks);
    this.lastMetrics.updatedAt = Date.now();
  }

  async _refreshRegistration() {
    try {
      const redisKeys = await getRedisKeys();
      const rawValue = await runRedisCliAsync(
        this.config.REDIS_URL,
        ['hget', redisKeys.CLUSTER_SERVERS, String(this.config.SERVER_ID)],
        { timeout: 900 }
      );
      const registration = parseRegistration(rawValue.trim(), Date.now());
      this.lastMetrics.registration = registration.registration;
      this.lastMetrics.heartbeatAge = registration.heartbeatAge;
      this.lastMetrics.redisState = 'live';
    } catch {
      const hadLiveState = ['live', 'stale'].includes(this.lastMetrics.redisState);
      this.lastMetrics.redisState = hadLiveState ? 'stale' : 'unavailable';
      if (!hadLiveState) this.lastMetrics.registration = 'unavailable';
    }
  }

  async _refreshRedisStatus() {
    try {
      const response = await runRedisCliAsync(this.config.REDIS_URL, ['PING'], { timeout: 900 });
      if (!/PONG/i.test(response)) throw new Error('Unexpected Redis PING response');
      this.lastMetrics.redisState = 'live';
    } catch {
      const hadLiveState = ['live', 'stale'].includes(this.lastMetrics.redisState);
      this.lastMetrics.redisState = hadLiveState ? 'stale' : 'unavailable';
    }
  }

  _truncate(value, maxLength) {
    const text = value ? String(value) : 'unknown';
    if (text.length <= maxLength) return text;
    const head = Math.floor((maxLength - 1) / 2);
    return `${text.slice(0, head)}…${text.slice(-(maxLength - head - 1))}`;
  }

  _databaseDisplay(maxLength = 80) {
    const rawUrl = process.env.DATABASE_URL;
    let display = null;
    if (typeof rawUrl === 'string' && rawUrl.length > 0) {
      try {
        const url = new URL(rawUrl);
        const protocol = url.protocol.replace(/:$/, '') || 'postgres';
        const port = url.port ? `:${url.port}` : '';
        const database = url.pathname ? url.pathname.replace(/^\//, '') : '';
        display = `${protocol}://${url.hostname || 'localhost'}${port}${database ? `/${database}` : ''}`;
      } catch {
        display = '[invalid DATABASE_URL]';
      }
    }
    if (!display) {
      const host = process.env.DB_CONNECT_HOST || process.env.PGHOST || '127.0.0.1';
      const port = process.env.PGPORT || '5432';
      const database = process.env.PGDATABASE || process.env.DB_NAME || 'Qor';
      display = `postgres://${host}:${port}/${database}`;
    }
    return this._truncate(display, maxLength);
  }

  _formatUptime(totalSeconds) {
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (days) return `${days}d ${hours}h ${minutes}m`;
    if (hours) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  }

  _registrationLabel() {
    return {
      standalone: 'Standalone',
      registered: this.lastMetrics.redisState === 'stale' ? 'Registered · stale' : 'Registered',
      pending: 'Pending',
      checking: 'Checking',
      corrupt: 'Invalid entry',
      unavailable: 'Unavailable',
    }[this.lastMetrics.registration] || 'Unavailable';
  }

  _tlsLabel() {
    const tls = this.tlsCache;
    if (tls.state === 'checking') return 'Checking';
    if (tls.state === 'missing') return 'Missing';
    if (tls.state === 'unavailable') return 'Unreadable';
    if (tls.state === 'expired') return 'Expired';
    const identity = tls.cn ? ` ${this._truncate(tls.cn, 24)}` : '';
    const remaining = tls.days === null ? '' : ` · ${tls.days}d`;
    return `TLS${identity}${remaining}`;
  }

  _overallStatus() {
    const metrics = this.lastMetrics;
    if (metrics.redisState === 'checking') return { state: 'starting', label: 'Starting' };
    if (
      ['expired', 'missing', 'unavailable'].includes(this.tlsCache.state) ||
      (this.tlsCache.days !== null && this.tlsCache.days < 3)
    ) return { state: 'degraded', label: 'Degraded' };
    if (metrics.registration === 'standalone') {
      return metrics.redisState === 'live'
        ? { state: 'healthy', label: '' }
        : { state: 'degraded', label: 'Redis offline' };
    }
    if (['checking', 'pending'].includes(metrics.registration)) return { state: 'starting', label: 'Starting' };
    if (
      metrics.registration !== 'registered' ||
      metrics.redisState !== 'live' ||
      metrics.heartbeatAge === null ||
      metrics.heartbeatAge >= 30
    ) return { state: 'degraded', label: 'Degraded' };
    return { state: 'healthy', label: '' };
  }

  _snapshot() {
    const overall = this._overallStatus();
    const heartbeat = this.lastMetrics.heartbeatAge === null ? '—' : `${this.lastMetrics.heartbeatAge}s ago`;
    return {
      pid: this.serverPid,
      serverId: this.config.SERVER_ID || 'unknown',
      endpoint: `${this.config.SERVER_HOST || '127.0.0.1'}:${this.config.PORT}`,
      uptime: this._formatUptime(Math.floor((Date.now() - this.startTime) / 1000)),
      cpu: this.lastMetrics.cpu,
      mem: this.lastMetrics.mem,
      status: overall.state,
      statusLabel: overall.label,
      registration: this.lastMetrics.registration,
      registrationLabel: this._registrationLabel(),
      heartbeat,
      tlsState: this.tlsCache.state,
      tlsLabel: this._tlsLabel(),
      redisState: this.lastMetrics.redisState,
      redis: safeUrlEndpointForDisplay(this.config.REDIS_URL, 'REDIS_URL'),
      database: this._databaseDisplay(),
      logs: [...this.logBuffer.getAll()],
    };
  }

  render() {
    if (this.running && this.dashboard) this.dashboard.update(this._snapshot());
  }

  stop(terminateServer = true) {
    if (terminateServer) this.shutdownRequested = true;
    if (this.stopPromise) return this.stopPromise;
    this.running = false;
    if (this.metricsInterval) clearInterval(this.metricsInterval);
    this.metricsInterval = null;
    if (this.sigintHandler) process.removeListener('SIGINT', this.sigintHandler);
    if (this.sigtermHandler) process.removeListener('SIGTERM', this.sigtermHandler);

    if (
      terminateServer &&
      this.serverProcess.exitCode === null &&
      this.serverProcess.signalCode === null
    ) {
      try { this.serverProcess.kill('SIGTERM'); } catch { }
      this.forceKillTimer = setTimeout(() => {
        if (this.serverProcess.exitCode === null && this.serverProcess.signalCode === null) {
          try { this.serverProcess.kill('SIGKILL'); } catch { }
        }
      }, 2000);
      this.forceKillTimer.unref?.();
    }

    this.stopPromise = this.dashboard
      ? this.dashboard.stop().catch(() => {})
      : Promise.resolve();
    return this.stopPromise;
  }

  async start() {
    const { createServerDashboard, logEntry } = await import('./qor-rezi-tui.js');
    this.logEntryFactory = logEntry;
    this.dashboard = createServerDashboard(this._snapshot(), {
      stop: () => { void this.stop(); },
    });
    await this.dashboard.start();
    this.render();
    void this.updateMetrics();
    this.metricsInterval = setInterval(() => void this.updateMetrics(), 1000);
    this.sigintHandler = () => { void this.stop(); };
    this.sigtermHandler = () => { void this.stop(); };
    process.on('SIGINT', this.sigintHandler);
    process.on('SIGTERM', this.sigtermHandler);
  }
}

async function checkTLSIfMissing() {
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

async function validateDbCaBundleEnv() {
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

async function validateRedisTls() {
  const rawUrl = CONFIG.REDIS_URL;
  let urlObj;
  try {
    urlObj = new URL(rawUrl);
  } catch {
    logErr('ERROR: REDIS_URL is invalid.');
    process.exit(1);
  }

  if (urlObj.protocol !== 'rediss:') {
    logErr('ERROR: REDIS_URL must use rediss:// and TLS.');
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
  } else if (await isPortInUse(port)) {
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
    logErr(`ERROR: ${REDIS_SERVER_BIN} not found or not executable, install Redis with TLS support or set TLS_REDIS_SERVER to a TLS-capable binary.`);
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
  const useTui = !CONFIG.NO_GUI && Boolean(process.stdin.isTTY && process.stdout.isTTY);
  if (useTui) {
    console.log("Starting Server...");
  }

  await checkTLSIfMissing();
  validateTLSCertificates();
  await validateDbCaBundleEnv();
  await validatePostgresBootstrap();
  await validateServerDeps();
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

  // Auto-allocate port if unset or explicitly requested as dynamic.
  const configuredPort = Number(CONFIG.PORT);
  if (!CONFIG.PORT || configuredPort === 0) {
    log('Auto-allocating port...');
    try {
      CONFIG.PORT = String(await findAvailablePort(8443, 100));
      log(`Allocated port: ${CONFIG.PORT}`);
    } catch (err) {
      logErr(err.message);
      process.exit(1);
    }
  } else {
    if (!Number.isSafeInteger(configuredPort) || configuredPort < 1 || configuredPort > 65535) {
      logErr(`ERROR: Invalid server port: ${CONFIG.PORT}`);
      process.exit(1);
    }
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

  await validateRedisTls();

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

  if (!useTui) {
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

  const childServer = spawn(process.execPath, [serverJs], {
    cwd: repoRoot,
    env: serverEnv,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  // Setup TUI
  const uiTui = new ReziServerUI(childServer, CONFIG);

  const lastLinesArr = [];
  const MAX_LAST_LOG = 80;
  const pushLastLog = (line) => {
    lastLinesArr.push(line);
    if (lastLinesArr.length > MAX_LAST_LOG) lastLinesArr.shift();
  };
  const processOutputLine = (line) => {
    if (!line.trim()) return;
    uiTui.addLog(line);
    pushLastLog(sanitizeTerminalLog(line));
  };
  const stdoutLines = createLineCollector(processOutputLine);
  const stderrLines = createLineCollector(processOutputLine);

  childServer.stdout.on('data', (chunk) => stdoutLines.push(chunk));
  childServer.stderr.on('data', (chunk) => stderrLines.push(chunk));

  childServer.on('close', async (code, signal) => {
    stdoutLines.flush();
    stderrLines.flush();
    const expectedShutdown = uiTui.shutdownRequested;
    await uiTui.stop(false);

    const failed = typeof code === 'number'
      ? code !== 0
      : Boolean(signal && !expectedShutdown);
    if (failed) {
      const reason = typeof code === 'number' ? `code ${code}` : `signal ${signal}`;
      console.error(`\n[ERROR] Server exited with ${reason}`);
      if (lastLinesArr.length) {
        console.error('[ERROR] Last server log lines:');
        for (const l of lastLinesArr) console.error('  ' + l);
      } else {
        console.error('[ERROR] No logs captured. Re-run with NO_GUI=true for raw output.');
      }
    }

    const exitCode = typeof code === 'number' ? code : (expectedShutdown ? 0 : 1);
    setTimeout(() => process.exit(exitCode), 200);
  });

  await uiTui.start();
}

main().catch((e) => { logErr(e.message); process.exit(1); });
