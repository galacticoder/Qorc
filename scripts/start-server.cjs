#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
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
  if (!fs.existsSync(filePath)) throw new Error(`Environment file not found: ${filePath}`);
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
}

loadDotEnv(path.join(repoRoot, '.env'));

const CONFIG = {
  PORT: process.env.PORT || '',
  BIND_ADDRESS: process.env.BIND_ADDRESS || '127.0.0.1',
  REDIS_URL: process.env.REDIS_URL || '',
  CLUSTER_PRIMARY: process.env.CLUSTER_PRIMARY || '',
  AUTO_APPROVE: process.env.CLUSTER_AUTO_APPROVE || '',
  ALLOWED_CORS_ORIGINS: process.env.ALLOWED_CORS_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173',
  TLS_CERT_PATH: process.env.TLS_CERT_PATH || '',
  TLS_KEY_PATH: process.env.TLS_KEY_PATH || '',
  NO_GUI: (process.env.NO_GUI || 'false').toLowerCase() === 'true',
  SERVER_HOST: process.env.SERVER_HOST || '',
  SERVER_ID: process.env.SERVER_ID || '',
};

const serverDir = path.join(repoRoot, 'server');

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
  if (url.username || url.password || url.search || url.hash) {
    throw new Error('REDIS_URL must not contain credentials, query parameters, or a fragment');
  }

  const hostname = url.hostname.startsWith('[') && url.hostname.endsWith(']')
    ? url.hostname.slice(1, -1)
    : url.hostname;
  const port = url.port;
  if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
    throw new Error('REDIS_URL contains an invalid port');
  }

  const redisPassword = process.env.REDIS_PASSWORD;
  if (typeof redisPassword !== 'string' || redisPassword.length < 32 || !/^[A-Za-z0-9_-]+$/.test(redisPassword)) {
    throw new Error('REDIS_PASSWORD must contain at least 32 base64url characters');
  }
  const env = { REDISCLI_AUTH: redisPassword };

  const cliArgs = ['-h', hostname, '-p', port, '--tls'];

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

  if (
    !process.env.REDIS_TLS_SERVERNAME ||
    !process.env.REDIS_CA_CERT_PATH ||
    !process.env.REDIS_CLIENT_CERT_PATH ||
    !process.env.REDIS_CLIENT_KEY_PATH
  ) {
    throw new Error('Redis mutual TLS configuration is incomplete');
  }
  cliArgs.push('--sni', process.env.REDIS_TLS_SERVERNAME);
  cliArgs.push('--cacert', process.env.REDIS_CA_CERT_PATH);
  cliArgs.push('--cert', process.env.REDIS_CLIENT_CERT_PATH);
  cliArgs.push('--key', process.env.REDIS_CLIENT_KEY_PATH);

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
  return new Promise((resolve, reject) => {
    const server = require('net').createServer();
    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        resolve(true);
      } else {
        reject(err);
      }
    });
    server.once('listening', () => {
      server.close();
      resolve(false);
    });
    server.listen(port, '0.0.0.0');
  });
}

function validateTLSCertificates() {
  if (!CONFIG.TLS_CERT_PATH || !CONFIG.TLS_KEY_PATH) {
    throw new Error('TLS_CERT_PATH and TLS_KEY_PATH are required');
  }

  const certPath = path.isAbsolute(CONFIG.TLS_CERT_PATH)
    ? CONFIG.TLS_CERT_PATH
    : path.join(repoRoot, CONFIG.TLS_CERT_PATH);
  const keyPath = path.isAbsolute(CONFIG.TLS_KEY_PATH)
    ? CONFIG.TLS_KEY_PATH
    : path.join(repoRoot, CONFIG.TLS_KEY_PATH);

  if (!fs.existsSync(certPath)) {
    throw new Error(`TLS certificate not found: ${certPath}`);
  }

  if (!fs.existsSync(keyPath)) {
    throw new Error(`TLS key not found: ${keyPath}`);
  }

  fs.accessSync(certPath, fs.constants.R_OK);
  fs.accessSync(keyPath, fs.constants.R_OK);

  CONFIG.TLS_CERT_PATH = certPath;
  CONFIG.TLS_KEY_PATH = keyPath;
}

class ReziServerUI {
  constructor(serverProcess, config) {
    this.serverProcess = serverProcess;
    this.serverPid = serverProcess.pid;
    this.config = config;
    this.logBuffer = new CircularBuffer(1000);
    this.logSequence = 0;
    this.running = true;
    this.shutdownRequested = false;
    this.startTime = Date.now();
    this.lastMetrics = {
      cpu: null,
      mem: null,
      registration: 'checking',
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
      tasks.push(this._refreshRegistration());
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

  _truncate(value, maxLength) {
    const text = value ? String(value) : 'unknown';
    if (text.length <= maxLength) return text;
    const head = Math.floor((maxLength - 1) / 2);
    return `${text.slice(0, head)}…${text.slice(-(maxLength - head - 1))}`;
  }

  _databaseDisplay(maxLength = 80) {
    const rawUrl = process.env.DATABASE_URL;
    try {
      const url = new URL(rawUrl);
      const protocol = url.protocol.replace(/:$/, '');
      const database = url.pathname.replace(/^\//, '');
      return this._truncate(
        `${protocol}://${url.hostname}:${url.port}/${database}`,
        maxLength
      );
    } catch {
      return this._truncate('[invalid DATABASE_URL]', maxLength);
    }
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
      serverId: this.config.SERVER_ID,
      endpoint: `${this.config.SERVER_HOST}:${this.config.PORT}`,
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
    const { createServerDashboard, logEntry } = await import('./qorc-rezi-tui.js');
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

async function validateDbCaBundleEnv() {
  const pinnedPath = process.env.PGSSLROOTCERT;
  if (!pinnedPath) {
    throw new Error('PGSSLROOTCERT is required');
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
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('REDIS_URL is invalid');
  }
  if (url.protocol !== 'rediss:' || !url.hostname || !url.port) {
    throw new Error('REDIS_URL must use rediss:// and include a host and port');
  }
  const port = Number(url.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error('REDIS_URL contains an invalid port');
  }
  for (const name of [
    'REDIS_TLS_SERVERNAME',
    'REDIS_CA_CERT_PATH',
    'REDIS_CLIENT_CERT_PATH',
    'REDIS_CLIENT_KEY_PATH'
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required`);
  }
  try {
    const out = runRedisCli(rawUrl, ['PING'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 1500
    }).trim();
    if (out !== 'PONG') throw new Error('Redis returned an unexpected PING response');
  } catch (error) {
    throw new Error(`Configured Redis is unavailable: ${error.message}`);
  }
}


async function main() {
  const useTui = !CONFIG.NO_GUI && Boolean(process.stdin.isTTY && process.stdout.isTTY);
  if (useTui) {
    console.log("Starting Server...");
  }

  validateTLSCertificates();
  await validateDbCaBundleEnv();
  if (!CONFIG.SERVER_HOST) {
    throw new Error('SERVER_HOST is required');
  }
  if (!CONFIG.SERVER_ID) {
    throw new Error('SERVER_ID is required');
  }
  if (!['true', 'false'].includes(CONFIG.CLUSTER_PRIMARY)) {
    throw new Error('CLUSTER_PRIMARY must be explicitly set to true or false');
  }
  if (!['true', 'false'].includes(CONFIG.AUTO_APPROVE)) {
    throw new Error('CLUSTER_AUTO_APPROVE must be explicitly set to true or false');
  }
  const configuredPort = Number(CONFIG.PORT);
  if (!Number.isSafeInteger(configuredPort) || configuredPort < 1 || configuredPort > 65535) {
    throw new Error(`Invalid server port: ${CONFIG.PORT}`);
  }
  if (await isPortInUse(CONFIG.PORT)) {
    throw new Error(`Port ${CONFIG.PORT} is already in use`);
  }

  await validateRedisTls();

  log('Configuration:');
  log(`  Server ID: ${CONFIG.SERVER_ID}`);
  log(`  Server Host: ${CONFIG.SERVER_HOST}:${CONFIG.PORT}`);
  log(`  Primary: ${CONFIG.CLUSTER_PRIMARY}`);
  log(`  Redis: ${safeUrlEndpointForDisplay(CONFIG.REDIS_URL, 'REDIS_URL')}`);
  log(`  Auto-Approve: ${CONFIG.AUTO_APPROVE}`);
  log(`  TLS Cert: ${CONFIG.TLS_CERT_PATH}`);
  log(`  TLS Key: ${CONFIG.TLS_KEY_PATH}`);

  const serverEnv = {
    ...process.env,
    PORT: String(CONFIG.PORT),
    BIND_ADDRESS: CONFIG.BIND_ADDRESS,
    REDIS_URL: CONFIG.REDIS_URL,
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
