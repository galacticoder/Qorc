#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawn, execFile } = require('child_process');
const { pathToFileURL } = require('url');
const { parseActiveServers } = require('./loadbalancer-tui-state.cjs');

const repoRoot = path.resolve(__dirname, '..');
const lbScript = path.join(repoRoot, 'server', 'load-balancer', 'auto-loadbalancer.js');
const edgeRuntimeRoot = '/opt/qorc-edge';
const edgeRuntimeLibDir = path.join(edgeRuntimeRoot, 'lib');
const bundledHaproxyBin = path.join(edgeRuntimeRoot, 'bin', 'haproxy');
const bundledOqsModule = path.join(edgeRuntimeLibDir, 'ossl-modules', 'oqsprovider.so');
const redisClientModuleUrl = pathToFileURL(
  path.join(repoRoot, 'server', 'session', 'redis-client.js')
).href;
const redisKeysModuleUrl = pathToFileURL(
  path.join(repoRoot, 'server', 'config', 'redis-keys.js')
).href;
if (process.platform !== 'linux') {
  console.error('[LB] Native load-balancer deployment supports only Linux.');
  process.exit(1);
}

delete process.env.LD_PRELOAD;
process.env.LD_LIBRARY_PATH = edgeRuntimeLibDir;

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
    if (!(key in process.env)) process.env[key] = val;
  }
}

loadDotEnv(path.join(repoRoot, '.env'));

const CONFIG = {
  NO_GUI: (process.env.NO_GUI || 'false').toLowerCase() === 'true',
  HAPROXY_HTTPS_PORT: process.env.HAPROXY_HTTPS_PORT,
  HAPROXY_STATS_PORT: process.env.HAPROXY_STATS_PORT,
  SERVER_ACTIVE_TIMEOUT_MS: Math.min(
    Math.max(parseInt(process.env.LB_SERVER_ACTIVE_TIMEOUT_MS || '45000', 10) || 45000, 10000),
    300000
  ),
};

if (!process.env.REDIS_QUIET_ERRORS) {
  process.env.REDIS_QUIET_ERRORS = 'true';
}

function log(...args) { console.log('[LB]', ...args); }
function logErr(...args) { console.error('[LB]', ...args); }

function wipeByteBuffers(...values) {
  for (const value of values) {
    try { value?.fill?.(0); } catch { }
  }
}

function wipeCommandKeypair(keypair) {
  for (const family of Object.values(keypair || {})) {
    wipeByteBuffers(family?.publicKey, family?.secretKey);
  }
}

async function validateTuiDependencies() {
  for (const packageName of ['@rezi-ui/core', '@rezi-ui/node']) {
    try {
      require.resolve(packageName, { paths: [path.join(repoRoot, 'server')] });
    } catch {
      throw new Error(`Missing terminal UI dependency: ${packageName}`);
    }
  }
}

class CircularBuffer { constructor(n = 1000) { this.a = []; this.n = n; } push(x) { this.a.push(x); if (this.a.length > this.n) this.a.shift(); } get() { return this.a; } }
class RateLimiter { constructor(ms = 1000) { this.ms = ms; this.last = 0; } ok() { const now = Date.now(); if (now - this.last >= this.ms) { this.last = now; return true; } return false; } }

const ANSI_SEQUENCE = /\x1b\[[0-?]*[ -/]*[@-~]/g;

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

function readProcessMetrics(pid) {
  return new Promise((resolve) => {
    execFile(
      'ps',
      ['-p', String(pid), '-o', '%cpu=,%mem='],
      { encoding: 'utf8', timeout: 500 },
      (error, stdout) => {
        if (error) {
          resolve(null);
          return;
        }
        const values = stdout.trim().split(/\s+/);
        resolve(values.length >= 2 ? { cpu: values[0], mem: values[1] } : null);
      }
    );
  });
}

async function hasOqsProvider(env) {
  return new Promise((resolve) => {
    const p = spawn('openssl', ['list', '-providers'], { env, stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '';
    p.stdout.on('data', (d) => out += String(d));
    p.on('exit', () => resolve(/oqs/i.test(out)));
  });
}

async function isPinnedHaproxyVersion(haproxyBin) {
  return new Promise((resolve) => {
    const p = spawn(haproxyBin, ['-v'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const collect = (chunk) => {
      if (output.length < 4096) output += String(chunk).slice(0, 4096 - output.length);
    };
    p.stdout.on('data', collect);
    p.stderr.on('data', collect);
    p.on('error', () => resolve(false));
    p.on('exit', (code) => resolve(
      code === 0 && /HAProxy version 3\.2\.21(?:-[0-9A-Fa-f]+)?(?:\s|$)/.test(output)
    ));
  });
}

async function checkQuantumReady() {
  const localConf = path.join(repoRoot, 'server', 'config', 'openssl-oqs.cnf');
  const oqsModule = bundledOqsModule;
  if (!fs.existsSync(oqsModule)) {
    throw new Error(`Bundled OQS provider is unavailable: ${oqsModule}`);
  }
  process.env.OQS_PROVIDER_MODULE = oqsModule;
  process.env.OPENSSL_MODULES = path.dirname(oqsModule);
  fs.writeFileSync(localConf, [
    'openssl_conf = openssl_init',
    '',
    '[openssl_init]',
    'providers = provider_sect',
    '',
    '[provider_sect]',
    'default = default_sect',
    'oqsprovider = oqs_sect',
    '',
    '[default_sect]',
    'activate = 1',
    '',
    '[oqs_sect]',
    'module = ${ENV::OQS_PROVIDER_MODULE}',
    'activate = 1',
    ''
  ].join('\n'), { encoding: 'utf8', mode: 0o600 });
  const env = {
    ...process.env,
    OPENSSL_CONF: localConf,
    OQS_PROVIDER_MODULE: oqsModule,
    OPENSSL_MODULES: path.dirname(oqsModule)
  };

  if (!await hasOqsProvider(env)) {
    throw new Error('Bundled OQS provider failed to load');
  }

  process.env.OPENSSL_CONF = localConf;
}

async function checkHaproxyBuiltOrReady() {
  const bundledBin = bundledHaproxyBin;
  if (!fs.existsSync(bundledBin)) {
    throw new Error(`Bundled HAProxy executable is unavailable: ${bundledBin}`);
  }
  const versionOk = await isPinnedHaproxyVersion(bundledBin);
  if (!versionOk) throw new Error('Bundled HAProxy version does not match 3.2.21');
}

class ReziLBTUI {
  constructor(childPid) {
    this.pid = childPid;
    this.buf = new CircularBuffer(1000);
    this.logSequence = 0;
    this.run = true;
    this.metrics = new RateLimiter(1000);
    this.stats = {
      cpu: null,
      mem: null,
      servers: null,
      serverList: [],
      onionUrl: null,
      lbPort: CONFIG.HAPROXY_HTTPS_PORT,
      dataState: 'connecting',
      updatedAt: null,
    };
    this.pollInFlight = null;
    this.redisModulesPromise = null;
    this.dashboard = null;
    this.stopPromise = null;
    this.cmdHistory = [];
    this.cmdHistoryIndex = -1;
    this.commands = [
      { name: '/help', desc: 'Show available commands', aliases: ['/h', '/?'] },
      { name: '/reload', desc: 'Reload HAProxy configuration', aliases: ['/r'] },
      { name: '/servers', desc: 'Show active servers', aliases: ['/s'] },
      { name: '/clear', desc: 'Clear log buffer', aliases: ['/c'] },
      { name: '/quit', desc: 'Stop load balancer and exit', aliases: ['/q'] },
    ];
  }

  add(line) {
    if (line.includes('\r')) {
      const parts = line.split('\r');
      line = parts[parts.length - 1];
    }
    const cleanLine = String(line)
      .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
      .replace(ANSI_SEQUENCE, '')
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
    const entry = this.logEntryFactory
      ? this.logEntryFactory(cleanLine, ++this.logSequence, 'load-balancer')
      : {
          id: `load-balancer-${++this.logSequence}`,
          timestamp: Date.now(),
          level: /\b(error|fatal|panic|failed)\b/i.test(cleanLine) ? 'error' : (/\bwarn/i.test(cleanLine) ? 'warn' : 'info'),
          source: 'load-balancer',
          message: cleanLine,
        };
    this.buf.push(entry);
    this.render();
  }

  async getKeypair() {
    if (this._keypair) return this._keypair;

    try {
      const path = require('path');
      const secureCreds = path.join(repoRoot, 'server', 'config', 'secure-credentials.js');
      const { unlockKeypair } = await import(`file://${secureCreds}`);

      const username = process.env.HAPROXY_STATS_USERNAME;
      const password = process.env.HAPROXY_STATS_PASSWORD;

      if (!username || !password) {
        throw new Error('HAProxy stats credentials not available in environment');
      }

      this._keypair = await unlockKeypair(username, password);
      return this._keypair;
    } catch (error) {
      throw new Error(`Failed to unlock keypair: ${error.message}`);
    }
  }

  async getRedisModules() {
    if (!this.redisModulesPromise) {
      this.redisModulesPromise = Promise.all([
        import(redisClientModuleUrl),
        import(redisKeysModuleUrl),
      ]).then(([redis, keys]) => ({
        withRedisClient: redis.withRedisClient,
        redisKeys: keys.REDIS_KEYS,
      })).catch((error) => {
        this.redisModulesPromise = null;
        throw error;
      });
    }
    return this.redisModulesPromise;
  }

  async withRedisClient(operation) {
    const { withRedisClient } = await this.getRedisModules();
    return withRedisClient(operation);
  }

  async sendEncryptedCommand(commandObj) {
    const crypto = require('crypto');
    const path = require('path');
    const temporaryBytes = [];

    try {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      const { x25519 } = await import('@noble/curves/ed25519.js');
      const [{ CryptoUtils }, { deriveQuantumAeadKey }, { PROTOCOL_KEYS }] = await Promise.all([
        import(path.join(repoRoot, 'server', 'crypto', 'unified-crypto.js')),
        import(path.join(repoRoot, 'server', 'crypto', 'aead-key-derivation.js')),
        import(path.join(repoRoot, 'server', 'config', 'protocol-keys.js')),
      ]);

      if (commandObj?.cmd !== 'reload') throw new Error('Unsupported load-balancer command');
      const keypair = await this.getKeypair();
      const command = {
        cmd: 'reload',
        commandId: crypto.randomUUID(),
        issuedAt: Date.now(),
      };
      const payloadBytes = Buffer.from(JSON.stringify(command), 'utf8');
      temporaryBytes.push(payloadBytes);

      const ephemeralX25519Secret = crypto.randomBytes(32);
      const ephemeralX25519Public = x25519.getPublicKey(ephemeralX25519Secret);
      const x25519SharedSecret = x25519.getSharedSecret(ephemeralX25519Secret, keypair.x25519.publicKey);
      temporaryBytes.push(ephemeralX25519Secret, ephemeralX25519Public, x25519SharedSecret);

      const kemEnc = ml_kem1024.encapsulate(keypair.kyber.publicKey);
      const kyberSharedSecret = kemEnc.sharedSecret;
      const kyberCiphertext = kemEnc.cipherText;
      temporaryBytes.push(kyberSharedSecret, kyberCiphertext);

      const rawSecret = Buffer.concat([
        Buffer.from(kyberSharedSecret),
        Buffer.from(x25519SharedSecret),
      ]);
      const aeadKey = await deriveQuantumAeadKey(rawSecret, PROTOCOL_KEYS.LB_COMMAND_ENCRYPTION);
      temporaryBytes.push(rawSecret, aeadKey);

      const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
      const nonce = CryptoUtils.Random.generateRandomBytes(36);
      const aad = new TextEncoder().encode(PROTOCOL_KEYS.LB_COMMAND_AAD);
      const { ciphertext, tag } = aead.encrypt(payloadBytes, nonce, aad);
      temporaryBytes.push(nonce, aad, ciphertext, tag);

      const encryptedPackage = {
        kyberCiphertext: Buffer.from(kyberCiphertext).toString('base64'),
        x25519EphemeralPublic: Buffer.from(ephemeralX25519Public).toString('base64'),
        nonce: Buffer.from(nonce).toString('base64'),
        ciphertext: Buffer.from(ciphertext).toString('base64'),
        tag: Buffer.from(tag).toString('base64'),
      };

      const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
      const signature = ml_dsa87.sign(packageBytes, keypair.dilithium.secretKey);
      temporaryBytes.push(packageBytes, signature);

      const payload = {
        version: 2,
        encrypted: encryptedPackage,
        signature: Buffer.from(signature).toString('base64'),
        algorithm: 'ML-KEM-1024 + X25519 + PostQuantumAEAD + ML-DSA-87',
      };

      const { redisKeys } = await this.getRedisModules();
      await this.withRedisClient(async (client) => {
        await client.publish(redisKeys.LB_ENCRYPTED_COMMAND_CHANNEL, JSON.stringify(payload));
      });
    } catch (error) {
      throw new Error(`Failed to send encrypted command: ${error.message}`);
    } finally {
      wipeByteBuffers(...temporaryBytes);
    }
  }

  async executeCommand(cmd) {
    cmd = cmd.trim();
    if (!cmd) return;

    if (this.cmdHistory.length === 0 || this.cmdHistory[this.cmdHistory.length - 1] !== cmd) {
      this.cmdHistory.push(cmd);
      if (this.cmdHistory.length > 100) this.cmdHistory.shift();
    }

    this.add(`> ${cmd}`);

    const parts = cmd.split(/\s+/);
    const mainCmd = parts[0].toLowerCase();

    let cmdDef = this.commands.find(c =>
      c.name.toLowerCase() === mainCmd ||
      (c.aliases || []).some(a => a.toLowerCase() === mainCmd)
    );

    if (!cmdDef && parts.length > 1) {
      const fullCmd = `${parts[0]} ${parts[1]}`.toLowerCase();
      cmdDef = this.commands.find(c => c.name.toLowerCase() === fullCmd);
    }

    if (!cmdDef) {
      this.add(`Unknown command: ${mainCmd}`);
      this.add(`Type /help for available commands`);
      return;
    }

    try {
      if (cmdDef.name === '/help') {
        this.add('Available commands:');
        for (const c of this.commands) {
          const aliases = c.aliases && c.aliases.length > 0 ? ` (${c.aliases.join(', ')})` : '';
          this.add(`  ${c.name}${aliases} - ${c.desc}`);
        }
      } else if (cmdDef.name === '/reload') {
        try {
          await this.sendEncryptedCommand({ cmd: 'reload', pid: this.pid });
          this.add('Reload command sent');
        } catch (error) {
          this.add(`Error: ${error.message}`);
        }
      } else if (cmdDef.name === '/servers') {
        if (this.stats.serverList.length === 0) {
          this.add('No active servers');
        } else {
          this.add(`Active servers (${this.stats.serverList.length}):`);
          for (const s of this.stats.serverList) {
            this.add(`  - ${s.id} (${s.host}:${s.port})`);
          }
        }
      } else if (cmdDef.name === '/clear') {
        this.buf = new CircularBuffer(1000);
        this.add('Log cleared');
      } else if (cmdDef.name === '/quit') {
        this.add('Stopping load balancer...');
        this.stop();
        try { process.kill(this.pid, 'SIGTERM'); } catch { }
        return;
      }
    } catch (error) {
      this.add(`Error executing command: ${error.message}`);
    }
  }

  async getStatusSnapshot() {
    const { redisKeys } = await this.getRedisModules();
    return this.withRedisClient(async (client) => {
      const [storedServers, onionUrl, storedPort] = await Promise.all([
        client.hgetall(redisKeys.CLUSTER_SERVERS),
        client.get(redisKeys.LB_ONION_ADDRESS),
        client.get(redisKeys.LB_HTTPS_PORT),
      ]);
      const servers = parseActiveServers(
        storedServers,
        Date.now(),
        CONFIG.SERVER_ACTIVE_TIMEOUT_MS
      );

      let lbPort = null;
      if (storedPort) {
        const parsedPort = Number(storedPort);
        if (Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
          lbPort = String(parsedPort);
        }
      }
      return {
        servers,
        onionUrl: typeof onionUrl === 'string' && onionUrl.length > 0 ? onionUrl : null,
        lbPort,
      };
    });
  }

  poll() {
    if (this.pollInFlight || !this.metrics.ok()) return this.pollInFlight;
    this.pollInFlight = this.pollOnce().finally(() => {
      this.pollInFlight = null;
      if (this.run) this.render();
    });
    return this.pollInFlight;
  }

  async pollOnce() {
    const metricsPromise = readProcessMetrics(this.pid);
    try {
      const snapshot = await this.getStatusSnapshot();
      this.stats.servers = snapshot.servers.length;
      this.stats.serverList = snapshot.servers;
      this.stats.onionUrl = snapshot.onionUrl;
      if (snapshot.lbPort) this.stats.lbPort = snapshot.lbPort;
      this.stats.dataState = 'live';
      this.stats.updatedAt = Date.now();
    } catch {
      this.stats.dataState = this.stats.updatedAt === null ? 'unavailable' : 'stale';
    }

    const processMetrics = await metricsPromise;
    if (processMetrics) {
      this.stats.cpu = processMetrics.cpu;
      this.stats.mem = processMetrics.mem;
    }
  }

  recallHistory(direction, currentValue) {
    if (!this.cmdHistory.length) return currentValue;
    if (direction < 0) {
      this.cmdHistoryIndex = this.cmdHistoryIndex < 0
        ? this.cmdHistory.length - 1
        : Math.max(0, this.cmdHistoryIndex - 1);
      return this.cmdHistory[this.cmdHistoryIndex];
    }
    if (this.cmdHistoryIndex < 0) return currentValue;
    if (this.cmdHistoryIndex < this.cmdHistory.length - 1) {
      this.cmdHistoryIndex += 1;
      return this.cmdHistory[this.cmdHistoryIndex];
    }
    this.cmdHistoryIndex = -1;
    return '/';
  }

  _dataLabel() {
    return {
      connecting: 'Connecting',
      live: 'Connected',
      stale: 'Last known state',
      unavailable: 'Redis unavailable',
    }[this.stats.dataState] || 'Unknown';
  }

  _snapshot() {
    return {
      pid: this.pid,
      cpu: this.stats.cpu,
      mem: this.stats.mem,
      servers: this.stats.servers,
      serverList: [...this.stats.serverList],
      onionUrl: this.stats.onionUrl,
      httpsPort: CONFIG.HAPROXY_HTTPS_PORT,
      statsPort: CONFIG.HAPROXY_STATS_PORT,
      heartbeatWindow: `${Math.round(CONFIG.SERVER_ACTIVE_TIMEOUT_MS / 1000)} seconds`,
      dataState: this.stats.dataState,
      dataLabel: this._dataLabel(),
      logs: [...this.buf.get()],
    };
  }

  render() {
    if (this.run && this.dashboard) this.dashboard.update(this._snapshot());
  }

  terminate() {
    void this.stop();
    try { process.kill(this.pid, 'SIGTERM'); } catch { }
  }

  stop() {
    wipeCommandKeypair(this._keypair);
    this._keypair = null;
    if (this.stopPromise) return this.stopPromise;
    this.run = false;
    if (this.interval) clearInterval(this.interval);
    this.interval = null;
    if (this.sigintHandler) process.removeListener('SIGINT', this.sigintHandler);
    if (this.sigtermHandler) process.removeListener('SIGTERM', this.sigtermHandler);
    this.stopPromise = this.dashboard
      ? this.dashboard.stop().catch(() => {})
      : Promise.resolve();
    return this.stopPromise;
  }

  async start() {
    const { createLoadBalancerDashboard, logEntry } = await import('./qorc-rezi-tui.js');
    this.logEntryFactory = logEntry;
    this.dashboard = createLoadBalancerDashboard(this._snapshot(), {
      stop: () => this.terminate(),
      submitCommand: async (command) => {
        this.cmdHistoryIndex = -1;
        await this.executeCommand(command);
        this.render();
      },
      recallHistory: (direction, currentValue) => this.recallHistory(direction, currentValue),
    });
    await this.dashboard.start();
    this.render();
    void this.poll();
    this.interval = setInterval(() => void this.poll(), 1000);
    this.sigintHandler = () => this.terminate();
    this.sigtermHandler = () => this.terminate();
    process.on('SIGINT', this.sigintHandler);
    process.on('SIGTERM', this.sigtermHandler);
  }
}


async function checkHaproxyCertFile() {
  const certPath = process.env.TLS_CERT_PATH;
  const keyPath = process.env.TLS_KEY_PATH;
  const haproxyCertPath = path.join(repoRoot, 'server', 'config', 'certs', 'cert.pem');
  const backendCaPath = path.join(repoRoot, 'server', 'config', 'certs', 'backend-ca.pem');

  if (!certPath || !keyPath) throw new Error('TLS_CERT_PATH and TLS_KEY_PATH are required');
  const resolvedCertPath = path.resolve(repoRoot, certPath);
  const resolvedKeyPath = path.resolve(repoRoot, keyPath);
  const certContent = fs.readFileSync(resolvedCertPath, 'utf8');
  const keyContent = fs.readFileSync(resolvedKeyPath, 'utf8');
  const combined = certContent + '\n' + keyContent;
  const certDir = path.dirname(haproxyCertPath);
  fs.mkdirSync(certDir, { recursive: true });
  fs.writeFileSync(haproxyCertPath, combined, { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(haproxyCertPath, 0o600);
  fs.writeFileSync(backendCaPath, certContent, { encoding: 'utf8', mode: 0o644 });
  fs.chmodSync(backendCaPath, 0o644);
  log(`[CERT] Updated HAProxy cert.pem from ${path.basename(resolvedCertPath)}`);
}

async function checkHaproxyCerts() {
  await checkQuantumReady();
  await checkHaproxyCertFile();
  await checkHaproxyBuiltOrReady();
}

async function checkStatsCredentials() {
  const credsFile = path.join(repoRoot, 'server', 'config', '.haproxy-stats-creds.pqc');
  const keysFile = path.join(repoRoot, 'server', 'config', '.haproxy-keys.enc');
  const secureCredentialsPath = path.join(repoRoot, 'server', 'config', 'secure-credentials.js');
  const loadSecureCredentials = () => import(pathToFileURL(secureCredentialsPath).href);
  const username = typeof process.env.HAPROXY_STATS_USERNAME === 'string'
    ? process.env.HAPROXY_STATS_USERNAME.trim()
    : '';
  const password = typeof process.env.HAPROXY_STATS_PASSWORD === 'string'
    ? process.env.HAPROXY_STATS_PASSWORD
    : '';

  if (!username || !password) {
    throw new Error('HAPROXY_STATS_USERNAME and HAPROXY_STATS_PASSWORD must be set in .env.');
  }

  process.env.HAPROXY_STATS_USERNAME = username;

  const { saveCredentials, verifyCredentials } = await loadSecureCredentials();
  const credentialsExist = fs.existsSync(credsFile);
  const keysExist = fs.existsSync(keysFile);
  if (credentialsExist !== keysExist) {
    throw new Error('HAProxy credential material is incomplete');
  }
  if (credentialsExist) {
    try {
      if (!await verifyCredentials(username, password)) {
        throw new Error('Stored credentials do not match the configured environment');
      }
      return;
    } catch (error) {
      throw new Error(`HAProxy stats credentials in .env cannot unlock the stored credential material: ${error.message}`);
    }
  }

  log('[SECURE-CREDS] Generating command encryption keys from .env credentials...');
  await saveCredentials(username, password);
  if (!fs.existsSync(credsFile) || !fs.existsSync(keysFile)) {
    throw new Error('HAProxy credential material was not created');
  }
}

(async () => {
  if (!process.env.REDIS_URL) throw new Error('REDIS_URL is required');
  const redisPassword = process.env.REDIS_PASSWORD;
  if (typeof redisPassword !== 'string' || redisPassword.length < 32 || !/^[A-Za-z0-9_-]+$/.test(redisPassword)) {
    throw new Error('REDIS_PASSWORD must contain at least 32 base64url characters');
  }
  for (const [name, value] of [
    ['HAPROXY_HTTPS_PORT', CONFIG.HAPROXY_HTTPS_PORT],
    ['HAPROXY_STATS_PORT', CONFIG.HAPROXY_STATS_PORT],
  ]) {
    if (!/^\d{1,5}$/.test(value || '') || Number(value) < 1 || Number(value) > 65535) {
      throw new Error(`${name} must be an integer from 1 through 65535`);
    }
  }
  if (!fs.existsSync(lbScript)) {
    logErr('auto-loadbalancer not found at server/load-balancer/auto-loadbalancer.js');
    process.exit(1);
  }

  if (!CONFIG.NO_GUI) await validateTuiDependencies();

  await checkHaproxyCerts();
  await checkStatsCredentials();

  if (!['127.0.0.1', '0.0.0.0'].includes(process.env.HAPROXY_STATS_BIND_ADDRESS)) {
    throw new Error('HAPROXY_STATS_BIND_ADDRESS must be 127.0.0.1 or 0.0.0.0');
  }

  const env = { ...process.env, REDIS_URL: process.env.REDIS_URL, HAPROXY_HTTPS_PORT: String(CONFIG.HAPROXY_HTTPS_PORT), HAPROXY_STATS_PORT: String(CONFIG.HAPROXY_STATS_PORT) };

  if (CONFIG.NO_GUI) {
    const child = spawn(process.execPath, [lbScript], { cwd: repoRoot, env, stdio: 'inherit' });

    let exiting = false;
    const handleSignal = (signal) => {
      if (exiting) return;
      exiting = true;
      try {
        child.kill(signal);
      } catch { }
    };

    process.on('SIGINT', () => handleSignal('SIGINT'));
    process.on('SIGTERM', () => handleSignal('SIGTERM'));

    child.on('exit', (code) => {
      setTimeout(() => {
        process.exit(Number.isInteger(code) ? code : 1);
      }, 100);
    });
    return;
  }

  const child = spawn(process.execPath, [lbScript], { cwd: repoRoot, env, stdio: ['ignore', 'pipe', 'pipe'] });

  const ui = new ReziLBTUI(child.pid);

  const last = []; const MAX = 200; const push = (l) => { last.push(l); if (last.length > MAX) last.shift(); };
  const collectLine = (line) => {
    if (!line.trim()) return;
    ui.add(line);
    push(line);
  };
  const stdoutLines = createLineCollector(collectLine);
  const stderrLines = createLineCollector(collectLine);
  child.stdout.on('data', (chunk) => stdoutLines.push(chunk));
  child.stderr.on('data', (chunk) => stderrLines.push(chunk));
  child.on('exit', async (code) => {
    stdoutLines.flush();
    stderrLines.flush();
    await ui.stop();

    const exitCode = Number.isInteger(code) ? code : 1;
    if (exitCode !== 0) {
      console.error(`\n[ERROR] Load balancer exited with code ${exitCode}`);
      if (last.length) { console.error('[ERROR] Last output:'); for (const l of last) console.error('  ' + l); }
    }
    process.exit(exitCode);
  });

  await ui.start();
})();
