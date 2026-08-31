#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');
const { pathToFileURL } = require('url');
const { parseActiveServers } = require('./loadbalancer-tui-state.cjs');

const repoRoot = path.resolve(__dirname, '..');
const serverDir = path.join(repoRoot, 'server');
const lbScript = path.join(repoRoot, 'server', 'load-balancer', 'auto-loadbalancer.js');
const edgeRuntimeRoot = '/opt/qor-edge';
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
      if (!(key in process.env)) process.env[key] = val;
    }
  } catch { }
}

loadDotEnv(path.join(repoRoot, '.env'));

if (!process.env.REDIS_URL) process.env.REDIS_URL = 'rediss://127.0.0.1:6379';

const CONFIG = {
  NO_GUI: (process.env.NO_GUI || 'false').toLowerCase() === 'true',
  HAPROXY_HTTPS_PORT: process.env.HAPROXY_HTTPS_PORT || '8443',
  HAPROXY_STATS_PORT: process.env.HAPROXY_STATS_PORT || '8404',
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

async function validateTuiDependencies() {
  const hasRezi = ['@rezi-ui/core', '@rezi-ui/node'].every((packageName) => {
    try {
      require.resolve(packageName, { paths: [serverDir] });
      return true;
    } catch {
      return false;
    }
  });
  if (hasRezi) return;

  log('Installing terminal UI dependencies ...');
  await new Promise((resolve, reject) => {
    const child = spawn('npm', ['install', '--omit=dev'], { cwd: serverDir, stdio: 'inherit' });
    child.on('exit', (code) => code === 0
      ? resolve()
      : reject(new Error(`npm install failed: ${code}`)));
  });
}

class CircularBuffer { constructor(n = 1000) { this.a = []; this.n = n; } push(x) { this.a.push(x); if (this.a.length > this.n) this.a.shift(); } get() { return this.a; } len() { return this.a.length; } }
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

async function runNodeScript(scriptPath, args = [], env = process.env) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [scriptPath, ...args], { stdio: 'inherit', env });
    p.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`${path.basename(scriptPath)} failed: ${code}`)));
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

async function testHaproxyConfig(haproxyBin, cfgPath, env) {
  return new Promise((resolve) => {
    const p = spawn(haproxyBin, ['-c', '-f', cfgPath], { env, stdio: ['ignore', 'ignore', 'ignore'] });
    p.on('exit', (code) => resolve(code === 0));
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
  const hapCfgPath = path.join(repoRoot, 'server', 'config', 'haproxy-quantum.cfg');
  const oqsModule = bundledOqsModule;
  if (!fs.existsSync(oqsModule)) {
    throw new Error(`Bundled OQS provider is unavailable: ${oqsModule}`);
  }
  process.env.OQS_PROVIDER_MODULE = oqsModule;
  process.env.OPENSSL_MODULES = path.dirname(oqsModule);
  const env = {
    ...process.env,
    OPENSSL_CONF: localConf,
    OQS_PROVIDER_MODULE: oqsModule,
    OPENSSL_MODULES: path.dirname(oqsModule)
  };

  let needSetup = !fs.existsSync(localConf) || !fs.existsSync(hapCfgPath);
  if (!needSetup) {
    const ok = await hasOqsProvider(env);
    if (!ok) needSetup = true;
  }
  if (needSetup) {
    log('Generating edge TLS configuration from the bundled crypto runtime...');
    await runNodeScript(path.join(repoRoot, 'scripts', 'setup-quantum-haproxy.cjs'));
  }

  if (!await hasOqsProvider(env)) {
    throw new Error('Bundled OQS provider failed to load');
  }

  process.env.OPENSSL_CONF = localConf;
  process.env.LB_OPENSSL_CONF = localConf;
  process.env.LB_HAPROXY_CFG = hapCfgPath;
}

async function checkHaproxyBuiltOrReady() {
  const localConf = process.env.LB_OPENSSL_CONF || path.join(repoRoot, 'server', 'config', 'openssl-oqs.cnf');
  const hapCfgPath = process.env.LB_HAPROXY_CFG || path.join(repoRoot, 'server', 'config', 'haproxy-quantum.cfg');
  const env = { ...process.env, OPENSSL_CONF: localConf };
  const bundledBin = bundledHaproxyBin;
  if (!fs.existsSync(bundledBin)) {
    throw new Error(`Bundled HAProxy executable is unavailable: ${bundledBin}`);
  }
  const [versionOk, configOk] = await Promise.all([
    isPinnedHaproxyVersion(bundledBin),
    testHaproxyConfig(bundledBin, hapCfgPath, env),
  ]);
  if (!versionOk) throw new Error('Bundled HAProxy version does not match 3.2.21');
  if (!configOk) throw new Error('Bundled HAProxy rejected the required PQ TLS configuration');
  process.env.LB_HAPROXY_BIN = bundledBin;
}

class ReziLBTUI {
  constructor(childPid) {
    this.pid = childPid;
    this.buf = new CircularBuffer(1000);
    this.logSequence = 0;
    this.scroll = 0;
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

    try {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      const { x25519 } = await import('@noble/curves/ed25519.js');
      const cryptoModule = await import(path.join(repoRoot, 'server', 'crypto', 'unified-crypto.js'));
      const { CryptoUtils } = cryptoModule;

      const keypair = await this.getKeypair();
      const payloadBytes = Buffer.from(JSON.stringify(commandObj), 'utf8');

      const ephemeralX25519Secret = crypto.randomBytes(32);
      const ephemeralX25519Public = x25519.getPublicKey(ephemeralX25519Secret);
      const x25519SharedSecret = x25519.getSharedSecret(ephemeralX25519Secret, keypair.x25519.publicKey);

      const kemEnc = ml_kem1024.encapsulate(keypair.kyber.publicKey);
      const kyberSharedSecret = kemEnc.sharedSecret;
      const kyberCiphertext = kemEnc.ciphertext || kemEnc.cipherText;

      const rawSecret = Buffer.concat([
        Buffer.from(kyberSharedSecret),
        Buffer.from(x25519SharedSecret),
      ]);
      const info = new TextEncoder().encode('lb-command-encryption-v2');
      const aeadKey = await CryptoUtils.KDF.quantumHKDF(
        new Uint8Array(rawSecret),
        CryptoUtils.Hash.shake256(rawSecret, 64),
        info,
        32
      );

      const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
      const nonce = CryptoUtils.Random.generateRandomBytes(36);
      const aad = new TextEncoder().encode('lb-command-v2');
      const { ciphertext, tag } = aead.encrypt(payloadBytes, nonce, aad);

      const encryptedPackage = {
        kyberCiphertext: Buffer.from(kyberCiphertext).toString('base64'),
        x25519EphemeralPublic: Buffer.from(ephemeralX25519Public).toString('base64'),
        nonce: Buffer.from(nonce).toString('base64'),
        ciphertext: Buffer.from(ciphertext).toString('base64'),
        tag: Buffer.from(tag).toString('base64'),
      };

      const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
      const signature = ml_dsa87.sign(packageBytes, keypair.dilithium.secretKey);

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
    }
  }

  async executeCommand(cmd) {
    cmd = cmd.trim();
    if (!cmd) return;

    if (this.cmdHistory.length === 0 || this.cmdHistory[this.cmdHistory.length - 1] !== cmd) {
      this.cmdHistory.push(cmd);
      if (this.cmdHistory.length > 100) this.cmdHistory.shift();
    }

    this.add(`\x1b[36m> ${cmd}\x1b[0m`);

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
      this.add(`\x1b[31mUnknown command: ${mainCmd}\x1b[0m`);
      this.add(`Type /help for available commands`);
      return;
    }

    try {
      if (cmdDef.name === '/help') {
        this.add('\x1b[33mAvailable commands:\x1b[0m');
        for (const c of this.commands) {
          const aliases = c.aliases && c.aliases.length > 0 ? ` (${c.aliases.join(', ')})` : '';
          this.add(`  \x1b[36m${c.name}\x1b[0m${aliases} - ${c.desc}`);
        }
      } else if (cmdDef.name === '/reload') {
        try {
          await this.sendEncryptedCommand({ cmd: 'reload', pid: this.pid });
          this.add('\x1b[32mReload command sent\x1b[0m');
        } catch (error) {
          this.add(`\x1b[31mError: ${error.message}\x1b[0m`);
        }
      } else if (cmdDef.name === '/servers') {
        if (this.stats.serverList.length === 0) {
          this.add('No active servers');
        } else {
          this.add(`\x1b[33mActive servers (${this.stats.serverList.length}):\x1b[0m`);
          for (const s of this.stats.serverList) {
            this.add(`  - ${s.id} (${s.host}:${s.port})`);
          }
        }
      } else if (cmdDef.name === '/clear') {
        this.buf = new CircularBuffer(1000);
        this.scroll = 0;
        this.add('\x1b[32mLog cleared\x1b[0m');
      } else if (cmdDef.name === '/quit') {
        this.add('Stopping load balancer...');
        this.stop();
        try { process.kill(this.pid, 'SIGTERM'); } catch { }
        return;
      }
    } catch (error) {
      this.add(`\x1b[31mError executing command: ${error.message}\x1b[0m`);
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
      httpsPort: this.stats.lbPort || CONFIG.HAPROXY_HTTPS_PORT,
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
    const { createLoadBalancerDashboard, logEntry } = await import('./qor-rezi-tui.js');
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

  if (certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    try {
      const certContent = fs.readFileSync(certPath, 'utf8');
      const keyContent = fs.readFileSync(keyPath, 'utf8');
      const combined = certContent + '\n' + keyContent;

      const certDir = path.dirname(haproxyCertPath);
      if (!fs.existsSync(certDir)) {
        fs.mkdirSync(certDir, { recursive: true });
      }

      fs.writeFileSync(haproxyCertPath, combined, 'utf8');
      log(`[CERT] Updated HAProxy cert.pem from ${path.basename(certPath)}`);
    } catch (e) {
      logErr(`[CERT] Failed to update HAProxy cert.pem: ${e.message}`);
    }
  } else {
    log(`[CERT] TLS_CERT_PATH/TLS_KEY_PATH not set or missing, skipping cert.pem update`);
  }
}

async function checkHaproxyCerts() {
  await checkHaproxyCertFile();
  await checkQuantumReady();
  await checkHaproxyBuiltOrReady();
}

async function checkStatsCredentials() {
  const credsFile = path.join(repoRoot, 'server', 'config', '.haproxy-stats-creds.pqc');
  const keysFile = path.join(repoRoot, 'server', 'config', '.haproxy-keys.enc');
  const secureCredentialsPath = path.join(repoRoot, 'server', 'config', 'secure-credentials.js');
  const loadSecureCredentials = () => import(pathToFileURL(secureCredentialsPath).href);

  const hasEnv = process.env.HAPROXY_STATS_USERNAME && process.env.HAPROXY_STATS_PASSWORD;
  const hasKeys = fs.existsSync(keysFile);

  if (hasEnv && hasKeys) return;

  if (hasEnv && !hasKeys) {
    try {
      log('[SECURE-CREDS] Generating missing command encryption keys...');
      const { saveCredentials } = await loadSecureCredentials();
      await saveCredentials(
        process.env.HAPROXY_STATS_USERNAME,
        process.env.HAPROXY_STATS_PASSWORD
      );
      if (fs.existsSync(keysFile)) return;
    } catch (e) {
      logErr('[SECURE-CREDS] Failed to generate keys: ' + e.message);
    }
  }
  const canPrompt = process.stdin.isTTY;

  // Unlock existing creds
  if (fs.existsSync(credsFile) && fs.existsSync(keysFile)) {
    if (!canPrompt) {
      logErr('HAProxy stats credentials exist but cannot prompt to unlock in non-interactive mode.');
      logErr('Provide HAPROXY_STATS_USERNAME and HAPROXY_STATS_PASSWORD in env.');
      logErr('Example: export HAPROXY_STATS_USERNAME=your_username');
      logErr('         export HAPROXY_STATS_PASSWORD=your_password');
      process.exit(1);
    }

    if (CONFIG.NO_GUI && !process.stdin.isTTY) {
      logErr('Cannot prompt for credentials in NO_GUI mode without a TTY.');
      logErr('Run in foreground or provide credentials via environment variables.');
      process.exit(1);
    }

    const readline = require('readline');
    const askLine = (q) => new Promise((resolve) => { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); rl.question(q, (ans) => { rl.close(); resolve(ans); }); });
    const askPassword = (prompt) => new Promise((resolve) => {
      process.stdout.write(prompt);
      const wasRaw = process.stdin.isRaw;
      process.stdin.setRawMode(true);
      process.stdin.setEncoding('utf8');
      process.stdin.resume();
      let buf = '';
      const onData = (c) => {
        c = String(c);
        if (c === '\n' || c === '\r' || c === '\u0004') {
          process.stdout.write('\n');
          process.stdin.removeListener('data', onData);
          process.stdin.setRawMode(wasRaw);
          resolve(buf);
          return;
        }
        buf += c;
      };
      process.stdin.on('data', onData);
    });

    const user = await askLine('Enter HAProxy stats username: ');
    const pass = await askPassword('Password: ');
    try {
      const { loadCredentials } = await loadSecureCredentials();
      const credentials = await loadCredentials({ username: user, password: pass });
      if (credentials?.username && credentials?.password) {
        process.env.HAPROXY_STATS_USERNAME = credentials.username;
        process.env.HAPROXY_STATS_PASSWORD = credentials.password;
        return;
      }
      logErr('Failed to unlock HAProxy stats credentials.');
      process.exit(1);
    } catch (e) {
      const stderr = String(e?.stderr || '');
      if (/Username does not match encrypted keyset/i.test(stderr)) {
        logErr('Username does not match stored credentials.');
      } else if (/decipher|decrypt|auth|decrypt/i.test(stderr)) {
        logErr('Incorrect password.');
      } else {
        logErr('Failed to unlock credentials.');
      }
      process.exit(1);
    }
  }

  // Create new creds
  if (!canPrompt) {
    const user = 'admin';
    const pass = crypto.randomBytes(32).toString('base64');
    process.env.HAPROXY_STATS_USERNAME = user;
    process.env.HAPROXY_STATS_PASSWORD = pass;
    try {
      const { saveCredentials } = await loadSecureCredentials();
      await saveCredentials(user, pass);
    } catch { }
    return;
  }

  const rl2 = require('readline').createInterface({ input: process.stdin, output: process.stdout });
  const ask2 = (q) => new Promise((res) => rl2.question(q, (ans) => res(ans)));
  let user = await ask2('Enter HAProxy stats username (default: admin): ');
  if (!user) user = 'admin';

  process.stdout.write('Enter a strong password (leave empty to generate): ');
  const pass1 = await new Promise((resolve) => {
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    let buf = '';
    const onData = (c) => {
      c = String(c);
      if (c === '\n' || c === '\r' || c === '\u0004') {
        process.stdout.write('\n');
        process.stdin.removeListener('data', onData);
        process.stdin.setRawMode(wasRaw);
        resolve(buf);
        return;
      }
      buf += c;
    };
    process.stdin.on('data', onData);
  });
  let password = pass1;
  if (!password) {
    password = crypto.randomBytes(32).toString('base64');
    console.log(`Generated password: ${password}`);
  } else {
    process.stdout.write('Confirm password: ');
    const pass2 = await new Promise((resolve) => {
      const wasRaw = process.stdin.isRaw;
      process.stdin.setRawMode(true);
      process.stdin.setEncoding('utf8');
      process.stdin.resume();
      let buf = '';
      const onData = (c) => {
        c = String(c);
        if (c === '\n' || c === '\r' || c === '\u0004') {
          process.stdout.write('\n');
          process.stdin.removeListener('data', onData);
          process.stdin.setRawMode(wasRaw);
          resolve(buf);
          return;
        }
        buf += c;
      };
      process.stdin.on('data', onData);
    });
    if (password !== pass2) {
      logErr('Passwords do not match. Aborting.');
      process.exit(1);
    }
  }

  process.env.HAPROXY_STATS_USERNAME = user;
  process.env.HAPROXY_STATS_PASSWORD = password;
  try {
    const { saveCredentials } = await loadSecureCredentials();
    await saveCredentials(user, password);
  } catch (e) {
    logErr('Failed to encrypt credentials');
    process.exit(1);
  }
  rl2.close();
}

(async () => {
  if (!fs.existsSync(lbScript)) {
    logErr('auto-loadbalancer not found at server/load-balancer/auto-loadbalancer.js');
    process.exit(1);
  }

  if (!CONFIG.NO_GUI) await validateTuiDependencies();

  await checkHaproxyCerts();
  await checkStatsCredentials();

  const hapBin = process.env.LB_HAPROXY_BIN;
  if (!hapBin) throw new Error('Bundled HAProxy runtime was not selected');

  if (!process.env.HAPROXY_CERT_PATH) {
    process.env.HAPROXY_CERT_PATH = path.join(repoRoot, 'server', 'config', 'certs');
  }
  const uid = (typeof process.getuid === 'function') ? String(process.getuid()) : 'nouid';
  process.env.HAPROXY_STATS_SOCKET = process.env.HAPROXY_STATS_SOCKET || path.join(os.tmpdir(), `haproxy-admin-${uid}.sock`);

  const env = { ...process.env, REDIS_URL: process.env.REDIS_URL, HAPROXY_HTTPS_PORT: String(CONFIG.HAPROXY_HTTPS_PORT), HAPROXY_STATS_PORT: String(CONFIG.HAPROXY_STATS_PORT), HAPROXY_STATS_SOCKET: process.env.HAPROXY_STATS_SOCKET };

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
        process.exit(code || 0);
      }, 100);
    });
    return;
  }

  const child = spawn(process.execPath, [lbScript], { cwd: repoRoot, env, stdio: ['ignore', 'pipe', 'pipe'] });

  let exitedImmediately = false;
  let capturedOutput = [];
  const immediateCheck = setTimeout(() => {
    exitedImmediately = false;
  }, 1000);

  const ui = new ReziLBTUI(child.pid);

  const last = []; const MAX = 200; const push = (l) => { last.push(l); if (last.length > MAX) last.shift(); };
  const collectLine = (line) => {
    if (!line.trim()) return;
    ui.add(line);
    push(line);
    if (exitedImmediately) capturedOutput.push(line);
  };
  const stdoutLines = createLineCollector(collectLine);
  const stderrLines = createLineCollector(collectLine);
  child.stdout.on('data', (chunk) => stdoutLines.push(chunk));
  child.stderr.on('data', (chunk) => stderrLines.push(chunk));
  child.on('exit', async (code) => {
    clearTimeout(immediateCheck);
    stdoutLines.flush();
    stderrLines.flush();
    await ui.stop();

    if (code === 0 && exitedImmediately !== false) {
      const hasExistingMsg = capturedOutput.some(l => /already running/i.test(l));
      if (hasExistingMsg) {
        // Extract existing PID
        const pidMatch = capturedOutput.join('\n').match(/PID:\s*(\d+)/);
        const existingPid = pidMatch ? parseInt(pidMatch[1], 10) : null;

        if (existingPid) {
          console.log(`\n[INFO] Stopping existing load balancer (PID: ${existingPid})...`);
          try {
            process.kill(existingPid, 'SIGTERM');
            setTimeout(async () => {
              console.log('[INFO] Restarting with TUI...\n');
              const restartChild = spawn(process.execPath, [lbScript], { cwd: repoRoot, env, stdio: ['ignore', 'pipe', 'pipe'] });
              const restartUi = new ReziLBTUI(restartChild.pid);
              const restartLast = [];
              const collectRestartLine = (line) => {
                if (!line.trim()) return;
                restartUi.add(line);
                restartLast.push(line);
                if (restartLast.length > MAX) restartLast.shift();
              };
              const restartStdoutLines = createLineCollector(collectRestartLine);
              const restartStderrLines = createLineCollector(collectRestartLine);
              restartChild.stdout.on('data', (chunk) => restartStdoutLines.push(chunk));
              restartChild.stderr.on('data', (chunk) => restartStderrLines.push(chunk));
              restartChild.on('exit', async (c) => {
                restartStdoutLines.flush();
                restartStderrLines.flush();
                await restartUi.stop();
                if (c !== 0) {
                  console.error(`\n[ERROR] Load balancer exited with code ${c}`);
                  if (restartLast.length) {
                    console.error('[ERROR] Last output:');
                    for (const l of restartLast) console.error('  ' + l);
                  }
                }
                process.exit(c || 0);
              });
              await restartUi.start();
            }, 500);
            return;
          } catch (e) {
            console.error('[ERROR] Failed to stop existing instance:', e.message);
          }
        }
      }

      if (capturedOutput.length) {
        console.log();
        for (const l of capturedOutput) console.log(l);
        console.log();
      }
      console.log('[INFO] Press Ctrl+C to exit');
      if (process.stdin.isTTY) {
        try { process.stdin.setRawMode(false); } catch { }
        process.stdin.pause();
      }
      const exitHandler = () => { console.log('\n'); process.exit(0); };
      process.on('SIGINT', exitHandler);
      process.on('SIGTERM', exitHandler);
      setInterval(() => { }, 1000);
      return;
    }

    if (code !== 0) {
      console.error(`\n[ERROR] Load balancer exited with code ${code}`);
      if (last.length) { console.error('[ERROR] Last output:'); for (const l of last) console.error('  ' + l); }
    }
    process.exit(code || 0);
  });

  exitedImmediately = true;
  await ui.start();
})();
