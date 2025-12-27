#!/usr/bin/env node
/*
 * Load balancer
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const lbScript = path.join(repoRoot, 'server', 'load-balancer', 'auto-loadbalancer.js');

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

if (!process.env.REDIS_URL) process.env.REDIS_URL = 'redis://127.0.0.1:6379';

const CONFIG = {
  NO_GUI: (process.env.NO_GUI || 'false').toLowerCase() === 'true',
  HAPROXY_HTTP_PORT: process.env.HAPROXY_HTTP_PORT || '8080',
  HAPROXY_HTTPS_PORT: process.env.HAPROXY_HTTPS_PORT || '8443',
  HAPROXY_STATS_PORT: process.env.HAPROXY_STATS_PORT || '8404',
};

if (!process.env.PRESENCE_REDIS_QUIET_ERRORS) {
  process.env.PRESENCE_REDIS_QUIET_ERRORS = 'true';
}

function log(...args) { console.log('[LB]', ...args); }
function logErr(...args) { console.error('[LB]', ...args); }

class CircularBuffer { constructor(n = 1000) { this.a = []; this.n = n; } push(x) { this.a.push(x); if (this.a.length > this.n) this.a.shift(); } get() { return this.a; } len() { return this.a.length; } }
class Debouncer { constructor(fn, d = 50) { this.fn = fn; this.d = d; this.t = null; this.p = false; } call() { this.p = true; if (this.t) return; this.t = setTimeout(() => { if (this.p) { this.fn(); this.p = false; } this.t = null; }, this.d); } flush() { if (this.t) { clearTimeout(this.t); this.t = null; } if (this.p) { this.fn(); this.p = false; } } }
class RateLimiter { constructor(ms = 1000) { this.ms = ms; this.last = 0; } ok() { const now = Date.now(); if (now - this.last >= this.ms) { this.last = now; return true; } return false; } }

async function getTunnelUrl() { try { const logPath = path.join(repoRoot, 'scripts', 'config', 'tunnel', 'cloudflared.log'); if (!fs.existsSync(logPath)) return null; const c = fs.readFileSync(logPath, 'utf8'); const m = c.match(/https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/); return m ? m[0] : null; } catch { return null; } }
function isHAProxyInstalled() { try { execSync('command -v haproxy >/dev/null 2>&1'); return true; } catch { return false; } }

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

async function readOqsModulePath() {
  try {
    const infoPath = path.join(repoRoot, 'server', 'config', 'oqs-module-path.txt');
    if (!fs.existsSync(infoPath)) return null;
    const raw = fs.readFileSync(infoPath, 'utf8').trim();
    if (!raw) return null;
    if (!fs.existsSync(raw)) return null;
    return raw;
  } catch {
    return null;
  }
}

async function ensureQuantumReady() {
  const localConf = path.join(repoRoot, 'server', 'config', 'openssl-oqs.cnf');
  const hapCfgPath = path.join(repoRoot, 'server', 'config', 'haproxy-quantum.cfg');

  let oqsModule = await readOqsModulePath();
  let env = { ...process.env, OPENSSL_CONF: localConf };
  if (oqsModule) {
    env.OQS_PROVIDER_MODULE = oqsModule;
    if (process.platform !== 'win32') {
      try { env.OPENSSL_MODULES = path.dirname(oqsModule); } catch { }
    }
  }

  let needSetup = !fs.existsSync(localConf) || !fs.existsSync(hapCfgPath);
  if (!needSetup) {
    const ok = await hasOqsProvider(env);
    if (!ok) needSetup = true;
  }
  if (needSetup) {
    log('Running quantum setup...');
    await runNodeScript(path.join(repoRoot, 'scripts', 'setup-quantum-haproxy.cjs'));
    oqsModule = await readOqsModulePath();
    env = { ...process.env, OPENSSL_CONF: localConf };
    if (oqsModule) {
      env.OQS_PROVIDER_MODULE = oqsModule;
      if (process.platform !== 'win32') {
        try { env.OPENSSL_MODULES = path.dirname(oqsModule); } catch { }
      }
    }
  }

  const ok2 = await hasOqsProvider(env);
  if (!ok2) {
    log('Ensuring dependencies (may prompt for sudo)...');
    await runNodeScript(path.join(repoRoot, 'scripts', 'install-deps.cjs'), ['quantum'], { ...process.env, FORCE_REBUILD: '1' });
    await runNodeScript(path.join(repoRoot, 'scripts', 'setup-quantum-haproxy.cjs'));
    oqsModule = await readOqsModulePath();
    env = { ...process.env, OPENSSL_CONF: localConf };
    if (oqsModule) {
      env.OQS_PROVIDER_MODULE = oqsModule;
      if (process.platform !== 'win32') {
        try { env.OPENSSL_MODULES = path.dirname(oqsModule); } catch { }
      }
    }
  }

  process.env.OPENSSL_CONF = localConf;
  process.env.LB_OPENSSL_CONF = localConf;
  process.env.LB_HAPROXY_CFG = hapCfgPath;
  if (oqsModule) {
    process.env.OQS_PROVIDER_MODULE = oqsModule;
    if (process.platform !== 'win32') {
      try { process.env.OPENSSL_MODULES = path.dirname(oqsModule); } catch { }
    }
  }
}

async function ensureHaproxyBuiltOrReady() {
  const localConf = process.env.LB_OPENSSL_CONF || path.join(repoRoot, 'server', 'config', 'openssl-oqs.cnf');
  const hapCfgPath = process.env.LB_HAPROXY_CFG || path.join(repoRoot, 'server', 'config', 'haproxy-quantum.cfg');
  const env = { ...process.env, OPENSSL_CONF: localConf };

  const buildMetaPath = path.join(repoRoot, 'server', 'config', 'haproxy-build.json');
  const builtBin = fs.existsSync(buildMetaPath) ? (JSON.parse(fs.readFileSync(buildMetaPath, 'utf8')).haproxy_bin || null) : null;

  // 1) Try system haproxy
  if (isHAProxyInstalled()) {
    const ok = await testHaproxyConfig('haproxy', hapCfgPath, env);
    if (ok) { process.env.LB_HAPROXY_BIN = 'haproxy'; return; }
  }
  // 2) Try previously built binary
  if (builtBin && fs.existsSync(builtBin)) {
    const ok2 = await testHaproxyConfig(builtBin, hapCfgPath, env);
    if (ok2) { process.env.LB_HAPROXY_BIN = builtBin; return; }
  }
  // 3) Build 
  log('Building HAProxy with OQS...');
  await runNodeScript(path.join(repoRoot, 'scripts', 'build-quantum-haproxy.cjs'));
  
  if (fs.existsSync(buildMetaPath)) {
    try {
      const meta = JSON.parse(fs.readFileSync(buildMetaPath, 'utf8'));
      if (meta.haproxy_bin && fs.existsSync(meta.haproxy_bin)) {
        const ok3 = await testHaproxyConfig(meta.haproxy_bin, hapCfgPath, env);
        if (ok3) { process.env.LB_HAPROXY_BIN = meta.haproxy_bin; return; }
      }
    } catch { }
  }
  logErr('Failed to prepare a HAProxy binary that validates the PQC config.');
  logErr('If you built to a temp dir, consider installing it: see server/config/haproxy-build.json');
  process.exit(1);
}

class LBTUI {
  constructor(childPid) {
    this.pid = childPid;
    this.buf = new CircularBuffer(1000);
    this.scroll = 0;
    this.run = true;
    this.w = process.stdout.columns || 80;
    this.h = process.stdout.rows || 24;
    this.renderDeb = new Debouncer(() => this.renderFrame(), 50);
    this.metrics = new RateLimiter(1000);
    this.stats = { cpu: '?', mem: '?', servers: 0, serverList: [], url: null, lbPort: CONFIG.HAPROXY_HTTPS_PORT };

    this.cmdMode = false;
    this.cmdInput = '';
    this.cmdCursor = 0;
    this.cmdHistory = [];
    this.cmdHistoryIndex = -1;
    this.cmdSuggestions = [];
    this.cmdSuggestionIndex = 0;
    this.showInlineSuggestion = true;

    // Available commands
    this.commands = [
      { name: '/help', desc: 'Show available commands', aliases: ['/h', '/?'] },
      { name: '/tunnel restart', desc: 'Restart Cloudflare tunnel', aliases: ['/tr'] },
      { name: '/tunnel status', desc: 'Show tunnel status', aliases: ['/ts'] },
      { name: '/reload', desc: 'Reload HAProxy configuration', aliases: ['/r'] },
      { name: '/servers', desc: 'Show active servers', aliases: ['/s'] },
      { name: '/clear', desc: 'Clear log buffer', aliases: ['/c'] },
      { name: '/quit', desc: 'Stop load balancer and exit', aliases: ['/q'] },
    ];

    process.stdout.on('resize', () => {
      this.w = process.stdout.columns || 80;
      this.h = process.stdout.rows || 24;
      this.renderDeb.call();
    });

    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true);
      process.stdin.setEncoding('utf8');
      try { process.stdin.resume(); } catch { }
      process.stdin.on('data', k => this.onKey(k));
    }

    process.stdout.write('\x1b[?1049h\x1b[?7l\x1b[2J\x1b[H\x1b[?25l');
  }

  stop() {
    if (!this.run) return;
    this.run = false;
    this.renderDeb.flush();
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    if (process.stdin.isTTY) {
      try { process.stdin.setRawMode(false); } catch { }
      try { process.stdin.pause(); } catch { }
    }
    process.stdout.write('\x1b[?7h\x1b[?25h\x1b[?1049l');
  }

  add(line) {
    this.buf.push(line);
    this.renderDeb.call();
  }

  updateCmdSuggestions() {
    if (!this.cmdInput.startsWith('/')) {
      this.cmdSuggestions = [];
      return;
    }

    const input = this.cmdInput.toLowerCase();
    this.cmdSuggestions = [];

    const exactMatches = [];
    const partialMatches = [];

    for (const cmd of this.commands) {
      if (cmd.name.toLowerCase() === input) {
        exactMatches.push(cmd.name);
      } else if (cmd.name.toLowerCase().startsWith(input)) {
        partialMatches.push(cmd.name);
      } else {
        for (const alias of cmd.aliases || []) {
          if (alias.toLowerCase().startsWith(input)) {
            partialMatches.push(cmd.name);
            break;
          }
        }
      }
    }

    this.cmdSuggestions = [...exactMatches, ...partialMatches];
    this.cmdSuggestionIndex = 0;
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

      const mod = await import(path.join(repoRoot, 'server', 'presence', 'presence.js'));
      const { withRedisClient } = mod;
      await withRedisClient(async (client) => {
        await client.publish('lb:command:encrypted', JSON.stringify(payload));
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
      } else if (cmdDef.name === '/tunnel restart') {
        this.add('Restarting tunnel...');
        try {
          await this.sendEncryptedCommand({ cmd: 'restart_tunnel', pid: this.pid });
          this.add('\x1b[32mTunnel restart command sent\x1b[0m');
        } catch (error) {
          this.add(`\x1b[31mError: ${error.message}\x1b[0m`);
        }
      } else if (cmdDef.name === '/tunnel status') {
        const url = this.stats.url || 'Not available';
        this.add(`Tunnel URL: \x1b[32m${url}\x1b[0m`);
      } else if (cmdDef.name === '/reload') {
        this.add('Reloading HAProxy configuration...');
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

  onKey(k) {
    const c = k.charCodeAt(0);

    if (this.cmdMode) {
      if (c === 3 || k === '\x1b') { // Ctrl+C or ESC
        this.cmdMode = false;
        this.cmdInput = '';
        this.cmdCursor = 0;
        this.cmdSuggestions = [];
        this.cmdHistoryIndex = -1;
        this.renderDeb.call();
        return;
      }

      if (k === '\r' || k === '\n') { // Enter
        const cmd = this.cmdInput;
        this.cmdMode = false;
        this.cmdInput = '';
        this.cmdCursor = 0;
        this.cmdSuggestions = [];
        this.cmdHistoryIndex = -1;
        this.renderDeb.call();
        if (cmd) this.executeCommand(cmd);
        return;
      }

      if (k === '\t') { // Tab autocomplete
        if (this.cmdSuggestions.length > 0) {
          this.cmdInput = this.cmdSuggestions[this.cmdSuggestionIndex];
          this.cmdCursor = this.cmdInput.length;
          this.cmdSuggestionIndex = (this.cmdSuggestionIndex + 1) % this.cmdSuggestions.length;
          this.updateCmdSuggestions();
          this.renderDeb.call();
        }
        return;
      }

      if (k === '\x7f' || k === '\b') { // Backspace
        if (this.cmdCursor > 0) {
          this.cmdInput = this.cmdInput.slice(0, this.cmdCursor - 1) + this.cmdInput.slice(this.cmdCursor);
          this.cmdCursor--;
          this.updateCmdSuggestions();
          this.renderDeb.call();
        }
        return;
      }

      if (k === '\x1b[3~') { // Delete
        if (this.cmdCursor < this.cmdInput.length) {
          this.cmdInput = this.cmdInput.slice(0, this.cmdCursor) + this.cmdInput.slice(this.cmdCursor + 1);
          this.updateCmdSuggestions();
          this.renderDeb.call();
        }
        return;
      }

      if (k === '\x1b[D') { // Left arrow
        if (this.cmdCursor > 0) {
          this.cmdCursor--;
          this.renderDeb.call();
        }
        return;
      }

      if (k === '\x1b[C') { // Right arrow
        if (this.cmdCursor < this.cmdInput.length) {
          this.cmdCursor++;
          this.renderDeb.call();
        }
        return;
      }

      if (k === '\x1b[H' || c === 1) { // Home or Ctrl+A
        this.cmdCursor = 0;
        this.renderDeb.call();
        return;
      }

      if (k === '\x1b[F' || c === 5) { // End or Ctrl+E
        this.cmdCursor = this.cmdInput.length;
        this.renderDeb.call();
        return;
      }

      if (k === '\x1b[A') { // Up arrow history
        if (this.cmdHistory.length > 0) {
          if (this.cmdHistoryIndex === -1) {
            this.cmdHistoryIndex = this.cmdHistory.length - 1;
          } else if (this.cmdHistoryIndex > 0) {
            this.cmdHistoryIndex--;
          }
          this.cmdInput = this.cmdHistory[this.cmdHistoryIndex];
          this.cmdCursor = this.cmdInput.length;
          this.updateCmdSuggestions();
          this.renderDeb.call();
        }
        return;
      }

      if (k === '\x1b[B') { // Down arrow history
        if (this.cmdHistoryIndex !== -1) {
          if (this.cmdHistoryIndex < this.cmdHistory.length - 1) {
            this.cmdHistoryIndex++;
            this.cmdInput = this.cmdHistory[this.cmdHistoryIndex];
          } else {
            this.cmdHistoryIndex = -1;
            this.cmdInput = '';
          }
          this.cmdCursor = this.cmdInput.length;
          this.updateCmdSuggestions();
          this.renderDeb.call();
        }
        return;
      }

      if (c >= 32 && c <= 126) {
        this.cmdInput = this.cmdInput.slice(0, this.cmdCursor) + k + this.cmdInput.slice(this.cmdCursor);
        this.cmdCursor++;
        this.updateCmdSuggestions();
        this.renderDeb.call();
        return;
      }

      return;
    }

    // Normal mode handling
    if (k === '/' || k === ':') {
      this.cmdMode = true;
      this.cmdInput = '/';
      this.cmdCursor = 1;
      this.updateCmdSuggestions();
      this.renderDeb.call();
      return;
    }

    if (k === 'q' || k === 'Q' || c === 3) {
      this.stop();
      try { process.kill(this.pid, 'SIGTERM'); } catch { }
      return;
    }

    const vis = Math.max(1, this.h - 7);
    const max = Math.max(0, this.buf.len() - vis);

    if (k === '\x1b[A' || k === 'k') {
      this.scroll = Math.min(this.scroll + 1, max);
      this.renderDeb.call();
    } else if (k === '\x1b[B' || k === 'j') {
      this.scroll = Math.max(this.scroll - 1, 0);
      this.renderDeb.call();
    } else if (k === '\x1b[5~' || c === 21) {
      this.scroll = Math.min(this.scroll + vis, max);
      this.renderDeb.call();
    } else if (k === '\x1b[6~' || c === 4) {
      this.scroll = Math.max(this.scroll - vis, 0);
      this.renderDeb.call();
    } else if (k === 'g') {
      this.scroll = max;
      this.renderDeb.call();
    } else if (k === 'G') {
      this.scroll = 0;
      this.renderDeb.call();
    }
  }
  poll() {
    if (!this.metrics.ok()) return;
    try { const out = execSync(`ps -p ${this.pid} -o %cpu=,%mem=`, { encoding: 'utf8', timeout: 500 }).trim().split(/\s+/); if (out.length >= 2) { this.stats.cpu = out[0]; this.stats.mem = out[1]; } } catch { }
    this.getActiveServers().then(servers => { this.stats.servers = servers.length; this.stats.serverList = servers; this.renderDeb.call(); }).catch(() => { });
    this.getLbPort().then(port => { if (port) this.stats.lbPort = port; this.renderDeb.call(); }).catch(() => { });
    getTunnelUrl().then(u => { this.stats.url = u; this.renderDeb.call(); }).catch(() => { });
  }

  async getActiveServers() {
    try {
      const mod = await import(path.join(repoRoot, 'server', 'presence', 'presence.js'));
      const { withRedisClient } = mod;
      return await withRedisClient(async (client) => {
        const servers = await client.hgetall('cluster:servers');
        const now = Date.now();
        const active = [];
        for (const [id, data] of Object.entries(servers || {})) {
          try {
            const info = JSON.parse(data);
            if (now - (info.lastHeartbeat || 0) < 10000) {
              active.push({ id, host: info.host || '127.0.0.1', port: info.port || '?' });
            }
          } catch { }
        }
        return active;
      });
    } catch (e) {
      return [];
    }
  }

  async getLbPort() {
    try {
      const mod = await import(path.join(repoRoot, 'server', 'presence', 'presence.js'));
      const { withRedisClient } = mod;
      return await withRedisClient(async (client) => {
        const val = await client.get('cluster:lb:httpsPort');
        if (!val) return null;
        const num = Number(val);
        if (!Number.isFinite(num) || num <= 0 || num > 65535) return String(val);
        return String(num);
      });
    } catch (e) {
      return null;
    }
  }
  
  start() {
    this.renderDeb.call();
    this.interval = setInterval(() => {
      this.poll();
      this.renderDeb.call();
    }, 1000);
    process.on('SIGINT', () => this.stop());
    process.on('SIGTERM', () => this.stop());
  }

  renderFrame() {
    if (!this.run) return;
    const w = this.w, h = this.h;
    const lines = [];

    // Header
    const left = ` Load Balancer `;
    const center = ` PID ${this.pid} | CPU ${this.stats.cpu}% | MEM ${this.stats.mem}% `;
    const urlShort = this.stats.url ? this.stats.url : 'pending...';
    const right = ` ${urlShort} `;
    const leftLen = left.length, centerLen = center.length, rightLen = right.length;
    let cst = Math.max(leftLen + 1, Math.floor((w - centerLen) / 2));
    let rst = Math.max(cst + centerLen + 1, w - rightLen);
    let hdr = '';
    hdr += left;
    hdr += ' '.repeat(Math.max(0, cst - leftLen));
    if (cst + centerLen < rst) {
      hdr += center;
      hdr += ' '.repeat(Math.max(0, rst - cst - centerLen));
    }
    if (rst + rightLen <= w) {
      hdr += right.substring(0, w - rst);
    }
    hdr = hdr.substring(0, w);
    hdr += ' '.repeat(Math.max(0, w - hdr.length));
    lines.push('\x1b[30;46;1m' + hdr + '\x1b[0m');

    // Stats line
    const httpsPort = this.stats.lbPort || CONFIG.HAPROXY_HTTPS_PORT;
    const statsLeft = `\x1b[36mStats: http://localhost:${CONFIG.HAPROXY_STATS_PORT}/haproxy-stats\x1b[0m  \x1b[36mHTTPS :${httpsPort}\x1b[0m`;
    const serverInfo = `\x1b[33mServers: ${this.stats.servers}\x1b[0m`;
    const statsLeftClean = statsLeft.replace(/\x1b\[[^m]*m/g, '');
    const serverInfoClean = serverInfo.replace(/\x1b\[[^m]*m/g, '');
    const padding = ' '.repeat(Math.max(0, w - statsLeftClean.length - serverInfoClean.length));
    lines.push(statsLeft + padding + serverInfo);

    // Log area
    lines.push('┌' + '─'.repeat(Math.max(0, w - 2)) + '┐');
    const vis = Math.max(1, h - 7);
    const start = Math.max(0, this.buf.len() - vis - this.scroll);
    const end = this.buf.len() - this.scroll;
    const slice = this.buf.get().slice(start, end);
    for (let i = 0; i < vis; i++) {
      const ln = slice[i] || '';
      const tr = ln.substring(0, Math.max(0, w - 4));
      const pad = tr + ' '.repeat(Math.max(0, w - 4 - tr.length));
      const sb = i === 0 && this.scroll > 0 ? '▲' : (i === vis - 1 && (this.buf.len() - end) > 0 ? '▼' : '│');
      lines.push('│ ' + pad + ' ' + sb);
    }
    lines.push('└' + '─'.repeat(Math.max(0, w - 2)) + '┘');

    // Command area
    if (this.cmdMode) {
      const cmdPrefix = 'Command: ';
      const maxInputWidth = w - cmdPrefix.length - 2;
      const cmdDisplay = this.cmdInput.substring(0, maxInputWidth);
      const cursorPos = Math.min(this.cmdCursor, cmdDisplay.length);

      let inlineSuggestion = '';
      if (this.cmdSuggestions.length > 0 && this.cmdInput.length > 0 && this.cmdCursor === this.cmdInput.length) {
        const firstSuggestion = this.cmdSuggestions[0];
        if (firstSuggestion.toLowerCase().startsWith(this.cmdInput.toLowerCase())) {
          inlineSuggestion = firstSuggestion.substring(this.cmdInput.length);
        }
      }

      const beforeCursor = cmdDisplay.substring(0, cursorPos);
      const atCursor = cmdDisplay[cursorPos] || (inlineSuggestion ? inlineSuggestion[0] : ' ');
      const afterCursor = cmdDisplay.substring(cursorPos + 1);

      let cmdLine = cmdPrefix + beforeCursor + '\x1b[7m' + atCursor + '\x1b[0m\x1b[30;43m' + afterCursor;
      if (cursorPos === this.cmdInput.length && inlineSuggestion.length > 0) {
        cmdLine += '\x1b[90m' + inlineSuggestion.substring(cursorPos === cmdDisplay.length ? 1 : 0) + '\x1b[0m\x1b[30;43m';
      }

      const totalLen = cmdPrefix.length + cmdDisplay.length + (inlineSuggestion.length > 0 ? inlineSuggestion.length : 0);
      const cmdLinePad = ' '.repeat(Math.max(0, w - totalLen));
      lines.push('\x1b[30;43m' + cmdLine + cmdLinePad + '\x1b[0m');

      lines.push(' '.repeat(w));
    } else {
      const footer = ' /: command  q: quit  Arrows PgUp/PgDn Home/End';
      const foot = footer + ' '.repeat(Math.max(0, w - footer.length));
      lines.push('\x1b[30;46m' + foot.substring(0, w) + '\x1b[0m');
      lines.push(' '.repeat(w));
    }

    const out = '\x1b[H' + lines.join('\n');
    try {
      process.stdout.write(out);
    } catch { }
  }
}


async function ensureHaproxyCertFile() {
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

async function ensureHaproxyCerts() {
  await ensureHaproxyCertFile();
  await ensureQuantumReady();
  await ensureHaproxyBuiltOrReady();
}

async function ensureStatsCredentials() {
  const credsFile = path.join(repoRoot, 'server', 'config', '.haproxy-stats-creds.pqc');
  const keysFile = path.join(repoRoot, 'server', 'config', '.haproxy-keys.enc');
  const secureCli = path.join(repoRoot, 'server', 'config', 'secure-credentials.js');

  if (process.env.HAPROXY_STATS_USERNAME && process.env.HAPROXY_STATS_PASSWORD) return;
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
      const out = execSync(`${process.execPath} ${JSON.stringify(secureCli)} load-unlocked ${JSON.stringify(user)} ${JSON.stringify(pass)}`, { encoding: 'utf8' });
      const mUser = out.match(/\bUsername:\s*(.*)/);
      const mPass = out.match(/\bPassword:\s*(.*)/);
      if (mUser && mPass) {
        process.env.HAPROXY_STATS_USERNAME = mUser[1].trim();
        process.env.HAPROXY_STATS_PASSWORD = mPass[1].trim();
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
    const pass = execSync('openssl rand -base64 32', { encoding: 'utf8' }).trim();
    process.env.HAPROXY_STATS_USERNAME = user;
    process.env.HAPROXY_STATS_PASSWORD = pass;
    try {
      execSync(`${process.execPath} ${JSON.stringify(secureCli)} save ${JSON.stringify(user)} ${JSON.stringify(pass)}`, { stdio: 'inherit' });
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
    password = execSync('openssl rand -base64 32', { encoding: 'utf8' }).trim();
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
    execSync(`${process.execPath} ${JSON.stringify(secureCli)} save ${JSON.stringify(user)} ${JSON.stringify(password)}`, { stdio: 'inherit' });
  } catch (e) {
    logErr('Failed to encrypt credentials');
    process.exit(1);
  }
  rl2.close();
}

(async () => {
  if (!fs.existsSync(lbScript)) {
    logErr('auto-loadbalancer not found at server/loadbalancer/auto-loadbalancer.js');
    process.exit(1);
  }

  console.log('\x1b[34m╔════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[34m║\x1b[32m            Load Balancer                 \x1b[34m║\x1b[0m');
  console.log('\x1b[34m╚════════════════════════════════════════════╝\x1b[0m');

  await ensureHaproxyCerts();
  await ensureStatsCredentials();

  const hapBin = process.env.LB_HAPROXY_BIN || 'haproxy';
  process.env.LB_HAPROXY_BIN = hapBin;

  if (!process.env.HAPROXY_CERT_PATH) {
    process.env.HAPROXY_CERT_PATH = path.join(repoRoot, 'server', 'config', 'certs');
  }
  const uid = (typeof process.getuid === 'function') ? String(process.getuid()) : 'nouid';
  process.env.HAPROXY_STATS_SOCKET = process.env.HAPROXY_STATS_SOCKET || path.join(os.tmpdir(), `haproxy-admin-${uid}.sock`);

  const env = { ...process.env, REDIS_URL: process.env.REDIS_URL, HAPROXY_HTTP_PORT: String(CONFIG.HAPROXY_HTTP_PORT), HAPROXY_HTTPS_PORT: String(CONFIG.HAPROXY_HTTPS_PORT), HAPROXY_STATS_PORT: String(CONFIG.HAPROXY_STATS_PORT), HAPROXY_STATS_SOCKET: process.env.HAPROXY_STATS_SOCKET };

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

  const ui = new LBTUI(child.pid);

  const last = []; const MAX = 200; const push = (l) => { last.push(l); if (last.length > MAX) last.shift(); };
  const onData = (d) => {
    String(d).split('\n').forEach((ln) => {
      if (ln.trim()) {
        ui.add(ln);
        push(ln);
        if (exitedImmediately) capturedOutput.push(ln);
      }
    });
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  child.on('exit', (code) => {
    clearTimeout(immediateCheck);
    ui.stop();

    if (code === 0 && exitedImmediately !== false) {
      const hasExistingMsg = capturedOutput.some(l => /already running/i.test(l));
      if (hasExistingMsg) {
        // Extract existing PID
        const pidMatch = capturedOutput.join('\n').match(/PID:\s*(\d+)/);
        const existingPid = pidMatch ? parseInt(pidMatch[1], 10) : null;

        if (existingPid) {
          // Kill existing instance and restart with TUI
          console.log(`\n[INFO] Stopping existing load balancer (PID: ${existingPid})...`);
          try {
            process.kill(existingPid, 'SIGTERM');
            setTimeout(() => {
              console.log('[INFO] Restarting with TUI...\n');
              const restartChild = spawn(process.execPath, [lbScript], { cwd: repoRoot, env, stdio: ['ignore', 'pipe', 'pipe'] });
              const restartUi = new LBTUI(restartChild.pid);
              const restartLast = [];
              const restartOnData = (d) => { String(d).split('\n').forEach((ln) => { if (ln.trim()) { restartUi.add(ln); restartLast.push(ln); if (restartLast.length > MAX) restartLast.shift(); } }); };
              restartChild.stdout.on('data', restartOnData);
              restartChild.stderr.on('data', restartOnData);
              restartChild.on('exit', (c) => { restartUi.stop(); if (c !== 0) { console.error(`\n[ERROR] Load balancer exited with code ${c}`); if (restartLast.length) { console.error('[ERROR] Last output:'); for (const l of restartLast) console.error('  ' + l); } } process.exit(c || 0); });
              restartUi.start();
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
  ui.start();
})();
