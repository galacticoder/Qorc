#!/usr/bin/env node
/**
 * Automatic Load Balancer Manager
 * 
 * Monitors Redis for active servers and automatically:
 * - Generates HAProxy configuration
 * - Starts/stops HAProxy based on server count
 * - Updates configuration when servers join/leave
 * - Supports cross-machine server discovery
 */

import { withRedisClient } from '../presence/presence.js';
import { HAProxyConfigGenerator } from './haproxy-config-generator.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import net from 'net';
import { fileURLToPath } from 'url';

const execFileAsync = promisify(execFile);

function findInPath(binName) {
  const pathEnv = process.env.PATH || '';
  const parts = pathEnv.split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
  for (const dir of parts) {
    for (const ext of exts) {
      const candidate = path.join(dir, binName + ext);
      try {
        if (existsSync(candidate)) return candidate;
      } catch { }
    }
  }
  return null;
}

async function deleteCloudflaredTunnels() {
  try {
    const pidPath = path.join(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'config', 'tunnel', 'pid'));
    if (existsSync(pidPath)) {
      const pid = parseInt(await fs.readFile(pidPath, 'utf8'), 10);
      try { process.kill(pid, 'SIGTERM'); } catch { }
      await fs.unlink(pidPath).catch(() => { });
    }
  } catch { }

  if (process.platform !== 'win32') {
    try {
      await execFileAsync('pkill', ['cloudflared']);
    } catch { }
  }
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const DEFAULT_HTTPS_PORT = parseInt(process.env.HAPROXY_HTTPS_PORT || (isRoot ? '443' : '8443'), 10);
const TMPDIR = os.tmpdir();
const HAPROXY_CONFIG_PATH = process.env.HAPROXY_CONFIG_PATH ||
  path.join('/app/server/config', 'haproxy-auto.cfg');
const HAPROXY_PID_FILE = process.env.HAPROXY_PID_FILE ||
  (isRoot && process.platform !== 'win32' ? '/var/run/haproxy-auto.pid' : path.join(TMPDIR, 'haproxy-auto.pid'));
const LOADBALANCER_LOCK_FILE = process.env.LOADBALANCER_LOCK_FILE ||
  (isRoot && process.platform !== 'win32' ? '/var/run/auto-loadbalancer.pid' : path.join(TMPDIR, 'auto-loadbalancer.pid'));
const MIN_SERVERS_FOR_LB = 1; // Start load balancer when at least one server is available

class AutoLoadBalancer {
  constructor() {
    this.isRunning = false;
    this.haproxyPid = null;
    this.listenPort = DEFAULT_HTTPS_PORT;
    this.lastServerCount = 0;
    this.lastServerHash = '';
    this.monitorInterval = null;
    this.consecutiveFailures = 0;
    this.maxConsecutiveFailures = 3;
    this.lastTunnelCheck = 0;
    this.tunnelCheckInterval = 1000;
    this.lastTunnelRestart = 0;
    this.tunnelRestartFailures = 0;
    this.maxTunnelRestartFailures = 5;
    this.tunnelBackoffMs = 10000;
    this.tunnelDisabled = false;
    this.isStopping = false;
    this.commandSubscriber = null;
    this.commandQueue = [];
    this.processingCommand = false;
    this.commandEncryptionKey = null;
    const here = fileURLToPath(import.meta.url);
    const clusterDir = path.dirname(here);
    this.serverDir = path.resolve(clusterDir, '..');
    this.repoRoot = path.resolve(this.serverDir, '..');
    this.scriptsDir = path.resolve(this.repoRoot, 'scripts');
  }

  /**
   * Get active servers from Redis
   */
  async getActiveServers() {
    return await withRedisClient(async (client) => {
      const servers = await client.hgetall('cluster:servers');
      const now = Date.now();
      const activeServers = [];

      for (const [serverId, data] of Object.entries(servers)) {
        try {
          const serverInfo = JSON.parse(data);
          const lastHeartbeat = serverInfo.lastHeartbeat || 0;
          const age = now - lastHeartbeat;

          // Server is active if heartbeat is less than 10 seconds old
          if (age < 10000) {
            activeServers.push({
              serverId,
              host: serverInfo.host || '127.0.0.1',
              port: serverInfo.port || 8443,
              lastHeartbeat,
              ...serverInfo
            });
          }
        } catch (err) {
          cryptoLogger.error('[AUTO-LB] Failed to parse server data', { serverId, error: err.message });
        }
      }

      return activeServers;
    });
  }

  /**
   * Find an available HTTPS listen port that does not conflict with backends
   */
  async resolveListenPort(servers) {
    const backendPorts = new Set();
    for (const s of servers || []) {
      const p = Number(s.port) || 0;
      if (p > 0 && p < 65536) backendPorts.add(p);
    }

    const isPortFree = (port) => new Promise((resolve) => {
      const srv = net.createServer();
      srv.unref();
      srv.on('error', () => resolve(false));
      srv.listen({ port, host: '0.0.0.0' }, () => {
        srv.close(() => resolve(true));
      });
    });

    let candidate = DEFAULT_HTTPS_PORT;
    for (let i = 0; i < 20; i += 1) {
      const port = candidate + i;
      if (backendPorts.has(port)) continue;
      const free = await isPortFree(port);
      if (free) return port;
    }
    return DEFAULT_HTTPS_PORT;
  }

  /**
   * Generate HAProxy configuration from active servers
   */
  async generateHAProxyConfig(servers) {
    const listenPort = await this.resolveListenPort(servers);
    this.listenPort = listenPort;

    const generator = new HAProxyConfigGenerator({
      listenPort,
      httpPort: parseInt(process.env.HAPROXY_HTTP_PORT || (isRoot ? '80' : '8080'), 10),
      statsPort: parseInt(process.env.HAPROXY_STATS_PORT || '8404', 10),
      tlsCertPath: process.env.HAPROXY_CERT_PATH || '/etc/haproxy/certs',
      statsUsername: process.env.HAPROXY_STATS_USERNAME || 'admin',
      statsPassword: process.env.HAPROXY_STATS_PASSWORD || 'adminpass',
    });

    try {
      await withRedisClient(async (client) => {
        await client.set('cluster:lb:httpsPort', String(listenPort));
      });
    } catch {
    }

    for (const server of servers) {
      generator.addBackend({
        name: server.serverId,
        host: server.host,
        port: server.port,
        weight: 100,
        maxconn: 10000,
      });
    }

    if (generator.backends.length === 0 && servers.length > 0) {
      console.log(`\n[WARNING] No valid backends found - all servers have invalid ports`);
      console.log(`[WARNING] Servers need to be restarted with valid ports\n`);
      return null;
    }

    if (generator.backends.length === 0) {
      console.log(`\n[WARNING] No servers detected - HAProxy will return 503 until servers come online\n`);
    }

    const config = generator.generateConfig();
    const configDir = path.dirname(HAPROXY_CONFIG_PATH);
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 });
    await fs.writeFile(HAPROXY_CONFIG_PATH, config, { mode: 0o600 });

    return config;
  }

  /**
   * Check if HAProxy is installed
   */
  async isHAProxyInstalled() {
    try {
      const bin = process.env.HAPROXY_BIN || 'haproxy';
      return !!findInPath(bin);
    } catch {
      return false;
    }
  }


  /**
 * Check if cloudflared tunnel is running
 */
  async isTunnelRunning() {
    try {
      const pidPath = path.join(this.scriptsDir, 'config', 'tunnel', 'pid');

      if (existsSync(pidPath)) {
        const pidContent = await fs.readFile(pidPath, 'utf8');
        const pid = parseInt(pidContent, 10);

        try {
          process.kill(pid, 0);
          return true;
        } catch {
          return false;
        }
      }

      return false;
    } catch {
      return false;
    }
  }

  /**
   * Restart cloudflared tunnel
   */
  async restartTunnel() {
    try {
      console.log('\n[TUNNEL] Restarting tunnel...');

      // Stop existing tunnel
      const pidPath = path.join(this.scriptsDir, 'config', 'tunnel', 'pid');
      if (existsSync(pidPath)) {
        try {
          const pid = parseInt(await fs.readFile(pidPath, 'utf8'), 10);
          process.kill(pid, 'SIGTERM');
        } catch {}
        await fs.unlink(pidPath).catch(() => {});
      }

      const logPath = path.join(this.scriptsDir, 'config', 'tunnel', 'cloudflared.log');
      const port = this.listenPort || DEFAULT_HTTPS_PORT;
      
      await fs.mkdir(path.dirname(logPath), { recursive: true, mode: 0o700 });
      await fs.mkdir(path.dirname(pidPath), { recursive: true, mode: 0o700 });

      const cloudflaredBin = findInPath('cloudflared');
      if (!cloudflaredBin) {
        console.error('[TUNNEL] cloudflared not found');
        return false;
      }

      try {
        await fs.writeFile(logPath, '', { mode: 0o600 });
      } catch {
      }

      const args = ['tunnel', '--url', `https://127.0.0.1:${port}`, '--no-tls-verify'];

      let logFile;
      try {
        logFile = await fs.open(logPath, 'a', 0o600);
      } catch {
        logFile = null;
      }

      const child = spawn(cloudflaredBin, args, {
        detached: true,
        stdio: ['ignore', logFile ? logFile.fd : 'ignore', logFile ? logFile.fd : 'ignore'],
        env: { ...process.env }
      });
      child.unref();
      if (logFile) {
        try { await logFile.close(); } catch { }
      }
      await fs.writeFile(pidPath, String(child.pid), { mode: 0o600 });
      
      console.log('[TUNNEL] Waiting for tunnel URL to appear in log...');
      let tunnelUrl = null;
      for (let i = 0; i < 40 && !tunnelUrl; i += 1) {
        await sleep(1000);
        tunnelUrl = await this.getTunnelUrl();
        try {
          process.kill(child.pid, 0);
        } catch {
          break;
        }
        if (i > 0 && i % 5 === 0 && !tunnelUrl) {
          console.log(`[TUNNEL] Still waiting... (${i} seconds)`);
        }
      }

      if (tunnelUrl) {
        try { const u = new URL(tunnelUrl); tunnelUrl = `https://${u.hostname}`; } catch { }
        console.log(`[TUNNEL] Tunnel restarted: ${tunnelUrl}`);
        return true;
      }

      console.log('[TUNNEL] Tunnel started but no public URL was detected within 40 seconds');

      try {
        const content = await fs.readFile(logPath, 'utf8');
        const lines = content.split('\n').filter(Boolean);
        const tail = lines.slice(Math.max(0, lines.length - 30));
        if (tail.length > 0) {
          console.log('[TUNNEL] cloudflared log tail:');
          for (const line of tail) {
            console.log(`  ${line.slice(0, 500)}`);
          }
        }
      } catch {
      }
      return false;
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to restart tunnel', error);
      console.error('[TUNNEL] Failed to restart:', error.message);
      return false;
    }
  }
  
  /**
   * Get tunnel URL from cloudflared log
   */
  async getTunnelUrl() {
    try {
      const logPath = path.join(this.scriptsDir, 'config', 'tunnel', 'cloudflared.log');
      if (!existsSync(logPath)) return null;
      
      const content = await fs.readFile(logPath, 'utf8');
      const lines = content.split('\n');
      for (let i = lines.length - 1; i >= 0; i--) {
        const match = lines[i].match(/https?:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com(?:\/)?/);
        if (match) {
          return match[0].replace(/\/$/, '');
        }
      }
      return null;
    } catch (_err) {
      return null;
    }
  }

  /**
   * Display HAProxy status and URLs
   */
  async displayHAProxyStatus(pid, skipTunnel = false) {
    const servers = await this.getActiveServers();

    console.log(`\n[OK] HAProxy Load Balancer Running`);
    console.log(`\tPID: ${pid}`);
    console.log(`\tActive Servers: ${servers.length}`);
    if (servers.length > 0) {
      servers.forEach(s => {
        console.log(`\t  - ${s.serverId} (${s.host}:${s.port})`);
      });
    }
    console.log(`\tStats Dashboard: http://localhost:${process.env.HAPROXY_STATS_PORT || 8404}/haproxy-stats`);
    
    if (!skipTunnel) {
      const tunnelUrl = await this.getTunnelUrl();
      if (tunnelUrl) {
        console.log(`\tTunnel URL: ${tunnelUrl}`);
      }
    }
    console.log();
  }

  /**
   * Start HAProxy with generated configuration
   */
  async startHAProxy() {
    if (!await this.isHAProxyInstalled()) {
      cryptoLogger.warn('[AUTO-LB] HAProxy not installed');
      console.log('[WARNING] HAProxy not installed. Install it first (e.g., run: node scripts/install-deps.cjs haproxy), then retry.');
      return false;
    }

    try {
      if (existsSync(HAPROXY_PID_FILE)) {
        const pid = parseInt(await fs.readFile(HAPROXY_PID_FILE, 'utf8'), 10);
        try {
          process.kill(pid, 0);
          this.haproxyPid = pid;
          this.isRunning = true;

          await this.displayHAProxyStatus(pid, true);

          return true;
        } catch {
          await fs.unlink(HAPROXY_PID_FILE);
        }
      }

      // Start HAProxy
      const env = { ...process.env };
      if (process.platform !== 'win32' && process.env.LD_LIBRARY_PATH) {
        env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
      }
      let openssl_conf = '';
      if (process.platform !== 'win32' && process.env.OPENSSL_CONF) {
        try {
          if (existsSync(process.env.OPENSSL_CONF)) openssl_conf = process.env.OPENSSL_CONF;
        } catch { }
      }
      if (openssl_conf) {
        env.OPENSSL_CONF = openssl_conf;
      }

      let oqs_module = '';
      if (process.platform !== 'win32' && process.env.OQS_PROVIDER_MODULE) {
        try {
          if (existsSync(process.env.OQS_PROVIDER_MODULE)) oqs_module = process.env.OQS_PROVIDER_MODULE;
        } catch { }
      }
      if (oqs_module) {
        env.OQS_PROVIDER_MODULE = oqs_module;
      }
      // Clean up stale stats socket if present
      try {
        const uid = (typeof process.getuid === 'function') ? String(process.getuid()) : 'nouid';
        const statsSock = process.env.HAPROXY_STATS_SOCKET || path.join(os.tmpdir(), `haproxy-admin-${uid}.sock`);
        if (existsSync(statsSock)) { await fs.unlink(statsSock).catch(() => { }); }
      } catch { }
      await execFileAsync('haproxy', ['-f', HAPROXY_CONFIG_PATH, '-D', '-p', HAPROXY_PID_FILE], { env });

      const pid = parseInt(await fs.readFile(HAPROXY_PID_FILE, 'utf8'), 10);
      this.haproxyPid = pid;
      this.isRunning = true;

      // Display status for newly started HAProxy
      await this.displayHAProxyStatus(pid, true);

      this.consecutiveFailures = 0;
      return true;
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to start HAProxy', error);
      console.error('[ERROR] Failed to start HAProxy:', error.message);

      this.consecutiveFailures++;
      if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
        console.error(`\n[FATAL] HAProxy failed ${this.consecutiveFailures} times consecutively.`);
        console.error('[FATAL] Configuration issues detected. Please check the HAProxy config.');
        console.error('[FATAL] Exiting to prevent endless retry loop.\n');
        process.exit(1);
      }

      return false;
    }
  }

  /**
   * Stop HAProxy
   */
  async stopHAProxy() {
    try {
      if (existsSync(HAPROXY_PID_FILE)) {
        const pid = parseInt(await fs.readFile(HAPROXY_PID_FILE, 'utf8'), 10);

        // Try to kill the process
        try {
          process.kill(pid, 'SIGTERM');
          cryptoLogger.info('[AUTO-LB] Stopped HAProxy', { pid });
          console.log(`[STOPPED] HAProxy stopped (PID: ${pid})`);
        } catch (_killError) {
          console.log(`[WARN] HAProxy process ${pid} not found (may have already exited)`);
        }

        try {
          await fs.unlink(HAPROXY_PID_FILE);
        } catch (unlinkError) {
          if (unlinkError.code !== 'ENOENT') {
            throw unlinkError;
          }
        }

        this.isRunning = false;
        this.haproxyPid = null;
      } else {
        console.log('[INFO] No HAProxy PID file found (already stopped)');
      }
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to stop HAProxy', error);
      console.error(`[ERROR] Failed to stop HAProxy: ${error.message}`);
    }
  }

  /**
   * Reload HAProxy 
   */
  async reloadHAProxy() {
    if (!this.isRunning || !existsSync(HAPROXY_PID_FILE)) {
      return await this.startHAProxy();
    }

    try {
      // Validate config first
      const env = { ...process.env };
      if (process.platform !== 'win32') {
        if (process.env.LD_LIBRARY_PATH) {
          env.LD_LIBRARY_PATH = process.env.LD_LIBRARY_PATH;
        }
        if (process.env.OPENSSL_CONF) {
          env.OPENSSL_CONF = process.env.OPENSSL_CONF;
        }
        if (process.env.OQS_PROVIDER_MODULE) {
          env.OQS_PROVIDER_MODULE = process.env.OQS_PROVIDER_MODULE;
        }
      }

      const { stdout: validationOutput } = await execFileAsync('haproxy', ['-f', HAPROXY_CONFIG_PATH, '-c'], { env });
      cryptoLogger.info('[AUTO-LB] HAProxy config validated', { output: validationOutput.trim() });

      // Soft reload 
      const oldPid = parseInt(await fs.readFile(HAPROXY_PID_FILE, 'utf8'), 10);
      await execFileAsync('haproxy', ['-f', HAPROXY_CONFIG_PATH, '-D', '-p', HAPROXY_PID_FILE, '-sf', String(oldPid)], { env });

      const newPid = parseInt(await fs.readFile(HAPROXY_PID_FILE, 'utf8'), 10);
      this.haproxyPid = newPid;

      cryptoLogger.info('[AUTO-LB] Reloaded HAProxy', { oldPid, newPid });
      console.log(`\n[RELOADED] HAProxy configuration updated`);
      console.log(`\tOld PID: ${oldPid} → New PID: ${newPid}`);

      const tunnelUrl = await this.getTunnelUrl();
      if (tunnelUrl) {
        console.log(`\tTunnel URL: ${tunnelUrl}`);
      }
      console.log(`\treload successful\n`);

      this.consecutiveFailures = 0;
      return true;
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to reload HAProxy', error);
      console.error('[ERROR] Failed to reload HAProxy:', error.message);

      // Log stderr if available
      if (error.stderr) {
        console.error('[ERROR] HAProxy stderr:', error.stderr);
      }

      this.consecutiveFailures++;
      if (this.consecutiveFailures >= this.maxConsecutiveFailures) {
        console.error(`\n[FATAL] HAProxy reload failed ${this.consecutiveFailures} times consecutively.`);
        console.error('[FATAL] Configuration issues detected. Exiting.\n');
        process.exit(1);
      }

      return false;
    }
  }

  /**
   * Generate a hash of server configuration for change detection
   */
  generateServerHash(servers) {
    const sorted = [...servers].sort((a, b) => a.serverId.localeCompare(b.serverId));
    return sorted.map(s => `${s.serverId}:${s.host}:${s.port}`).join('|');
  }

  /**
   * Monitor cluster and manage load balancer
   */
  async monitor() {
    try {
      const now = Date.now();
      const servers = await this.getActiveServers();
      const serverCount = servers.length;
      const serverHash = this.generateServerHash(servers);

      // Check if server configuration changed
      const serversChanged = serverHash !== this.lastServerHash;

      // Log server changes when they occur
      if (serversChanged) {
        console.log(`\n[SERVER CHANGE] ${serverCount} server(s) detected`);
        servers.forEach(s => {
          const portStatus = (!s.port || s.port === 0 || s.port === '0') ? ' [INVALID PORT - will be skipped]' : '';
          console.log(`\t${s.serverId}`);
          console.log(`\t${s.host}:${s.port}${portStatus}`);
        });

        const tunnelUrl = await this.getTunnelUrl();
        if (tunnelUrl) {
          console.log(`\tTunnel URL: ${tunnelUrl}`);
        }

        this.lastServerCount = serverCount;
        this.lastServerHash = serverHash;
      }

      if (serverCount >= MIN_SERVERS_FOR_LB) {
        if (serversChanged) {
          const config = await this.generateHAProxyConfig(servers);

          if (config) {
            if (!this.isRunning) {
              await this.startHAProxy();
            } else {
              await this.reloadHAProxy();
            }
          } else if (this.isRunning) {
            console.log(`\n[WARNING] All backends invalid - keeping existing HAProxy config`);
          }
        } else if (!this.isRunning) {
          const config = await this.generateHAProxyConfig(servers);
          if (config) {
            await this.startHAProxy();
          }
        }
      } else if (serverCount === 0) {
        if (serversChanged) {
          console.log(`\n[WARNING] No servers detected - HAProxy will return 503 until servers come online`);
          const config = await this.generateHAProxyConfig([]);
          if (config) {
            if (!this.isRunning) {
              await this.startHAProxy();
            } else {
              await this.reloadHAProxy();
            }
          }
        } else if (!this.isRunning) {
          const config = await this.generateHAProxyConfig([]);
          if (config) {
            await this.startHAProxy();
          }
        }
        this.lastServerHash = '';
      }

      if (now - this.lastTunnelCheck > this.tunnelCheckInterval) {
        this.lastTunnelCheck = now;

        if (!this.tunnelDisabled) {
          const running = await this.isTunnelRunning();

          if (!running) {
            const sinceLastRestart = now - (this.lastTunnelRestart || 0);

            if (this.tunnelRestartFailures >= this.maxTunnelRestartFailures) {
              if (!this.tunnelDisabled) {
                console.error(`\n[TUNNEL] Disabling automatic tunnel restart after ${this.tunnelRestartFailures} failed attempts.`);
                console.error('[TUNNEL] Check cloudflared installation/config (CLOUDFLARED_TOKEN, connectivity) and restart the load balancer.');
                this.tunnelDisabled = true;
              }
            } else if (sinceLastRestart >= this.tunnelBackoffMs) {
              console.log('\n[WARNING] Tunnel is not running, attempting restart...');
              const ok = await this.restartTunnel();
              this.lastTunnelRestart = Date.now();

              if (!ok) {
                this.tunnelRestartFailures += 1;
                this.tunnelBackoffMs = Math.min(this.tunnelBackoffMs * 2, 5 * 60 * 1000);
              } else {
                this.tunnelRestartFailures = 0;
                this.tunnelBackoffMs = 10000;
              }
            }
          } else {
            this.tunnelRestartFailures = 0;
            this.tunnelBackoffMs = 10000;
          }
        }
      }

    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Monitor cycle failed', error);
    }
  }

  /**
   * Acquire process lock to prevent multiple instances
   */
  async acquireLock() {
    try {
      if (existsSync(LOADBALANCER_LOCK_FILE)) {
        const existingPid = parseInt(await fs.readFile(LOADBALANCER_LOCK_FILE, 'utf8'), 10);

        try {
          process.kill(existingPid, 0);

          console.log(`\n[INFO] Auto Load Balancer already running (PID: ${existingPid})`);

          if (existsSync(HAPROXY_PID_FILE)) {
            const haproxyPid = parseInt(await fs.readFile(HAPROXY_PID_FILE, 'utf8'), 10);
            await this.displayHAProxyStatus(haproxyPid, true);
          } else {
            console.log(`\tStats Dashboard: http://localhost:${process.env.HAPROXY_STATS_PORT || 8404}/haproxy-stats`);
            const tunnelUrl = await this.getTunnelUrl();
            if (tunnelUrl) {
              console.log(`\tPublic URL: ${tunnelUrl}`);
            }
            console.log();
          }

          console.log(`[INFO] To stop the load balancer, run: kill ${existingPid}\n`);
          process.exit(0);
        } catch {
          console.log(`[CLEANUP] Removing stale lock file for PID ${existingPid}`);
          await fs.unlink(LOADBALANCER_LOCK_FILE);
        }
      }

      // Create lock file with current PID
      await fs.writeFile(LOADBALANCER_LOCK_FILE, process.pid.toString(), { mode: 0o600 });
      cryptoLogger.info('[AUTO-LB] Acquired process lock', { pid: process.pid, lockFile: LOADBALANCER_LOCK_FILE });
      return true;
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to acquire lock', error);
      return false;
    }
  }

  /**
   * Release process lock
   */
  async releaseLock() {
    try {
      if (existsSync(LOADBALANCER_LOCK_FILE)) {
        const lockPid = parseInt(await fs.readFile(LOADBALANCER_LOCK_FILE, 'utf8'), 10);

        if (lockPid === process.pid) {
          await fs.unlink(LOADBALANCER_LOCK_FILE);
          cryptoLogger.info('[AUTO-LB] Released process lock', { pid: process.pid });
        }
      }
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to release lock', error);
    }
  }

  /**
   * Initialize command encryption using HAProxy stats keypair
   */
  async initCommandEncryption() {
    try {
      const secureCreds = path.join(this.repoRoot, 'server', 'config', 'secure-credentials.js');
      const { unlockKeypair } = await import(`file://${secureCreds}`);

      const username = process.env.HAPROXY_STATS_USERNAME;
      const password = process.env.HAPROXY_STATS_PASSWORD;

      if (!username || !password) {
        throw new Error('HAProxy stats credentials not available in environment');
      }

      this.commandKeypair = await unlockKeypair(username, password);
      cryptoLogger.info('[AUTO-LB] Initialized PQ command encryption using HAProxy stats keypair');
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to initialize command encryption', error);
      throw error;
    }
  }

  /**
   * Decrypt command payload using ML-KEM-1024 + X25519 hybrid encryption
   */
  async decryptCommand(encryptedData) {
    try {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      const { x25519 } = await import('@noble/curves/ed25519.js');

      const payload = JSON.parse(encryptedData);
      if (payload.version !== 2) {
        throw new Error('Unsupported command payload version');
      }
      const encryptedPackage = payload.encrypted;

      // Verify ML-DSA-87 signature first
      const packageBytes = Buffer.from(JSON.stringify(encryptedPackage));
      const signatureBuffer = Buffer.from(payload.signature, 'base64');

      const isValid = ml_dsa87.verify(
        signatureBuffer,
        packageBytes,
        this.commandKeypair.dilithium.publicKey
      );

      if (!isValid) {
        throw new Error('Command signature verification failed - data may be tampered');
      }

      // Parse encrypted components
      const kyberCiphertext = Buffer.from(encryptedPackage.kyberCiphertext, 'base64');
      const x25519EphemeralPublic = Buffer.from(encryptedPackage.x25519EphemeralPublic, 'base64');
      const nonce = Buffer.from(encryptedPackage.nonce, 'base64');
      const ciphertext = Buffer.from(encryptedPackage.ciphertext, 'base64');
      const tag = Buffer.from(encryptedPackage.tag, 'base64');
      const kyberSharedSecret = ml_kem1024.decapsulate(kyberCiphertext, this.commandKeypair.kyber.secretKey);
      const x25519SharedSecret = x25519.getSharedSecret(this.commandKeypair.x25519.secretKey, x25519EphemeralPublic);

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
      const aad = new TextEncoder().encode('lb-command-v2');
      let plaintext;
      try {
        plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
      } catch (_error) {
        throw new Error('SECURITY: Command decryption failed - invalid ciphertext');
      }

      return JSON.parse(Buffer.from(plaintext).toString('utf8'));
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Command decryption failed', error);
      throw new Error('Failed to decrypt command');
    }
  }

  /**
   * Process command queue sequentially
   */
  async processCommandQueue() {
    if (this.processingCommand || this.commandQueue.length === 0) {
      return;
    }

    this.processingCommand = true;

    try {
      while (this.commandQueue.length > 0) {
        const cmd = this.commandQueue.shift();

        try {
          cryptoLogger.info('[AUTO-LB] Processing queued command', { command: cmd.cmd, queueLength: this.commandQueue.length });

          // Execute command
          if (cmd.cmd === 'restart_tunnel') {
            console.log('\n[COMMAND] Restarting tunnel (requested from TUI)...');

            // Pause automatic tunnel restart logic while handling manual command
            const previousDisabled = this.tunnelDisabled;
            this.tunnelDisabled = true;

            const success = await this.restartTunnel();
            if (success) {
              console.log('[COMMAND] Tunnel restarted successfully\n');
              this.tunnelDisabled = previousDisabled;
              this.tunnelRestartFailures = 0;
              this.tunnelBackoffMs = 10000;
              this.lastTunnelRestart = Date.now();
            } else {
              console.error('[COMMAND] Tunnel restart failed\n');
              this.tunnelRestartFailures += 1;
              if (this.tunnelRestartFailures >= this.maxTunnelRestartFailures) {
                console.error(`\n[TUNNEL] Disabling automatic tunnel restart after ${this.tunnelRestartFailures} failed attempts (manual command).`);
                console.error('[TUNNEL] Check cloudflared installation/config (CLOUDFLARED_TOKEN, connectivity) and restart the load balancer.');
              } else {
                console.error('[TUNNEL] Automatic tunnel restart is temporarily disabled after manual failure.');
              }
            }
          } else if (cmd.cmd === 'reload') {
            console.log('\n[COMMAND] Reloading HAProxy (requested from TUI)...');
            const success = await this.reloadHAProxy();
            if (success) {
              console.log('[COMMAND] HAProxy reloaded successfully\n');
            } else {
              console.error('[COMMAND] HAProxy reload failed\n');
            }
          } else {
            console.log(`[COMMAND] Unknown command: ${cmd.cmd}`);
          }
        } catch (error) {
          cryptoLogger.error('[AUTO-LB] Failed to execute command', { command: cmd.cmd, error });
          console.error(`[COMMAND] Error executing ${cmd.cmd}:`, error.message);
        }

        if (this.commandQueue.length > 0) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }
    } finally {
      this.processingCommand = false;
    }
  }

  /**
   * Setup Redis command listener for TUI commands with PQ encryption
   */
  async setupCommandListener() {
    try {
      await this.initCommandEncryption();
      await withRedisClient(async (client) => {
        this.commandSubscriber = client.duplicate();

        if (this.commandSubscriber.status !== 'ready' && this.commandSubscriber.status !== 'connecting') {
          await this.commandSubscriber.connect();
        }

        if (this.commandSubscriber.status === 'connecting') {
          await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => reject(new Error('Redis subscriber connection timeout')), 5000);
            this.commandSubscriber.once('ready', () => { clearTimeout(timeout); resolve(); });
            this.commandSubscriber.once('error', (err) => { clearTimeout(timeout); reject(err); });
          });
        }

        await this.commandSubscriber.subscribe('lb:command:encrypted');

        this.commandSubscriber.on('message', async (channel, encryptedMessage) => {
          if (channel !== 'lb:command:encrypted') {
            return;
          }

          try {
            // Validate message is not empty
            if (!encryptedMessage || typeof encryptedMessage !== 'string' || encryptedMessage.trim().length === 0) {
              cryptoLogger.debug('[AUTO-LB] Received empty or invalid message, ignoring');
              return;
            }

            // Decrypt the command
            const cmd = await this.decryptCommand(encryptedMessage);

            cryptoLogger.info('[AUTO-LB] Received encrypted command from TUI', { command: cmd.cmd });

            // Add to queue
            this.commandQueue.push(cmd);

            // Process queue
            this.processCommandQueue().catch((error) => {
              cryptoLogger.error('[AUTO-LB] Command queue processing error', error);
            });
          } catch (error) {
            if (encryptedMessage && encryptedMessage.trim().length > 0) {
              cryptoLogger.error('[AUTO-LB] Failed to process encrypted command', error);
              console.error('[COMMAND] Error processing command:', error.message);
            }
          }
        });

        cryptoLogger.info('[AUTO-LB] PQ-encrypted command listener setup complete');
      });
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to setup command listener', error);
      console.error('[ERROR] Failed to setup command listener:', error.message);
    }
  }

  /**
   * Start monitoring
   */
  async start() {
    // Acquire process lock first
    if (!await this.acquireLock()) {
      process.exit(1);
    }

    console.log('[STARTING] Load balancer monitor');
    console.log(`\tPID: ${process.pid}`);
    console.log(`\tLock file: ${LOADBALANCER_LOCK_FILE}`);
    console.log(`\tRedis: ${process.env.REDIS_URL || 'redis://127.0.0.1:6379'}`);
    console.log(`\tMin servers: ${MIN_SERVERS_FOR_LB}`);

    try {
      console.log('\t[INIT] Cleaning up any existing tunnels...');
      await deleteCloudflaredTunnels();
      console.log('\t[INIT] Existing tunnels cleaned');
      const logPath = path.join(this.scriptsDir, 'config', 'tunnel', 'cloudflared.log');
      if (existsSync(logPath)) {
        await fs.unlink(logPath);
        console.log('\t[INIT] Cleared old tunnel log file');
      }
    } catch (error) {
      cryptoLogger.warn('[AUTO-LB] Failed to clean tunnels on startup', error);
    }

    // Setup command listener for TUI (skip in NO_GUI mode)
    const noGui = (process.env.NO_GUI || 'false').toLowerCase() === 'true';
    if (!noGui) {
      await this.setupCommandListener();
    } else {
      console.log('\t[INIT] Skipping command listener (NO_GUI mode)');
    }

    await this.monitor();

    this.monitorInterval = setInterval(() => this.monitor(), 1000);

    const handleShutdown = (signal) => {
      if (this.isStopping) {
        return;
      }
      console.log(`\n[SIGNAL] Received ${signal}, shutting down...`);
      this.stop().catch((err) => {
        console.error('Error during shutdown:', err);
        process.exit(1);
      });
    };

    process.on('SIGINT', () => handleShutdown('SIGINT'));
    process.on('SIGTERM', () => handleShutdown('SIGTERM'));

    process.on('beforeExit', async () => {
      await this.releaseLock();
    });
  }

  /**
   * Stop monitoring and cleanup
   */
  async stop() {
    if (this.isStopping) {
      return;
    }
    this.isStopping = true;

    console.log('\n[SHUTDOWN] Stopping load balancer monitor...');
    console.log(`\tMonitor PID: ${process.pid}`);

    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
      console.log('\t[OK] Stopped monitoring interval');
    }

    // Close command listener
    if (this.commandSubscriber) {
      try {
        await this.commandSubscriber.unsubscribe('lb:command:encrypted');
        await this.commandSubscriber.quit();
        console.log('\t[OK] Closed command listener');
      } catch {
      }
      this.commandSubscriber = null;
    }

    // Clear any pending commands
    this.commandQueue = [];

    // Wipe encryption keys from memory
    if (this.commandKeypair) {
      if (this.commandKeypair.kyber?.secretKey) {
        crypto.randomFillSync(this.commandKeypair.kyber.secretKey);
        this.commandKeypair.kyber.secretKey.fill(0);
      }
      if (this.commandKeypair.x25519?.secretKey) {
        crypto.randomFillSync(this.commandKeypair.x25519.secretKey);
        this.commandKeypair.x25519.secretKey.fill(0);
      }
      if (this.commandKeypair.dilithium?.secretKey) {
        crypto.randomFillSync(this.commandKeypair.dilithium.secretKey);
        this.commandKeypair.dilithium.secretKey.fill(0);
      }
      this.commandKeypair = null;
    }

    // Stop HAProxy if running
    if (this.isRunning || existsSync(HAPROXY_PID_FILE)) {
      console.log('\t[OK] Stopping HAProxy...');
      await this.stopHAProxy();
    }

    // Force kill any active cloudflared tunnels
    if (this.isRunning) {
      console.log('\t[OK] Killing all tunnels (cloudflared)...');
      await deleteCloudflaredTunnels();

      if (process.platform !== 'win32') {
        try {
          await execFileAsync('pkill', ['-9', 'cloudflared']);
        } catch { }
      }
      console.log('\t[OK] All tunnels terminated');
    }
    try {
    } catch (error) {
      cryptoLogger.warn('[AUTO-LB] Failed to kill tunnels on shutdown', error);
    }

    await this.releaseLock();
    console.log('\t[OK] Released process lock\n');

    process.exit(0);
  }
}

// CLI mode
if (import.meta.url === `file://${process.argv[1]}`) {
  const manager = new AutoLoadBalancer();
  manager.start().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

export { AutoLoadBalancer };