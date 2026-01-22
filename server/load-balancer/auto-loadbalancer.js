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
import { HAProxyManager } from './haproxy-manager.js';
import { TorManager } from './tor-manager.js';
import { LBCommandListener } from './lb-command-listener.js';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import os from 'os';
import net from 'net';
import { fileURLToPath } from 'url';

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const TMPDIR = os.tmpdir();
const DEFAULT_HTTPS_PORT = parseInt(process.env.HAPROXY_HTTPS_PORT || (isRoot ? '443' : '8443'), 10);

const LOADBALANCER_LOCK_FILE = process.env.LOADBALANCER_LOCK_FILE ||
  (isRoot && process.platform !== 'win32' ? '/var/run/auto-loadbalancer.pid' : path.join(TMPDIR, 'auto-loadbalancer.pid'));
const MIN_SERVERS_FOR_LB = 1;

class AutoLoadBalancer {
  constructor() {
    this.listenPort = DEFAULT_HTTPS_PORT;
    this.lastServerCount = 0;
    this.lastServerHash = '';
    this.monitorInterval = null;
    this.isStopping = false;

    const here = fileURLToPath(import.meta.url);
    const clusterDir = path.dirname(here);
    this.serverDir = path.resolve(clusterDir, '..');
    this.repoRoot = path.resolve(this.serverDir, '..');
    this.scriptsDir = path.resolve(this.repoRoot, 'scripts');

    this.haproxyManager = new HAProxyManager();
    this.torManager = new TorManager(this.scriptsDir);
    this.commandListener = new LBCommandListener(this.repoRoot, this.handleCommand.bind(this));
  }

  // Handle commands from TUI
  async handleCommand(cmd) {
    if (cmd.cmd === 'reload') {
      console.log('\n[COMMAND] Reloading HAProxy (requested from TUI)...');
      const success = await this.haproxyManager.reload();
      if (success) {
        console.log('[COMMAND] HAProxy reloaded successfully\n');
      } else {
        console.error('[COMMAND] HAProxy reload failed\n');
      }
    } else {
      console.log(`[COMMAND] Unknown command: ${cmd.cmd}`);
    }
  }

  // Get active servers from Redis
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

  // Find an available HTTPS listen port
  async resolveListenPort(servers, currentPort = null) {
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

      // If is current port and HAProxy is running then keep it
      if (currentPort && port === currentPort && this.haproxyManager.isRunning) {
        return port;
      }

      const free = await isPortFree(port);
      if (free) return port;
    }
    return currentPort || candidate;
  }

  // Find an available stats port
  async resolveStatsPort(currentPort = null) {
    const defaultStats = parseInt(process.env.HAPROXY_STATS_PORT || '8404', 10);

    // If we have a current port and HAProxy is running then stay
    if (currentPort && this.haproxyManager.isRunning) {
      return currentPort;
    }

    const isPortFree = (port) => new Promise((resolve) => {
      const srv = net.createServer();
      srv.unref();
      srv.on('error', () => resolve(false));
      srv.listen({ port, host: '127.0.0.1' }, () => {
        srv.close(() => resolve(true));
      });
    });

    for (let i = 0; i < 20; i += 1) {
      const port = defaultStats + i;
      if (await isPortFree(port)) return port;
    }
    return currentPort || defaultStats;
  }

  // Generate HAProxy configuration
  async generateHAProxyConfig(servers) {
    const listenPort = await this.resolveListenPort(servers, this.listenPort);
    this.listenPort = listenPort;

    const statsPort = await this.resolveStatsPort(this.statsPort);
    this.statsPort = statsPort;

    const generator = new HAProxyConfigGenerator({
      listenPort,
      httpPort: parseInt(process.env.HAPROXY_HTTP_PORT || (isRoot ? '80' : '8080'), 10),
      statsPort: statsPort,
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
      return null;
    }

    if (generator.backends.length === 0) {
      console.log(`\n[WARNING] No servers detected - HAProxy will return 503 until servers come online\n`);
    }

    const config = generator.generateConfig();
    const configDir = path.dirname(this.haproxyManager.configPath);
    await fs.mkdir(configDir, { recursive: true, mode: 0o700 });
    await fs.writeFile(this.haproxyManager.configPath, config, { mode: 0o600 });

    return config;
  }

  // Generate hash for change detection
  generateServerHash(servers) {
    const sorted = [...servers].sort((a, b) => a.serverId.localeCompare(b.serverId));
    return sorted.map(s => `${s.serverId}:${s.host}:${s.port}`).join('|');
  }

  // Monitor cluster and manage load balancer
  async monitor() {
    try {
      const servers = await this.getActiveServers();
      const serverCount = servers.length;
      const serverHash = this.generateServerHash(servers);

      const serversChanged = serverHash !== this.lastServerHash;

      if (serversChanged) {
        console.log(`\n[SERVER CHANGE] ${serverCount} server(s) detected`);
        servers.forEach(s => {
          const portStatus = (!s.port || s.port === 0 || s.port === '0') ? ' [INVALID PORT - will be skipped]' : '';
          console.log(`\t${s.serverId}`);
          console.log(`\t${s.host}:${s.port}${portStatus}`);
        });

        const onionAddr = await this.torManager.getOnionAddress();
        if (onionAddr) {
          console.log(`\tOnion URL:  http://${onionAddr}`);
        }

        this.lastServerCount = serverCount;
        this.lastServerHash = serverHash;
      }

      if (serverCount >= MIN_SERVERS_FOR_LB) {
        if (serversChanged) {
          const config = await this.generateHAProxyConfig(servers);

          if (config) {
            if (!this.haproxyManager.isRunning) {
              await this.haproxyManager.start();
            } else {
              await this.haproxyManager.reload();
            }
          } else if (this.haproxyManager.isRunning) {
            console.log(`\n[WARNING] All backends invalid - keeping existing HAProxy config`);
          }
        } else if (!this.haproxyManager.isRunning) {
          const config = await this.generateHAProxyConfig(servers);
          if (config) {
            await this.haproxyManager.start();
          }
        }
      } else if (serverCount === 0) {
        if (serversChanged) {
          const config = await this.generateHAProxyConfig([]);
          if (config) {
            if (!this.haproxyManager.isRunning) {
              await this.haproxyManager.start();
            } else {
              await this.haproxyManager.reload();
            }
          }
        } else if (!this.haproxyManager.isRunning) {
          const config = await this.generateHAProxyConfig([]);
          if (config) {
            await this.haproxyManager.start();
          }
        }
        this.lastServerHash = '';
      }

      await this.torManager.monitor(this.listenPort);

      // Periodically update the onion address in Redis for the TUI to display
      const onionAddr = await this.torManager.getOnionAddress();
      if (onionAddr) {
        await withRedisClient(async (client) => {
          await client.set('cluster:lb:onionAddress', onionAddr);
        });
      }

    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Monitor cycle failed', error);
    }
  }

  async acquireLock() {
    try {
      if (existsSync(LOADBALANCER_LOCK_FILE)) {
        const existingPid = parseInt(await fs.readFile(LOADBALANCER_LOCK_FILE, 'utf8'), 10);

        try {
          process.kill(existingPid, 0);

          console.log(`\n[INFO] Auto Load Balancer already running (PID: ${existingPid})`);

          if (this.haproxyManager.pidFile && existsSync(this.haproxyManager.pidFile)) {
            const haproxyPid = parseInt(await fs.readFile(this.haproxyManager.pidFile, 'utf8'), 10);
            const servers = await this.getActiveServers();
            await this.haproxyManager.displayStatus(haproxyPid, servers);
          } else {
            console.log(`\tStats Dashboard: http://localhost:${process.env.HAPROXY_STATS_PORT || 8404}/haproxy-stats`);
          }

          const onionAddr = await this.torManager.getOnionAddress();
          if (onionAddr) {
            console.log(`\tOnion URL:  http://${onionAddr}`);
          }
          console.log();

          console.log(`[INFO] To stop the load balancer, run: kill ${existingPid}\n`);
          process.exit(0);
        } catch {
          console.log(`[CLEANUP] Removing stale lock file for PID ${existingPid}`);
          await fs.unlink(LOADBALANCER_LOCK_FILE);
        }
      }

      await fs.writeFile(LOADBALANCER_LOCK_FILE, process.pid.toString(), { mode: 0o600 });
      cryptoLogger.info('[AUTO-LB] Acquired process lock', { pid: process.pid, lockFile: LOADBALANCER_LOCK_FILE });
      return true;
    } catch (error) {
      cryptoLogger.error('[AUTO-LB] Failed to acquire lock', error);
      return false;
    }
  }

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

  async start() {
    if (!await this.acquireLock()) {
      process.exit(1);
    }

    console.log('[STARTING] Load balancer monitor');
    console.log(`\tPID: ${process.pid}`);
    console.log(`\tLock file: ${LOADBALANCER_LOCK_FILE}`);
    console.log(`\tRedis: ${process.env.REDIS_URL || 'redis://127.0.0.1:6379'}`);
    console.log(`\tMin servers: ${MIN_SERVERS_FOR_LB}`);


    const noGui = (process.env.NO_GUI || 'false').toLowerCase() === 'true';
    if (!noGui) {
      await this.commandListener.setup();
    } else {
      console.log('\t[INIT] Skipping command listener (NO_GUI mode)');
    }

    await this.monitor();
    await this.torManager.start(this.listenPort);

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

    await this.commandListener.stop();

    if (this.haproxyManager.isRunning || (this.haproxyManager.pidFile && existsSync(this.haproxyManager.pidFile))) {
      console.log('\t[OK] Stopping HAProxy...');
      await this.haproxyManager.stop();
    }

    if (this.haproxyManager.isRunning) {
      console.log('\t[OK] Stopping Tor service...');
      await this.torManager.stop();
      console.log('\t[OK] Tor service terminated');
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