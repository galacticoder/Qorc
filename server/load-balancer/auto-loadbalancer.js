/**
 * Automatic Load Balancer Manager
 */

import { withRedisClient } from '../session/redis-client.js';
import { HAProxyConfigGenerator, parseHAProxyPort } from './haproxy-config-generator.js';

import { HAProxyManager } from './haproxy-manager.js';
import { TorManager } from './tor-manager.js';
import { LBCommandListener } from './lb-command-listener.js';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  IS_ROOT,
  TEMP_DIRECTORY,
  haproxyStatsDashboardUrl,
} from '../config/infrastructure.js';
import { REDIS_KEYS } from '../config/redis-keys.js';
import { processMatchesExecutable, readProcessIdFileSnapshot } from '../utils/process-identity.js';
import { acquireProcessLock, releaseProcessLock } from '../utils/process-lock.js';
import { safeServiceEndpointForDisplay } from '../utils/safe-url.js';
import { parseClusterServerRecord } from '../cluster/server-record.js';

const DEFAULT_HTTPS_PORT = parseHAProxyPort(
  process.env.HAPROXY_HTTPS_PORT,
  'HAPROXY_HTTPS_PORT'
);
const SERVER_ACTIVE_TIMEOUT_MS = Math.min(
  Math.max(parseInt(process.env.LB_SERVER_ACTIVE_TIMEOUT_MS || '45000', 10) || 45000, 10000),
  300000
);

const LOADBALANCER_LOCK_FILE = path.resolve(
  IS_ROOT ? '/var/run/auto-loadbalancer.pid' : path.join(TEMP_DIRECTORY, 'auto-loadbalancer.pid')
);
const LOADBALANCER_ENTRY_PATH = fileURLToPath(import.meta.url);
class AutoLoadBalancer {
  constructor() {
    this.listenPort = DEFAULT_HTTPS_PORT;
    this.lastServerHash = '';
    this.monitorInterval = null;
    this.isStopping = false;

    const here = fileURLToPath(import.meta.url);
    const clusterDir = path.dirname(here);
    this.serverDir = path.resolve(clusterDir, '..');
    this.repoRoot = path.resolve(this.serverDir, '..');

    this.haproxyManager = new HAProxyManager();
    this.torManager = new TorManager();
    this.commandListener = new LBCommandListener(this.repoRoot, this.handleCommand.bind(this));
  }

  // Handle commands from TUI
  async handleCommand(cmd) {
    if (cmd.cmd === 'reload') {
      console.log('\n[COMMAND] Reloading HAProxy (requested from TUI)...');
      await this.haproxyManager.reload();
      console.log('[COMMAND] HAProxy reloaded successfully\n');
    } else {
      console.log(`[COMMAND] Unknown command: ${cmd.cmd}`);
    }
  }

  // Get active servers from Redis
  async getActiveServers() {
    return await withRedisClient(async (client) => {
      const servers = await client.hgetall(REDIS_KEYS.CLUSTER_SERVERS);
      const now = Date.now();
      const activeServers = [];

      for (const [serverId, data] of Object.entries(servers)) {
        const serverInfo = parseClusterServerRecord(data, serverId, now);
        if (!serverInfo) {
          console.warn('[AUTO-LB] Ignoring invalid cluster server record', { serverId });
          continue;
        }
        const age = now - serverInfo.lastHeartbeat;
        if (age >= -30_000 && age < SERVER_ACTIVE_TIMEOUT_MS) {
          activeServers.push(serverInfo);
        }
      }

      return activeServers;
    });
  }

  // Generate HAProxy configuration
  async generateHAProxyConfig(servers) {
    const listenPort = this.listenPort;
    const statsPort = parseHAProxyPort(process.env.HAPROXY_STATS_PORT, 'HAPROXY_STATS_PORT');
    this.statsPort = statsPort;

    const generator = new HAProxyConfigGenerator({
      listenPort,
      statsPort: statsPort,
      tlsCertPath: path.join(this.serverDir, 'config', 'certs'),
      statsUsername: process.env.HAPROXY_STATS_USERNAME,
      statsPassword: process.env.HAPROXY_STATS_PASSWORD,
      statsBindAddress: process.env.HAPROXY_STATS_BIND_ADDRESS,
    });

    await withRedisClient(async (client) => {
      await client.set(REDIS_KEYS.LB_HTTPS_PORT, String(listenPort));
    });

    for (const server of servers) {
      generator.addBackend({
        name: server.serverId,
        host: server.host,
        port: server.port,
        weight: 100,
        maxconn: 10000,
      });
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
    const servers = await this.getActiveServers();
    const serverCount = servers.length;
    const serverHash = this.generateServerHash(servers);
    const serversChanged = serverHash !== this.lastServerHash;

    if (serversChanged) {
      console.log(`\n[SERVER CHANGE] ${serverCount} server(s) detected`);
      servers.forEach(s => {
        console.log(`\t${s.serverId}`);
        console.log(`\t${s.host}:${s.port}`);
      });

      const onionAddr = await this.torManager.getOnionAddress();
      if (onionAddr) {
        console.log(`\tOnion URL:  https://${onionAddr}`);
      }
    }

    if (serversChanged || !this.haproxyManager.isRunning) {
      await this.generateHAProxyConfig(servers);
      if (this.haproxyManager.isRunning) {
        await this.haproxyManager.reload();
      } else {
        await this.haproxyManager.start();
      }
      this.lastServerHash = serverHash;
    }

    await this.torManager.monitor(this.listenPort);

    const onionAddr = await this.torManager.getOnionAddress();
    await withRedisClient(async (client) => {
      if (onionAddr && this.torManager.isPublished()) {
        await client.set(REDIS_KEYS.LB_ONION_ADDRESS, `https://${onionAddr}`);
      } else {
        await client.del(REDIS_KEYS.LB_ONION_ADDRESS);
      }
    });
  }

  async acquireLock() {
    try {
      const lock = await acquireProcessLock(LOADBALANCER_LOCK_FILE, LOADBALANCER_ENTRY_PATH);
      if (!lock.acquired) {
        const existingPid = lock.pid;
        console.log(`\n[INFO] Auto Load Balancer already running (PID: ${existingPid})`);

        if (this.haproxyManager.pidFile && existsSync(this.haproxyManager.pidFile)) {
          const snapshot = await readProcessIdFileSnapshot(this.haproxyManager.pidFile);
          const haproxyPid = snapshot?.pid && await processMatchesExecutable(
            snapshot.pid,
            this.haproxyManager.haproxyBin
          ) ? snapshot.pid : null;
          const servers = await this.getActiveServers();
          if (haproxyPid) await this.haproxyManager.displayStatus(haproxyPid, servers);
        } else {
          console.log(`\tStats Dashboard: ${haproxyStatsDashboardUrl()}`);
        }

        const onionAddr = await this.torManager.getOnionAddress();
        if (onionAddr) console.log(`\tOnion URL:  https://${onionAddr}`);
        console.log();
        console.log(`[INFO] To stop the load balancer, run: kill ${existingPid}\n`);
        process.exit(0);
      }
      console.log('[AUTO-LB] Acquired process lock', { pid: process.pid, lockFile: LOADBALANCER_LOCK_FILE });
      return true;
    } catch (error) {
      console.error('[AUTO-LB] Failed to acquire lock', error);
      return false;
    }
  }

  async releaseLock() {
    try {
      if (await releaseProcessLock(LOADBALANCER_LOCK_FILE)) {
        console.log('[AUTO-LB] Released process lock', { pid: process.pid });
      }
    } catch (error) {
      console.error('[AUTO-LB] Failed to release lock', error);
    }
  }

  async start() {
    if (!await this.acquireLock()) {
      process.exit(1);
    }

    console.log('[STARTING] Load balancer monitor');
    console.log(`\tPID: ${process.pid}`);
    console.log(`\tLock file: ${LOADBALANCER_LOCK_FILE}`);
    console.log(`\tRedis: ${safeServiceEndpointForDisplay(process.env.REDIS_URL)}`);

    const noGui = (process.env.NO_GUI || 'false').toLowerCase() === 'true';
    if (!noGui) {
      await this.commandListener.setup();
    } else {
      console.log('\t[INIT] Skipping command listener (NO_GUI mode)');
    }

    await this.monitor();
    await this.torManager.start(this.listenPort);

    this.monitorInterval = setInterval(() => {
      this.monitor().catch((error) => {
        console.error('[AUTO-LB] Monitor cycle failed', error);
        this.stop(1).catch((shutdownError) => {
          console.error('[AUTO-LB] Fatal shutdown failed', shutdownError);
          process.exit(1);
        });
      });
    }, 1000);

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

  async stop(exitCode = 0) {
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

    if (await this.torManager.isRunning()) {
      console.log('\t[OK] Stopping Tor service...');
      await this.torManager.stop();
      console.log('\t[OK] Tor service terminated');
    }

    await this.releaseLock();
    console.log('\t[OK] Released process lock\n');

    process.exit(exitCode);
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
