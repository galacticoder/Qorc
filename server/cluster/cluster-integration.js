/**
 * Cluster Integration for Server
 */

import { ClusterManager } from './cluster-manager.js';
import { generateConfigFromCluster } from '../load-balancer/haproxy-config-generator.js';

import crypto from 'crypto';
import path from 'path';
import {
  CLUSTER_MASTER_KEY,
} from '../config/redis-keys.js';
import { TEMP_DIRECTORY } from '../config/infrastructure.js';
import {
  CLUSTER_APPROVED_EVENT,
  CLUSTER_JOIN_REQUEST_EVENT,
  CLUSTER_KEYS_ROTATED_EVENT,
  CLUSTER_PROMOTED_EVENT
} from './protocol.js';

let clusterManager = null;
let configUpdateInterval = null;
let configUpdateTask = null;

export function getClusterTelemetry() {
  if (process.env.ENABLE_CLUSTERING !== 'true') {
    return {
      serverId: process.env.SERVER_ID || 'default',
      registration: 'standalone',
      heartbeatAgeSeconds: null,
    };
  }
  return clusterManager?.getTelemetrySnapshot?.() || {
    serverId: process.env.SERVER_ID || 'default',
    registration: 'checking',
    heartbeatAgeSeconds: null,
  };
}

// Initialize cluster integration
export async function initializeCluster({
  serverHybridKeyPair,
  serverId = null,
  isPrimary = null,
  autoApprove = false
}) {
  try {
    if (!serverId) {
      serverId = process.env.SERVER_ID || generateServerId();
    }

    if (isPrimary === null || isPrimary === undefined) {
      isPrimary = process.env.CLUSTER_PRIMARY === 'true' || process.env.SERVER_ROLE === 'primary';

      if (!isPrimary) {
        const { withRedisClient } = await import('../session/redis-client.js');
        try {
          const existingMaster = await withRedisClient(async (client) => {
            return await client.get(CLUSTER_MASTER_KEY);
          });
          isPrimary = !existingMaster;
          if (isPrimary) {
            console.log('[CLUSTER] No existing master found, becoming primary server');
          }
        } catch (error) {
          console.warn('[CLUSTER] Could not check for existing master, defaulting to non-primary', error);
          isPrimary = false;
        }
      }
    }

    const enableAutoApprove = autoApprove || process.env.CLUSTER_AUTO_APPROVE === 'true';

    console.log('[CLUSTER] Initializing cluster integration', {
      serverId,
      isPrimary,
      autoApprove: enableAutoApprove
    });

    clusterManager = new ClusterManager({
      serverId,
      serverKeys: serverHybridKeyPair,
      isPrimary,
      autoApprove: enableAutoApprove,
    });

    setupClusterEventHandlers(clusterManager, autoApprove);
    await clusterManager.initialize();

    if (isPrimary && process.env.HAPROXY_AUTO_CONFIG === 'true') {
      startHAProxyConfigUpdater(clusterManager);
    }

    console.log('[CLUSTER] Cluster integration initialized', { serverId });

    return clusterManager;
  } catch (error) {
    console.error('[CLUSTER] Failed to initialize cluster integration', error);
    throw error;
  }
}

// Generate unique server ID
function generateServerId() {
  const hostname = process.env.HOSTNAME || 'server';
  const randomPart = crypto.randomBytes(8).toString('hex');
  return `${hostname}-${randomPart}`;
}

// Set up cluster event handlers
function setupClusterEventHandlers(manager, autoApprove) {
  manager.on(CLUSTER_JOIN_REQUEST_EVENT, async (serverInfo) => {
    console.log('[CLUSTER] New server requesting to join', {
      serverId: serverInfo.serverId,
      requestedAt: new Date(serverInfo.requestedAt).toISOString()
    });

    if (autoApprove) {
      console.warn('[CLUSTER] Auto-approving server (auto-approve is enabled)', {
        serverId: serverInfo.serverId
      });
      try {
        await manager.approveServer(serverInfo.serverId);
      } catch (error) {
        console.error('[CLUSTER] Failed to auto-approve server', error);
      }
    } else {
      console.log('[CLUSTER] Server awaiting manual approval', {
        serverId: serverInfo.serverId,
        message: 'Run: npm run cluster:approve <serverId>'
      });
    }
  });

  // Handle server approved
  manager.on('server-approved', ({ serverId }) => {
    console.log('[CLUSTER] Server approved and joined cluster', { serverId });
  });

  // Handle server joined
  manager.on('server-joined', ({ serverId }) => {
    console.log('[CLUSTER] New server joined cluster', { serverId });
  });

  // Handle server removed
  manager.on('server-removed', ({ serverId }) => {
    console.warn('[CLUSTER] Server removed from cluster', { serverId });
  });

  // Handle server dead
  manager.on('server-dead', ({ serverId }) => {
    console.error('[CLUSTER] Server marked as dead', { serverId });
  });

  // Handle promotion to primary
  manager.on(CLUSTER_PROMOTED_EVENT, () => {
    console.log('[CLUSTER] This server has been promoted to primary');

    if (process.env.HAPROXY_AUTO_CONFIG === 'true') {
      startHAProxyConfigUpdater(manager);
    }
  });

  // Handle approval
  manager.on(CLUSTER_APPROVED_EVENT, () => {
    console.log('[CLUSTER] This server has been approved and joined the cluster');
  });

  // Handle rejection
  manager.on('rejected', ({ reason }) => {
    console.error('[CLUSTER] This server was rejected from the cluster', { reason });
  });

  // Handle keys rotated
  manager.on(CLUSTER_KEYS_ROTATED_EVENT, () => {
    console.log('[CLUSTER] Cluster authentication keys rotated');
  });
}

// Start HAProxy configuration updater
function startHAProxyConfigUpdater(manager) {
  if (configUpdateInterval) {
    return;
  }

  const configuredInterval = Number(process.env.HAPROXY_UPDATE_INTERVAL || 60_000);
  const updateInterval = Number.isSafeInteger(configuredInterval) && configuredInterval >= 5_000
    ? Math.min(configuredInterval, 3_600_000)
    : 60_000;
  const configPath = process.env.HAPROXY_CONFIG_PATH || (process.platform === 'win32' ? path.join(TEMP_DIRECTORY, 'haproxy.cfg') : '/etc/haproxy/haproxy.cfg');

  console.log('[CLUSTER] Starting HAProxy config auto-updater', {
    interval: updateInterval,
    configPath
  });

  const runUpdate = () => {
    if (configUpdateTask) return;
    const task = updateHAProxyConfig(manager, configPath)
      .catch((error) => {
        console.error('[CLUSTER] Failed to update HAProxy config', error);
      })
      .finally(() => {
        if (configUpdateTask === task) configUpdateTask = null;
      });
    configUpdateTask = task;
  };

  runUpdate();
  configUpdateInterval = setInterval(runUpdate, updateInterval);
}

// Update HAProxy configuration
async function updateHAProxyConfig(manager, configPath) {
  try {
    console.log('[CLUSTER] Updating HAProxy configuration');
    const generator = await generateConfigFromCluster(manager, configPath);

    if (process.env.HAPROXY_AUTO_RELOAD === 'true') {
      await generator.reloadHAProxy(configPath);
      console.log('[CLUSTER] HAProxy configuration updated and reloaded');
    } else {
      console.log('[CLUSTER] HAProxy configuration updated (reload manually)');
    }
  } catch (error) {
    console.error('[CLUSTER] Failed to update HAProxy configuration', error);
    throw error;
  }
}

// Get cluster manager instance
export function getClusterManager() {
  return clusterManager;
}

// Get cluster status
export async function getClusterStatus() {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }

  return await clusterManager.getClusterStatus();
}

// Get all server public keys for client distribution
export async function getAllServerPublicKeys() {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }

  return await clusterManager.getAllServerKeys();
}

// Approve a pending server (primary only)
export async function approveServer(serverId) {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }

  return await clusterManager.approveServer(serverId);
}

// Reject a pending server (primary only)
export async function rejectServer(serverId, reason) {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }

  return await clusterManager.rejectServer(serverId, reason);
}

// Get list of pending servers
export async function getPendingServers() {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }

  return await clusterManager.getPendingServers();
}

// Force remove a server from cluster (primary only)
export async function removeServer(serverId) {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }

  return await clusterManager.forceRemoveServer(serverId);
}

// Shutdown of cluster integration
export async function shutdownCluster() {
  console.log('[CLUSTER] Shutting down cluster integration');

  if (configUpdateInterval) {
    clearInterval(configUpdateInterval);
    configUpdateInterval = null;
  }
  if (configUpdateTask) {
    await configUpdateTask;
    configUpdateTask = null;
  }

  if (clusterManager) {
    await clusterManager.shutdown();
    clusterManager = null;
  }

  console.log('[CLUSTER] Cluster integration shutdown complete');
}

// Register cluster shutdown handlers
export function registerClusterShutdownHandlers() {
  const signals = ['SIGINT', 'SIGTERM', 'SIGQUIT'];

  signals.forEach(signal => {
    process.on(signal, async () => {
      console.log(`[CLUSTER] Received ${signal}, initiating shutdown`);

      try {
        await shutdownCluster();
      } catch (error) {
        console.error('[CLUSTER] Error during cluster shutdown', error);
      }

      process.exit(0);
    });
  });

  process.on('uncaughtException', async (error) => {
    console.error('[CLUSTER] Uncaught exception, shutting down', error);

    try {
      await shutdownCluster();
    } catch (shutdownError) {
      console.error('[CLUSTER] Error during emergency shutdown', shutdownError);
    }

    process.exit(1);
  });

  process.on('unhandledRejection', async (reason) => {
    console.error('[CLUSTER] Unhandled rejection, shutting down', { reason });

    try {
      await shutdownCluster();
    } catch (shutdownError) {
      console.error('[CLUSTER] Error during emergency shutdown', shutdownError);
    }

    process.exit(1);
  });
}
