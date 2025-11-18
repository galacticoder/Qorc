/**
 * Cluster Integration for Server
 * 
 * Integrates ClusterManager with the main server to enable:
 * - Automatic server registration
 * - Multi-server key distribution
 * - Health monitoring
 * - shutdown
 */

import { ClusterManager } from './cluster-manager.js';
import { generateConfigFromCluster } from './haproxy-config-generator.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import crypto from 'crypto';
import os from 'os';
import path from 'path';

let clusterManager = null;
let configUpdateInterval = null;

/**
 * Initialize cluster integration
 */
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
      
      // If still not set, check if cluster master exists in Redis
      if (!isPrimary) {
        const { withRedisClient } = await import('../presence/presence.js');
        try {
          const existingMaster = await withRedisClient(async (client) => {
            return await client.get('cluster:master');
          });
          isPrimary = !existingMaster;
          if (isPrimary) {
            cryptoLogger.info('[CLUSTER] No existing master found - becoming primary server');
          }
        } catch (error) {
          cryptoLogger.warn('[CLUSTER] Could not check for existing master, defaulting to non-primary', error);
          isPrimary = false;
        }
      }
    }
    
    // Get auto-approve setting from env or parameter
    const enableAutoApprove = autoApprove || process.env.CLUSTER_AUTO_APPROVE === 'true';
    
    cryptoLogger.info('[CLUSTER] Initializing cluster integration', {
      serverId,
      isPrimary,
      autoApprove: enableAutoApprove
    });
    
    // Create cluster manager
    clusterManager = new ClusterManager({
      serverId,
      serverKeys: serverHybridKeyPair,
      isPrimary,
      autoApprove: enableAutoApprove,
    });
    
    // Set up event handlers
    setupClusterEventHandlers(clusterManager, autoApprove);
    
    // Initialize cluster manager
    await clusterManager.initialize();
    
    if (isPrimary && process.env.HAPROXY_AUTO_CONFIG === 'true') {
      startHAProxyConfigUpdater(clusterManager);
    }
    
    cryptoLogger.info('[CLUSTER] Cluster integration initialized', { serverId });
    
    return clusterManager;
  } catch (error) {
    cryptoLogger.error('[CLUSTER] Failed to initialize cluster integration', error);
    throw error;
  }
}

/**
 * Generate unique server ID
 */
function generateServerId() {
  const hostname = process.env.HOSTNAME || 'server';
  const randomPart = crypto.randomBytes(8).toString('hex');
  return `${hostname}-${randomPart}`;
}

/**
 * Set up cluster event handlers
 */
function setupClusterEventHandlers(manager, autoApprove) {
  manager.on('join-request', async (serverInfo) => {
    cryptoLogger.info('[CLUSTER] New server requesting to join', {
      serverId: serverInfo.serverId,
      requestedAt: new Date(serverInfo.requestedAt).toISOString()
    });
    
    if (autoApprove) {
      cryptoLogger.warn('[CLUSTER] Auto-approving server (auto-approve is enabled)', {
        serverId: serverInfo.serverId
      });
      try {
        await manager.approveServer(serverInfo.serverId);
      } catch (error) {
        cryptoLogger.error('[CLUSTER] Failed to auto-approve server', error);
      }
    } else {
      cryptoLogger.info('[CLUSTER] Server awaiting manual approval', {
        serverId: serverInfo.serverId,
        message: 'Run: npm run cluster:approve <serverId>'
      });
    }
  });
  
  // Handle server approved
  manager.on('server-approved', ({ serverId }) => {
    cryptoLogger.info('[CLUSTER] Server approved and joined cluster', { serverId });
  });
  
  // Handle server joined
  manager.on('server-joined', ({ serverId }) => {
    cryptoLogger.info('[CLUSTER] New server joined cluster', { serverId });
  });
  
  // Handle server removed
  manager.on('server-removed', ({ serverId }) => {
    cryptoLogger.warn('[CLUSTER] Server removed from cluster', { serverId });
  });
  
  // Handle server dead
  manager.on('server-dead', ({ serverId }) => {
    cryptoLogger.error('[CLUSTER] Server marked as dead', { serverId });
  });
  
  // Handle promotion to primary
  manager.on('promoted-to-primary', () => {
    cryptoLogger.info('[CLUSTER] This server has been promoted to primary');
    
    // Start HAProxy config updater if enabled
    if (process.env.HAPROXY_AUTO_CONFIG === 'true') {
      startHAProxyConfigUpdater(manager);
    }
  });
  
  // Handle approval
  manager.on('approved', () => {
    cryptoLogger.info('[CLUSTER] This server has been approved and joined the cluster');
  });
  
  // Handle rejection
  manager.on('rejected', ({ reason }) => {
    cryptoLogger.error('[CLUSTER] This server was rejected from the cluster', { reason });
  });
  
  // Handle keys rotated
  manager.on('keys-rotated', () => {
    cryptoLogger.info('[CLUSTER] Cluster authentication keys rotated');
  });
}

/**
 * Start automatic HAProxy configuration updater
 */
function startHAProxyConfigUpdater(manager) {
  if (configUpdateInterval) {
    return;
  }
  
  const updateInterval = parseInt(process.env.HAPROXY_UPDATE_INTERVAL || '60000', 10);
  const configPath = process.env.HAPROXY_CONFIG_PATH || (process.platform === 'win32' ? path.join(os.tmpdir(), 'haproxy.cfg') : '/etc/haproxy/haproxy.cfg');
  
  cryptoLogger.info('[CLUSTER] Starting HAProxy config auto-updater', {
    interval: updateInterval,
    configPath
  });
  
  // Update immediately
  updateHAProxyConfig(manager, configPath).catch(error => {
    cryptoLogger.error('[CLUSTER] Failed to update HAProxy config', error);
  });
  
  // Set up periodic updates
  configUpdateInterval = setInterval(async () => {
    try {
      await updateHAProxyConfig(manager, configPath);
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to update HAProxy config', error);
    }
  }, updateInterval);
}

/**
 * Update HAProxy configuration
 */
async function updateHAProxyConfig(manager, configPath) {
  try {
    cryptoLogger.debug('[CLUSTER] Updating HAProxy configuration');
    
    const generator = await generateConfigFromCluster(manager, configPath);
    
    // Validate and reload if configured
    if (process.env.HAPROXY_AUTO_RELOAD === 'true') {
      await generator.reloadHAProxy(configPath);
      cryptoLogger.info('[CLUSTER] HAProxy configuration updated and reloaded');
    } else {
      cryptoLogger.info('[CLUSTER] HAProxy configuration updated (reload manually)');
    }
  } catch (error) {
    cryptoLogger.error('[CLUSTER] Failed to update HAProxy configuration', error);
    throw error;
  }
}

/**
 * Get cluster manager instance
 */
export function getClusterManager() {
  return clusterManager;
}

/**
 * Get cluster status
 */
export async function getClusterStatus() {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }
  
  return await clusterManager.getClusterStatus();
}

/**
 * Get all server public keys for client distribution
 */
export async function getAllServerPublicKeys() {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }
  
  return await clusterManager.getAllServerKeys();
}

/**
 * Approve a pending server (primary only)
 */
export async function approveServer(serverId) {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }
  
  return await clusterManager.approveServer(serverId);
}

/**
 * Reject a pending server (primary only)
 */
export async function rejectServer(serverId, reason) {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }
  
  return await clusterManager.rejectServer(serverId, reason);
}

/**
 * Get list of pending servers
 */
export async function getPendingServers() {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }
  
  return await clusterManager.getPendingServers();
}

/**
 * Force remove a server from cluster (primary only)
 */
export async function removeServer(serverId) {
  if (!clusterManager) {
    throw new Error('Cluster manager not initialized');
  }
  
  return await clusterManager.forceRemoveServer(serverId);
}

/**
 * shutdown of cluster integration
 */
export async function shutdownCluster() {
  cryptoLogger.info('[CLUSTER] Shutting down cluster integration');
  
  // Stop config updater
  if (configUpdateInterval) {
    clearInterval(configUpdateInterval);
    configUpdateInterval = null;
  }
  
  // Shutdown cluster manager
  if (clusterManager) {
    await clusterManager.shutdown();
    clusterManager = null;
  }
  
  cryptoLogger.info('[CLUSTER] Cluster integration shutdown complete');
}

/**
 * Register cluster shutdown handlers
 */
export function registerClusterShutdownHandlers() {
  const signals = ['SIGINT', 'SIGTERM', 'SIGQUIT'];
  
  signals.forEach(signal => {
    process.on(signal, async () => {
      cryptoLogger.info(`[CLUSTER] Received ${signal}, initiating graceful shutdown`);
      
      try {
        await shutdownCluster();
      } catch (error) {
        cryptoLogger.error('[CLUSTER] Error during cluster shutdown', error);
      }
      
      process.exit(0);
    });
  });
  
  process.on('uncaughtException', async (error) => {
    cryptoLogger.error('[CLUSTER] Uncaught exception, shutting down', error);
    
    try {
      await shutdownCluster();
    } catch (shutdownError) {
      cryptoLogger.error('[CLUSTER] Error during emergency shutdown', shutdownError);
    }
    
    process.exit(1);
  });
  
  process.on('unhandledRejection', async (reason) => {
    cryptoLogger.error('[CLUSTER] Unhandled rejection, shutting down', { reason });
    
    try {
      await shutdownCluster();
    } catch (shutdownError) {
      cryptoLogger.error('[CLUSTER] Error during emergency shutdown', shutdownError);
    }
    
    process.exit(1);
  });
}