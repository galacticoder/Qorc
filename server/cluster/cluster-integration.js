/**
 * Cluster Integration for Server
 */

import { ClusterManager } from './cluster-manager.js';

import {
  CLUSTER_APPROVED_EVENT,
  CLUSTER_JOIN_REQUEST_EVENT,
  CLUSTER_KEYS_ROTATED_EVENT,
  CLUSTER_PROMOTED_EVENT
} from './protocol.js';

let clusterManager = null;

export function getClusterTelemetry() {
  return clusterManager?.getTelemetrySnapshot?.() || {
    serverId: process.env.SERVER_ID,
    registration: 'checking',
    heartbeatAgeSeconds: null,
  };
}

// Initialize cluster integration
export async function initializeCluster({
  serverHybridKeyPair,
  serverId,
  isPrimary,
  autoApprove
}) {
  try {
    if (typeof isPrimary !== 'boolean') throw new Error('Cluster role must be explicitly configured');
    if (typeof autoApprove !== 'boolean') throw new Error('Cluster auto-approval must be explicitly configured');

    console.log('[CLUSTER] Initializing cluster integration', {
      serverId,
      isPrimary,
      autoApprove
    });

    clusterManager = new ClusterManager({
      serverId,
      serverKeys: serverHybridKeyPair,
      isPrimary,
      autoApprove,
    });

    setupClusterEventHandlers(clusterManager, autoApprove);
    await clusterManager.initialize();

    console.log('[CLUSTER] Cluster integration initialized', { serverId });

    return clusterManager;
  } catch (error) {
    console.error('[CLUSTER] Failed to initialize cluster integration', error);
    throw error;
  }
}

// Set up cluster event handlers
function setupClusterEventHandlers(manager, autoApprove) {
  manager.on(CLUSTER_JOIN_REQUEST_EVENT, async (serverInfo) => {
    console.log('[CLUSTER] New server requesting to join', {
      serverId: serverInfo.serverId,
      requestedAt: new Date(serverInfo.requestedAt).toISOString()
    });

    if (autoApprove && manager.isPrimary) {
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

  if (clusterManager) {
    await clusterManager.shutdown();
    clusterManager = null;
  }

  console.log('[CLUSTER] Cluster integration shutdown complete');
}
