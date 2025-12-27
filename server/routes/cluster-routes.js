/**
 * Cluster Management API Routes
 */

import express from 'express';
import {
  getClusterManager,
  getClusterStatus,
  getAllServerPublicKeys,
  approveServer,
  rejectServer,
  getPendingServers,
  removeServer
} from '../cluster/cluster-integration.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { requireAdmin } from '../../scripts/admin-auth.js';

const router = express.Router();

// Get all server public keys for clients
router.get('/server-keys', async (req, res) => {
  try {
    const keys = await getAllServerPublicKeys();

    const serverKeys = Object.entries(keys).map(([serverId, keyData]) => ({
      serverId,
      publicKeys: keyData.publicKeys,
    }));

    res.json({
      success: true,
      serverKeys,
      timestamp: Date.now(),
    });
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Failed to get server keys', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve server keys'
    });
  }
});

// Health check endpoint for load balancer
router.get('/health', async (req, res) => {
  try {
    const manager = getClusterManager();
    const isHealthy = manager && manager.isApproved && !manager.isShuttingDown;

    if (isHealthy) {
      res.status(200).json({
        status: 'healthy',
        serverId: manager.serverId,
        timestamp: Date.now(),
      });
    } else {
      res.status(503).json({
        status: 'unhealthy',
        reason: !manager ? 'not initialized' :
          !manager.isApproved ? 'not approved' :
            'shutting down',
        timestamp: Date.now(),
      });
    }
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Health check failed', error);
    res.status(503).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: Date.now(),
    });
  }
});

// Get cluster status (admin)
router.get('/status', requireAdmin, async (req, res) => {
  try {
    const status = await getClusterStatus();
    res.json({
      success: true,
      cluster: status,
      timestamp: Date.now(),
    });
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Failed to get cluster status', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve cluster status'
    });
  }
});

// Get pending servers awaiting approval (admin)
router.get('/pending', requireAdmin, async (req, res) => {
  try {
    const pending = await getPendingServers();
    res.json({
      success: true,
      pending,
      timestamp: Date.now(),
    });
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Failed to get pending servers', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve pending servers'
    });
  }
});

// Approve a pending server (admin)
router.post('/approve/:serverId', requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;

    if (!serverId) {
      return res.status(400).json({
        success: false,
        error: 'serverId is required',
      });
    }

    await approveServer(serverId);

    cryptoLogger.info('[CLUSTER-API] Server approved', { serverId });

    res.json({
      success: true,
      message: `Server ${serverId} approved`,
      serverId,
      timestamp: Date.now(),
    });
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Failed to approve server', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Reject a pending server (admin)
router.post('/reject/:serverId', requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { reason } = req.body;

    if (!serverId) {
      return res.status(400).json({
        success: false,
        error: 'serverId is required',
      });
    }

    await rejectServer(serverId, reason || 'Rejected by admin');

    cryptoLogger.info('[CLUSTER-API] Server rejected', { serverId, reason });

    res.json({
      success: true,
      message: `Server ${serverId} rejected`,
      serverId,
      reason: reason || 'Rejected by admin',
      timestamp: Date.now(),
    });
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Failed to reject server', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Force remove a server from cluster (admin)
router.delete('/remove/:serverId', requireAdmin, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { reason } = req.body;

    if (!serverId) {
      return res.status(400).json({
        success: false,
        error: 'serverId is required',
      });
    }

    if (typeof serverId !== 'string' || serverId.length < 3) {
      return res.status(400).json({
        success: false,
        error: 'Invalid serverId format',
      });
    }

    const result = await removeServer(serverId);

    cryptoLogger.info('[CLUSTER-API] Server force removed via API', {
      serverId,
      adminId: req.admin?.id,
      reason: reason || 'Force removal via admin API',
      removedServer: result.removedServer,
    });

    res.json({
      success: true,
      message: `Server ${serverId} has been removed from cluster`,
      serverId,
      removedServer: result.removedServer,
      removedBy: req.admin?.id,
      timestamp: Date.now(),
    });
  } catch (error) {
    cryptoLogger.error('[CLUSTER-API] Failed to remove server', {
      error: error.message,
      serverId: req.params.serverId,
      adminId: req.admin?.id,
    });

    const status = error.message.includes('not found') ? 404 :
      error.message.includes('not initialized') ? 503 :
        error.message.includes('Only primary') ? 403 : 500;

    res.status(status).json({
      success: false,
      error: error.message,
      serverId: req.params.serverId,
    });
  }
});

export default router;