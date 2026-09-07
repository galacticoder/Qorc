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

import { requireAdmin } from '../../scripts/admin-auth.js';
import { SERVER_KEYS_UNAVAILABLE_MESSAGE } from '../config/error-codes.js';
import { CLUSTER_SERVER_ID_RE } from '../cluster/signed-message.js';

const router = express.Router();
const REASON_MAX_CHARS = 256;
const CLUSTER_ADMIN_JSON_LIMIT = 2048;
const parseClusterAdminJson = express.json({ limit: CLUSTER_ADMIN_JSON_LIMIT, strict: true });

function validServerId(value) {
  return typeof value === 'string' && CLUSTER_SERVER_ID_RE.test(value);
}

function parseReason(body) {
  if (
    typeof body !== 'object' ||
    Array.isArray(body) ||
    Object.getPrototypeOf(body) !== Object.prototype ||
    Object.keys(body).length !== 1 ||
    !Object.hasOwn(body, 'reason')
  ) return null;
  if (typeof body.reason !== 'string') return null;
  const reason = body.reason.trim();
  if (!reason || reason.length > REASON_MAX_CHARS || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(reason)) return null;
  return reason;
}

function clusterOperationFailed(res, error, responseMessage) {
  const message = String(error?.message || '');
  const status = message.includes('not found') ? 404 :
    message.includes('not initialized') ? 503 :
      message.includes('Only primary') || message.includes('Cannot remove self') ? 403 : 500;
  return res.status(status).json({ success: false, error: responseMessage });
}

router.use((req, res, next) => {
  if (req.method === 'GET' && req.path === '/health') return next();
  return requireAdmin(req, res, next);
});

router.use((req, res, next) => {
  if (req.method === 'GET' && req.path === '/health') return next();
  return parseClusterAdminJson(req, res, next);
});

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
    console.error('[CLUSTER-API] Failed to get server keys', error);
    res.status(500).json({
      success: false,
      error: SERVER_KEYS_UNAVAILABLE_MESSAGE
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
        timestamp: Date.now(),
      });
    } else {
      res.status(503).json({
        status: 'unhealthy',
        timestamp: Date.now(),
      });
    }
  } catch (error) {
    console.error('[CLUSTER-API] Health check failed', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: Date.now(),
    });
  }
});

// Get cluster status (admin)
router.get('/status', async (req, res) => {
  try {
    const status = await getClusterStatus();
    res.json({
      success: true,
      cluster: status,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error('[CLUSTER-API] Failed to get cluster status', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve cluster status'
    });
  }
});

// Get pending servers awaiting approval (admin)
router.get('/pending', async (req, res) => {
  try {
    const pending = await getPendingServers();
    res.json({
      success: true,
      pending,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error('[CLUSTER-API] Failed to get pending servers', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve pending servers'
    });
  }
});

// Approve a pending server (admin)
router.post('/approve/:serverId', async (req, res) => {
  try {
    const { serverId } = req.params;

    if (!validServerId(serverId)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid serverId format',
      });
    }

    await approveServer(serverId);

    console.log('[CLUSTER-API] Server approved', { serverId });

    res.json({
      success: true,
      message: `Server ${serverId} approved`,
      serverId,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error('[CLUSTER-API] Failed to approve server', error);
    return clusterOperationFailed(res, error, 'Server approval failed');
  }
});

// Reject a pending server (admin)
router.post('/reject/:serverId', async (req, res) => {
  try {
    const { serverId } = req.params;
    const reason = parseReason(req.body);

    if (!validServerId(serverId) || reason === null) {
      return res.status(400).json({
        success: false,
        error: 'Invalid rejection request',
      });
    }

    await rejectServer(serverId, reason);

    console.log('[CLUSTER-API] Server rejected', { serverId, reason });

    res.json({
      success: true,
      message: `Server ${serverId} rejected`,
      serverId,
      reason,
      timestamp: Date.now(),
    });
  } catch (error) {
    console.error('[CLUSTER-API] Failed to reject server', error);
    return clusterOperationFailed(res, error, 'Server rejection failed');
  }
});

// Force remove a server from cluster (admin)
router.delete('/remove/:serverId', async (req, res) => {
  try {
    const { serverId } = req.params;
    const reason = parseReason(req.body);

    if (!validServerId(serverId) || reason === null) {
      return res.status(400).json({
        success: false,
        error: 'Invalid removal request',
      });
    }

    const result = await removeServer(serverId);

    console.log('[CLUSTER-API] Server force removed via API', {
      serverId,
      adminId: req.admin?.id,
      reason,
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
    console.error('[CLUSTER-API] Failed to remove server', {
      error: error.message,
      serverId: req.params.serverId,
      adminId: req.admin?.id,
    });

    return clusterOperationFailed(res, error, 'Server removal failed');
  }
});

export default router;
