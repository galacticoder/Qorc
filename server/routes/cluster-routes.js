/**
 * Cluster Management API Routes
 * 
 * - HYBRID POST-QUANTUM AUTHENTICATION:
 *   · ML-KEM-1024 + X25519 (hybrid key encapsulation)
 *   · ML-DSA-87 + Ed25519 (dual signatures)
 *   · Username+password protected admin keys
 * - Rate limiting on all endpoints
 * - Comprehensive audit logging
 * - Fail-closed security model
 * 
 * Provides endpoints for:
 * - Server public key distribution (for clients)
 * - Cluster status (admin only)
 * - Server approval/rejection (admin only)
 * - Server force removal (admin only)
 * - Health checks
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
import { requireAdmin } from '../cluster/hybrid-admin-auth.js';

const router = express.Router();

/**
 * PUBLIC: Get all server public keys for clients
 */
router.get('/server-keys', async (req, res) => {
  try {
    const keys = await getAllServerPublicKeys();
    
    // Format for client consumption
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

/**
 * PUBLIC: Health check endpoint for load balancer
 */
router.get('/health', async (req, res) => {
  try {
    const manager = getClusterManager();
    
    // Check if approved and healthy
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

/**
 * ADMIN: Get cluster status
 */
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

/**
 * ADMIN: Get pending servers awaiting approval
 */
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

/**
 * ADMIN: Approve a pending server
 */
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

/**
 * ADMIN: Reject a pending server
 */
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

/**
 * ADMIN: Force remove a server from cluster
 */
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
    
    // Validate serverId format
    if (typeof serverId !== 'string' || serverId.length < 3) {
      return res.status(400).json({
        success: false,
        error: 'Invalid serverId format',
      });
    }
    
    // Force remove server from cluster
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
    
    // Return appropriate error status
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