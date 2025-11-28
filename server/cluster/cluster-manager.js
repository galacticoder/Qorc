/**
 * Server Cluster Manager
 * 
 * Manages server clustering with:
 * - Redis-based server discovery and registration
 * - Mutual authentication using post-quantum crypto
 * - Health monitoring and automatic failover
 * - Server-to-server secure communication
 * - Approval-based cluster joining
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';
import { withRedisClient, createSubscriber } from '../presence/presence.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// Redis keys for cluster coordination
const CLUSTER_KEYS = {
  SERVERS: 'cluster:servers',                    // Hash of active servers
  PENDING: 'cluster:pending',                    // Set of servers awaiting approval
  KEYS: 'cluster:keys',                          // Hash of server public keys
  HEALTH: 'cluster:health',                      // Hash of server health status
  MASTER: 'cluster:master',                      // Current master server ID
  TOKENS: 'cluster:tokens',                      // Hash of cluster authentication tokens
  MESSAGES: 'cluster:messages',                  // Pub/sub channel for inter-server messages
  SHARED_CONFIG: 'cluster:config',               // Shared configuration (e.g., server password)
};

// Configuration
const CONFIG = {
  HEARTBEAT_INTERVAL: 5000,                      // 5 seconds
  HEALTH_CHECK_INTERVAL: 10000,                  // 10 seconds
  SERVER_TIMEOUT: 30000,                         // 30 seconds (miss 6 heartbeats)
  APPROVAL_TIMEOUT: 300000,                      // 5 minutes for admin approval
  MIN_SERVERS_FOR_CLUSTER: 1,                    // Minimum servers to form cluster
  MAX_SERVERS_IN_CLUSTER: 100,                   // Maximum cluster size
  KEY_ROTATION_INTERVAL: 86400000,               // 24 hours
};

export class ClusterManager extends EventEmitter {
  constructor({ serverId, serverKeys, isPrimary = false, autoApprove = false }) {
    super();

    if (!serverId || typeof serverId !== 'string') {
      throw new Error('serverId is required and must be a string');
    }

    if (!serverKeys?.kyber?.publicKey || !serverKeys?.dilithium?.publicKey || !serverKeys?.x25519?.publicKey) {
      throw new Error('serverKeys must contain kyber, dilithium, and x25519 public keys');
    }

    this.serverId = serverId;
    this.serverKeys = serverKeys;
    this.isPrimary = isPrimary;
    this.autoApprove = autoApprove;
    this.isApproved = isPrimary; // Primary server is auto-approved
    this.isShuttingDown = false;

    // Cluster state
    this.clusterServers = new Map(); // serverId -> serverInfo
    this.serverHealth = new Map();   // serverId -> health data

    // Authentication tokens for inter-server communication
    this.clusterToken = null;
    this.clusterSigningKey = null;
    this.clusterPublicKey = null;

    // Intervals
    this.heartbeatInterval = null;
    this.healthCheckInterval = null;
    this.keyRotationInterval = null;

    // Redis subscriber for cluster messages
    this.messageSubscriber = null;

    cryptoLogger.info('[CLUSTER] Cluster manager initialized', {
      serverId: this.serverId,
      isPrimary: this.isPrimary,
      autoApprove: this.autoApprove
    });
  }

  /**
   * Parse PORT environment variable with support for "dynamic" (0 = auto-assign)
   */
  parsePort(portValue) {
    const DEFAULT_PORT = 8443;
    if (!portValue) return DEFAULT_PORT;
    if (typeof portValue === 'string') {
      const lower = portValue.toLowerCase();
      if (lower === 'dynamic' || lower === '0') return DEFAULT_PORT;
    }
    const parsed = parseInt(portValue, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_PORT;
    return parsed;
  }

  /**
   * Initialize cluster manager and join cluster
   */
  async initialize() {
    try {
      // Generate cluster authentication keys
      await this.generateClusterKeys();

      // Clean up stale server entries before joining
      await this.cleanupStaleServers();

      // Register server in cluster
      if (this.isPrimary) {
        await this.initializePrimaryServer();
      } else {
        await this.requestClusterJoin();
      }

      // Set up cluster message subscriber
      await this.setupMessageSubscriber();

      // Start heartbeat and health monitoring
      this.startHeartbeat();
      this.startHealthMonitoring();

      // Set up key rotation
      this.startKeyRotation();

      cryptoLogger.info('[CLUSTER] Cluster manager started', {
        serverId: this.serverId,
        isApproved: this.isApproved
      });

      this.emit('initialized');
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to initialize cluster manager', error);
      throw error;
    }
  }

  /**
   * Generate post-quantum keys for cluster authentication
   */
  async generateClusterKeys() {
    try {
      // Generate ML-DSA key pair for signing cluster messages
      const keyPair = ml_dsa87.keygen();
      this.clusterSigningKey = keyPair.secretKey;
      this.clusterPublicKey = keyPair.publicKey;

      // Generate secure random token for this server
      this.clusterToken = crypto.randomBytes(64).toString('base64url');

      cryptoLogger.info('[CLUSTER] Generated cluster authentication keys', {
        serverId: this.serverId
      });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to generate cluster keys', error);
      throw error;
    }
  }

  /**
   * Initialize as primary server (master)
   */
  async initializePrimaryServer() {
    try {
      await withRedisClient(async (client) => {
        const pipeline = client.pipeline();

        // Register as master server
        pipeline.set(CLUSTER_KEYS.MASTER, this.serverId);

        // Register server info
        const serverInfo = {
          serverId: this.serverId,
          isPrimary: true,
          joinedAt: Date.now(),
          lastHeartbeat: Date.now(),
          status: 'active',
          publicKeys: this.exportPublicKeys(),
          host: process.env.SERVER_HOST || process.env.HOST || '127.0.0.1',
          port: this.parsePort(process.env.PORT),
        };
        pipeline.hset(CLUSTER_KEYS.SERVERS, this.serverId, JSON.stringify(serverInfo));

        // Register public keys
        pipeline.hset(CLUSTER_KEYS.KEYS, this.serverId, JSON.stringify({
          serverId: this.serverId,
          clusterPublicKey: Buffer.from(this.clusterPublicKey).toString('base64'),
          publicKeys: this.exportPublicKeys(),
        }));

        // Store cluster token (hashed)
        const tokenHash = crypto.createHash('sha256').update(this.clusterToken).digest('hex');
        pipeline.hset(CLUSTER_KEYS.TOKENS, this.serverId, tokenHash);

        // Initialize health
        pipeline.hset(CLUSTER_KEYS.HEALTH, this.serverId, JSON.stringify({
          status: 'healthy',
          lastCheck: Date.now(),
          uptime: 0,
        }));

        // Store shared server password hash if provided
        if (process.env.SERVER_PASSWORD_HASH) {
          pipeline.hset(CLUSTER_KEYS.SHARED_CONFIG, 'SERVER_PASSWORD_HASH', process.env.SERVER_PASSWORD_HASH);
          cryptoLogger.info('[CLUSTER] Stored shared server password hash in Redis');
        }

        await pipeline.exec();
      });

      cryptoLogger.info('[CLUSTER] Initialized as primary server', {
        serverId: this.serverId
      });

      this.emit('primary-initialized');
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to initialize primary server', error);
      throw error;
    }
  }

  /**
   * Request to join cluster (with auto-approval support)
   */
  async requestClusterJoin() {
    try {
      await withRedisClient(async (client) => {
        // Check if already approved
        const existingServer = await client.hget(CLUSTER_KEYS.SERVERS, this.serverId);
        if (existingServer) {
          this.isApproved = true;
          cryptoLogger.info('[CLUSTER] Server already approved', { serverId: this.serverId });
          return;
        }

        const pendingInfo = {
          serverId: this.serverId,
          requestedAt: Date.now(),
          publicKeys: this.exportPublicKeys(),
          clusterPublicKey: Buffer.from(this.clusterPublicKey).toString('base64'),
          host: process.env.SERVER_HOST || process.env.HOST || '127.0.0.1',
          port: this.parsePort(process.env.PORT),
        };

        // If auto-approve is enabled, directly register server
        if (this.autoApprove) {
          const serverInfo = {
            serverId: this.serverId,
            isPrimary: false,
            joinedAt: Date.now(),
            lastHeartbeat: Date.now(),
            approvedBy: 'auto-approve',
            status: 'active',
            publicKeys: this.exportPublicKeys(),
            host: pendingInfo.host,
            port: pendingInfo.port,
          };

          const pipeline = client.pipeline();
          pipeline.hset(CLUSTER_KEYS.SERVERS, this.serverId, JSON.stringify(serverInfo));
          pipeline.hset(CLUSTER_KEYS.KEYS, this.serverId, JSON.stringify({
            serverId: this.serverId,
            clusterPublicKey: pendingInfo.clusterPublicKey,
            publicKeys: pendingInfo.publicKeys,
          }));
          pipeline.hset(CLUSTER_KEYS.HEALTH, this.serverId, JSON.stringify({
            status: 'healthy',
            lastCheck: Date.now(),
            uptime: 0,
          }));
          await pipeline.exec();

          this.isApproved = true;
          cryptoLogger.info('[CLUSTER] Server auto-approved and joined cluster', {
            serverId: this.serverId
          });
          this.emit('approved');
          return;
        }

        // Manual approval flow
        await client.hset(CLUSTER_KEYS.PENDING, this.serverId, JSON.stringify(pendingInfo));
        await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
          type: 'join-request',
          serverId: this.serverId,
          timestamp: Date.now(),
          data: pendingInfo,
        }));

        cryptoLogger.info('[CLUSTER] Sent cluster join request', {
          serverId: this.serverId
        });

        this.emit('join-requested');
      });

      // Wait for approval if not auto-approved
      if (!this.isApproved) {
        await this.waitForApproval();
      }
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to request cluster join', error);
      throw error;
    }
  }

  /**
   * Wait for cluster join approval
   */
  async waitForApproval() {
    const startTime = Date.now();

    while (!this.isApproved && Date.now() - startTime < CONFIG.APPROVAL_TIMEOUT) {
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Check if approved
      const isApproved = await withRedisClient(async (client) => {
        const serverInfo = await client.hget(CLUSTER_KEYS.SERVERS, this.serverId);
        return !!serverInfo;
      });

      if (isApproved) {
        this.isApproved = true;
        cryptoLogger.info('[CLUSTER] Server approved and joined cluster', {
          serverId: this.serverId
        });
        this.emit('approved');
        return;
      }
    }

    if (!this.isApproved) {
      const error = new Error('Cluster join approval timeout - admin must approve this server');
      cryptoLogger.error('[CLUSTER] Join approval timeout', { serverId: this.serverId });
      throw error;
    }
  }

  /**
   * Approve a pending server (primary only)
   */
  async approveServer(targetServerId) {
    if (!this.isPrimary) {
      throw new Error('Only primary server can approve new servers');
    }

    try {
      await withRedisClient(async (client) => {
        // Get pending server info
        const pendingData = await client.hget(CLUSTER_KEYS.PENDING, targetServerId);
        if (!pendingData) {
          throw new Error(`Server ${targetServerId} not found in pending list`);
        }

        const pendingInfo = JSON.parse(pendingData);

        // Verify server count limit
        const serverCount = await client.hlen(CLUSTER_KEYS.SERVERS);
        if (serverCount >= CONFIG.MAX_SERVERS_IN_CLUSTER) {
          throw new Error('Maximum cluster size reached');
        }

        const pipeline = client.pipeline();

        // Move from pending to approved
        pipeline.hdel(CLUSTER_KEYS.PENDING, targetServerId);

        // Register server
        const serverInfo = {
          serverId: targetServerId,
          isPrimary: false,
          joinedAt: Date.now(),
          lastHeartbeat: Date.now(),
          approvedBy: this.serverId,
          status: 'active',
          publicKeys: pendingInfo.publicKeys,
          host: pendingInfo.host || '127.0.0.1',
          port: pendingInfo.port || 8443,
        };
        pipeline.hset(CLUSTER_KEYS.SERVERS, targetServerId, JSON.stringify(serverInfo));

        // Register public keys
        pipeline.hset(CLUSTER_KEYS.KEYS, targetServerId, JSON.stringify({
          serverId: targetServerId,
          clusterPublicKey: pendingInfo.clusterPublicKey,
          publicKeys: pendingInfo.publicKeys,
        }));

        // Initialize health
        pipeline.hset(CLUSTER_KEYS.HEALTH, targetServerId, JSON.stringify({
          status: 'healthy',
          lastCheck: Date.now(),
          uptime: 0,
        }));

        await pipeline.exec();

        // Notify cluster
        await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
          type: 'server-approved',
          serverId: targetServerId,
          approvedBy: this.serverId,
          timestamp: Date.now(),
        }));
      });

      cryptoLogger.info('[CLUSTER] Approved server', {
        targetServerId,
        approvedBy: this.serverId
      });

      this.emit('server-approved', { serverId: targetServerId });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to approve server', error);
      throw error;
    }
  }

  /**
   * Reject a pending server (primary only)
   */
  async rejectServer(targetServerId, reason = 'Rejected by admin') {
    if (!this.isPrimary) {
      throw new Error('Only primary server can reject servers');
    }

    try {
      await withRedisClient(async (client) => {
        await client.hdel(CLUSTER_KEYS.PENDING, targetServerId);

        // Notify rejected server
        await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
          type: 'server-rejected',
          serverId: targetServerId,
          rejectedBy: this.serverId,
          reason,
          timestamp: Date.now(),
        }));
      });

      cryptoLogger.info('[CLUSTER] Rejected server', {
        targetServerId,
        reason
      });

      this.emit('server-rejected', { serverId: targetServerId, reason });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to reject server', error);
      throw error;
    }
  }

  /**
   * Get list of pending servers (primary only)
   */
  async getPendingServers() {
    return await withRedisClient(async (client) => {
      const pending = await client.hgetall(CLUSTER_KEYS.PENDING);
      return Object.entries(pending).map(([serverId, data]) => ({
        serverId,
        ...JSON.parse(data)
      }));
    });
  }

  /**
   * Force remove a server from cluster (primary only)
   */
  async forceRemoveServer(targetServerId) {
    if (!this.isPrimary) {
      throw new Error('Only primary server can force remove servers');
    }

    if (targetServerId === this.serverId) {
      throw new Error('Cannot remove self from cluster');
    }

    try {
      let serverInfo = null;

      await withRedisClient(async (client) => {
        // Get server info before removal for audit logging
        const serverData = await client.hget(CLUSTER_KEYS.SERVERS, targetServerId);
        if (serverData) {
          serverInfo = JSON.parse(serverData);
        }

        // Also check pending servers
        const pendingData = await client.hget(CLUSTER_KEYS.PENDING, targetServerId);
        if (pendingData && !serverInfo) {
          serverInfo = JSON.parse(pendingData);
          serverInfo.status = 'pending';
        }

        if (!serverInfo) {
          throw new Error(`Server ${targetServerId} not found in cluster or pending list`);
        }

        // Remove from all Redis keys
        const pipeline = client.pipeline();
        pipeline.hdel(CLUSTER_KEYS.SERVERS, targetServerId);
        pipeline.hdel(CLUSTER_KEYS.PENDING, targetServerId);
        pipeline.hdel(CLUSTER_KEYS.HEALTH, targetServerId);
        pipeline.hdel(CLUSTER_KEYS.KEYS, targetServerId);
        pipeline.hdel(CLUSTER_KEYS.TOKENS, targetServerId);

        await pipeline.exec();

        // Notify cluster of forced removal
        await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
          type: 'server-force-removed',
          serverId: targetServerId,
          removedBy: this.serverId,
          reason: 'Admin force removal',
          timestamp: Date.now(),
        }));
      });

      // Update local state
      this.clusterServers.delete(targetServerId);
      this.serverHealth.delete(targetServerId);

      cryptoLogger.info('[CLUSTER] Server force removed', {
        targetServerId,
        removedBy: this.serverId,
        serverInfo,
        action: 'ADMIN_FORCE_REMOVAL'
      });

      this.emit('server-removed', { serverId: targetServerId, forced: true });

      return {
        success: true,
        serverId: targetServerId,
        removedServer: serverInfo,
      };
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to force remove server', error);
      throw error;
    }
  }

  /**
   * Start sending heartbeats
   */
  startHeartbeat() {
    this.heartbeatInterval = setInterval(async () => {
      if (!this.isApproved || this.isShuttingDown) return;

      try {
        await this.sendHeartbeat();
      } catch (error) {
        cryptoLogger.error('[CLUSTER] Heartbeat failed', error);
      }
    }, CONFIG.HEARTBEAT_INTERVAL);
  }

  /**
   * Update server port in Redis (for dynamic port allocation)
   */
  async updateServerPort(actualPort) {
    try {
      await withRedisClient(async (client) => {
        const serverData = await client.hget(CLUSTER_KEYS.SERVERS, this.serverId);
        if (serverData) {
          const info = JSON.parse(serverData);
          const oldPort = info.port;
          info.port = actualPort;
          info.host = process.env.SERVER_HOST || process.env.HOST || '127.0.0.1';
          await client.hset(CLUSTER_KEYS.SERVERS, this.serverId, JSON.stringify(info));
          cryptoLogger.info('[CLUSTER] Updated server port in Redis', {
            serverId: this.serverId,
            oldPort,
            newPort: actualPort
          });
        }
      });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to update server port', error);
    }
  }

  /**
   * Send heartbeat to cluster
   */
  async sendHeartbeat() {
    try {
      await withRedisClient(async (client) => {
        const serverInfo = await client.hget(CLUSTER_KEYS.SERVERS, this.serverId);
        if (!serverInfo) {
          cryptoLogger.warn('[CLUSTER] Server not registered, re-registering');
          if (this.isPrimary) {
            await this.initializePrimaryServer();
          }
          return;
        }

        const info = JSON.parse(serverInfo);
        info.lastHeartbeat = Date.now();

        await client.hset(CLUSTER_KEYS.SERVERS, this.serverId, JSON.stringify(info));
      });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to send heartbeat', error);
      throw error;
    }
  }

  /**
   * Start health monitoring of cluster servers
   */
  startHealthMonitoring() {
    this.healthCheckInterval = setInterval(async () => {
      if (!this.isApproved || this.isShuttingDown) return;

      try {
        await this.checkClusterHealth();
      } catch (error) {
        cryptoLogger.error('[CLUSTER] Health check failed', error);
      }
    }, CONFIG.HEALTH_CHECK_INTERVAL);
  }

  /**
   * Check health of all cluster servers
   */
  async checkClusterHealth() {
    try {
      await withRedisClient(async (client) => {
        const servers = await client.hgetall(CLUSTER_KEYS.SERVERS);
        const now = Date.now();

        for (const [serverId, data] of Object.entries(servers)) {
          const serverInfo = JSON.parse(data);
          const timeSinceHeartbeat = now - serverInfo.lastHeartbeat;

          if (timeSinceHeartbeat > CONFIG.SERVER_TIMEOUT) {
            // Server is dead
            await this.handleDeadServer(serverId, serverInfo);
          } else {
            // Update local cache
            this.clusterServers.set(serverId, serverInfo);

            // Update health status
            const health = {
              status: 'healthy',
              lastCheck: now,
              uptime: now - serverInfo.joinedAt,
              lastHeartbeat: serverInfo.lastHeartbeat,
            };
            await client.hset(CLUSTER_KEYS.HEALTH, serverId, JSON.stringify(health));
            this.serverHealth.set(serverId, health);
          }
        }
      });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to check cluster health', error);
      throw error;
    }
  }

  /**
   * Clean up stale server entries on startup
   */
  async cleanupStaleServers() {
    try {
      await withRedisClient(async (client) => {
        const servers = await client.hgetall(CLUSTER_KEYS.SERVERS);
        const now = Date.now();
        let cleanedCount = 0;

        for (const [serverId, data] of Object.entries(servers)) {
          try {
            const serverInfo = JSON.parse(data);
            const timeSinceHeartbeat = now - (serverInfo.lastHeartbeat || 0);

            if (timeSinceHeartbeat > CONFIG.SERVER_TIMEOUT * 2) {
              cryptoLogger.warn('[CLUSTER] Removing stale server entry', {
                serverId,
                timeSinceHeartbeat: Math.round(timeSinceHeartbeat / 1000) + 's',
                lastHeartbeat: new Date(serverInfo.lastHeartbeat).toISOString()
              });

              const pipeline = client.pipeline();
              pipeline.hdel(CLUSTER_KEYS.SERVERS, serverId);
              pipeline.hdel(CLUSTER_KEYS.HEALTH, serverId);
              pipeline.hdel(CLUSTER_KEYS.KEYS, serverId);
              pipeline.hdel(CLUSTER_KEYS.TOKENS, serverId);

              // If the stale server was primary, clear master key
              if (serverInfo.isPrimary) {
                const currentMaster = await client.get(CLUSTER_KEYS.MASTER);
                if (currentMaster === serverId) {
                  cryptoLogger.warn('[CLUSTER] Removing stale primary server master key', { serverId });
                  pipeline.del(CLUSTER_KEYS.MASTER);
                }
              }

              await pipeline.exec();
              cleanedCount++;
            }
          } catch (_parseError) {
            cryptoLogger.warn('[CLUSTER] Removing corrupted server entry', { serverId });
            await client.hdel(CLUSTER_KEYS.SERVERS, serverId);
            cleanedCount++;
          }
        }

        if (cleanedCount > 0) {
          cryptoLogger.info('[CLUSTER] Stale server cleanup completed', {
            cleanedCount,
            message: 'Removed ghost servers from previous crashes'
          });
        } else {
          cryptoLogger.info('[CLUSTER] No stale servers found - cluster is clean');
        }
      });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to clean up stale servers', error);
    }
  }

  /**
   * Handle a dead/unresponsive server
   */
  async handleDeadServer(serverId, serverInfo) {
    try {
      cryptoLogger.warn('[CLUSTER] Detected dead server', { serverId });

      await withRedisClient(async (client) => {
        const pipeline = client.pipeline();

        // Remove from active servers
        pipeline.hdel(CLUSTER_KEYS.SERVERS, serverId);
        pipeline.hdel(CLUSTER_KEYS.HEALTH, serverId);
        pipeline.hdel(CLUSTER_KEYS.KEYS, serverId);
        pipeline.hdel(CLUSTER_KEYS.TOKENS, serverId);

        await pipeline.exec();

        // Notify cluster
        await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
          type: 'server-dead',
          serverId,
          detectedBy: this.serverId,
          timestamp: Date.now(),
        }));
      });

      // Update local state
      this.clusterServers.delete(serverId);
      this.serverHealth.delete(serverId);

      this.emit('server-dead', { serverId, serverInfo });

      // If primary died, initiate election
      if (serverInfo.isPrimary) {
        await this.handlePrimaryFailure();
      }
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to handle dead server', error);
    }
  }

  /**
   * Handle primary server failure (initiate election)
   * Queue-based primary selection
   */
  async handlePrimaryFailure() {
    cryptoLogger.warn('[CLUSTER] Primary server failed, initiating queue-based election');

    try {
      await withRedisClient(async (client) => {
        const servers = await client.hgetall(CLUSTER_KEYS.SERVERS);
        if (Object.keys(servers).length === 0) {
          cryptoLogger.error('[CLUSTER] No servers available after primary failure');
          return;
        }

        let oldestServer = null;
        let oldestTime = Date.now();

        // Find the oldest server (earliest joinedAt timestamp) = next in queue
        for (const [serverId, data] of Object.entries(servers)) {
          const info = JSON.parse(data);
          if (info.joinedAt < oldestTime) {
            oldestTime = info.joinedAt;
            oldestServer = { serverId, info };
          }
        }

        if (oldestServer) {
          // Promote to primary
          oldestServer.info.isPrimary = true;
          await client.hset(CLUSTER_KEYS.SERVERS, oldestServer.serverId, JSON.stringify(oldestServer.info));
          await client.set(CLUSTER_KEYS.MASTER, oldestServer.serverId);

          cryptoLogger.info('[CLUSTER] Queue-based election completed', {
            newPrimary: oldestServer.serverId,
            joinedAt: new Date(oldestServer.info.joinedAt).toISOString(),
            message: 'Next server in queue promoted to primary'
          });

          // Notify cluster
          await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
            type: 'primary-elected',
            serverId: oldestServer.serverId,
            timestamp: Date.now(),
          }));

          // If we are the new primary, update our state
          if (oldestServer.serverId === this.serverId) {
            this.isPrimary = true;
            cryptoLogger.info('[CLUSTER] This server promoted to primary (next in queue)');
            this.emit('promoted-to-primary');
          }
        }
      });
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to handle primary failure', error);
    }
  }

  /**
   * Set up message subscriber for inter-server communication
   */
  async setupMessageSubscriber() {
    try {
      this.messageSubscriber = await createSubscriber();
      await this.messageSubscriber.subscribe(CLUSTER_KEYS.MESSAGES);

      this.messageSubscriber.on('message', async (channel, message) => {
        try {
          const msg = JSON.parse(message);
          await this.handleClusterMessage(msg);
        } catch (error) {
          cryptoLogger.error('[CLUSTER] Failed to handle cluster message', error);
        }
      });

      cryptoLogger.info('[CLUSTER] Message subscriber initialized');
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to setup message subscriber', error);
      throw error;
    }
  }

  /**
   * Handle cluster messages
   */
  async handleClusterMessage(msg) {
    // Ignore own messages
    if (msg.serverId === this.serverId) return;

    switch (msg.type) {
      case 'join-request':
        if (this.isPrimary) {
          cryptoLogger.info('[CLUSTER] Received join request', { serverId: msg.serverId });
          this.emit('join-request', msg.data);
        }
        break;

      case 'server-approved':
        if (msg.serverId === this.serverId) {
          this.isApproved = true;
          this.emit('approved');
        }
        this.emit('server-joined', { serverId: msg.serverId });
        break;

      case 'server-rejected':
        if (msg.serverId === this.serverId) {
          cryptoLogger.error('[CLUSTER] Server join rejected', { reason: msg.reason });
          this.emit('rejected', { reason: msg.reason });
          await this.shutdown();
          process.exit(1);
        }
        break;

      case 'server-dead':
        cryptoLogger.warn('[CLUSTER] Server marked as dead', { serverId: msg.serverId });
        this.clusterServers.delete(msg.serverId);
        this.serverHealth.delete(msg.serverId);
        this.emit('server-removed', { serverId: msg.serverId });
        break;

      case 'primary-elected':
        cryptoLogger.info('[CLUSTER] New primary elected', { serverId: msg.serverId });
        if (msg.serverId === this.serverId) {
          this.isPrimary = true;
          this.emit('promoted-to-primary');
        }
        break;

      default:
        cryptoLogger.debug('[CLUSTER] Unknown message type', { type: msg.type });
    }
  }

  /**
   * Start key rotation
   */
  startKeyRotation() {
    this.keyRotationInterval = setInterval(async () => {
      if (!this.isApproved || this.isShuttingDown) return;

      try {
        await this.rotateKeys();
      } catch (error) {
        cryptoLogger.error('[CLUSTER] Key rotation failed', error);
      }
    }, CONFIG.KEY_ROTATION_INTERVAL);
  }

  /**
   * Rotate cluster authentication keys
   */
  async rotateKeys() {
    try {
      cryptoLogger.info('[CLUSTER] Starting key rotation', { serverId: this.serverId });

      // Generate new cluster keys
      await this.generateClusterKeys();

      // Update in Redis
      await withRedisClient(async (client) => {
        const keysData = await client.hget(CLUSTER_KEYS.KEYS, this.serverId);
        if (keysData) {
          const keys = JSON.parse(keysData);
          keys.clusterPublicKey = Buffer.from(this.clusterPublicKey).toString('base64');
          await client.hset(CLUSTER_KEYS.KEYS, this.serverId, JSON.stringify(keys));
        }

        // Update token hash
        const tokenHash = crypto.createHash('sha256').update(this.clusterToken).digest('hex');
        await client.hset(CLUSTER_KEYS.TOKENS, this.serverId, tokenHash);
      });

      cryptoLogger.info('[CLUSTER] Key rotation completed', { serverId: this.serverId });
      this.emit('keys-rotated');
    } catch (error) {
      cryptoLogger.error('[CLUSTER] Failed to rotate keys', error);
      throw error;
    }
  }

  /**
   * Export public keys for distribution
   */
  exportPublicKeys() {
    return {
      kyber: Buffer.from(this.serverKeys.kyber.publicKey).toString('base64'),
      dilithium: Buffer.from(this.serverKeys.dilithium.publicKey).toString('base64'),
      x25519: Buffer.from(this.serverKeys.x25519.publicKey).toString('base64'),
    };
  }

  /**
   * Get all server public keys from cluster
   */
  async getAllServerKeys() {
    return await withRedisClient(async (client) => {
      const keysData = await client.hgetall(CLUSTER_KEYS.KEYS);
      const keys = {};

      for (const [serverId, data] of Object.entries(keysData)) {
        keys[serverId] = JSON.parse(data);
      }

      return keys;
    });
  }

  /**
   * Get cluster status
   */
  async getClusterStatus() {
    return await withRedisClient(async (client) => {
      const [servers, pending, health, master] = await Promise.all([
        client.hgetall(CLUSTER_KEYS.SERVERS),
        client.hgetall(CLUSTER_KEYS.PENDING),
        client.hgetall(CLUSTER_KEYS.HEALTH),
        client.get(CLUSTER_KEYS.MASTER),
      ]);

      return {
        master,
        serverCount: Object.keys(servers).length,
        pendingCount: Object.keys(pending).length,
        servers: Object.entries(servers).map(([id, data]) => ({
          serverId: id,
          ...JSON.parse(data),
          health: health[id] ? JSON.parse(health[id]) : null,
        })),
        pending: Object.entries(pending).map(([id, data]) => ({
          serverId: id,
          ...JSON.parse(data),
        })),
      };
    });
  }

  /**
   * Get shared cluster configuration
   * @param {string} key - Configuration key to retrieve
   */
  static async getSharedConfig(key) {
    return await withRedisClient(async (client) => {
      return await client.hget(CLUSTER_KEYS.SHARED_CONFIG, key);
    });
  }

  /**
   * Set shared cluster configuration (primary only)
   * @param {string} key - Configuration key
   * @param {string} value - Configuration value
   */
  async setSharedConfig(key, value) {
    if (!this.isPrimary) {
      throw new Error('Only primary server can set shared configuration');
    }

    return await withRedisClient(async (client) => {
      await client.hset(CLUSTER_KEYS.SHARED_CONFIG, key, value);
      cryptoLogger.info('[CLUSTER] Set shared configuration', { key });
    });
  }

  /**
   * shutdown
   */
  async shutdown() {
    cryptoLogger.info('[CLUSTER] Shutting down cluster manager', { serverId: this.serverId });
    this.isShuttingDown = true;

    // Remove from cluster BEFORE clearing intervals
    try {
      await withRedisClient(async (client) => {
        const pipeline = client.pipeline();
        pipeline.hdel(CLUSTER_KEYS.SERVERS, this.serverId);
        pipeline.hdel(CLUSTER_KEYS.HEALTH, this.serverId);
        pipeline.hdel(CLUSTER_KEYS.KEYS, this.serverId);
        pipeline.hdel(CLUSTER_KEYS.TOKENS, this.serverId);

        // If this is the primary server, remove master key so another server can become primary
        if (this.isPrimary) {
          cryptoLogger.info('[CLUSTER] Removing master key - allowing new primary election', { serverId: this.serverId });
          pipeline.del(CLUSTER_KEYS.MASTER);
        }

        await pipeline.exec();

        // Notify cluster
        await client.publish(CLUSTER_KEYS.MESSAGES, JSON.stringify({
          type: 'server-shutdown',
          serverId: this.serverId,
          isPrimary: this.isPrimary,
          timestamp: Date.now(),
        }));
      });
    } catch (error) {
      // Ignore pool draining errors during shutdown (expected)
      if (!error?.message?.includes('pool is draining') && !error?.message?.includes('cannot accept work')) {
        cryptoLogger.error('[CLUSTER] Error during shutdown cleanup', error);
      }
    }

    // Clear intervals AFTER Redis cleanup
    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    if (this.healthCheckInterval) clearInterval(this.healthCheckInterval);
    if (this.keyRotationInterval) clearInterval(this.keyRotationInterval);

    // Unsubscribe from messages
    if (this.messageSubscriber) {
      try {
        await this.messageSubscriber.unsubscribe();
        await this.messageSubscriber.quit();
      } catch (error) {
        if (!error?.message?.includes('pool is draining') && !error?.message?.includes('Connection is closed')) {
          cryptoLogger.error('[CLUSTER] Error closing message subscriber', error);
        }
      }
    }

    cryptoLogger.info('[CLUSTER] Cluster manager shutdown complete');
    this.emit('shutdown');
  }
}