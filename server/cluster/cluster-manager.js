/**
 * Server Cluster Manager
 */

import crypto from 'crypto';
import { EventEmitter } from 'events';
import { withRedisClient, createSubscriber } from '../session/redis-client.js';
import { REDIS_KEYS } from '../config/redis-keys.js';
import {
  CLUSTER_APPROVED_EVENT,
  CLUSTER_JOIN_REQUEST_EVENT,
  CLUSTER_KEYS_ROTATED_EVENT,
  CLUSTER_PROMOTED_EVENT
} from './protocol.js';
import { SHA_256_ALGORITHM } from '../utils/crypto-consts.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  X25519_KEY_BYTES,
} from '../../shared/crypto-sizes.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import {
  CLUSTER_MESSAGE_REPLAY_TTL_MS,
  CLUSTER_SERVER_ID_RE,
  createSignedClusterMessage,
  inspectSignedClusterMessage,
  verifyInspectedClusterMessage,
  wipeInspectedClusterMessage,
} from './signed-message.js';
import {
  isValidAdvertisedHost,
  isValidAdvertisedPort,
  isValidClusterPublicKeys,
  isValidClusterServerRecord,
} from './server-record.js';

import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

// Redis keys for cluster coordination
const CLUSTER_KEYS = {
  SERVERS: REDIS_KEYS.CLUSTER_SERVERS,                  // Hash of active servers
  PENDING: REDIS_KEYS.CLUSTER_PENDING,           // Set of servers awaiting approval
  KEYS: REDIS_KEYS.CLUSTER_KEYS,                 // Hash of server public keys
  HEALTH: REDIS_KEYS.CLUSTER_HEALTH,             // Hash of server health status
  MASTER: REDIS_KEYS.CLUSTER_MASTER,                    // Current master server ID
  TOKENS: REDIS_KEYS.CLUSTER_TOKENS,             // Hash of cluster authentication tokens
  MESSAGES: REDIS_KEYS.CLUSTER_MESSAGES,         // Pub/sub channel for inter-server messages
  SHARED_CONFIG: REDIS_KEYS.CLUSTER_CONFIG,      // Shared configuration
};

// Configuration
const CONFIG = {
  HEARTBEAT_INTERVAL: 5000,                      // 5 seconds
  HEALTH_CHECK_INTERVAL: 10000,                  // 10 seconds
  SERVER_TIMEOUT: 30000,                         // 30 seconds
  APPROVAL_TIMEOUT: 300000,                      // 5 minutes for admin approval
  MIN_SERVERS_FOR_CLUSTER: 1,                    // Minimum servers to form cluster
  MAX_SERVERS_IN_CLUSTER: 100,                   // Maximum cluster size
  KEY_ROTATION_INTERVAL: 86400000,               // 24 hours
};

function parseClusterRecord(raw) {
  try {
    const parsed = JSON.parse(typeof raw === 'string' ? raw : String(raw));
    if (!parsed || Object.getPrototypeOf(parsed) !== Object.prototype) return null;
    return parsed;
  } catch {
    return null;
  }
}

function exactByteLength(value, length) {
  return value instanceof Uint8Array && value.length === length;
}

function validPendingInfo(value, serverId) {
  return Boolean(
    hasExactPlainObjectKeys(value, [
      'clusterPublicKey', 'host', 'port', 'publicKeys', 'requestedAt', 'serverId'
    ]) &&
    value.serverId === serverId &&
    Number.isSafeInteger(value.requestedAt) &&
    value.requestedAt >= Date.now() - CONFIG.APPROVAL_TIMEOUT &&
    value.requestedAt <= Date.now() + 30_000 &&
    canonicalBase64Shape(value.clusterPublicKey, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES }) &&
    isValidClusterPublicKeys(value.publicKeys) &&
    isValidAdvertisedHost(value.host) &&
    isValidAdvertisedPort(value.port)
  );
}

function validClusterKeyRecord(value, serverId) {
  return Boolean(
    hasExactPlainObjectKeys(value, ['clusterPublicKey', 'publicKeys', 'serverId']) &&
    value.serverId === serverId &&
    canonicalBase64Shape(value.clusterPublicKey, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES }) &&
    isValidClusterPublicKeys(value.publicKeys)
  );
}

export class ClusterManager extends EventEmitter {
  constructor({ serverId, serverKeys, isPrimary = false, autoApprove = false }) {
    super();

    if (typeof serverId !== 'string' || !CLUSTER_SERVER_ID_RE.test(serverId)) {
      throw new Error('serverId is required and must be a string');
    }

    if (
      !exactByteLength(serverKeys?.kyber?.publicKey, ML_KEM_1024_PUBLIC_KEY_BYTES) ||
      !exactByteLength(serverKeys?.dilithium?.publicKey, ML_DSA_87_PUBLIC_KEY_BYTES) ||
      !exactByteLength(serverKeys?.x25519?.publicKey, X25519_KEY_BYTES)
    ) {
      throw new Error('serverKeys must contain kyber, dilithium, and x25519 public keys');
    }

    this.serverId = serverId;
    this.serverKeys = serverKeys;
    this.isPrimary = isPrimary;
    this.autoApprove = autoApprove;
    this.isApproved = isPrimary;
    this.isShuttingDown = false;
    this.lastHeartbeatAt = null;

    // Cluster state
    this.clusterServers = new Map(); // serverId -> serverInfo
    this.serverHealth = new Map();   // serverId -> health data

    // Authentication tokens for interserver communication
    this.clusterToken = null;
    this.clusterSigningKey = null;
    this.clusterPublicKey = null;

    // Intervals
    this.heartbeatInterval = null;
    this.healthCheckInterval = null;
    this.keyRotationInterval = null;
    this.heartbeatTask = null;
    this.healthCheckTask = null;
    this.keyRotationTask = null;
    this.keyRotationBarrier = null;
    this.clusterPublishTasks = new Set();
    this.shutdownPromise = null;

    // Redis subscriber for cluster messages
    this.messageSubscriber = null;

    console.log('[CLUSTER] Cluster manager initialized', {
      serverId: this.serverId,
      isPrimary: this.isPrimary,
      autoApprove: this.autoApprove
    });
  }

  // Initialize cluster manager and join cluster
  async initialize() {
    try {
      await this.generateClusterKeys();
      await this.cleanupStaleServers();
      await this.setupMessageSubscriber();

      if (this.isPrimary) {
        await this.initializePrimaryServer();
      } else {
        await this.requestClusterJoin();
      }
      if (this.isApproved) this.lastHeartbeatAt = Date.now();

      this.startHeartbeat();
      this.startHealthMonitoring();
      this.startKeyRotation();

      console.log('[CLUSTER] Cluster manager started', {
        serverId: this.serverId,
        isApproved: this.isApproved
      });

      this.emit('initialized');
    } catch (error) {
      console.error('[CLUSTER] Failed to initialize cluster manager', error);
      throw error;
    }
  }

  // Generate keys for cluster authentication
  async generateClusterKeys() {
    try {
      const keyPair = ml_dsa87.keygen();
      this.clusterSigningKey?.fill?.(0);
      this.clusterSigningKey = keyPair.secretKey;
      this.clusterPublicKey = keyPair.publicKey;

      // Generate secure random token for this server
      this.clusterToken = crypto.randomBytes(64).toString('base64url');

      console.log('[CLUSTER] Generated cluster authentication keys', {
        serverId: this.serverId
      });
    } catch (error) {
      console.error('[CLUSTER] Failed to generate cluster keys', error);
      throw error;
    }
  }

  async publishClusterMessage(client, type, fields = {}) {
    if (this.keyRotationBarrier) await this.keyRotationBarrier;
    const payload = {
      version: 1,
      type,
      messageId: crypto.randomUUID(),
      issuedAt: Date.now(),
      senderId: this.serverId,
      ...fields,
    };
    const task = (async () => {
      const signedMessage = createSignedClusterMessage(this.clusterSigningKey, payload);
      await client.publish(CLUSTER_KEYS.MESSAGES, signedMessage);
    })();
    this.clusterPublishTasks.add(task);
    try {
      await task;
    } finally {
      this.clusterPublishTasks.delete(task);
    }
  }

  async authenticateClusterMessage(raw) {
    const inspected = inspectSignedClusterMessage(raw);
    if (!inspected) return null;

    let publicKey = null;
    try {
      const accepted = await withRedisClient(async (client) => {
        const { payload } = inspected;
        let keyData;
        if (payload.type === CLUSTER_JOIN_REQUEST_EVENT) {
          const pendingRaw = await client.hget(CLUSTER_KEYS.PENDING, payload.senderId);
          const pending = parseClusterRecord(pendingRaw);
          if (!validPendingInfo(pending, payload.senderId)) return false;
          keyData = pending;
        } else {
          const registeredRaw = await client.hget(CLUSTER_KEYS.KEYS, payload.senderId);
          const registered = parseClusterRecord(registeredRaw);
          if (!validClusterKeyRecord(registered, payload.senderId)) return false;
          keyData = registered;
        }

        if (!canonicalBase64Shape(keyData?.clusterPublicKey, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES })) {
          return false;
        }
        publicKey = Buffer.from(keyData.clusterPublicKey, 'base64');
        if (!verifyInspectedClusterMessage(inspected, publicKey)) return false;

        const claimed = await client.set(
          `${REDIS_KEYS.CLUSTER_MESSAGE_REPLAY_PREFIX}${payload.messageId}`,
          '1',
          'PX',
          CLUSTER_MESSAGE_REPLAY_TTL_MS,
          'NX'
        );
        return claimed === 'OK';
      });
      return accepted ? inspected.payload : null;
    } finally {
      publicKey?.fill?.(0);
      wipeInspectedClusterMessage(inspected);
    }
  }

  async isPrimaryControlMessage(message) {
    return await withRedisClient(async (client) => {
      const master = await client.get(CLUSTER_KEYS.MASTER);
      return master === message.senderId;
    });
  }

  // Get host to advertise to cluster
  #getAdvertisedHost() {
    const host = process.env.SERVER_HOST;
    if (!isValidAdvertisedHost(host)) throw new Error('SERVER_HOST contains an invalid cluster host');
    return host;
  }

  // Get port to advertise to cluster
  #getAdvertisedPort() {
    const port = Number(process.env.PORT);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
      throw new Error('PORT contains an invalid cluster port');
    }
    return port;
  }

  // Initialize as primary master server
  async initializePrimaryServer() {
    let masterClaimed = false;
    let registrationCommitted = false;
    try {
      await withRedisClient(async (client) => {
        masterClaimed = await client.set(CLUSTER_KEYS.MASTER, this.serverId, 'NX') === 'OK';
        if (!masterClaimed) {
          throw new Error('A primary server is already registered');
        }
        const pipeline = client.pipeline();

        // Register server info
        const serverInfo = {
          serverId: this.serverId,
          isPrimary: true,
          joinedAt: Date.now(),
          lastHeartbeat: Date.now(),
          status: 'active',
          publicKeys: this.exportPublicKeys(),
          host: this.#getAdvertisedHost(),
          port: this.#getAdvertisedPort(),
        };
        pipeline.hset(CLUSTER_KEYS.SERVERS, this.serverId, JSON.stringify(serverInfo));

        // Register public keys
        pipeline.hset(CLUSTER_KEYS.KEYS, this.serverId, JSON.stringify({
          serverId: this.serverId,
          clusterPublicKey: Buffer.from(this.clusterPublicKey).toString('base64'),
          publicKeys: this.exportPublicKeys(),
        }));

        const tokenHash = crypto.createHash(SHA_256_ALGORITHM).update(this.clusterToken).digest('hex');
        pipeline.hset(CLUSTER_KEYS.TOKENS, this.serverId, tokenHash);

        pipeline.hset(CLUSTER_KEYS.HEALTH, this.serverId, JSON.stringify({
          status: 'healthy',
          lastCheck: Date.now(),
          uptime: 0,
        }));

        const results = await pipeline.exec();
        if (results.some(([error]) => error)) throw new Error('Primary cluster registration failed');
        registrationCommitted = true;
      });

      console.log('[CLUSTER] Initialized as primary server', {
        serverId: this.serverId
      });

      this.emit('primary-initialized');
    } catch (error) {
      if (masterClaimed && !registrationCommitted) {
        try {
          await withRedisClient(async (client) => {
            await client.eval(
              "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
              1,
              CLUSTER_KEYS.MASTER,
              this.serverId
            );
          });
        } catch { }
      }
      console.error('[CLUSTER] Failed to initialize primary server', error);
      throw error;
    }
  }

  // Request to join cluster
  async requestClusterJoin() {
    try {
      await withRedisClient(async (client) => {
        const [existingServer, existingPending] = await Promise.all([
          client.hget(CLUSTER_KEYS.SERVERS, this.serverId),
          client.hget(CLUSTER_KEYS.PENDING, this.serverId),
        ]);
        if (existingServer || existingPending) {
          throw new Error('Cluster serverId is already registered or awaiting approval');
        }

        const pendingInfo = {
          serverId: this.serverId,
          requestedAt: Date.now(),
          publicKeys: this.exportPublicKeys(),
          clusterPublicKey: Buffer.from(this.clusterPublicKey).toString('base64'),
          host: this.#getAdvertisedHost(),
          port: this.#getAdvertisedPort(),
        };

        // Only the primary may convert this pending request into membership.
        await client.hset(CLUSTER_KEYS.PENDING, this.serverId, JSON.stringify(pendingInfo));
        await this.publishClusterMessage(client, CLUSTER_JOIN_REQUEST_EVENT);

        console.log('[CLUSTER] Sent cluster join request', {
          serverId: this.serverId
        });

        this.emit('join-requested');
      });

      // Wait for approval
      if (!this.isApproved) {
        await this.waitForApproval();
      }
    } catch (error) {
      console.error('[CLUSTER] Failed to request cluster join', error);
      throw error;
    }
  }

  // Wait for cluster join approval
  async waitForApproval() {
    const startTime = Date.now();

    while (!this.isApproved && Date.now() - startTime < CONFIG.APPROVAL_TIMEOUT) {
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const isApproved = await withRedisClient(async (client) => {
        const [serverInfo, keyData] = await Promise.all([
          client.hget(CLUSTER_KEYS.SERVERS, this.serverId),
          client.hget(CLUSTER_KEYS.KEYS, this.serverId),
        ]);
        const keys = parseClusterRecord(keyData);
        return Boolean(
          serverInfo &&
          validClusterKeyRecord(keys, this.serverId) &&
          keys.clusterPublicKey === Buffer.from(this.clusterPublicKey).toString('base64')
        );
      });

      if (isApproved) {
        this.isApproved = true;
        console.log('[CLUSTER] Server approved and joined cluster', {
          serverId: this.serverId
        });
        this.emit(CLUSTER_APPROVED_EVENT);
        return;
      }
    }

    if (!this.isApproved) {
      const error = new Error('Cluster join approval timeout - admin must approve this server');
      console.error('[CLUSTER] Join approval timeout', { serverId: this.serverId });
      throw error;
    }
  }

  // Approve a pending server (primary only)
  async approveServer(targetServerId) {
    if (!this.isPrimary) {
      throw new Error('Only primary server can approve new servers');
    }
    if (typeof targetServerId !== 'string' || !CLUSTER_SERVER_ID_RE.test(targetServerId)) {
      throw new Error('Invalid cluster serverId');
    }

    try {
      await withRedisClient(async (client) => {
        const pendingData = await client.hget(CLUSTER_KEYS.PENDING, targetServerId);
        if (!pendingData) {
          throw new Error(`Server ${targetServerId} not found in pending list`);
        }

        const pendingInfo = parseClusterRecord(pendingData);
        if (!validPendingInfo(pendingInfo, targetServerId)) {
          throw new Error(`Server ${targetServerId} has corrupted pending data`);
        }

        const now = Date.now();
        const serverInfo = {
          serverId: targetServerId,
          isPrimary: false,
          joinedAt: now,
          lastHeartbeat: now,
          approvedBy: this.serverId,
          status: 'active',
          publicKeys: pendingInfo.publicKeys,
          host: pendingInfo.host,
          port: pendingInfo.port,
        };
        const keyInfo = {
          serverId: targetServerId,
          clusterPublicKey: pendingInfo.clusterPublicKey,
          publicKeys: pendingInfo.publicKeys,
        };
        const healthInfo = {
          status: 'healthy',
          lastCheck: now,
          uptime: 0,
        };

        const committed = Number(await client.eval(
          `
            local pending = redis.call('HGET', KEYS[1], ARGV[1])
            if not pending then return 0 end
            if pending ~= ARGV[2] then return -1 end
            if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return -2 end
            if redis.call('HLEN', KEYS[2]) >= tonumber(ARGV[3]) then return -3 end
            redis.call('HDEL', KEYS[1], ARGV[1])
            redis.call('HSET', KEYS[2], ARGV[1], ARGV[4])
            redis.call('HSET', KEYS[3], ARGV[1], ARGV[5])
            redis.call('HSET', KEYS[4], ARGV[1], ARGV[6])
            return 1
          `,
          4,
          CLUSTER_KEYS.PENDING,
          CLUSTER_KEYS.SERVERS,
          CLUSTER_KEYS.KEYS,
          CLUSTER_KEYS.HEALTH,
          targetServerId,
          pendingData,
          CONFIG.MAX_SERVERS_IN_CLUSTER,
          JSON.stringify(serverInfo),
          JSON.stringify(keyInfo),
          JSON.stringify(healthInfo)
        ));
        if (committed === 0) throw new Error(`Server ${targetServerId} not found in pending list`);
        if (committed === -1) throw new Error(`Server ${targetServerId} pending request changed during approval`);
        if (committed === -2) throw new Error(`Server ${targetServerId} is already registered`);
        if (committed === -3) throw new Error('Maximum cluster size reached');
        if (committed !== 1) throw new Error('Cluster approval transaction failed');

        await this.publishClusterMessage(client, 'server-approved', {
          targetServerId,
        });
      });

      console.log('[CLUSTER] Approved server', {
        targetServerId,
        approvedBy: this.serverId
      });

      this.emit('server-approved', { serverId: targetServerId });
    } catch (error) {
      console.error('[CLUSTER] Failed to approve server', error);
      throw error;
    }
  }

  // Reject a pending server
  async rejectServer(targetServerId, reason = 'Rejected by admin') {
    if (!this.isPrimary) {
      throw new Error('Only primary server can reject servers');
    }
    if (typeof targetServerId !== 'string' || !CLUSTER_SERVER_ID_RE.test(targetServerId)) {
      throw new Error('Invalid cluster serverId');
    }

    try {
      await withRedisClient(async (client) => {
        await client.hdel(CLUSTER_KEYS.PENDING, targetServerId);

        await this.publishClusterMessage(client, 'server-rejected', {
          targetServerId,
          reason,
        });
      });

      console.log('[CLUSTER] Rejected server', {
        targetServerId,
        reason
      });

      this.emit('server-rejected', { serverId: targetServerId, reason });
    } catch (error) {
      console.error('[CLUSTER] Failed to reject server', error);
      throw error;
    }
  }

  // Get list of pending servers (primary only)
  async getPendingServers() {
    return await withRedisClient(async (client) => {
      const pending = await client.hgetall(CLUSTER_KEYS.PENDING);
      return Object.entries(pending)
        .map(([serverId, data]) => {
          const parsed = parseClusterRecord(data);
          if (!validPendingInfo(parsed, serverId)) return null;
          return { serverId, ...parsed };
        })
        .filter(Boolean);
    });
  }

  // Force remove a server from cluster (primary only)
  async forceRemoveServer(targetServerId) {
    if (!this.isPrimary) {
      throw new Error('Only primary server can force remove servers');
    }
    if (typeof targetServerId !== 'string' || !CLUSTER_SERVER_ID_RE.test(targetServerId)) {
      throw new Error('Invalid cluster serverId');
    }

    if (targetServerId === this.serverId) {
      throw new Error('Cannot remove self from cluster');
    }

    try {
      let serverInfo = null;

      await withRedisClient(async (client) => {
        const serverData = await client.hget(CLUSTER_KEYS.SERVERS, targetServerId);
        if (serverData) {
          const parsed = parseClusterRecord(serverData);
          serverInfo = isValidClusterServerRecord(parsed, targetServerId)
            ? parsed
            : { serverId: targetServerId };
        }

        const pendingData = await client.hget(CLUSTER_KEYS.PENDING, targetServerId);
        if (pendingData && !serverInfo) {
          const parsed = parseClusterRecord(pendingData);
          serverInfo = validPendingInfo(parsed, targetServerId)
            ? { ...parsed, status: 'pending' }
            : { serverId: targetServerId, status: 'pending' };
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
        await this.publishClusterMessage(client, 'server-force-removed', {
          targetServerId,
          reason: 'Admin force removal',
        });
      });

      this.clusterServers.delete(targetServerId);
      this.serverHealth.delete(targetServerId);

      console.log('[CLUSTER] Server force removed', {
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
      console.error('[CLUSTER] Failed to force remove server', error);
      throw error;
    }
  }

  // Start sending heartbeats
  startHeartbeat() {
    if (this.heartbeatInterval) return;
    this.heartbeatInterval = setInterval(() => {
      if (!this.isApproved || this.isShuttingDown || this.heartbeatTask) return;

      const task = this.sendHeartbeat()
        .catch((error) => {
          console.error('[CLUSTER] Heartbeat failed', error);
        })
        .finally(() => {
          if (this.heartbeatTask === task) this.heartbeatTask = null;
        });
      this.heartbeatTask = task;
    }, CONFIG.HEARTBEAT_INTERVAL);
  }

  // Update server port in Redis
  async updateServerPort(actualPort) {
    try {
      if (!Number.isSafeInteger(actualPort) || actualPort < 1 || actualPort > 65535) {
        throw new Error('Invalid bound server port');
      }
      await withRedisClient(async (client) => {
        const serverData = await client.hget(CLUSTER_KEYS.SERVERS, this.serverId);
        if (serverData) {
          const info = parseClusterRecord(serverData);
          if (!isValidClusterServerRecord(info, this.serverId)) {
            console.warn('[CLUSTER] Server entry is corrupted, cannot update port', { serverId: this.serverId });
            return;
          }
          const oldPort = info.port;
          info.port = actualPort;
          info.host = this.#getAdvertisedHost();
          const committed = await client.eval(
            "if redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then redis.call('HSET', KEYS[1], ARGV[1], ARGV[3]); return 1 else return 0 end",
            1,
            CLUSTER_KEYS.SERVERS,
            this.serverId,
            serverData,
            JSON.stringify(info)
          );
          if (committed !== 1) throw new Error('Cluster registration changed while updating its port');
          console.log('[CLUSTER] Updated server port in Redis', {
            serverId: this.serverId,
            oldPort,
            newPort: actualPort
          });
        }
      });
    } catch (error) {
      console.error('[CLUSTER] Failed to update server port', error);
    }
  }

  // Send heartbeat to cluster
  async sendHeartbeat() {
    let membershipLost = false;
    try {
      await withRedisClient(async (client) => {
        const serverInfo = await client.hget(CLUSTER_KEYS.SERVERS, this.serverId);
        if (!serverInfo) {
          console.warn('[CLUSTER] Server registration is missing', { serverId: this.serverId });
          membershipLost = true;
          return;
        }

        const info = parseClusterRecord(serverInfo);
        if (!isValidClusterServerRecord(info, this.serverId)) {
          console.warn('[CLUSTER] Server registration is corrupted', { serverId: this.serverId });
          membershipLost = true;
          return;
        }
        info.lastHeartbeat = Date.now();
        const updated = JSON.stringify(info);
        const committed = await client.eval(
          "if redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then redis.call('HSET', KEYS[1], ARGV[1], ARGV[3]); return 1 else return 0 end",
          1,
          CLUSTER_KEYS.SERVERS,
          this.serverId,
          serverInfo,
          updated
        );
        if (committed !== 1) {
          membershipLost = !this.isPrimary;
          if (this.isPrimary) throw new Error('Primary cluster registration changed during heartbeat');
          return;
        }
        this.lastHeartbeatAt = info.lastHeartbeat;
      });
      if (membershipLost) {
        this.isApproved = false;
        this.emit('self-membership-lost');
      }
    } catch (error) {
      console.error('[CLUSTER] Failed to send heartbeat', error);
      throw error;
    }
  }

  getTelemetrySnapshot() {
    return {
      serverId: this.serverId,
      registration: this.isApproved ? 'registered' : 'pending',
      heartbeatAgeSeconds: this.lastHeartbeatAt === null
        ? null
        : Math.max(0, Math.floor((Date.now() - this.lastHeartbeatAt) / 1000)),
    };
  }

  // Start health monitoring of cluster servers
  startHealthMonitoring() {
    if (this.healthCheckInterval) return;
    this.healthCheckInterval = setInterval(() => {
      if (!this.isApproved || this.isShuttingDown || this.healthCheckTask) return;

      const task = this.checkClusterHealth()
        .catch((error) => {
          console.error('[CLUSTER] Health check failed', error);
        })
        .finally(() => {
          if (this.healthCheckTask === task) this.healthCheckTask = null;
        });
      this.healthCheckTask = task;
    }, CONFIG.HEALTH_CHECK_INTERVAL);
  }

  // Check health of all cluster servers
  async checkClusterHealth() {
    try {
      await withRedisClient(async (client) => {
        const now = Date.now();
        let cursor = '0';
        const batchCount = 200;

        do {
          const [nextCursor, entries] = await client.hscan(CLUSTER_KEYS.SERVERS, cursor, 'COUNT', batchCount);
          cursor = nextCursor;
          if (entries && entries.length) {
            const pipe = client.pipeline();
            let hasCommands = false;

            for (let i = 0; i < entries.length; i += 2) {
              const serverId = entries[i];
              const data = entries[i + 1];
              const serverInfo = parseClusterRecord(data);

              if (!isValidClusterServerRecord(serverInfo, serverId, now)) {
                console.warn('[CLUSTER] Removing corrupted server entry during health check', { serverId });
                pipe.hdel(CLUSTER_KEYS.SERVERS, serverId);
                pipe.hdel(CLUSTER_KEYS.HEALTH, serverId);
                pipe.hdel(CLUSTER_KEYS.KEYS, serverId);
                pipe.hdel(CLUSTER_KEYS.TOKENS, serverId);
                await client.eval(
                  "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
                  1,
                  CLUSTER_KEYS.MASTER,
                  serverId
                );
                hasCommands = true;
                continue;
              }

              const timeSinceHeartbeat = now - serverInfo.lastHeartbeat;

              if (serverId !== this.serverId && timeSinceHeartbeat > CONFIG.SERVER_TIMEOUT) {
                await this.handleDeadServer(serverId, serverInfo, data);
              } else {
                this.clusterServers.set(serverId, serverInfo);

                const health = {
                  status: 'healthy',
                  lastCheck: now,
                  uptime: now - serverInfo.joinedAt,
                  lastHeartbeat: serverInfo.lastHeartbeat,
                };
                pipe.hset(CLUSTER_KEYS.HEALTH, serverId, JSON.stringify(health));
                hasCommands = true;
                this.serverHealth.set(serverId, health);
              }
            }

            if (hasCommands) {
              await pipe.exec();
            }
          }
        } while (cursor !== '0');
      });
    } catch (error) {
      console.error('[CLUSTER] Failed to check cluster health', error);
      throw error;
    }
  }

  // Clean up stale server entries on startup
  async cleanupStaleServers() {
    try {
      await withRedisClient(async (client) => {
        const now = Date.now();
        let cleanedCount = 0;
        let cursor = '0';
        const batchCount = 200;

        do {
          const [nextCursor, entries] = await client.hscan(CLUSTER_KEYS.SERVERS, cursor, 'COUNT', batchCount);
          cursor = nextCursor;
          if (entries && entries.length) {
            const pipeline = client.pipeline();
            let hasCommands = false;

            for (let i = 0; i < entries.length; i += 2) {
              const serverId = entries[i];
              const data = entries[i + 1];
              try {
                const serverInfo = parseClusterRecord(data);
                if (!isValidClusterServerRecord(serverInfo, serverId, now)) throw new Error('Invalid cluster server record');
                const timeSinceHeartbeat = now - serverInfo.lastHeartbeat;

                if (timeSinceHeartbeat > CONFIG.SERVER_TIMEOUT * 2) {
                  console.warn('[CLUSTER] Removing stale server entry', {
                    serverId,
                    timeSinceHeartbeat: Math.round(timeSinceHeartbeat / 1000) + 's',
                    lastHeartbeat: new Date(serverInfo.lastHeartbeat).toISOString()
                  });

                  pipeline.hdel(CLUSTER_KEYS.SERVERS, serverId);
                  pipeline.hdel(CLUSTER_KEYS.HEALTH, serverId);
                  pipeline.hdel(CLUSTER_KEYS.KEYS, serverId);
                  pipeline.hdel(CLUSTER_KEYS.TOKENS, serverId);

                  if (serverInfo.isPrimary) {
                    const currentMaster = await client.get(CLUSTER_KEYS.MASTER);
                    if (currentMaster === serverId) {
                      console.warn('[CLUSTER] Removing stale primary server master key', { serverId });
                      await client.eval(
                        "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
                        1,
                        CLUSTER_KEYS.MASTER,
                        serverId
                      );
                    }
                  }

                  hasCommands = true;
                  cleanedCount++;
                }
              } catch (_parseError) {
                console.warn('[CLUSTER] Removing corrupted server entry', { serverId });
                pipeline.hdel(CLUSTER_KEYS.SERVERS, serverId);
                pipeline.hdel(CLUSTER_KEYS.HEALTH, serverId);
                pipeline.hdel(CLUSTER_KEYS.KEYS, serverId);
                pipeline.hdel(CLUSTER_KEYS.TOKENS, serverId);
                await client.eval(
                  "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
                  1,
                  CLUSTER_KEYS.MASTER,
                  serverId
                );
                hasCommands = true;
                cleanedCount++;
              }
            }

            if (hasCommands) {
              await pipeline.exec();
            }
          }
        } while (cursor !== '0');

        if (cleanedCount > 0) {
          console.log('[CLUSTER] Stale server cleanup completed', {
            cleanedCount,
            message: 'Removed ghost servers from previous crashes'
          });
        }
      });
    } catch (error) {
      console.error('[CLUSTER] Failed to clean up stale servers', error);
    }
  }

  // Handle a dead/unresponsive server
  async handleDeadServer(serverId, serverInfo, expectedServerRecord) {
    try {
      console.warn('[CLUSTER] Detected dead server', { serverId });

      const removed = await withRedisClient(async (client) => {
        const staleBefore = Date.now() - CONFIG.SERVER_TIMEOUT;
        const result = await client.eval(
          "local current = redis.call('HGET', KEYS[1], ARGV[1]); if current ~= ARGV[2] then return 0 end; local ok, record = pcall(cjson.decode, current); if not ok or type(record) ~= 'table' or type(record.lastHeartbeat) ~= 'number' then return -1 end; if record.lastHeartbeat > tonumber(ARGV[3]) then return 0 end; redis.call('HDEL', KEYS[1], ARGV[1]); redis.call('HDEL', KEYS[2], ARGV[1]); redis.call('HDEL', KEYS[3], ARGV[1]); redis.call('HDEL', KEYS[4], ARGV[1]); return 1",
          4,
          CLUSTER_KEYS.SERVERS,
          CLUSTER_KEYS.HEALTH,
          CLUSTER_KEYS.KEYS,
          CLUSTER_KEYS.TOKENS,
          serverId,
          expectedServerRecord,
          staleBefore
        );
        if (result === -1) {
          throw new Error('Cluster server record became invalid during dead-server removal');
        }
        if (result !== 1) return false;

        await this.publishClusterMessage(client, 'server-dead', {
          targetServerId: serverId,
        });
        return true;
      });
      if (!removed) return;

      this.clusterServers.delete(serverId);
      this.serverHealth.delete(serverId);

      this.emit('server-dead', { serverId, serverInfo });

      if (serverInfo.isPrimary) {
        await this.handlePrimaryFailure(serverId);
      }
    } catch (error) {
      console.error('[CLUSTER] Failed to handle dead server', error);
    }
  }

  /**
   * Handle primary server failure
   * Queue-based primary selection
   */
  async handlePrimaryFailure(failedPrimaryId) {
    console.warn('[CLUSTER] Primary server failed, initiating queue-based election');

    try {
      await withRedisClient(async (client) => {
        const servers = await client.hgetall(CLUSTER_KEYS.SERVERS);
        if (Object.keys(servers).length === 0) {
          console.error('[CLUSTER] No servers available after primary failure');
          return;
        }

        let oldestServer = null;
        let oldestTime = Date.now();

        // Find the oldest server (earliest joinedAt timestamp) = next in queue
        for (const [serverId, data] of Object.entries(servers)) {
          const info = parseClusterRecord(data);
          if (!isValidClusterServerRecord(info, serverId)) continue;
          if (info.joinedAt < oldestTime) {
            oldestTime = info.joinedAt;
            oldestServer = { serverId, info };
          }
        }

        if (oldestServer) {
          // Promote to primary only if no other server won the election first.
          oldestServer.info.isPrimary = true;
          const promoted = await client.eval(
            "local current = redis.call('GET', KEYS[1]); if (not current) or current == ARGV[1] then redis.call('HSET', KEYS[2], ARGV[2], ARGV[3]); redis.call('SET', KEYS[1], ARGV[2]); return 1 else return 0 end",
            2,
            CLUSTER_KEYS.MASTER,
            CLUSTER_KEYS.SERVERS,
            failedPrimaryId,
            oldestServer.serverId,
            JSON.stringify(oldestServer.info)
          );
          if (promoted !== 1) {
            console.log('[CLUSTER] Primary election already completed by another server');
            return;
          }

          console.log('[CLUSTER] Queue-based election completed', {
            newPrimary: oldestServer.serverId,
            joinedAt: new Date(oldestServer.info.joinedAt).toISOString(),
            message: 'Next server in queue promoted to primary'
          });

          await this.publishClusterMessage(client, 'primary-elected', {
            targetServerId: oldestServer.serverId,
          });

          if (oldestServer.serverId === this.serverId) {
            this.isPrimary = true;
            console.log('[CLUSTER] This server promoted to primary (next in queue)');
            this.emit(CLUSTER_PROMOTED_EVENT);
          }
        }
      });
    } catch (error) {
      console.error('[CLUSTER] Failed to handle primary failure', error);
    }
  }

  // Set up message subscriber for inter-server communication
  async setupMessageSubscriber() {
    try {
      this.messageSubscriber = await createSubscriber();
      await this.messageSubscriber.subscribe(CLUSTER_KEYS.MESSAGES);

      this.messageSubscriber.on('message', async (channel, message) => {
        try {
          if (channel !== CLUSTER_KEYS.MESSAGES) return;
          const msg = await this.authenticateClusterMessage(message);
          if (!msg) return;
          await this.handleClusterMessage(msg);
        } catch (error) {
          console.error('[CLUSTER] Failed to handle authenticated cluster message', error);
        }
      });

      console.log('[CLUSTER] Message subscriber initialized');
    } catch (error) {
      console.error('[CLUSTER] Failed to setup message subscriber', error);
      throw error;
    }
  }

  // Handle cluster messages
  async handleClusterMessage(msg) {
    if (msg.senderId === this.serverId) return;

    switch (msg.type) {
      case CLUSTER_JOIN_REQUEST_EVENT:
        if (this.isPrimary) {
          const pending = await withRedisClient(async (client) => {
            return parseClusterRecord(await client.hget(CLUSTER_KEYS.PENDING, msg.senderId));
          });
          if (!pending || pending.serverId !== msg.senderId) return;
          console.log('[CLUSTER] Received authenticated join request', { serverId: msg.senderId });
          this.emit(CLUSTER_JOIN_REQUEST_EVENT, pending);
        }
        break;

      case 'server-approved':
        if (!await this.isPrimaryControlMessage(msg)) return;
        if (msg.targetServerId === this.serverId) {
          this.isApproved = true;
          this.emit(CLUSTER_APPROVED_EVENT);
        }
        this.emit('server-joined', { serverId: msg.targetServerId });
        break;

      case 'server-rejected':
        if (!await this.isPrimaryControlMessage(msg)) return;
        if (msg.targetServerId === this.serverId) {
          console.error('[CLUSTER] Server join rejected', { reason: msg.reason });
          this.emit('rejected', { reason: msg.reason });
          await this.shutdown();
          process.exit(1);
        }
        break;

      case 'server-force-removed':
        if (!await this.isPrimaryControlMessage(msg)) return;
        if (msg.targetServerId === this.serverId) {
          this.isApproved = false;
          await this.shutdown();
          this.emit('server-removed', { serverId: this.serverId, forced: true });
          this.emit('self-force-removed');
        } else {
          this.clusterServers.delete(msg.targetServerId);
          this.serverHealth.delete(msg.targetServerId);
          this.emit('server-removed', { serverId: msg.targetServerId, forced: true });
        }
        break;

      case 'server-dead':
        {
          const removalCommitted = await withRedisClient(async (client) => (
            await client.hget(CLUSTER_KEYS.SERVERS, msg.targetServerId)
          )) === null;
          if (!removalCommitted) return;
        }
        console.warn('[CLUSTER] Server marked as dead', { serverId: msg.targetServerId });
        this.clusterServers.delete(msg.targetServerId);
        this.serverHealth.delete(msg.targetServerId);
        this.emit('server-removed', { serverId: msg.targetServerId });
        break;

      case 'primary-elected':
        {
          const electionCommitted = await withRedisClient(async (client) => {
            const [master, serverRaw] = await Promise.all([
              client.get(CLUSTER_KEYS.MASTER),
              client.hget(CLUSTER_KEYS.SERVERS, msg.targetServerId),
            ]);
            const server = parseClusterRecord(serverRaw);
            return master === msg.targetServerId && server?.isPrimary === true;
          });
          if (!electionCommitted) return;
        }
        console.log('[CLUSTER] New primary elected', { serverId: msg.targetServerId });
        if (msg.targetServerId === this.serverId) {
          this.isPrimary = true;
          this.emit(CLUSTER_PROMOTED_EVENT);
        }
        break;

      default:
        break;
    }
  }

  // Start key rotation
  startKeyRotation() {
    if (this.keyRotationInterval) return;
    this.keyRotationInterval = setInterval(() => {
      if (!this.isApproved || this.isShuttingDown || this.keyRotationTask) return;

      const task = this.rotateKeys()
        .catch((error) => {
          console.error('[CLUSTER] Key rotation failed', error);
        })
        .finally(() => {
          if (this.keyRotationTask === task) this.keyRotationTask = null;
        });
      this.keyRotationTask = task;
    }, CONFIG.KEY_ROTATION_INTERVAL);
  }

  // Rotate cluster authentication keys
  async rotateKeys() {
    if (this.keyRotationBarrier) {
      await this.keyRotationBarrier;
      return;
    }
    let releaseRotation;
    this.keyRotationBarrier = new Promise((resolve) => {
      releaseRotation = resolve;
    });
    let nextKeyPair = null;
    let nextToken = null;
    try {
      console.log('[CLUSTER] Starting key rotation', { serverId: this.serverId });
      await Promise.allSettled([...this.clusterPublishTasks]);
      nextKeyPair = ml_dsa87.keygen();
      nextToken = crypto.randomBytes(64).toString('base64url');

      await withRedisClient(async (client) => {
        const keysData = await client.hget(CLUSTER_KEYS.KEYS, this.serverId);
        const keys = parseClusterRecord(keysData);
        if (!validClusterKeyRecord(keys, this.serverId)) {
          throw new Error('Registered cluster key record is missing or invalid');
        }
        keys.clusterPublicKey = Buffer.from(nextKeyPair.publicKey).toString('base64');

        const tokenHash = crypto.createHash(SHA_256_ALGORITHM).update(nextToken).digest('hex');
        const pipeline = client.pipeline();
        pipeline.hset(CLUSTER_KEYS.KEYS, this.serverId, JSON.stringify(keys));
        pipeline.hset(CLUSTER_KEYS.TOKENS, this.serverId, tokenHash);
        const results = await pipeline.exec();
        if (results.some(([error]) => error)) throw new Error('Cluster key rotation persistence failed');
      });

      this.clusterSigningKey?.fill?.(0);
      this.clusterPublicKey?.fill?.(0);
      this.clusterSigningKey = nextKeyPair.secretKey;
      this.clusterPublicKey = nextKeyPair.publicKey;
      this.clusterToken = nextToken;
      nextKeyPair = null;
      nextToken = null;

      console.log('[CLUSTER] Key rotation completed', { serverId: this.serverId });
      this.emit(CLUSTER_KEYS_ROTATED_EVENT);
    } catch (error) {
      console.error('[CLUSTER] Failed to rotate keys', error);
      throw error;
    } finally {
      nextKeyPair?.secretKey?.fill?.(0);
      nextKeyPair?.publicKey?.fill?.(0);
      nextToken = null;
      this.keyRotationBarrier = null;
      releaseRotation();
    }
  }

  // Export public keys for distribution
  exportPublicKeys() {
    return {
      kyber: Buffer.from(this.serverKeys.kyber.publicKey).toString('base64'),
      dilithium: Buffer.from(this.serverKeys.dilithium.publicKey).toString('base64'),
      x25519: Buffer.from(this.serverKeys.x25519.publicKey).toString('base64'),
    };
  }

  // Get all server public keys from cluster
  async getAllServerKeys() {
    return await withRedisClient(async (client) => {
      const keysData = await client.hgetall(CLUSTER_KEYS.KEYS);
      const keys = {};

      for (const [serverId, data] of Object.entries(keysData)) {
        const parsed = parseClusterRecord(data);
        if (validClusterKeyRecord(parsed, serverId)) {
          keys[serverId] = parsed;
        }
      }

      return keys;
    });
  }

  // Get cluster status
  async getClusterStatus() {
    return await withRedisClient(async (client) => {
      const [servers, pending, health, master] = await Promise.all([
        client.hgetall(CLUSTER_KEYS.SERVERS),
        client.hgetall(CLUSTER_KEYS.PENDING),
        client.hgetall(CLUSTER_KEYS.HEALTH),
        client.get(CLUSTER_KEYS.MASTER),
      ]);

      const validServers = Object.entries(servers)
        .map(([id, data]) => {
          const info = parseClusterRecord(data);
          if (!isValidClusterServerRecord(info, id)) return null;
          const healthInfo = health[id] ? parseClusterRecord(health[id]) : null;
          return { ...info, serverId: id, health: healthInfo };
        })
        .filter(Boolean);
      const validPending = Object.entries(pending)
        .map(([id, data]) => {
          const info = parseClusterRecord(data);
          if (!validPendingInfo(info, id)) return null;
          return { ...info, serverId: id };
        })
        .filter(Boolean);

      return {
        master,
        serverCount: validServers.length,
        pendingCount: validPending.length,
        servers: validServers,
        pending: validPending,
      };
    });
  }

  // Get shared cluster configuration
  static async getSharedConfig(key) {
    return await withRedisClient(async (client) => {
      return await client.hget(CLUSTER_KEYS.SHARED_CONFIG, key);
    });
  }

  // Set shared cluster configuration (primary only)
  async setSharedConfig(key, value) {
    if (!this.isPrimary) {
      throw new Error('Only primary server can set shared configuration');
    }
    if (typeof key !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(key)) {
      throw new Error('Invalid shared cluster configuration key');
    }
    if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 65_536) {
      throw new Error('Invalid shared cluster configuration value');
    }

    return await withRedisClient(async (client) => {
      await client.hset(CLUSTER_KEYS.SHARED_CONFIG, key, value);
      console.log('[CLUSTER] Set shared configuration', { key });
    });
  }

  // Shutdown cluster manager
  shutdown() {
    if (this.shutdownPromise) return this.shutdownPromise;
    this.shutdownPromise = this.#performShutdown();
    return this.shutdownPromise;
  }

  async #performShutdown() {
    console.log('[CLUSTER] Shutting down cluster manager', { serverId: this.serverId });
    this.isShuttingDown = true;

    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    if (this.healthCheckInterval) clearInterval(this.healthCheckInterval);
    if (this.keyRotationInterval) clearInterval(this.keyRotationInterval);
    this.heartbeatInterval = null;
    this.healthCheckInterval = null;
    this.keyRotationInterval = null;

    await Promise.allSettled([
      this.heartbeatTask,
      this.healthCheckTask,
      this.keyRotationTask,
      ...this.clusterPublishTasks,
    ].filter(Boolean));
    this.heartbeatTask = null;
    this.healthCheckTask = null;
    this.keyRotationTask = null;

    try {
      await withRedisClient(async (client) => {
        const pipeline = client.pipeline();
        pipeline.hdel(CLUSTER_KEYS.SERVERS, this.serverId);
        pipeline.hdel(CLUSTER_KEYS.HEALTH, this.serverId);
        pipeline.hdel(CLUSTER_KEYS.KEYS, this.serverId);
        pipeline.hdel(CLUSTER_KEYS.TOKENS, this.serverId);

        if (this.isPrimary) {
          console.log('[CLUSTER] Removing master key', { serverId: this.serverId });
        }

        await pipeline.exec();

        if (this.isPrimary) {
          await client.eval(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
            1,
            CLUSTER_KEYS.MASTER,
            this.serverId
          );
        }

      });
    } catch (error) {
      if (!error?.message?.includes('pool is draining') && !error?.message?.includes('cannot accept work')) {
        console.error('[CLUSTER] Error during shutdown cleanup', error);
      }
    }

    if (this.messageSubscriber) {
      try {
        await this.messageSubscriber.unsubscribe();
        await this.messageSubscriber.quit();
      } catch (error) {
        if (!error?.message?.includes('pool is draining') && !error?.message?.includes('Connection is closed')) {
          console.error('[CLUSTER] Error closing message subscriber', error);
        }
      }
      this.messageSubscriber = null;
    }

    this.clusterSigningKey?.fill?.(0);
    this.clusterPublicKey?.fill?.(0);
    this.clusterSigningKey = null;
    this.clusterPublicKey = null;
    this.clusterToken = null;

    console.log('[CLUSTER] Cluster manager shutdown complete');
    this.emit('shutdown');
  }
}
