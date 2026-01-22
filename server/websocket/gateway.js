import { SignalType } from '../signals.js';
import { ConnectionStateManager } from '../presence/connection-state.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { processWebSocketMessage } from '../messaging/chunked-message-handler.js';
import { presenceService } from '../presence/presence-service.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { withRedisClient } from '../presence/presence.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import fs from 'fs';

// Attach WebSocket gateway
export function attachGateway({
  wss,
  serverHybridKeyPair,
  serverId = null,
  createSession = ConnectionStateManager.createSession,
  refreshSession = ConnectionStateManager.refreshSession,
  getSessionState = ConnectionStateManager.getState,
  rateLimiter = rateLimitMiddleware,
  logger = cryptoLogger,
  config,
  onMessage,
}) {
  if (!wss) {
    throw new Error('attachGateway requires a WebSocketServer instance');
  }
  if (!serverHybridKeyPair) {
    throw new Error('attachGateway requires serverHybridKeyPair');
  }

  const {
    bandwidthQuota = 5 * 1024 * 1024,
    bandwidthWindowMs = 60 * 1000,
    messageHardLimitPerMinute = 1000,
    heartbeatIntervalMs = 30000,
  } = config || {};

  const isTestEnv = false;

  const stats = {
    connectionsOpened: 0,
    connectionsClosed: 0,
    rateLimitExceeded: 0,
    totalMessages: 0,
    messagesPerSecond: 0,
  };
  let ttyStream = null;
  let lastProgressUpdate = 0;


  if (isTestEnv) {
    try {
      ttyStream = fs.createWriteStream('/dev/tty', { flags: 'w' });
    } catch (_e) {
    }
  }

  const updateProgress = () => {
    if (!isTestEnv || !ttyStream || stats.connectionsOpened === 0) return;
    const now = Date.now();
    if (now - lastProgressUpdate < 50 && stats.connectionsClosed < stats.connectionsOpened) return;
    lastProgressUpdate = now;

    const total = stats.connectionsOpened;
    const closed = stats.connectionsClosed;
    const percent = total > 0 ? Math.floor((closed / total) * 100) : 0;
    const barLength = 30;
    const filled = Math.floor((percent / 100) * barLength);
    const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);

    ttyStream.write(`\r[WS] ${bar} ${closed}/${total} | ${stats.rateLimitExceeded} rate-limited | ${stats.totalMessages} msgs`);

    if (closed === total) {
      ttyStream.write('\n');
    }
  };


  const localDeliveryMap = new Map(); // Per-server: username -> Set<ws objects>
  const REDIS_DELIVERY_KEY_PREFIX = 'ws:delivery:';
  const REDIS_CONNECTION_TTL = 3600;

  const SESSION_REFRESH_MIN_INTERVAL_MS = 60_000;
  const DELIVERY_STALE_THRESHOLD_MS = 5 * 60_000;

  const safeJsonParse = (raw) => {
    if (typeof raw !== 'string') return null;
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  };

  const maybeRefreshSession = (ws, reason) => {
    try {
      const sid = ws?._sessionId;
      if (!sid) return;
      const now = Date.now();
      const last = Number(ws._lastSessionRefreshAt || 0);
      if (now - last < SESSION_REFRESH_MIN_INTERVAL_MS) return;
      ws._lastSessionRefreshAt = now;

      void refreshSession(sid).catch((error) => {
        logger.warn('[WS] Session refresh failed', {
          reason,
          sessionId: sid?.slice(0, 8) + '...',
          error: error?.message || String(error)
        });
      });

      const username = ws?._username;
      const field = ws?._redisDeliveryField;
      if (!username || !field) return;

      void withRedisClient(async (client) => {
        const key = `${REDIS_DELIVERY_KEY_PREFIX}${username}`;
        const serverId = process.env.SERVER_ID || 'default';
        const connectedAt = Number(ws?._connectedAt || now) || now;
        const value = JSON.stringify({ serverId, sessionId: sid, connectedAt, lastSeen: now });
        await client.hset(key, field, value);
        await client.expire(key, REDIS_CONNECTION_TTL);
      }).catch((error) => {
        logger.warn('[WS] Failed to touch Redis delivery entry', {
          reason,
          username,
          error: error?.message || String(error)
        });
      });
    } catch {
    }
  };

  let cachedPublicKeyMessage = null;
  let cachedPublicKeyLogInfo = null;

  const getCachedPublicKeyMessage = () => {
    if (cachedPublicKeyMessage) {
      return { message: cachedPublicKeyMessage, logInfo: cachedPublicKeyLogInfo };
    }

    if (!serverHybridKeyPair ||
      !serverHybridKeyPair.kyber?.publicKey ||
      !serverHybridKeyPair.dilithium?.publicKey ||
      !serverHybridKeyPair.x25519?.publicKey) {
      throw new Error('Server hybrid key pair not properly initialized');
    }

    const dilithiumPublicBase64 = CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey);
    const kyberPublicBase64 = CryptoUtils.Hybrid.exportKyberPublicBase64(serverHybridKeyPair.kyber.publicKey);
    const x25519PublicBase64 = CryptoUtils.Hybrid.exportX25519PublicBase64(serverHybridKeyPair.x25519.publicKey);

    const keyMessage = JSON.stringify({
      type: SignalType.SERVER_PUBLIC_KEY,
      serverId: serverId || 'default',
      hybridKeys: {
        kyberPublicBase64,
        dilithiumPublicBase64,
        x25519PublicBase64
      }
    });

    cachedPublicKeyMessage = keyMessage;
    cachedPublicKeyLogInfo = {
      serverId: serverId || 'default',
      dilithiumPublicKeyLength: Buffer.from(dilithiumPublicBase64, 'base64').length,
      kyberPublicKeyLength: serverHybridKeyPair.kyber.publicKey.length,
      originalSize: keyMessage.length,
    };

    return { message: cachedPublicKeyMessage, logInfo: cachedPublicKeyLogInfo };
  };

  // Add local WebSocket connection to delivery map
  const addLocalConnection = async (username, ws) => {
    if (!username || !ws) return;

    let set = localDeliveryMap.get(username);
    if (!set) {
      set = new Set();
      localDeliveryMap.set(username, set);
    }
    set.add(ws);

    logger.debug('[WS] Added local connection', {
      username: username.slice(0, 4) + '...',
      sessionId: ws._sessionId?.slice(0, 8) + '...',
      totalConnections: set.size
    });

    // Register in Redis for distributed delivery
    if (ws._sessionId) {
      try {
        await withRedisClient(async (client) => {
          const key = `${REDIS_DELIVERY_KEY_PREFIX}${username}`;
          const serverId = process.env.SERVER_ID || 'default';
          const nowTimestamp = Date.now();
          const connectedAt = Number(ws?._connectedAt || nowTimestamp) || nowTimestamp;
          const field = `${serverId}:${ws._sessionId}`;
          const connectionData = JSON.stringify({
            serverId,
            sessionId: ws._sessionId,
            connectedAt,
            lastSeen: nowTimestamp
          });
          ws._redisDeliveryField = field;
          await client.hset(key, field, connectionData);
          await client.expire(key, REDIS_CONNECTION_TTL);
        });
      } catch (error) {
        logger.warn('[WS] Failed to register connection in Redis', { username, error: error.message });
      }
    }
  };

  // Remove local WebSocket connection from delivery map
  const removeLocalConnection = async (username, ws) => {
    if (!username || !ws) return;

    const set = localDeliveryMap.get(username);
    if (set) {
      set.delete(ws);
      if (set.size === 0) localDeliveryMap.delete(username);

      logger.debug('[WS] Removed local connection', {
        username: username.slice(0, 4) + '...',
        sessionId: ws._sessionId?.slice(0, 8) + '...',
        remainingConnections: set.size
      });
    }

    // Remove from Redis registry
    if (ws._sessionId) {
      try {
        await withRedisClient(async (client) => {
          const key = `${REDIS_DELIVERY_KEY_PREFIX}${username}`;
          const serverId = process.env.SERVER_ID || 'default';
          const field = ws._redisDeliveryField || `${serverId}:${ws._sessionId}`;
          await client.hdel(key, field);
        });
      } catch (error) {
        logger.warn('[WS] Failed to remove connection from Redis', { username, error: error.message });
      }
    }
  };

  // Get local WebSocket connections for a username
  const getLocalConnections = (username) => {
    if (!username) return null;
    const set = localDeliveryMap.get(username);
    return set ? new Set(set) : null;
  };

  // Get all server instances that have connections for a username
  const getDistributedConnectionServers = async (username) => {
    if (!username) return [];

    try {
      return await withRedisClient(async (client) => {
        const key = `${REDIS_DELIVERY_KEY_PREFIX}${username}`;
        const values = await client.hvals(key);
        const out = [];
        for (const raw of values || []) {
          const parsed = safeJsonParse(raw);
          if (parsed) out.push(parsed);
        }
        return out;
      });
    } catch (error) {
      logger.warn('[WS] Failed to get distributed connections from Redis', { username, error: error.message });
      return [];
    }
  };

  // Handle incoming WebSocket message
  const handleMessage = async ({ ws, sessionId, message, parsed }) => {
    if (typeof onMessage === 'function') {
      try {
        await onMessage({ ws, sessionId, message, parsed });
      } catch (error) {
        logger.error('[WS] Message handler error', {
          sessionId: sessionId?.slice(0, 8) + '...',
          error: error.message
        });
        throw error;
      }
    }
    return { handled: true };
  };

  const heartbeatInterval = setInterval(() => {
    for (const ws of wss.clients) {
      try {
        if (ws?._isP2PSignaling) {
          continue;
        }
        if (ws.isAlive === false) {
          try { ws.terminate?.(); } catch { }
          continue;
        }
        ws.isAlive = false;
        try {
          ws.ping(() => { });
        } catch { }
        maybeRefreshSession(ws, 'heartbeat');
      } catch (error) {
        logger.error('[WS] Error during heartbeat:', error);
      }
    }
  }, heartbeatIntervalMs);

  let staleCleanupCursor = '0';
  const staleFieldCleanupCursors = new Map();
  const STALE_FIELD_SCAN_PAGES_PER_KEY = 5;
  const staleConnectionCleanupInterval = setInterval(async () => {
    try {
      await withRedisClient(async (client) => {
        const nowTimestamp = Date.now();
        const [newCursor, keys] = await client.scan(
          staleCleanupCursor,
          'MATCH',
          `${REDIS_DELIVERY_KEY_PREFIX}*`,
          'COUNT',
          50
        );
        staleCleanupCursor = newCursor;

        let totalCleaned = 0;

        for (const key of keys) {
          try {
            let fieldCursor = staleFieldCleanupCursors.get(key) || '0';
            let pages = 0;
            let keyFinished = false;

            do {
              const [nextFieldCursor, entries] = await client.hscan(key, fieldCursor, 'COUNT', 200);
              fieldCursor = nextFieldCursor;
              pages += 1;

              const toDelete = [];
              for (let i = 0; i < (entries?.length || 0); i += 2) {
                const field = entries[i];
                const raw = entries[i + 1];
                const parsed = safeJsonParse(raw);
                const lastSeen = Number(parsed?.lastSeen || parsed?.connectedAt || 0);
                if (!parsed || !lastSeen || (nowTimestamp - lastSeen) > DELIVERY_STALE_THRESHOLD_MS) {
                  toDelete.push(field);
                }
              }

              if (toDelete.length > 0) {
                await client.hdel(key, ...toDelete);
                totalCleaned += toDelete.length;
              }

              if (fieldCursor === '0') {
                keyFinished = true;
                break;
              }
            } while (pages < STALE_FIELD_SCAN_PAGES_PER_KEY);

            if (keyFinished) {
              staleFieldCleanupCursors.delete(key);
              const remaining = await client.hlen(key);
              if (remaining === 0) {
                await client.del(key);
              }
            } else {
              staleFieldCleanupCursors.set(key, fieldCursor);
            }
          } catch (err) {
            logger.warn('[WS] Error cleaning up delivery key', { key, error: err.message });
          }
        }

        if (totalCleaned > 0) {
          logger.info('[WS] Cleaned up stale connections across cluster', {
            totalCleaned,
            keysScanned: keys.length,
          });
        }
      });
    } catch (error) {
      logger.warn('[WS] Error during stale connection cleanup', { error: error.message });
    }
  }, 60_000);

  wss.on('connection', async (ws, req) => {
    const isP2PSignaling = req?.url?.startsWith('/p2p-signaling');
    if (isP2PSignaling) {
      ws._isP2PSignaling = true;
      return;
    }

    try {
      ws.upgradeReq = req;
      ws.headers = req?.headers || {};
      const hdrId = ws.headers['x-device-id'];
      if (hdrId && typeof hdrId === 'string') {
        ws.deviceId = hdrId.trim().slice(0, 64);
      }
    } catch (_) { }

    try {
      const allowed = await rateLimiter.checkConnectionLimit(ws);
      if (!allowed) {
        logger.warn('[WS] Connection rejected due to rate limiting');
        ws.close(1008, 'Rate limit exceeded');
        return;
      }
    } catch (error) {
      logger.error('[WS] Rate limiting error during connection:', error);
      ws.close(1011, 'Rate limiting error');
      return;
    }

    let sessionId;
    let messageCount = 0;
    let bandwidthUsed = 0;
    const connectionOpenedAt = Date.now();

    try {
      sessionId = await createSession();
      ws._sessionId = sessionId;
      ws._connectedAt = connectionOpenedAt;
      stats.connectionsOpened++;
      if (!isTestEnv) {
        logger.info('[WS] Created session', { sessionId: sessionId?.slice(0, 8) + '...' });
      }
    } catch (error) {
      logger.error('[WS] Failed to create session', { error: error.message });
      ws.close(1011, 'Internal server error');
      return;
    }

    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('ping', () => {
      ws.isAlive = true;
      try {
        ws.pong();
      } catch (error) {
        logger.warn('[WS] Pong failed', { error: error.message });
      }
    });

    ws._username = null;

    try {
      const { message, logInfo } = getCachedPublicKeyMessage();

      if (ws.readyState !== 1) {
        logger.warn('[WS] Connection closed before key exchange', {
          sessionId: sessionId?.slice(0, 8) + '...',
          readyState: ws.readyState
        });
        return;
      }

      logger.info('[WS] Sending server public keys', {
        sessionId: sessionId?.slice(0, 8) + '...',
        ...logInfo,
        readyState: ws.readyState,
        bufferedAmount: ws.bufferedAmount
      });

      ws.send(message, (error) => {
        if (error) {
          logger.error('[WS] Failed to send server public keys', {
            sessionId: sessionId?.slice(0, 8) + '...',
            error: error.message,
            readyState: ws.readyState
          });
        }
      });
    } catch (error) {
      logger.error('[WS] Failed to send server public keys', {
        sessionId: sessionId?.slice(0, 8) + '...',
        error: error.message,
        stack: error.stack
      });
      ws.close(1011, 'Key exchange failed');
      return;
    }


    ws.on('message', async (messageBuffer) => {
      const now = Date.now();
      if (!ws._bandwidthWindowStart) {
        ws._bandwidthWindowStart = connectionOpenedAt;
      }
      if (!ws._messageWindowStart) {
        ws._messageWindowStart = connectionOpenedAt;
      }

      if (now - ws._bandwidthWindowStart > bandwidthWindowMs) {
        ws._bandwidthWindowStart = now;
        bandwidthUsed = 0;
      }

      if (now - ws._messageWindowStart > 60_000) {
        ws._messageWindowStart = now;
        messageCount = 0;
      }

      if (bandwidthUsed + messageBuffer.length > bandwidthQuota) {
        logger.warn('[WS] Bandwidth quota exceeded', {
          sessionId: sessionId?.slice(0, 8) + '...',
          bytes: bandwidthUsed + messageBuffer.length,
          quota: bandwidthQuota
        });
        try {
          await sendSecureMessage(ws, {
            type: SignalType.ERROR,
            error: 'Bandwidth quota exceeded',
            code: 'BANDWIDTH_QUOTA_EXCEEDED',
            quota: bandwidthQuota,
            used: bandwidthUsed,
          });
        } catch { }
        ws.close(1008, 'Bandwidth quota exceeded');
        return;
      }

      bandwidthUsed += messageBuffer.length;

      if (messageCount >= messageHardLimitPerMinute) {
        const state = await getSessionState(sessionId);
        stats.rateLimitExceeded++;
        if (isTestEnv) {
          updateProgress();
        } else {
          logger.warn('[WS] Message rate limit exceeded', {
            sessionId: sessionId?.slice(0, 8) + '...',
            username: state?.username ? state.username.slice(0, 4) + '...' : 'unknown',
            messageCount
          });
        }
        ws.close(1008, 'Message rate limit exceeded');
        return;
      }

      messageCount += 1;

      let messageString;
      if (Buffer.isBuffer(messageBuffer)) {
        messageString = messageBuffer.toString('utf8');
      } else if (messageBuffer instanceof ArrayBuffer) {
        messageString = Buffer.from(messageBuffer).toString('utf8');
      } else if (typeof messageBuffer === 'string') {
        messageString = messageBuffer;
      } else {
        logger.error('[WS] Unknown message format', {
          sessionId: sessionId?.slice(0, 8) + '...',
          type: typeof messageBuffer,
          constructor: messageBuffer?.constructor?.name
        });
        throw new Error('Invalid message format: unknown type');
      }

      try {
        const messageResult = await processWebSocketMessage(sessionId, messageString);

        if (!messageResult || typeof messageResult !== 'object') {
          throw new Error('Invalid message result structure');
        }

        if (!messageResult.type) {
          throw new Error('Message result missing type field');
        }

        if (messageResult.type === 'chunk_progress') {
          logger.debug('[WS] Chunk progress', {
            sessionId: sessionId?.slice(0, 8) + '...',
            progress: Math.round(messageResult.progress * 100) + '%'
          });

          return;
        }

        if (messageResult.type !== 'complete' || messageResult.data === null || messageResult.data === undefined) {
          throw new Error(`Unexpected message result type: ${messageResult.type}`);
        }

        const parsed = messageResult.data;
        const raw = typeof messageResult.raw === 'string' ? messageResult.raw : messageString;
        stats.totalMessages++;
        await handleMessage({ ws, sessionId, message: raw, parsed });
        maybeRefreshSession(ws, 'message');
      } catch (error) {
        logger.error('[WS] Message processing error', {
          sessionId: sessionId?.slice(0, 8) + '...',
          error: error.message
        });
        if (error.message.includes('too large') || error.message.includes('size')) {
          ws.close(1009, 'Message too large');
        } else if (error.message.includes('invalid') || error.message.includes('malformed')) {
          ws.close(1002, 'Invalid message format');
        } else {
          ws.close(1011, 'Internal processing error');
        }
      }
    });

    ws.on('close', async () => {
      let username = ws._username;
      let wasAuthenticated = ws.clientState?.hasAuthenticated;

      if (sessionId) {
        try {
          const state = await ConnectionStateManager.getState(sessionId);
          if (!username && state?.username) {
            username = state.username;
            logger.debug('[WS] Retrieved username from Redis on close', {
              username: username?.slice(0, 4) + '...',
              sessionId: sessionId?.slice(0, 8) + '...'
            });
          }
          if (!wasAuthenticated && state?.hasAuthenticated) {
            wasAuthenticated = true;
          }
        } catch (error) {
          logger.warn('[WS] Failed to retrieve state from Redis on close', {
            sessionId: sessionId?.slice(0, 8) + '...',
            error: error.message
          });
        }
      }

      if (username) {
        await removeLocalConnection(username, ws);

        if (wasAuthenticated) {
          try {
            await presenceService.setUserOffline(username, ws._sessionId || sessionId);
            logger.debug('[WS] User marked offline on close', {
              username: username?.slice(0, 4) + '...',
              sessionId: sessionId?.slice(0, 8) + '...'
            });
          } catch (e) {
            logger.warn('[WS] Failed to mark user offline', {
              username: username?.slice(0, 4) + '...',
              error: e?.message
            });
          }
        }
      } else {
        logger.warn('[WS] No username found on connection close', {
          sessionId: sessionId?.slice(0, 8) + '...',
          hadUsername: !!ws._username,
          hadClientState: !!ws.clientState
        });
      }

      if (sessionId) {
        try {
          await ConnectionStateManager.cleanupConnection(sessionId);
        } catch (error) {
          logger.error('[WS] Failed to cleanup connection state on close', {
            sessionId: sessionId?.slice(0, 8) + '...',
            error: error.message
          });
        }
      }

      const duration = Date.now() - connectionOpenedAt;
      stats.connectionsClosed++;

      logger.info('[WS] Connection closed', {
        sessionId: sessionId?.slice(0, 8) + '...',
        duration: `${duration}ms`,
        messages: messageCount
      });
    });
  });

  return {
    stop: () => {
      clearInterval(heartbeatInterval);
      clearInterval(staleConnectionCleanupInterval);
      localDeliveryMap.clear();
      if (isTestEnv && stats.connectionsOpened > 0) {
        updateProgress();
        if (ttyStream) {
          ttyStream.end();
        }
      }
      logger.info('[WS] Gateway stopped', { stats });
    },
    addLocalConnection,
    removeLocalConnection,
    getLocalConnections,
    getDistributedConnectionServers,
    getStats: () => ({ ...stats }),
  };
}
