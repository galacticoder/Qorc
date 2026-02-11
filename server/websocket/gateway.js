import { SignalType } from '../signals.js';
import { ConnectionStateManager } from '../session/connection-state.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { withRedisClient } from '../session/redis-client.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import {
  registerLocalSocket,
  unregisterLocalSocket,
  claimInbox,
  routeToInbox
} from '../routing/blind-router.js';
import { validateCapabilityToken } from '../routing/capability-tokens.js';
import { TimingProtection } from '../routing/timing-protection.js';
import { BlindSignatureIssuer } from '../security/blind-signatures.js';

// Attach WebSocket gateway
export function attachGateway({
  wss,
  serverHybridKeyPair,
  serverId = null,
  createSession = ConnectionStateManager.createSession,
  refreshSession = ConnectionStateManager.refreshSession,
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
    heartbeatIntervalMs = 30000,
    fixedMessageSizeBytes = null,
  } = config || {};

  const REDIS_CONNECTION_TTL = 31536000;

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

      // Refresh inbox registration in blind router
      const inboxId = ws?._primaryInboxId;
      if (!inboxId) return;

      void withRedisClient(async (client) => {
        const key = `inbox:${inboxId}`;
        const serverId = process.env.SERVER_ID || 'default';
        const value = JSON.stringify({ serverId, sessionId: sid, lastSeen: now });
        await client.setex(key, REDIS_CONNECTION_TTL, value);
      }).catch((error) => {
        logger.warn('[WS] Failed to refresh inbox entry', {
          reason,
          inboxPrefix: inboxId?.slice(0, 8) + '...',
          error: error?.message || String(error)
        });
      });
    } catch {
    }
  };

  let cachedPublicKeyMessage = null;
  let cachedPublicKeyLogInfo = null;

  const getCachedPublicKeyMessage = async () => {
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

    // Check if server password is required
    const { getServerPasswordHash } = await import('../config/config.js');
    const serverPasswordHash = getServerPasswordHash();

    // Get blind signature public key metadata (RSABSSA-PSS)
    const blindPublicKey = await BlindSignatureIssuer.getPublicKey();

    const keyMessage = JSON.stringify({
      type: SignalType.SERVER_PUBLIC_KEY,
      serverId: serverId || 'default',
      hybridKeys: {
        kyberPublicBase64,
        dilithiumPublicBase64,
        x25519PublicBase64,
        blindPublicKey
      },
      requiresServerPassword: !!serverPasswordHash,
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

  // Add local WebSocket connection using blind routing
  const addLocalConnection = async (ws) => {
    if (!ws) return;

    // Register socket with blind router
    if (!ws._blindSocketId) {
      registerLocalSocket(ws);
    }

    // If socket has inbox IDs from auth, claim them
    if (ws._primaryInboxId && ws._capabilityToken) {
      try {
        await claimInbox(ws, ws._capabilityToken, ws._primaryInboxId);
      } catch (error) {
        logger.warn('[WS] Failed to claim inbox', { error: error.message });
      }
    }

    // Register for cover traffic
    if (ws._primaryInboxId) {
      TimingProtection.registerForCoverTraffic(ws._primaryInboxId);
    }
  };

  // Remove local WebSocket connection using blind routing
  const removeLocalConnection = async (ws) => {
    if (!ws) return;

    // Unregister from cover traffic
    if (ws._primaryInboxId) {
      TimingProtection.unregisterFromCoverTraffic(ws._primaryInboxId);
    }

    // Unregister socket from blind router
    unregisterLocalSocket(ws);
  };

  // Route message to inbox
  const routeToInboxId = async (inboxId, sealedEnvelope, options = {}) => {
    return await routeToInbox(inboxId, sealedEnvelope, options);
  };

  // Validate capability token for blind routing
  const validateBlindAuthToken = async (token) => {
    return await validateCapabilityToken(token);
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
        if (ws.readyState !== 1) {
          continue;
        }
        if (ws.isAlive === false) {
          const missed = Number(ws._missedHeartbeats || 0) + 1;
          ws._missedHeartbeats = missed;

          if (missed >= 2) {
            logger.warn('[WS] Heartbeat timeout; closing stale connection', {
              sessionId: ws?._sessionId?.slice(0, 8) + '...',
              missedHeartbeats: missed
            });
            try {
              ws.close(1011, 'Heartbeat timeout');
            } catch { }
            setTimeout(() => {
              try {
                if (ws.readyState !== 3) {
                  ws.terminate?.();
                }
              } catch { }
            }, 5000);
          }
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
  const staleConnectionCleanupInterval = setInterval(async () => {
    try {
      await withRedisClient(async (client) => {
        const nowTimestamp = Date.now();
        const [newCursor, keys] = await client.scan(
          staleCleanupCursor,
          'MATCH',
          'inbox:*',
          'COUNT',
          50
        );
        staleCleanupCursor = newCursor;

        let totalCleaned = 0;

        for (const key of keys) {
          try {
            if (typeof key === 'string' && key.startsWith('inbox:queue:')) {
              continue;
            }

            const keyType = await client.type(key);
            if (keyType !== 'string') {
              continue;
            }

            const raw = await client.get(key);
            const parsed = safeJsonParse(raw);
            const lastSeen = Number(parsed?.lastSeen || 0);

            if (!parsed || !lastSeen || (nowTimestamp - lastSeen) > DELIVERY_STALE_THRESHOLD_MS) {
              await client.del(key);
              totalCleaned++;
            }
          } catch (err) {
            logger.warn('[WS] Error cleaning up inbox key', {
              keyPrefix: key?.slice(0, 14) + '...',
              error: err.message
            });
          }
        }

        if (totalCleaned > 0) {
          logger.info('[WS] Cleaned up stale inbox entries', {
            totalCleaned,
            keysScanned: keys.length,
          });
        }
      });
    } catch (error) {
      logger.warn('[WS] Error during stale inbox cleanup', { error: error.message });
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
    let bandwidthUsed = 0;
    try {
      sessionId = await createSession();
      ws._sessionId = sessionId;
      logger.info('[WS] Created session', { sessionId: sessionId?.slice(0, 8) + '...' });
    } catch (error) {
      logger.error('[WS] Failed to create session', { error: error.message });
      ws.close(1011, 'Internal server error');
      return;
    }

    ws.isAlive = true;
    ws._missedHeartbeats = 0;
    ws.on('pong', () => {
      ws.isAlive = true;
      ws._missedHeartbeats = 0;
      ws._lastPongAt = Date.now();
    });

    ws.on('ping', () => {
      ws.isAlive = true;
      ws._missedHeartbeats = 0;
      ws._lastPongAt = Date.now();
      try {
        ws.pong();
      } catch (error) {
        logger.warn('[WS] Pong failed', { error: error.message });
      }
    });

    try {
      const { message, logInfo } = await getCachedPublicKeyMessage();

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
      const messageBytes = Buffer.isBuffer(messageBuffer)
        ? messageBuffer.length
        : (messageBuffer instanceof ArrayBuffer
          ? messageBuffer.byteLength
          : (typeof messageBuffer === 'string' ? Buffer.byteLength(messageBuffer) : 0));

      if (fixedMessageSizeBytes && ws._pqSessionId) {
        if (messageBytes !== fixedMessageSizeBytes) {
          const maxAllowed = fixedMessageSizeBytes * 2;
          if (messageBytes > maxAllowed) {
            logger.warn('[WS] Invalid fixed message size', {
              sessionId: sessionId?.slice(0, 8) + '...',
              bytes: messageBytes,
              expected: fixedMessageSizeBytes,
              maxAllowed
            });
            ws.close(1009, 'Invalid message size');
            return;
          }
          logger.warn('[WS] Non-standard message size', {
            sessionId: sessionId?.slice(0, 8) + '...',
            bytes: messageBytes,
            expected: fixedMessageSizeBytes,
            maxAllowed
          });
        }
      } else if (fixedMessageSizeBytes && messageBytes > fixedMessageSizeBytes) {
        logger.warn('[WS] Message too large (pre-handshake)', {
          sessionId: sessionId?.slice(0, 8) + '...',
          bytes: messageBytes,
          max: fixedMessageSizeBytes
        });
        ws.close(1009, 'Message too large');
        return;
      }

      if (!ws._bandwidthWindowStart) {
        ws._bandwidthWindowStart = now;
      }
      if (now - ws._bandwidthWindowStart > bandwidthWindowMs) {
        ws._bandwidthWindowStart = now;
        bandwidthUsed = 0;
      }

      if (bandwidthUsed + messageBytes > bandwidthQuota) {
        logger.warn('[WS] Bandwidth quota exceeded', {
          sessionId: sessionId?.slice(0, 8) + '...',
          bytes: bandwidthUsed + messageBytes,
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

      bandwidthUsed += messageBytes;

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
        const parsed = JSON.parse(messageString);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('Invalid message structure: expected object');
        }
        if (typeof parsed.type !== 'string' || parsed.type.length === 0 || parsed.type.length > 64) {
          throw new Error('Invalid or missing message type');
        }

        await handleMessage({ ws, sessionId, message: messageString, parsed });
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
      await removeLocalConnection(ws);
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

      logger.info('[WS] Connection closed', {
        sessionId: sessionId?.slice(0, 8) + '...',
      });
    });
  });

  return {
    stop: () => {
      clearInterval(heartbeatInterval);
      clearInterval(staleConnectionCleanupInterval);
      TimingProtection.stopCoverTraffic();
      logger.info('[WS] Gateway stopped');
    },
    addLocalConnection,
    removeLocalConnection,
    routeToInboxId,
    validateBlindAuthToken,
    getServerPublicKeyMessage: getCachedPublicKeyMessage,
  };
}
