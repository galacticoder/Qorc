import { SignalType } from '../signals.js';
import { ConnectionStateManager } from '../session/connection-state.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { withRedisClient } from '../session/redis-client.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import { deleteCachedPQSession } from '../session/pq-session-storage.js';
import { validateCapabilityToken } from '../routing/capability-tokens.js';
import { TimingProtection } from '../routing/timing-protection.js';
import { BlindSignatureIssuer } from '../security/blind-signatures.js';
import {
  registerLocalSocket,
  unregisterLocalSocket,
  routeToGlobalMix
} from '../routing/blind-router.js';
import { recordWsIngress } from '../diagnostics/runtime-monitor.js';

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

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
  onConnectionActive,
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

  const SESSION_REFRESH_MIN_INTERVAL_MS = 60_000;
  const DELIVERY_STALE_THRESHOLD_MS = 5 * 60_000;
  const HEARTBEAT_MISSED_LIMIT = Math.max(3, Number.parseInt(process.env.WS_HEARTBEAT_MISSED_LIMIT || '6', 10) || 6);
  const LARGE_FRAME_WINDOW_MS = envInt('WS_LARGE_FRAME_WINDOW_MS', 60_000, 1_000, 10 * 60_000);
  const LARGE_FRAME_MAX_COUNT = envInt('WS_LARGE_FRAME_MAX_COUNT', 64, 1, 10_000);
  const LARGE_FRAME_MAX_BYTES = envInt('WS_LARGE_FRAME_MAX_BYTES', 32 * 1024 * 1024, 1024 * 1024, 1024 * 1024 * 1024);

  const consumeLargeFrameBudget = (ws, messageBytes) => {
    const now = Date.now();
    if (!ws._largeFrameWindowStart || now - ws._largeFrameWindowStart > LARGE_FRAME_WINDOW_MS) {
      ws._largeFrameWindowStart = now;
      ws._largeFrameWindowCount = 0;
      ws._largeFrameWindowBytes = 0;
    }
    ws._largeFrameWindowCount = Number(ws._largeFrameWindowCount || 0) + 1;
    ws._largeFrameWindowBytes = Number(ws._largeFrameWindowBytes || 0) + Math.max(0, messageBytes);
    return ws._largeFrameWindowCount <= LARGE_FRAME_MAX_COUNT &&
      ws._largeFrameWindowBytes <= LARGE_FRAME_MAX_BYTES;
  };

  const safeJsonParse = (raw) => {
    if (typeof raw !== 'string') return null;
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  };

  const hasClaimedInboxRoute = (ws) => {
    return !!(ws?._claimedInboxRoutes && ws._claimedInboxRoutes.size > 0);
  };

  const isLocalDeliveryReady = (ws) => {
    return !!(ws?._unlinkedSession || hasClaimedInboxRoute(ws));
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
          error: error?.message || String(error)
        });
      });

      if (!ws._blindSocketId && ws._pqSessionId && isLocalDeliveryReady(ws)) {
        registerLocalSocket(ws);
      }
    } catch {
    }
  };

  let cachedPublicKeyPayload = null;
  let cachedPublicKeyLogInfo = null;

  const getCachedPublicKeyMessage = async () => {
    if (cachedPublicKeyPayload) {
      const message = JSON.stringify({
        ...cachedPublicKeyPayload,
        serverTime: Date.now()
      });
      return {
        message,
        logInfo: {
          ...cachedPublicKeyLogInfo,
          originalSize: message.length
        }
      };
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

    const keyPayload = {
      type: SignalType.SERVER_PUBLIC_KEY,
      serverId: serverId || 'default',
      hybridKeys: {
        kyberPublicBase64,
        dilithiumPublicBase64,
        x25519PublicBase64,
        blindPublicKey
      },
      requiresServerPassword: !!serverPasswordHash,
    };
    const keyMessage = JSON.stringify({
      ...keyPayload,
      serverTime: Date.now()
    });

    cachedPublicKeyPayload = keyPayload;
    cachedPublicKeyLogInfo = {
      serverId: serverId || 'default',
      dilithiumPublicKeyLength: Buffer.from(dilithiumPublicBase64, 'base64').length,
      kyberPublicKeyLength: serverHybridKeyPair.kyber.publicKey.length,
      originalSize: keyMessage.length,
    };

    return { message: keyMessage, logInfo: cachedPublicKeyLogInfo };
  };

  // Add local WebSocket connection using blind routing
  const addLocalConnection = async (ws) => {
    if (!ws) return;

    // Only receive ready sockets join local privacy broadcasts
    if (!isLocalDeliveryReady(ws)) {
      ws._localDeliveryDeferred = true;
      return;
    }

    if (!ws._blindSocketId) {
      registerLocalSocket(ws);
    }
  };

  // Remove local WebSocket connection using blind routing
  const removeLocalConnection = async (ws) => {
    if (!ws) return;

    // Unregister socket from blind router
    unregisterLocalSocket(ws);
  };

  const routeToGlobalMixStream = async (sealedEnvelope, options = {}) => {
    return await routeToGlobalMix(sealedEnvelope, options);
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
        if (ws.readyState !== 1) {
          continue;
        }
        if (ws.isAlive === false) {
          const missed = Number(ws._missedHeartbeats || 0) + 1;
          ws._missedHeartbeats = missed;

          if (missed >= HEARTBEAT_MISSED_LIMIT) {
            logger.warn('[WS] Heartbeat timeout. closing stale connection', {
              missedHeartbeats: missed,
              missedLimit: HEARTBEAT_MISSED_LIMIT
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
            continue;
          }
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
            const lastSeen = Number(parsed?.lastSeen || parsed?.registeredAt || 0);

            if (!parsed || !lastSeen || (nowTimestamp - lastSeen) > DELIVERY_STALE_THRESHOLD_MS) {
              await client.del(key);
              totalCleaned++;
            }
          } catch (err) {
            logger.warn('[WS] Error cleaning up inbox key', {
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
    if (typeof onConnectionActive === 'function') {
      try {
        onConnectionActive();
      } catch (error) {
        logger.warn('[WS] Connection activation hook failed', {
          error: error?.message || String(error)
        });
      }
    }

    try {
      ws.upgradeReq = req;
      ws.headers = req?.headers || {};
    } catch (_) { }

    try {
      const allowed = await rateLimiter.checkConnectionLimit(ws);
      if (!allowed) {
        logger.warn('[WS] Connection rejected due to rate limiting', {
          socketId: ws._blindSocketId,
          code: 1008
        });
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
      logger.info('[WS] Created session');
    } catch (error) {
      logger.error('[WS] Failed to create session', {
        error: error.message,
        code: 1011
      });
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
          readyState: ws.readyState
        });
        return;
      }

      logger.info('[WS] Sending server public keys', {
        ...logInfo,
        readyState: ws.readyState,
        bufferedAmount: ws.bufferedAmount
      });

      ws.send(message, (error) => {
        if (error) {
          logger.error('[WS] Failed to send server public keys', {
            error: error.message,
            readyState: ws.readyState
          });
        } else {
          logger.info('[WS] Server public keys delivered to OS buffer');
        }
      });
    } catch (error) {
      logger.error('[WS] Failed to send server public keys', {
        error: error.message,
        stack: error.stack,
        code: 1011
      });
      ws.close(1011, 'Key exchange failed');
      return;
    }

    ws.on('message', async (messageBuffer) => {
      const receivedAt = Date.now();
      ws.isAlive = true;
      ws._missedHeartbeats = 0;
      ws._lastMessageAt = receivedAt;

      const previousMessageProcessing = ws._messageProcessing || Promise.resolve();
      let releaseMessageProcessing = () => {};
      ws._messageProcessing = new Promise((resolve) => {
        releaseMessageProcessing = resolve;
      });
      await previousMessageProcessing.catch(() => {});

      try {
        const now = receivedAt;
        const messageBytes = Buffer.isBuffer(messageBuffer)
          ? messageBuffer.length
          : (messageBuffer instanceof ArrayBuffer
            ? messageBuffer.byteLength
            : (typeof messageBuffer === 'string' ? Buffer.byteLength(messageBuffer) : 0));

        if (fixedMessageSizeBytes && ws._pqSessionId) {
          if (messageBytes !== fixedMessageSizeBytes) {
            const maxAllowed = Math.max(fixedMessageSizeBytes * 2, 8 * 1024 * 1024);
            if (messageBytes > maxAllowed) {
              logger.warn('[WS] Invalid fixed message size', {
                bytes: messageBytes,
                expected: fixedMessageSizeBytes,
                maxAllowed,
                code: 1009
              });
              ws.close(1009, 'Invalid message size');
              return;
            }
            if (messageBytes > fixedMessageSizeBytes) {
              logger.warn('[WS] Non-standard message size', {
                bytes: messageBytes,
                expected: fixedMessageSizeBytes,
                maxAllowed
              });
              if (!consumeLargeFrameBudget(ws, messageBytes)) {
                logger.warn('[WS] Large-frame budget exceeded', {
                  count: Number(ws._largeFrameWindowCount || 0),
                  bytes: Number(ws._largeFrameWindowBytes || 0),
                  windowMs: LARGE_FRAME_WINDOW_MS,
                  code: 1008
                });
                ws.close(1008, 'Large message rate exceeded');
                return;
              }
            }
          }
        } else if (fixedMessageSizeBytes && messageBytes > fixedMessageSizeBytes) {
          logger.warn('[WS] Message too large (pre-handshake)', {
            bytes: messageBytes,
            max: fixedMessageSizeBytes,
            code: 1009
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
          logger.warn('[WS] Closing connection due to bandwidth quota', {
            code: 1008
          });
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
          recordWsIngress(messageBytes, parsed.type);

          await handleMessage({ ws, sessionId, message: messageString, parsed });
          maybeRefreshSession(ws, 'message');
        } catch (error) {
          logger.error('[WS] Message processing error', {
            error: error.message
          });
          if (error.message.includes('too large') || error.message.includes('size')) {
            ws.close(1009, 'Message too large');
          } else if (error.message.includes('invalid') || error.message.includes('malformed')) {
            ws.close(1002, 'Invalid message format');
          } else {
            try {
              ws.send(JSON.stringify({ type: 'error', message: 'Internal processing error' }));
            } catch { }
          }
        }
      } finally {
        releaseMessageProcessing();
      }
    });

    ws.on('close', async (code, reason) => {
      if (ws._pqSessionId) {
        deleteCachedPQSession(ws._pqSessionId);
      }
      await removeLocalConnection(ws);
      if (sessionId) {
        try {
          await ConnectionStateManager.cleanupConnection(sessionId);
        } catch (error) {
          logger.error('[WS] Failed to cleanup connection state on close', {
            error: error.message
          });
        }
      }

      logger.info('[WS] Connection closed', { closed: true });
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
    routeToGlobalMixStream,
    validateBlindAuthToken,
    getServerPublicKeyMessage: getCachedPublicKeyMessage,
  };
}
