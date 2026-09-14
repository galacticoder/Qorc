import { SignalType } from '../signals.js';
import { rateLimitMiddleware } from '../rate-limiting/rate-limit-middleware.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';

import { clearSocketPQSession, sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import { TimingProtection } from '../routing/timing-protection.js';
import {
  unregisterLocalSocket
} from '../routing/blind-router.js';
import { envInt } from '../utils/env.js';
import { isSafeJsonTree, isSafeWireMessageType } from '../utils/validation.js';
import { awaitMessageHandlerWithDeadline } from './message-handler-deadline.js';
import { revokeAllWebSocketConnections } from './revoke-connections.js';

const strictTextDecoder = new TextDecoder('utf-8', { fatal: true });

class WsIngressFrameError extends Error {
  constructor(closeCode, closeReason, logCode) {
    super(logCode);
    this.closeCode = closeCode;
    this.closeReason = closeReason;
    this.logCode = logCode;
  }
}

function rawMessageByteLength(raw) {
  if (typeof raw === 'string') return Buffer.byteLength(raw, 'utf8');
  if (Buffer.isBuffer(raw)) return raw.length;
  if (raw instanceof ArrayBuffer) return raw.byteLength;
  if (ArrayBuffer.isView(raw)) return raw.byteLength;
  if (Array.isArray(raw) && raw.every(Buffer.isBuffer)) {
    const total = raw.reduce((sum, part) => sum + part.length, 0);
    if (Number.isSafeInteger(total)) return total;
  }
  throw new WsIngressFrameError(1002, 'Invalid frame format', 'INVALID_RAW_FRAME');
}

function decodeTextFrame(raw, byteLength) {
  try {
    if (typeof raw === 'string') return raw;
    if (Buffer.isBuffer(raw)) return strictTextDecoder.decode(raw);
    if (raw instanceof ArrayBuffer) return strictTextDecoder.decode(new Uint8Array(raw));
    if (ArrayBuffer.isView(raw)) {
      return strictTextDecoder.decode(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength));
    }
    if (Array.isArray(raw) && raw.every(Buffer.isBuffer)) {
      return strictTextDecoder.decode(Buffer.concat(raw, byteLength));
    }
  } catch {
    throw new WsIngressFrameError(1007, 'Invalid UTF-8 payload', 'INVALID_UTF8');
  }
  throw new WsIngressFrameError(1002, 'Invalid frame format', 'INVALID_RAW_FRAME');
}

// Attach WebSocket gateway
export function attachGateway({
  wss,
  serverHybridKeyPair,
  serverId,
  rateLimiter = rateLimitMiddleware,
  logger = console,
  config,
  onMessage,
  onBinaryMessage,
  onConnectionClosed,
}) {
  if (!wss) {
    throw new Error('attachGateway requires a WebSocketServer instance');
  }
  if (!serverHybridKeyPair) {
    throw new Error('attachGateway requires serverHybridKeyPair');
  }
  if (typeof serverId !== 'string' || serverId.length === 0) {
    throw new Error('attachGateway requires serverId');
  }

  const {
    bandwidthQuota = 5 * 1024 * 1024,
    bandwidthWindowMs = 60 * 1000,
    messageQuota = 500,
    messageWindowMs = 60 * 1000,
    heartbeatIntervalMs = 30000,
    fixedMessageSizeBytes = null,
  } = config || {};

  const HEARTBEAT_MISSED_LIMIT = envInt('WS_HEARTBEAT_MISSED_LIMIT', 6, 3, 20);
  const PENDING_MESSAGE_MAX_COUNT = envInt('WS_PENDING_MESSAGE_MAX_COUNT', 64, 4, 4096);
  const PENDING_MESSAGE_MAX_BYTES = envInt(
    'WS_PENDING_MESSAGE_MAX_BYTES',
    16 * 1024 * 1024,
    1024 * 1024,
    256 * 1024 * 1024
  );
  const MAX_CONCURRENT_CONNECTIONS = envInt('WS_MAX_CONCURRENT_CONNECTIONS', 4096, 64, 100_000);
  const MESSAGE_HANDLER_TIMEOUT_MS = envInt(
    'WS_MESSAGE_HANDLER_TIMEOUT_MS',
    30_000,
    1_000,
    120_000
  );

  let cachedPublicKeyPayload = null;
  const getCachedPublicKeyPayload = async () => {
    if (cachedPublicKeyPayload) {
      return {
        ...cachedPublicKeyPayload,
        serverTime: Date.now()
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

    const { isServerPasswordGateReady } = await import('../config/config.js');

    const keyPayload = {
      type: SignalType.SERVER_PUBLIC_KEY,
      serverId,
      hybridKeys: {
        kyberPublicBase64,
        dilithiumPublicBase64,
        x25519PublicBase64
      },
      requiresServerPassword: isServerPasswordGateReady(),
    };
    const currentPayload = {
      ...keyPayload,
      serverTime: Date.now()
    };

    cachedPublicKeyPayload = keyPayload;
    return currentPayload;
  };
  const getCachedPublicKeyMessage = async () => JSON.stringify(
    await getCachedPublicKeyPayload()
  );

  // Remove local WebSocket connection using blind routing
  const removeLocalConnection = async (ws) => {
    if (!ws) return;

    unregisterLocalSocket(ws);
  };

  // Handle incoming WebSocket message
  const handleMessage = async ({ ws, parsed }) => {
    if (typeof onMessage === 'function') {
      try {
        if (ws._connectionAbortSignal?.aborted) return { handled: false };
        const handlerPromise = onMessage({ ws, parsed });
        await awaitMessageHandlerWithDeadline(handlerPromise, {
          signal: ws._connectionAbortSignal,
          timeoutMs: MESSAGE_HANDLER_TIMEOUT_MS
        });
      } catch (error) {
        if (error?.code === 'WS_MESSAGE_HANDLER_ABORTED') {
          return { handled: false };
        }
        if (error?.code === 'WS_MESSAGE_HANDLER_TIMEOUT') {
          throw new WsIngressFrameError(
            1011,
            'Message processing timeout',
            'MESSAGE_HANDLER_TIMEOUT'
          );
        }
        logger.error('[WS] Message handler error', {
          error: error.message
        });
        throw error;
      }
    }
    return { handled: true };
  };

  const handleBinaryMessage = async ({ ws, frame }) => {
    if (typeof onBinaryMessage !== 'function') {
      throw new WsIngressFrameError(1003, 'Binary frames are unsupported', 'BINARY_FRAME');
    }
    try {
      if (ws._connectionAbortSignal?.aborted) return { handled: false };
      const handlerPromise = onBinaryMessage({ ws, frame });
      await awaitMessageHandlerWithDeadline(handlerPromise, {
        signal: ws._connectionAbortSignal,
        timeoutMs: MESSAGE_HANDLER_TIMEOUT_MS
      });
    } catch (error) {
      if (error?.code === 'WS_MESSAGE_HANDLER_ABORTED') {
        return { handled: false };
      }
      if (error?.code === 'WS_MESSAGE_HANDLER_TIMEOUT') {
        throw new WsIngressFrameError(
          1011,
          'Message processing timeout',
          'MESSAGE_HANDLER_TIMEOUT'
        );
      }
      logger.error('[WS] Binary message handler error', {
        error: error.message
      });
      throw error;
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
      } catch (error) {
        logger.error('[WS] Error during heartbeat:', error);
      }
    }
  }, heartbeatIntervalMs);

  wss.on('connection', async (ws) => {
    const connectedAt = Date.now();
    const connectionAbortController = new AbortController();
    ws._connectionAbortController = connectionAbortController;
    ws._connectionAbortSignal = connectionAbortController.signal;
    const earlyFrames = [];
    let earlyFrameBytes = 0;
    const discardEarlyFrames = () => {
      earlyFrames.length = 0;
      earlyFrameBytes = 0;
      ws.off('message', captureEarlyMessage);
    };
    const captureEarlyMessage = (messageBuffer, isBinary) => {
      if (ws._ingressQueueRejected) return;
      try {
        const messageBytes = rawMessageByteLength(messageBuffer);
        if (
          earlyFrames.length + 1 > PENDING_MESSAGE_MAX_COUNT ||
          earlyFrameBytes + messageBytes > PENDING_MESSAGE_MAX_BYTES
        ) {
          ws._ingressQueueRejected = true;
          logger.warn('[WS] Early message queue exceeded', {
            pendingCount: earlyFrames.length + 1,
            pendingBytes: earlyFrameBytes + messageBytes,
            maxCount: PENDING_MESSAGE_MAX_COUNT,
            maxBytes: PENDING_MESSAGE_MAX_BYTES
          });
          discardEarlyFrames();
          ws.close(1008, 'Pending message queue exceeded');
          return;
        }
        earlyFrames.push({ messageBuffer, isBinary });
        earlyFrameBytes += messageBytes;
      } catch (error) {
        ws._ingressQueueRejected = true;
        discardEarlyFrames();
        const frameError = error instanceof WsIngressFrameError
          ? error
          : new WsIngressFrameError(1002, 'Invalid frame format', 'INVALID_RAW_FRAME');
        logger.warn('[WS] Early ingress frame rejected', { code: frameError.logCode });
        ws.close(frameError.closeCode, frameError.closeReason);
      }
    };
    ws.on('message', captureEarlyMessage);
    let connectionCleanupStarted = false;
    ws.on('error', (error) => {
      connectionAbortController.abort();
      logger.warn('[WS] Socket transport error', {
        code: typeof error?.code === 'string' ? error.code : 'WS_TRANSPORT_ERROR'
      });
    });
    ws.on('close', async (code) => {
      if (connectionCleanupStarted) return;
      connectionCleanupStarted = true;
      const details = {
        code,
        durationMs: Date.now() - connectedAt,
        missedHeartbeats: Number(ws._missedHeartbeats || 0)
      };
      if (code === 1000 || code === 1001) {
        logger.info('[WS] Connection closed', details);
      } else {
        logger.warn('[WS] Connection closed abnormally', details);
      }
      connectionAbortController.abort();
      discardEarlyFrames();
      try {
        clearSocketPQSession(ws);
        await removeLocalConnection(ws);
        if (typeof onConnectionClosed === 'function') {
          try { onConnectionClosed(ws); } catch { }
        }
      } finally {
        ws._messageProcessing = null;
        ws._pendingMessageCount = 0;
        ws._pendingMessageBytes = 0;
      }
    });

    if (wss.clients.size > MAX_CONCURRENT_CONNECTIONS) {
      logger.warn('[WS] Concurrent connection capacity reached');
      discardEarlyFrames();
      ws.close(1013, 'Server connection capacity reached');
      return;
    }

    try {
      const allowed = await rateLimiter.checkConnectionLimit(ws);
      if (!allowed) {
        discardEarlyFrames();
        return;
      }
    } catch (error) {
      logger.error('[WS] Rate limiting error during connection:', error);
      discardEarlyFrames();
      ws.close(1011, 'Rate limiting error');
      return;
    }

    let bandwidthUsed = 0;
    let ingressMessageCount = 0;
    let ingressMessageWindowStart = Date.now();

    ws.isAlive = true;
    ws._missedHeartbeats = 0;
    ws.on('pong', () => {
      ws.isAlive = true;
      ws._missedHeartbeats = 0;
    });

    ws.on('ping', () => {
      ws.isAlive = true;
      ws._missedHeartbeats = 0;
    });

    try {
      const message = await getCachedPublicKeyMessage();

      if (ws.readyState !== 1) {
        logger.warn('[WS] Connection closed before key exchange', {
          readyState: ws.readyState
        });
        return;
      }

      ws.send(message, (error) => {
        if (error) {
          logger.error('[WS] Failed to send server public keys', {
            error: error.message,
            readyState: ws.readyState
          });
        }
      });
    } catch (error) {
      logger.error('[WS] Failed to send server public keys', {
        error: error.message,
        stack: error.stack,
        code: 1011
      });
      discardEarlyFrames();
      ws.close(1011, 'Key exchange failed');
      return;
    }

    const handleIngressMessage = async (messageBuffer, isBinary) => {
      try {
      const binaryFrame = isBinary === true;
      const receivedAt = Date.now();
      ws.isAlive = true;
      ws._missedHeartbeats = 0;

      if (ws._ingressQueueRejected) return;

      if (receivedAt - ingressMessageWindowStart >= messageWindowMs) {
        ingressMessageWindowStart = receivedAt;
        ingressMessageCount = 0;
      }
      ingressMessageCount += 1;
      if (ingressMessageCount > messageQuota) {
        ws._ingressQueueRejected = true;
        logger.warn('[WS] Ingress frame rate exceeded', {
          count: ingressMessageCount,
          maxCount: messageQuota,
          windowMs: messageWindowMs
        });
        ws.close(1008, 'Message rate exceeded');
        return;
      }

      const messageBytes = rawMessageByteLength(messageBuffer);
      const pendingCount = Number(ws._pendingMessageCount || 0) + 1;
      const pendingBytes = Number(ws._pendingMessageBytes || 0) + messageBytes;
      if (pendingCount > PENDING_MESSAGE_MAX_COUNT || pendingBytes > PENDING_MESSAGE_MAX_BYTES) {
        ws._ingressQueueRejected = true;
        logger.warn('[WS] Pending message queue exceeded', {
          pendingCount,
          pendingBytes,
          maxCount: PENDING_MESSAGE_MAX_COUNT,
          maxBytes: PENDING_MESSAGE_MAX_BYTES
        });
        ws.close(1008, 'Pending message queue exceeded');
        return;
      }
      ws._pendingMessageCount = pendingCount;
      ws._pendingMessageBytes = pendingBytes;

      const previousMessageProcessing = ws._messageProcessing || Promise.resolve();
      let releaseMessageProcessing = () => {};
      ws._messageProcessing = new Promise((resolve) => {
        releaseMessageProcessing = resolve;
      });

      try {
        await previousMessageProcessing.catch(() => {});
        if (ws._ingressQueueRejected || ws.readyState !== 1) return;

        const now = receivedAt;

        if (binaryFrame && !ws._pqSessionId && !ws._pqPendingSessionId) {
          throw new WsIngressFrameError(1003, 'Binary frame before secure session', 'EARLY_BINARY_FRAME');
        }
        if (!binaryFrame && (ws._pqSessionId || ws._pqPendingSessionId)) {
          throw new WsIngressFrameError(1003, 'Encrypted binary cell required', 'TEXT_AFTER_PQ_SESSION');
        }
        if (binaryFrame && fixedMessageSizeBytes && messageBytes !== fixedMessageSizeBytes) {
          throw new WsIngressFrameError(1009, 'Invalid encrypted cell size', 'INVALID_BINARY_CELL_SIZE');
        }
        if (fixedMessageSizeBytes && messageBytes > fixedMessageSizeBytes) {
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

        try {
          if (binaryFrame) {
            const frame = Buffer.isBuffer(messageBuffer)
              ? messageBuffer
              : Buffer.from(messageBuffer);
            await handleBinaryMessage({ ws, frame });
            return;
          }
          const messageString = decodeTextFrame(messageBuffer, messageBytes);
          let parsed;
          try {
            parsed = JSON.parse(messageString);
          } catch {
            throw new WsIngressFrameError(1002, 'Invalid JSON payload', 'INVALID_JSON');
          }
          if (
            !parsed ||
            typeof parsed !== 'object' ||
            Array.isArray(parsed) ||
            !isSafeJsonTree(parsed, {
              maxDepth: 32,
              maxNodes: 20_000,
              maxKeyLength: 256
            })
          ) {
            throw new WsIngressFrameError(1002, 'Invalid message structure', 'INVALID_MESSAGE_OBJECT');
          }
          if (!isSafeWireMessageType(parsed.type)) {
            throw new WsIngressFrameError(1002, 'Invalid message type', 'INVALID_MESSAGE_TYPE');
          }
          await handleMessage({ ws, parsed });
        } catch (error) {
          if (error instanceof WsIngressFrameError) {
            ws._ingressQueueRejected = true;
            logger.warn('[WS] Protocol frame rejected', { code: error.logCode });
            if (error.logCode === 'MESSAGE_HANDLER_TIMEOUT') {
              connectionAbortController.abort();
              try {
                ws.terminate?.();
              } catch { }
            } else {
              ws.close(error.closeCode, error.closeReason);
            }
          } else {
            logger.error('[WS] Message handler failed');
            try {
              await sendSecureMessage(ws, {
                type: SignalType.ERROR,
                message: 'Internal processing error'
              });
            } catch { }
          }
        }
      } finally {
        ws._pendingMessageCount = Math.max(0, Number(ws._pendingMessageCount || 0) - 1);
        ws._pendingMessageBytes = Math.max(0, Number(ws._pendingMessageBytes || 0) - messageBytes);
        releaseMessageProcessing();
      }
      } catch (error) {
        ws._ingressQueueRejected = true;
        const frameError = error instanceof WsIngressFrameError
          ? error
          : new WsIngressFrameError(1011, 'Internal processing error', 'INGRESS_PROCESSING_FAILED');
        logger.warn('[WS] Ingress frame rejected', { code: frameError.logCode });
        try {
          ws.close(frameError.closeCode, frameError.closeReason);
        } catch { }
      }
    };

    ws.off('message', captureEarlyMessage);
    ws.on('message', handleIngressMessage);
    const queuedFrames = earlyFrames.splice(0, earlyFrames.length);
    earlyFrameBytes = 0;
    for (const { messageBuffer, isBinary } of queuedFrames) {
      void handleIngressMessage(messageBuffer, isBinary);
    }

  });

  return {
    stop: async () => {
      clearInterval(heartbeatInterval);
      await TimingProtection.stopCoverTraffic();
      logger.info('[WS] Gateway stopped');
    },
    removeLocalConnection,
    revokeAllConnections: () => revokeAllWebSocketConnections(wss),
    getServerPublicKeyPayload: getCachedPublicKeyPayload,
    getServerPublicKeyMessage: getCachedPublicKeyMessage,
  };
}
