import nodeCrypto from 'crypto';
if (!global.crypto) {
  global.crypto = nodeCrypto.webcrypto;
}
import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import { SignalType } from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import { MessageDatabase, UserDatabase, BlockingDatabase, initDatabase } from './database/database.js';
import * as ServerConfig from './config/config.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';
import { ConnectionStateManager } from './presence/connection-state.js';
import authRoutes from './routes/auth-routes.js';
import { createServer as createBootstrapServer, registerShutdownHandlers } from './bootstrap/server-bootstrap.js';
import { attachGateway } from './websocket/gateway.js';
import { attachP2PSignaling } from './websocket/p2p-signaling.js';
import { cleanupSessionManager } from './session/session-manager.js';
import { checkBlocking } from './security/blocking.js';
import { logEvent, logError, logDeliveryEvent, logRateLimitEvent } from './security/logging.js';
import { presenceService } from './presence/presence-service.js';
import { SERVER_CONSTANTS, SECURITY_HEADERS, CORS_CONFIG } from './config/constants.js';
import { logger as cryptoLogger } from './crypto/crypto-logger.js';
import { withRedisClient } from './presence/presence.js';
import { getPQSession } from './session/pq-session-storage.js';
import { handlePQHandshake, handlePQEnvelope, sendPQEncryptedResponse, createPQResponseSender, sendSecureMessage, initializeEnvelopeHandler } from './messaging/pq-envelope-handler.js';
import { handleBundlePublish, handleBundleRequest, handleBundleFailure } from './messaging/libsignal-handler.js';
import { initializeCluster, shutdownCluster } from './cluster/cluster-integration.js';
import clusterRoutes from './routes/cluster-routes.js';

const KYBER_PUBLIC_KEY_LENGTH = 1568;
const DILITHIUM_PUBLIC_KEY_LENGTH = 2592;
const X25519_PUBLIC_KEY_LENGTH = 32;

function isValidBase64Key(b64, expectedLen) {
  if (!b64 || typeof b64 !== 'string') return false;
  try {
    const bytes = Buffer.from(b64, 'base64');
    return bytes.length === expectedLen;
  } catch (_e) {
    return false;
  }
}

function sanitizeHybridKeysServer(keys) {
  const out = {};
  if (keys && typeof keys === 'object') {
    if (isValidBase64Key(keys.kyberPublicBase64, KYBER_PUBLIC_KEY_LENGTH)) out.kyberPublicBase64 = keys.kyberPublicBase64;
    if (isValidBase64Key(keys.dilithiumPublicBase64, DILITHIUM_PUBLIC_KEY_LENGTH)) out.dilithiumPublicBase64 = keys.dilithiumPublicBase64;
    if (isValidBase64Key(keys.x25519PublicBase64, X25519_PUBLIC_KEY_LENGTH)) out.x25519PublicBase64 = keys.x25519PublicBase64;
  }
  return out;
}

let server, wss, serverHybridKeyPair, blockTokenCleanupInterval, statusLogInterval;

async function createExpressApp() {
  const app = express();
  app.set('trust proxy', true);

  app.use((req, res, next) => {
    for (const [header, value] of Object.entries(SECURITY_HEADERS)) {
      res.setHeader(header, value);
    }

    const allowedOrigins = CORS_CONFIG.ALLOWED_ORIGINS || [];
    const requestOrigin = req.headers.origin;

    if (requestOrigin && allowedOrigins.includes(requestOrigin)) {
      res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      res.setHeader('Vary', 'Origin');
    }

    res.setHeader('Access-Control-Allow-Methods', CORS_CONFIG.ALLOWED_METHODS);
    res.setHeader('Access-Control-Allow-Headers', CORS_CONFIG.ALLOWED_HEADERS);
    res.setHeader('Access-Control-Allow-Credentials', String(CORS_CONFIG.ALLOW_CREDENTIALS === true));
    res.setHeader('Access-Control-Max-Age', `${CORS_CONFIG.MAX_AGE_SECONDS}`);

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }

    next();
  });

  app.use(express.json({ limit: SERVER_CONSTANTS.MAX_JSON_PAYLOAD_SIZE }));
  app.use('/api/auth', authRoutes);
  app.use('/api/cluster', clusterRoutes);
  app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: Date.now() });
  });

  // Handle tunnel URL endpoint (ngrok)
  app.get('/api/tunnel-url', async (req, res) => {
    try {
      const resp = await fetch('http://127.0.0.1:4040/api/tunnels');
      if (!resp.ok) {
        res.status(404).type('text/plain').send('Tunnel URL not found');
        return;
      }
      const data = await resp.json();
      const httpsTunnel = (data.tunnels || []).find(t => typeof t.public_url === 'string' && t.public_url.startsWith('https://'));
      if (httpsTunnel) {
        res.type('text/plain').send(httpsTunnel.public_url);
      } else {
        res.status(404).type('text/plain').send('Tunnel URL not found');
      }
    } catch (error) {
      logError(error, { endpoint: '/api/tunnel-url' });
      res.status(500).type('text/plain').send('Server error');
    }
  });

  app.get('/api/ice/config', (req, res) => {
    try {
      const turnRaw = process.env.TURN_SERVERS || '';
      const stunRaw = process.env.STUN_SERVERS || '';
      let turnServers = null;
      let stunServers = null;
      if (turnRaw) {
        try {
          const parsed = JSON.parse(turnRaw);
          if (Array.isArray(parsed)) turnServers = parsed;
        } catch { }
      }
      if (stunRaw) {
        try {
          const parsed = JSON.parse(stunRaw);
          if (Array.isArray(parsed)) stunServers = parsed;
        } catch { }
      }
      const iceServers = [];
      if (stunServers && Array.isArray(stunServers)) {
        for (const url of stunServers) {
          if (typeof url === 'string' && url.startsWith('stun:')) {
            iceServers.push({ urls: url });
          }
        }
      }
      if (turnServers && Array.isArray(turnServers)) {
        for (const entry of turnServers) {
          if (!entry) continue;
          const urls = entry.urls;
          const hasUrls = Array.isArray(urls) ? urls.length > 0 : typeof urls === 'string';
          if (!hasUrls) continue;
          if (!entry.username || !entry.credential) continue;
          iceServers.push(entry);
        }
      }
      const iceTransportPolicy = process.env.ICE_TRANSPORT_POLICY === 'relay' ? 'relay' : 'all';
      res.json({ iceServers, iceTransportPolicy });
    } catch (error) {
      logError(error, { endpoint: '/api/ice/config' });
      res.status(500).json({ error: 'ICE configuration error' });
    }
  });

  // Serve static frontend files
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const distPath = path.join(__dirname, '../dist');
  if (fs.existsSync(distPath)) {
    app.use(express.static(distPath));

    app.get(/^\/(?!api\/).*/, (req, res) => {
      const indexPath = path.join(distPath, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(404).send('Application not built. Run: npm run build');
      }
    });
  }

  return app;
}

async function createWebSocketServer({ server: httpsServer }) {
  wss = new WebSocketServer({ server: httpsServer });
  await presenceService.recordServerStartup();

  try {
    const cleanupResults = await presenceService.cleanupStaleSessions();
    logEvent('startup-cleanup', cleanupResults);
  } catch (error) {
    logError(error, { operation: 'startup-cleanup' });
  }

  try {
    const clearedCount = await presenceService.clearAllPresenceData();
    logEvent('presence-cleared', { clearedCount });
  } catch (error) {
    logError(error, { operation: 'presence-clear' });
  }

  // Set up pattern subscriber for cross-instance delivery
  try {
    await presenceService.createPatternSubscriber(async ({ message }) => {
      const parsedMessage = JSON.parse(message);
      const senderUser = parsedMessage.encryptedPayload?.from || parsedMessage.from;
      const recipientUser = parsedMessage.to || parsedMessage.encryptedPayload?.to;

      if (!recipientUser) {
        cryptoLogger.warn('[CROSS-INSTANCE] No recipient username in message', {
          hasTo: !!parsedMessage.to,
          hasEncPayloadTo: !!parsedMessage.encryptedPayload?.to
        });
        return;
      }

      cryptoLogger.debug('[CROSS-INSTANCE] Received message for delivery', {
        recipient: recipientUser.slice(0, 8) + '...',
        sender: senderUser?.slice(0, 8) + '...'
      });

      const senderBlockedByRecipient = await checkBlocking(senderUser, recipientUser);
      const recipientBlockedBySender = await checkBlocking(recipientUser, senderUser);

      if (senderBlockedByRecipient || recipientBlockedBySender) {
        logDeliveryEvent('cross-instance-blocked', {
          senderUser,
          recipientUser,
          reason: senderBlockedByRecipient ? 'sender-blocked-by-recipient' : 'recipient-blocked-by-sender'
        });
        cryptoLogger.debug('[CROSS-INSTANCE] Message blocked', {
          sender: senderUser?.slice(0, 8) + '...',
          recipient: recipientUser.slice(0, 8) + '...',
          reason: senderBlockedByRecipient ? 'sender-blocked' : 'recipient-blocked'
        });
        return;
      }

      // Deliver to local connections
      let localSet = global.gateway?.getLocalConnections?.(recipientUser);

      // If no local connections found wait for connection registration
      if (!localSet || localSet.size === 0) {
        await new Promise(r => setTimeout(r, 100));
        localSet = global.gateway?.getLocalConnections?.(recipientUser);
      }

      if (localSet && localSet.size) {
        let deliveredCount = 0;
        for (const client of localSet) {
          if (client && client.readyState === 1) {
            const recipientSessionId = client._sessionId;
            if (recipientSessionId) {
              const recipientState = await ConnectionStateManager.getState(recipientSessionId);
              let isAuthed = !!recipientState?.hasAuthenticated;
              if (!isAuthed) {
                const userAuth = await ConnectionStateManager.getUserAuthState(recipientUser);
                isAuthed = !!userAuth?.hasAuthenticated;
              }
              if (isAuthed) {
                // Use cross-instance delivery
                const recipientPqSessionId = client._pqSessionId;
                if (recipientPqSessionId) {
                  const recipientPqSession = await getPQSession(recipientPqSessionId);
                  if (recipientPqSession) {
                    try {
                      await sendPQEncryptedResponse(client, recipientPqSession, parsedMessage);
                      deliveredCount++;
                      cryptoLogger.debug('[CROSS-INSTANCE] Delivered via PQ envelope', {
                        recipient: recipientUser.slice(0, 8) + '...',
                        session: recipientSessionId.slice(0, 8) + '...'
                      });
                    } catch (err) {
                      cryptoLogger.error('[CROSS-INSTANCE] PQ envelope failed', {
                        recipient: recipientUser.slice(0, 8) + '...',
                        session: recipientSessionId.slice(0, 8) + '...',
                        error: err.message
                      });
                    }
                  } else {
                    cryptoLogger.warn('[CROSS-INSTANCE] No PQ session', {
                      recipient: recipientUser.slice(0, 8) + '...',
                      session: recipientSessionId.slice(0, 8) + '...'
                    });
                  }
                } else {
                  cryptoLogger.warn('[CROSS-INSTANCE] No PQ session ID', {
                    recipient: recipientUser.slice(0, 8) + '...',
                    session: recipientSessionId.slice(0, 8) + '...'
                  });
                }
              }
            }
          }
        }
        if (deliveredCount > 0) {
          logDeliveryEvent('cross-instance-delivered', {
            username: recipientUser.slice(0, 8) + '...',
            count: deliveredCount
          });
        } else {
          // No local connections found - message will be handled by offline queue at origin
          cryptoLogger.debug('[CROSS-INSTANCE] No local connections found', {
            recipient: recipientUser.slice(0, 8) + '...',
            localSetSize: localSet?.size || 0,
            sender: senderUser?.slice(0, 8) + '...'
          });
        }
      } else {
        // User not found locally message may be delivered by another server
        cryptoLogger.debug('[CROSS-INSTANCE] No local connections for user', {
          recipient: recipientUser.slice(0, 8) + '...',
          sender: senderUser?.slice(0, 8) + '...'
        });
      }
    });
  } catch (error) {
    logError(error, { operation: 'pattern-subscriber-setup' });
  }

  // Set up periodic cleanup
  blockTokenCleanupInterval = setInterval(async () => {
    try {
      await BlockingDatabase.cleanupExpiredTokens();
    } catch (error) {
      logError(error, { operation: 'block-token-cleanup' });
    }
  }, SERVER_CONSTANTS.BLOCK_TOKEN_CLEANUP_INTERVAL);

  // Set up status logging
  statusLogInterval = setInterval(async () => {
    try {
      const stats = await rateLimitMiddleware.getStats();
      const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();

      const userMessageLimiters = stats?.users?.messageLimiters || 0;
      const userBundleLimiters = stats?.users?.bundleLimiters || 0;
      const userAuthLimiters = stats?.users?.authLimiters || 0;
      const activeUserLimiters = stats?.users?.activeLimiters || 0;
      const hasUserLimiters = userMessageLimiters > 0 || userBundleLimiters > 0 || userAuthLimiters > 0;

      if (globalStatus.isBlocked || hasUserLimiters) {
        logRateLimitEvent('status-report', {
          globalConnectionBlocked: globalStatus.isBlocked,
          globalConnectionAttempts: globalStatus.attempts,
          activeUserLimiters,
        });
      } else {
        clearInterval(statusLogInterval);
        statusLogInterval = null;
      }
    } catch (error) {
      logError(error, { operation: 'rate-limit-status' });
    }
  }, SERVER_CONSTANTS.STATUS_LOG_INTERVAL);

  return wss;
}

async function prepareWorkerContext() {
  const flatKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPair();

  serverHybridKeyPair = {
    kyber: {
      publicKey: flatKeyPair.mlKemPublicKey,
      secretKey: flatKeyPair.mlKemSecretKey
    },
    dilithium: {
      publicKey: flatKeyPair.mlDsaPublicKey,
      secretKey: flatKeyPair.mlDsaSecretKey
    },
    x25519: {
      publicKey: flatKeyPair.x25519PublicKey,
      secretKey: flatKeyPair.x25519SecretKey
    }
  };

  initializeEnvelopeHandler(serverHybridKeyPair);
  const authHandler = new authentication.AccountAuthHandler(serverHybridKeyPair);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverHybridKeyPair, null, ServerConfig);

  return {
    serverHybridKeyPair,
    authHandler,
    serverAuthHandler,
  };
}


async function onServerReady({ server: httpsServer, wss: wsServer, context, workerId, tls }) {
  server = httpsServer;
  wss = wsServer;
  serverHybridKeyPair = context.serverHybridKeyPair;

  server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
      cryptoLogger.error('[SECURITY] Port already in use', {
        port: ServerConfig.PORT,
        serverId: process.env.SERVER_ID,
        message: 'Exiting server'
      });
      logError(error, {
        operation: 'server-listen',
        port: ServerConfig.PORT,
        critical: true
      });
      process.exit(1);
    } else {
      cryptoLogger.error('[SECURITY] Server error', error);
      logError(error, { operation: 'server-error' });
    }
  });

  server.listen(ServerConfig.PORT, process.env.BIND_ADDRESS || '127.0.0.1', async () => {
    const actualPort = server.address().port;

    logEvent('server-started', {
      port: actualPort,
      workerId,
      tlsSource: tls?.source || 'unknown',
      serverId: process.env.SERVER_ID
    });
    cryptoLogger.info('[SERVER] Server listening', {
      port: actualPort,
      serverId: process.env.SERVER_ID,
      address: process.env.BIND_ADDRESS || '127.0.0.1'
    });

    const wasDynamicPort = (ServerConfig.PORT === 0 || ServerConfig.PORT === '0');
    if (wasDynamicPort) {
      process.env.PORT = actualPort.toString();
      cryptoLogger.info('[SERVER] Updated PORT env to actual assigned port', { actualPort });
    }

    if (process.env.ENABLE_CLUSTERING === 'true') {
      try {
        logEvent('cluster-init', { message: 'Initializing server clustering' });

        const clusterManager = await initializeCluster({
          serverHybridKeyPair,
          serverId: process.env.SERVER_ID,
          isPrimary: process.env.CLUSTER_PRIMARY === 'true' ? true : null,
          autoApprove: process.env.CLUSTER_AUTO_APPROVE === 'true',
        });

        if (wasDynamicPort && clusterManager) {
          await clusterManager.updateServerPort(actualPort);
        }

        logEvent('cluster-ready', {
          serverId: clusterManager.serverId,
          isPrimary: clusterManager.isPrimary,
          isApproved: clusterManager.isApproved
        });
      } catch (error) {
        logError(error, { operation: 'cluster-initialization' });
        cryptoLogger.error('[CLUSTER] Failed to initialize clustering', error);
      }
    } else {
      cryptoLogger.info('[CLUSTER] Clustering disabled (set ENABLE_CLUSTERING=true in env to enable)');
    }
  });

  // Attach WebSocket gateway
  const gateway = attachGateway({
    wss,
    serverHybridKeyPair,
    serverId: process.env.SERVER_ID || 'default',
    config: {
      bandwidthQuota: SERVER_CONSTANTS.BANDWIDTH_QUOTA,
      bandwidthWindowMs: SERVER_CONSTANTS.BANDWIDTH_WINDOW,
      messageHardLimitPerMinute: SERVER_CONSTANTS.MESSAGE_HARD_LIMIT_PER_MINUTE,
      heartbeatIntervalMs: SERVER_CONSTANTS.HEARTBEAT_INTERVAL,
    },
    onMessage: async ({ ws, sessionId, message }) => {
      await handleWebSocketMessage({ ws, sessionId, message, context });
    },
  });

  // Store gateway reference for cross-instance delivery
  global.gateway = gateway;
  attachP2PSignaling(wss, cryptoLogger);
}

async function handleWebSocketMessage({ ws, sessionId, message, context }) {
  const { authHandler, serverAuthHandler } = context;

  try {
    const msgString = message.toString().trim();
    if (msgString.length === 0) { return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Empty message' }); }

    if (msgString.includes('check-user-exists')) {
      cryptoLogger.debug('[AUTH] Received check-user-exists message', {
        sessionId: sessionId?.slice(0, 8) + '...'
      });
    }

    let testParse;
    try {
      testParse = JSON.parse(msgString);
    } catch (_parseError) {
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid JSON format' });
    }

    if (typeof testParse !== 'object' || testParse === null) { return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message format - expected object' }); }

    const normalizedMessage = testParse;
    const state = await ConnectionStateManager.getState(sessionId);

    if (!state) {
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Session not found' });
    }

    switch (normalizedMessage.type) {
      case SignalType.ACCOUNT_SIGN_UP:
      case SignalType.ACCOUNT_SIGN_IN:
        await authHandler.processAuthRequest(ws, msgString);
        break;
      case SignalType.DEVICE_PROOF_RESPONSE:
        await authHandler.processDeviceProofResponse(ws, msgString);
        break;
      case SignalType.TOKEN_VALIDATION:
        try {
          const { accessToken, refreshToken } = normalizedMessage;

          if (!accessToken || typeof accessToken !== 'string') {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Invalid access token'
            });
          }

          if (!refreshToken || typeof refreshToken !== 'string') {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Invalid refresh token'
            });
          }

          const { TokenService } = await import('./authentication/token-service.js');

          let hashedUserId;
          try {
            const accessPayload = await TokenService.verifyToken(accessToken, 'access');
            hashedUserId = accessPayload.sub;
          } catch (error) {
            cryptoLogger.warn('[TOKEN-VALIDATION] Access token verification failed', { error: error.message });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Invalid access token'
            });
          }

          let username;
          try {
            username = await withRedisClient(async (client) => {
              const mappingKey = `userId:hash:${hashedUserId}`;
              return await client.get(mappingKey);
            });
          } catch (error) {
            cryptoLogger.error('[TOKEN-VALIDATION] Failed to lookup username from token hash', { error: error.message });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Token validation error'
            });
          }

          if (!username) {
            cryptoLogger.warn('[TOKEN-VALIDATION] No username found for hashed user ID', {
              hashedUserId: hashedUserId?.slice(0, 8) + '...'
            });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'User not found'
            });
          }

          const userRecord = await UserDatabase.loadUser(username);
          if (!userRecord) {
            cryptoLogger.warn('[TOKEN-VALIDATION] Account missing in DB for resolved username', { username: username.slice(0, 8) + '...' });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Account not found'
            });
          }

          let accessPayload;
          let refreshPayload;
          try {
            accessPayload = await TokenService.verifyToken(accessToken, 'access', true);
            refreshPayload = await TokenService.verifyToken(refreshToken, 'refresh');
          } catch (_e) {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Invalid token payload'
            });
          }

          if (accessPayload.sub !== refreshPayload.sub) {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Subject mismatch'
            });
          }

          const tokensValid = await TokenService.validateTokens(accessToken, refreshToken, username);

          if (!tokensValid) {
            cryptoLogger.warn('[TOKEN-VALIDATION] Token validation failed for extracted user', {
              username: username.slice(0, 4) + '...'
            });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Token validation failed'
            });
          }

          try {
            const { TokenSecurityManager } = await import('./authentication/token-security.js');
            const secCheck = await TokenSecurityManager.validateTokenSecurity(accessToken, { userId: hashedUserId, initialLogin: true });
            if (!secCheck.valid) {
              const reason = secCheck.reason || 'security_policy_violation';
              const friendly = {
                token_too_old: 'Token was issued too long ago',
                token_blacklisted: 'Token has been revoked',
                invalid_token_format: 'Invalid token format',
                suspicious_token_usage: 'Suspicious token activity detected',
                validation_error: 'Token validation error',
              };
              return await sendSecureMessage(ws, {
                type: SignalType.TOKEN_VALIDATION_RESPONSE,
                valid: false,
                error: reason,
                message: friendly[reason] || 'Security policy violation'
              });
            }
          } catch (_e) {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Token validation error'
            });
          }
          try {
            await ConnectionStateManager.forceCleanupUserSessions(username);
          } catch (_cleanupError) {
          }

          // Restore authentication to WebSocket session
          ws._username = username;
          ws._hasAuthenticated = true;

          // Update connection state in Redis with authenticated status
          await ConnectionStateManager.updateState(sessionId, {
            username: username,
            hasAuthenticated: true,
            hasServerAuth: false,
            pqSessionId: ws._pqSessionId || null,
            connectedAt: Date.now(),
            lastActivity: Date.now()
          });

          // Register connection for local message delivery on this server
          try {
            if (global.gateway?.addLocalConnection) {
              await global.gateway.addLocalConnection(username, ws);
            }
          } catch (e) {
            cryptoLogger.warn('[TOKEN-VALIDATION] addLocalConnection failed', { error: e?.message });
          }

          // Mark user as online on this server
          try {
            await presenceService.setUserOnline(username, sessionId);
          } catch (e) {
            cryptoLogger.warn('[TOKEN-VALIDATION] setUserOnline failed', { error: e?.message });
          }

          cryptoLogger.info('[TOKEN-VALIDATION] Token validation successful', {
            username: username.slice(0, 4) + '...',
            sessionId: sessionId?.slice(0, 8) + '...'
          });

          // Send success response with username extracted from validated tokens
          await sendSecureMessage(ws, {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            valid: true,
            username: username
          });
        } catch (error) {
          cryptoLogger.error('[TOKEN-VALIDATION] Validation failed', { error: error.message });
          await sendSecureMessage(ws, {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            valid: false,
            error: 'Token validation error'
          });
        }
        break;

      case SignalType.AUTH_RECOVERY:
        cryptoLogger.info('[AUTH-RECOVERY] Received auth recovery request', {
          username: normalizedMessage.username?.slice(0, 4) + '...'
        });
        try {
          const username = normalizedMessage.username;
          if (!username || typeof username !== 'string') {
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              message: 'Invalid username for recovery'
            });
          }

          const user = await UserDatabase.loadUser(username);
          if (!user) {
            cryptoLogger.warn('[AUTH-RECOVERY] User not found', { username });
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              message: 'User not found'
            });
          }

          const authState = await ConnectionStateManager.getUserAuthState(username);
          if (!authState || !authState.hasAuthenticated) {
            cryptoLogger.warn('[AUTH-RECOVERY] No valid auth state found, requiring full authentication', { username });
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              message: 'Please sign in with your credentials',
              requiresFullAuth: true
            });
          }

          try {
            await ConnectionStateManager.forceCleanupUserSessions(username);
            cryptoLogger.info('[AUTH-RECOVERY] Cleaned up old session for user', {
              username: username.slice(0, 4) + '...'
            });
          } catch (cleanupError) {
            cryptoLogger.warn('[AUTH-RECOVERY] Failed to cleanup old session, continuing', {
              error: cleanupError?.message
            });
          }

          // Restore authentication to WebSocket session
          ws._username = username;
          ws._hasAuthenticated = true;

          // Update connection state in Redis with authenticated status
          await ConnectionStateManager.updateState(sessionId, {
            username: username,
            hasAuthenticated: true,
            hasServerAuth: authState.hasServerAuth || false,
            pqSessionId: ws._pqSessionId || null,
            connectedAt: Date.now(),
            lastActivity: Date.now()
          });

          // Register connection for local message delivery on this server
          try {
            if (global.gateway?.addLocalConnection) {
              await global.gateway.addLocalConnection(username, ws);
            }
          } catch (e) {
            cryptoLogger.warn('[AUTH-RECOVERY] addLocalConnection failed', { error: e?.message });
          }

          // Mark user as online on this server
          try {
            await presenceService.setUserOnline(username, sessionId);
          } catch (e) {
            cryptoLogger.warn('[AUTH-RECOVERY] setUserOnline failed', { error: e?.message });
          }

          cryptoLogger.info('[AUTH-RECOVERY] Auth state restored successfully', {
            username: username.slice(0, 4) + '...',
            sessionId: sessionId?.slice(0, 8) + '...'
          });

          await sendSecureMessage(ws, {
            type: SignalType.AUTH_SUCCESS,
            message: 'Authentication restored',
            recovered: true
          });
        } catch (error) {
          cryptoLogger.error('[AUTH-RECOVERY] Recovery failed', { error: error.message });
          await sendSecureMessage(ws, {
            type: SignalType.AUTH_ERROR,
            message: 'Recovery failed'
          });
        }
        break;

      case SignalType.SERVER_PASSWORD:
        await serverAuthHandler.handleServerPassword(ws, normalizedMessage);
        break;

      case SignalType.ENCRYPTED_MESSAGE:
        await handleEncryptedMessage({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.STORE_OFFLINE_MESSAGE:
        await handleStoreOfflineMessage({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.RETRIEVE_OFFLINE_MESSAGES:
        await handleRetrieveOfflineMessages({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.RATE_LIMIT_STATUS:
        await handleRateLimitStatus({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.PASSWORD_HASH_RESPONSE: {
        const username = state.username || ws.clientState?.username;
        if (!username) {
          cryptoLogger.error('[AUTH] Password hash received but no username in state');
          return await sendSecureMessage(ws, {
            type: SignalType.AUTH_ERROR,
            message: 'Authentication state error'
          });
        }
        await authHandler.handlePasswordHash(ws, username, normalizedMessage.passwordHash);
        break;
      }

      case 'client-error':
        cryptoLogger.error('[CLIENT-ERROR] Client reported error', {
          sessionId: sessionId?.slice(0, 8) + '...',
          username: state.username?.slice(0, 4) + '...' || 'unknown',
          error: normalizedMessage.error
        });
        await sendSecureMessage(ws, {
          type: 'error-acknowledged',
          timestamp: Date.now()
        });
        break;

      case SignalType.PASSPHRASE_HASH:
        {
          const username = state.username || ws.clientState?.username;
          if (!username) {
            cryptoLogger.error('[AUTH] Passphrase hash received but no username in state');
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              message: 'Authentication state error'
            });
          }
          await authHandler.handlePassphrase(ws, username, normalizedMessage.passphraseHash, false);
        }
        break;

      case SignalType.LIBSIGNAL_PUBLISH_BUNDLE:
        // Store Signal Protocol bundle for user
        await handleBundlePublish({
          ws,
          parsed: normalizedMessage,
          state,
          context,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case 'signal-bundle-failure':
        // Client reports Signal bundle generation failure
        await handleBundleFailure({
          ws,
          parsed: normalizedMessage,
          state,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.LIBSIGNAL_REQUEST_BUNDLE:
        // Client requesting another user's Signal Protocol bundle
        await handleBundleRequest({
          ws,
          parsed: normalizedMessage,
          state,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.HYBRID_KEYS_UPDATE:
        // Store hybrid public keys for user
        if (!state.username) {
          cryptoLogger.error('[AUTH] Hybrid keys update received but no username in state');
          return await sendSecureMessage(ws, {
            type: 'keys-stored',
            success: false,
            error: 'Authentication state error'
          });
        }

        cryptoLogger.info('[AUTH] Hybrid keys update received', {
          username: state.username.slice(0, 8) + '...'
        });

        try {
          // Decrypt the user data payload to extract hybrid keys
          const userPayload = await CryptoUtils.Hybrid.decryptIncoming(
            normalizedMessage.userData,
            {
              kyberSecretKey: serverHybridKeyPair.kyber.secretKey,
              x25519SecretKey: serverHybridKeyPair.x25519.secretKey
            }
          );

          // Parse the decrypted payload to extract public keys
          let parsedKeys;
          if (userPayload.payloadJson) {
            parsedKeys = userPayload.payloadJson;
          } else {
            const decoded = new TextDecoder().decode(userPayload.payload);
            parsedKeys = JSON.parse(decoded);
          }

          // Extract public keys from the payload and sanitize
          const extracted = {
            kyberPublicBase64: parsedKeys.kyberPublicBase64 || '',
            dilithiumPublicBase64: parsedKeys.dilithiumPublicBase64 || '',
            x25519PublicBase64: parsedKeys.x25519PublicBase64 || ''
          };
          const hybridPublicKeys = sanitizeHybridKeysServer(extracted);

          cryptoLogger.debug('[AUTH] Sanitized hybrid keys', {
            hasKyber: !!hybridPublicKeys.kyberPublicBase64,
            hasDilithium: !!hybridPublicKeys.dilithiumPublicBase64,
            hasX25519: !!hybridPublicKeys.x25519PublicBase64
          });

          // Store keys in the users table via Postgres
          const { UserDatabase } = await import('./database/database.js');
          await UserDatabase.updateHybridPublicKeys(state.username, hybridPublicKeys);

          cryptoLogger.info('[AUTH] Hybrid keys stored successfully', {
            username: state.username.slice(0, 8) + '...',
            dilithiumPrefix: hybridPublicKeys.dilithiumPublicBase64.slice(0, 6) + '...',
            dilithiumSuffix: '...' + hybridPublicKeys.dilithiumPublicBase64.slice(-6)
          });

          await sendSecureMessage(ws, {
            type: 'keys-stored',
            success: true
          });
        } catch (error) {
          cryptoLogger.error('[AUTH] Failed to process hybrid keys', {
            username: state.username,
            error: error.message
          });
          await sendSecureMessage(ws, {
            type: 'keys-stored',
            success: false,
            error: 'Failed to process keys'
          });
        }
        break;

      case SignalType.SESSION_RESET_REQUEST:
        // Forward session reset request to the target user
        await handleSessionResetRequest({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.SESSION_ESTABLISHED:
        // Forward session establishment confirmation to the target user
        await handleSessionEstablished({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.SERVER_LOGIN:
        // Route to server authentication handler
        if (normalizedMessage.resetType) {
          await handleServerLogin({ ws, sessionId, parsed: normalizedMessage, state });
        } else {
          // Server password authentication
          await serverAuthHandler.handleServerAuthentication(
            ws,
            JSON.stringify(normalizedMessage),
            state
          );
        }
        break;

      case SignalType.REQUEST_SERVER_PUBLIC_KEY:
        await sendSecureMessage(ws, {
          type: SignalType.SERVER_PUBLIC_KEY,
          serverId: process.env.SERVER_ID || 'default',
          hybridKeys: {
            kyberPublicBase64: CryptoUtils.Hybrid.exportKyberPublicBase64(serverHybridKeyPair.kyber.publicKey),
            dilithiumPublicBase64: CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey),
            x25519PublicBase64: CryptoUtils.Hybrid.exportX25519PublicBase64(serverHybridKeyPair.x25519.publicKey)
          },
        });
        break;

      case SignalType.REQUEST_MESSAGE_HISTORY:
        await handleMessageHistory({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.CHECK_USER_EXISTS:
        // Require authentication to prevent user enumeration attacks
        if (!state?.hasAuthenticated || !state?.username) {
          cryptoLogger.warn('[CHECK_USER_EXISTS] Rejected - not authenticated');
          return await sendSecureMessage(ws, {
            type: SignalType.ERROR,
            message: 'Authentication required'
          });
        }
        await handleCheckUserExists({ ws, sessionId, parsed: normalizedMessage, state, context });
        break;

      case SignalType.USER_DISCONNECT: {
        // User initiated disconnect via secure control message
        const payloadUsername = typeof normalizedMessage.username === 'string' ? normalizedMessage.username.trim() : null;
        const stateUsername = state?.username;

        if (!state?.hasAuthenticated || !stateUsername) {
          cryptoLogger.warn('[USER-DISCONNECT] Rejected - not authenticated', {
            sessionId: sessionId?.slice(0, 8) + '...'
          });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
        }

        if (!payloadUsername || payloadUsername !== stateUsername) {
          cryptoLogger.warn('[USER-DISCONNECT] Username mismatch', {
            sessionId: sessionId?.slice(0, 8) + '...',
            stateUsername: stateUsername.slice(0, 4) + '...',
            payloadUsername: payloadUsername ? payloadUsername.slice(0, 4) + '...' : null
          });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid disconnect request' });
        }

        logEvent('user-disconnect', {
          username: stateUsername.slice(0, 4) + '...',
          sessionId: sessionId?.slice(0, 8) + '...',
          timestamp: normalizedMessage.timestamp || Date.now()
        });

        try {
          ws.close(1000, 'User disconnect');
        } catch (_e) {
        }

        break;
      }

      case SignalType.P2P_FETCH_PEER_CERT: {
        try {
          if (!state?.hasAuthenticated || !state?.username) {
            return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
          }
          const target = typeof normalizedMessage?.username === 'string' ? normalizedMessage.username.trim() : '';
          if (!target || target.length > 128) {
            return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid username' });
          }
          const { UserDatabase } = await import('./database/database.js');
          const keys = await UserDatabase.getHybridPublicKeys(target);
          if (!keys) {
            return await sendSecureMessage(ws, { type: SignalType.P2P_PEER_CERT, username: target, error: 'NOT_FOUND' });
          }
          if (!keys || !keys.kyberPublicBase64 || !keys.dilithiumPublicBase64) {
            return await sendSecureMessage(ws, { type: SignalType.P2P_PEER_CERT, username: target, error: 'KEYS_MISSING' });
          }
          const issuedAt = Date.now();
          const expiresAt = issuedAt + 5 * 60 * 1000;
          const proof = CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey);
          const canonical = JSON.stringify({
            username: target,
            dilithiumPublicKey: keys.dilithiumPublicBase64,
            kyberPublicKey: keys.kyberPublicBase64,
            x25519PublicKey: keys.x25519PublicBase64 || '',
            proof,
            issuedAt,
            expiresAt
          });
          const signatureBytes = await CryptoUtils.Dilithium.sign(new TextEncoder().encode(canonical), serverHybridKeyPair.dilithium.secretKey);
          const signature = Buffer.from(signatureBytes).toString('base64');

          await sendSecureMessage(ws, {
            type: SignalType.P2P_PEER_CERT,
            username: target,
            dilithiumPublicKey: keys.dilithiumPublicBase64,
            kyberPublicKey: keys.kyberPublicBase64,
            x25519PublicKey: keys.x25519PublicBase64 || '',
            proof,
            issuedAt,
            expiresAt,
            signature
          });
        } catch (_err) {
          try { await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to build peer certificate' }); } catch { }
        }
        break;
      }

      case SignalType.BLOCK_LIST_SYNC:
        await handleBlockListSync({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.BLOCK_TOKENS_UPDATE: {
        // Store server-side block tokens for filtering
        if (!state?.hasAuthenticated || !state?.username) {
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
        }
        try {
          const tokens = Array.isArray(normalizedMessage.blockTokens) ? normalizedMessage.blockTokens : [];
          const blockerHash = typeof normalizedMessage.blockerHash === 'string' ? normalizedMessage.blockerHash : undefined;
          const { BlockingDatabase } = await import('./database/database.js');
          await BlockingDatabase.storeBlockTokens(tokens, blockerHash);

          const { clearBlockingCache } = await import('./security/blocking.js');
          const blockedHashes = tokens.map(t => t.blockedHash).filter(Boolean);
          await clearBlockingCache(blockerHash, blockedHashes);

          await sendSecureMessage(ws, { type: 'ok', message: 'block-tokens-updated' });
        } catch (_error) {
          await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to update block tokens' });
        }
        break;
      }

      case SignalType.RETRIEVE_BLOCK_LIST:
        await handleRetrieveBlockList({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.PQ_SESSION_INIT:
      case SignalType.PQ_HANDSHAKE_INIT:
        await handlePQHandshake({ ws, sessionId, parsed: normalizedMessage, serverHybridKeyPair });
        break;

      case SignalType.PQ_HEARTBEAT_PING:
        // Post-quantum heartbeat
        await sendSecureMessage(ws, {
          type: SignalType.PQ_HEARTBEAT_PONG,
          sessionId: ws._pqSessionId || sessionId,
          timestamp: Date.now()
        });
        break;

      case SignalType.PQ_ENVELOPE:
        // Post-quantum encrypted WebSocket envelope - decrypt and process inner message
        await handlePQEnvelope({
          ws,
          sessionId,
          envelope: normalizedMessage,
          context,
          handleInnerMessage: handleWebSocketMessage
        });
        break;

      case SignalType.REGISTER: {
        const { register, signature, publicKey } = normalizedMessage.payload || {};
        const username = normalizedMessage.from;

        if (!register || !signature || !publicKey || !username) {
          cryptoLogger.warn('[REGISTER] Missing required fields');
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid registration format' });
        }

        if (register.username !== username) {
          cryptoLogger.warn('[REGISTER] Username mismatch');
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Username mismatch' });
        }

        // 1. Verify timestamp (5 minute window)
        const now = Date.now();
        if (Math.abs(now - register.timestamp) > 5 * 60 * 1000) {
          cryptoLogger.warn('[REGISTER] Stale registration', { username });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Registration expired' });
        }

        // 2. Fetch stored public keys for the user to verify identity
        const { UserDatabase } = await import('./database/database.js');
        const storedKeys = await UserDatabase.getHybridPublicKeys(username);

        if (!storedKeys || !storedKeys.dilithiumPublicBase64) {
          cryptoLogger.warn('[REGISTER] User not found or no keys', { username });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'User not found' });
        }

        // 3. Verify the provided public key matches the stored one
        if (storedKeys.dilithiumPublicBase64 !== publicKey) {
          cryptoLogger.warn('[REGISTER] Public key mismatch', { username });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid public key' });
        }

        // 4. Verify the signature
        try {
          const canonical = new TextEncoder().encode(JSON.stringify(register));
          const signatureBytes = Buffer.from(signature, 'base64');
          const publicKeyBytes = Buffer.from(publicKey, 'base64');

          const isValid = await CryptoUtils.Dilithium.verify(signatureBytes, canonical, publicKeyBytes);

          if (!isValid) {
            cryptoLogger.warn('[REGISTER] Invalid signature', { username });
            return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid signature' });
          }
        } catch (err) {
          cryptoLogger.error('[REGISTER] Verification error', { username, error: err.message });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Verification failed' });
        }

        // 5. Authenticate the session
        ws._username = username;
        ws._hasAuthenticated = true;

        // Update connection state
        await ConnectionStateManager.updateState(sessionId, {
          username: username,
          hasAuthenticated: true,
          lastActivity: Date.now()
        });

        // Register for local delivery
        if (global.gateway?.addLocalConnection) {
          await global.gateway.addLocalConnection(username, ws);
        }

        cryptoLogger.info('[REGISTER] P2P signaling session authenticated', { username });
        await sendSecureMessage(ws, { type: 'register-ack', success: true });
        break;
      }

      default:
        logEvent('unknown-message-type', { type: normalizedMessage.type, sessionId });
        await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Unknown message type' });
    }
  } catch (error) {
    logError(error, { sessionId });
    try {
      await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Internal server error' });
    } catch (_sendError) {
    }
  }
}

async function handleEncryptedMessage({ ws, sessionId, parsed, state }) {
  // Strict authentication validation
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[MESSAGE-FORWARD] Rejected message from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      hasState: !!state,
      hasAuth: state?.hasAuthenticated
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  // Verify username is present in state
  if (!state.username || typeof state.username !== 'string') {
    cryptoLogger.error('[MESSAGE-FORWARD] Missing username in authenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      hasUsername: !!state.username
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid session state' });
  }

  // Verify WebSocket session matches state
  if (ws._username && ws._username !== state.username) {
    cryptoLogger.error('[MESSAGE-FORWARD] Session username mismatch', {
      sessionId: sessionId?.slice(0, 8) + '...',
      wsUsername: ws._username?.slice(0, 4) + '...',
      stateUsername: state.username?.slice(0, 4) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Session mismatch' });
  }

  const { to: toUser, encryptedPayload } = parsed;
  if (!toUser || !encryptedPayload) {
    cryptoLogger.error('[MESSAGE-FORWARD] Invalid message format', {
      hasTo: !!toUser,
      hasPayload: !!encryptedPayload
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message format' });
  }

  const normalizedMessage = {
    type: parsed.type,
    to: toUser,
    encryptedPayload,
    from: state.username
  };

  const senderBlockedByRecipient = await checkBlocking(state.username, toUser);
  const recipientBlockedBySender = await checkBlocking(toUser, state.username);

  if (senderBlockedByRecipient || recipientBlockedBySender) {
    logDeliveryEvent('message-blocked', {
      from: state.username,
      to: toUser,
      reason: senderBlockedByRecipient ? 'sender-blocked-by-recipient' : 'recipient-blocked-by-sender'
    });
    return await sendSecureMessage(ws, { type: 'ok', message: 'blocked' });
  }

  // Save message to database
  try {
    await MessageDatabase.saveMessageInDB(normalizedMessage, serverHybridKeyPair);
  } catch (error) {
    logError(error, { operation: 'save-message' });
  }

  cryptoLogger.debug('[MESSAGE-FORWARD] Forwarding message', {
    from: state.username.slice(0, 8) + '...',
    to: toUser.slice(0, 8) + '...'
  });


  let localSet = global.gateway?.getLocalConnections?.(toUser);
  let localDeliveryAttempted = false;

  if ((!localSet || localSet.size === 0)) {
    await new Promise(r => setTimeout(r, 150));
    localSet = global.gateway?.getLocalConnections?.(toUser);
  }

  if (localSet && localSet.size) {
    localDeliveryAttempted = true;
    let deliveredCount = 0;

    for (const client of localSet) {
      if (client && client.readyState === 1) {
        const recipientSessionId = client._sessionId;

        if (recipientSessionId) {
          const recipientState = await ConnectionStateManager.getState(recipientSessionId);
          let isAuthed = !!recipientState?.hasAuthenticated;
          if (!isAuthed) {
            const userAuth = await ConnectionStateManager.getUserAuthState(toUser);
            isAuthed = !!userAuth?.hasAuthenticated;
          }

          if (isAuthed) {
            const recipientPqSessionId = client._pqSessionId;
            if (recipientPqSessionId) {
              const recipientPqSession = await getPQSession(recipientPqSessionId);

              if (recipientPqSession) {
                try {
                  await sendPQEncryptedResponse(client, recipientPqSession, normalizedMessage);
                  deliveredCount++;
                  cryptoLogger.debug('[MESSAGE-FORWARD] Delivered via PQ envelope', {
                    session: recipientSessionId.slice(0, 8) + '...'
                  });
                } catch (err) {
                  cryptoLogger.error('[MESSAGE-FORWARD] PQ envelope failed', {
                    session: recipientSessionId.slice(0, 8) + '...',
                    error: err.message
                  });
                }
              } else {
                cryptoLogger.warn('[MESSAGE-FORWARD] No PQ session', {
                  session: recipientSessionId.slice(0, 8) + '...'
                });
              }
            } else {
              cryptoLogger.warn('[MESSAGE-FORWARD] No PQ session ID', {
                session: recipientSessionId.slice(0, 8) + '...'
              });
            }
          }
        }
      }
    }
    if (deliveredCount > 0) {
      await sendSecureMessage(ws, { type: 'ok', message: 'relayed' });
      logDeliveryEvent('local-delivery', { to: toUser, deliveredCount });
      return;
    }
  }

  let isOnline = await presenceService.isUserOnline(toUser);
  if (!isOnline) {
    await new Promise(r => setTimeout(r, 100));
    isOnline = await presenceService.isUserOnline(toUser);
  }

  if (isOnline) {
    cryptoLogger.debug('[MESSAGE-FORWARD] User online but not local, trying cross-instance', {
      from: state.username.slice(0, 8) + '...',
      to: toUser.slice(0, 8) + '...',
      localDeliveryAttempted
    });

    try {
      await presenceService.publishToUser(toUser, JSON.stringify(normalizedMessage));
      await sendSecureMessage(ws, { type: 'ok', message: 'relayed' });
      logDeliveryEvent('cross-instance-published', { to: toUser });
      return;
    } catch (error) {
      logError(error, { operation: 'cross-instance-delivery' });
      await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Delivery failed' });
      return;
    }
  }

  // User is offline, queue the message
  cryptoLogger.debug('[MESSAGE-FORWARD] User offline, queueing message', {
    from: state.username.slice(0, 8) + '...',
    to: toUser.slice(0, 8) + '...',
    localDeliveryAttempted,
    isOnline
  });

  // Queue for offline delivery
  try {
    const success = await MessageDatabase.queueOfflineMessage(toUser, normalizedMessage);
    if (success) {
      await sendSecureMessage(ws, { type: 'ok', message: 'queued' });
      logDeliveryEvent('offline-queued', { to: toUser });
    } else {
      await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to queue message' });
    }
  } catch (error) {
    logError(error, { operation: 'offline-queue' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to queue message' });
  }
}

async function handleSessionResetRequest({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[SESSION-RESET] Rejected from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  if (!state.username || typeof state.username !== 'string') {
    cryptoLogger.error('[SESSION-RESET] Missing username in authenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid session state' });
  }

  const { targetUsername } = parsed;
  if (!targetUsername || typeof targetUsername !== 'string') {
    cryptoLogger.error('[SESSION-RESET] Invalid target username', {
      from: state.username.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid target username' });
  }

  cryptoLogger.info('[SESSION-RESET] Forwarding session reset request', {
    from: state.username.slice(0, 8) + '...',
    to: targetUsername.slice(0, 8) + '...'
  });

  const resetNotification = {
    type: SignalType.SESSION_RESET_REQUEST,
    from: state.username,
    reason: 'stale-keys-detected'
  };

  // Try local delivery
  let localSet = global.gateway?.getLocalConnections?.(targetUsername);

  if ((!localSet || localSet.size === 0)) {
    await new Promise(r => setTimeout(r, 150));
    localSet = global.gateway?.getLocalConnections?.(targetUsername);
  }

  if (localSet && localSet.size) {
    let deliveredCount = 0;
    for (const client of localSet) {
      if (client && client.readyState === 1) {
        const recipientSessionId = client._sessionId;
        if (recipientSessionId) {
          const recipientState = await ConnectionStateManager.getState(recipientSessionId);
          let isAuthed = !!recipientState?.hasAuthenticated;
          if (!isAuthed) {
            const userAuth = await ConnectionStateManager.getUserAuthState(targetUsername);
            isAuthed = !!userAuth?.hasAuthenticated;
          }
          if (isAuthed) {
            const recipientPqSessionId = client._pqSessionId;
            if (recipientPqSessionId) {
              const recipientPqSession = await getPQSession(recipientPqSessionId);
              if (recipientPqSession) {
                try {
                  await sendPQEncryptedResponse(client, recipientPqSession, resetNotification);
                  deliveredCount++;
                } catch (err) {
                  cryptoLogger.error('[SESSION-RESET] Delivery failed', {
                    session: recipientSessionId.slice(0, 8) + '...',
                    error: err.message
                  });
                }
              } else {
              }
            }
          }
        }
      }
    }
    if (deliveredCount > 0) {
      cryptoLogger.info('[SESSION-ESTABLISHED] Notification delivered', {
        from: state.username.slice(0, 8) + '...',
        to: targetUsername.slice(0, 8) + '...',
        count: deliveredCount
      });
    }
  }

  await sendSecureMessage(ws, { type: 'ok', message: 'session-reset-sent' });
}

async function handleSessionEstablished({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated) {
    cryptoLogger.warn('[SESSION-ESTABLISHED] Rejected from unauthenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  if (!state.username || typeof state.username !== 'string') {
    cryptoLogger.error('[SESSION-ESTABLISHED] Missing username in authenticated session', {
      sessionId: sessionId?.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid session state' });
  }

  const targetUsername = parsed.username;
  if (!targetUsername || typeof targetUsername !== 'string') {
    cryptoLogger.error('[SESSION-ESTABLISHED] Invalid target username', {
      from: state.username.slice(0, 8) + '...'
    });
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid target username' });
  }

  cryptoLogger.info('[SESSION-ESTABLISHED] Forwarding session establishment confirmation', {
    from: state.username.slice(0, 8) + '...',
    to: targetUsername.slice(0, 8) + '...'
  });

  const sessionEstablishedNotification = {
    type: SignalType.SESSION_ESTABLISHED,
    from: state.username,
    username: state.username
  };

  // Try local delivery
  let localSet = global.gateway?.getLocalConnections?.(targetUsername);

  if ((!localSet || localSet.size === 0)) {
    await new Promise(r => setTimeout(r, 50));
    localSet = global.gateway?.getLocalConnections?.(targetUsername);
  }

  if (localSet && localSet.size) {
    let deliveredCount = 0;
    for (const client of localSet) {
      if (client && client.readyState === 1) {
        const recipientSessionId = client._sessionId;
        if (recipientSessionId) {
          const recipientState = await ConnectionStateManager.getState(recipientSessionId);
          let isAuthed = !!recipientState?.hasAuthenticated;
          if (!isAuthed) {
            const userAuth = await ConnectionStateManager.getUserAuthState(targetUsername);
            isAuthed = !!userAuth?.hasAuthenticated;
          }
          if (isAuthed) {
            const recipientPqSessionId = client._pqSessionId;
            if (recipientPqSessionId) {
              const recipientPqSession = await getPQSession(recipientPqSessionId);
              if (recipientPqSession) {
                try {
                  await sendPQEncryptedResponse(client, recipientPqSession, sessionEstablishedNotification);
                  deliveredCount++;
                } catch (err) {
                  cryptoLogger.error('[SESSION-ESTABLISHED] Delivery failed', {
                    session: recipientSessionId.slice(0, 8) + '...',
                    error: err.message
                  });
                }
              } else { }
            }
          }
        }
      }
    }
    if (deliveredCount > 0) {
      cryptoLogger.info('[SESSION-ESTABLISHED] Notification delivered', {
        from: state.username.slice(0, 8) + '...',
        to: targetUsername.slice(0, 8) + '...',
        count: deliveredCount
      });
    }
  }

  await sendSecureMessage(ws, { type: 'ok', message: 'session-established-sent' });
}

async function handleStoreOfflineMessage({ ws, parsed, state }) {
  if (!state?.hasAuthenticated) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const { messageId, to, encryptedPayload } = parsed;
  if (!messageId || !to || !encryptedPayload) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message data' });
  }

  const senderBlockedByRecipient = await checkBlocking(state.username, to);
  const recipientBlockedBySender = await checkBlocking(to, state.username);

  if (senderBlockedByRecipient || recipientBlockedBySender) {
    logDeliveryEvent('offline-message-blocked', {
      from: state.username,
      to,
      reason: senderBlockedByRecipient ? 'sender-blocked-by-recipient' : 'recipient-blocked-by-sender'
    });
    return await sendSecureMessage(ws, { type: 'ok', message: 'blocked' });
  }

  try {
    const offlineMessage = {
      type: SignalType.ENCRYPTED_MESSAGE,
      to,
      encryptedPayload,
    };

    const success = await MessageDatabase.queueOfflineMessage(to, offlineMessage);
    if (success) {
      await sendSecureMessage(ws, { type: 'ok', message: 'Offline message stored' });
      logEvent('offline-message-stored', { username: state.username });
    } else {
      await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to store offline message' });
    }
  } catch (error) {
    logError(error, { operation: 'store-offline-message' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error storing offline message' });
  }
}

async function handleRetrieveOfflineMessages({ ws, state }) {
  if (!state?.hasAuthenticated) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const offlineMessages = await MessageDatabase.takeOfflineMessages(state.username, 50);

    const pqSessionId = ws._pqSessionId;
    if (pqSessionId) {
      const session = await getPQSession(pqSessionId);
      if (session) {
        const responsePayload = {
          type: SignalType.OFFLINE_MESSAGES_RESPONSE,
          messages: offlineMessages,
          count: offlineMessages.length,
        };
        await sendPQEncryptedResponse(ws, session, responsePayload);
        logEvent('offline-messages-retrieved', {
          username: state.username,
          count: offlineMessages.length,
          pqEncrypted: true
        });
      } else {
        cryptoLogger.error('[OFFLINE-MESSAGES] No PQ session');
        throw new Error('PQ session required');
      }
    } else {
      cryptoLogger.error('[OFFLINE-MESSAGES] No PQ session ID');
      throw new Error('PQ session required');
    }
  } catch (error) {
    logError(error, { operation: 'retrieve-offline-messages' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error retrieving offline messages' });
  }
}

async function handleRateLimitStatus({ ws, state }) {
  try {
    const stats = rateLimitMiddleware.getStats();
    const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();
    const userStatus = state?.username ? await rateLimitMiddleware.getUserStatus(state.username) : null;

    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      stats,
      globalConnectionStatus: globalStatus,
      userStatus,
    });
  } catch (error) {
    logError(error, { operation: 'rate-limit-status' });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error getting rate limit status' });
  }
}

async function handleServerLogin({ ws, parsed }) {
  if (parsed.resetType === 'global') {
    await rateLimitMiddleware.resetGlobalConnectionLimits();
    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      message: 'Global connection rate limits reset successfully',
    });
  } else if (parsed.resetType === 'user' && parsed.username) {
    await rateLimitMiddleware.resetUserLimits(parsed.username);
    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      message: `Rate limits reset for user: ${parsed.username}`,
    });
  } else {
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Invalid reset type or missing username',
    });
  }
}

async function handleMessageHistory({ ws, sessionId, parsed, state }) {
  if (!state?.hasAuthenticated) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  const now = Date.now();
  if (state.lastHistoryRequest && (now - state.lastHistoryRequest) < SERVER_CONSTANTS.HISTORY_REQUEST_COOLDOWN) {
    return await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Rate limited: too many history requests',
      error: 'RATE_LIMITED',
    });
  }
  await ConnectionStateManager.updateState(sessionId, { lastHistoryRequest: now });

  try {
    const { limit = 50, since } = parsed;
    const requestLimit = Math.min(Math.max(1, parseInt(limit) || 50), SERVER_CONSTANTS.MAX_HISTORY_LIMIT);

    let sinceTimestamp = null;
    if (since !== undefined) {
      const parsedSince = parseInt(since);
      if (isNaN(parsedSince) || !isFinite(parsedSince) || parsedSince < 0) {
        return await sendSecureMessage(ws, {
          type: SignalType.ERROR,
          message: 'Invalid since parameter: must be a finite positive integer timestamp',
          error: 'INVALID_SINCE_PARAMETER',
        });
      }
      sinceTimestamp = parsedSince;
    }

    const messages = await MessageDatabase.getMessagesForUser(state.username, requestLimit);
    const filteredMessages = sinceTimestamp ?
      messages.filter(msg => msg.timestamp > sinceTimestamp) :
      messages;

    await sendSecureMessage(ws, {
      type: SignalType.MESSAGE_HISTORY_RESPONSE,
      messages: filteredMessages,
      hasMore: messages.length === requestLimit,
      timestamp: Date.now(),
    });

    logEvent('message-history-requested', {
      username: state.username,
      limit: requestLimit,
      returned: filteredMessages.length
    });
  } catch (error) {
    logError(error, { operation: 'message-history' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Failed to fetch message history',
      error: 'HISTORY_FETCH_FAILED',
    });
  }
}

async function handleCheckUserExists({ ws, parsed, state, context }) {
  const { username } = parsed;

  const sendResponse = async (responseData) => {
    const pqSessionId = context?.pqSessionId || ws?._pqSessionId;
    if (pqSessionId) {
      const pqSession = await getPQSession(pqSessionId);
      if (pqSession) {
        try {
          await sendPQEncryptedResponse(ws, pqSession, responseData);
          return;
        } catch (err) {
          cryptoLogger.error('[USER-CHECK] PQ send failed', {
            error: err.message
          });
          throw err;
        }
      }
    }
    cryptoLogger.error('[USER-CHECK] No PQ session');
    throw new Error('PQ session required');
  };

  if (!username || typeof username !== 'string') {
    return await sendResponse({
      type: SignalType.USER_EXISTS_RESPONSE,
      exists: false,
      error: 'Invalid username',
    });
  }

  try {
    // Check if user exists in database
    const user = await UserDatabase.loadUser(username);

    const response = {
      type: SignalType.USER_EXISTS_RESPONSE,
      exists: !!user,
      username: username,
    };

    // Include hybrid public keys if user exists
    let sanitizedKeys = null;
    if (user && user.hybridPublicKeys) {
      try {
        // Parse and sanitize the keys before returning
        const parsedKeys = typeof user.hybridPublicKeys === 'string'
          ? JSON.parse(user.hybridPublicKeys)
          : user.hybridPublicKeys;
        sanitizedKeys = sanitizeHybridKeysServer(parsedKeys);
        response.hybridPublicKeys = sanitizedKeys;
      } catch (parseError) {
        cryptoLogger.error('[USER-CHECK] Failed to parse hybrid keys', {
          error: parseError.message
        });
      }
    }

    try {
      if (sanitizedKeys && sanitizedKeys.kyberPublicBase64 && sanitizedKeys.dilithiumPublicBase64) {
        const issuedAt = Date.now();
        const expiresAt = issuedAt + 5 * 60 * 1000;
        const proof = CryptoUtils.Hybrid.exportDilithiumPublicBase64(serverHybridKeyPair.dilithium.publicKey);
        const canonical = JSON.stringify({
          username,
          dilithiumPublicKey: sanitizedKeys.dilithiumPublicBase64,
          kyberPublicKey: sanitizedKeys.kyberPublicBase64,
          x25519PublicKey: sanitizedKeys.x25519PublicBase64 || '',
          proof,
          issuedAt,
          expiresAt
        });
        const signatureBytes = await CryptoUtils.Dilithium.sign(new TextEncoder().encode(canonical), serverHybridKeyPair.dilithium.secretKey);
        const signature = Buffer.from(signatureBytes).toString('base64');
        response.peerCertificate = {
          username,
          dilithiumPublicKey: sanitizedKeys.dilithiumPublicBase64,
          kyberPublicKey: sanitizedKeys.kyberPublicBase64,
          x25519PublicKey: sanitizedKeys.x25519PublicBase64 || '',
          proof,
          issuedAt,
          expiresAt,
          signature
        };
      }
    } catch (certErr) {
      cryptoLogger.warn('[USER-CHECK] Failed to attach peer certificate', { error: certErr?.message || String(certErr) });
    }

    await sendResponse(response);

    cryptoLogger.debug('[USER-CHECK] User existence check completed', {
      requester: state?.username?.slice(0, 8) + '...',
      target: username.slice(0, 8) + '...',
      exists: !!user,
      hasKeys: !!user?.hybridPublicKeys
    });
  } catch (error) {
    logError(error, { operation: 'check-user-exists', username });
    await sendResponse({
      type: SignalType.USER_EXISTS_RESPONSE,
      exists: false,
      error: 'Failed to check user existence',
    });
  }
}

async function handleBlockListSync({ ws, parsed, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const { encryptedBlockList, blockListHash, salt, version, lastUpdated } = parsed;

    if (!encryptedBlockList || !blockListHash || !salt) {
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        message: 'Missing encrypted block list, hash, or salt'
      });
    }

    await BlockingDatabase.storeEncryptedBlockList(
      state.username,
      encryptedBlockList,
      blockListHash,
      salt,
      version,
      lastUpdated
    );

    await sendSecureMessage(ws, {
      type: SignalType.BLOCK_LIST_SYNC,
      success: true,
      message: 'Block list synchronized successfully',
    });

    logEvent('block-list-synced', { username: state.username });
  } catch (error) {
    logError(error, { operation: 'block-list-sync' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error synchronizing block list'
    });
  }
}

async function handleRetrieveBlockList({ ws, state }) {
  if (!state?.hasAuthenticated || !state?.username) {
    return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
  }

  try {
    const blockList = await BlockingDatabase.getEncryptedBlockList(state.username);

    if (blockList) {
      await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_RESPONSE,
        encryptedBlockList: blockList.encryptedBlockList,
        blockListHash: blockList.blockListHash,
        salt: blockList.salt,
        version: blockList.version,
        lastUpdated: blockList.lastUpdated,
      });
    } else {
      await sendSecureMessage(ws, {
        type: SignalType.BLOCK_LIST_RESPONSE,
        encryptedBlockList: null,
        message: 'No block list found',
      });
    }

    logEvent('block-list-retrieved', { username: state.username });
  } catch (error) {
    logError(error, { operation: 'retrieve-block-list' });
    await sendSecureMessage(ws, {
      type: SignalType.ERROR,
      message: 'Error retrieving block list'
    });
  }
}

async function gracefulShutdown(signal) {
  logEvent('shutdown-initiated', { signal });

  // Shutdown cluster first (removes from Redis cluster:master if primary)
  try {
    await shutdownCluster();
  } catch (error) {
    logError(error, { operation: 'cluster-shutdown' });
  }

  // Clear intervals
  if (blockTokenCleanupInterval) {
    clearInterval(blockTokenCleanupInterval);
    blockTokenCleanupInterval = null;
  }
  if (statusLogInterval) {
    clearInterval(statusLogInterval);
    statusLogInterval = null;
  }

  // Cleanup session manager before closing Redis
  try {
    await cleanupSessionManager();
  } catch (error) {
    logError(error, { operation: 'session-cleanup' });
  }

  // Close WebSocket server
  if (wss) {
    wss.close();
  }

  // Close HTTPS server
  if (server) {
    server.close();
  }

  // Close presence service pattern subscriber
  try {
    await presenceService.close();
  } catch (error) {
    logError(error, { operation: 'presence-close' });
  }

  // Cleanup Redis connections after all operations complete
  try {
    const { cleanup: cleanupRedis } = await import('./presence/presence.js');
    await cleanupRedis();
  } catch (error) {
    logError(error, { operation: 'redis-cleanup' });
  }

  logEvent('shutdown-completed', { signal });

  await new Promise(resolve => setTimeout(resolve, 50));
}

// Main server startup
async function startServer() {
  try {
    // Register shutdown handlers
    registerShutdownHandlers({
      handler: gracefulShutdown,
    });

    await setServerPasswordOnInput();
    await initDatabase();

    // Log auto-generated security keys status
    cryptoLogger.info('Encryption keys initialized');
    cryptoLogger.info(`PASSWORD_HASH_PEPPER: ${process.env.PASSWORD_HASH_PEPPER ? 'loaded' : 'missing'}`);
    cryptoLogger.info(`USER_ID_SALT: ${process.env.USER_ID_SALT ? 'loaded' : 'missing'}`);
    cryptoLogger.info(`DB_FIELD_KEY: ${process.env.DB_FIELD_KEY ? 'loaded' : 'missing'}`);
    cryptoLogger.warn('CRITICAL: Backup generated key files securely - losing them makes data unrecoverable');

    logEvent('server-initialized', {
      port: ServerConfig.PORT,
      rateLimiterBackend: rateLimitMiddleware.getStats().backend
    });

    // Create server using bootstrap module
    const result = await createBootstrapServer({
      createApp: createExpressApp,
      createWebSocketServer,
      onServerReady,
      prepareWorkerContext,
      tls: {
        certPath: process.env.TLS_CERT_PATH,
        keyPath: process.env.TLS_KEY_PATH,
      },
    });

    return result;
  } catch (error) {
    logError(error, { operation: 'server-startup' });
    process.exit(1);
  }
}

startServer().catch((error) => {
  logError(error, { operation: 'main-startup' });
  process.exit(1);
});
