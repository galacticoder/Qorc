import nodeCrypto from 'crypto';
if (!global.crypto) {
  global.crypto = nodeCrypto.webcrypto;
}
import fs from 'fs';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer } from 'ws';
import { SignalType } from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import { BlockingDatabase, UserDatabase, initDatabase } from './database/database.js';
import * as ServerConfig from './config/config.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';
import { ConnectionStateManager } from './presence/connection-state.js';
import authRoutes from './routes/auth-routes.js';
import apiRoutes from './routes/api-routes.js';
import { createServer as createBootstrapServer, registerShutdownHandlers } from './bootstrap/server-bootstrap.js';
import { attachGateway } from './websocket/gateway.js';
import { attachQuicRelay } from './websocket/quic-relay.js';
import { cleanupSessionManager } from './session/session-manager.js';
import { checkBlocking } from './security/blocking.js';
import { logEvent, logError, logDeliveryEvent, logRateLimitEvent } from './security/logging.js';
import { presenceService } from './presence/presence-service.js';
import { SERVER_CONSTANTS, SECURITY_HEADERS, CORS_CONFIG } from './config/constants.js';
import { logger as cryptoLogger } from './crypto/crypto-logger.js';
import { withRedisClient } from './presence/presence.js';
import { handlePQHandshake, handlePQEnvelope, createPQResponseSender, sendSecureMessage, initializeEnvelopeHandler } from './messaging/pq-envelope-handler.js';
import { handleBundlePublish, handleBundleRequest, handleBundleFailure } from './messaging/libsignal-handler.js';
import { initializeCluster, shutdownCluster } from './cluster/cluster-integration.js';
import clusterRoutes from './routes/cluster-routes.js';
import {
  handleEncryptedMessage,
  handleSessionResetRequest,
  handleSessionEstablished,
  handleStoreOfflineMessage,
  handleRetrieveOfflineMessages,
  handleRateLimitStatus,
  handleServerLogin,
  handleCheckUserExists,
  handleBlockListSync,
  handleRetrieveBlockList,
  handleBlockTokensUpdate,
  handleAvatarUpload,
  handleAvatarFetch,
  handleP2PFetchPeerCert,
  handleHybridKeysUpdate,
  handleRegister,
  deliverToLocalConnections
} from './handlers/signal-handlers.js';

let server, wss, serverHybridKeyPair, blockTokenCleanupInterval, statusLogInterval;

async function createExpressApp() {
  const app = express();
  app.set('trust proxy', true);

  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
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
  app.use('/api', apiRoutes);

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
      let parsedMessage;
      try {
        const raw = typeof message === 'string' ? message : String(message);
        parsedMessage = JSON.parse(raw);
      } catch (error) {
        cryptoLogger.warn('[CROSS-INSTANCE] Invalid message payload', {
          error: error?.message || String(error)
        });
        return;
      }
      const senderUser = parsedMessage.encryptedPayload?.from || parsedMessage.from;
      const recipientUser = parsedMessage.to || parsedMessage.encryptedPayload?.to;

      if (!recipientUser) {
        cryptoLogger.warn('[CROSS-INSTANCE] No recipient username in message', {
          hasTo: !!parsedMessage.to,
          hasEncPayloadTo: !!parsedMessage.encryptedPayload?.to
        });
        return;
      }

      const senderBlockedByRecipient = await checkBlocking(senderUser, recipientUser);
      const recipientBlockedBySender = await checkBlocking(recipientUser, senderUser);

      if (senderBlockedByRecipient || recipientBlockedBySender) {
        logDeliveryEvent('cross-instance-blocked', {
          senderUser,
          recipientUser,
          reason: senderBlockedByRecipient ? 'sender-blocked-by-recipient' : 'recipient-blocked-by-sender'
        });
        return;
      }

      // Deliver to local connections using shared helper
      const result = await deliverToLocalConnections(recipientUser, parsedMessage);
      if (result.delivered) {
        logDeliveryEvent('cross-instance-delivered', {
          username: recipientUser.slice(0, 8) + '...',
          count: result.count
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

  const { DeviceAttestationService } = await import('./authentication/device-attestation.js');
  const { getPgPool } = await import('./database/database.js');
  const db = await getPgPool();
  const deviceAttestationService = new DeviceAttestationService(db, {
    maxAccounts: ServerConfig.DEVICE_MAX_ACCOUNTS
  });
  await deviceAttestationService.initialize();

  return {
    serverHybridKeyPair,
    authHandler,
    serverAuthHandler,
    deviceAttestationService
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
    onMessage: async ({ ws, sessionId, message, parsed }) => {
      await handleWebSocketMessage({ ws, sessionId, message, parsed, context });
    },
  });

  // Store gateway reference for cross-instance delivery
  global.gateway = gateway;
  const quicRelay = attachQuicRelay(wss, cryptoLogger);
  global.quicRelay = quicRelay;
}

async function handleWebSocketMessage({ ws, sessionId, message, parsed, context }) {
  const { authHandler, serverAuthHandler } = context;

  try {
    const msgString = (typeof message === 'string' ? message : String(message)).trim();
    if (msgString.length === 0) {
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Empty message' });
    }

    let normalizedMessage = null;
    if (parsed && typeof parsed === 'object') {
      normalizedMessage = parsed;
    } else {
      try {
        normalizedMessage = JSON.parse(msgString);
      } catch (_parseError) {
        return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid JSON format' });
      }
    }

    if (typeof normalizedMessage !== 'object' || normalizedMessage === null) { return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message format - expected object' }); }
    const state = await ConnectionStateManager.getState(sessionId);

    if (!state) {
      return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Session not found' });
    }

    switch (normalizedMessage.type) {
      case SignalType.ACCOUNT_SIGN_UP:
      case SignalType.ACCOUNT_SIGN_IN:
        ws._deviceAttestationService = context.deviceAttestationService;
        await authHandler.processAuthRequest(ws, msgString);
        break;
      case SignalType.DEVICE_PROOF_RESPONSE:
        await authHandler.processDeviceProofResponse(ws, msgString);
        break;
      case SignalType.DEVICE_CHALLENGE_REQUEST:
        ws._deviceAttestationService = context.deviceAttestationService;
        await authHandler.processDeviceChallengeRequest(ws);
        break;
      case SignalType.DEVICE_ATTESTATION:
        ws._deviceAttestationService = context.deviceAttestationService;
        await authHandler.processDeviceAttestation(ws, msgString);
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

          ws._username = username;
          ws._authenticated = true;
          ws._hasAuthenticated = true;

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

          try {
            await presenceService.setUserOnline(username, sessionId);
          } catch (e) {
            cryptoLogger.warn('[TOKEN-VALIDATION] setUserOnline failed', { error: e?.message });
          }

          cryptoLogger.info('[TOKEN-VALIDATION] Token validation successful', {
            username: username.slice(0, 4) + '...',
            sessionId: sessionId?.slice(0, 8) + '...'
          });

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

          ws._username = username;
          ws._authenticated = true;
          ws._hasAuthenticated = true;

          await ConnectionStateManager.updateState(sessionId, {
            username: username,
            hasAuthenticated: true,
            hasServerAuth: authState.hasServerAuth || false,
            pqSessionId: ws._pqSessionId || null,
            connectedAt: Date.now(),
            lastActivity: Date.now()
          });

          try {
            if (global.gateway?.addLocalConnection) {
              await global.gateway.addLocalConnection(username, ws);
            }
          } catch (e) {
            cryptoLogger.warn('[AUTH-RECOVERY] addLocalConnection failed', { error: e?.message });
          }

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

      case SignalType.CLIENT_ERROR:
        cryptoLogger.error('[CLIENT-ERROR] Client reported error', {
          sessionId: sessionId?.slice(0, 8) + '...',
          username: state.username?.slice(0, 4) + '...' || 'unknown',
          error: normalizedMessage.error
        });
        await sendSecureMessage(ws, {
          type: SignalType.ERROR_ACKNOWLEDGED,
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
        await handleBundlePublish({
          ws,
          parsed: normalizedMessage,
          state,
          context,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.SIGNAL_BUNDLE_FAILURE:
        await handleBundleFailure({
          ws,
          parsed: normalizedMessage,
          state,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.LIBSIGNAL_REQUEST_BUNDLE:
        await handleBundleRequest({
          ws,
          parsed: normalizedMessage,
          state,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.HYBRID_KEYS_UPDATE:
        await handleHybridKeysUpdate({ ws, parsed: normalizedMessage, state, serverHybridKeyPair });
        break;

      case SignalType.SESSION_RESET_REQUEST:
        await handleSessionResetRequest({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.SESSION_ESTABLISHED:
        await handleSessionEstablished({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.SERVER_LOGIN:
        if (normalizedMessage.resetType) {
          await handleServerLogin({ ws, sessionId, parsed: normalizedMessage, state });
        } else {
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


      case SignalType.CHECK_USER_EXISTS:
        if (!state?.hasAuthenticated || !state?.username) {
          cryptoLogger.warn('[CHECK_USER_EXISTS] Rejected - not authenticated');
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
        }
        await handleCheckUserExists({ ws, parsed: normalizedMessage, state, context, serverHybridKeyPair });
        break;

      case SignalType.USER_DISCONNECT:
        await handleUserDisconnect({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.P2P_FETCH_PEER_CERT:
        await handleP2PFetchPeerCert({ ws, parsed: normalizedMessage, state, serverHybridKeyPair });
        break;

      case SignalType.BLOCK_LIST_SYNC:
        await handleBlockListSync({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.BLOCK_TOKENS_UPDATE:
        await handleBlockTokensUpdate({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.RETRIEVE_BLOCK_LIST:
        await handleRetrieveBlockList({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.PQ_SESSION_INIT:
      case SignalType.PQ_HANDSHAKE_INIT:
        await handlePQHandshake({ ws, sessionId, parsed: normalizedMessage, serverHybridKeyPair });
        break;

      case SignalType.PQ_HEARTBEAT_PING:
        await sendSecureMessage(ws, {
          type: SignalType.PQ_HEARTBEAT_PONG,
          sessionId: ws._pqSessionId || sessionId,
          timestamp: Date.now()
        });
        break;

      case SignalType.PQ_ENVELOPE:
        await handlePQEnvelope({
          ws,
          sessionId,
          envelope: normalizedMessage,
          context,
          handleInnerMessage: handleWebSocketMessage
        });
        break;

      case SignalType.REGISTER:
        await handleRegister({ ws, sessionId, parsed: normalizedMessage, serverHybridKeyPair });
        break;

      case SignalType.AVATAR_UPLOAD:
        await handleAvatarUpload({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.AVATAR_FETCH:
        await handleAvatarFetch({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.PING:
        await sendSecureMessage(ws, { type: SignalType.PONG, timestamp: Date.now() });
        break;

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

async function shutdownServer(signal) {
  logEvent('shutdown-initiated', { signal });

  try {
    await shutdownCluster();
  } catch (error) {
    logError(error, { operation: 'cluster-shutdown' });
  }

  if (blockTokenCleanupInterval) {
    clearInterval(blockTokenCleanupInterval);
    blockTokenCleanupInterval = null;
  }
  if (statusLogInterval) {
    clearInterval(statusLogInterval);
    statusLogInterval = null;
  }

  try {
    await cleanupSessionManager();
  } catch (error) {
    logError(error, { operation: 'session-cleanup' });
  }

  if (wss) {
    wss.close();
  }

  if (server) {
    server.close();
  }

  try {
    await presenceService.close();
  } catch (error) {
    logError(error, { operation: 'presence-close' });
  }

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
    registerShutdownHandlers({
      handler: shutdownServer,
    });

    await setServerPasswordOnInput();
    await initDatabase();

    cryptoLogger.info('Encryption keys initialized');
    cryptoLogger.info(`PASSWORD_HASH_PEPPER: ${process.env.PASSWORD_HASH_PEPPER ? 'loaded' : 'missing'}`);
    cryptoLogger.info(`USER_ID_SALT: ${process.env.USER_ID_SALT ? 'loaded' : 'missing'}`);
    cryptoLogger.info(`DB_FIELD_KEY: ${process.env.DB_FIELD_KEY ? 'loaded' : 'missing'}`);
    cryptoLogger.warn('CRITICAL: Backup generated key files securely - losing them makes data unrecoverable');

    logEvent('server-initialized', {
      port: ServerConfig.PORT,
      rateLimiterBackend: rateLimitMiddleware.getStats().backend
    });

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
