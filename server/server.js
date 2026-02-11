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
import { BlockingDatabase, DiscoveryDB, initDatabase } from './database/database.js';
import * as ServerConfig from './config/config.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';
import { ConnectionStateManager } from './session/connection-state.js';
import authRoutes from './routes/auth-routes.js';
import apiRoutes from './routes/api-routes.js';
import { createServer as createBootstrapServer, registerShutdownHandlers } from './bootstrap/server-bootstrap.js';
import { attachGateway } from './websocket/gateway.js';
import { attachQuicRelay } from './websocket/quic-relay.js';
import { cleanupSessionManager } from './session/session-manager.js';
import { logEvent, logError, logRateLimitEvent } from './security/logging.js';
import { SERVER_CONSTANTS, SECURITY_HEADERS, CORS_CONFIG } from './config/constants.js';
import { logger as cryptoLogger } from './crypto/crypto-logger.js';
import { handlePQHandshake, handlePQEnvelope, createPQResponseSender, sendSecureMessage, initializeEnvelopeHandler } from './messaging/pq-envelope-handler.js';
import { handleBundlePublish, handleBundleFailure } from './messaging/libsignal-handler.js';
import { initializeCluster, shutdownCluster } from './cluster/cluster-integration.js';
import clusterRoutes from './routes/cluster-routes.js';
import {
  handleStoreOfflineMessage,
  handleRetrieveOfflineMessages,
  handleRateLimitStatus,
  handleBlockListSync,
  handleRetrieveBlockList,
  handleBlockTokensUpdate,
  handleHybridKeysUpdate,
  handleBlindRoute,
  handleClaimInbox,
  handleRotateInbox,
  handleOwnershipProof
} from './handlers/signal-handlers.js';
import { BlindRouter } from './routing/blind-router.js';
import { TimingProtection } from './routing/timing-protection.js';
import { oprfDiscoveryServer } from './crypto/oprf-discovery.js';

// Discovery epoch manager
class DiscoveryEpochManager {
  constructor() {
    this.currentEpoch = 1;
    this.epochStartTime = Date.now();
    this.EPOCH_DURATION_MS = 6 * 60 * 60 * 1000;
    this.rotationInterval = null;
  }

  start() {
    this.rotationInterval = setInterval(() => {
      this.rotateEpoch();
    }, this.EPOCH_DURATION_MS);
    cryptoLogger.info('[DISCOVERY-EPOCH] Epoch manager started', { 
      currentEpoch: this.currentEpoch,
      durationHours: 6 
    });
  }

  rotateEpoch() {
    this.currentEpoch++;
    this.epochStartTime = Date.now();
    cryptoLogger.info('[DISCOVERY-EPOCH] Rotated to new epoch', { 
      newEpoch: this.currentEpoch,
      previousEpoch: this.currentEpoch - 1 
    });
  }

  getCurrentEpoch() {
    return this.currentEpoch;
  }

  getPreviousEpoch() {
    return this.currentEpoch > 1 ? this.currentEpoch - 1 : 1;
  }

  getEpochInfo() {
    return {
      current: this.currentEpoch,
      previous: this.getPreviousEpoch(),
      startedAt: this.epochStartTime,
      rotatesAt: this.epochStartTime + this.EPOCH_DURATION_MS
    };
  }

  stop() {
    if (this.rotationInterval) {
      clearInterval(this.rotationInterval);
      this.rotationInterval = null;
    }
  }
}

const discoveryEpochManager = new DiscoveryEpochManager();

let server, wss, serverHybridKeyPair, blockTokenCleanupInterval, statusLogInterval, discoveryCleanupInterval;

// Cleanup every 30 mins
discoveryCleanupInterval = setInterval(async () => {
  try {
    await DiscoveryDB.cleanup();
  } catch (e) { }
}, 1800000);

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

  // Set up blind delivery subscriber for cross-instance message routing
  try {
    await BlindRouter.subscribeToBlindDelivery();
    cryptoLogger.info('[CROSS-INSTANCE] Blind delivery subscriber initialized');
  } catch (error) {
    logError(error, { operation: 'blind-delivery-subscriber-setup' });
  }

  // Set up periodic cleanup
  blockTokenCleanupInterval = setInterval(async () => {
    try {
      await BlockingDatabase.cleanupExpiredBlocks();
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

  const { getPgPool } = await import('./database/database.js');
  const db = await getPgPool();

  // Initialize OPAQUE server
  const { OPAQUEServer } = await import('./crypto/opaque-service.js');
  await OPAQUEServer.initialize();

  // Initialize Privacy Pass server
  const { PrivacyPassServer, NullifierStore } = await import('./authentication/privacy-pass-server.js');
  const nullifierStore = new NullifierStore(db);
  await PrivacyPassServer.initialize(nullifierStore);

  // Initialize OPRF Discovery server
  await oprfDiscoveryServer.initialize();
  
  // Start discovery epoch manager for rotating tokens
  discoveryEpochManager.start();

  const authHandler = new authentication.AccountAuthHandler(serverHybridKeyPair, db);
  const serverAuthHandler = new authentication.ServerAuthHandler(serverHybridKeyPair, db, ServerConfig);

  return {
    serverHybridKeyPair,
    authHandler,
    serverAuthHandler
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
      heartbeatIntervalMs: SERVER_CONSTANTS.HEARTBEAT_INTERVAL,
      fixedMessageSizeBytes: SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES,
    },
    onMessage: async ({ ws, sessionId, message, parsed }) => {
      await handleWebSocketMessage({ ws, sessionId, message, parsed, context });
    },
  });

  // Store gateway reference for cross instance delivery
  global.gateway = gateway;
  const quicRelay = attachQuicRelay(wss, cryptoLogger);
  global.quicRelay = quicRelay;

  // Start blind routing cover traffic for timing correlation resistance
  TimingProtection.startCoverTraffic(async (inboxId) => {
    try {
      const { createDummyFrame } = await import('./routing/message-padding.js');
      const dummyFrame = createDummyFrame();
      await gateway.routeToInboxId(inboxId, {
        version: 'ss-v1',
        ciphertext: dummyFrame.toString('base64'),
        ephemeralKey: '',
        nonce: ''
      });
    } catch { }
  });

  // Subscribe to blind delivery channel for distributed routing
  BlindRouter.subscribeToBlindDelivery().catch(err => {
    cryptoLogger.warn('[SERVER] Failed to subscribe to blind delivery:', err.message);
  });
}

// Dedup cache for discovery publish (token -> timestamp)
const recentPublishTokens = new Map();
const PUBLISH_DEDUP_WINDOW_MS = 5000;

async function handleWebSocketMessage({ ws, sessionId, message, parsed, context }) {
  const { authHandler } = context;

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

    // Get session state and ephemeral state
    const sessionState = await ConnectionStateManager.getState(sessionId) || {};
    const ephemeralState = authentication.SecureStateManager.getState(ws);
    const state = { ...sessionState, ...ephemeralState };

    const serverPasswordHash = ServerConfig.getServerPasswordHash();

    // Ensure transport and gatekeeper signals always pass
    const isTransportSignal = [
      'request-server-public-key',
      'pq-handshake-init',
      'pq-handshake-ack',
      'pq-heartbeat-ping',
      'pq-heartbeat-pong',
      'ping',
      'pong',
      SignalType.PQ_ENVELOPE
    ].includes(normalizedMessage.type);

    const isGatekeeperSignal = [
      'server-entry-request',
      'server-entry-challenge',
      'server-entry-token-issuance',
      'privacy-pass-redemption'
    ].includes(normalizedMessage.type);

    // Account auth signals are allowed before server entry token
    const isAccountAuthSignal = [
      SignalType.AUTH_OT_REGISTER_REQUEST,
      SignalType.AUTH_OT_REGISTER_FINALIZE,
      SignalType.AUTH_OT_REQUEST,
      SignalType.AUTH_OT_FINALIZE,
      SignalType.TOKEN_VALIDATION,
      SignalType.BLIND_SIGNATURE_REQUEST,
      SignalType.ZK_REFRESH_CHALLENGE,
      SignalType.ZK_REFRESH_RESPONSE,
      SignalType.CLAIM_INBOX
    ].includes(normalizedMessage.type);

    if (serverPasswordHash && !state.hasServerAuth && !ws._unlinkedSession && !isTransportSignal && !isGatekeeperSignal && !isAccountAuthSignal) {
      cryptoLogger.warn('[GATEKEEPER] Access denied: Server entry token required', {
        sessionId: sessionId?.slice(0, 8),
        signalType: normalizedMessage.type,
        state: { hasServerAuth: !!state.hasServerAuth }
      });
      return await sendSecureMessage(ws, {
        type: SignalType.AUTH_ERROR,
        message: 'Server entry token required',
        code: 'SERVER_ENTRY_REQUIRED'
      });
    }

    // Apply per message rate limiting
    try {
      const rateLimitPrincipalId = state?.credentialId || state?.userId || ws?._sessionId || sessionId;
      if (rateLimitPrincipalId) {
        const allowed = await rateLimitMiddleware.applyMessageRateLimiting(
          ws,
          normalizedMessage.type,
          String(rateLimitPrincipalId)
        );
        if (!allowed) {
          return;
        }
      }
    } catch (rateLimitError) {
      cryptoLogger.warn('[RATE-LIMIT] Failed to apply message rate limiting', {
        error: rateLimitError?.message || String(rateLimitError)
      });
    }

    switch (normalizedMessage.type) {
      case SignalType.AUTH_OT_REGISTER_REQUEST:
        await authHandler.handleOTRegisterRequest(ws, normalizedMessage);
        break;
      case SignalType.AUTH_OT_REGISTER_FINALIZE:
        const otRegRes = await authHandler.handleOTRegisterFinalize(ws, normalizedMessage);
        if (otRegRes?.success) {
          await ConnectionStateManager.updateState(sessionId, {
            hasServerAuth: true,
            userId: otRegRes.internalId
          });
          cryptoLogger.info('[GATEKEEPER] Server entry granted via OT registration', { sessionId: sessionId?.slice(0, 8) });
        }
        break;
      case SignalType.AUTH_OT_REQUEST:
        await authHandler.handleOTSignIn(ws, normalizedMessage);
        break;
      case SignalType.AUTH_OT_FINALIZE:
        const otFinalRes = await authHandler.handleSignInFinalize(ws, normalizedMessage);
        if (otFinalRes?.success) {
          await ConnectionStateManager.updateState(sessionId, {
            hasServerAuth: true,
            credentialId: otFinalRes.credentialId
          });
          cryptoLogger.info('[GATEKEEPER] Server entry granted via OT login', { sessionId: sessionId?.slice(0, 8) });
        }
        break;
      case SignalType.ZK_REFRESH_CHALLENGE:
        await authHandler.handleZKChallengeRequest(ws);
        break;
      case SignalType.ZK_REFRESH_RESPONSE:
        await authHandler.processDeviceProofResponse(ws, msgString);
        break;
      case SignalType.BLIND_SIGNATURE_REQUEST:
        await authHandler.handleBlindSignatureRequest(ws, normalizedMessage.blindedToken);
        break;
      case SignalType.SERVER_ENTRY_REQUEST:
        await authHandler.processAuthRequest(ws, msgString);
        break;
      case SignalType.SERVER_ENTRY_TOKEN_ISSUANCE:
        await authHandler.processAuthRequest(ws, msgString);
        break;
      case SignalType.PRIVACY_PASS_REDEMPTION:
        try {
          cryptoLogger.info('[GATEKEEPER] Processing Privacy Pass redemption', {
            hasToken: !!normalizedMessage.token,
            hasNullifier: !!normalizedMessage.nullifier,
            hasMac: !!normalizedMessage.mac
          });
          const isValid = await authHandler.gatekeeper.verifyEntryToken(normalizedMessage);
          if (isValid) {
            await ConnectionStateManager.updateState(sessionId, { hasServerAuth: true });
            await sendSecureMessage(ws, { type: SignalType.OK, message: 'Server entry granted' });
            cryptoLogger.info('[GATEKEEPER] Server entry granted via Privacy Pass', { sessionId: sessionId?.slice(0, 8) });
          } else {
            cryptoLogger.warn('[GATEKEEPER] Privacy Pass token verification returned false');
            await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Invalid entry token' });
          }
        } catch (error) {
          cryptoLogger.error('[GATEKEEPER] Token redemption failed', { error: error.message, stack: error.stack?.slice(0, 200) });
          await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Entry verification failed' });
        }
        break;
      case SignalType.TOKEN_VALIDATION:
        try {
          const { accessToken } = normalizedMessage;

          if (!accessToken || typeof accessToken !== 'string') {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Invalid session token'
            });
          }

          const { anonymousSessionService } = await import('./authentication/anonymous-session-service.js');

          // Verify anonymous session token
          const result = await anonymousSessionService.verifySession(accessToken);

          if (!result.valid) {
            cryptoLogger.warn('[TOKEN-VALIDATION] Session validation failed', { error: result.error });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: result.error || 'Invalid session token'
            });
          }

          // Get session capabilities
          const capabilities = await anonymousSessionService.getSessionCapabilities(result.sessionId);

          ws._authenticated = true;
          ws._hasAuthenticated = true;
          ws._anonymousSession = true;

          // Capture blinded token for unlinked credential issuance
          if (normalizedMessage.blindedToken) {
            ws._pendingBlindedToken = normalizedMessage.blindedToken;
          }

          await ConnectionStateManager.updateState(sessionId, {
            hasAuthenticated: true,
            hasServerAuth: true,
            pqSessionId: ws._pqSessionId || null,
            connectedAt: Date.now(),
            lastActivity: Date.now(),
            scopes: capabilities.scopes || []
          });

          // Register connection for local message delivery
          try {
            if (global.gateway?.addLocalConnection) {
              await global.gateway.addLocalConnection(ws);
            }
          } catch (e) {
            cryptoLogger.warn('[TOKEN-VALIDATION] addLocalConnection failed', { error: e?.message });
          }

          cryptoLogger.info('[TOKEN-VALIDATION] Anonymous session validation successful', {
            sessionId: result.sessionId?.slice(0, 8) + '...'
          });

          const response = {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            valid: true
          };

          // Issue blind signature if requested
          if (ws._pendingBlindedToken) {
            try {
              const { BlindSignatureIssuer } = await import('./security/blind-signatures.js');
              const { generateCapabilityToken, storeCapabilityToken } = await import('./routing/capability-tokens.js');

              const cap = generateCapabilityToken();
              try {
                await storeCapabilityToken(cap.token, [], {
                  ttl: Math.max(1, Math.floor((cap.expiresAt - Date.now()) / 1000))
                });
              } catch (e) {
                cryptoLogger.warn('[TOKEN-VALIDATION] Failed to store capability token', { error: e?.message });
              }

              const signed = await BlindSignatureIssuer.signBlindedMessage(ws._pendingBlindedToken);
              const serverBlindPublicKey = await BlindSignatureIssuer.getPublicKey();
              response.blindRouting = {
                capabilityToken: cap.token,
                expiresAt: cap.expiresAt,
                signedBlindedToken: signed.signature,
                blindSignatureKid: signed.kid,
                serverBlindPublicKey
              };
              ws._pendingBlindedToken = null;
            } catch (e) {
              cryptoLogger.error('[TOKEN-VALIDATION] Failed to sign blinded token:', { error: e.message });
            }
          }

          await sendSecureMessage(ws, response);
        } catch (error) {
          cryptoLogger.error('[TOKEN-VALIDATION] Validation failed', { error: error.message });
          await sendSecureMessage(ws, {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            valid: false,
            error: 'Session validation error'
          });
        }
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

      case SignalType.LIBSIGNAL_PUBLISH_BUNDLE:
        await handleBundlePublish({
          ws,
          parsed: normalizedMessage,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.SIGNAL_BUNDLE_FAILURE:
        await handleBundleFailure({
          ws,
          parsed: normalizedMessage,
          sendPQResponse: await createPQResponseSender(ws, context)
        });
        break;

      case SignalType.HYBRID_KEYS_UPDATE:
        await handleHybridKeysUpdate({ ws, parsed: normalizedMessage, state, serverHybridKeyPair });
        break;

      case SignalType.REQUEST_SERVER_PUBLIC_KEY:
        try {
          const { message } = await gateway.getServerPublicKeyMessage();
          ws.send(message);
          cryptoLogger.info('[SERVER] Sent server public keys on request', { sessionId: sessionId?.slice(0, 8) });
        } catch (error) {
          cryptoLogger.error('[SERVER] Failed to send server public keys on request', { error: error.message });
          await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Failed to retrieve server keys' });
        }
        break;

      case SignalType.OPRF_DISCOVERY_PUBLIC_KEY:
        try {
          const oprfPublicKey = oprfDiscoveryServer.getPublicKey();
          const epochInfo = discoveryEpochManager.getEpochInfo();
          await sendSecureMessage(ws, {
            type: SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
            publicKey: oprfPublicKey,
            epoch: epochInfo.current,
            previousEpoch: epochInfo.previous,
            epochRotatesAt: epochInfo.rotatesAt
          });
        } catch (error) {
          cryptoLogger.error('[OPRF-DISCOVERY] Failed to get public key:', error.message);
          await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'OPRF service unavailable' });
        }
        break;

      case SignalType.OPRF_BLIND_EVALUATE:
        if (!normalizedMessage.blindedPoint) {
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Blinded point required' });
        }
        try {
          const clientId = sessionId || ws._pqSessionId || 'anonymous';
          const evalResult = oprfDiscoveryServer.blindEvaluate(normalizedMessage.blindedPoint, clientId);
          const epochInfo = discoveryEpochManager.getEpochInfo();
          await sendSecureMessage(ws, {
            type: SignalType.OPRF_BLIND_EVALUATE_RESPONSE,
            blindedPoint: normalizedMessage.blindedPoint,
            evaluated: evalResult.evaluated,
            proof: evalResult.proof,
            publicKey: evalResult.publicKey,
            epoch: epochInfo.current
          });
        } catch (error) {
          cryptoLogger.error('[OPRF-DISCOVERY] Blind evaluation failed:', error.message);
          await sendSecureMessage(ws, { type: SignalType.ERROR, message: error.message || 'OPRF evaluation failed' });
        }
        break;

      case SignalType.PUBLISH_DISCOVERY:
        if ((!normalizedMessage.token && !normalizedMessage.previousEpochToken) || !normalizedMessage.encryptedBlob) {
          cryptoLogger.warn('[DISCOVERY] Reject publish - invalid payload', {
            hasToken: !!normalizedMessage.token,
            hasPreviousEpochToken: !!normalizedMessage.previousEpochToken,
            hasEncryptedBlob: !!normalizedMessage.encryptedBlob,
            sessionId: (sessionId || ws._pqSessionId || '').slice(0, 8)
          });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid discovery payload' });
        }

        // Deduplicate rapid publish requests with the same token
        if (normalizedMessage.token) {
          const now = Date.now();
          const lastPublish = recentPublishTokens.get(normalizedMessage.token);
          if (lastPublish && (now - lastPublish) < PUBLISH_DEDUP_WINDOW_MS) {
            cryptoLogger.info('[DISCOVERY] Duplicate publish suppressed', {
              tokenPrefix: String(normalizedMessage.token).slice(0, 8),
              msSinceLastPublish: now - lastPublish
            });
            return await sendSecureMessage(ws, { type: SignalType.OK, success: true, op: 'publish-discovery' });
          }
          recentPublishTokens.set(normalizedMessage.token, now);
          // Periodically clean stale entries
          if (recentPublishTokens.size > 500) {
            for (const [token, ts] of recentPublishTokens) {
              if (now - ts > PUBLISH_DEDUP_WINDOW_MS) recentPublishTokens.delete(token);
            }
          }
        }

        if (!state?.hasAuthenticated && !ws._unlinkedSession) {
          cryptoLogger.warn('[DISCOVERY] Reject publish - not authenticated', {
            tokenPrefix: String(normalizedMessage.token).slice(0, 8),
            encryptedBlobLen: typeof normalizedMessage.encryptedBlob === 'string' ? normalizedMessage.encryptedBlob.length : null,
            hasAuthenticated: !!state?.hasAuthenticated,
            unlinkedSession: !!ws._unlinkedSession,
            sessionId: (sessionId || ws._pqSessionId || '').slice(0, 8)
          });
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Authentication required' });
        }

        cryptoLogger.info('[DISCOVERY] Publish received', {
          tokenPrefix: String(normalizedMessage.token).slice(0, 8),
          prevTokenPrefix: String(normalizedMessage.previousEpochToken).slice(0, 8),
          encryptedBlobLen: typeof normalizedMessage.encryptedBlob === 'string' ? normalizedMessage.encryptedBlob.length : null,
          hasAuthenticated: !!state?.hasAuthenticated,
          unlinkedSession: !!ws._unlinkedSession,
          sessionId: (sessionId || ws._pqSessionId || '').slice(0, 8)
        });

        try {
          // Store for current epoch token
          const expiresAt = Date.now() + (31536000 * 1000);
          let publishSuccess = false;
          
          if (normalizedMessage.token) {
            const publishedCurrent = await DiscoveryDB.store(
              normalizedMessage.token,
              normalizedMessage.encryptedBlob,
              expiresAt
            );
            publishSuccess = publishSuccess || publishedCurrent;
          }
          
          // Also store for previous epoch token
          if (normalizedMessage.previousEpochToken) {
            const publishedPrevious = await DiscoveryDB.store(
              normalizedMessage.previousEpochToken,
              normalizedMessage.encryptedBlob,
              expiresAt
            );
            publishSuccess = publishSuccess || publishedPrevious;
          }
          
          cryptoLogger.info('[DISCOVERY] Publish stored', {
            tokenPrefix: String(normalizedMessage.token).slice(0, 8),
            success: publishSuccess,
            expiresAt
          });
          await sendSecureMessage(ws, { type: SignalType.OK, success: publishSuccess, op: 'publish-discovery' });
        } catch (e) {
          cryptoLogger.error('[DISCOVERY] Publish failed', {
            tokenPrefix: String(normalizedMessage.token).slice(0, 8),
            error: e?.message || String(e)
          });
          await sendSecureMessage(ws, { type: SignalType.OK, success: false, op: 'publish-discovery' });
        }
        break;

      case SignalType.QUERY_DISCOVERY:
        if (!normalizedMessage.token) {
          return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Discovery token required' });
        }

        cryptoLogger.info('[DISCOVERY] Query received', {
          tokenPrefix: String(normalizedMessage.token).slice(0, 8),
          hasPrevEpochToken: !!normalizedMessage.previousEpochToken,
          hasAuthenticated: !!state?.hasAuthenticated,
          unlinkedSession: !!ws._unlinkedSession,
          sessionId: (sessionId || ws._pqSessionId || '').slice(0, 8)
        });

        let discoveryRow = null;
        try {
          // Try current epoch token
          discoveryRow = await DiscoveryDB.lookup(normalizedMessage.token);
          
          // If not found and previous epoch token provided then try that
          if (!discoveryRow && normalizedMessage.previousEpochToken) {
            cryptoLogger.info('[DISCOVERY] Current epoch token not found, trying previous epoch', {
              prevTokenPrefix: String(normalizedMessage.previousEpochToken).slice(0, 8)
            });
            discoveryRow = await DiscoveryDB.lookup(normalizedMessage.previousEpochToken);
          }
        } catch (e) {
          cryptoLogger.error('[DISCOVERY] Query lookup failed', {
            tokenPrefix: String(normalizedMessage.token).slice(0, 8),
            error: e?.message || String(e)
          });
        }

        const discoveryBlob = discoveryRow?.encryptedBlob || null;
        cryptoLogger.info('[DISCOVERY] Query result', {
          tokenPrefix: String(normalizedMessage.token).slice(0, 8),
          exists: !!discoveryBlob,
          usedPrevEpoch: !!discoveryRow && normalizedMessage.previousEpochToken,
          encryptedBlobLen: typeof discoveryBlob === 'string' ? discoveryBlob.length : null
        });
        await sendSecureMessage(ws, {
          type: SignalType.DISCOVERY_RESULT,
          token: normalizedMessage.token,
          requestId: typeof normalizedMessage.requestId === 'string' ? normalizedMessage.requestId.slice(0, 128) : undefined,
          encryptedBlob: discoveryBlob || null,
          exists: !!discoveryBlob
        });
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
        if (ws._pqSessionId) {
          await sendSecureMessage(ws, {
            type: SignalType.PQ_HEARTBEAT_PONG,
            sessionId: ws._pqSessionId,
            timestamp: Date.now()
          });
        }
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

      case SignalType.PING:
        await sendSecureMessage(ws, { type: SignalType.PONG, timestamp: Date.now() });
        break;

      case SignalType.BLIND_ROUTE:
        await handleBlindRoute({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.CLAIM_INBOX:
        await handleClaimInbox({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.ROTATE_INBOX:
        await handleRotateInbox({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.OWNERSHIP_PROOF:
        await handleOwnershipProof({ ws, parsed: normalizedMessage, state });
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
