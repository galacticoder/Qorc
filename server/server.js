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
import { DiscoveryDB, initDatabase, privateLookupId } from './database/database.js';
import * as ServerConfig from './config/config.js';
import * as authentication from './authentication/authentication.js';
import { setServerPasswordOnInput } from './authentication/auth-utils.js';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';
import { ConnectionStateManager } from './session/connection-state.js';
import authRoutes from './routes/auth-routes.js';
import apiRoutes, { clearSpoolSnapshotCache, getSpoolSnapshotCacheStats } from './routes/api-routes.js';
import { createServer as createBootstrapServer, registerShutdownHandlers } from './bootstrap/server-bootstrap.js';
import { attachGateway } from './websocket/gateway.js';
import { cleanupSessionManager } from './session/session-manager.js';
import { logEvent, logError, logRateLimitEvent } from './security/logging.js';
import { SERVER_CONSTANTS, SECURITY_HEADERS, CORS_CONFIG } from './config/constants.js';
import { logger as cryptoLogger } from './crypto/crypto-logger.js';
import {
  handlePQHandshake,
  handlePQEnvelope,
  createPQResponseSender,
  sendSecureMessage,
  initializeEnvelopeHandler,
  encryptedResponseSizeClass,
  getEncryptedResponsePlaintextBudgetBytes
} from './messaging/pq-envelope-handler.js';
import { initializeCluster, shutdownCluster } from './cluster/cluster-integration.js';
import clusterRoutes from './routes/cluster-routes.js';
import {
  handleRateLimitStatus,
  handleBlockListSync,
  handleRetrieveBlockList,
  handleBlindRoute,
  handleClaimInbox,
  handleRotateInbox,
  handlePirManifestRequest,
  handlePirQuery
} from './handlers/signal-handlers.js';
import { BlindRouter } from './routing/blind-router.js';
import { TimingProtection } from './routing/timing-protection.js';
import { oprfDiscoveryServer } from './crypto/oprf-discovery.js';
import { assertPirWorkerReadyForRequiredMode, getPirWorkerConfig } from './pir/pir-worker-client.js';
import { clearPirDatabaseCaches, getPirCacheStats } from './pir/pir-databases.js';
import { clearPQSessionCache, getPQSessionCacheStats } from './session/pq-session-storage.js';
import { buildDiscoverySnapshotResponse, getDiscoverySnapshotConfig } from './discovery/snapshot-service.js';
import { enqueueDiscoveryPublication, startDiscoveryPublicationRelay } from './discovery/publication-privacy.js';
import { startRuntimeMonitor } from './diagnostics/runtime-monitor.js';

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

function startServerCoverTraffic() {
  TimingProtection.startCoverTraffic(async () => {
    try {
      await BlindRouter.enqueueMixnetCoverWrite();
    } catch { }
  });
}

function getRuntimeDiagnostics() {
  return {
    caches: {
      pqSessions: getPQSessionCacheStats(),
      pir: getPirCacheStats(),
      spoolSnapshot: getSpoolSnapshotCacheStats(),
      blindRouter: BlindRouter.getBlindRouterRuntimeStats(),
      timing: TimingProtection.getTimingRuntimeStats()
    }
  };
}

async function cleanupIdleRuntime() {
  TimingProtection.stopCoverTraffic();
  return {
    coverTrafficStopped: true,
    timing: TimingProtection.clearTimingRuntimeState(),
    blindRouter: BlindRouter.pruneBlindRouterRuntimeState({ force: true }),
    pqSessions: clearPQSessionCache(),
    pir: clearPirDatabaseCaches(),
    spoolSnapshot: clearSpoolSnapshotCache()
  };
}

let server, wss, serverHybridKeyPair, statusLogInterval, discoveryCleanupInterval, stopRuntimeMonitor;

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

  // Terminal error handler
  app.use((err, req, res, next) => {
    const aborted =
      err?.type === 'request.aborted' ||
      err?.code === 'ECONNABORTED' ||
      err?.message === 'request aborted' ||
      req.aborted === true;
    if (aborted || res.headersSent || res.writableEnded) {
      try { if (!res.headersSent && res.writable) res.status(400).end(); } catch { /* socket gone */ }
      return;
    }
    const status = Number.isInteger(err?.status || err?.statusCode)
      ? (err.status || err.statusCode)
      : 500;
    if (status >= 500) {
      logError(err, { endpoint: req.originalUrl });
    }
    try {
      res.status(status >= 400 && status < 600 ? status : 500).json({ ok: false, error: 'request_failed' });
    } catch { /* socket gone */ }
  });

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

  try {
    startDiscoveryPublicationRelay();
    logEvent('discovery-publication-relay-started', {
      mode: 'delayed-batch'
    });
  } catch (error) {
    logError(error, { operation: 'discovery-publication-relay-setup' });
  }

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
  const pirWorkerState = await assertPirWorkerReadyForRequiredMode();
  const pirWorkerConfig = getPirWorkerConfig();
  logEvent('pir-worker-ready', {
    configured: pirWorkerConfig.configured,
    required: pirWorkerState.required === true,
    ready: pirWorkerState.ready === true,
    scheme: pirWorkerConfig.schemeId,
    parameterId: pirWorkerConfig.parameterId
  });

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
  logEvent('discovery-epoch-started', {
    currentEpoch: discoveryEpochManager.getCurrentEpoch(),
    durationHours: 6
  });

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
    onConnectionActive: startServerCoverTraffic
  });

  // Store gateway reference for cross instance delivery
  global.gateway = gateway;

  if (!stopRuntimeMonitor) {
    stopRuntimeMonitor = startRuntimeMonitor({
      getWss: () => wss,
      logger: cryptoLogger,
      getDiagnostics: getRuntimeDiagnostics,
      onIdleCleanup: cleanupIdleRuntime
    });
  }

  // Start blind routing cover traffic
  startServerCoverTraffic();

  // Subscribe to blind delivery channel for distributed routing
  BlindRouter.subscribeToBlindDelivery().catch(err => {
    cryptoLogger.warn('[SERVER] Failed to subscribe to blind delivery:', err.message);
  });
}

// Dedup cache for discovery publish (token -> timestamp)
const recentPublishTokens = new Map();
const PUBLISH_DEDUP_WINDOW_MS = 5000;
const DISCOVERY_EPOCH_DURATION_MS = 6 * 60 * 60 * 1000;
const DISCOVERY_FORWARD_PUBLISH_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const DISCOVERY_LEASE_TTL_MS = DISCOVERY_FORWARD_PUBLISH_WINDOW_MS + DISCOVERY_EPOCH_DURATION_MS;
const MAX_DISCOVERY_TOKEN_BATCH = 160;
const DISCOVERY_SNAPSHOT_RESPONSE_BUDGET_BYTES = getEncryptedResponsePlaintextBudgetBytes();
const DISCOVERY_SNAPSHOT_SAFE_PADDING_FLOOR = 128;
const DISCOVERY_SNAPSHOT_SAFE_DUMMY_BLOB_CHARS = 2048;
const DISCOVERY_SNAPSHOT_MAX_INITIAL_ROWS = 512;

function serializedPayloadBytes(payload) {
  try {
    return Buffer.byteLength(JSON.stringify(payload), 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function medianEncryptedBlobChars(rows) {
  const sample = (Array.isArray(rows) ? rows : [])
    .slice(0, 4096)
    .map((row) => (typeof row?.encryptedBlob === 'string' ? row.encryptedBlob.length : 0))
    .filter((length) => length > 0)
    .sort((a, b) => a - b);
  if (sample.length === 0) return 0;
  return sample[Math.floor(sample.length / 2)];
}

function initialDiscoverySnapshotRowLimit(rows, dummyBlobChars) {
  const rowCount = Array.isArray(rows) ? rows.length : 0;
  if (rowCount <= 0) return 0;

  const medianBlobChars = medianEncryptedBlobChars(rows);
  const estimatedEntryChars = Math.max(512, medianBlobChars, dummyBlobChars) + 160;
  const entryBudgetBytes = Math.floor(DISCOVERY_SNAPSHOT_RESPONSE_BUDGET_BYTES * 0.35);
  const estimatedRows = Math.floor(entryBudgetBytes / estimatedEntryChars);
  return Math.max(1, Math.min(rowCount, DISCOVERY_SNAPSHOT_MAX_INITIAL_ROWS, estimatedRows));
}

function buildBoundedDiscoverySnapshotPayload({ requestId, rows, snapshotConfig, requestedMode, deltaSince }) {
  const baseOptions = {
    deltaSince: requestedMode === 'delta' ? deltaSince : undefined
  };
  let dummyBlobChars = Math.min(snapshotConfig.dummyBlobChars, DISCOVERY_SNAPSHOT_SAFE_DUMMY_BLOB_CHARS);
  let paddingFloor = Math.min(snapshotConfig.paddingFloor, DISCOVERY_SNAPSHOT_SAFE_PADDING_FLOOR);
  let rowLimit = initialDiscoverySnapshotRowLimit(rows, dummyBlobChars);
  let lastPayloadBytes = 0;

  for (let attempt = 0; attempt < 18; attempt += 1) {
    const snapshotRows = Array.isArray(rows) ? rows.slice(0, rowLimit) : [];
    const snapshotResponse = buildDiscoverySnapshotResponse(snapshotRows, {
      ...snapshotConfig,
      ...baseOptions,
      maxRows: Math.max(1, rowLimit || 1),
      paddingFloor,
      dummyBlobChars
    });
    const payload = {
      type: SignalType.DISCOVERY_SNAPSHOT,
      requestId,
      success: true,
      ...snapshotResponse
    };
    const payloadBytes = serializedPayloadBytes(payload);
    lastPayloadBytes = payloadBytes;
    if (payloadBytes <= DISCOVERY_SNAPSHOT_RESPONSE_BUDGET_BYTES) {
      return {
        payload,
        payloadBytes,
        rowLimit,
        paddingFloor,
        dummyBlobChars
      };
    }

    if (dummyBlobChars > 512) {
      dummyBlobChars = Math.max(512, Math.floor(dummyBlobChars / 2));
      continue;
    }
    if (paddingFloor > 1) {
      paddingFloor = Math.max(1, Math.floor(paddingFloor / 2));
      continue;
    }
    if (rowLimit > 0) {
      rowLimit = Math.floor(rowLimit / 2);
      continue;
    }
    break;
  }

  return {
    payload: {
      type: SignalType.DISCOVERY_SNAPSHOT,
      requestId,
      success: false,
      error: 'discovery_snapshot_too_large'
    },
    payloadBytes: lastPayloadBytes,
    rowLimit,
    paddingFloor,
    dummyBlobChars,
    tooLarge: true
  };
}

async function handleWebSocketMessage({ ws, sessionId, message, parsed, context }) {
  const { authHandler } = context;

  try {
    let normalizedMessage = null;
    let msgString = null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      normalizedMessage = parsed;
      msgString = JSON.stringify(normalizedMessage);
    } else {
      msgString = (typeof message === 'string' ? message : String(message || '')).trim();
      if (msgString.length === 0) {
        return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Empty message' });
      }

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
    if (ws._authenticated || ws._hasAuthenticated) {
      state.hasAuthenticated = true;
    }
    if (ws._hasServerAuth) {
      state.hasServerAuth = true;
    }

    const serverPasswordHash = ServerConfig.getServerPasswordHash();

    // Ensure transport and gatekeeper signals always pass
    const isTransportSignal = [
      SignalType.REQUEST_SERVER_PUBLIC_KEY,
      SignalType.PQ_HANDSHAKE_INIT,
      SignalType.PQ_HANDSHAKE_ACK,
      SignalType.PQ_HEARTBEAT_PING,
      SignalType.PQ_HEARTBEAT_PONG,
      SignalType.PING,
      SignalType.PONG,
      SignalType.PQ_ENVELOPE
    ].includes(normalizedMessage.type);

    const isGatekeeperSignal = [
      SignalType.SERVER_ENTRY_REQUEST,
      SignalType.SERVER_ENTRY_CHALLENGE,
      SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
      SignalType.PRIVACY_PASS_REDEMPTION
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

    const isDiscoveryBootstrapSignal = [
      SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
      SignalType.OPRF_BLIND_EVALUATE
    ].includes(normalizedMessage.type);

    if (!ws._pqSessionId && !isTransportSignal) {
      cryptoLogger.warn('[SECURE-MSG] Rejecting pre-PQ message without closing socket', {
        signalType: normalizedMessage.type
      });
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        code: 'PQ_SESSION_REQUIRED',
        message: 'PQ handshake required before this request',
        requiresHandshake: true
      });
    }

    if (serverPasswordHash && !state.hasServerAuth && !ws._unlinkedSession && !isTransportSignal && !isGatekeeperSignal && !isAccountAuthSignal && !isDiscoveryBootstrapSignal) {
      cryptoLogger.warn('[GATEKEEPER] Access denied: Server entry token required', {
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
      const rateLimitPrincipalId = ws?._blindSocketId || ws?._sessionId || sessionId;
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
          const grantsServerEntry = !serverPasswordHash || !!ws._hasServerAuth;
          ws._authenticated = true;
          ws._hasAuthenticated = true;
          ws._hasServerAuth = grantsServerEntry;
          await ConnectionStateManager.updateState(sessionId, {
            hasServerAuth: grantsServerEntry,
            hasAuthenticated: true
          });
          if (grantsServerEntry) {
            try {
              await global.gateway?.addLocalConnection?.(ws);
            } catch (e) {
              cryptoLogger.warn('[AUTH] addLocalConnection after registration failed', { error: e?.message });
            }
            cryptoLogger.info('[GATEKEEPER] Server entry granted via OT registration');
          } else {
            cryptoLogger.info('[GATEKEEPER] Server entry still required after OT registration');
          }
        }
        break;
      case SignalType.AUTH_OT_REQUEST:
        await authHandler.handleOTSignIn(ws, normalizedMessage);
        break;
      case SignalType.AUTH_OT_FINALIZE:
        const otFinalRes = await authHandler.handleSignInFinalize(ws, normalizedMessage);
        if (otFinalRes?.success) {
          const grantsServerEntry = !serverPasswordHash || !!ws._hasServerAuth;
          ws._authenticated = true;
          ws._hasAuthenticated = true;
          ws._hasServerAuth = grantsServerEntry;
          await ConnectionStateManager.updateState(sessionId, {
            hasServerAuth: grantsServerEntry,
            hasAuthenticated: true
          });
          if (grantsServerEntry) {
            try {
              await global.gateway?.addLocalConnection?.(ws);
            } catch (e) {
              cryptoLogger.warn('[AUTH] addLocalConnection after login failed', { error: e?.message });
            }
            cryptoLogger.info('[GATEKEEPER] Server entry granted via OT login');
          } else {
            cryptoLogger.info('[GATEKEEPER] Server entry still required after OT login');
          }
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
            ws._hasServerAuth = true;
            await ConnectionStateManager.updateState(sessionId, { hasServerAuth: true });
            await sendSecureMessage(ws, { type: SignalType.OK, message: 'Server entry granted' });
            cryptoLogger.info('[GATEKEEPER] Server entry granted via Privacy Pass');
          } else {
            cryptoLogger.warn('[GATEKEEPER] Privacy Pass token verification returned false');
            await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Invalid entry token' });
          }
        } catch (error) {
          cryptoLogger.error('[GATEKEEPER] Token redemption failed', { error: error.message });
          await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Entry verification failed' });
        }
        break;
      case SignalType.TOKEN_VALIDATION:
        try {
          const { resumeRedemption } = normalizedMessage;

          const { anonymousSessionService } = await import('./authentication/anonymous-session-service.js');

          // Unlinkable autologin: the client resumes ONLY by redeeming a fresh one-time anonymous
          // Privacy Pass token. There is no stable-token fallback — a replayable token would let the
          // server link a client's reconnects.
          let result;
          if (resumeRedemption) {
            try {
              const { PrivacyPassServer, PrivacyPassHelpers } = await import('./authentication/privacy-pass-server.js');
              const parsed = PrivacyPassHelpers.parseRedemptionRequest(resumeRedemption);
              const redeemed = await PrivacyPassServer.redeemToken(
                parsed.token,
                parsed.nullifier,
                parsed.mac,
                parsed.tokenSecret,
                'account-auth'
              );
              if (redeemed?.valid) {
                // Grant fresh anonymous session for this connection only
                const session = await anonymousSessionService.createSessionWithCapabilities();
                result = { valid: true, sessionId: session.sessionId };
              } else {
                result = { valid: false, error: 'resume_token_invalid' };
              }
            } catch (e) {
              result = { valid: false, error: 'resume_token_invalid' };
            }
          } else {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: false,
              error: 'Invalid session token'
            });
          }

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
          const scopes = Array.isArray(capabilities?.scopes) ? capabilities.scopes : [];
          const sessionGrantsServerEntry = scopes.includes('server:entry');
          const serverEntryRequired = Boolean(serverPasswordHash) && !state.hasServerAuth && !ws._hasServerAuth && !sessionGrantsServerEntry;
          const serverEntryGranted = !serverEntryRequired;

          ws._authenticated = true;
          ws._hasAuthenticated = true;
          ws._anonymousSession = true;
          ws._hasServerAuth = serverEntryGranted;

          // Capture blinded token for unlinked credential issuance
          if (normalizedMessage.blindedToken) {
            ws._pendingBlindedToken = normalizedMessage.blindedToken;
          }

          await ConnectionStateManager.updateState(sessionId, {
            hasAuthenticated: true,
            hasServerAuth: serverEntryGranted,
            pqSessionId: ws._pqSessionId || null,
            connectedAt: Date.now(),
            lastActivity: Date.now(),
            scopes
          });

          if (!serverEntryGranted) {
            ws._pendingBlindedToken = null;
            cryptoLogger.warn('[TOKEN-VALIDATION] Session valid but server entry is still required');
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              valid: true,
              serverEntryRequired: true,
              serverEntryGranted: false
            });
          }

          // Register connection for local message delivery
          try {
            if (global.gateway?.addLocalConnection) {
              await global.gateway.addLocalConnection(ws);
            }
          } catch (e) {
            cryptoLogger.warn('[TOKEN-VALIDATION] addLocalConnection failed', { error: e?.message });
          }

          cryptoLogger.info('[TOKEN-VALIDATION] Anonymous session validation successful');

          const response = {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            valid: true,
            serverEntryRequired: false,
            serverEntryGranted: true
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


      case SignalType.RATE_LIMIT_STATUS:
        await handleRateLimitStatus({ ws, sessionId, parsed: normalizedMessage, state });
        break;

      case SignalType.REQUEST_SERVER_PUBLIC_KEY:
        try {
          const { message } = await gateway.getServerPublicKeyMessage();
          ws.send(message);
          cryptoLogger.info('[SERVER] Sent server public keys on request');
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
        {
          const requestId = typeof normalizedMessage.requestId === 'string'
            ? normalizedMessage.requestId.slice(0, 128)
            : undefined;
          if (!normalizedMessage.blindedPoint) {
            return await sendSecureMessage(ws, { type: SignalType.ERROR, requestId, message: 'Blinded point required' });
          }
          try {
            const clientId = privateLookupId('oprf-rate-client-v2', sessionId || ws._pqSessionId || 'anonymous');
            const evalResult = oprfDiscoveryServer.blindEvaluate(normalizedMessage.blindedPoint, clientId);
            const epochInfo = discoveryEpochManager.getEpochInfo();
            await sendSecureMessage(ws, {
              type: SignalType.OPRF_BLIND_EVALUATE_RESPONSE,
              requestId,
              blindedPoint: normalizedMessage.blindedPoint,
              evaluated: evalResult.evaluated,
              proof: evalResult.proof,
              publicKey: evalResult.publicKey,
              epoch: epochInfo.current
            });
          } catch (error) {
            cryptoLogger.error('[OPRF-DISCOVERY] Blind evaluation failed:', {
              error: error.message
            });
            const isRateLimit = error.message?.toLowerCase().includes('rate limit');
            await sendSecureMessage(ws, {
              type: SignalType.ERROR,
              requestId,
              message: error.message || 'OPRF evaluation failed',
              code: isRateLimit ? 'OPRF_RATE_LIMIT' : 'OPRF_EVAL_FAILURE'
            });
          }
        }
        break;

      case SignalType.PUBLISH_DISCOVERY:
        {
          const requestId = typeof normalizedMessage.requestId === 'string'
            ? normalizedMessage.requestId.slice(0, 128)
            : undefined;
          const sendPublishAck = async ({ success, error, stage }) => {
            const ackPayload = {
              type: SignalType.OK,
              requestId,
              success: success === true,
              op: 'publish-discovery',
              stage,
              serverTime: Date.now()
            };
            if (typeof error === 'string' && error) {
              ackPayload.error = error.slice(0, 160);
            }
            try {
              await sendSecureMessage(ws, ackPayload);
              cryptoLogger.info('[DISCOVERY] Publish ack sent', {
                success: ackPayload.success,
                stage,
                hasRequestId: typeof requestId === 'string' && requestId.length > 0
              });
              return true;
            } catch (ackError) {
              cryptoLogger.warn('[DISCOVERY] Publish ack send failed', {
                success: ackPayload.success,
                stage,
                hasRequestId: typeof requestId === 'string' && requestId.length > 0
              });
              throw ackError;
            }
          };

          // K-anon discovery publish. client sends { epochId, bucketId, publishId } entries
          const normalizedBucketBatch = [];
          const seenPublish = new Set();
          const appendBucket = (raw) => {
            if (!raw || typeof raw !== 'object') return;
            const epochId = typeof raw.epochId === 'string' ? raw.epochId.trim() : '';
            const bucketId = Number.isInteger(raw.bucketId) ? raw.bucketId : Number.parseInt(raw.bucketId, 10);
            const publishId = typeof raw.publishId === 'string' ? raw.publishId.trim().toLowerCase() : '';
            if (!epochId || epochId.length > 64) return;
            if (!Number.isInteger(bucketId) || bucketId < 0) return;
            if (!/^[a-f0-9]{16,128}$/.test(publishId)) return;
            const key = `${epochId}:${publishId}`;
            if (seenPublish.has(key)) return;
            seenPublish.add(key);
            normalizedBucketBatch.push({ epochId, bucketId, publishId });
          };
          if (Array.isArray(normalizedMessage.bucketBatch)) {
            for (const raw of normalizedMessage.bucketBatch) {
              if (normalizedBucketBatch.length >= MAX_DISCOVERY_TOKEN_BATCH) break;
              appendBucket(raw);
            }
          }

          const primaryToken = normalizedBucketBatch[0]?.publishId || '';
          const publishLogShape = () => {
            const blobLen = typeof normalizedMessage.encryptedBlob === 'string'
              ? normalizedMessage.encryptedBlob.length
              : 0;
            const encryptedBlobSizeClass = blobLen <= 0
              ? 'none'
              : blobLen <= 16 * 1024
                ? 'lte-16k'
                : blobLen <= 64 * 1024
                  ? 'lte-64k'
                  : blobLen <= 256 * 1024
                    ? 'lte-256k'
                    : 'gt-256k';
            return {
              tokenBatchClass: normalizedBucketBatch.length <= 1
                ? 'single'
                : normalizedBucketBatch.length >= MAX_DISCOVERY_TOKEN_BATCH
                  ? 'max'
                  : 'batch',
              encryptedBlobSizeClass
            };
          };

          if (normalizedBucketBatch.length === 0 || !normalizedMessage.encryptedBlob) {
            cryptoLogger.warn('[DISCOVERY] Reject publish - invalid payload', {
              hasBucketBatch: Array.isArray(normalizedMessage.bucketBatch),
              bucketEntryCount: normalizedBucketBatch.length,
              hasEncryptedBlob: !!normalizedMessage.encryptedBlob
            });
            return await sendPublishAck({
              success: false,
              error: 'invalid_discovery_payload',
              stage: 'invalid-payload'
            });
          }

          const publishAuthenticated = !!state?.hasAuthenticated
            || !!ws._authenticated
            || !!ws._hasAuthenticated
            || !!ws._unlinkedSession;
          if (publishAuthenticated && !state.hasAuthenticated && !ws._unlinkedSession) {
            state.hasAuthenticated = true;
          }
          if (!publishAuthenticated) {
            cryptoLogger.warn('[DISCOVERY] Reject publish - not authenticated', {
              ...publishLogShape(),
              hasAuthenticated: !!state?.hasAuthenticated,
              wsAuthenticated: !!ws._authenticated,
              wsHasAuthenticated: !!ws._hasAuthenticated,
              unlinkedSession: !!ws._unlinkedSession
            });
            return await sendPublishAck({
              success: false,
              error: 'authentication_required',
              stage: 'auth-required'
            });
          }

          // Deduplicate rapid publish requests with the same primary token
          if (primaryToken) {
            const now = Date.now();
            const primaryTokenKey = privateLookupId('discovery-publish-dedup-v2', primaryToken);
            const lastPublish = recentPublishTokens.get(primaryTokenKey);
            if (lastPublish && (now - lastPublish) < PUBLISH_DEDUP_WINDOW_MS) {
              cryptoLogger.info('[DISCOVERY] Duplicate publish suppressed', {
                ...publishLogShape(),
                suppressionWindow: 'recent'
              });
              await sendPublishAck({ success: true, stage: 'dedup-suppressed' });
              return;
            }
            recentPublishTokens.set(primaryTokenKey, now);
            // Periodically clean stale entries
            if (recentPublishTokens.size > 500) {
              for (const [token, ts] of recentPublishTokens) {
                if (now - ts > PUBLISH_DEDUP_WINDOW_MS) recentPublishTokens.delete(token);
              }
            }
          }

          cryptoLogger.info('[DISCOVERY] Publish received', {
            ...publishLogShape(),
            hasAuthenticated: !!state?.hasAuthenticated,
            wsAuthenticated: !!ws._authenticated,
            wsHasAuthenticated: !!ws._hasAuthenticated,
            unlinkedSession: !!ws._unlinkedSession
          });

          // Rolling discoverability lease
          const expiresAt = Date.now() + DISCOVERY_LEASE_TTL_MS;
          let publishSuccess = false;
          try {
            const enqueueResult = await enqueueDiscoveryPublication({
              bucketBatch: normalizedBucketBatch,
              encryptedBlob: normalizedMessage.encryptedBlob,
              expiresAt
            });
            publishSuccess = enqueueResult.queued === true;
            cryptoLogger.info('[DISCOVERY] Publish enqueue completed', {
              ...publishLogShape(),
              success: publishSuccess,
              backend: enqueueResult.backend || 'unknown'
            });
          } catch (e) {
            cryptoLogger.error('[DISCOVERY] Publish failed', {
              ...publishLogShape(),
              error: e?.message || String(e)
            });
            await sendPublishAck({ success: false, error: e?.message, stage: 'queue-failed' });
            break;
          }

          cryptoLogger.info('[DISCOVERY] Publish queued for delayed batch storage', {
            ...publishLogShape(),
            success: publishSuccess,
            releaseWindow: 'delayed-batch'
          });
          await sendPublishAck({ success: publishSuccess, stage: 'queued' });
        }
        break;

      case SignalType.DISCOVERY_SNAPSHOT_REQUEST:
        {
          const requestId = typeof normalizedMessage.requestId === 'string'
            ? normalizedMessage.requestId.slice(0, 128)
            : undefined;

          cryptoLogger.info('[DISCOVERY] Target-free snapshot requested', {
            hasAuthenticated: !!state?.hasAuthenticated,
            unlinkedSession: !!ws._unlinkedSession
          });
          logEvent('discovery-snapshot-requested', {
            mode: normalizedMessage.snapshotMode === 'delta' ? 'delta' : 'full',
            gateClass: state?.hasServerAuth ? 'server-entry' : ws._unlinkedSession ? 'unlinked' : 'open'
          });

          const snapshotConfig = getDiscoverySnapshotConfig();
          const requestedMode = normalizedMessage.snapshotMode === 'delta' ? 'delta' : 'full';
          const deltaSince = Number(normalizedMessage.deltaSince);
          const snapshot = requestedMode === 'delta' && Number.isFinite(deltaSince)
            ? await DiscoveryDB.snapshotSince(deltaSince, snapshotConfig.maxRows)
            : await DiscoveryDB.snapshotActive(snapshotConfig.maxRows);
          const boundedSnapshot = buildBoundedDiscoverySnapshotPayload({
            requestId,
            rows: snapshot,
            snapshotConfig,
            requestedMode,
            deltaSince
          });
          const snapshotResponse = boundedSnapshot.payload?.snapshot
            ? { snapshot: boundedSnapshot.payload.snapshot }
            : { snapshot: null };
          cryptoLogger.info('[DISCOVERY] Snapshot response prepared', {
            mode: requestedMode,
            rowCountClass: snapshot.length <= 0
              ? 'none'
              : snapshot.length === 1
                ? 'single'
                : snapshot.length <= 32
                  ? 'small'
                : snapshot.length <= 1024
                  ? 'medium'
                  : 'large',
            payloadSizeClass: encryptedResponseSizeClass(boundedSnapshot.payloadBytes),
            responseBudgetClass: encryptedResponseSizeClass(DISCOVERY_SNAPSHOT_RESPONSE_BUDGET_BYTES),
            boundedRowClass: boundedSnapshot.rowLimit <= 0
              ? 'none'
              : boundedSnapshot.rowLimit === 1
                ? 'single'
                : boundedSnapshot.rowLimit <= 32
                  ? 'small'
                  : boundedSnapshot.rowLimit <= 1024
                    ? 'medium'
                    : 'large',
            boundedPaddingClass: boundedSnapshot.paddingFloor <= 1
              ? 'single'
              : boundedSnapshot.paddingFloor <= 32
                ? 'small'
                : boundedSnapshot.paddingFloor <= 1024
                  ? 'medium'
                  : 'large',
            tooLarge: boundedSnapshot.tooLarge === true,
            compressedSizeClass: typeof snapshotResponse.snapshot?.compressed === 'string' && snapshotResponse.snapshot.compressed.length <= 16 * 1024
              ? 'lte-16k'
              : typeof snapshotResponse.snapshot?.compressed === 'string' && snapshotResponse.snapshot.compressed.length <= 256 * 1024
                ? 'lte-256k'
                : 'gt-256k'
          });
          logEvent('discovery-snapshot-prepared', {
            mode: requestedMode,
            rowClass: snapshot.length <= 0
              ? 'none'
              : snapshot.length === 1
                ? 'single'
                : snapshot.length <= 32
                  ? 'small'
                  : snapshot.length <= 1024
                    ? 'medium'
                    : 'large',
            compressedClass: typeof snapshotResponse.snapshot?.compressed === 'string' && snapshotResponse.snapshot.compressed.length <= 16 * 1024
              ? 'lte-16k'
              : typeof snapshotResponse.snapshot?.compressed === 'string' && snapshotResponse.snapshot.compressed.length <= 256 * 1024
                ? 'lte-256k'
                : 'gt-256k'
          });
          await sendSecureMessage(ws, boundedSnapshot.payload);
        }
        break;

      case SignalType.PIR_MANIFEST_REQUEST:
        await handlePirManifestRequest({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.PIR_QUERY:
        await handlePirQuery({ ws, parsed: normalizedMessage, state });
        break;

      case SignalType.BLOCK_LIST_SYNC:
        await handleBlockListSync({ ws, sessionId, parsed: normalizedMessage, state });
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

  if (statusLogInterval) {
    clearInterval(statusLogInterval);
    statusLogInterval = null;
  }

  if (stopRuntimeMonitor) {
    stopRuntimeMonitor();
    stopRuntimeMonitor = null;
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
