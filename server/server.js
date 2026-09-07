import nodeCrypto from 'crypto';

if (process.platform !== 'linux') {
  throw new Error('Native server deployment supports only Linux');
}

if (!globalThis.crypto?.subtle) throw new Error('Node.js 22 or newer is required');
import express from 'express';
import { WebSocketServer } from 'ws';
import {
  isLinkedAuthenticationSignalType,
  isPreServerEntrySignalType,
  isUnlinkedApplicationSignalType,
  SignalType
} from './signals.js';
import { CryptoUtils } from './crypto/unified-crypto.js';
import {
  closePgPool,
  destroyDatabaseSecrets,
  DiscoveryDB,
  initDatabase,
  privateLookupId,
  UserDatabase
} from './database/database.js';
import { AvatarBlobDB } from './database/avatar-blob-db.js';
import * as ServerConfig from './config/config.js';
import * as authentication from './authentication/authentication.js';
import { initializeServerPasswordGate } from './authentication/auth-utils.js';
import { ServerGatekeeper } from './authentication/gatekeeper.js';
import { startServerPasswordMonitor } from './authentication/server-password-monitor.js';
import {
  startPrivateAuthPirService,
  stopPrivateAuthPirService,
} from './authentication/private-auth-pir.js';
import { destroyAdminAuth, initializeAdminAuth } from '../scripts/admin-auth.js';
import { rateLimitMiddleware } from './rate-limiting/rate-limit-middleware.js';
import apiRoutes, {
  destroyApiRoutes,
  dispatchAnonymousApiOperation
} from './routes/api-routes.js';
import {
  createPqAnonymousBodyAdmission,
  createPqAnonymousHttpHandler,
  handlePqAnonymousHttpParseError,
  PQ_ANONYMOUS_HTTP_MAX_REQUEST_BYTES
} from './routes/pq-anonymous-http.js';
import { createServer as createBootstrapServer, registerShutdownHandlers } from './bootstrap/server-bootstrap.js';
import { attachGateway } from './websocket/gateway.js';
import { validateWsWireProtection } from './security/layer-agreement-policy.js';
import { SERVER_CONSTANTS, SECURITY_HEADERS, CORS_CONFIG } from './config/constants.js';
import { PROTOCOL_KEYS } from './config/protocol-keys.js';
import { POW_SEED_BYTES, SHA_256_ALGORITHM } from './utils/crypto-consts.js';

import {
  handlePQHandshake,
  handlePQBinaryCell,
  sendSecureMessage,
  initializeEnvelopeHandler,
  destroyEnvelopeHandler
} from './messaging/pq-envelope-handler.js';
import { initializeCluster, shutdownCluster } from './cluster/cluster-integration.js';
import { CLUSTER_SERVER_ID_RE } from './cluster/signed-message.js';
import { getServerRuntimeTelemetry } from './telemetry/runtime-telemetry.js';
import clusterRoutes from './routes/cluster-routes.js';
import {
  handleBlindRoute,
  handleActivateDelivery,
  hasAnonymousDeliveryAuthorization,
  isLiveDeliverySocket
} from './handlers/delivery-handlers.js';
import { BlindRouter } from './routing/blind-router.js';
import { TimingProtection } from './routing/timing-protection.js';
import { OPRF_DISCOVERY_POW_DIFFICULTY, oprfDiscoveryServer } from './crypto/oprf-discovery.js';
import {
  enqueueDiscoveryPublication,
  startDiscoveryPublicationRelay,
  stopDiscoveryPublicationRelay
} from './discovery/publication-privacy.js';
import {
  destroyDiscoveryPublicationAuthentication,
  initializeDiscoveryPublicationAuthentication
} from './discovery/publication-auth.js';
import { getDiscoveryEpochInfo } from './discovery/epoch.js';
import {
  destroyDiscoveryBucketSecrets,
  isCanonicalDiscoveryBlob,
  isCanonicalDiscoveryBucketIds
} from './discovery/bucket-layout.js';
import {
  destroyDiscoveryBucketIndex
} from './discovery/bucket-index.js';
import { cleanup as cleanupRedis } from './session/redis-client.js';
import { shutdownAuthCryptoWorker } from './crypto/auth-crypto-worker-service.js';
import { destroyAuthRootKey } from './crypto/auth-root.js';
import { verifyPowSolution } from './security/auth-throttle.js';
import {
  pirEpochWindowMs,
  prebuildCurrentPirEpoch,
  prebuildNextPirEpoch,
  startPirService,
  stopPirService
} from './pir/pir-service.js';

let pirPrebuildTimer = null;
import {
  claimAnonymousRequestPow,
  deriveAnonymousRequestPowSeed
} from './security/anonymous-request-pow.js';
import {
  destroyKeyTransparencyService,
  initializeKeyTransparencyService
} from './key-transparency/service.js';
import { hasExactPlainObjectKeys } from './utils/validation.js';
import { isCanonicalBase64Bytes } from './utils/encoding.js';
import {
  DISCOVERY_EPOCH_ID_RE,
  HEX_64_RE,
  PUBLICATION_ID_RE,
  UUID_V4_RE
} from './utils/patterns.js';
import { LOOPBACK_HOST } from './config/infrastructure.js';
import {
  ACCOUNT_AUTH_PURPOSE
} from './config/audiences.js';
import {
  recordServerOperation,
  setDeliveryTelemetryProvider,
  setRuntimeTelemetryProvider,
  startServerTelemetry,
  stopServerTelemetry
} from './telemetry/server-telemetry.js';
import {
  DISCOVERY_EPOCH_EXPIRED,
  DISCOVERY_PUBLICATION_UNAVAILABLE,
  INVALID_REQUEST,
  PQ_SESSION_REQUIRED,
  SERVER_KEYS_UNAVAILABLE_MESSAGE
} from './config/error-codes.js';

const DISCOVERY_PUBLISH_POW_DOMAIN = PROTOCOL_KEYS.DISCOVERY_PUBLISH_POW;
const DISCOVERY_PUBLISH_POW_DIFFICULTY = 18;
const SERVER_ENTRY_TOKEN_INVALID = 'SERVER_ENTRY_TOKEN_INVALID';

function startServerCoverTraffic() {
  TimingProtection.startCoverTraffic(async () => {
    try {
      await BlindRouter.enqueueMixnetCoverWrite();
    } catch { }
  });
}

async function enforceConnectionPrivacyMode(ws, message) {
  const requestedMode = isLinkedAuthenticationSignalType(message?.type)
    ? 'linked-authentication'
    : isUnlinkedApplicationSignalType(message?.type)
      ? 'anonymous-application'
      : null;
  if (!requestedMode) return true;

  if (!ws._connectionPrivacyMode) {
    ws._connectionPrivacyMode = requestedMode;
    return true;
  }
  if (ws._connectionPrivacyMode === requestedMode) return true;

  const requestId = typeof message?.requestId === 'string' &&
    UUID_V4_RE.test(message.requestId)
    ? message.requestId
    : undefined;
  try {
    await sendSecureMessage(ws, {
      type: SignalType.AUTH_ERROR,
      ...(requestId ? { requestId } : {}),
      code: 'CONNECTION_MODE_CONFLICT',
      message: 'Connection privacy mode conflict'
    });
  } finally {
    ws.close(1008, 'Connection privacy mode conflict');
  }
  return false;
}

let server, wss, gateway, serverHybridKeyPair, retentionCleanupInterval, serverPasswordMonitor;
let retentionCleanupInFlight = null;

async function runRetentionCleanup() {
  if (retentionCleanupInFlight) return retentionCleanupInFlight;
  const pending = (async () => {
    await DiscoveryDB.cleanup();
    await AvatarBlobDB.pruneExpired();
    await AvatarBlobDB.enforceCap(SERVER_CONSTANTS.AVATAR_BLOB_MAX_COUNT);
  })();
  retentionCleanupInFlight = pending;
  try {
    await pending;
  } finally {
    if (retentionCleanupInFlight === pending) retentionCleanupInFlight = null;
  }
}

function startRetentionCleanup() {
  if (retentionCleanupInterval) return;
  retentionCleanupInterval = setInterval(() => {
    void runRetentionCleanup().catch((error) => {
      console.error('[SERVER] Retention cleanup failed', error);
    });
  }, 30 * 60_000);
  retentionCleanupInterval.unref?.();
}

async function createExpressApp({ context }) {
  const app = express();
  app.disable('x-powered-by');

  app.use((req, res, next) => {
    const started = performance.now();
    let recorded = false;
    const record = () => {
      if (recorded) return;
      recorded = true;
      recordServerOperation(performance.now() - started, {
        bytes: Number(req.headers['content-length'] || 0)
      });
    };
    res.once('finish', record);
    res.once('close', record);
    next();
  });

  app.use((req, res, next) => {
    for (const [header, value] of Object.entries(SECURITY_HEADERS)) {
      res.setHeader(header, value);
    }

    const allowedOrigins = CORS_CONFIG.ALLOWED_ORIGINS || [];
    const requestOrigin = req.headers.origin;
    const isAllowedOrigin = !!requestOrigin && allowedOrigins.includes(requestOrigin);

    res.setHeader('Access-Control-Allow-Methods', CORS_CONFIG.ALLOWED_METHODS);
    res.setHeader('Access-Control-Allow-Headers', CORS_CONFIG.ALLOWED_HEADERS);
    res.setHeader('Access-Control-Max-Age', `${CORS_CONFIG.MAX_AGE_SECONDS}`);

    if (isAllowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', requestOrigin);
      res.setHeader('Vary', 'Origin');
    }

    if (req.method === 'OPTIONS') {
      if (requestOrigin && !isAllowedOrigin) {
        res.status(403).end();
        return;
      }
      res.status(204).end();
      return;
    }

    next();
  });

  const pqAnonymousHttpHandler = createPqAnonymousHttpHandler({
    serverHybridKeyPair: context.serverHybridKeyPair,
    dispatchOperation: dispatchAnonymousApiOperation
  });
  const pqAnonymousBodyAdmission = createPqAnonymousBodyAdmission();
  app.post(
    '/api/anonymous',
    pqAnonymousBodyAdmission,
    express.raw({
      type: 'application/octet-stream',
      limit: PQ_ANONYMOUS_HTTP_MAX_REQUEST_BYTES,
      inflate: false
    }),
    pqAnonymousHttpHandler,
    handlePqAnonymousHttpParseError
  );

  app.use('/api/cluster', clusterRoutes);
  app.use('/api', apiRoutes);
  app.use('/api', (_req, res) => {
    res.status(404).json({ ok: false, error: 'not_found' });
  });

  // Terminal error handler
  app.use((err, req, res, _next) => {
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
      console.error('[HTTP] Request failed', err);
    }
    try {
      res.status(status >= 400 && status < 600 ? status : 500).json({ ok: false, error: 'request_failed' });
    } catch { /* socket gone */ }
  });

  return app;
}

async function createWebSocketServer({ server: httpsServer }) {
  wss = new WebSocketServer({
    server: httpsServer,
    maxPayload: SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES,
    verifyClient: ({ origin }, done) => {
      const allowed = !origin || (CORS_CONFIG.ALLOWED_ORIGINS || []).includes(origin);
      done(allowed, allowed ? 101 : 403, allowed ? undefined : 'Forbidden');
    }
  });

  await BlindRouter.subscribeToBlindDelivery();
  console.log('[CROSS-INSTANCE] Blind delivery subscriber initialized');

  try {
    await startPirService();
    await prebuildCurrentPirEpoch();
    void prebuildNextPirEpoch()?.catch((error) => {
      console.error('[PIR] Snapshot refresh failed', error);
    });
    pirPrebuildTimer = setInterval(() => {
      try {
        void prebuildNextPirEpoch()?.catch((error) => {
          console.error('[PIR] Snapshot refresh failed', error);
        });
      } catch (error) {
        console.error('[PIR] Snapshot prebuild failed', error);
      }
    }, Math.max(1000, Math.floor(pirEpochWindowMs() / 2)));
    pirPrebuildTimer.unref?.();
    console.log('[PIR] Spool retrieval service started');
  } catch (error) {
    console.error('[PIR] Service setup failed', error);
    console.error(`[PIR] FATAL: ${error?.message ?? error}`);
    throw error;
  }

  startDiscoveryPublicationRelay();
  console.log('[DISCOVERY] Publication relay started');

  return wss;
}

async function prepareServerContext() {
  const identitySeedHex = process.env.SERVER_TRANSPORT_IDENTITY_SEED;
  if (typeof identitySeedHex !== 'string' || !HEX_64_RE.test(identitySeedHex)) {
    throw new Error('SERVER_TRANSPORT_IDENTITY_SEED must be a shared, random 32-byte hex seed');
  }
  const identitySeed = Buffer.from(identitySeedHex, 'hex');
  delete process.env.SERVER_TRANSPORT_IDENTITY_SEED;
  let flatKeyPair;
  try {
    flatKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPairFromSeed(identitySeed);
  } finally {
    identitySeed.fill(0);
  }

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
  BlindRouter.initializeGlobalMixAuthentication(serverHybridKeyPair.dilithium);
  initializeDiscoveryPublicationAuthentication(serverHybridKeyPair.dilithium);
  await initializeKeyTransparencyService(serverHybridKeyPair.dilithium);

  initializeEnvelopeHandler(serverHybridKeyPair);

  const { getPgPool } = await import('./database/database.js');
  const db = await getPgPool();
  await rateLimitMiddleware.limiter();

  // Initialize OPAQUE server
  const { OPAQUEServer } = await import('./crypto/opaque-service.js');
  await OPAQUEServer.initialize();
  await startPrivateAuthPirService(await UserDatabase.getPrivateAuthRecords());

  // Initialize Privacy Pass server
  const { PrivacyPassServer, NullifierStore } = await import('./authentication/privacy-pass-server.js');
  const nullifierStore = new NullifierStore(db);
  await PrivacyPassServer.initialize(nullifierStore);

  const clusterAdminUsername = process.env.CLUSTER_ADMIN_USERNAME?.trim();
  const clusterAdminPassword = process.env.CLUSTER_ADMIN_PASSWORD;
  if ((clusterAdminUsername && !clusterAdminPassword) || (!clusterAdminUsername && clusterAdminPassword)) {
    throw new Error('CLUSTER_ADMIN_USERNAME and CLUSTER_ADMIN_PASSWORD must be configured together');
  }
  if (clusterAdminUsername && clusterAdminPassword) {
    await initializeAdminAuth(clusterAdminUsername, clusterAdminPassword);
    delete process.env.CLUSTER_ADMIN_PASSWORD;
  }

  // Initialize OPRF Discovery server
  await oprfDiscoveryServer.initialize();

  const discoveryEpochInfo = getDiscoveryEpochInfo();
  console.log('[DISCOVERY] Epoch started', {
    currentEpoch: discoveryEpochInfo.current,
    durationHours: 6
  });

  const authHandler = new authentication.AccountAuthHandler();

  return {
    serverHybridKeyPair,
    authHandler
  };
}

function destroyServerTransportKeys() {
  const keyPair = serverHybridKeyPair;
  keyPair?.kyber?.publicKey?.fill(0);
  keyPair?.kyber?.secretKey?.fill(0);
  keyPair?.dilithium?.publicKey?.fill(0);
  keyPair?.dilithium?.secretKey?.fill(0);
  keyPair?.x25519?.publicKey?.fill(0);
  keyPair?.x25519?.secretKey?.fill(0);
  serverHybridKeyPair = null;
}

async function onServerReady({ server: httpsServer, wss: wsServer, context }) {
  server = httpsServer;
  wss = wsServer;
  serverHybridKeyPair = context.serverHybridKeyPair;

  gateway = attachGateway({
    wss,
    serverHybridKeyPair,
    serverId: process.env.SERVER_ID,
    config: {
      bandwidthQuota: SERVER_CONSTANTS.BANDWIDTH_QUOTA,
      bandwidthWindowMs: SERVER_CONSTANTS.BANDWIDTH_WINDOW,
      messageQuota: SERVER_CONSTANTS.MESSAGE_HARD_LIMIT_PER_MINUTE,
      messageWindowMs: SERVER_CONSTANTS.MESSAGE_RATE_RESET_INTERVAL,
      heartbeatIntervalMs: SERVER_CONSTANTS.HEARTBEAT_INTERVAL,
      fixedMessageSizeBytes: SERVER_CONSTANTS.WS_FIXED_MESSAGE_SIZE_BYTES,
    },
    onMessage: async ({ ws, parsed }) => {
      const started = performance.now();
      try {
        await handleWebSocketMessage({ ws, parsed, context });
      } finally {
        recordServerOperation(performance.now() - started);
      }
    },
    onBinaryMessage: async ({ ws, frame }) => {
      const started = performance.now();
      try {
        await handlePQBinaryCell({
          ws,
          cell: frame,
          context,
          handleInnerMessage: handleWebSocketMessage
        });
      } finally {
        recordServerOperation(performance.now() - started, {
          frame: true,
          bytes: frame?.byteLength || frame?.length || 0
        });
      }
    },
    onConnectionClosed: (ws) => context.authHandler.clearConnectionState(ws)
  });

  const bindAddress = process.env.BIND_ADDRESS || LOOPBACK_HOST;
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.removeListener('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    try {
      server.listen(ServerConfig.PORT, bindAddress);
    } catch (error) {
      server.removeListener('error', onError);
      server.removeListener('listening', onListening);
      reject(error);
    }
  });

  server.on('error', (error) => {
    console.error('[SECURITY] HTTPS server error', error);
  });

  const boundAddress = server.address();
  if (!boundAddress || typeof boundAddress === 'string') {
    throw new Error('HTTPS server did not expose a bound TCP address');
  }
  const actualPort = boundAddress.port;

  console.log('[SERVER] Server listening', {
    port: actualPort,
    serverId: process.env.SERVER_ID,
    address: bindAddress
  });

  serverPasswordMonitor = await startServerPasswordMonitor({
    rotatePassword: (password) => ServerGatekeeper.rotateExplicit(password),
    onPasswordRotated: async ({ disconnectClients }) => {
      if (disconnectClients) {
        const revoked = gateway?.revokeAllConnections?.() || 0;
        console.log('[SERVER] Revoked sockets after password rotation', { revoked });
        return;
      }
      const retainedClients = Array.from(wss?.clients || []).filter((socket) => (
        socket.readyState === 1 && socket._pqSessionId && socket._hasServerAuth
      ));
      const notificationResults = await Promise.allSettled(retainedClients.map((socket) => sendSecureMessage(socket, {
        type: SignalType.SERVER_ENTRY_CREDENTIAL_ROTATED,
      })));
      console.log('[SERVER] Existing sockets retained after password rotation', {
        retained: retainedClients.length,
        notified: notificationResults.filter((result) => (
          result.status === 'fulfilled' && result.value !== false
        )).length
      });
    },
  });

  startServerCoverTraffic();

  console.log('[CLUSTER] Initializing server clustering');
  if (!['true', 'false'].includes(process.env.CLUSTER_PRIMARY)) {
    throw new Error('CLUSTER_PRIMARY must be explicitly set to true or false');
  }
  if (!['true', 'false'].includes(process.env.CLUSTER_AUTO_APPROVE)) {
    throw new Error('CLUSTER_AUTO_APPROVE must be explicitly set to true or false');
  }
  const clusterManager = await initializeCluster({
    serverHybridKeyPair,
    serverId: process.env.SERVER_ID,
    isPrimary: process.env.CLUSTER_PRIMARY === 'true',
    autoApprove: process.env.CLUSTER_AUTO_APPROVE === 'true',
  });
  const terminateAfterClusterRemoval = () => {
    console.error('[CLUSTER] This server lost cluster membership; shutting down the server process');
    process.kill(process.pid, 'SIGTERM');
  };
  clusterManager.once('self-force-removed', terminateAfterClusterRemoval);
  clusterManager.once('self-membership-lost', terminateAfterClusterRemoval);
  console.log('[CLUSTER] Server clustering ready', {
    serverId: clusterManager.serverId,
    isPrimary: clusterManager.isPrimary,
    isApproved: clusterManager.isApproved
  });
}

const recentPublishTokens = new Map();
const pendingPublishTokens = new Map();
const PUBLISH_DEDUP_WINDOW_MS = 5000;
const RECENT_PUBLISH_TOKEN_MAX = 2048;

function discoveryPublicationDedupKey(publication, encryptedBlob) {
  const contentDigest = nodeCrypto
    .createHash(SHA_256_ALGORITHM)
    .update(PROTOCOL_KEYS.DISCOVERY_PUBLISH_CONTENT)
    .update(publication.epochId)
    .update('\0')
    .update(publication.publishId)
    .update('\0')
    .update(publication.bucketIds.join(','))
    .update('\0')
    .update(encryptedBlob)
    .digest('base64url');
  return privateLookupId(PROTOCOL_KEYS.DISCOVERY_PUBLISH_DEDUP, contentDigest);
}

function rememberRecentPublishToken(tokenKey, publishedAt) {
  for (const [token, timestamp] of recentPublishTokens) {
    if (publishedAt - timestamp >= PUBLISH_DEDUP_WINDOW_MS) {
      recentPublishTokens.delete(token);
    }
  }
  recentPublishTokens.delete(tokenKey);
  while (recentPublishTokens.size >= RECENT_PUBLISH_TOKEN_MAX) {
    const oldest = recentPublishTokens.keys().next().value;
    if (typeof oldest !== 'string') break;
    recentPublishTokens.delete(oldest);
  }
  recentPublishTokens.set(tokenKey, publishedAt);
  const expiry = setTimeout(() => {
    if (recentPublishTokens.get(tokenKey) === publishedAt) {
      recentPublishTokens.delete(tokenKey);
    }
  }, PUBLISH_DEDUP_WINDOW_MS + 1);
  expiry.unref?.();
}
const DISCOVERY_FORWARD_PUBLISH_WINDOW_MS = 24 * 60 * 60 * 1000;
const DISCOVERY_LEASE_TTL_MS = DISCOVERY_FORWARD_PUBLISH_WINDOW_MS;

async function handleWebSocketMessage({ ws, parsed, context, isPqProtected = false }) {
  const { authHandler } = context;

  try {
    const normalizedMessage = parsed;

    if (typeof normalizedMessage !== 'object' || normalizedMessage === null) { return await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Invalid message format - expected object' }); }

    const wireProtection = validateWsWireProtection({
      hasPqSession: !!ws._pqSessionId,
      isPqProtected,
      messageType: normalizedMessage.type
    });
    if (!wireProtection.valid) {
      console.warn('[SECURE-MSG] Rejected invalid WebSocket protection phase', {
        reason: wireProtection.reason
      });
      ws.close(1008, 'Invalid secure transport phase');
      return;
    }

    const serverPasswordRequired = ServerConfig.isServerPasswordGateReady();

    const isTransportSignal = [
      SignalType.REQUEST_SERVER_PUBLIC_KEY,
      SignalType.PQ_HANDSHAKE_INIT
    ].includes(normalizedMessage.type);

    if (!ws._pqSessionId && !isTransportSignal) {
      console.warn('[SECURE-MSG] Rejecting pre-PQ message without closing socket', {
        signalType: normalizedMessage.type
      });
      return await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        code: PQ_SESSION_REQUIRED,
        message: 'PQ handshake required before this request',
        requiresHandshake: true
      });
    }

    if (!await enforceConnectionPrivacyMode(ws, normalizedMessage)) {
      return;
    }

    if (
      serverPasswordRequired &&
      !ws._hasServerAuth &&
      !ws._unlinkedSession &&
      !isPreServerEntrySignalType(normalizedMessage.type)
    ) {
      console.warn('[GATEKEEPER] Access denied: Server entry token required', {
        signalType: normalizedMessage.type,
        hasServerAuth: ws._hasServerAuth === true
      });
      return await sendSecureMessage(ws, {
        type: SignalType.AUTH_ERROR,
        message: 'Server entry token required',
        code: 'SERVER_ENTRY_REQUIRED'
      });
    }

    // message rate limiting
    try {
      const allowed = await rateLimitMiddleware.applyMessageRateLimiting(
        ws,
        normalizedMessage.type,
        normalizedMessage
      );
      if (!allowed) {
        return;
      }
    } catch (rateLimitError) {
      console.error('[RATE-LIMIT] Message processing stopped because rate limiting is unavailable', {
        error: rateLimitError?.message || String(rateLimitError)
      });
      try {
        await sendSecureMessage(ws, {
          type: SignalType.ERROR,
          code: 'RATE_LIMIT_UNAVAILABLE',
          message: 'Service temporarily unavailable'
        });
      } finally {
        ws.close(1013, 'Rate limiting unavailable');
      }
      return;
    }

    if (!isLiveDeliverySocket(ws)) return false;

    switch (normalizedMessage.type) {
      case SignalType.AUTH_REGISTER_REQUEST:
        await authHandler.handleRegisterRequest(ws, normalizedMessage);
        break;
      case SignalType.AUTH_REGISTER_FINALIZE:
        await authHandler.handleRegisterFinalize(ws, normalizedMessage);
        break;
      case SignalType.AUTH_REGISTER_CONFIRM:
        const registrationResult = await authHandler.handleRegisterConfirm(ws, normalizedMessage);
        if (registrationResult?.success) {
          if (!isLiveDeliverySocket(ws)) return false;
          const grantsServerEntry = !ServerConfig.isServerPasswordGateReady() || !!ws._hasServerAuth;
          ws._authenticated = true;
          ws._accountAuthViaAnonymousToken = false;
          ws._hasServerAuth = grantsServerEntry;
          if (grantsServerEntry) {
            console.log('[GATEKEEPER] Server entry granted');
          } else {
            console.log('[GATEKEEPER] Server entry still required after registration');
          }
        }
        break;
      case SignalType.AUTH_PIR_REQUEST:
        await authHandler.handlePIRSignIn(ws, normalizedMessage);
        break;
      case SignalType.AUTH_PIR_FINALIZE:
        const pirFinalResult = await authHandler.handleSignInFinalize(ws, normalizedMessage);
        if (pirFinalResult?.success) {
          if (!isLiveDeliverySocket(ws)) return false;
          const grantsServerEntry = !ServerConfig.isServerPasswordGateReady() || !!ws._hasServerAuth;
          ws._authenticated = true;
          ws._accountAuthViaAnonymousToken = false;
          ws._hasServerAuth = grantsServerEntry;
          if (grantsServerEntry) {
            console.log('[GATEKEEPER] Server entry granted via private login');
          } else {
            console.log('[GATEKEEPER] Server entry still required after private login');
          }
        }
        break;
      case SignalType.SERVER_ENTRY_REQUEST:
        await authHandler.gatekeeper.handleEntryRequest(ws, normalizedMessage);
        break;
      case SignalType.SERVER_ENTRY_TOKEN_ISSUANCE:
        await authHandler.gatekeeper.handleTokenIssuance(ws, normalizedMessage);
        break;
      case SignalType.ACCOUNT_AUTH_TOKEN_REFRESH:
        await authHandler.gatekeeper.handleAccountAuthTokenRefresh(ws, normalizedMessage);
        break;
      case SignalType.PRIVACY_PASS_REDEMPTION:
        try {
          const requestId = typeof normalizedMessage.requestId === 'string' &&
            UUID_V4_RE.test(normalizedMessage.requestId)
            ? normalizedMessage.requestId
            : null;
          if (!requestId) {
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              message: 'Invalid entry token request',
              code: INVALID_REQUEST
            });
          }
          if (!hasExactPlainObjectKeys(normalizedMessage, [
            'mac',
            'nullifier',
            'requestId',
            'token',
            'tokenSecret',
            'type'
          ])) {
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              requestId,
              message: 'Invalid entry token request',
              code: INVALID_REQUEST
            });
          }
          console.log('[GATEKEEPER] Processing Privacy Pass redemption', {
            hasToken: !!normalizedMessage.token,
            hasNullifier: !!normalizedMessage.nullifier,
            hasMac: !!normalizedMessage.mac
          });
          const verification = await authHandler.gatekeeper.verifyEntryToken(normalizedMessage);
          if (
            verification.valid &&
            isLiveDeliverySocket(ws) &&
            ServerGatekeeper.isServerEntryAuthorizationGenerationCurrent(
              verification.authorizationGeneration
            )
          ) {
            const delivered = await sendSecureMessage(ws, {
              type: SignalType.OK,
              requestId,
              message: 'Server entry granted'
            });
            if (delivered === false) return false;
            if (
              !isLiveDeliverySocket(ws) ||
              !ServerGatekeeper.isServerEntryAuthorizationGenerationCurrent(
                verification.authorizationGeneration
              )
            ) return false;
            ws._hasServerAuth = true;
            console.log('[GATEKEEPER] Server entry granted');
          } else {
            console.warn('[GATEKEEPER] Privacy Pass token verification returned false');
            await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              requestId,
              message: 'Invalid entry token',
              code: SERVER_ENTRY_TOKEN_INVALID
            });
          }
        } catch (error) {
          console.error('[GATEKEEPER] Token redemption failed', { error: error.message });
          const requestId = typeof normalizedMessage.requestId === 'string' &&
            UUID_V4_RE.test(normalizedMessage.requestId)
            ? normalizedMessage.requestId
            : undefined;
          await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: 'Entry verification failed' });
        }
        break;
      case SignalType.TOKEN_VALIDATION:
        let tokenValidationPreviousAuth = null;
        const tokenValidationRequestId = typeof normalizedMessage.requestId === 'string' &&
          UUID_V4_RE.test(normalizedMessage.requestId)
          ? normalizedMessage.requestId
          : null;
        const rollbackTokenValidationAuthorization = () => {
          if (!tokenValidationPreviousAuth) return;
          if (
            !isLiveDeliverySocket(ws) ||
            !ServerGatekeeper.isServerEntryAuthorizationGenerationCurrent(
              tokenValidationPreviousAuth.serverEntryAuthorizationGeneration
            )
          ) {
            tokenValidationPreviousAuth = null;
            return;
          }
          ws._authenticated = tokenValidationPreviousAuth.authenticated;
          ws._hasServerAuth = tokenValidationPreviousAuth.hasServerAuth;
          if (tokenValidationPreviousAuth.accountAuthViaAnonymousToken === undefined) {
            delete ws._accountAuthViaAnonymousToken;
          } else {
            ws._accountAuthViaAnonymousToken = tokenValidationPreviousAuth.accountAuthViaAnonymousToken;
          }
          tokenValidationPreviousAuth = null;
        };
        try {
          if (!tokenValidationRequestId) {
            return await sendSecureMessage(ws, {
              type: SignalType.AUTH_ERROR,
              message: 'Invalid session token request',
              code: INVALID_REQUEST
            });
          }
          if (ws._authenticated) {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              requestId: tokenValidationRequestId,
              valid: false,
              error: 'Authentication state conflict'
            });
          }
          const { resumeRedemption } = normalizedMessage;

          if (
            !hasExactPlainObjectKeys(normalizedMessage, ['requestId', 'type', 'resumeRedemption']) ||
            normalizedMessage.type !== SignalType.TOKEN_VALIDATION ||
            !hasExactPlainObjectKeys(resumeRedemption, ['mac', 'nullifier', 'token', 'tokenSecret'])
          ) {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              requestId: tokenValidationRequestId,
              valid: false,
              error: 'Invalid session token'
            });
          }

          // Unlink autologin
          let result;
          if (resumeRedemption) {
            try {
              const { PrivacyPassServer, PrivacyPassHelpers } = await import('./authentication/privacy-pass-server.js');
              const parsed = PrivacyPassHelpers.parseRedemptionRequest(resumeRedemption);
              let redeemed;
              try {
                redeemed = await PrivacyPassServer.redeemToken(
                  parsed.token,
                  parsed.nullifier,
                  parsed.mac,
                  parsed.tokenSecret,
                  ACCOUNT_AUTH_PURPOSE
                );
              } finally {
                parsed.token.fill(0);
                parsed.nullifier.fill(0);
                parsed.mac.fill(0);
                parsed.tokenSecret.fill(0);
              }
              if (redeemed?.valid) {
                result = { valid: true };
              } else {
                result = { valid: false, error: 'resume_token_invalid' };
              }
            } catch {
              result = { valid: false, error: 'resume_token_invalid' };
            }
          } else {
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              requestId: tokenValidationRequestId,
              valid: false,
              error: 'Invalid session token'
            });
          }

          if (!result.valid) {
            console.warn('[TOKEN-VALIDATION] Session validation failed', { error: result.error });
            return await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              requestId: tokenValidationRequestId,
              valid: false,
              error: result.error || 'Invalid session token'
            });
          }

          if (!isLiveDeliverySocket(ws)) return false;
          const serverEntryRequired = ServerConfig.isServerPasswordGateReady() && !ws._hasServerAuth;
          const serverEntryGranted = !serverEntryRequired;

          tokenValidationPreviousAuth = {
            authenticated: ws._authenticated,
            hasServerAuth: ws._hasServerAuth,
            accountAuthViaAnonymousToken: ws._accountAuthViaAnonymousToken,
            serverEntryAuthorizationGeneration:
              ServerGatekeeper.getServerEntryAuthorizationGeneration()
          };
          ws._authenticated = true;
          ws._accountAuthViaAnonymousToken = true;
          ws._hasServerAuth = serverEntryGranted;

          if (!serverEntryGranted) {
            console.warn('[TOKEN-VALIDATION] Session valid but server entry required');
            const delivered = await sendSecureMessage(ws, {
              type: SignalType.TOKEN_VALIDATION_RESPONSE,
              requestId: tokenValidationRequestId,
              valid: true,
              serverEntryRequired: true,
              serverEntryGranted: false
            });
            if (delivered === false) {
              rollbackTokenValidationAuthorization();
              return false;
            }
            tokenValidationPreviousAuth = null;
            return delivered;
          }

          console.log('[TOKEN-VALIDATION] Anonymous session validation successful');

          const response = {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            requestId: tokenValidationRequestId,
            valid: true,
            serverEntryRequired: false,
            serverEntryGranted: true
          };

          const delivered = await sendSecureMessage(ws, response);
          if (delivered === false) {
            rollbackTokenValidationAuthorization();
            return false;
          }
          tokenValidationPreviousAuth = null;
        } catch (error) {
          rollbackTokenValidationAuthorization();
          console.error('[TOKEN-VALIDATION] Validation failed', { error: error.message });
          await sendSecureMessage(ws, {
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            requestId: tokenValidationRequestId,
            valid: false,
            error: 'Session validation error'
          });
        }
        break;

      case SignalType.REQUEST_SERVER_PUBLIC_KEY:
        if (!hasExactPlainObjectKeys(normalizedMessage, ['type'])) {
          ws.close(1008, 'Invalid server key request');
          break;
        }
        try {
          const payload = await gateway.getServerPublicKeyPayload();
          await sendSecureMessage(ws, payload);
          console.log('[SERVER] Sent server public keys on request');
        } catch (error) {
          console.error('[SERVER] Failed to send server public keys on request', { error: error.message });
          await sendSecureMessage(ws, { type: SignalType.ERROR, message: SERVER_KEYS_UNAVAILABLE_MESSAGE });
        }
        break;

      case SignalType.OPRF_DISCOVERY_PUBLIC_KEY:
        if (
          !hasAnonymousDeliveryAuthorization(ws) ||
          Object.keys(normalizedMessage).sort().join(',') !== 'type'
        ) {
          return await sendSecureMessage(ws, {
            type: SignalType.ERROR,
            code: 'UNLINKED_SESSION_REQUIRED',
            message: 'Anonymous session required for discovery'
          });
        }
        try {
          const oprfPublicKey = oprfDiscoveryServer.getPublicKey();
          const epochInfo = getDiscoveryEpochInfo();
          await sendSecureMessage(ws, {
            type: SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
            publicKey: oprfPublicKey,
            epoch: epochInfo.current,
            epochRotatesAt: epochInfo.rotatesAt,
            powDifficulty: OPRF_DISCOVERY_POW_DIFFICULTY
          });
        } catch (error) {
          console.error('[OPRF-DISCOVERY] Failed to get public key:', error.message);
          await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'OPRF service unavailable' });
        }
        break;

      case SignalType.PUBLISH_DISCOVERY:
        {
          const requestId = typeof normalizedMessage.requestId === 'string' &&
            PUBLICATION_ID_RE.test(normalizedMessage.requestId)
            ? normalizedMessage.requestId
            : undefined;
          const sendPublishAck = async ({ success, error }) => {
            const ackPayload = {
              type: SignalType.OK,
              requestId,
              success: success === true,
              op: SignalType.PUBLISH_DISCOVERY
            };
            if (success !== true) {
              ackPayload.error = typeof error === 'string' && /^[a-z0-9_]{1,64}$/.test(error)
                ? error
                : 'discovery_publish_failed';
            }
            try {
              await sendSecureMessage(ws, ackPayload);
              return true;
            } catch (ackError) {
              console.warn('[DISCOVERY] Publish acknowledgement send failed');
              throw ackError;
            }
          };

          if (!hasAnonymousDeliveryAuthorization(ws)) {
            return await sendPublishAck({
              success: false,
              error: 'unlinked_session_required'
            });
          }

          const rawPublication = normalizedMessage.publication;
          const publicationShapeValid = hasExactPlainObjectKeys(
            rawPublication,
            ['epochId', 'publishId', 'bucketIds']
          );
          const publication = publicationShapeValid
            ? {
                epochId: typeof rawPublication.epochId === 'string' ? rawPublication.epochId.trim() : '',
                publishId: typeof rawPublication.publishId === 'string'
                  ? rawPublication.publishId.trim().toLowerCase()
                  : '',
                bucketIds: Array.isArray(rawPublication.bucketIds)
                  ? rawPublication.bucketIds.slice()
                  : null
              }
            : null;
          const discoveryEpochInfo = getDiscoveryEpochInfo();
          const currentDiscoveryEpochId = String(discoveryEpochInfo.startedAt);
          const publicationValid = Boolean(
            publication &&
            DISCOVERY_EPOCH_ID_RE.test(publication.epochId) &&
            HEX_64_RE.test(publication.publishId) &&
            isCanonicalDiscoveryBucketIds(publication.bucketIds) &&
            isCanonicalDiscoveryBlob(normalizedMessage.encryptedBlob) &&
            isCanonicalBase64Bytes(normalizedMessage.powNonce, POW_SEED_BYTES) &&
            typeof normalizedMessage.powSolution === 'string'
          );

          if (
            Object.keys(normalizedMessage).sort().join(',') !== 'encryptedBlob,powNonce,powSolution,publication,requestId,type' ||
            !requestId ||
            !publicationValid
          ) {
            console.warn('[DISCOVERY] Rejected invalid publication payload');
            return await sendPublishAck({
              success: false,
              error: 'invalid_discovery_payload'
            });
          }

          if (publication.epochId !== currentDiscoveryEpochId) {
            return await sendPublishAck({
              success: false,
              error: DISCOVERY_EPOCH_EXPIRED
            });
          }

          const publishPowSeed = deriveAnonymousRequestPowSeed(
            DISCOVERY_PUBLISH_POW_DOMAIN,
            publication.epochId,
            normalizedMessage.powNonce,
            [
              publication.publishId,
              ...publication.bucketIds.map(String),
              normalizedMessage.encryptedBlob
            ]
          );
          if (!verifyPowSolution(
            publishPowSeed,
            DISCOVERY_PUBLISH_POW_DIFFICULTY,
            normalizedMessage.powSolution
          )) {
            return await sendPublishAck({
              success: false,
              error: 'invalid_discovery_work'
            });
          }

          const publishTokenKey = discoveryPublicationDedupKey(
            publication,
            normalizedMessage.encryptedBlob
          );
          if (publishTokenKey) {
            const now = Date.now();
            const lastPublish = recentPublishTokens.get(publishTokenKey);
            if (lastPublish && (now - lastPublish) < PUBLISH_DEDUP_WINDOW_MS) {
              await sendPublishAck({ success: true });
              return;
            }
          }

          const publishPowClaim = await claimAnonymousRequestPow(
            DISCOVERY_PUBLISH_POW_DOMAIN,
            publishPowSeed,
            normalizedMessage.powSolution,
            discoveryEpochInfo.rotatesAt
          );
          if (publishPowClaim === 'unavailable') {
            return await sendPublishAck({
              success: false,
              error: DISCOVERY_PUBLICATION_UNAVAILABLE
            });
          }
          if (publishPowClaim !== 'claimed') {
            return await sendPublishAck({
              success: false,
              error: 'discovery_work_replayed'
            });
          }
          if (!hasAnonymousDeliveryAuthorization(ws)) return false;

          // Rolling discoverability lease
          let publishSuccess = false;
          let enqueueResult = null;
          let enqueueWork = pendingPublishTokens.get(publishTokenKey);
          let ownsEnqueueWork = false;
          try {
            if (!enqueueWork) {
              if (pendingPublishTokens.size >= RECENT_PUBLISH_TOKEN_MAX) {
                return await sendPublishAck({
                  success: false,
                  error: 'discovery_publication_busy'
                });
              }
              enqueueWork = enqueueDiscoveryPublication({
                publication,
                encryptedBlob: normalizedMessage.encryptedBlob,
                leaseMs: DISCOVERY_LEASE_TTL_MS,
                authorizationCheck: () => hasAnonymousDeliveryAuthorization(ws)
              });
              pendingPublishTokens.set(publishTokenKey, enqueueWork);
              ownsEnqueueWork = true;
            }
            enqueueResult = await enqueueWork;
            publishSuccess = enqueueResult.queued === true;
            if (publishSuccess && ownsEnqueueWork) {
              rememberRecentPublishToken(publishTokenKey, Date.now());
            }
          } catch {
            console.error('[DISCOVERY] Publication enqueue failed');
            await sendPublishAck({ success: false, error: DISCOVERY_PUBLICATION_UNAVAILABLE });
            break;
          } finally {
            if (
              ownsEnqueueWork &&
              pendingPublishTokens.get(publishTokenKey) === enqueueWork
            ) {
              pendingPublishTokens.delete(publishTokenKey);
            }
          }

          if (!hasAnonymousDeliveryAuthorization(ws)) return false;

          await sendPublishAck({
            success: publishSuccess,
            error: publishSuccess ? undefined : enqueueResult?.error
          });
        }
        break;

      case SignalType.PQ_HANDSHAKE_INIT:
        await handlePQHandshake({ ws, parsed: normalizedMessage, serverHybridKeyPair });
        break;

      case SignalType.PQ_HEARTBEAT_PING:
        if (
          ws._pqSessionId &&
          hasExactPlainObjectKeys(normalizedMessage, ['sessionId', 'timestamp', 'type']) &&
          normalizedMessage.sessionId === ws._pqSessionId &&
          Number.isSafeInteger(normalizedMessage.timestamp) &&
          Math.abs(normalizedMessage.timestamp - Date.now()) <= 5 * 60_000
        ) {
          await sendSecureMessage(ws, {
            type: SignalType.PQ_HEARTBEAT_PONG,
            sessionId: ws._pqSessionId,
            timestamp: Date.now()
          });
        } else {
          ws.close(1008, 'Invalid heartbeat request');
        }
        break;

      case SignalType.BLIND_ROUTE:
        await handleBlindRoute({ ws, parsed: normalizedMessage });
        break;

      case SignalType.ACTIVATE_DELIVERY:
        await handleActivateDelivery({ ws, parsed: normalizedMessage });
        break;

      default:
        console.warn('[WS] Unknown message type', normalizedMessage.type);
        ws.close(1008, 'Unknown message type');
    }
  } catch (error) {
    try {
      console.error('[SRV-DIAG] websocket-message handler threw', {
        messageType: parsed?.type,
        error: error?.message,
        code: error?.code,
        stack: error?.stack,
      });
    } catch { }
    try {
      await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
      });
    } catch (_sendError) {
    }
  }
}

async function settleWithin(promise, timeoutMs) {
  let timer = null;
  try {
    return await Promise.race([
      Promise.resolve(promise).then(() => true, () => true),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(false), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function closeWebSocketServer() {
  const target = wss;
  wss = null;
  if (!target) return;

  const closePromise = new Promise((resolve) => {
    try {
      target.close(() => resolve());
    } catch {
      resolve();
    }
  });
  for (const socket of target.clients || []) {
    try {
      socket.close(1001, 'Server shutting down');
    } catch {
    }
  }
  if (await settleWithin(closePromise, 1500)) return;

  for (const socket of target.clients || []) {
    try {
      socket.terminate?.();
    } catch {
    }
  }
  await settleWithin(closePromise, 500);
}

async function closeHttpsServer() {
  const target = server;
  server = null;
  if (!target) return;

  const closePromise = new Promise((resolve) => {
    try {
      target.close(() => resolve());
      target.closeIdleConnections?.();
    } catch {
      resolve();
    }
  });
  if (await settleWithin(closePromise, 1500)) return;
  target.closeAllConnections?.();
  await settleWithin(closePromise, 500);
}

async function shutdownServer(signal) {
  console.log('[SERVER] Shutdown initiated', { signal });
  recentPublishTokens.clear();
  pendingPublishTokens.clear();

  await serverPasswordMonitor?.stop?.();
  serverPasswordMonitor = null;

  await gateway?.stop?.();
  gateway = null;

  if (retentionCleanupInterval) {
    clearInterval(retentionCleanupInterval);
    retentionCleanupInterval = null;
  }

  await retentionCleanupInFlight?.catch(() => { });

  await closeWebSocketServer();
  await closeHttpsServer();

  await stopDiscoveryPublicationRelay();
  destroyDiscoveryPublicationAuthentication();
  await TimingProtection.stopCoverTraffic();
  try {
    await BlindRouter.stopBlindDeliverySubscription();
  } catch (error) {
    console.error('[SERVER] Blind delivery shutdown failed', error);
  } finally {
    BlindRouter.destroyGlobalMixAuthentication();
  }
  if (pirPrebuildTimer) {
    clearInterval(pirPrebuildTimer);
    pirPrebuildTimer = null;
  }
  try {
    await stopPirService();
  } catch (error) {
    console.error('[SERVER] PIR shutdown failed', error);
  }

  try {
    await shutdownCluster();
  } catch (error) {
    console.error('[SERVER] Cluster shutdown failed', error);
  }

  try {
    await rateLimitMiddleware.close();
  } catch (error) {
    console.error('[SERVER] Rate limiter shutdown failed', error);
  }

  try {
    await shutdownAuthCryptoWorker();
  } catch (error) {
    console.error('[SERVER] Authentication worker shutdown failed', error);
  }

  try {
    await stopPrivateAuthPirService();
  } catch (error) {
    console.error('[SERVER] Private authentication PIR shutdown failed', error);
  }

  try {
    const [{ PrivacyPassServer }, { OPAQUEServer }, { ServerGatekeeper }] = await Promise.all([
      import('./authentication/privacy-pass-server.js'),
      import('./crypto/opaque-service.js'),
      import('./authentication/gatekeeper.js')
    ]);
    await PrivacyPassServer.destroy();
    OPAQUEServer.destroy();
    await ServerGatekeeper.destroy();
    destroyAdminAuth();
  } catch (error) {
    console.error('[SERVER] Authentication secret shutdown failed', error);
  }

  destroyEnvelopeHandler();
  destroyKeyTransparencyService();
  destroyServerTransportKeys();
  oprfDiscoveryServer.destroy?.();
  await destroyDiscoveryBucketIndex();
  await destroyApiRoutes();
  destroyDiscoveryBucketSecrets();
  destroyDatabaseSecrets();
  destroyAuthRootKey();

  try {
    await cleanupRedis();
  } catch (error) {
    console.error('[SERVER] Redis shutdown failed', error);
  }
  try {
    await closePgPool();
  } catch (error) {
    console.error('[SERVER] Database shutdown failed', error);
  }

  await stopServerTelemetry();

  console.log('[SERVER] Shutdown completed', { signal });
}

// Main server startup
async function startServer() {
  let unregisterShutdownHandlers = null;
  try {
    if (!CLUSTER_SERVER_ID_RE.test(process.env.SERVER_ID || '')) {
      throw new Error('SERVER_ID is required and must be a valid cluster server ID');
    }
    ServerConfig.validateConfig();
    setDeliveryTelemetryProvider(BlindRouter.getTelemetrySnapshot);
    setRuntimeTelemetryProvider(getServerRuntimeTelemetry);
    startServerTelemetry();
    unregisterShutdownHandlers = registerShutdownHandlers({
      handler: shutdownServer,
    });

    await initializeServerPasswordGate();
    await initDatabase();
    await runRetentionCleanup();
    startRetentionCleanup();

    console.log('[SERVER] Core services initialized', { port: ServerConfig.PORT });

    const result = await createBootstrapServer({
      createApp: createExpressApp,
      createWebSocketServer,
      onServerReady,
      prepareServerContext,
      tls: {
        certPath: process.env.TLS_CERT_PATH,
        keyPath: process.env.TLS_KEY_PATH,
      },
    });

    return result;
  } catch (error) {
    console.error('[SERVER] Startup failed', error);
    unregisterShutdownHandlers?.();
    try {
      await shutdownServer('startup-failed');
    } catch (shutdownError) {
      console.error('[SERVER] Startup failure cleanup failed', shutdownError);
    }
    throw error;
  }
}

startServer().catch((error) => {
  console.error('[SERVER] Fatal startup failure', error);
  process.exit(1);
});
