import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FORBIDDEN_ACTIVE_SEND_SELECTOR_FIELDS,
  findForbiddenActiveSendSelectors,
  validateBlindRouteSelectorPolicy
} from '../routing/destination-selector-policy.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('blind-route selector policy accepts only opaque active-send shape', () => {
  const result = validateBlindRouteSelectorPolicy({
    type: 'blind-route',
    sealedEnvelope: {
      version: 'ss-v1',
      ciphertext: 'opaque',
      ephemeralKey: 'opaque',
      nonce: 'opaque'
    }
  });

  assert.equal(result.valid, true);
  assert.deepEqual(result.fields, []);
});

test('blind-route selector policy rejects all known destination selector fields', () => {
  for (const field of FORBIDDEN_ACTIVE_SEND_SELECTOR_FIELDS) {
    const found = findForbiddenActiveSendSelectors({
      type: 'blind-route',
      sealedEnvelope: {},
      [field]: 'selector'
    });

    assert.deepEqual(found, [field], `${field} must be rejected on active sends`);
  }
});

test('active send routing no longer contains rendezvous bucket derivation', () => {
  const routingSource = fs.readFileSync(
    path.join(repoRoot, 'src/lib/transport/rendezvous-routing.ts'),
    'utf8'
  );

  assert.equal(routingSource.includes('deriveRendezvousBucketId'), false);
  assert.equal(routingSource.includes('qor-rendezvous-bucket'), false);
  assert.equal(routingSource.includes('RENDEZVOUS_BUCKET'), false);
});

test('discovery snapshot wire names do not claim computational PIR', () => {
  const clientSignals = fs.readFileSync(
    path.join(repoRoot, 'src/lib/types/signal-types.ts'),
    'utf8'
  );
  const serverSignals = fs.readFileSync(
    path.join(repoRoot, 'server/signals.js'),
    'utf8'
  );

  assert.equal(clientSignals.includes('pir-discovery-snapshot'), false);
  assert.equal(serverSignals.includes('pir-discovery-snapshot'), false);
  assert.equal(clientSignals.includes('DISCOVERY_SNAPSHOT_REQUEST'), true);
  assert.equal(serverSignals.includes('DISCOVERY_SNAPSHOT_REQUEST'), true);
});

test('server-visible route claim path does not create mailbox-backed delivery state', () => {
  const inboxHandler = fs.readFileSync(
    path.join(repoRoot, 'server/handlers/inbox-handlers.js'),
    'utf8'
  );
  const blindClient = fs.readFileSync(
    path.join(repoRoot, 'src/lib/transport/blind-routing-client.ts'),
    'utf8'
  );

  assert.equal(inboxHandler.includes('ensureOfflineMailboxByLookupId'), false);
  assert.equal(inboxHandler.includes('rotateOfflineMailboxesByLookupIds'), false);
  assert.equal(blindClient.includes('oldMailboxLookupIds'), false);
  assert.equal(blindClient.includes('newMailboxLookupIds'), false);
});

test('discovery PIR page layout uses compact 8-byte handle records (two-tier)', async () => {
  const {
    buildPirPageDatabase, decodeHandleRecord, deriveSlotFingerprint, deriveBlobHandle, derivePirRecordSlot
  } = await import('../pir/page-layout.js');

  const slotKey = 'a'.repeat(43);
  const encryptedBlob = 'blob:' + 'x'.repeat(20000); // big bundle: still a tiny PIR record
  const database = buildPirPageDatabase({ kind: 'discovery', sourceRecords: [{ slotKey, encryptedBlob }] });

  assert.equal(database.manifest.recordSize, 8);
  assert.equal(database.manifest.recordEncoding, 'qor-discovery-handle-record-v1');
  assert.equal(database.records.every((record) => record.length === 8), true);
  assert.equal(typeof database.manifest.databaseDigest, 'string');
  assert.equal(database.manifest.slotDerivation, 'qor-pir-slot-v1');
  assert.equal(Array.isArray(database.blobsBySlot), true);

  const slot = derivePirRecordSlot({
    kind: 'discovery', slotKey, epochStart: database.manifest.slotEpoch, recordCount: database.manifest.recordCount, probe: 0
  });
  const rec = decodeHandleRecord(database.records[slot]);
  const expFp = Buffer.from(deriveSlotFingerprint({ kind: 'discovery', slotKey, epochStart: database.manifest.slotEpoch })).toString('base64url');
  assert.equal(rec.fingerprint, expFp);
  assert.equal(database.blobsBySlot[slot], encryptedBlob);
});

test('discovery is the only computational-PIR kind (opaque/global-spool retired)', async () => {
  const { isPirDatabaseKind, PIR_DATABASE_KINDS } = await import('../pir/page-layout.js');
  assert.equal(isPirDatabaseKind('discovery'), true);
  assert.equal(isPirDatabaseKind('opaque'), false);
  assert.deepEqual([...PIR_DATABASE_KINDS], ['discovery']);
});

test('discovery PIR manifest carries hint-free public params inline (no setup chunks)', async () => {
  process.env.REDIS_URL ||= 'redis://127.0.0.1:6379';
  const { publicManifest } = await import('../pir/pir-databases.js');
  const manifest = publicManifest({
    uploadedToWorker: true,
    workerPublicParams: { publicParams: 'AAAA-public-params', dbRows: 8, dbCols: 8 },
    manifest: {
      kind: 'discovery',
      epochId: 'epoch-test',
      recordCount: 1024,
      recordSize: 24,
      expiresAt: Date.now() + 60_000
    }
  });

  assert.equal(manifest.workerReady, true);
  assert.equal(manifest.queryPrivacy, 'computational-pir-worker');
  assert.equal(manifest.workerScheme, 'hintless-simplepir');
  assert.equal(manifest.workerPublicParams, 'AAAA-public-params');
  assert.equal(manifest.workerDbRows, 8);
  assert.equal(manifest.workerSetup, undefined);
  assert.equal(manifest.workerSetupChunked, undefined);
  assert.equal(manifest.workerSetupDigest, undefined);
});

test('global spool is served as a uniform per-epoch encrypted snapshot', async () => {
  const { buildSpoolSnapshotResponse, decodeSpoolSnapshotResponse } = await import('../routing/spool-snapshot-service.js');
  const env = (c) => ({
    envelope: {
      version: 'ss-v1',
      ciphertext: Buffer.alloc(800, c).toString('base64'),
      ephemeralKey: Buffer.alloc(32, c).toString('base64'),
      nonce: Buffer.alloc(12, c).toString('base64')
    }
  });
  const response = buildSpoolSnapshotResponse([env(1), env(2)], { now: 1_000_000 });
  const decoded = decodeSpoolSnapshotResponse(response.snapshot);
  assert.equal(decoded.realCountHidden, true);
  assert.equal(decoded.paddedEntryCount >= 256, true);
  assert.equal(Array.isArray(decoded.entries), true);
  assert.equal(decoded.entries.length, decoded.paddedEntryCount);
});

test('discovery records use deterministic client-known token slots', async () => {
  const { buildPirPageDatabase, decodeHandleRecord, deriveSlotFingerprint, derivePirRecordSlot } = await import('../pir/page-layout.js');
  const { deriveDiscoveryPirSlotKey } = await import('../database/discovery-db.js');

  const token = 'a'.repeat(64);
  const slotKey = deriveDiscoveryPirSlotKey(token);
  const encryptedBlob = 'token-record-blob';
  const database = buildPirPageDatabase({ kind: 'discovery', sourceRecords: [{ slotKey, encryptedBlob }] });

  const slot = derivePirRecordSlot({
    kind: 'discovery', slotKey, epochStart: database.manifest.slotEpoch, recordCount: database.manifest.recordCount, probe: 0
  });
  const rec = decodeHandleRecord(database.records[slot]);
  const expFp = Buffer.from(deriveSlotFingerprint({ kind: 'discovery', slotKey, epochStart: database.manifest.slotEpoch })).toString('base64url');
  assert.equal(rec.fingerprint, expFp);
  assert.equal(database.blobsBySlot[slot], encryptedBlob);
});

test('docker server profile starts pinned PIR worker by default', () => {
  const compose = fs.readFileSync(
    path.join(repoRoot, 'docker/docker-compose.yml'),
    'utf8'
  );
  const dockerHelper = fs.readFileSync(
    path.join(repoRoot, 'scripts/start-docker.cjs'),
    'utf8'
  );
  const lock = JSON.parse(fs.readFileSync(
    path.join(repoRoot, 'workers/hintless/hintless.lock.json'),
    'utf8'
  ));

  assert.equal(compose.includes('pir-worker:'), true);
  assert.equal(compose.includes('dockerfile: Dockerfile'), true);
  assert.equal(compose.includes('context: ../workers/hintless'), true);
  assert.equal(compose.includes('PIR_WORKER_URL=${PIR_WORKER_URL:-http://pir-worker:8787}'), true);
  assert.equal(compose.includes('PIR_REQUIRE_WORKER=${PIR_REQUIRE_WORKER:-true}'), true);
  assert.equal(compose.includes('SETUP_CHUNK'), false);
  assert.equal(lock.upstream.commit, '49434e086ec56d19546ca6e97353671b690ba19b');
  assert.equal(fs.existsSync(path.join(repoRoot, 'workers/hintless/upstream/MODULE.bazel')), true);
  assert.equal(dockerHelper.includes('postgres redis pir-worker'), true);
});

test('offline retrieval uses a uniform spool snapshot, not a per-record selector', () => {
  const serverSignals = fs.readFileSync(
    path.join(repoRoot, 'server/signals.js'),
    'utf8'
  );
  const serverMain = fs.readFileSync(
    path.join(repoRoot, 'server/server.js'),
    'utf8'
  );
  const clientGlobalSpoolPir = fs.readFileSync(
    path.join(repoRoot, 'src/lib/websocket/global-spool-pir-handler.ts'),
    'utf8'
  );
  const apiRoutes = fs.readFileSync(
    path.join(repoRoot, 'server/routes/api-routes.js'),
    'utf8'
  );

  assert.equal(fs.existsSync(path.join(repoRoot, 'server/handlers/offline-handlers.js')), false);
  assert.equal(serverSignals.includes('DELIVERY_BATCH_REQUEST'), false);
  assert.equal(serverMain.includes('handleDeliveryBatchRequest'), false);
  assert.equal(apiRoutes.includes("router.get('/spool/snapshot'"), true);
  assert.equal(clientGlobalSpoolPir.includes('fetchSnapshot'), true);
  assert.equal(clientGlobalSpoolPir.includes('decodeSpoolSnapshot'), true);
  assert.equal(clientGlobalSpoolPir.includes('createPirWordQuery'), false);
});

test('discovery PIR layout defaults: tiny handle records, big record floor/count', async () => {
  const { getPirLayoutConfig } = await import('../pir/page-layout.js');

  delete process.env.PIR_DISCOVERY_RECORD_FLOOR;
  delete process.env.PIR_DISCOVERY_MAX_SOURCE_RECORDS;
  delete process.env.PIR_DISCOVERY_SLOT_LOAD_FACTOR;
  delete process.env.PIR_DISCOVERY_EPOCH_MS;

  const config = getPirLayoutConfig('discovery');
  
  assert.equal(config.recordSize, 8);
  assert.equal(config.paddingFloor, 1024);
  assert.equal(config.maxSourceRecords, 65536);
  assert.equal(config.slotLoadFactor, 1);
  assert.equal(config.epochMs, 6 * 60 * 60_000);
});

test('global spool PIR snapshot uses latest rolling window and coarse mixnet logs', () => {
  const router = fs.readFileSync(
    path.join(repoRoot, 'server/routing/blind-router.js'),
    'utf8'
  );

  assert.equal(router.includes('zrevrangebyscore(GLOBAL_MIX_SPOOL_KEY'), true);
  assert.equal(router.includes('realCount:'), false);
  assert.equal(router.includes('coverCount:'), false);
  assert.equal(router.includes('realCountClass'), true);
  assert.equal(router.includes('releaseAfterMs'), false);
  assert.equal(router.includes('takeGlobalMixMessages'), false);
  assert.equal(router.includes('_globalMixCursor'), false);
});

test('server-generated mixnet cover is enabled and live-only by default', () => {
  const router = fs.readFileSync(
    path.join(repoRoot, 'server/routing/blind-router.js'),
    'utf8'
  );
  const timing = fs.readFileSync(
    path.join(repoRoot, 'server/routing/timing-protection.js'),
    'utf8'
  );

  assert.equal(timing.includes("envInt('SERVER_COVER_TRAFFIC_WRITES_MIN', 1, 1"), true);
  assert.equal(timing.includes("envInt('SERVER_COVER_TRAFFIC_WRITES_MAX', 3"), true);
  assert.equal(router.includes('SERVER_GENERATED_COVER_RETAINED_IN_SPOOL'), false);
  assert.equal(router.includes('if (!cover) {\n    await queueGlobalMixMessage(sealedEnvelope);'), true);
  assert.equal(router.includes('cover: !!entry.cover'), true);
});

test('client synthetic blind-route cover is enabled by default', () => {
  const constants = fs.readFileSync(
    path.join(repoRoot, 'src/lib/constants.ts'),
    'utf8'
  );
  const websocket = fs.readFileSync(
    path.join(repoRoot, 'src/lib/websocket/websocket.ts'),
    'utf8'
  );

  assert.equal(constants.includes('WS_COVER_TRAFFIC_MAX_INTERVAL_MS = 45_000'), true);
  assert.equal(constants.includes('WS_COVER_TRAFFIC_MIN_INTERVAL_MS = 10_000'), true);
  assert.equal(websocket.includes('createCoverSealedEnvelope()'), true);
  assert.equal(websocket.includes('if (WS_COVER_TRAFFIC_MAX_INTERVAL_MS <= 0) return'), false);
});

test('global mix spool has message and byte retention budgets', () => {
  const router = fs.readFileSync(
    path.join(repoRoot, 'server/routing/blind-router.js'),
    'utf8'
  );

  assert.equal(router.includes("envInt('GLOBAL_MIX_SPOOL_MAX_MESSAGES', 1024"), true);
  assert.equal(router.includes("envInt('GLOBAL_MIX_SPOOL_MAX_BYTES', 16 * 1024 * 1024"), true);
  assert.equal(router.includes('trimGlobalMixSpool(client)'), true);
  assert.equal(router.includes('removeSpoolMembers'), true);
});

test('PIR worker upload retries transient socket failures', () => {
  const workerClient = fs.readFileSync(
    path.join(repoRoot, 'server/pir/pir-worker-client.js'),
    'utf8'
  );
  const databases = fs.readFileSync(
    path.join(repoRoot, 'server/pir/pir-databases.js'),
    'utf8'
  );

  assert.equal(workerClient.includes('PIR_WORKER_REQUEST_RETRIES'), true);
  assert.equal(workerClient.includes("'UND_ERR_SOCKET'"), true);
  assert.equal(workerClient.includes('Worker request transient failure; retrying'), true);
  assert.equal(workerClient.includes('retryable: result.retryable === true'), true);
  assert.equal(databases.includes('PIR_WORKER_UPLOAD_TRANSIENT_RETRY_MS'), true);
  assert.equal(databases.includes('database.workerUpload.retryable === true'), true);
});

test('P2P sealed envelopes require transport auth without becoming message identity', () => {
  const service = fs.readFileSync(
    path.join(repoRoot, 'src/lib/transport/secure-p2p-service.ts'),
    'utf8'
  );
  const p2pForwarder = fs.readFileSync(
    path.join(repoRoot, 'src/hooks/p2p/messaging.ts'),
    'utf8'
  );

  assert.equal(service.includes('Rejecting unsigned or unauthenticated P2P sealed envelope'), true);
  assert.equal(service.includes('verifyRouteProof('), true);
  assert.equal(service.includes('incomingRouteProofSequence'), true);
  assert.equal(p2pForwarder.includes('(payload as any).from = message.from'), false);
  assert.equal(p2pForwarder.includes('(payload as any).to = message.to'), false);
});

test('PQ WebSocket envelopes bind to fresh self-tested client signing keys', () => {
  const handshake = fs.readFileSync(
    path.join(repoRoot, 'src/lib/websocket/handshake.ts'),
    'utf8'
  );
  const encryption = fs.readFileSync(
    path.join(repoRoot, 'src/lib/websocket/encryption.ts'),
    'utf8'
  );
  const websocketClient = fs.readFileSync(
    path.join(repoRoot, 'src/lib/websocket/websocket.ts'),
    'utf8'
  );
  const tauriBindings = fs.readFileSync(
    path.join(repoRoot, 'src/lib/tauri-bindings.ts'),
    'utf8'
  );
  const tauriMain = fs.readFileSync(
    path.join(repoRoot, 'src-tauri/src/main.rs'),
    'utf8'
  );

  assert.equal(handshake.includes('isUsableSigningKeyPair'), true);
  assert.equal(handshake.includes('WS_SIGNING_KEY_SELF_TEST_MESSAGE'), true);
  assert.equal(handshake.includes('clientSigningPublicKey: signingKeyPair?.publicKey'), true);
  assert.equal(handshake.includes('session.storePQKeys'), false);
  assert.equal(encryption.includes('PQ session signing key binding mismatch'), true);
  assert.equal(websocketClient.includes('session.getPQKeys'), false);
  assert.equal(websocketClient.includes('exportSessionKeys'), false);
  assert.equal(websocketClient.includes('importSessionKeys'), false);
  assert.equal(tauriBindings.includes('storePQKeys'), false);
  assert.equal(tauriBindings.includes('getPQKeys'), false);
  assert.equal(tauriMain.includes('session_store_pq_keys'), false);
  assert.equal(tauriMain.includes('session_get_pq_keys'), false);
});

test('client and desktop packaging expose a single runtime surface', () => {
  const rootPackage = JSON.parse(fs.readFileSync(
    path.join(repoRoot, 'package.json'),
    'utf8'
  ));
  const viteConfig = fs.readFileSync(
    path.join(repoRoot, 'vite.config.simple.ts'),
    'utf8'
  );
  const tauriConfig = fs.readFileSync(
    path.join(repoRoot, 'src-tauri/tauri.conf.json'),
    'utf8'
  );
  const cargoToml = fs.readFileSync(
    path.join(repoRoot, 'src-tauri/Cargo.toml'),
    'utf8'
  );
  const cargoLock = fs.readFileSync(
    path.join(repoRoot, 'src-tauri/Cargo.lock'),
    'utf8'
  );
  const startClient = fs.readFileSync(
    path.join(repoRoot, 'scripts/start-client.cjs'),
    'utf8'
  );
  const envFile = fs.readFileSync(
    path.join(repoRoot, '.env'),
    'utf8'
  );
  const cryptoLogger = fs.readFileSync(
    path.join(repoRoot, 'server/crypto/crypto-logger.js'),
    'utf8'
  );

  assert.equal(Object.prototype.hasOwnProperty.call(rootPackage.scripts, 'vite'), false);
  assert.equal(rootPackage.scripts.build.includes('--mode'), false);
  assert.equal(viteConfig.includes('sourcemap: false'), true);
  assert.equal(viteConfig.includes('drop_console: true'), true);
  assert.equal(viteConfig.includes('drop_debugger: true'), true);
  assert.equal(viteConfig.includes('server:'), false);
  assert.equal(JSON.parse(tauriConfig).app.windows[0].devtools, true);
  assert.equal(cargoToml.includes('tauri-plugin-devtools'), false);
  assert.equal(cargoToml.includes('"devtools"'), true);
  assert.equal(cargoLock.includes('tauri-plugin-devtools'), false);
  assert.equal(startClient.includes("target', 'debug'"), false);
  assert.equal(envFile.includes('CRYPTO_DEBUG'), false);
  assert.equal(envFile.includes('CRYPTO_LOG_LEVEL=warn'), true);
  assert.equal(cryptoLogger.includes("process.env.CRYPTO_LOG_LEVEL || 'warn'"), true);
});
