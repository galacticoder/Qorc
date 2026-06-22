import express from 'express';
import { logError } from '../security/logging.js';
import { cryptoLogger } from '../database/core.js';
import { DiscoveryDB } from '../database/database.js';
import { buildDiscoverySnapshotResponse, getDiscoverySnapshotConfig } from '../discovery/snapshot-service.js';
import { buildSpoolSnapshotResponse, getSpoolSnapshotConfig } from '../routing/spool-snapshot-service.js';
import { snapshotGlobalMixSpool } from '../routing/blind-router.js';
import { getPirDatabase, forcePirWorkerReupload, publicManifest } from '../pir/pir-databases.js';
import { queryPirWorker } from '../pir/pir-worker-client.js';
import { DISCOVERY_PIR_DATABASE_KIND, DISCOVERY_BUCKET_TARGET_SIZE, padDiscoveryBucket } from '../pir/page-layout.js';
import { oprfDiscoveryServer } from '../crypto/oprf-discovery.js';
import crypto from 'crypto';
import {
  AvatarBlobDB,
  syntheticMissBlob,
  isValidAvatarBlobId,
  isValidAvatarBlobData,
  AVATAR_BLOB_B64_CHARS
} from '../database/avatar-blob-db.js';

const PIR_HTTP_MAX_QUERY_CHARS = 8 * 1024 * 1024;
const PIR_HTTP_RESPONSE_CHAR_BUDGET = 8 * 1024 * 1024;
const PIR_HTTP_MAX_INFLIGHT = Math.max(1, Number.parseInt(process.env.DISCOVERY_PIR_HTTP_MAX_INFLIGHT || '24', 10) || 24);
let pirHttpInflight = 0;
const OPRF_HTTP_MAX_INFLIGHT = Math.max(1, Number.parseInt(process.env.DISCOVERY_OPRF_HTTP_MAX_INFLIGHT || '64', 10) || 64);
let oprfHttpInflight = 0;

const router = express.Router();

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function serializedPayloadBytes(payload) {
  try {
    return Buffer.byteLength(JSON.stringify(payload), 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

const SPOOL_SNAPSHOT_RESPONSE_MAX_BYTES = envInt(
  'SPOOL_SNAPSHOT_RESPONSE_MAX_BYTES',
  8 * 1024 * 1024,
  512 * 1024,
  128 * 1024 * 1024
);

function buildBoundedSpoolSnapshotPayload(rows, config, epochStart) {
  let maxRows = Math.max(1, Math.trunc(config.maxRows || 1));
  let paddingFloor = Math.max(1, Math.trunc(config.paddingFloor || 1));
  let maxPlaintextBytes = Math.min(config.maxPlaintextBytes, SPOOL_SNAPSHOT_RESPONSE_MAX_BYTES);
  let lastPayloadBytes = 0;

  for (let attempt = 0; attempt < 16; attempt += 1) {
    const response = buildSpoolSnapshotResponse(rows, {
      ...config,
      now: epochStart,
      maxRows,
      paddingFloor,
      maxPlaintextBytes
    });
    const payload = { ok: true, distribution: 'uniform-anonymous-cdn-tor-suitable', ...response };
    const payloadBytes = serializedPayloadBytes(payload);
    lastPayloadBytes = payloadBytes;
    if (payloadBytes <= SPOOL_SNAPSHOT_RESPONSE_MAX_BYTES) {
      return { payload, payloadBytes, maxRows, paddingFloor, maxPlaintextBytes };
    }

    if (maxRows > 1) {
      maxRows = Math.max(1, Math.floor(maxRows / 2));
      continue;
    }
    if (paddingFloor > 1) {
      paddingFloor = Math.max(1, Math.floor(paddingFloor / 2));
      continue;
    }
    if (maxPlaintextBytes > 1024 * 1024) {
      maxPlaintextBytes = Math.max(1024 * 1024, Math.floor(maxPlaintextBytes / 2));
      continue;
    }
    break;
  }

  return {
    payload: { ok: false, error: 'spool_snapshot_too_large' },
    payloadBytes: lastPayloadBytes,
    tooLarge: true
  };
}

router.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: Date.now() });
});

router.get('/tunnel-url', async (req, res) => {
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

router.get('/discovery/snapshot', async (_req, res) => {
  try {
    const config = getDiscoverySnapshotConfig();
    const rows = await DiscoveryDB.snapshotActive(config.maxRows);
    const response = buildDiscoverySnapshotResponse(rows);
    res.setHeader('Cache-Control', `public, max-age=${Math.max(30, Math.floor(config.epochMs / 2000))}, immutable`);
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      distribution: 'target-free-anonymous-cdn-tor-suitable',
      ...response
    });
  } catch (error) {
    logError(error, { endpoint: '/api/discovery/snapshot' });
    res.status(500).json({ ok: false, error: 'snapshot_unavailable' });
  }
});

let spoolSnapshotCache = null;

export function getSpoolSnapshotCacheStats() {
  if (!spoolSnapshotCache) {
    return { cached: false, payloadBytes: 0 };
  }
  return {
    cached: true,
    epochStart: spoolSnapshotCache.epochStart,
    payloadBytes: serializedPayloadBytes(spoolSnapshotCache.payload)
  };
}

export function clearSpoolSnapshotCache() {
  const stats = getSpoolSnapshotCacheStats();
  spoolSnapshotCache = null;
  return {
    cleared: stats.cached,
    payloadBytesCleared: stats.payloadBytes
  };
}

router.get('/spool/snapshot', async (_req, res) => {
  try {
    const config = getSpoolSnapshotConfig();
    const epochStart = Math.floor(Date.now() / config.epochMs) * config.epochMs;
    if (!spoolSnapshotCache || spoolSnapshotCache.epochStart !== epochStart) {
      const rows = await snapshotGlobalMixSpool(config.maxRows);
      const boundedSnapshot = buildBoundedSpoolSnapshotPayload(rows, config, epochStart);
      if (boundedSnapshot.tooLarge) {
        cryptoLogger.warn('[SPOOL] Snapshot exceeded response budget', {
          payloadBytes: boundedSnapshot.payloadBytes,
          maxBytes: SPOOL_SNAPSHOT_RESPONSE_MAX_BYTES
        });
      }
      spoolSnapshotCache = {
        epochStart,
        payload: boundedSnapshot.payload
      };
    }
    res.setHeader('Cache-Control', `public, max-age=${Math.max(5, Math.floor(config.epochMs / 2000))}, immutable`);
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(spoolSnapshotCache.payload);
  } catch (error) {
    logError(error, { endpoint: '/api/spool/snapshot' });
    res.status(500).json({ ok: false, error: 'spool_snapshot_unavailable' });
  }
});

// tier 2 the discovery PIR record returned only a tiny handle and client fetches the full encrypted bundle directly by handle
router.post('/pir/query', async (req, res) => {
  cryptoLogger.info('[PIR-HTTP] /api/pir/query hit', {
    epochIdLen: typeof req.body?.epochId === 'string' ? req.body.epochId.length : 0,
    queryLen: typeof req.body?.query === 'string' ? req.body.query.length : 0,
    inflight: pirHttpInflight
  });
  if (pirHttpInflight >= PIR_HTTP_MAX_INFLIGHT) {
    res.status(503).json({ ok: false, error: 'pir_busy' });
    return;
  }
  pirHttpInflight += 1;
  try {
    const kind = DISCOVERY_PIR_DATABASE_KIND;
    const epochId = typeof req.body?.epochId === 'string' ? req.body.epochId.slice(0, 128) : '';
    const query = typeof req.body?.query === 'string' ? req.body.query : '';
    if (!query || query.length > PIR_HTTP_MAX_QUERY_CHARS) {
      res.status(400).json({ ok: false, error: 'invalid_pir_query' });
      return;
    }

    const databaseResult = await getPirDatabase(kind, { epochId, ensureWorker: true });
    if (!databaseResult.success) {
      res.status(503).json({ ok: false, error: databaseResult.error });
      return;
    }
    const manifest = databaseResult.database.manifest;
    if (manifest.epochId !== epochId) {
      res.status(409).json({ ok: false, error: 'pir_epoch_mismatch' });
      return;
    }
    if (!databaseResult.database.workerUpload?.uploaded) {
      res.status(503).json({ ok: false, error: databaseResult.database.workerUpload?.error || 'pir_worker_unavailable' });
      return;
    }

    let response = await queryPirWorker({
      kind,
      epochId,
      query,
      maxResponseChars: PIR_HTTP_RESPONSE_CHAR_BUDGET
    });
    
    if (!response.success && response.error === 'pir_epoch_not_loaded') {
      const reup = await forcePirWorkerReupload(databaseResult.database);
      if (reup?.uploaded) {
        response = await queryPirWorker({ kind, epochId, query, maxResponseChars: PIR_HTTP_RESPONSE_CHAR_BUDGET });
      }
    }
    if (!response.success) {
      res.status(503).json({ ok: false, error: response.error || 'pir_query_failed' });
      return;
    }

    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      epochId,
      response: response.response,
      proof: response.proof,
      recordDigest: response.recordDigest,
      manifestDigest: manifest.databaseDigest
    });
  } catch (error) {
    logError(error, { endpoint: '/api/pir/query' });
    res.status(500).json({ ok: false, error: 'pir_query_unavailable' });
  } finally {
    pirHttpInflight = Math.max(0, pirHttpInflight - 1);
  }
});

// Unlinkable avatar content store
const AVATAR_HTTP_MAX_INFLIGHT = Math.max(1, Number.parseInt(process.env.AVATAR_HTTP_MAX_INFLIGHT || '16', 10) || 16);
const AVATAR_GET_MAX_BATCH = Math.max(1, Number.parseInt(process.env.AVATAR_GET_MAX_BATCH || '16', 10) || 16);
const AVATAR_BLOB_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const AVATAR_MISS_SECRET = process.env.AVATAR_MISS_SECRET || crypto.randomBytes(32).toString('hex');
let avatarHttpInflight = 0;

// Anonymous upload of one PURB { blobId, data (base64), expiresAt }
router.post('/avatar/blob/put', async (req, res) => {
  if (avatarHttpInflight >= AVATAR_HTTP_MAX_INFLIGHT) {
    res.status(503).json({ ok: false, error: 'avatar_busy' });
    return;
  }
  avatarHttpInflight += 1;
  try {
    const blobId = typeof req.body?.blobId === 'string' ? req.body.blobId : '';
    const data = typeof req.body?.data === 'string' ? req.body.data : '';
    if (!isValidAvatarBlobId(blobId) || !isValidAvatarBlobData(data)) {
      res.status(400).json({ ok: false, error: 'invalid_avatar_blob' });
      return;
    }
    const now = Date.now();
    let expiresAt = Number(req.body?.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= now) expiresAt = now + AVATAR_BLOB_MAX_TTL_MS;
    expiresAt = Math.min(expiresAt, now + AVATAR_BLOB_MAX_TTL_MS);
    const ok = await AvatarBlobDB.store(blobId, data, expiresAt, now);
    res.status(ok ? 200 : 500).json({ ok });
  } catch (error) {
    logError(error, { endpoint: '/api/avatar/blob/put' });
    res.status(503).json({ ok: false, error: 'avatar_put_failed' });
  } finally {
    avatarHttpInflight = Math.max(0, avatarHttpInflight - 1);
  }
});

// Batch fetch with cover traffic { ids: string[] }
router.post('/avatar/blob/get', async (req, res) => {
  if (avatarHttpInflight >= AVATAR_HTTP_MAX_INFLIGHT) {
    res.status(503).json({ ok: false, error: 'avatar_busy' });
    return;
  }
  avatarHttpInflight += 1;
  try {
    const rawIds = Array.isArray(req.body?.ids) ? req.body.ids : [];
    const ids = Array.from(new Set(rawIds.filter(isValidAvatarBlobId))).slice(0, AVATAR_GET_MAX_BATCH);
    if (ids.length === 0) {
      res.status(400).json({ ok: false, error: 'invalid_avatar_ids' });
      return;
    }
    const now = Date.now();
    const blobs = [];
    for (const id of ids) {
      const data = await AvatarBlobDB.get(id, now);
      blobs.push({ id, data: data || syntheticMissBlob(id, AVATAR_MISS_SECRET) });
    }
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({ ok: true, blobs });
  } catch (error) {
    logError(error, { endpoint: '/api/avatar/blob/get' });
    res.status(503).json({ ok: false, error: 'avatar_get_failed' });
  } finally {
    avatarHttpInflight = Math.max(0, avatarHttpInflight - 1);
  }
});

// A random sample of currently valid blobIds for clients to draw cover traffic decoys from
router.post('/avatar/pool', async (req, res) => {
  if (avatarHttpInflight >= AVATAR_HTTP_MAX_INFLIGHT) {
    res.status(503).json({ ok: false, error: 'avatar_busy' });
    return;
  }
  avatarHttpInflight += 1;
  try {
    const limit = Number.parseInt(req.body?.limit, 10);
    const ids = await AvatarBlobDB.samplePool(Number.isFinite(limit) ? limit : 256);
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({ ok: true, ids });
  } catch (error) {
    logError(error, { endpoint: '/api/avatar/pool' });
    res.status(503).json({ ok: false, error: 'avatar_pool_failed' });
  } finally {
    avatarHttpInflight = Math.max(0, avatarHttpInflight - 1);
  }
});

// k-anonymous discovery keys-blob retrieval
const DISCOVERY_BUCKET_MAX_IDS = Math.max(1, Number.parseInt(process.env.DISCOVERY_BUCKET_MAX_IDS || '4', 10) || 4);
const DISCOVERY_BUCKET_MAX_INFLIGHT = Math.max(1, Number.parseInt(process.env.DISCOVERY_BUCKET_MAX_INFLIGHT || '8', 10) || 8);
let discoveryBucketInflight = 0;
router.post('/discovery/bucket', async (req, res) => {
  if (discoveryBucketInflight >= DISCOVERY_BUCKET_MAX_INFLIGHT) {
    res.status(503).json({ ok: false, error: 'bucket_busy' });
    return;
  }
  discoveryBucketInflight += 1;
  try {
    const raw = Array.isArray(req.body?.bucketIds) ? req.body.bucketIds : [];
    const bucketIds = Array.from(new Set(raw.filter((n) => Number.isInteger(n) && n >= 0))).slice(0, DISCOVERY_BUCKET_MAX_IDS);
    if (bucketIds.length === 0) {
      res.status(400).json({ ok: false, error: 'invalid_bucket_ids' });
      return;
    }
    const result = await getPirDatabase(DISCOVERY_PIR_DATABASE_KIND);
    const db = result?.database;
    const blobsByBucket = db?.blobsByBucket;
    if (!result?.success || !Array.isArray(blobsByBucket)) {
      res.status(503).json({ ok: false, error: 'bucket_unavailable' });
      return;
    }
    
    const manifest = db.manifest || {};
    const epochId = manifest.epochId || '';
    const targetSize = manifest.bucketTargetSize || DISCOVERY_BUCKET_TARGET_SIZE;
    const medianBlobLen = manifest.medianBlobLen || 1024;
    const buckets = {};

    for (const id of bucketIds) {
      const real = (id >= 0 && id < blobsByBucket.length) ? blobsByBucket[id] : [];
      buckets[id] = padDiscoveryBucket(real, { epochId, bucketId: id, targetSize, medianBlobLen });
    }

    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({ ok: true, epochId, bucketCount: blobsByBucket.length, buckets });
  } catch (error) {
    logError(error, { endpoint: '/api/discovery/bucket' });
    res.status(503).json({ ok: false, error: 'bucket_failed' });
  } finally {
    discoveryBucketInflight = Math.max(0, discoveryBucketInflight - 1);
  }
});

// Discovery OPRF blind-evaluate
router.post('/oprf/evaluate', async (req, res) => {
  if (oprfHttpInflight >= OPRF_HTTP_MAX_INFLIGHT) {
    res.status(503).json({ ok: false, error: 'oprf_busy' });
    return;
  }
  oprfHttpInflight += 1;
  try {
    const blindedPoint = typeof req.body?.blindedPoint === 'string' ? req.body.blindedPoint : '';
    if (!blindedPoint || blindedPoint.length > 8192) {
      res.status(400).json({ ok: false, error: 'invalid_blinded_point' });
      return;
    }
    const evalResult = oprfDiscoveryServer.blindEvaluate(blindedPoint, 'discovery-http-anon');
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      evaluated: evalResult.evaluated,
      proof: evalResult.proof,
      publicKey: evalResult.publicKey
    });
  } catch (error) {
    const isRateLimit = String(error?.message || '').toLowerCase().includes('rate limit');
    res.status(isRateLimit ? 429 : 503).json({ ok: false, error: error?.message || 'oprf_eval_failed' });
  } finally {
    oprfHttpInflight = Math.max(0, oprfHttpInflight - 1);
  }
});

// Discovery PIR manifest
router.post('/pir/manifest', async (req, res) => {
  try {
    const kind = DISCOVERY_PIR_DATABASE_KIND;
    const result = await getPirDatabase(kind, { ensureWorker: req.body?.prepareWorker === true });
    if (!result.success) {
      res.status(503).json({ ok: false, error: result.error });
      return;
    }
    const manifest = publicManifest(result.database);
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      manifest,
      workerUpload: result.database.workerUpload
        ? { uploaded: !!result.database.workerUpload.uploaded, error: result.database.workerUpload.error }
        : undefined
    });
  } catch (error) {
    logError(error, { endpoint: '/api/pir/manifest' });
    res.status(500).json({ ok: false, error: 'pir_manifest_unavailable' });
  }
});

export default router;
