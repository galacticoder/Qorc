import express from 'express';
import {
  getPaddedDiscoveryBuckets,
  getDiscoveryBucketIndex,
  publicDiscoveryManifest
} from '../discovery/bucket-index.js';
import { OPRF_DISCOVERY_POW_DIFFICULTY, oprfDiscoveryServer } from '../crypto/oprf-discovery.js';
import crypto from 'crypto';
import { PrivacyPassHelpers, PrivacyPassServer } from '../authentication/privacy-pass-server.js';
import {
  AvatarBlobDB,
  syntheticMissBlob,
  isValidAvatarBlobId,
  isValidAvatarBlobData
} from '../database/avatar-blob-db.js';
import { verifyPowSolution } from '../security/auth-throttle.js';
import {
  claimAnonymousRequestPow,
  deriveAnonymousRequestPowSeed,
  reservePowNullifier
} from '../security/anonymous-request-pow.js';
import { getDiscoveryEpochInfo } from '../discovery/epoch.js';
import { deriveAuthRootKey } from '../crypto/auth-root.js';
import { SERVER_CONSTANTS } from '../config/constants.js';
import { answerPirQuery, readReadyPirTagIndex } from '../pir/pir-service.js';
import { SPOOL_PIR_EPOCH_UNAVAILABLE } from '../../shared/spool-pir-layout.js';
import {
  KEY_TRANSPARENCY_APPEND_POW_DIFFICULTY,
  KEY_TRANSPARENCY_DELTA_MAX_EPOCHS,
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  KEY_TRANSPARENCY_POW_EPOCH_MS,
  KEY_TRANSPARENCY_SYNC_POW_DIFFICULTY,
  exactPlainObject,
  isKeyTransparencyHash,
  isKeyTransparencyLabel,
  keyTransparencyPowEpoch,
} from '../../shared/key-transparency-protocol.js';
import {
  appendKeyTransparency,
  syncKeyTransparency
} from '../key-transparency/service.js';
import {
  ACCOUNT_AUTH_PURPOSE,
  AVATAR_BLOB_GET_AUDIENCE,
  AVATAR_BLOB_PUT_AUDIENCE,
  AVATAR_POOL_AUDIENCE,
  DISCOVERY_MANIFEST_AUDIENCE,
  KEY_TRANSPARENCY_APPEND_AUDIENCE,
  KEY_TRANSPARENCY_SYNC_AUDIENCE,
  SERVER_ENTRY_PURPOSE
} from '../config/audiences.js';
import {
  ANONYMOUS_OPERATION_FAILED,
  DISCOVERY_EPOCH_EXPIRED
} from '../config/error-codes.js';
import { envInt } from '../utils/env.js';
import { isCanonicalBase64Bytes } from '../utils/encoding.js';
import { setNoStoreHeaders } from '../utils/http.js';
import { createTokenBucketRateLimiter } from '../utils/rate-limit.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { SHA_256_ALGORITHM } from '../utils/crypto-consts.js';
import { SESSION_FINGERPRINT_RE, DISCOVERY_EPOCH_ID_RE } from '../../shared/patterns.js';
import { POW_SEED_BYTES } from '../../shared/crypto-sizes.js';
import {
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_BUCKET_TARGET_SIZE,
  DISCOVERY_DATABASE_KIND,
  DISCOVERY_FIXED_BUCKET_COUNT,
} from '../../shared/discovery-constants.js';
import {
  SPOOL_TAG_PROTOCOL,
  SPOOL_PIR_LAYOUT,
  KEY_TRANSPARENCY_APPEND_POW_DOMAIN,
  KEY_TRANSPARENCY_SYNC_POW_DOMAIN,
} from '../../shared/protocol-keys.js';

let oprfHttpInflight = 0;
const DISCOVERY_BUCKET_POW_DIFFICULTY = 18;
const AVATAR_GET_POW_DIFFICULTY = 16;
const AVATAR_PUT_POW_DIFFICULTY = 18;
const router = express.Router();
const PQ_ANONYMOUS_INTERNAL_REQUEST = Symbol('qorc.pqAnonymousInternalRequest');
const PIR_COMPONENT_MAX_BYTES = 2 * 1024 * 1024;

function fail(res, status, error) {
  return res.status(status).json({ ok: false, error });
}

const ANONYMOUS_OPERATION_ROUTES = Object.freeze({
  [AVATAR_BLOB_GET_AUDIENCE]: Object.freeze({ method: 'POST', path: '/avatar/blob/get' }),
  [AVATAR_BLOB_PUT_AUDIENCE]: Object.freeze({ method: 'POST', path: '/avatar/blob/put' }),
  [AVATAR_POOL_AUDIENCE]: Object.freeze({ method: 'POST', path: '/avatar/pool' }),
  'discovery/bucket': Object.freeze({ method: 'POST', path: '/discovery/bucket' }),
  [DISCOVERY_MANIFEST_AUDIENCE]: Object.freeze({ method: 'POST', path: '/discovery/manifest' }),
  [KEY_TRANSPARENCY_APPEND_AUDIENCE]: Object.freeze({ method: 'POST', path: '/key-transparency/append' }),
  [KEY_TRANSPARENCY_SYNC_AUDIENCE]: Object.freeze({ method: 'POST', path: '/key-transparency/sync' }),
  'oprf/evaluate': Object.freeze({ method: 'POST', path: '/oprf/evaluate' }),
  'spool/tag-index': Object.freeze({ method: 'GET', path: '/spool/tag-index' }),
  'spool/pir': Object.freeze({ method: 'POST', path: '/spool/pir' })
});

router.use((_req, res, next) => {
  setNoStoreHeaders(res);
  next();
});

router.get('/health', (_req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: Date.now() });
});

const pqAnonymousOperationPaths = Object.freeze(Array.from(new Set(
  Object.values(ANONYMOUS_OPERATION_ROUTES).map(({ path }) => path)
)));

router.use(pqAnonymousOperationPaths, (req, res, next) => {
  if (req[PQ_ANONYMOUS_INTERNAL_REQUEST] !== true) {
    fail(res, 404, 'anonymous_transport_required');
    return;
  }
  next();
});

function deriveOprfPowSeed(blindedPoint, epoch, publicKey) {
  return crypto.createHash(SHA_256_ALGORITHM)
    .update(PROTOCOL_KEYS.DISCOVERY_OPRF_POW)
    .update('\0')
    .update(publicKey)
    .update('\0')
    .update(String(epoch))
    .update('\0')
    .update(blindedPoint)
    .digest()
    .subarray(0, POW_SEED_BYTES)
    .toString('base64');
}

async function claimOprfPow(blindedPoint, epoch, expiresAt) {
  const requestDigest = crypto.createHash(SHA_256_ALGORITHM)
    .update(PROTOCOL_KEYS.DISCOVERY_OPRF_POW_NULLIFIER)
    .update('\0')
    .update(String(epoch))
    .update('\0')
    .update(blindedPoint)
    .digest('hex');
  return reservePowNullifier(PROTOCOL_KEYS.DISCOVERY_OPRF_POW_CLAIM, requestDigest, expiresAt);
}

const OPRF_HTTP_MAX_INFLIGHT = envInt('DISCOVERY_OPRF_HTTP_MAX_INFLIGHT', 64, 1, 256);

const oprfRateLimiter = createTokenBucketRateLimiter(envInt('DISCOVERY_OPRF_HTTP_MAX_RPS', 500, 1, 10_000));
const discoveryManifestRateLimiter = createTokenBucketRateLimiter(envInt('DISCOVERY_MANIFEST_HTTP_MAX_RPS', 50, 1, 2_000));

const discoveryBucketRateLimiter = createTokenBucketRateLimiter(
  envInt('DISCOVERY_BUCKET_HTTP_MAX_RPS', 30 * DISCOVERY_BUCKET_QUERY_COUNT, 1, 1024)
);
const avatarGetRateLimiter = createTokenBucketRateLimiter(envInt('AVATAR_GET_HTTP_MAX_RPS', 30, 1, 2_000));
const avatarPutRateLimiter = createTokenBucketRateLimiter(envInt('AVATAR_PUT_HTTP_MAX_RPS', 20, 1, 2_000));
const avatarPoolRateLimiter = createTokenBucketRateLimiter(envInt('AVATAR_POOL_HTTP_MAX_RPS', 10, 1, 2_000));

const spoolTagIndexRateLimiter = createTokenBucketRateLimiter(
  envInt('SPOOL_TAG_INDEX_HTTP_MAX_RPS', 50, 1, 2_000)
);
const spoolPirRateLimiter = createTokenBucketRateLimiter(
  envInt('SPOOL_PIR_HTTP_MAX_RPS', 8, 1, 128)
);
const SPOOL_PIR_MAX_INFLIGHT = envInt('SPOOL_PIR_MAX_INFLIGHT', 2, 1, 8);
const SPOOL_PIR_MAX_RESPONSE_BYTES = 760 * 1024;
let spoolPirInflight = 0;
const keyTransparencySyncRateLimiter = createTokenBucketRateLimiter(envInt('KEY_TRANSPARENCY_SYNC_MAX_RPS', 50, 1, 2_000));
const keyTransparencyAppendRateLimiter = createTokenBucketRateLimiter(envInt('KEY_TRANSPARENCY_APPEND_MAX_RPS', 8, 1, 256));
const KEY_TRANSPARENCY_SYNC_MAX_INFLIGHT = envInt('KEY_TRANSPARENCY_SYNC_MAX_INFLIGHT', 16, 1, 128);
const KEY_TRANSPARENCY_APPEND_MAX_INFLIGHT = envInt('KEY_TRANSPARENCY_APPEND_MAX_INFLIGHT', 4, 1, 32);
let keyTransparencySyncInflight = 0;
let keyTransparencyAppendInflight = 0;
let avatarPoolCache = { epoch: -1, ids: [] };
let avatarPoolBuildPromise = null;
let apiCacheGeneration = 0;

function clearApiRouteCaches() {
  apiCacheGeneration += 1;
  avatarPoolCache = { epoch: -1, ids: [] };
  avatarPoolBuildPromise = null;
  avatarCapEnforcePromise = null;
}
const DISCOVERY_BUCKET_RESPONSE_MAX_BYTES = envInt(
  'DISCOVERY_BUCKET_RESPONSE_MAX_BYTES',
  48 * 1024 * 1024,
  1024 * 1024,
  48 * 1024 * 1024
);

function keyTransparencyPowExpiresAt(epoch) {
  return (epoch + 1) * KEY_TRANSPARENCY_POW_EPOCH_MS;
}


// whole tag index identical for every caller
router.get('/spool/tag-index', async (req, res) => {
  if (!hasExactPlainObjectKeys(req.body, [])) {
    fail(res, 400, 'invalid_spool_tag_index_request');
    return;
  }
  if (!spoolTagIndexRateLimiter()) {
    fail(res, 503, 'spool_tag_index_busy');
    return;
  }
  try {
    const { epoch, tags, probes } = readReadyPirTagIndex();
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      protocol: SPOOL_TAG_PROTOCOL,
      pirLayout: SPOOL_PIR_LAYOUT,
      epoch,
      count: tags.length,
      tags: tags.join(''),
      probes: probes.join('')
    });
  } catch (error) {
    console.error('[API] Spool tag index request failed', error);
    fail(res, 500, 'spool_tag_index_unavailable');
  }
});

router.post('/spool/pir', async (req, res) => {
  let admitted = false;
  let query = null;
  let pubParams = null;
  if (!spoolPirRateLimiter() || spoolPirInflight >= SPOOL_PIR_MAX_INFLIGHT) {
    fail(res, 503, 'spool_pir_busy');
    return;
  }
  spoolPirInflight += 1;
  admitted = true;
  try {
    const body = req.body;
    if (
      !exactPlainObject(body, ['epoch', 'layout', 'pubParams', 'query']) ||
      body.layout !== SPOOL_PIR_LAYOUT ||
      !Number.isSafeInteger(body.epoch) ||
      body.epoch < 0 ||
      !canonicalBase64Shape(body.query, { maxBytes: PIR_COMPONENT_MAX_BYTES }) ||
      !canonicalBase64Shape(body.pubParams, { maxBytes: PIR_COMPONENT_MAX_BYTES })
    ) {
      fail(res, 400, 'invalid_pir_query');
      return;
    }
    query = Buffer.from(body.query, 'base64');
    pubParams = Buffer.from(body.pubParams, 'base64');
    const response = await answerPirQuery(
      body.epoch,
      query,
      pubParams
    );
    if (
      !Buffer.isBuffer(response) ||
      response.length === 0 ||
      response.length > SPOOL_PIR_MAX_RESPONSE_BYTES
    ) {
      response?.fill?.(0);
      fail(res, 503, 'spool_pir_unavailable');
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    try {
      res.status(200).json({ ok: true, response: response.toString('base64') });
    } finally {
      response.fill(0);
    }
  } catch (error) {
    if (error?.message === 'PIR epoch is unavailable') {
      fail(res, 409, SPOOL_PIR_EPOCH_UNAVAILABLE);
      return;
    }
    console.error('[API] Spool PIR request failed', error);
    fail(res, 503, 'spool_pir_unavailable');
  } finally {
    query?.fill(0);
    pubParams?.fill(0);
    if (admitted) spoolPirInflight = Math.max(0, spoolPirInflight - 1);
  }
});

const AVATAR_GET_BATCH_SIZE = 10;
const AVATAR_GET_MAX_INFLIGHT = 8;
const AVATAR_PUT_MAX_INFLIGHT = 4;
const AVATAR_POOL_MAX_INFLIGHT = 4;
const AVATAR_POOL_RESPONSE_SIZE = 256;
const AVATAR_BLOB_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const AVATAR_EXPIRY_QUANTUM_MS = 6 * 60 * 60 * 1000;
const avatarMissSecretBytes = deriveAuthRootKey(PROTOCOL_KEYS.AVATAR_SYNTHETIC_MISS_ROOT);
const AVATAR_MISS_SECRET = Buffer.from(avatarMissSecretBytes);
avatarMissSecretBytes.fill(0);

export async function destroyApiRoutes() {
  const pending = Array.from(new Set([
    avatarPoolBuildPromise,
    avatarCapEnforcePromise
  ].filter(Boolean)));
  clearApiRouteCaches();
  if (pending.length > 0) await Promise.allSettled(pending);
  AVATAR_MISS_SECRET.fill(0);
}
const AVATAR_ENFORCE_EVERY = envInt('AVATAR_ENFORCE_EVERY', 100, 1, 1_000);
let avatarPutsSinceEnforce = 0;
let avatarGetInflight = 0;
let avatarPutInflight = 0;
let avatarPoolInflight = 0;
let avatarCapEnforcePromise = null;

function scheduleAvatarCapEnforcement() {
  if (avatarCapEnforcePromise) return;
  const pending = AvatarBlobDB.enforceCap(SERVER_CONSTANTS.AVATAR_BLOB_MAX_COUNT);
  avatarCapEnforcePromise = pending;
  void pending.finally(() => {
    if (avatarCapEnforcePromise === pending) avatarCapEnforcePromise = null;
  }).catch(() => {});
}

async function getCachedAvatarPool() {
  for (;;) {
    const epoch = getDiscoveryEpochInfo().current;
    if (avatarPoolCache.epoch === epoch) return avatarPoolCache;
    if (!avatarPoolBuildPromise) {
      const generation = apiCacheGeneration;
      const pending = AvatarBlobDB.samplePool(AVATAR_POOL_RESPONSE_SIZE).then((ids) => ({
        epoch,
        ids: ids.slice().sort()
      }));
      avatarPoolBuildPromise = pending;
      void pending.then((entry) => {
        if (
          generation === apiCacheGeneration &&
          entry.epoch === getDiscoveryEpochInfo().current &&
          entry.ids.length >= AVATAR_POOL_RESPONSE_SIZE
        ) {
          avatarPoolCache = entry;
        }
      }).finally(() => {
        if (avatarPoolBuildPromise === pending) avatarPoolBuildPromise = null;
      }).catch(() => {});
    }
    const entry = await avatarPoolBuildPromise;
    if (entry.epoch !== getDiscoveryEpochInfo().current) continue;
    return entry;
  }
}

router.post('/avatar/blob/put', async (req, res) => {
  let admitted = false;
  let accountRedemption = null;
  let serverEntryRedemption = null;
  try {
    if (
      !req.body ||
      typeof req.body !== 'object' ||
      Array.isArray(req.body) ||
      Object.keys(req.body).sort().join(',') !== 'authorization,blobId,data,powEpoch,powNonce,powSolution,serverEntryAuthorization' ||
      !hasExactPlainObjectKeys(req.body.authorization, ['mac', 'nullifier', 'token', 'tokenSecret']) ||
      !hasExactPlainObjectKeys(req.body.serverEntryAuthorization, ['mac', 'nullifier', 'token', 'tokenSecret'])
    ) {
      fail(res, 400, 'invalid_avatar_blob');
      return;
    }
    const blobId = typeof req.body.blobId === 'string' ? req.body.blobId : '';
    const data = typeof req.body.data === 'string' ? req.body.data : '';
    if (
      !isValidAvatarBlobId(blobId) ||
      !isValidAvatarBlobData(data)
    ) {
      fail(res, 400, 'invalid_avatar_blob');
      return;
    }
    const epochInfo = getDiscoveryEpochInfo();
    if (
      req.body.powEpoch !== epochInfo.current ||
      !isCanonicalBase64Bytes(req.body.powNonce, POW_SEED_BYTES) ||
      typeof req.body.powSolution !== 'string'
    ) {
      fail(res, 400, 'invalid_avatar_work');
      return;
    }
    const powSeed = deriveAnonymousRequestPowSeed(
      PROTOCOL_KEYS.AVATAR_PUT_HTTP_POW,
      req.body.powEpoch,
      req.body.powNonce,
      [blobId, data]
    );
    if (!verifyPowSolution(powSeed, AVATAR_PUT_POW_DIFFICULTY, req.body.powSolution)) {
      fail(res, 400, 'invalid_avatar_work');
      return;
    }
    if (!avatarPutRateLimiter() || avatarPutInflight >= AVATAR_PUT_MAX_INFLIGHT) {
      fail(res, 503, 'avatar_busy');
      return;
    }
    avatarPutInflight += 1;
    admitted = true;
    const powClaim = await claimAnonymousRequestPow(
      PROTOCOL_KEYS.AVATAR_PUT_HTTP_POW,
      powSeed,
      req.body.powSolution,
      epochInfo.rotatesAt
    );
    if (powClaim === 'unavailable') {
      fail(res, 503, 'avatar_unavailable');
      return;
    }
    if (powClaim !== 'claimed') {
      fail(res, 409, 'avatar_work_replayed');
      return;
    }
    try {
      accountRedemption = PrivacyPassHelpers.parseRedemptionRequest(req.body.authorization);
      serverEntryRedemption = PrivacyPassHelpers.parseRedemptionRequest(req.body.serverEntryAuthorization);
      const redeemed = await PrivacyPassServer.redeemTokenBatch([
        { ...accountRedemption, expectedPurpose: ACCOUNT_AUTH_PURPOSE },
        { ...serverEntryRedemption, expectedPurpose: SERVER_ENTRY_PURPOSE }
      ]);
      if (
        redeemed?.valid !== true ||
        !PrivacyPassServer.isServerEntryCredentialGenerationCurrent(
          redeemed.serverEntryCredentialGeneration
        )
      ) {
        fail(res, 401, 'avatar_upload_authorization_failed');
        return;
      }
    } catch {
      fail(res, 401, 'avatar_upload_authorization_failed');
      return;
    }
    const now = Date.now();
    const expiresAt = Math.ceil((now + AVATAR_BLOB_MAX_TTL_MS) / AVATAR_EXPIRY_QUANTUM_MS) * AVATAR_EXPIRY_QUANTUM_MS;
    const ok = await AvatarBlobDB.store(blobId, data, expiresAt);
    if (ok) {
      avatarPutsSinceEnforce += 1;
      if (avatarPutsSinceEnforce >= AVATAR_ENFORCE_EVERY) {
        avatarPutsSinceEnforce = 0;
        scheduleAvatarCapEnforcement();
      }
    }
    res.status(ok ? 200 : 500).json({ ok });
  } catch (error) {
    console.error('[API] Avatar upload request failed', error);
    fail(res, 503, 'avatar_put_failed');
  } finally {
    for (const redemption of [accountRedemption, serverEntryRedemption]) {
      redemption?.token.fill(0);
      redemption?.nullifier.fill(0);
      redemption?.mac.fill(0);
      redemption?.tokenSecret.fill(0);
    }
    if (admitted) avatarPutInflight = Math.max(0, avatarPutInflight - 1);
  }
});

router.post('/avatar/blob/get', async (req, res) => {
  let admitted = false;
  try {
    if (
      !req.body ||
      typeof req.body !== 'object' ||
      Array.isArray(req.body) ||
      Object.keys(req.body).sort().join(',') !== 'ids,powEpoch,powNonce,powSolution' ||
      !Array.isArray(req.body.ids) ||
      req.body.ids.length !== AVATAR_GET_BATCH_SIZE ||
      req.body.ids.some((id) => !isValidAvatarBlobId(id)) ||
      new Set(req.body.ids).size !== req.body.ids.length ||
      !Number.isSafeInteger(req.body.powEpoch) ||
      !isCanonicalBase64Bytes(req.body.powNonce, POW_SEED_BYTES) ||
      typeof req.body.powSolution !== 'string'
    ) {
      fail(res, 400, 'invalid_avatar_ids');
      return;
    }
    const ids = req.body.ids;
    const epochInfo = getDiscoveryEpochInfo();
    if (req.body.powEpoch !== epochInfo.current) {
      fail(res, 409, 'avatar_work_epoch_expired');
      return;
    }
    const powSeed = deriveAnonymousRequestPowSeed(
      PROTOCOL_KEYS.AVATAR_GET_HTTP_POW,
      req.body.powEpoch,
      req.body.powNonce,
      ids
    );
    if (!verifyPowSolution(powSeed, AVATAR_GET_POW_DIFFICULTY, req.body.powSolution)) {
      fail(res, 400, 'invalid_avatar_work');
      return;
    }
    if (!avatarGetRateLimiter() || avatarGetInflight >= AVATAR_GET_MAX_INFLIGHT) {
      fail(res, 503, 'avatar_busy');
      return;
    }
    avatarGetInflight += 1;
    admitted = true;
    const powClaim = await claimAnonymousRequestPow(
      PROTOCOL_KEYS.AVATAR_GET_HTTP_POW,
      powSeed,
      req.body.powSolution,
      epochInfo.rotatesAt
    );
    if (powClaim === 'unavailable') {
      fail(res, 503, 'avatar_unavailable');
      return;
    }
    if (powClaim !== 'claimed') {
      fail(res, 409, 'avatar_work_replayed');
      return;
    }
    const now = Date.now();
    const found = await AvatarBlobDB.getMany(ids, now);
    const blobs = ids.map((id) => {
      const synthetic = syntheticMissBlob(id, AVATAR_MISS_SECRET);
      return { id, data: found.get(id) || synthetic };
    });
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({ ok: true, blobs });
  } catch (error) {
    console.error('[API] Avatar retrieval request failed', error);
    fail(res, 503, 'avatar_get_failed');
  } finally {
    if (admitted) avatarGetInflight = Math.max(0, avatarGetInflight - 1);
  }
});

// A random sample of currently valid blobIds for clients to draw cover traffic decoys from
router.post('/avatar/pool', async (req, res) => {
  let admitted = false;
  try {
    if (
      !req.body ||
      typeof req.body !== 'object' ||
      Array.isArray(req.body) ||
      Object.keys(req.body).join(',') !== 'limit' ||
      req.body.limit !== AVATAR_POOL_RESPONSE_SIZE
    ) {
      fail(res, 400, 'invalid_avatar_pool_request');
      return;
    }
    if (!avatarPoolRateLimiter() || avatarPoolInflight >= AVATAR_POOL_MAX_INFLIGHT) {
      fail(res, 503, 'avatar_busy');
      return;
    }
    avatarPoolInflight += 1;
    admitted = true;
    const pool = await getCachedAvatarPool();
    if (pool.ids.length < AVATAR_POOL_RESPONSE_SIZE) {
      fail(res, 503, 'avatar_pool_not_ready');
      return;
    }

    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      ids: pool.ids,
      powEpoch: pool.epoch
    });
  } catch (error) {
    console.error('[API] Avatar pool request failed', error);
    fail(res, 503, 'avatar_pool_failed');
  } finally {
    if (admitted) avatarPoolInflight = Math.max(0, avatarPoolInflight - 1);
  }
});

// k-anonymous discovery keys-blob retrieval
const DISCOVERY_BUCKETS_PER_REQUEST = 1;
const DISCOVERY_BUCKET_MAX_INFLIGHT = Math.min(
  8 * DISCOVERY_BUCKET_QUERY_COUNT,
  Math.max(
    DISCOVERY_BUCKET_QUERY_COUNT,
    Number.parseInt(process.env.DISCOVERY_BUCKET_MAX_INFLIGHT || '', 10) ||
      2 * DISCOVERY_BUCKET_QUERY_COUNT
  )
);
let discoveryBucketInflight = 0;
router.post('/discovery/bucket', async (req, res) => {
  let admitted = false;
  try {
    if (
      !req.body ||
      typeof req.body !== 'object' ||
      Array.isArray(req.body) ||
      Object.keys(req.body).sort().join(',') !== 'bucketIds,epochId,powNonce,powSolution' ||
      typeof req.body.epochId !== 'string' ||
      !DISCOVERY_EPOCH_ID_RE.test(req.body.epochId) ||
      !isCanonicalBase64Bytes(req.body.powNonce, POW_SEED_BYTES) ||
      typeof req.body.powSolution !== 'string'
    ) {
      fail(res, 400, 'invalid_bucket_request');
      return;
    }
    const raw = Array.isArray(req.body?.bucketIds) ? req.body.bucketIds : [];
    const bucketIds = Array.from(new Set(raw.filter((n) => (
      Number.isInteger(n) && n >= 0 && n < DISCOVERY_FIXED_BUCKET_COUNT
    ))));
    
    if (raw.length !== DISCOVERY_BUCKETS_PER_REQUEST || bucketIds.length !== DISCOVERY_BUCKETS_PER_REQUEST) {
      fail(res, 400, 'invalid_bucket_ids');
      return;
    }
    const epochInfo = getDiscoveryEpochInfo();
    if (req.body.epochId !== String(epochInfo.startedAt)) {
      fail(res, 409, DISCOVERY_EPOCH_EXPIRED);
      return;
    }
    const powSeed = deriveAnonymousRequestPowSeed(
      PROTOCOL_KEYS.DISCOVERY_BUCKET_HTTP_POW,
      req.body.epochId,
      req.body.powNonce,
      bucketIds.map(String)
    );
    if (!verifyPowSolution(powSeed, DISCOVERY_BUCKET_POW_DIFFICULTY, req.body.powSolution)) {
      fail(res, 400, 'invalid_bucket_work');
      return;
    }
    if (!discoveryBucketRateLimiter() || discoveryBucketInflight >= DISCOVERY_BUCKET_MAX_INFLIGHT) {
      fail(res, 503, 'bucket_busy');
      return;
    }
    discoveryBucketInflight += 1;
    admitted = true;
    const powClaim = await claimAnonymousRequestPow(
      PROTOCOL_KEYS.DISCOVERY_BUCKET_HTTP_POW,
      powSeed,
      req.body.powSolution,
      epochInfo.rotatesAt
    );
    if (powClaim === 'unavailable') {
      fail(res, 503, 'bucket_unavailable');
      return;
    }
    if (powClaim !== 'claimed') {
      fail(res, 409, 'bucket_work_replayed');
      return;
    }
    const result = await getDiscoveryBucketIndex({ epochId: req.body.epochId });
    const index = result?.index;
    const publishIdsByBucket = index?.publishIdsByBucket;
    if (!result?.success || !Array.isArray(publishIdsByBucket)) {
      res.status(result?.error === DISCOVERY_EPOCH_EXPIRED ? 409 : 503).json({
        ok: false,
        error: result?.error || 'bucket_unavailable'
      });
      return;
    }

    const manifest = index.manifest || {};
    const epochId = manifest.epochId || '';
    if (req.body.epochId !== epochId) {
      fail(res, 409, DISCOVERY_EPOCH_EXPIRED);
      return;
    }
    const targetSize = manifest.bucketTargetSize || DISCOVERY_BUCKET_TARGET_SIZE;
    if (bucketIds.some((id) => id >= publishIdsByBucket.length)) {
      fail(res, 400, 'invalid_bucket_ids');
      return;
    }

    const selectedRealBuckets = bucketIds.map((id) => publishIdsByBucket[id]);
    if (selectedRealBuckets.some((entries) => !Array.isArray(entries) || entries.length > targetSize)) {
      fail(res, 503, 'bucket_unavailable');
      return;
    }

    const responseUpperBound = 4096 +
      DISCOVERY_BUCKETS_PER_REQUEST * targetSize * (DISCOVERY_BLOB_BASE64_CHARS + 4);
    if (responseUpperBound > DISCOVERY_BUCKET_RESPONSE_MAX_BYTES) {
      fail(res, 503, 'bucket_unavailable');
      return;
    }

    const paddedBuckets = await getPaddedDiscoveryBuckets(index, bucketIds);
    if (!paddedBuckets) {
      fail(res, 503, 'bucket_unavailable');
      return;
    }
    const buckets = {};
    for (const id of bucketIds) {
      const padded = paddedBuckets.get(id);
      if (!padded || padded.length !== targetSize) {
        fail(res, 503, 'bucket_unavailable');
        return;
      }
      buckets[id] = padded;
    }

    const payload = { ok: true, epochId, bucketCount: publishIdsByBucket.length, buckets };
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(payload);
  } catch (error) {
    console.error('[API] Discovery bucket request failed', error);
    fail(res, 503, 'bucket_failed');
  } finally {
    if (admitted) discoveryBucketInflight = Math.max(0, discoveryBucketInflight - 1);
  }
});

// Discovery OPRF blind-evaluate
router.post('/oprf/evaluate', async (req, res) => {
  let admitted = false;
  try {
    if (
      !req.body ||
      typeof req.body !== 'object' ||
      Array.isArray(req.body) ||
      Object.keys(req.body).sort().join(',') !== 'blindedPoint,powEpoch,powSolution'
    ) {
      fail(res, 400, 'invalid_oprf_request');
      return;
    }
    const blindedPoint = typeof req.body?.blindedPoint === 'string' ? req.body.blindedPoint : '';
    const powEpoch = req.body?.powEpoch;
    const powSolution = req.body?.powSolution;
    const epochInfo = getDiscoveryEpochInfo();
    if (
      !SESSION_FINGERPRINT_RE.test(blindedPoint) ||
      !Number.isSafeInteger(powEpoch) ||
      powEpoch !== epochInfo.current ||
      typeof powSolution !== 'string'
    ) {
      fail(res, 400, 'invalid_oprf_request');
      return;
    }

    const publicKey = oprfDiscoveryServer.getPublicKey();
    const powSeed = deriveOprfPowSeed(blindedPoint, powEpoch, publicKey);
    if (!verifyPowSolution(powSeed, OPRF_DISCOVERY_POW_DIFFICULTY, powSolution)) {
      fail(res, 400, 'invalid_oprf_work');
      return;
    }
    if (!oprfRateLimiter() || oprfHttpInflight >= OPRF_HTTP_MAX_INFLIGHT) {
      fail(res, 503, 'oprf_busy');
      return;
    }

    oprfHttpInflight += 1;
    admitted = true;
    const powClaim = await claimOprfPow(blindedPoint, powEpoch, epochInfo.rotatesAt);
    if (powClaim === 'unavailable') {
      fail(res, 503, 'oprf_unavailable');
      return;
    }
    if (powClaim !== 'claimed') {
      fail(res, 409, 'oprf_work_replayed');
      return;
    }
    const evalResult = oprfDiscoveryServer.blindEvaluate(blindedPoint);
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      evaluated: evalResult.evaluated,
      proof: evalResult.proof,
      publicKey: evalResult.publicKey
    });
  } catch (error) {
    const isRateLimit = String(error?.message || '').toLowerCase().includes('rate limit');
    fail(res, isRateLimit ? 429 : 503, isRateLimit ? 'oprf_rate_limited' : 'oprf_eval_failed');
  } finally {
    if (admitted) oprfHttpInflight = Math.max(0, oprfHttpInflight - 1);
  }
});

// Public fixed shape discovery bucket manifest
router.post('/discovery/manifest', async (req, res) => {
  try {
    if (
      !hasExactPlainObjectKeys(req.body, ['kind']) ||
      req.body.kind !== DISCOVERY_DATABASE_KIND
    ) {
      fail(res, 400, 'invalid_discovery_manifest_request');
      return;
    }
    if (!discoveryManifestRateLimiter()) {
      fail(res, 503, 'discovery_busy');
      return;
    }
    const result = await getDiscoveryBucketIndex();
    if (!result.success) {
      fail(res, 503, 'discovery_manifest_unavailable');
      return;
    }
    const manifest = publicDiscoveryManifest(result.index);
    if (!manifest) {
      fail(res, 503, 'discovery_manifest_unavailable');
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      ok: true,
      manifest
    });
  } catch (error) {
    console.error('[API] Discovery manifest request failed', error);
    fail(res, 500, 'discovery_manifest_unavailable');
  }
});

router.post('/key-transparency/sync', async (req, res) => {
  let admitted = false;
  try {
    if (req[PQ_ANONYMOUS_INTERNAL_REQUEST] !== true) {
      fail(res, 404, 'anonymous_transport_required');
      return;
    }
    if (
      !hasExactPlainObjectKeys(req.body, [
        'fromEpoch', 'powEpoch', 'powNonce', 'powSolution', 'toEpoch'
      ]) ||
      !Number.isSafeInteger(req.body.fromEpoch) ||
      req.body.fromEpoch < 0 ||
      !Number.isSafeInteger(req.body.toEpoch) ||
      req.body.toEpoch < req.body.fromEpoch ||
      req.body.toEpoch - req.body.fromEpoch >= KEY_TRANSPARENCY_DELTA_MAX_EPOCHS ||
      req.body.powEpoch !== keyTransparencyPowEpoch() ||
      !isCanonicalBase64Bytes(req.body.powNonce, POW_SEED_BYTES) ||
      typeof req.body.powSolution !== 'string'
    ) {
      fail(res, 400, 'invalid_key_transparency_sync');
      return;
    }
    const powSeed = deriveAnonymousRequestPowSeed(
      KEY_TRANSPARENCY_SYNC_POW_DOMAIN,
      req.body.powEpoch,
      req.body.powNonce,
      [String(req.body.fromEpoch), String(req.body.toEpoch)]
    );
    if (!verifyPowSolution(powSeed, KEY_TRANSPARENCY_SYNC_POW_DIFFICULTY, req.body.powSolution)) {
      fail(res, 400, 'invalid_key_transparency_work');
      return;
    }
    if (
      !keyTransparencySyncRateLimiter() ||
      keyTransparencySyncInflight >= KEY_TRANSPARENCY_SYNC_MAX_INFLIGHT
    ) {
      fail(res, 503, 'key_transparency_busy');
      return;
    }
    keyTransparencySyncInflight += 1;
    admitted = true;
    const claim = await claimAnonymousRequestPow(
      KEY_TRANSPARENCY_SYNC_POW_DOMAIN,
      powSeed,
      req.body.powSolution,
      keyTransparencyPowExpiresAt(req.body.powEpoch)
    );
    if (claim === 'unavailable') {
      fail(res, 503, 'key_transparency_unavailable');
      return;
    }
    if (claim !== 'claimed') {
      fail(res, 409, 'key_transparency_work_replayed');
      return;
    }
    const result = await syncKeyTransparency(req.body.fromEpoch, req.body.toEpoch);
    res.status(200).json({ ok: true, result });
  } catch {
    fail(res, 503, 'key_transparency_sync_failed');
  } finally {
    if (admitted) keyTransparencySyncInflight = Math.max(0, keyTransparencySyncInflight - 1);
  }
});

// Append carries 132-byte record and nothing more
router.post('/key-transparency/append', async (req, res) => {
  let admitted = false;
  let accountRedemption = null;
  let serverEntryRedemption = null;
  try {
    if (req[PQ_ANONYMOUS_INTERNAL_REQUEST] !== true) {
      fail(res, 404, 'anonymous_transport_required');
      return;
    }
    if (
      !hasExactPlainObjectKeys(req.body, [
        'authorization',
        'epochLabel',
        'powEpoch',
        'powNonce',
        'powSolution',
        'recordHash',
        'serverEntryAuthorization',
        'version'
      ]) ||
      !hasExactPlainObjectKeys(req.body.authorization, ['mac', 'nullifier', 'token', 'tokenSecret']) ||
      !hasExactPlainObjectKeys(req.body.serverEntryAuthorization, ['mac', 'nullifier', 'token', 'tokenSecret']) ||
      !isKeyTransparencyLabel(req.body.epochLabel) ||
      !isKeyTransparencyHash(req.body.recordHash) ||
      !Number.isSafeInteger(req.body.version) ||
      req.body.version < 1 ||
      req.body.version > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
      req.body.powEpoch !== keyTransparencyPowEpoch() ||
      !isCanonicalBase64Bytes(req.body.powNonce, POW_SEED_BYTES) ||
      typeof req.body.powSolution !== 'string'
    ) {
      fail(res, 400, 'invalid_key_transparency_append');
      return;
    }
    const powSeed = deriveAnonymousRequestPowSeed(
      KEY_TRANSPARENCY_APPEND_POW_DOMAIN,
      req.body.powEpoch,
      req.body.powNonce,
      [
        req.body.epochLabel,
        String(req.body.version),
        req.body.recordHash
      ]
    );
    if (!verifyPowSolution(powSeed, KEY_TRANSPARENCY_APPEND_POW_DIFFICULTY, req.body.powSolution)) {
      fail(res, 400, 'invalid_key_transparency_work');
      return;
    }
    if (
      !keyTransparencyAppendRateLimiter() ||
      keyTransparencyAppendInflight >= KEY_TRANSPARENCY_APPEND_MAX_INFLIGHT
    ) {
      fail(res, 503, 'key_transparency_busy');
      return;
    }
    keyTransparencyAppendInflight += 1;
    admitted = true;
    const claim = await claimAnonymousRequestPow(
      KEY_TRANSPARENCY_APPEND_POW_DOMAIN,
      powSeed,
      req.body.powSolution,
      keyTransparencyPowExpiresAt(req.body.powEpoch)
    );
    if (claim === 'unavailable') {
      fail(res, 503, 'key_transparency_unavailable');
      return;
    }
    if (claim !== 'claimed') {
      fail(res, 409, 'key_transparency_work_replayed');
      return;
    }

    try {
      accountRedemption = PrivacyPassHelpers.parseRedemptionRequest(req.body.authorization);
      serverEntryRedemption = PrivacyPassHelpers.parseRedemptionRequest(req.body.serverEntryAuthorization);
    } catch {
      fail(res, 401, 'key_transparency_authorization_failed');
      return;
    }
    let redeemed;
    try {
      redeemed = await PrivacyPassServer.redeemTokenBatch([
        { ...accountRedemption, expectedPurpose: ACCOUNT_AUTH_PURPOSE },
        { ...serverEntryRedemption, expectedPurpose: SERVER_ENTRY_PURPOSE }
      ]);
    } catch {
      fail(res, 503, 'key_transparency_unavailable');
      return;
    }
    if (
      redeemed?.valid !== true ||
      !PrivacyPassServer.isServerEntryCredentialGenerationCurrent(
        redeemed.serverEntryCredentialGeneration
      )
    ) {
      fail(res, 401, 'key_transparency_authorization_failed');
      return;
    }

    const result = await appendKeyTransparency({
      epochLabel: req.body.epochLabel,
      recordHash: req.body.recordHash,
      version: req.body.version
    });
    if (!result.appended) {
      fail(res, 409, 'key_transparency_epoch_conflict');
      return;
    }
    res.status(200).json({ ok: true });
  } catch {
    fail(res, 503, 'key_transparency_append_failed');
  } finally {
    for (const redemption of [accountRedemption, serverEntryRedemption]) {
      redemption?.token.fill(0);
      redemption?.nullifier.fill(0);
      redemption?.mac.fill(0);
      redemption?.tokenSecret.fill(0);
    }
    if (admitted) keyTransparencyAppendInflight = Math.max(0, keyTransparencyAppendInflight - 1);
  }
});

export async function dispatchAnonymousApiOperation(operation, body) {
  if (
    typeof operation !== 'string' ||
    !Object.hasOwn(ANONYMOUS_OPERATION_ROUTES, operation) ||
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body) ||
    Object.getPrototypeOf(body) !== Object.prototype
  ) {
    return { ok: false, error: 'invalid_anonymous_operation' };
  }
  const target = ANONYMOUS_OPERATION_ROUTES[operation];

  return await new Promise((resolve) => {
    let settled = false;
    const headers = new Map();
    const timeout = setTimeout(() => {
      finish({ ok: false, error: 'anonymous_operation_timeout' });
    }, 180_000);
    timeout.unref?.();

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(payload && typeof payload === 'object'
        ? payload
        : { ok: false, error: 'invalid_anonymous_operation_response' });
    };

    const internalResponse = {
      locals: Object.create(null),
      statusCode: 200,
      headersSent: false,
      writableEnded: false,
      setHeader(name, value) {
        headers.set(String(name).toLowerCase(), value);
        return this;
      },
      getHeader(name) {
        return headers.get(String(name).toLowerCase());
      },
      removeHeader(name) {
        headers.delete(String(name).toLowerCase());
        return this;
      },
      status(code) {
        if (Number.isInteger(code) && code >= 100 && code <= 599) this.statusCode = code;
        return this;
      },
      json(payload) {
        this.headersSent = true;
        this.writableEnded = true;
        finish(payload);
        return this;
      },
      end() {
        this.headersSent = true;
        this.writableEnded = true;
        finish({ ok: false, error: 'empty_anonymous_operation_response' });
        return this;
      }
    };

    const internalRequest = Object.create(null);
    Object.defineProperties(internalRequest, {
      method: { value: target.method, writable: true, configurable: true },
      url: { value: target.path, writable: true, configurable: true },
      originalUrl: { value: target.path, writable: true, configurable: true },
      baseUrl: { value: '', writable: true, configurable: true },
      body: { value: body, writable: true, configurable: true },
      res: { value: internalResponse, writable: true, configurable: true }
    });
    internalRequest[PQ_ANONYMOUS_INTERNAL_REQUEST] = true;
    internalResponse.req = internalRequest;

    router.handle(internalRequest, internalResponse, (error) => {
      if (error) {
        finish({ ok: false, error: ANONYMOUS_OPERATION_FAILED });
        return;
      }
      if (!settled) finish({ ok: false, error: 'anonymous_operation_not_found' });
    });
  });
}

export default router;
