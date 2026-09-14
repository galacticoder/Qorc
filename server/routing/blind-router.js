/**
 * Blind Message Router
 * 
 * Routes sealed envelopes through a global delayed mix stream
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient, createSubscriber, closeSubscriber } from '../session/redis-client.js';
import { envInt } from '../utils/env.js';
import { randomDelay } from '../utils/random.js';
import { createTokenBucketRateLimiter } from '../utils/rate-limit.js';
import { exactRedisScoreArgument } from '../utils/redis-args.js';
import { awaitMessageHandlerWithDeadline } from '../websocket/message-handler-deadline.js';
import { hasPendingBroadcast, sendFlowControlledBroadcast } from './broadcast-flow-control.js';
import {
  moveRedisSortedSetLease,
  REDIS_SORTED_SET_LEASE_RELEASE_GUARD
} from '../utils/redis-lease.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { recordDeliveryExpired, recordDeliveryRetry, withoutStorageTelemetry } from '../telemetry/server-telemetry.js';

import { SignalType } from '../signals.js';
import { SEALED_STANDARD_CIPHERTEXT_BYTES, validateSealedEnvelope } from './sealed-sender.js';
import { SPOOL_DETECTION_PROBE_BYTES, SPOOL_TAG_BYTES,
  untargetedProbeHex,
} from '../../shared/spool-tag-protocol.js';
import {
  createSignedGlobalMixPublication,
  destroyGlobalMixAuthentication,
  initializeGlobalMixAuthentication,
  validateGlobalMixPublication,
} from './global-mix-publication.js';
import {
  ML_KEM_1024_CIPHERTEXT_BYTES,
  HASH_OUTPUT_BYTES,
  SEALED_NONCE_BYTES,
} from '../../shared/crypto-sizes.js';
import { BASE64URL_32_RE } from '../../shared/patterns.js';

export {
  createSignedGlobalMixPublication,
  destroyGlobalMixAuthentication,
  initializeGlobalMixAuthentication,
  validateGlobalMixPublication,
} from './global-mix-publication.js';

// Configuration
const DELIVERY_JITTER_MIN_MS = 10;
const DELIVERY_JITTER_MAX_MS = 100;
const DEDUP_WINDOW_MS = 10 * 60 * 1000;
const DEDUP_MAX_ENTRIES = 20_000;
const MIXNET_DELAY_MIN_MS = envInt('MIXNET_DELAY_MIN_MS', 1500, 250, 120000);
const MIXNET_DELAY_MAX_MS = envInt('MIXNET_DELAY_MAX_MS', 9000, MIXNET_DELAY_MIN_MS, 300000);
const MIXNET_FLUSH_MIN_MS = envInt('MIXNET_FLUSH_MIN_MS', 700, 100, 60000);
const MIXNET_FLUSH_MAX_MS = envInt('MIXNET_FLUSH_MAX_MS', 2500, MIXNET_FLUSH_MIN_MS, 120000);
const MIXNET_BATCH_MAX_MESSAGES = envInt('MIXNET_BATCH_MAX_MESSAGES', 24, 1, 256);
const MIXNET_FLUSH_CONCURRENCY = envInt('MIXNET_FLUSH_CONCURRENCY', 8, 1, 32);
const MIXNET_PROCESSING_TIMEOUT_MS = envInt('MIXNET_PROCESSING_TIMEOUT_MS', 120_000, 60_000, 10 * 60 * 1000);
const MIXNET_POOL_TTL_SECONDS = envInt('MIXNET_POOL_TTL_SECONDS', 60 * 60, 60, 60 * 60);
const MIXNET_INDEX_TTL_SECONDS = MIXNET_POOL_TTL_SECONDS + Math.ceil(MIXNET_DELAY_MAX_MS / 1000) + 60;
const MIXNET_PENDING_MAX_MESSAGES = envInt('MIXNET_PENDING_MAX_MESSAGES', 2048, 64, 100_000);
const MIXNET_PENDING_MAX_BYTES = envInt(
  'MIXNET_PENDING_MAX_BYTES',
  128 * 1024 * 1024,
  8 * 1024 * 1024,
  2 * 1024 * 1024 * 1024
);
const MIXNET_COVER_WRITES_MIN = envInt('MIXNET_COVER_WRITES_MIN', 1, 0, 32);
const MIXNET_COVER_WRITES_MAX = envInt('MIXNET_COVER_WRITES_MAX', 2, MIXNET_COVER_WRITES_MIN, 64);
const GLOBAL_MIX_SPOOL_TTL_SECONDS = envInt('GLOBAL_MIX_SPOOL_TTL_SECONDS', 24 * 60 * 60, 60, 7 * 24 * 60 * 60);
const GLOBAL_MIX_SPOOL_MAX_MESSAGES = envInt('GLOBAL_MIX_SPOOL_MAX_MESSAGES', 32768, 64, 10_000_000);
const GLOBAL_MIX_SPOOL_MAX_BYTES = envInt('GLOBAL_MIX_SPOOL_MAX_BYTES', 512 * 1024 * 1024, 1024 * 1024, 1024 * 1024 * 1024);
const LOCAL_BROADCAST_BUFFERED_MAX_BYTES = envInt('LOCAL_BROADCAST_BUFFERED_MAX_BYTES', 8 * 1024 * 1024, 1024 * 1024, 256 * 1024 * 1024);
const LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS = envInt('LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS', 30000, 1000, 10 * 60 * 1000);
const LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS = envInt('LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS', 2 * 60 * 1000, 10 * 1000, 30 * 60 * 1000);
const LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS = envInt('LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS', 2 * 60 * 1000, 10 * 1000, 30 * 60 * 1000);
const LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS = envInt('LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS', 0, 0, 5 * 60 * 1000);
const LOCAL_BROADCAST_CONCURRENCY = envInt('LOCAL_BROADCAST_CONCURRENCY', 8, 1, 64);
const LOCAL_BROADCAST_DRAIN_BUDGET_MS = 5_000;
const LOCAL_BROADCAST_WAIT_BUDGET_MS = 2_000;
const BLIND_ROUTE_MAX_LOCAL_SOCKETS = envInt('BLIND_ROUTE_MAX_LOCAL_SOCKETS', 2048, 64, 100_000);
const BLIND_DELIVERY_RETRY_MIN_MS = envInt('BLIND_DELIVERY_RETRY_MIN_MS', 5000, 1000, 60_000);
const BLIND_DELIVERY_RETRY_MAX_MS = envInt(
  'BLIND_DELIVERY_RETRY_MAX_MS',
  60_000,
  BLIND_DELIVERY_RETRY_MIN_MS,
  10 * 60 * 1000
);
const GLOBAL_MIX_SPOOL_TRIM_BATCH = 256;
const SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS = Math.ceil(SEALED_STANDARD_CIPHERTEXT_BYTES / 3) * 4;
const SEALED_KEM_CIPHERTEXT_BASE64_CHARS = Math.ceil(ML_KEM_1024_CIPHERTEXT_BYTES / 3) * 4;
const SEALED_NONCE_BASE64_CHARS = Math.ceil(SEALED_NONCE_BYTES / 3) * 4;
const GLOBAL_MIX_SPOOL_MEMBER_BYTES = Buffer.byteLength(JSON.stringify({
  id: 'A'.repeat(43),
  envelope: {
    version: PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL,
    ciphertext: 'A'.repeat(SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS),
    ephemeralKey: 'A'.repeat(SEALED_KEM_CIPHERTEXT_BASE64_CHARS),
    nonce: 'A'.repeat(SEALED_NONCE_BASE64_CHARS),
    tag: 'a'.repeat(SPOOL_TAG_BYTES * 2),
    probe: 'a'.repeat(SPOOL_DETECTION_PROBE_BYTES * 2)
  }
}), 'utf8');
const GLOBAL_MIX_SPOOL_READ_EXPIRY_GUARD_MS = 1_000;
const GLOBAL_MIX_PUBLICATION_MAX_BYTES = envInt(
  'GLOBAL_MIX_PUBLICATION_MAX_BYTES',
  2 * 1024 * 1024,
  512 * 1024,
  16 * 1024 * 1024
);
const GLOBAL_MIX_DELIVERY_QUEUE_MAX_MESSAGES = envInt(
  'GLOBAL_MIX_DELIVERY_QUEUE_MAX_MESSAGES',
  64,
  1,
  4096
);
const GLOBAL_MIX_DELIVERY_QUEUE_MAX_BYTES = envInt(
  'GLOBAL_MIX_DELIVERY_QUEUE_MAX_BYTES',
  32 * 1024 * 1024,
  1024 * 1024,
  512 * 1024 * 1024
);
const GLOBAL_MIX_PUBLICATION_QUEUE_MAX_MESSAGES = envInt(
  'GLOBAL_MIX_PUBLICATION_QUEUE_MAX_MESSAGES',
  64,
  1,
  4096
);
const GLOBAL_MIX_PUBLICATION_QUEUE_MAX_BYTES = envInt(
  'GLOBAL_MIX_PUBLICATION_QUEUE_MAX_BYTES',
  32 * 1024 * 1024,
  1024 * 1024,
  512 * 1024 * 1024
);
const GLOBAL_MIX_PUBLICATION_QUEUE_MAX_AGE_MS = 30_000;
const GLOBAL_MIX_PUBLICATION_VERIFY_MAX_RPS = envInt(
  'GLOBAL_MIX_PUBLICATION_VERIFY_MAX_RPS',
  128,
  1,
  2_000
);
const GLOBAL_MIX_SPOOL_INDEX_MEMBER_RE =
  /^([A-Za-z0-9_-]{43}):([1-9][0-9]{0,9}):([0-9a-f]{16}):([0-9a-f]{64})$/;
const GLOBAL_MIX_SPOOL_INDEX_BYTES_LUA_PATTERN = '^[^:]+:([0-9]+):';
const MIXNET_INDEX_MEMBER_RE = /^([A-Za-z0-9_-]{43}):([1-9][0-9]{0,9})$/;

// Message deduplication cache
const recentDeliveryHashes = new Map();
const recentPublicationIds = new Map();
let mixnetRelayStarted = false;
let mixnetRelayTimer = null;
let mixnetRelayFlushInFlight = false;
let mixnetRelayFlushCompletion = null;
let blindDeliverySubscriberPromise = null;
let blindDeliverySubscriber = null;
let blindDeliveryRetryTimer = null;
let blindDeliveryRetryAttempts = 0;
let blindDeliverySubscriptionDesired = false;
let blindDeliverySubscriptionGeneration = 0;
const globalMixDeliveryQueue = [];
let globalMixDeliveryQueuedBytes = 0;
let globalMixDeliveryDrainPromise = null;
let globalMixDeliveryGeneration = 0;
let globalMixDeliveryPressureLoggedAt = 0;
const allowGlobalMixPublicationVerification = createTokenBucketRateLimiter(
  GLOBAL_MIX_PUBLICATION_VERIFY_MAX_RPS
);
const globalMixPublicationQueue = [];
let globalMixPublicationQueuedBytes = 0;
let globalMixPublicationDrainPromise = null;
let globalMixPublicationGeneration = 0;

function parseGlobalSpoolIndexMember(value) {
  if (typeof value !== 'string') return null;
  const match = GLOBAL_MIX_SPOOL_INDEX_MEMBER_RE.exec(value);
  if (!match) return null;
  const bytes = Number(match[2]);
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > GLOBAL_MIX_PUBLICATION_MAX_BYTES) {
    return null;
  }
  return { id: match[1], bytes, tag: match[3], probe: match[4] };
}

function isCurrentGlobalSpoolRow(row) {
  return row?.bytes === GLOBAL_MIX_SPOOL_MEMBER_BYTES;
}

export function parseGlobalSpoolStoredEntry(raw, row) {
  if (
    !hasExactPlainObjectKeys(row, ['bytes', 'id', 'probe', 'tag']) ||
    !BASE64URL_32_RE.test(row.id) ||
    row.bytes !== GLOBAL_MIX_SPOOL_MEMBER_BYTES ||
    !GLOBAL_MIX_SPOOL_INDEX_MEMBER_RE.test(`${row.id}:${row.bytes}:${row.tag}:${row.probe}`) ||
    typeof raw !== 'string' ||
    Buffer.byteLength(raw, 'utf8') !== row.bytes
  ) return null;

  let stored;
  try {
    stored = JSON.parse(raw);
  } catch {
    return null;
  }
  if (
    !hasExactPlainObjectKeys(stored, ['envelope', 'id']) ||
    stored.id !== row.id ||
    !validateGlobalEnvelope(stored.envelope).valid ||
    stored.envelope.ciphertext.length !== SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS ||
    stored.envelope.tag !== row.tag ||
    stored.envelope.probe !== row.probe
  ) return null;

  const envelopeHash = getEnvelopeHash(stored.envelope);
  if (!envelopeHash) return null;
  const expectedId = Buffer.from(
    blake3(
      Buffer.from(`${PROTOCOL_KEYS.GLOBAL_SPOOL_HASH}\0${envelopeHash}`),
      { dkLen: HASH_OUTPUT_BYTES }
    )
  ).toString('base64url');
  return expectedId === row.id ? stored : null;
}

function parseMixnetIndexMember(value) {
  if (typeof value !== 'string') return null;
  const match = MIXNET_INDEX_MEMBER_RE.exec(value);
  if (!match) return null;
  const bytes = Number(match[2]);
  if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > GLOBAL_MIX_PUBLICATION_MAX_BYTES) {
    return null;
  }
  return { id: match[1], bytes };
}

function getEnvelopeHash(sealedEnvelope) {
  try {
    if (!sealedEnvelope || typeof sealedEnvelope !== 'object' || Array.isArray(sealedEnvelope)) return null;
    const canonical = JSON.stringify({
      version: sealedEnvelope.version,
      ciphertext: sealedEnvelope.ciphertext,
      ephemeralKey: sealedEnvelope.ephemeralKey,
      nonce: sealedEnvelope.nonce
    });
    const hashBytes = blake3(
      Buffer.from(`${PROTOCOL_KEYS.GLOBAL_MIX_HASH}\0${canonical}`),
      { dkLen: HASH_OUTPUT_BYTES }
    );
    return Buffer.from(hashBytes).toString('base64url');
  } catch {
    return null;
  }
}

function createCoverSealedEnvelope() {
  return {
    version: PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL,
    ciphertext: crypto.randomBytes(SEALED_STANDARD_CIPHERTEXT_BYTES).toString('base64'),
    ephemeralKey: crypto.randomBytes(ML_KEM_1024_CIPHERTEXT_BYTES).toString('base64'),
    nonce: crypto.randomBytes(SEALED_NONCE_BYTES).toString('base64'),
    tag: crypto.randomBytes(SPOOL_TAG_BYTES).toString('hex'),
    probe: untargetedProbeHex()
  };
}

function validateGlobalEnvelope(sealedEnvelope) {
  const sealedValidation = validateSealedEnvelope(sealedEnvelope);
  if (!sealedValidation.valid) {
    return { valid: false, error: `invalid_sealed_envelope:${sealedValidation.error}` };
  }
  return { valid: true };
}

function createMixnetEntry(sealedEnvelope, cover) {
  const now = Date.now();
  const delayMs = randomDelay(MIXNET_DELAY_MIN_MS, MIXNET_DELAY_MAX_MS);
  const releaseAt = now + delayMs;
  const entropy = crypto.randomBytes(32).toString('base64url');
  const id = Buffer.from(
    blake3(Buffer.from(`global:${now}:${entropy}`), { dkLen: HASH_OUTPUT_BYTES })
  ).toString('base64url');
  return {
    id,
    cover,
    envelope: sealedEnvelope,
    releaseAt,
    expiresAt: releaseAt + (MIXNET_POOL_TTL_SECONDS * 1000)
  };
}

function hasValidMixnetLifetime(entry) {
  return (
    hasExactPlainObjectKeys(entry, ['cover', 'envelope', 'expiresAt', 'id', 'releaseAt']) &&
    typeof entry.id === 'string' &&
    BASE64URL_32_RE.test(entry.id) &&
    typeof entry.cover === 'boolean' &&
    Number.isSafeInteger(entry.releaseAt) &&
    Number.isSafeInteger(entry.expiresAt) &&
    entry.expiresAt > entry.releaseAt &&
    entry.expiresAt - entry.releaseAt === MIXNET_POOL_TTL_SECONDS * 1000 &&
    validateGlobalEnvelope(entry.envelope).valid
  );
}

function shuffleArray(array) {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(0, i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function scheduleMixnetFlush(delayMs = null) {
  if (!mixnetRelayStarted || mixnetRelayTimer) return;
  const delay = Number.isFinite(delayMs)
    ? Math.max(0, Math.trunc(delayMs))
    : randomDelay(MIXNET_FLUSH_MIN_MS, MIXNET_FLUSH_MAX_MS);

  mixnetRelayTimer = setTimeout(async () => {
    mixnetRelayTimer = null;
    try {
      await flushMixnetDelayPool();
    } finally {
      if (mixnetRelayStarted) {
        scheduleMixnetFlush();
      }
    }
  }, delay);
}

function startMixnetRelay() {
  if (mixnetRelayStarted) return;
  mixnetRelayStarted = true;
  scheduleMixnetFlush(randomDelay(MIXNET_FLUSH_MIN_MS, MIXNET_FLUSH_MAX_MS));
  console.log('[MIXNET] Delay-pool relay started', {
    delayMinMs: MIXNET_DELAY_MIN_MS,
    delayMaxMs: MIXNET_DELAY_MAX_MS,
    coverMin: MIXNET_COVER_WRITES_MIN,
    coverMax: MIXNET_COVER_WRITES_MAX,
    pendingMaxMessages: MIXNET_PENDING_MAX_MESSAGES,
    pendingMaxBytes: MIXNET_PENDING_MAX_BYTES,
    globalSpoolMaxMessages: GLOBAL_MIX_SPOOL_MAX_MESSAGES,
    globalSpoolMaxBytes: GLOBAL_MIX_SPOOL_MAX_BYTES
  });
}

async function stopMixnetRelay() {
    mixnetRelayStarted = false;
    if (mixnetRelayTimer) {
      clearTimeout(mixnetRelayTimer);
      mixnetRelayTimer = null;
    }
    await mixnetRelayFlushCompletion?.catch(() => { });
}

function reserveDeliveryHash(hash) {
  if (!hash) return { duplicate: false, token: null };
  const now = Date.now();
  const prev = recentDeliveryHashes.get(hash);
  if (prev && (now - prev.createdAt) < DEDUP_WINDOW_MS) {
    return { duplicate: true, token: null };
  }
  const token = Symbol('delivery-reservation');
  recentDeliveryHashes.set(hash, { createdAt: now, token });
  // Periodic cleanup
  if (recentDeliveryHashes.size > DEDUP_MAX_ENTRIES) {
    for (const [k, entry] of recentDeliveryHashes) {
      if (now - entry.createdAt > DEDUP_WINDOW_MS) recentDeliveryHashes.delete(k);
    }
    // Hard-evict oldest entries if still over limit after expiry sweep
    if (recentDeliveryHashes.size > DEDUP_MAX_ENTRIES) {
      const excess = recentDeliveryHashes.size - DEDUP_MAX_ENTRIES;
      let removed = 0;
      for (const k of recentDeliveryHashes.keys()) {
        if (removed >= excess) break;
        recentDeliveryHashes.delete(k);
        removed++;
      }
    }
  }
  return { duplicate: false, token };
}

function rollbackDeliveryHash(hash, token) {
  if (!hash || !token) return;
  const current = recentDeliveryHashes.get(hash);
  if (current?.token === token) {
    recentDeliveryHashes.delete(hash);
  }
}

function pruneRecentDeliveryHashes(now = Date.now(), force = false) {
  let removed = 0;
  for (const [hash, entry] of recentDeliveryHashes.entries()) {
    if (force || now - entry.createdAt > DEDUP_WINDOW_MS) {
      recentDeliveryHashes.delete(hash);
      removed += 1;
    }
  }
  return removed;
}

function reservePublicationId(publicationId) {
  if (typeof publicationId !== 'string' || !BASE64URL_32_RE.test(publicationId)) {
    return false;
  }
  const now = Date.now();
  const previous = recentPublicationIds.get(publicationId);
  if (previous && now - previous < DEDUP_WINDOW_MS) return false;
  recentPublicationIds.set(publicationId, now);
  if (recentPublicationIds.size > DEDUP_MAX_ENTRIES) {
    for (const [id, createdAt] of recentPublicationIds) {
      if (now - createdAt > DEDUP_WINDOW_MS || recentPublicationIds.size > DEDUP_MAX_ENTRIES) {
        recentPublicationIds.delete(id);
      }
    }
  }
  return true;
}

function pruneRecentPublicationIds(now = Date.now(), force = false) {
  let removed = 0;
  for (const [id, createdAt] of recentPublicationIds) {
    if (force || now - createdAt > DEDUP_WINDOW_MS) {
      recentPublicationIds.delete(id);
      removed += 1;
    }
  }
  return removed;
}

// In-memory socket registry
const localSocketRegistry = new Map();

export function pruneBlindRouterRuntimeState({ force = false } = {}) {
  let closedSocketsRemoved = 0;
  for (const [socketId, ws] of localSocketRegistry.entries()) {
    if (!ws || ws.readyState !== 1) {
      localSocketRegistry.delete(socketId);
      closedSocketsRemoved += 1;
    }
  }
  return {
    closedSocketsRemoved,
    recentDeliveryHashesRemoved: pruneRecentDeliveryHashes(Date.now(), force),
    recentPublicationIdsRemoved: pruneRecentPublicationIds(Date.now(), force)
  };
}

/**
 * Register a local WebSocket connection
 */
export function registerLocalSocket(ws) {
  if (!ws || typeof ws !== 'object') {
    throw new Error('A WebSocket is required for blind delivery registration');
  }

  const existingSocketId = ws._blindSocketId;
  if (typeof existingSocketId === 'string') {
    if (localSocketRegistry.get(existingSocketId) === ws) return existingSocketId;
    delete ws._blindSocketId;
  }

  pruneBlindRouterRuntimeState();
  if (localSocketRegistry.size >= BLIND_ROUTE_MAX_LOCAL_SOCKETS) {
    throw new Error('Blind delivery registration capacity reached');
  }

  let socketId;
  do {
    socketId = crypto.randomBytes(32).toString('base64url');
  } while (localSocketRegistry.has(socketId));

  ws._blindSocketId = socketId;
  localSocketRegistry.set(socketId, ws);

  return socketId;
}

/**
 * Unregister a local WebSocket connection
 */
export function unregisterLocalSocket(ws) {
  const socketId = ws?._blindSocketId;
  if (socketId) {
    if (localSocketRegistry.get(socketId) === ws) {
      localSocketRegistry.delete(socketId);
    }
    delete ws._blindSocketId;
  }
}

export async function routeToGlobalMix(sealedEnvelope, options = {}) {
  const validation = validateGlobalEnvelope(sealedEnvelope);
  if (!validation.valid) {
    return { queued: false, delivered: 0, error: validation.error };
  }

  if (
    options.liveOnly !== true &&
    sealedEnvelope.ciphertext.length !== SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS
  ) {
    return { queued: false, delivered: 0, error: 'global_mix_spool_unsupported_size' };
  }

  const dedupHash = getEnvelopeHash(sealedEnvelope);
  const reservation = reserveDeliveryHash(dedupHash);
  if (reservation.duplicate) {
    return { queued: true, delivered: 0, deduplicated: true };
  }

  try {
    if (options.liveOnly === true) {
      const result = await writeToGlobalMixSpool(sealedEnvelope, { persist: false });
      if (!result?.queued) rollbackDeliveryHash(dedupHash, reservation.token);
      return result;
    }
    const result = await enqueueValidatedMixnetRelay(sealedEnvelope);
    if (!result?.queued) {
      rollbackDeliveryHash(dedupHash, reservation.token);
    }
    return result;
  } catch (error) {
    rollbackDeliveryHash(dedupHash, reservation.token);
    throw error;
  }
}

export async function enqueueMixnetRelay(sealedEnvelope, options = {}) {
  const validation = validateGlobalEnvelope(sealedEnvelope);
  if (!validation.valid) {
    return { queued: false, delivered: 0, error: validation.error };
  }

  if (
    options.cover !== true &&
    sealedEnvelope.ciphertext.length !== SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS
  ) {
    return { queued: false, delivered: 0, error: 'global_mix_spool_unsupported_size' };
  }

  return enqueueValidatedMixnetRelay(sealedEnvelope, options);
}

async function enqueueValidatedMixnetRelay(sealedEnvelope, options = {}) {
  const isCover = options.cover === true;
  const entry = createMixnetEntry(sealedEnvelope, isCover);
  const rawEntry = JSON.stringify(entry);
  const entryBytes = Buffer.byteLength(rawEntry, 'utf8');
  if (entryBytes <= 0 || entryBytes > GLOBAL_MIX_PUBLICATION_MAX_BYTES) {
    return { queued: false, delivered: 0, error: 'mixnet_entry_too_large' };
  }
  const indexMember = `${entry.id}:${entryBytes}`;
  const entryKey = `${PROTOCOL_KEYS.MIXNET_ENTRY_REDIS_PREFIX}${entry.id}`;
  const pendingMessageLimit = isCover
    ? Math.max(1, Math.floor(MIXNET_PENDING_MAX_MESSAGES / 2))
    : MIXNET_PENDING_MAX_MESSAGES;
  const pendingByteLimit = isCover
    ? Math.max(1, Math.floor(MIXNET_PENDING_MAX_BYTES / 2))
    : MIXNET_PENDING_MAX_BYTES;

  try {
    const queued = await withRedisClient((client) => client.eval(
      ENQUEUE_MIX_MEMBER_SCRIPT,
      4,
      PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS,
      PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS,
      PROTOCOL_KEYS.MIXNET_PENDING_BYTES_REDIS,
      entryKey,
      entry.releaseAt,
      indexMember,
      rawEntry,
      entryBytes,
      MIXNET_INDEX_TTL_SECONDS,
      entry.expiresAt - Date.now(),
      pendingMessageLimit,
      pendingByteLimit,
      Date.now() - (MIXNET_POOL_TTL_SECONDS * 1000),
      MIXNET_BATCH_MAX_MESSAGES
    ));
    if (Number(queued) !== 1) {
      return { queued: false, delivered: 0, error: 'mixnet_capacity_reached' };
    }
    startMixnetRelay();
    scheduleMixnetFlush();
    return {
      queued: true,
      delivered: 0,
      relay: 'mixnet-delay-pool'
    };
  } catch (error) {
    console.error('[MIXNET] Failed to enqueue ingress relay packet', { error: error.message });
    return { queued: false, delivered: 0, error: 'mixnet_enqueue_failed' };
  }
}

const ENQUEUE_MIX_MEMBER_SCRIPT = `
  local delayPool = KEYS[1]
  local processingPool = KEYS[2]
  local bytesKey = KEYS[3]
  local entryKey = KEYS[4]
  local score = ARGV[1]
  local indexMember = ARGV[2]
  local entry = ARGV[3]
  local memberBytes = tonumber(ARGV[4])
  local indexTtl = tonumber(ARGV[5])
  local entryTtlMs = tonumber(ARGV[6])
  local maxMessages = tonumber(ARGV[7])
  local maxBytes = tonumber(ARGV[8])
  local oldestAllowed = ARGV[9]
  local trimBatch = tonumber(ARGV[10])

  local function indexedBytes(value)
    return tonumber(string.match(value, ':([0-9]+)$') or '0')
  end

  local storedBytes = redis.call('GET', bytesKey)
  local totalBytes = tonumber(storedBytes or '0')
  if not storedBytes then
    totalBytes = 0
    for _, existing in ipairs(redis.call('ZRANGE', delayPool, 0, -1)) do
      totalBytes = totalBytes + indexedBytes(existing)
    end
    for _, existing in ipairs(redis.call('ZRANGE', processingPool, 0, -1)) do
      totalBytes = totalBytes + indexedBytes(existing)
    end
  end

  local expired = redis.call('ZRANGEBYSCORE', delayPool, '-inf', oldestAllowed, 'LIMIT', 0, trimBatch)
  for _, oldMember in ipairs(expired) do
    if redis.call('ZREM', delayPool, oldMember) == 1 then
      totalBytes = totalBytes - indexedBytes(oldMember)
    end
  end
  if totalBytes < 0 then totalBytes = 0 end

  local pendingCount = redis.call('ZCARD', delayPool) + redis.call('ZCARD', processingPool)
  if pendingCount >= maxMessages or totalBytes + memberBytes > maxBytes then
    redis.call('SET', bytesKey, totalBytes, 'EX', indexTtl)
    redis.call('EXPIRE', delayPool, indexTtl)
    redis.call('EXPIRE', processingPool, indexTtl)
    return 0
  end

  if entryTtlMs <= 0 or not redis.call('SET', entryKey, entry, 'PX', entryTtlMs, 'NX') then
    return 0
  end
  if redis.call('ZADD', delayPool, 'NX', score, indexMember) ~= 1 then
    redis.call('DEL', entryKey)
    return 0
  end
  totalBytes = totalBytes + memberBytes
  redis.call('SET', bytesKey, totalBytes, 'EX', indexTtl)
  redis.call('EXPIRE', delayPool, indexTtl)
  redis.call('EXPIRE', processingPool, indexTtl)
  return 1
`;

export async function enqueueMixnetCoverWrite() {
  return enqueueMixnetRelay(createCoverSealedEnvelope(), { cover: true });
}

async function writeToGlobalMixSpool(sealedEnvelope, options = {}) {
  const spoolable =
    sealedEnvelope.ciphertext.length === SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS;
  const { persist = true } = options;
  if (persist && !spoolable) {
    throw new Error('global_mix_spool_unsupported_size');
  }
  let spoolInserted = true;

  const jitter = crypto.randomInt(DELIVERY_JITTER_MIN_MS, DELIVERY_JITTER_MAX_MS);
  await new Promise((resolve) => setTimeout(resolve, jitter));
  if (persist && spoolable) {
    spoolInserted = await queueGlobalMixMessage(sealedEnvelope);
  }

  const publication = createSignedGlobalMixPublication(sealedEnvelope);
  const publicationWire = JSON.stringify(publication);
  const localQueued = enqueueGlobalMixDelivery(
    publication,
    Buffer.byteLength(publicationWire, 'utf8')
  );
  const publicationQueued = enqueueGlobalMixPublication(publicationWire);
  const queued = persist || localQueued || publicationQueued;

  return {
    queued,
    delivered: 0,
    ...(!queued ? { error: 'live_delivery_unavailable' } : {}),
    ...(persist && !spoolInserted ? { deduplicated: true } : {})
  };
}

async function moveMixMember(client, sourceKey, destinationKey, raw, score, expectedSourceScore) {
  return moveRedisSortedSetLease(client, {
    sourceKey,
    destinationKey,
    member: raw,
    destinationScore: score,
    ttlSeconds: MIXNET_INDEX_TTL_SECONDS,
    expectedSourceScore
  });
}

const REMOVE_MIX_MEMBER_SCRIPT = `
${REDIS_SORTED_SET_LEASE_RELEASE_GUARD}
  local function indexedBytes(value)
    return tonumber(string.match(value, ':([0-9]+)$') or '0')
  end
  local storedBytes = redis.call('GET', KEYS[2])
  local totalBytes = 0
  if storedBytes then
    totalBytes = tonumber(storedBytes) - indexedBytes(ARGV[1])
  else
    for _, existing in ipairs(redis.call('ZRANGE', KEYS[3], 0, -1)) do
      totalBytes = totalBytes + indexedBytes(existing)
    end
    for _, existing in ipairs(redis.call('ZRANGE', KEYS[4], 0, -1)) do
      totalBytes = totalBytes + indexedBytes(existing)
    end
  end
  redis.call('DEL', KEYS[5])
  if totalBytes < 0 then totalBytes = 0 end
  redis.call('SET', KEYS[2], totalBytes, 'EX', ARGV[2])
  redis.call('EXPIRE', KEYS[3], ARGV[2])
  redis.call('EXPIRE', KEYS[4], ARGV[2])
  return 1
`;

async function removeMixMember(client, poolKey, raw, expectedSourceScore) {
  const sourceScore = exactRedisScoreArgument(expectedSourceScore);
  const indexEntry = parseMixnetIndexMember(raw);
  const entryKey = `${PROTOCOL_KEYS.MIXNET_ENTRY_REDIS_PREFIX}${indexEntry?.id || 'invalid'}`;
  return Number(await client.eval(
    REMOVE_MIX_MEMBER_SCRIPT,
    5,
    poolKey,
    PROTOCOL_KEYS.MIXNET_PENDING_BYTES_REDIS,
    PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS,
    PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS,
    entryKey,
    raw,
    MIXNET_INDEX_TTL_SECONDS,
    sourceScore
  )) === 1;
}

async function loadMixnetEntry(client, indexMember) {
  const indexEntry = parseMixnetIndexMember(indexMember);
  if (!indexEntry) return null;
  const raw = await client.get(`${PROTOCOL_KEYS.MIXNET_ENTRY_REDIS_PREFIX}${indexEntry.id}`);
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') !== indexEntry.bytes) {
    return null;
  }
  let entry;
  try {
    entry = JSON.parse(raw);
  } catch {
    return null;
  }
  if (entry?.id !== indexEntry.id || !hasValidMixnetLifetime(entry)) return null;
  return entry;
}

async function recoverStaleMixnetClaims(client) {
  const now = Date.now();
  const stale = await client.zrangebyscore(
    PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS,
    '-inf',
    now,
    'LIMIT',
    0,
    MIXNET_BATCH_MAX_MESSAGES
  );
  for (const indexMember of stale || []) {
    const currentScore = await client.zscore(PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS, indexMember);
    if (currentScore === null || Number(currentScore) > now) continue;
    const entry = await loadMixnetEntry(client, indexMember);
    if (!entry || entry.expiresAt <= now) {
      await removeMixMember(client, PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS, indexMember, currentScore);
      recordDeliveryExpired();
      continue;
    }
    const retryAt = Math.min(
      entry.expiresAt,
      now + randomDelay(MIXNET_FLUSH_MIN_MS, MIXNET_FLUSH_MAX_MS)
    );
    await moveMixMember(
      client,
      PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS,
      PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS,
      indexMember,
      retryAt,
      currentScore
    );
    recordDeliveryRetry();
  }
}

async function finalizeMixnetClaim(indexMember, entry, claimUntil, succeeded) {
  if (typeof indexMember !== 'string') return;
  await withRedisClient(async (client) => {
    if (succeeded) {
      await removeMixMember(client, PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS, indexMember, claimUntil);
      return;
    }
    const now = Date.now();
    if (!hasValidMixnetLifetime(entry) || entry.expiresAt <= now) {
      await removeMixMember(client, PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS, indexMember, claimUntil);
      recordDeliveryExpired();
      return;
    }
    const retryAt = Math.min(
      entry.expiresAt,
      now + randomDelay(MIXNET_FLUSH_MIN_MS, MIXNET_FLUSH_MAX_MS)
    );
    await moveMixMember(
      client,
      PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS,
      PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS,
      indexMember,
      retryAt,
      claimUntil
    );
    recordDeliveryRetry();
  });
}

async function flushMixnetDelayPool() {
  if (mixnetRelayFlushInFlight) return mixnetRelayFlushCompletion;
  mixnetRelayFlushInFlight = true;
  let completeFlush;
  const completion = new Promise((resolve) => { completeFlush = resolve; });
  mixnetRelayFlushCompletion = completion;

  const claimed = [];
  try {
    await withRedisClient(async (client) => {
      await trimExpiredGlobalMixSpool(client);
      await recoverStaleMixnetClaims(client);
      const dueMembers = await client.zrangebyscore(
        PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS,
        '-inf',
        Date.now(),
        'LIMIT',
        0,
        Math.min(MIXNET_BATCH_MAX_MESSAGES, MIXNET_FLUSH_CONCURRENCY)
      );

      for (const indexMember of dueMembers || []) {
        const currentScore = await client.zscore(PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS, indexMember);
        if (currentScore === null || Number(currentScore) > Date.now()) continue;
        const entry = await loadMixnetEntry(client, indexMember);
        const claimStartedAt = Date.now();
        if (
          !entry ||
          entry.expiresAt <= claimStartedAt
        ) {
          await removeMixMember(client, PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS, indexMember, currentScore);
          recordDeliveryExpired();
          continue;
        }

        const claimUntil = Math.min(
          entry.expiresAt,
          claimStartedAt + MIXNET_PROCESSING_TIMEOUT_MS
        );
        const moved = await moveMixMember(
          client,
          PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS,
          PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS,
          indexMember,
          claimUntil,
          currentScore
        );
        if (moved) {
          claimed.push({ entry, indexMember, claimUntil });
        }
      }
    });

    const coverCount = claimed.length > 0 && MIXNET_COVER_WRITES_MAX > 0
      ? crypto.randomInt(MIXNET_COVER_WRITES_MIN, MIXNET_COVER_WRITES_MAX + 1)
      : 0;
    const covers = Array.from({ length: coverCount }, () => ({
      entry: {
        id: crypto.randomBytes(32).toString('base64url'),
        cover: true,
        envelope: createCoverSealedEnvelope()
      }
    }));

    const batch = shuffleArray([...claimed, ...covers]);
    if (batch.length === 0) {
      return;
    }

    for (let offset = 0; offset < batch.length; offset += MIXNET_FLUSH_CONCURRENCY) {
      await Promise.all(
        batch
          .slice(offset, offset + MIXNET_FLUSH_CONCURRENCY)
          .map(processMixnetClaim)
      );
    }
  } catch (error) {
    console.error('[MIXNET] Delay-pool flush failed', { error: error.message });
  } finally {
    mixnetRelayFlushInFlight = false;
    if (mixnetRelayFlushCompletion === completion) mixnetRelayFlushCompletion = null;
    completeFlush();
  }
}

async function processMixnetClaim(claimedItem) {
  const entry = claimedItem?.entry;
  if (!entry?.envelope) return;
  const microDelay = randomDelay(0, 80);
  if (microDelay > 0) {
    await new Promise((resolve) => setTimeout(resolve, microDelay));
  }
  let succeeded = false;
  try {
    await writeToGlobalMixSpool(entry.envelope, {
      persist: entry.cover !== true
    });
    succeeded = true;
  } catch (error) {
    console.warn('[MIXNET] Global writer failed', {
      error: error?.message
    });
  } finally {
    try {
      await finalizeMixnetClaim(
        claimedItem.indexMember,
        entry,
        claimedItem.claimUntil,
        succeeded
      );
    } catch (error) {
      console.warn('[MIXNET] Durable claim finalization failed', {
        succeeded,
        error: error?.message
      });
    }
  }
}

async function queueGlobalMixMessage(sealedEnvelope) {
  try {
    return await withRedisClient(async (client) => {
      const now = Date.now();
      const score = (now * 1000) + crypto.randomInt(0, 1000);
      const envelopeHash = getEnvelopeHash(sealedEnvelope);
      if (!envelopeHash) throw new Error('global_mix_spool_invalid_envelope');
      const id = Buffer.from(
        blake3(
          Buffer.from(`${PROTOCOL_KEYS.GLOBAL_SPOOL_HASH}\0${envelopeHash}`),
          { dkLen: HASH_OUTPUT_BYTES }
        )
      ).toString('base64url');
      const memberObject = {
        id,
        envelope: sealedEnvelope
      };
      const member = JSON.stringify(memberObject);
      const memberBytes = Buffer.byteLength(member, 'utf8');
      if (
        memberBytes !== GLOBAL_MIX_SPOOL_MEMBER_BYTES ||
        memberBytes > GLOBAL_MIX_PUBLICATION_MAX_BYTES
      ) {
        throw new Error('global_mix_spool_invalid_member_size');
      }

      // one ciphertext size is spoolable
      if (sealedEnvelope.ciphertext.length !== SEALED_STANDARD_CIPHERTEXT_BASE64_CHARS) {
        throw new Error('global_mix_spool_unsupported_size');
      }
      const indexMember = `${id}:${memberBytes}:${sealedEnvelope.tag}:${sealedEnvelope.probe}`;
      const entryKey = `${PROTOCOL_KEYS.MIXNET_SPOOL_ENTRY_REDIS_PREFIX}${id}`;
      const ttlMilliseconds = GLOBAL_MIX_SPOOL_TTL_SECONDS * 1000;
      const oldestAllowed = ((now - (GLOBAL_MIX_SPOOL_TTL_SECONDS * 1000)) * 1000);
      const appendResult = await client.eval(
        APPEND_AND_TRIM_GLOBAL_SPOOL_SCRIPT,
        3,
        PROTOCOL_KEYS.MIXNET_SPOOL_INDEX_REDIS,
        PROTOCOL_KEYS.MIXNET_SPOOL_BYTES_REDIS,
        entryKey,
        score,
        indexMember,
        member,
        memberBytes,
        ttlMilliseconds,
        GLOBAL_MIX_SPOOL_TTL_SECONDS + 60,
        oldestAllowed,
        GLOBAL_MIX_SPOOL_MAX_MESSAGES,
        GLOBAL_MIX_SPOOL_MAX_BYTES,
        GLOBAL_MIX_SPOOL_TRIM_BATCH
      );
      if (!Array.isArray(appendResult) || Number(appendResult[0]) !== 1) {
        throw new Error('global_mix_spool_capacity_reached');
      }
      return Number(appendResult[3]) === 1;
    });
  } catch (error) {
    console.error('[BLIND-ROUTER] Global mix spool failed', { error: error.message });
    throw error;
  }
}

const APPEND_AND_TRIM_GLOBAL_SPOOL_SCRIPT = `
  local spool = KEYS[1]
  local bytesKey = KEYS[2]
  local entryKey = KEYS[3]
  local score = ARGV[1]
  local indexMember = ARGV[2]
  local member = ARGV[3]
  local memberBytes = tonumber(ARGV[4])
  local entryTtlMs = tonumber(ARGV[5])
  local indexTtl = tonumber(ARGV[6])
  local oldestAllowed = ARGV[7]
  local maxMessages = tonumber(ARGV[8])
  local maxBytes = tonumber(ARGV[9])
  local trimBatch = tonumber(ARGV[10])

  local function indexedBytes(value)
    return tonumber(string.match(value, '${GLOBAL_MIX_SPOOL_INDEX_BYTES_LUA_PATTERN}') or '0')
  end

  local storedTotalBytes = redis.call('GET', bytesKey)
  local totalBytes = tonumber(storedTotalBytes or '0')
  if not storedTotalBytes then
    totalBytes = 0
    local existingMembers = redis.call('ZRANGE', spool, 0, -1)
    for _, existingMember in ipairs(existingMembers) do
      totalBytes = totalBytes + indexedBytes(existingMember)
    end
  end

  local function removeMembers(members)
    for _, oldMember in ipairs(members) do
      if redis.call('ZREM', spool, oldMember) == 1 then
        totalBytes = totalBytes - indexedBytes(oldMember)
      end
    end
  end

  local expired = redis.call('ZRANGEBYSCORE', spool, '-inf', oldestAllowed, 'LIMIT', 0, trimBatch)
  removeMembers(expired)

  if totalBytes < 0 then totalBytes = 0 end
  local existing = redis.call('ZSCORE', spool, indexMember)
  if existing then
    local retained = redis.call('GET', entryKey)
    if retained == member then
      redis.call('SET', bytesKey, totalBytes, 'EX', indexTtl)
      redis.call('EXPIRE', spool, indexTtl)
      return { 1, redis.call('ZCARD', spool), totalBytes, 0 }
    end
    if retained then
      return { 0, redis.call('ZCARD', spool), totalBytes, 0 }
    end
    if redis.call('ZREM', spool, indexMember) == 1 then
      totalBytes = totalBytes - memberBytes
      if totalBytes < 0 then totalBytes = 0 end
    end
  end

  if memberBytes > maxBytes or redis.call('ZCARD', spool) >= maxMessages or totalBytes + memberBytes > maxBytes then
    redis.call('SET', bytesKey, totalBytes, 'EX', indexTtl)
    redis.call('EXPIRE', spool, indexTtl)
    return { 0, redis.call('ZCARD', spool), totalBytes, 0 }
  end

  if not redis.call('SET', entryKey, member, 'PX', entryTtlMs, 'NX') then
    return { 0, redis.call('ZCARD', spool), totalBytes, 0 }
  end
  if redis.call('ZADD', spool, 'NX', score, indexMember) ~= 1 then
    redis.call('DEL', entryKey)
    return { 0, redis.call('ZCARD', spool), totalBytes, 0 }
  end

  totalBytes = totalBytes + memberBytes
  redis.call('SET', bytesKey, totalBytes, 'EX', indexTtl)
  redis.call('EXPIRE', spool, indexTtl)
  return { 1, redis.call('ZCARD', spool), totalBytes, 1 }
`;

const TRIM_EXPIRED_GLOBAL_SPOOL_SCRIPT = `
  local spool = KEYS[1]
  local bytesKey = KEYS[2]
  local oldestAllowed = ARGV[1]
  local trimBatch = tonumber(ARGV[2])
  local indexTtl = tonumber(ARGV[3])

  local function indexedBytes(value)
    return tonumber(string.match(value, '${GLOBAL_MIX_SPOOL_INDEX_BYTES_LUA_PATTERN}') or '0')
  end

  local storedTotalBytes = redis.call('GET', bytesKey)
  local totalBytes = tonumber(storedTotalBytes or '0')
  if not storedTotalBytes then
    totalBytes = 0
    for _, existingMember in ipairs(redis.call('ZRANGE', spool, 0, -1)) do
      totalBytes = totalBytes + indexedBytes(existingMember)
    end
  end

  local removed = 0
  local expired = redis.call('ZRANGEBYSCORE', spool, '-inf', oldestAllowed, 'LIMIT', 0, trimBatch)
  for _, oldMember in ipairs(expired) do
    if redis.call('ZREM', spool, oldMember) == 1 then
      totalBytes = totalBytes - indexedBytes(oldMember)
      removed = removed + 1
    end
  end
  if totalBytes < 0 then totalBytes = 0 end

  local count = redis.call('ZCARD', spool)
  if count == 0 then
    redis.call('DEL', bytesKey)
  else
    redis.call('SET', bytesKey, totalBytes, 'EX', indexTtl)
    redis.call('EXPIRE', spool, indexTtl)
  end
  return { removed, count, totalBytes }
`;

async function trimExpiredGlobalMixSpool(client, now = Date.now()) {
  const oldestAllowed = ((now - (GLOBAL_MIX_SPOOL_TTL_SECONDS * 1000)) * 1000);
  const result = await client.eval(
    TRIM_EXPIRED_GLOBAL_SPOOL_SCRIPT,
    2,
    PROTOCOL_KEYS.MIXNET_SPOOL_INDEX_REDIS,
    PROTOCOL_KEYS.MIXNET_SPOOL_BYTES_REDIS,
    oldestAllowed,
    GLOBAL_MIX_SPOOL_TRIM_BATCH,
    GLOBAL_MIX_SPOOL_TTL_SECONDS + 60
  );
  const removed = Array.isArray(result) ? Number(result[0]) : 0;
  if (Number.isSafeInteger(removed) && removed > 0) recordDeliveryExpired(removed);
  return result;
}

export async function getBlindRouterTelemetry() {
  return withoutStorageTelemetry(() => withRedisClient(async (client) => {
    const [delayCount, processingCount, pendingBytes, spoolCount, spoolBytes, oldestSpool] = await Promise.all([
      client.zcard(PROTOCOL_KEYS.MIXNET_DELAY_POOL_REDIS),
      client.zcard(PROTOCOL_KEYS.MIXNET_PROCESSING_POOL_REDIS),
      client.get(PROTOCOL_KEYS.MIXNET_PENDING_BYTES_REDIS),
      client.zcard(PROTOCOL_KEYS.MIXNET_SPOOL_INDEX_REDIS),
      client.get(PROTOCOL_KEYS.MIXNET_SPOOL_BYTES_REDIS),
      client.zrange(PROTOCOL_KEYS.MIXNET_SPOOL_INDEX_REDIS, 0, 0, 'WITHSCORES')
    ]);
    const oldestScore = Array.isArray(oldestSpool) && oldestSpool.length >= 2
      ? Number(oldestSpool[1]) / 1000
      : 0;
    return {
      pendingMessages: Number(delayCount || 0) + Number(processingCount || 0),
      pendingBytes: Math.max(0, Number(pendingBytes || 0)),
      spoolMessages: Number(spoolCount || 0),
      spoolBytes: Math.max(0, Number(spoolBytes || 0)),
      oldestSpoolAgeMs: oldestScore > 0 ? Math.max(0, Date.now() - oldestScore) : 0,
      localDeliveryQueueMessages: globalMixDeliveryQueue.length,
      localDeliveryQueueBytes: globalMixDeliveryQueuedBytes,
      publicationQueueMessages: globalMixPublicationQueue.length,
      publicationQueueBytes: globalMixPublicationQueuedBytes
    };
  }));
}

async function tryLocalBroadcastDelivery(sealedEnvelope, generation) {
  if (generation !== globalMixDeliveryGeneration) return 0;
  const socketIds = Array.from(localSocketRegistry.keys());
  if (socketIds.length === 0) {
    return 0;
  }
  for (let index = socketIds.length - 1; index > 0; index -= 1) {
    const swap = crypto.randomInt(index + 1);
    [socketIds[index], socketIds[swap]] = [socketIds[swap], socketIds[index]];
  }

  let delivered = 0;
  const drainDeadline = Date.now() + LOCAL_BROADCAST_DRAIN_BUDGET_MS;
  for (let offset = 0; offset < socketIds.length; offset += LOCAL_BROADCAST_CONCURRENCY) {
    if (generation !== globalMixDeliveryGeneration) return delivered;
    const remainingMs = drainDeadline - Date.now();
    if (remainingMs <= 0) break;
    const batch = socketIds.slice(offset, offset + LOCAL_BROADCAST_CONCURRENCY);
    await Promise.all(batch.map(async (socketId) => {
      if (generation !== globalMixDeliveryGeneration) return;
      const ws = localSocketRegistry.get(socketId);
      if (!ws || ws.readyState !== 1) {
        localSocketRegistry.delete(socketId);
        return;
      }
      const now = Date.now();
      if (Number(ws._blindBroadcastSuspendedUntil || 0) > now) {
        return;
      }
      if (ws._connectionAbortSignal?.aborted || !ws._pqSessionId || !isBroadcastDeliveryReady(ws)) {
        return;
      }
      const pqSession = ws._pqSessionData;
      if (
        pqSession?.sessionId !== ws._pqSessionId ||
        Number(pqSession.sendQueueCount || 0) > 0 ||
        hasPendingBroadcast(ws)
      ) {
        return;
      }
      if (LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS > 0) {
        const lastSentAt = Number(ws._lastBlindBroadcastSentAt || 0);
        if (lastSentAt > 0 && now - lastSentAt < LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS) {
          return;
        }
      }
      if (Number(ws.bufferedAmount || 0) > LOCAL_BROADCAST_BUFFERED_MAX_BYTES) {
        if (!Number.isFinite(ws._blindBroadcastBackpressureSince) || ws._blindBroadcastBackpressureSince <= 0) {
          ws._blindBroadcastBackpressureSince = now;
        }
        if (now - ws._blindBroadcastBackpressureSince > LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS) {
          ws._blindBroadcastSuspendedUntil = now + LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS;
          ws._blindBroadcastBackpressureSince = 0;
          console.warn('[BLIND-ROUTER] Local privacy broadcast suspended, sustained backpressure', {
            bufferedClass: 'over-limit'
          });
          return;
        }
        if (shouldLogLocalBroadcastBackpressure(ws)) {
          console.warn('[BLIND-ROUTER] Local privacy broadcast skipped, socket backpressure', {
            bufferedClass: 'over-limit'
          });
        }
        return;
      }
      ws._blindBroadcastBackpressureSince = 0;
      try {
        const waitBudgetMs = Math.min(
          LOCAL_BROADCAST_WAIT_BUDGET_MS,
          Math.max(1, drainDeadline - Date.now())
        );
        const delivery = sendFlowControlledBroadcast(ws, () => sendToSocket(ws, sealedEnvelope)).then((didDeliver) => {
          if (didDeliver && generation === globalMixDeliveryGeneration && ws.readyState === 1) {
            ws._lastBlindBroadcastSentAt = Date.now();
          }
          return didDeliver;
        });
        const didDeliver = await awaitMessageHandlerWithDeadline(delivery, {
          signal: ws._connectionAbortSignal,
          timeoutMs: waitBudgetMs
        });
        if (!didDeliver) return;
        delivered += 1;
      } catch { }
    }));
  }
  return delivered;
}

function isBroadcastDeliveryReady(ws) {
  return ws?._unlinkedSession === true;
}

function shouldLogLocalBroadcastBackpressure(ws) {
  const now = Date.now();
  const last = Number(ws?._lastBlindBroadcastBackpressureLogAt || 0);
  if (now - last < LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS) {
    return false;
  }
  if (ws) {
    ws._lastBlindBroadcastBackpressureLogAt = now;
  }
  return true;
}

async function publishGlobalMixDelivery(publicationWire) {
  await withRedisClient(async (client) => {
    await client.publish(PROTOCOL_KEYS.GLOBAL_MIX_CHANNEL, publicationWire);
  });
}

function enqueueGlobalMixPublication(publicationWire) {
  if (!blindDeliverySubscriptionDesired) return false;
  const wireBytes = Buffer.byteLength(publicationWire, 'utf8');
  if (
    wireBytes <= 0 ||
    wireBytes > GLOBAL_MIX_PUBLICATION_MAX_BYTES ||
    globalMixPublicationQueue.length >= GLOBAL_MIX_PUBLICATION_QUEUE_MAX_MESSAGES ||
    globalMixPublicationQueuedBytes + wireBytes > GLOBAL_MIX_PUBLICATION_QUEUE_MAX_BYTES
  ) {
    return false;
  }
  globalMixPublicationQueue.push({
    wire: publicationWire,
    wireBytes,
    createdAt: Date.now(),
    generation: globalMixPublicationGeneration
  });
  globalMixPublicationQueuedBytes += wireBytes;
  startGlobalMixPublicationDrain();
  return true;
}

function startGlobalMixPublicationDrain() {
  if (globalMixPublicationDrainPromise) return;
  let drainPromise;
  const finish = () => {
    if (globalMixPublicationDrainPromise === drainPromise) {
      globalMixPublicationDrainPromise = null;
    }
    if (globalMixPublicationQueue.length > 0) {
      startGlobalMixPublicationDrain();
    }
  };
  drainPromise = (async () => {
    while (globalMixPublicationQueue.length > 0) {
      const queued = globalMixPublicationQueue.shift();
      if (!queued) continue;
      globalMixPublicationQueuedBytes = Math.max(0, globalMixPublicationQueuedBytes - queued.wireBytes);
      if (
        queued.generation !== globalMixPublicationGeneration ||
        Date.now() - queued.createdAt > GLOBAL_MIX_PUBLICATION_QUEUE_MAX_AGE_MS
      ) {
        continue;
      }
      try {
        await publishGlobalMixDelivery(queued.wire);
      } catch {
      }
    }
  })();
  globalMixPublicationDrainPromise = drainPromise;
  void drainPromise.then(finish, finish);
}

// captures tag index and its PIR records from one redis scan
export async function readGlobalMixPirSnapshot(now = Date.now()) {
  return withRedisClient(async (client) => {
    await trimExpiredGlobalMixSpool(client, now);
    const oldestReadable = (
      now - (GLOBAL_MIX_SPOOL_TTL_SECONDS * 1000) + GLOBAL_MIX_SPOOL_READ_EXPIRY_GUARD_MS
    ) * 1000;
    const members = await client.zrangebyscore(
      PROTOCOL_KEYS.MIXNET_SPOOL_INDEX_REDIS,
      `(${oldestReadable}`,
      '+inf'
    );
    const rows = [];
    for (const member of members || []) {
      const row = parseGlobalSpoolIndexMember(member);
      if (!row) throw new Error('invalid_global_mix_spool_index');
      if (!isCurrentGlobalSpoolRow(row)) continue;
      rows.push(row);
    }
    if (rows.length === 0) {
      return { ids: [], tags: [], probes: [], records: [] };
    }

    const raw = await client.mget(
      ...rows.map((row) => `${PROTOCOL_KEYS.MIXNET_SPOOL_ENTRY_REDIS_PREFIX}${row.id}`)
    );
    if (!Array.isArray(raw) || raw.length !== rows.length) {
      throw new Error('invalid_global_mix_spool_read');
    }

    const records = [];
    for (let index = 0; index < raw.length; index += 1) {
      if (typeof raw[index] !== 'string') {
        throw new Error('global_mix_spool_entry_expired_during_pir_build');
      }
      const stored = parseGlobalSpoolStoredEntry(raw[index], rows[index]);
      if (!stored) throw new Error('invalid_global_mix_spool_entry');
      const envelope = stored.envelope;
      records.push(Buffer.concat([
        Buffer.from(envelope.ephemeralKey, 'base64'),
        Buffer.from(envelope.nonce, 'base64'),
        Buffer.from(envelope.ciphertext, 'base64')
      ]));
    }
    return {
      ids: rows.map((row) => row.id),
      tags: rows.map((row) => row.tag),
      probes: rows.map((row) => row.probe),
      records
    };
  });
}

// Send envelope to socket
async function sendToSocket(ws, sealedEnvelope) {
  const pqSessionId = ws._pqSessionId;

  if (pqSessionId) {
    const { sendPQEncryptedResponse } = await import('../messaging/pq-envelope-handler.js');
    const session = ws._pqSessionData;

    if (session?.sessionId === pqSessionId) {
      const messageWrapper = {
        type: SignalType.SEALED_ENVELOPE,
        envelope: sealedEnvelope
      };
      return sendPQEncryptedResponse(ws, session, messageWrapper);
    }
  }

  throw new Error('No PQ session available for socket delivery');
}

function startGlobalMixDeliveryDrain() {
  if (globalMixDeliveryDrainPromise) return;
  let drainPromise;
  drainPromise = (async () => {
    while (globalMixDeliveryQueue.length > 0) {
      const queued = globalMixDeliveryQueue.shift();
      if (!queued) continue;
      globalMixDeliveryQueuedBytes = Math.max(0, globalMixDeliveryQueuedBytes - queued.wireBytes);
      if (queued.generation !== globalMixDeliveryGeneration) continue;
      await tryLocalBroadcastDelivery(queued.envelope, queued.generation);
    }
  })().catch(() => {
    console.warn('[BLIND-ROUTER] Cross-instance delivery drain failed');
  }).finally(() => {
    if (globalMixDeliveryDrainPromise === drainPromise) {
      globalMixDeliveryDrainPromise = null;
    }
    if (globalMixDeliveryQueue.length > 0) startGlobalMixDeliveryDrain();
  });
  globalMixDeliveryDrainPromise = drainPromise;
}

function enqueueGlobalMixDelivery(message, wireBytes) {
  if (!blindDeliverySubscriptionDesired) return false;
  const publication = validateGlobalMixPublication(message);
  if (!publication) return false;
  const retainedBytes = Number.isSafeInteger(wireBytes) && wireBytes > 0
    ? wireBytes
    : Buffer.byteLength(JSON.stringify(message), 'utf8');
  if (
    globalMixDeliveryQueue.length >= GLOBAL_MIX_DELIVERY_QUEUE_MAX_MESSAGES ||
    globalMixDeliveryQueuedBytes + retainedBytes > GLOBAL_MIX_DELIVERY_QUEUE_MAX_BYTES
  ) {
    const now = Date.now();
    if (now - globalMixDeliveryPressureLoggedAt >= LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS) {
      globalMixDeliveryPressureLoggedAt = now;
      console.warn('[BLIND-ROUTER] Cross-instance live delivery dropped under bounded pressure');
    }
    return false;
  }
  if (!reservePublicationId(publication.publicationId)) return false;
  globalMixDeliveryQueue.push({
    envelope: publication.envelope,
    wireBytes: retainedBytes,
    generation: globalMixDeliveryGeneration
  });
  globalMixDeliveryQueuedBytes += retainedBytes;
  startGlobalMixDeliveryDrain();
  return true;
}

// Subscribe to global mix delivery channel for this server
function scheduleBlindDeliveryRetry() {
  if (
    !blindDeliverySubscriptionDesired ||
    blindDeliveryRetryTimer ||
    blindDeliverySubscriber ||
    blindDeliverySubscriberPromise
  ) return;

  const upperBound = Math.min(
    BLIND_DELIVERY_RETRY_MAX_MS,
    BLIND_DELIVERY_RETRY_MIN_MS * (2 ** Math.min(blindDeliveryRetryAttempts, 6))
  );
  const delayMs = randomDelay(BLIND_DELIVERY_RETRY_MIN_MS, upperBound);
  blindDeliveryRetryAttempts += 1;
  blindDeliveryRetryTimer = setTimeout(() => {
    blindDeliveryRetryTimer = null;
    subscribeToBlindDelivery().catch(() => { });
  }, delayMs);
  blindDeliveryRetryTimer.unref?.();
}

export async function subscribeToBlindDelivery() {
  blindDeliverySubscriptionDesired = true;
  if (blindDeliverySubscriber) return;
  if (blindDeliverySubscriberPromise) {
    return blindDeliverySubscriberPromise;
  }

  const generation = blindDeliverySubscriptionGeneration;
  let subscriber = null;
  const initialization = (async () => {
    startMixnetRelay();
    subscriber = await createSubscriber();
    if (!blindDeliverySubscriptionDesired || generation !== blindDeliverySubscriptionGeneration) {
      throw new Error('Blind delivery subscription cancelled');
    }

    subscriber.on('message', (channel, message) => {
      const wireBytes = typeof message === 'string'
        ? Buffer.byteLength(message, 'utf8')
        : 0;
      if (
        channel !== PROTOCOL_KEYS.GLOBAL_MIX_CHANNEL ||
        typeof message !== 'string' ||
        wireBytes <= 0 ||
        wireBytes > GLOBAL_MIX_PUBLICATION_MAX_BYTES ||
        globalMixDeliveryQueue.length >= GLOBAL_MIX_DELIVERY_QUEUE_MAX_MESSAGES ||
        globalMixDeliveryQueuedBytes + wireBytes > GLOBAL_MIX_DELIVERY_QUEUE_MAX_BYTES ||
        !allowGlobalMixPublicationVerification()
      ) {
        return;
      }
      try {
        const parsed = JSON.parse(message);
        enqueueGlobalMixDelivery(parsed, wireBytes);
      } catch {
        const now = Date.now();
        if (now - globalMixDeliveryPressureLoggedAt >= LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS) {
          globalMixDeliveryPressureLoggedAt = now;
          console.warn('[BLIND-ROUTER] Invalid global mix delivery message dropped');
        }
      }
    });
    subscriber.once('end', () => {
      if (blindDeliverySubscriber !== subscriber) return;
      blindDeliverySubscriber = null;
      scheduleBlindDeliveryRetry();
    });
    await subscriber.subscribe(PROTOCOL_KEYS.GLOBAL_MIX_CHANNEL);
    if (!blindDeliverySubscriptionDesired || generation !== blindDeliverySubscriptionGeneration) {
      throw new Error('Blind delivery subscription cancelled');
    }

    blindDeliverySubscriber = subscriber;
    blindDeliveryRetryAttempts = 0;
    console.log('[BLIND-ROUTER] Global delivery subscription ready');
  })();
  blindDeliverySubscriberPromise = initialization;

  try {
    await initialization;
  } catch (error) {
    if (subscriber && blindDeliverySubscriber !== subscriber) {
      await closeSubscriber(subscriber);
    }
    if (blindDeliverySubscriberPromise === initialization) {
      blindDeliverySubscriberPromise = null;
    }
    if (blindDeliverySubscriptionDesired && generation === blindDeliverySubscriptionGeneration) {
      console.error('[BLIND-ROUTER] Global delivery subscription unavailable');
      scheduleBlindDeliveryRetry();
    }
    throw error;
  }

  if (blindDeliverySubscriberPromise === initialization) {
    blindDeliverySubscriberPromise = null;
  }
}

export async function stopBlindDeliverySubscription() {
  blindDeliverySubscriptionDesired = false;
  blindDeliverySubscriptionGeneration += 1;
  globalMixDeliveryGeneration += 1;
  globalMixPublicationGeneration += 1;
  globalMixDeliveryQueue.length = 0;
  globalMixDeliveryQueuedBytes = 0;
  globalMixPublicationQueue.length = 0;
  globalMixPublicationQueuedBytes = 0;
  if (blindDeliveryRetryTimer) {
    clearTimeout(blindDeliveryRetryTimer);
    blindDeliveryRetryTimer = null;
  }

  const pending = blindDeliverySubscriberPromise;
  if (pending) await pending.catch(() => { });
  blindDeliverySubscriberPromise = null;

  const subscriber = blindDeliverySubscriber;
  blindDeliverySubscriber = null;
  if (subscriber) await closeSubscriber(subscriber);
  blindDeliveryRetryAttempts = 0;
  await stopMixnetRelay();
  await globalMixPublicationDrainPromise?.catch(() => { });
  await globalMixDeliveryDrainPromise?.catch(() => { });
}

export const BlindRouter = {
  initializeGlobalMixAuthentication,
  destroyGlobalMixAuthentication,
  registerLocalSocket,
  unregisterLocalSocket,
  routeToGlobalMix,
  enqueueMixnetRelay,
  enqueueMixnetCoverWrite,
  getTelemetrySnapshot: getBlindRouterTelemetry,
  pruneBlindRouterRuntimeState,
  subscribeToBlindDelivery,
  stopBlindDeliverySubscription
};
