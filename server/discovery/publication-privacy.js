/**
 * Delayed opaque discovery publication relay
 */

import crypto from 'crypto';
import { DiscoveryDB } from '../database/database.js';
import { withRedisClient } from '../session/redis-client.js';
import {
  DISCOVERY_EPOCH_EXPIRED,
  DISCOVERY_PUBLICATION_UNAVAILABLE
} from '../config/error-codes.js';
import { envInt } from '../utils/env.js';
import { DISCOVERY_EPOCH_ID_RE, HEX_64_RE } from '../utils/patterns.js';
import { randomDelay } from '../utils/random.js';
import { exactRedisScoreArgument } from '../utils/redis-args.js';
import {
  moveRedisSortedSetLease,
  REDIS_SORTED_SET_LEASE_RELEASE_GUARD
} from '../utils/redis-lease.js';

import {
  getDiscoveryBucketIndex,
  invalidateDiscoveryBucketIndex
} from './bucket-index.js';
import {
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_FIXED_BUCKET_COUNT,
  DISCOVERY_PUBLICATION_BUCKET_COUNT,
  DISCOVERY_STORED_PUBLICATION_CAP,
  isCanonicalDiscoveryBlob,
  isCanonicalDiscoveryBucketIds
} from './bucket-layout.js';
import { currentDiscoveryEpochId } from './epoch.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

const DISCOVERY_PUBLICATION_POOL_KEY = PROTOCOL_KEYS.DISCOVERY_PUBLICATION_DELAY_REDIS;
const DISCOVERY_PUBLICATION_PROCESSING_KEY = PROTOCOL_KEYS.DISCOVERY_PUBLICATION_PROCESSING_REDIS;

const PUBLICATION_DELAY_MIN_MS = envInt('DISCOVERY_PUBLICATION_DELAY_MIN_MS', 2_000, 1000, 30 * 60 * 1000);
const PUBLICATION_DELAY_MAX_MS = envInt('DISCOVERY_PUBLICATION_DELAY_MAX_MS', 10_000, PUBLICATION_DELAY_MIN_MS, 60 * 60 * 1000);
const PUBLICATION_FLUSH_MIN_MS = envInt('DISCOVERY_PUBLICATION_FLUSH_MIN_MS', 1000, 500, 10 * 60 * 1000);
const PUBLICATION_FLUSH_MAX_MS = envInt('DISCOVERY_PUBLICATION_FLUSH_MAX_MS', 4000, PUBLICATION_FLUSH_MIN_MS, 15 * 60 * 1000);
const PUBLICATION_BATCH_MAX = envInt('DISCOVERY_PUBLICATION_BATCH_MAX', 32, 1, 512);
const PUBLICATION_FLUSH_CONCURRENCY = envInt('DISCOVERY_PUBLICATION_FLUSH_CONCURRENCY', 8, 1, 32);
const PUBLICATION_POOL_TTL_SECONDS = envInt('DISCOVERY_PUBLICATION_POOL_TTL_SECONDS', 7 * 24 * 60 * 60, 60, 30 * 24 * 60 * 60);
const PUBLICATION_PROCESSING_TIMEOUT_MS = envInt('DISCOVERY_PUBLICATION_PROCESSING_TIMEOUT_MS', 120_000, 60_000, 10 * 60 * 1000);
const COVER_WRITES_MIN = envInt('DISCOVERY_PUBLICATION_COVER_WRITES_MIN', 1, 0, 64);
const COVER_WRITES_MAX = envInt('DISCOVERY_PUBLICATION_COVER_WRITES_MAX', 3, COVER_WRITES_MIN, 128);
const IDLE_COVER_WRITES_MIN = envInt('DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MIN', 0, 0, 64);
const IDLE_COVER_WRITES_MAX = envInt('DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MAX', 0, IDLE_COVER_WRITES_MIN, 128);
const MAX_PUBLICATION_POOL_ENTRIES = envInt(
  'DISCOVERY_PUBLICATION_MAX_POOL_ENTRIES',
  512,
  100,
  8_192
);

const COVER_LEASE_MS = 24 * 60 * 60 * 1000;
const MAX_PUBLICATION_LEASE_MS = 90 * 24 * 60 * 60 * 1000;
const PUBLICATION_TIMESTAMP_QUANTUM_MS = envInt(
  'DISCOVERY_PUBLICATION_TIMESTAMP_QUANTUM_MS',
  15 * 60 * 1000,
  60 * 1000,
  6 * 60 * 60 * 1000
);
let relayStarted = false;
let relayTimer = null;
let flushInFlight = false;
let flushCompletion = null;
let indexPrewarmInFlight = null;

function randomOpaqueBlob() {
  return crypto.randomBytes((DISCOVERY_BLOB_BASE64_CHARS / 4) * 3).toString('base64');
}

function randomBucketIds() {
  const ids = new Set();
  while (ids.size < DISCOVERY_PUBLICATION_BUCKET_COUNT) {
    ids.add(crypto.randomInt(DISCOVERY_FIXED_BUCKET_COUNT));
  }
  return Array.from(ids);
}

function normalizePublication(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (Object.keys(value).sort().join(',') !== 'bucketIds,epochId,publishId') return null;
  const epochId = typeof value.epochId === 'string' ? value.epochId.trim() : '';
  const publishId = typeof value.publishId === 'string' ? value.publishId.trim().toLowerCase() : '';
  if (!DISCOVERY_EPOCH_ID_RE.test(epochId) || !HEX_64_RE.test(publishId)) return null;
  if (!isCanonicalDiscoveryBucketIds(value.bucketIds)) return null;
  return { epochId, publishId, bucketIds: value.bucketIds.slice() };
}

function coarseExpiresAt(now, leaseMs) {
  return Math.ceil((now + leaseMs) / PUBLICATION_TIMESTAMP_QUANTUM_MS) * PUBLICATION_TIMESTAMP_QUANTUM_MS;
}

function makeCoverPublication(now = Date.now()) {
  return {
    id: crypto.randomBytes(16).toString('base64url'),
    cover: true,
    publication: {
      epochId: currentDiscoveryEpochId(),
      publishId: crypto.randomBytes(32).toString('hex'),
      bucketIds: randomBucketIds()
    },
    encryptedBlob: randomOpaqueBlob(),
    leaseMs: COVER_LEASE_MS,
    releaseAt: now,
    expiresAt: coarseExpiresAt(now, COVER_LEASE_MS)
  };
}

function normalizePublicationEntry(value, { queued = false, now = Date.now() } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (
    Object.keys(value).sort().join(',') !==
    'cover,encryptedBlob,expiresAt,id,leaseMs,publication,releaseAt'
  ) return null;

  const publication = normalizePublication(value.publication);
  if (
    !/^[A-Za-z0-9_-]{22}$/.test(value.id) ||
    typeof value.cover !== 'boolean' ||
    (queued && value.cover !== false) ||
    !publication ||
    !isCanonicalDiscoveryBlob(value.encryptedBlob) ||
    !Number.isSafeInteger(value.leaseMs) ||
    value.leaseMs < 60_000 ||
    value.leaseMs > MAX_PUBLICATION_LEASE_MS ||
    !Number.isSafeInteger(value.releaseAt) ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.releaseAt < 0 ||
    value.expiresAt <= value.releaseAt ||
    value.expiresAt % PUBLICATION_TIMESTAMP_QUANTUM_MS !== 0 ||
    value.expiresAt - value.releaseAt > value.leaseMs + PUBLICATION_TIMESTAMP_QUANTUM_MS ||
    value.expiresAt <= now
  ) return null;

  return {
    id: value.id,
    cover: value.cover,
    publication,
    encryptedBlob: value.encryptedBlob,
    leaseMs: value.leaseMs,
    releaseAt: value.releaseAt,
    expiresAt: value.expiresAt
  };
}

function parsePublicationEntry(raw, options) {
  if (typeof raw !== 'string') return null;
  try {
    return normalizePublicationEntry(JSON.parse(raw), options);
  } catch {
    return null;
  }
}

function scheduleDiscoveryIndexRefresh() {
  if (!relayStarted) return;
  invalidateDiscoveryBucketIndex();
  if (!indexPrewarmInFlight) {
    indexPrewarmInFlight = getDiscoveryBucketIndex()
      .then((result) => {
        if (!result.success) {
          console.warn('[DISCOVERY-PUBLISH] Bucket index prewarm unavailable', { error: result.error });
        }
      })
      .catch((error) => {
        console.warn('[DISCOVERY-PUBLISH] Bucket index prewarm failed', {
          error: error?.message || String(error)
        });
      })
      .finally(() => {
        indexPrewarmInFlight = null;
      });
  }
}

function scheduleFlush(delayMs = null) {
  if (!relayStarted || relayTimer) return;
  const delay = Number.isFinite(delayMs)
    ? Math.max(0, Math.trunc(delayMs))
    : randomDelay(PUBLICATION_FLUSH_MIN_MS, PUBLICATION_FLUSH_MAX_MS);
  relayTimer = setTimeout(async () => {
    relayTimer = null;
    try {
      await flushDiscoveryPublicationRelay();
    } finally {
      if (relayStarted) scheduleFlush();
    }
  }, delay);
  relayTimer.unref?.();
}

export function startDiscoveryPublicationRelay() {
  if (relayStarted) return;
  relayStarted = true;
  scheduleFlush(randomDelay(PUBLICATION_FLUSH_MIN_MS, PUBLICATION_FLUSH_MAX_MS));
  console.log('[DISCOVERY-PUBLISH] Delayed publication relay started', {
    delayMinMs: PUBLICATION_DELAY_MIN_MS,
    delayMaxMs: PUBLICATION_DELAY_MAX_MS,
    coverMin: COVER_WRITES_MIN,
    coverMax: COVER_WRITES_MAX
  });
}

export async function stopDiscoveryPublicationRelay() {
  relayStarted = false;
  if (relayTimer) clearTimeout(relayTimer);
  relayTimer = null;
  const pending = [flushCompletion, indexPrewarmInFlight].filter(Boolean);
  if (pending.length > 0) await Promise.allSettled(pending);
}

const ENQUEUE_PUBLICATION_SCRIPT = `
  if (redis.call('ZCARD', KEYS[1]) + redis.call('ZCARD', KEYS[2])) >= tonumber(ARGV[1]) then
    return 0
  end
  if redis.call('ZADD', KEYS[1], 'NX', ARGV[2], ARGV[3]) ~= 1 then
    return 0
  end
  redis.call('EXPIRE', KEYS[1], ARGV[4])
  redis.call('EXPIRE', KEYS[2], ARGV[4])
  return 1
`;

async function movePublication(client, source, destination, raw, score, expectedSourceScore) {
  return moveRedisSortedSetLease(client, {
    sourceKey: source,
    destinationKey: destination,
    member: raw,
    destinationScore: score,
    ttlSeconds: PUBLICATION_POOL_TTL_SECONDS,
    expectedSourceScore,
    scoreContext: 'publication lease'
  });
}

const REMOVE_PUBLICATION_SCRIPT = `
${REDIS_SORTED_SET_LEASE_RELEASE_GUARD}
  redis.call('EXPIRE', KEYS[1], ARGV[2])
  return 1
`;

async function removePublication(client, pool, raw, expectedSourceScore) {
  const sourceScore = exactRedisScoreArgument(expectedSourceScore, 'publication lease');
  return Number(await client.eval(
    REMOVE_PUBLICATION_SCRIPT,
    1,
    pool,
    raw,
    PUBLICATION_POOL_TTL_SECONDS,
    sourceScore
  )) === 1;
}

export async function enqueueDiscoveryPublication({ publication, encryptedBlob, leaseMs }) {
  const normalized = normalizePublication(publication);
  if (!normalized || !isCanonicalDiscoveryBlob(encryptedBlob)) {
    return { queued: false, error: 'invalid_discovery_publication' };
  }
  if (normalized.epochId !== currentDiscoveryEpochId()) {
    return { queued: false, error: DISCOVERY_EPOCH_EXPIRED };
  }
  if (!Number.isSafeInteger(leaseMs) || leaseMs < 60_000 || leaseMs > MAX_PUBLICATION_LEASE_MS) {
    return { queued: false, error: 'invalid_discovery_publication_expiry' };
  }

  const acceptedAt = Date.now();
  const releaseAt = acceptedAt + randomDelay(PUBLICATION_DELAY_MIN_MS, PUBLICATION_DELAY_MAX_MS);
  const entry = {
    id: crypto.randomBytes(16).toString('base64url'),
    cover: false,
    publication: normalized,
    encryptedBlob,
    leaseMs,
    releaseAt,
    expiresAt: coarseExpiresAt(acceptedAt, leaseMs)
  };
  if (!normalizePublicationEntry(entry, { queued: true, now: acceptedAt })) {
    return { queued: false, error: 'invalid_discovery_publication_expiry' };
  }

  try {
    const enqueued = await withRedisClient((client) => client.eval(
      ENQUEUE_PUBLICATION_SCRIPT,
      2,
      DISCOVERY_PUBLICATION_POOL_KEY,
      DISCOVERY_PUBLICATION_PROCESSING_KEY,
      MAX_PUBLICATION_POOL_ENTRIES,
      entry.releaseAt,
      JSON.stringify(entry),
      PUBLICATION_POOL_TTL_SECONDS
    ));
    if (Number(enqueued) !== 1) {
      return { queued: false, error: 'discovery_publication_pool_full' };
    }
  } catch {
    return { queued: false, error: DISCOVERY_PUBLICATION_UNAVAILABLE };
  }

  startDiscoveryPublicationRelay();
  scheduleFlush();
  return { queued: true };
}

async function storePublication(entry, storedAt) {
  const normalized = normalizePublicationEntry(entry, { now: storedAt });
  if (!normalized) return 0;

  const stored = await DiscoveryDB.storePublication(
    normalized.publication.publishId,
    normalized.publication.bucketIds,
    normalized.encryptedBlob,
    normalized.expiresAt
  );
  
  return stored;
}

async function recoverStalePublicationClaims(client) {
  const now = Date.now();
  const stale = await client.zrangebyscore(
    DISCOVERY_PUBLICATION_PROCESSING_KEY,
    '-inf',
    now,
    'LIMIT',
    0,
    PUBLICATION_BATCH_MAX
  );
  for (const raw of stale || []) {
    const currentScore = await client.zscore(DISCOVERY_PUBLICATION_PROCESSING_KEY, raw);
    if (currentScore === null || Number(currentScore) > now) continue;
    if (!parsePublicationEntry(raw, { queued: true })) {
      await removePublication(
        client,
        DISCOVERY_PUBLICATION_PROCESSING_KEY,
        raw,
        currentScore
      );
      continue;
    }
    await movePublication(
      client,
      DISCOVERY_PUBLICATION_PROCESSING_KEY,
      DISCOVERY_PUBLICATION_POOL_KEY,
      raw,
      Date.now() + randomDelay(PUBLICATION_FLUSH_MIN_MS, PUBLICATION_FLUSH_MAX_MS),
      currentScore
    );
  }
}

async function finalizePublicationClaim(raw, claimUntil, succeeded) {
  if (typeof raw !== 'string') return;
  await withRedisClient(async (client) => {
    if (succeeded) {
      await removePublication(
        client,
        DISCOVERY_PUBLICATION_PROCESSING_KEY,
        raw,
        claimUntil
      );
      return;
    }
    if (!parsePublicationEntry(raw, { queued: true })) {
      await removePublication(
        client,
        DISCOVERY_PUBLICATION_PROCESSING_KEY,
        raw,
        claimUntil
      );
      return;
    }
    await movePublication(
      client,
      DISCOVERY_PUBLICATION_PROCESSING_KEY,
      DISCOVERY_PUBLICATION_POOL_KEY,
      raw,
      Date.now() + randomDelay(PUBLICATION_FLUSH_MIN_MS, PUBLICATION_FLUSH_MAX_MS),
      claimUntil
    );
  });
}

function shufflePublications(entries) {
  const shuffled = entries.slice();
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swap = crypto.randomInt(index + 1);
    [shuffled[index], shuffled[swap]] = [shuffled[swap], shuffled[index]];
  }
  return shuffled;
}

async function flushDiscoveryPublicationRelay() {
  if (flushInFlight) return { flushed: 0, stored: 0 };
  flushInFlight = true;
  let completeFlush;
  const completion = new Promise((resolve) => { completeFlush = resolve; });
  flushCompletion = completion;
  const claimed = [];

  try {
    await withRedisClient(async (client) => {
      await recoverStalePublicationClaims(client);
      const rawItems = await client.zrangebyscore(
        DISCOVERY_PUBLICATION_POOL_KEY,
        '-inf',
        Date.now(),
        'LIMIT',
        0,
        Math.min(PUBLICATION_BATCH_MAX, PUBLICATION_FLUSH_CONCURRENCY)
      );

      for (const raw of rawItems || []) {
        const currentScore = await client.zscore(DISCOVERY_PUBLICATION_POOL_KEY, raw);
        if (currentScore === null || Number(currentScore) > Date.now()) continue;
        const entry = parsePublicationEntry(raw, { queued: true });
        if (!entry) {
          await removePublication(
            client,
            DISCOVERY_PUBLICATION_POOL_KEY,
            raw,
            currentScore
          );
          continue;
        }
        const claimUntil = Date.now() + PUBLICATION_PROCESSING_TIMEOUT_MS;
        const moved = await movePublication(
          client,
          DISCOVERY_PUBLICATION_POOL_KEY,
          DISCOVERY_PUBLICATION_PROCESSING_KEY,
          raw,
          claimUntil,
          currentScore
        );
        if (moved) claimed.push({ entry, raw, claimUntil });
      }
    });

    const coverMin = claimed.length > 0 ? COVER_WRITES_MIN : IDLE_COVER_WRITES_MIN;
    const coverMax = claimed.length > 0 ? COVER_WRITES_MAX : IDLE_COVER_WRITES_MAX;
    const coverCount = coverMax > 0 ? crypto.randomInt(coverMin, coverMax + 1) : 0;
    const coverCreatedAt = Date.now();
    const covers = Array.from(
      { length: coverCount },
      () => ({ entry: makeCoverPublication(coverCreatedAt), raw: null })
    );
    const batch = shufflePublications([...claimed, ...covers]);
    const storedAt = Date.now();
    let stored = 0;

    for (let offset = 0; offset < batch.length; offset += PUBLICATION_FLUSH_CONCURRENCY) {
      const counts = await Promise.all(
        batch
          .slice(offset, offset + PUBLICATION_FLUSH_CONCURRENCY)
          .map((item) => processPublicationClaim(item, storedAt))
      );
      stored += counts.reduce((sum, count) => sum + count, 0);
    }

    if (stored > 0) {
      await DiscoveryDB.enforceCap(DISCOVERY_STORED_PUBLICATION_CAP);
      scheduleDiscoveryIndexRefresh();
    }
    return { flushed: batch.length, stored };
  } catch (error) {
    console.error('[DISCOVERY-PUBLISH] Delayed publication flush failed', {
      error: error?.message || String(error)
    });
    return { flushed: 0, stored: 0, error: 'discovery_publication_flush_failed' };
  } finally {
    flushInFlight = false;
    if (flushCompletion === completion) flushCompletion = null;
    completeFlush();
  }
}

async function processPublicationClaim(item, storedAt) {
  const count = await storePublication(item.entry, storedAt);
  if (item.raw) {
    try {
      await finalizePublicationClaim(item.raw, item.claimUntil, count > 0);
    } catch {
    }
  }
  return count;
}
