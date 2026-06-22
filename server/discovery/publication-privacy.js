/**
 * Discovery publication relay.
 *
 * Real discovery writes are queued into a delayed batch with cover writes so a
 * publish request is not the same event as the database visible refresh
 */

import crypto from 'crypto';
import { DiscoveryDB } from '../database/database.js';
import { withRedisClient } from '../session/redis-client.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { getPirDatabase, invalidatePirDatabase } from '../pir/pir-databases.js';
import { DISCOVERY_PIR_DATABASE_KIND, DISCOVERY_FIXED_BUCKET_COUNT, getPirLayoutConfig } from '../pir/page-layout.js';

function currentDiscoveryEpochId() {
  const epochMs = Math.max(1000, Number(getPirLayoutConfig(DISCOVERY_PIR_DATABASE_KIND)?.epochMs) || 6 * 60 * 60 * 1000);
  return String(Math.floor(Date.now() / epochMs) * epochMs);
}

// Validate batch of client supplied K-anon bucket entries. Each is { epochId, bucketId, publishId }
function normalizeBucketBatch(batch) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(batch) ? batch : []) {
    if (!raw || typeof raw !== 'object') continue;
    const epochId = typeof raw.epochId === 'string' ? raw.epochId.trim() : '';
    const bucketId = Number.isInteger(raw.bucketId) ? raw.bucketId : Number.parseInt(raw.bucketId, 10);
    const publishId = typeof raw.publishId === 'string' ? raw.publishId.trim().toLowerCase() : '';
    if (!epochId || epochId.length > 64) continue;
    if (!Number.isInteger(bucketId) || bucketId < 0 || bucketId >= DISCOVERY_FIXED_BUCKET_COUNT) continue;
    if (!/^[a-f0-9]{16,128}$/.test(publishId)) continue;
    const key = `${epochId}:${publishId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ epochId, bucketId, publishId });
    if (out.length >= 8) break;
  }
  return out;
}

const DISCOVERY_PUBLICATION_POOL_KEY = 'discovery:publication:delay-pool:v1';
const PUBLICATION_DELAY_MIN_MS = envInt('DISCOVERY_PUBLICATION_DELAY_MIN_MS', 2_000, 1000, 30 * 60 * 1000);
const PUBLICATION_DELAY_MAX_MS = envInt('DISCOVERY_PUBLICATION_DELAY_MAX_MS', 10_000, PUBLICATION_DELAY_MIN_MS, 60 * 60 * 1000);
const PUBLICATION_FLUSH_MIN_MS = envInt('DISCOVERY_PUBLICATION_FLUSH_MIN_MS', 1000, 500, 10 * 60 * 1000);
const PUBLICATION_FLUSH_MAX_MS = envInt('DISCOVERY_PUBLICATION_FLUSH_MAX_MS', 4000, PUBLICATION_FLUSH_MIN_MS, 15 * 60 * 1000);
const PUBLICATION_BATCH_MAX = envInt('DISCOVERY_PUBLICATION_BATCH_MAX', 32, 1, 512);
const PUBLICATION_POOL_TTL_SECONDS = envInt('DISCOVERY_PUBLICATION_POOL_TTL_SECONDS', 7 * 24 * 60 * 60, 60, 30 * 24 * 60 * 60);
const PUBLICATION_REDIS_ENQUEUE_TIMEOUT_MS = envInt('DISCOVERY_PUBLICATION_REDIS_ENQUEUE_TIMEOUT_MS', 2500, 500, 10_000);
const PUBLICATION_REDIS_FLUSH_TIMEOUT_MS = envInt('DISCOVERY_PUBLICATION_REDIS_FLUSH_TIMEOUT_MS', 3000, 500, 10_000);
const COVER_WRITES_MIN = envInt('DISCOVERY_PUBLICATION_COVER_WRITES_MIN', 1, 0, 64);
const COVER_WRITES_MAX = envInt('DISCOVERY_PUBLICATION_COVER_WRITES_MAX', 3, COVER_WRITES_MIN, 128);
const IDLE_COVER_WRITES_MIN = envInt('DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MIN', 0, 0, 64);
const IDLE_COVER_WRITES_MAX = envInt('DISCOVERY_PUBLICATION_IDLE_COVER_WRITES_MAX', 0, IDLE_COVER_WRITES_MIN, 128);
const COVER_TOKEN_BATCH_SIZE = envInt('DISCOVERY_PUBLICATION_COVER_TOKEN_BATCH_SIZE', 122, 1, 512);
const COVER_BLOB_CHARS = envInt('DISCOVERY_PUBLICATION_COVER_BLOB_CHARS', 16 * 1024, 1024, 1024 * 1024);
const COVER_LEASE_MS = envInt('DISCOVERY_PUBLICATION_COVER_LEASE_MS', 30 * 60 * 1000, 60_000, 90 * 24 * 60 * 60 * 1000);
const PIR_REFRESH_MIN_INTERVAL_MS = envInt('DISCOVERY_PIR_REFRESH_MIN_INTERVAL_MS', 45_000, 10_000, 6 * 60 * 60 * 1000);

let relayStarted = false;
let relayTimer = null;
let flushInFlight = false;
let pirPrewarmInFlight = false;
let pirPrewarmRequestedAgain = false;
let pirRefreshTimer = null;
let lastPirRefreshAt = 0;
const localPublicationPool = [];

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function randomDelay(minMs, maxMs) {
  return crypto.randomInt(Math.max(0, minMs), Math.max(minMs, maxMs) + 1);
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function randomOpaqueBlob(chars) {
  return crypto.randomBytes(Math.ceil(chars * 0.75)).toString('base64url').slice(0, chars);
}

function timeoutAfter(ms, message) {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(message)), ms);
  });
}

function queueLocalPublication(entry) {
  localPublicationPool.push(entry);
  if (localPublicationPool.length > PUBLICATION_BATCH_MAX * 32) {
    localPublicationPool.splice(0, localPublicationPool.length - PUBLICATION_BATCH_MAX * 32);
  }
}

function claimLocalPublications(now, limit) {
  const claimed = [];
  for (let index = 0; index < localPublicationPool.length && claimed.length < limit;) {
    const entry = localPublicationPool[index];
    if (!entry || Number(entry.releaseAt || 0) > now) {
      index += 1;
      continue;
    }
    claimed.push(entry);
    localPublicationPool.splice(index, 1);
  }
  return claimed;
}

function normalizeTokenBatch(tokens) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(tokens) ? tokens : []) {
    if (typeof raw !== 'string') continue;
    const token = raw.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/i.test(token) || seen.has(token)) continue;
    seen.add(token);
    out.push(token);
  }
  return out;
}

function makeCoverPublication(shape = {}) {
  const blobChars = Math.max(1024, Math.min(Number(shape.encryptedBlobChars) || COVER_BLOB_CHARS, 1024 * 1024));
  const bucketBatch = [{
    epochId: currentDiscoveryEpochId(),
    bucketId: crypto.randomInt(DISCOVERY_FIXED_BUCKET_COUNT),
    publishId: crypto.randomBytes(16).toString('hex')
  }];
  return {
    id: crypto.randomBytes(16).toString('base64url'),
    cover: true,
    bucketBatch,
    encryptedBlob: randomOpaqueBlob(blobChars),
    expiresAt: Date.now() + COVER_LEASE_MS,
    publishedAt: Date.now()
  };
}

function countClass(count) {
  const n = Number(count) || 0;
  if (n <= 0) return 'none';
  if (n === 1) return 'single';
  if (n <= 8) return 'small-batch';
  if (n <= 32) return 'medium-batch';
  return 'large-batch';
}

function scheduleDiscoveryPirPrewarm() {
  if (pirPrewarmInFlight) {
    pirPrewarmRequestedAgain = true;
    return;
  }

  pirPrewarmInFlight = true;
  setTimeout(async () => {
    try {
      do {
        pirPrewarmRequestedAgain = false;
        const startedAt = Date.now();
        // Prewarm discovery PIR database
        const discoveryResult = await getPirDatabase(DISCOVERY_PIR_DATABASE_KIND, { ensureWorker: true });
        cryptoLogger.info('[DISCOVERY-PUBLISH] Discovery PIR prewarm complete', {
          discoverySuccess: discoveryResult?.success === true,
          discoveryUploaded: discoveryResult?.database?.workerUpload?.uploaded === true,
          error: discoveryResult?.error || undefined,
          elapsedClass: Date.now() - startedAt <= 10_000
            ? 'lte-10s'
            : Date.now() - startedAt <= 60_000
              ? 'lte-60s'
              : 'gt-60s'
        });
      } while (pirPrewarmRequestedAgain);
    } catch (error) {
      cryptoLogger.warn('[DISCOVERY-PUBLISH] Discovery PIR prewarm failed', {
        error: error?.message || String(error)
      });
    } finally {
      pirPrewarmInFlight = false;
      if (pirPrewarmRequestedAgain) {
        scheduleDiscoveryPirPrewarm();
      }
    }
  }, 0);
}

function scheduleDiscoveryPirRefresh(reason = 'publication-batch') {
  const now = Date.now();
  const elapsed = lastPirRefreshAt > 0 ? now - lastPirRefreshAt : Number.POSITIVE_INFINITY;
  const delayMs = elapsed >= PIR_REFRESH_MIN_INTERVAL_MS ? 0 : PIR_REFRESH_MIN_INTERVAL_MS - elapsed;

  if (pirRefreshTimer) {
    cryptoLogger.info('[DISCOVERY-PUBLISH] Discovery PIR refresh coalesced', {
      reason,
      delayClass: delayMs <= 0 ? 'immediate' : delayMs <= 60_000 ? 'lte-60s' : delayMs <= 30 * 60_000 ? 'lte-30m' : 'gt-30m'
    });
    return;
  }

  cryptoLogger.info('[DISCOVERY-PUBLISH] Discovery PIR refresh scheduled', {
    reason,
    delayClass: delayMs <= 0 ? 'immediate' : delayMs <= 60_000 ? 'lte-60s' : delayMs <= 30 * 60_000 ? 'lte-30m' : 'gt-30m'
  });
  pirRefreshTimer = setTimeout(() => {
    pirRefreshTimer = null;
    lastPirRefreshAt = Date.now();
    
    invalidatePirDatabase(DISCOVERY_PIR_DATABASE_KIND);
    scheduleDiscoveryPirPrewarm();
  }, delayMs);
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
}

export function startDiscoveryPublicationRelay() {
  if (relayStarted) return;
  relayStarted = true;
  scheduleFlush(randomDelay(PUBLICATION_FLUSH_MIN_MS, PUBLICATION_FLUSH_MAX_MS));
  cryptoLogger.info('[DISCOVERY-PUBLISH] Delayed publication relay started', {
    delayMinMs: PUBLICATION_DELAY_MIN_MS,
    delayMaxMs: PUBLICATION_DELAY_MAX_MS,
    coverMin: COVER_WRITES_MIN,
    coverMax: COVER_WRITES_MAX
  });
}

export function stopDiscoveryPublicationRelay() {
  relayStarted = false;
  if (relayTimer) {
    clearTimeout(relayTimer);
    relayTimer = null;
  }
}

export async function enqueueDiscoveryPublication({ bucketBatch, encryptedBlob, expiresAt }) {
  const batch = normalizeBucketBatch(bucketBatch);
  if (batch.length === 0 || typeof encryptedBlob !== 'string' || encryptedBlob.length === 0) {
    return { queued: false, error: 'invalid_discovery_publication' };
  }
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    return { queued: false, error: 'invalid_discovery_publication_expiry' };
  }

  const entry = {
    id: crypto.randomBytes(16).toString('base64url'),
    cover: false,
    bucketBatch: batch,
    encryptedBlob,
    expiresAt: Math.trunc(expiresAt),
    publishedAt: Date.now(),
    releaseAt: Date.now() + randomDelay(PUBLICATION_DELAY_MIN_MS, PUBLICATION_DELAY_MAX_MS),
    shape: {
      tokenCount: batch.length,
      encryptedBlobChars: encryptedBlob.length
    }
  };

  let backend = 'redis';
  try {
    await Promise.race([
      withRedisClient(async (client) => {
        await client.zadd(DISCOVERY_PUBLICATION_POOL_KEY, entry.releaseAt, JSON.stringify(entry));
        await client.expire(DISCOVERY_PUBLICATION_POOL_KEY, PUBLICATION_POOL_TTL_SECONDS);
      }),
      timeoutAfter(PUBLICATION_REDIS_ENQUEUE_TIMEOUT_MS, 'discovery_publication_redis_enqueue_timeout')
    ]);
  } catch (error) {
    backend = 'local-fallback';
    queueLocalPublication(entry);
    cryptoLogger.warn('[DISCOVERY-PUBLISH] Redis enqueue unavailable; using local delayed publication fallback', {
      error: error?.message || String(error),
      localQueueClass: countClass(localPublicationPool.length)
    });
  }

  startDiscoveryPublicationRelay();
  scheduleFlush();
  cryptoLogger.info('[DISCOVERY-PUBLISH] Queued delayed publication', {
    tokenBatchClass: countClass(batch.length),
    encryptedBlobSizeClass: encryptedBlob.length <= 16 * 1024
      ? 'lte-16k'
      : encryptedBlob.length <= 64 * 1024
        ? 'lte-64k'
        : encryptedBlob.length <= 256 * 1024
          ? 'lte-256k'
          : 'gt-256k',
    releaseDelayClass: entry.releaseAt - Date.now() <= 15_000
      ? 'short'
      : entry.releaseAt - Date.now() <= 60_000
        ? 'medium'
        : 'long'
  });
  return {
    queued: true,
    backend,
    releaseAfterMs: Math.max(0, entry.releaseAt - Date.now())
  };
}

async function storePublication(entry) {
  const batch = normalizeBucketBatch(entry?.bucketBatch);
  if (batch.length === 0 || typeof entry?.encryptedBlob !== 'string' || !entry.encryptedBlob) {
    return 0;
  }
  const expiresAt = Number.isFinite(entry.expiresAt)
    ? Math.trunc(entry.expiresAt)
    : Date.now() + COVER_LEASE_MS;
  const publishedAt = Number.isFinite(entry.publishedAt)
    ? Math.trunc(entry.publishedAt)
    : Date.now();
  let stored = 0;
  for (const b of batch) {
    stored += await DiscoveryDB.storeBucketEntry(b.epochId, b.bucketId, b.publishId, entry.encryptedBlob, expiresAt, publishedAt);
  }
  return stored;
}

export async function flushDiscoveryPublicationRelay() {
  if (flushInFlight) return { flushed: 0, cover: 0 };
  flushInFlight = true;

  const claimed = claimLocalPublications(Date.now(), PUBLICATION_BATCH_MAX);
  try {
    if (claimed.length < PUBLICATION_BATCH_MAX) {
      try {
        await Promise.race([
          withRedisClient(async (client) => {
            const rawItems = await client.zrangebyscore(
              DISCOVERY_PUBLICATION_POOL_KEY,
              '-inf',
              Date.now(),
              'LIMIT',
              0,
              PUBLICATION_BATCH_MAX - claimed.length
            );

            for (const raw of rawItems || []) {
              let entry;
              try {
                entry = JSON.parse(raw);
              } catch {
                await client.zrem(DISCOVERY_PUBLICATION_POOL_KEY, raw);
                continue;
              }
              const removed = await client.zrem(DISCOVERY_PUBLICATION_POOL_KEY, raw);
              if (removed === 1) {
                claimed.push(entry);
              }
            }
          }),
          timeoutAfter(PUBLICATION_REDIS_FLUSH_TIMEOUT_MS, 'discovery_publication_redis_flush_timeout')
        ]);
      } catch (error) {
        cryptoLogger.warn('[DISCOVERY-PUBLISH] Redis flush unavailable; flushing local delayed publications only', {
          error: error?.message || String(error),
          localQueueClass: countClass(localPublicationPool.length)
        });
      }
    }

    if (claimed.length === 0 && localPublicationPool.length > 0) {
      const nextReleaseAt = localPublicationPool.reduce((min, entry) => {
        const releaseAt = Number(entry?.releaseAt || 0);
        return releaseAt > 0 ? Math.min(min, releaseAt) : min;
      }, Number.POSITIVE_INFINITY);
      if (Number.isFinite(nextReleaseAt)) {
        const delayMs = Math.max(0, Math.min(nextReleaseAt - Date.now(), PUBLICATION_FLUSH_MAX_MS));
        if (!relayTimer) {
          scheduleFlush(delayMs);
        }
      }
    }

    const coverMin = claimed.length > 0 ? COVER_WRITES_MIN : IDLE_COVER_WRITES_MIN;
    const coverMax = claimed.length > 0 ? COVER_WRITES_MAX : IDLE_COVER_WRITES_MAX;
    const coverCount = coverMax > 0
      ? crypto.randomInt(coverMin, coverMax + 1)
      : 0;
    const coverShape = claimed.find((entry) => entry?.shape)?.shape || {};
    const covers = Array.from({ length: coverCount }, () => makeCoverPublication(coverShape));
    const batch = [...claimed, ...covers].sort(() => crypto.randomInt(0, 3) - 1);
    let stored = 0;
    let coverStored = 0;
    for (const entry of batch) {
      const count = await storePublication(entry);
      stored += count;
      if (entry.cover) coverStored += count;
    }
    if (stored > 0) {
      scheduleDiscoveryPirRefresh('stored-publication-batch');
    }
    if (batch.length > 0) {
      cryptoLogger.info('[DISCOVERY-PUBLISH] Flushed delayed publication batch', {
        realBatchClass: countClass(claimed.length),
        coverBatchClass: countClass(covers.length),
        storedBatchClass: countClass(stored),
        coverStoredClass: countClass(coverStored)
      });
    }
    return { flushed: claimed.length, cover: covers.length, stored, coverStored };
  } catch (error) {
    cryptoLogger.error('[DISCOVERY-PUBLISH] Delayed publication flush failed', { error: error?.message });
    return { flushed: 0, cover: 0, error: 'discovery_publication_flush_failed' };
  } finally {
    flushInFlight = false;
  }
}
