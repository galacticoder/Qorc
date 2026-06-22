/**
 * Blind Message Router
 * 
 * Routes sealed envelopes through a global delayed mix stream
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient, createSubscriber } from '../session/redis-client.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { SignalType } from '../signals.js';
import { recordLocalBroadcast } from '../diagnostics/runtime-monitor.js';
import {
  validateCapabilityToken,
  isRouteLookupId
} from './capability-tokens.js';
import { validateSealedEnvelope } from './sealed-sender.js';

// Configuration
const DELIVERY_JITTER_MIN_MS = 10;
const DELIVERY_JITTER_MAX_MS = 100;
const DEDUP_WINDOW_MS = 10000;
const DEDUP_MAX_ENTRIES = 2000;
const MIXNET_DELAY_POOL_KEY = 'mixnet:delay:pool:v1';
const GLOBAL_MIX_SPOOL_KEY = 'mixnet:global:spool:v1';
const GLOBAL_MIX_SPOOL_BYTES_KEY = 'mixnet:global:spool:v1:bytes';
const GLOBAL_MIX_CHANNEL = 'blind:global-mix:deliver';
const MIXNET_ENABLED = String(process.env.MIXNET_RELAY_ENABLED || 'true').toLowerCase() !== 'false';
const MIXNET_DELAY_MIN_MS = envInt('MIXNET_DELAY_MIN_MS', 1500, 250, 120000);
const MIXNET_DELAY_MAX_MS = envInt('MIXNET_DELAY_MAX_MS', 9000, MIXNET_DELAY_MIN_MS, 300000);
const MIXNET_FLUSH_MIN_MS = envInt('MIXNET_FLUSH_MIN_MS', 700, 100, 60000);
const MIXNET_FLUSH_MAX_MS = envInt('MIXNET_FLUSH_MAX_MS', 2500, MIXNET_FLUSH_MIN_MS, 120000);
const MIXNET_BATCH_MAX_MESSAGES = envInt('MIXNET_BATCH_MAX_MESSAGES', 24, 1, 256);
const MIXNET_POOL_TTL_SECONDS = envInt('MIXNET_POOL_TTL_SECONDS', 7 * 24 * 60 * 60, 60, 30 * 24 * 60 * 60);
const MIXNET_AVOID_SAME_WRITER = String(process.env.MIXNET_AVOID_SAME_WRITER || 'true').toLowerCase() !== 'false';
const MIXNET_SAME_WRITER_FALLBACK_MS = envInt('MIXNET_SAME_WRITER_FALLBACK_MS', 60000, 1000, 15 * 60 * 1000);
const MIXNET_COVER_WRITES_MIN = envInt('MIXNET_COVER_WRITES_MIN', 1, 0, 32);
const MIXNET_COVER_WRITES_MAX = envInt('MIXNET_COVER_WRITES_MAX', 2, MIXNET_COVER_WRITES_MIN, 64);
const MIXNET_COVER_CIPHERTEXT_BYTES = envInt('MIXNET_COVER_CIPHERTEXT_BYTES', 32768, 2048, 1024 * 1024);
const MIXNET_COVER_EPHEMERAL_BYTES = envInt('MIXNET_COVER_EPHEMERAL_BYTES', 512, 32, 8192);
const MIXNET_COVER_NONCE_BYTES = envInt('MIXNET_COVER_NONCE_BYTES', 24, 12, 64);
const GLOBAL_MIX_SPOOL_TTL_SECONDS = envInt('GLOBAL_MIX_SPOOL_TTL_SECONDS', 24 * 60 * 60, 60, 30 * 24 * 60 * 60);
const GLOBAL_MIX_SPOOL_MAX_MESSAGES = envInt('GLOBAL_MIX_SPOOL_MAX_MESSAGES', 1024, 64, 10_000_000);
const GLOBAL_MIX_SPOOL_MAX_BYTES = envInt('GLOBAL_MIX_SPOOL_MAX_BYTES', 16 * 1024 * 1024, 1024 * 1024, 2 * 1024 * 1024 * 1024);
const LOCAL_BROADCAST_BUFFERED_MAX_BYTES = envInt('LOCAL_BROADCAST_BUFFERED_MAX_BYTES', 8 * 1024 * 1024, 1024 * 1024, 256 * 1024 * 1024);
const LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS = envInt('LOCAL_BROADCAST_BACKPRESSURE_LOG_INTERVAL_MS', 30000, 1000, 10 * 60 * 1000);
const LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS = envInt('LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS', 2 * 60 * 1000, 10 * 1000, 30 * 60 * 1000);
const LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS = envInt('LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS', 2 * 60 * 1000, 10 * 1000, 30 * 60 * 1000);
const LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS = envInt('LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS', 0, 0, 5 * 60 * 1000);

// Message deduplication cache: hash -> timestamp
const recentDeliveryHashes = new Map();
let mixnetRelayStarted = false;
let mixnetRelayTimer = null;
let mixnetRelayFlushInFlight = false;
let blindDeliverySubscriberPromise = null;

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function getServerId() {
  return process.env.SERVER_ID || 'default';
}

function randomDelay(minMs, maxMs) {
  const min = Math.max(0, Math.trunc(minMs));
  const max = Math.max(min, Math.trunc(maxMs));
  return crypto.randomInt(min, max + 1);
}

function countClass(value) {
  const count = Math.max(0, Number(value) || 0);
  if (count === 0) return '0';
  if (count === 1) return '1';
  if (count <= 3) return '2-3';
  if (count <= 7) return '4-7';
  if (count <= 15) return '8-15';
  if (count <= 31) return '16-31';
  return '32+';
}

function serializeSpoolMember(memberObject) {
  let member = JSON.stringify(memberObject);
  let byteSize = Buffer.byteLength(member, 'utf8');
  for (let i = 0; i < 4; i += 1) {
    memberObject.byteSize = byteSize;
    member = JSON.stringify(memberObject);
    const nextByteSize = Buffer.byteLength(member, 'utf8');
    if (nextByteSize === byteSize) break;
    byteSize = nextByteSize;
  }
  memberObject.byteSize = byteSize;
  return JSON.stringify(memberObject);
}

function getEnvelopeHash(sealedEnvelope) {
  try {
    if (!sealedEnvelope) return null;

    let snippet;
    if (typeof sealedEnvelope === 'string') {
      snippet = sealedEnvelope.slice(0, 128);
    } else if (typeof sealedEnvelope === 'object') {
      snippet = [
        sealedEnvelope.version,
        sealedEnvelope.nonce,
        typeof sealedEnvelope.ephemeralKey === 'string' ? sealedEnvelope.ephemeralKey.slice(0, 64) : '',
        typeof sealedEnvelope.ciphertext === 'string' ? sealedEnvelope.ciphertext.slice(0, 128) : ''
      ].join(':');
    } else {
      return null;
    }

    const hashBytes = blake3(Buffer.from(`global-mix:${snippet}`), { dkLen: 16 });
    return Buffer.from(hashBytes).toString('base64url');
  } catch {
    return null;
  }
}

function createCoverSealedEnvelope() {
  return {
    version: 'ss-v1',
    ciphertext: crypto.randomBytes(MIXNET_COVER_CIPHERTEXT_BYTES).toString('base64'),
    ephemeralKey: crypto.randomBytes(MIXNET_COVER_EPHEMERAL_BYTES).toString('base64'),
    nonce: crypto.randomBytes(MIXNET_COVER_NONCE_BYTES).toString('base64')
  };
}

function validateGlobalEnvelope(sealedEnvelope) {
  const sealedValidation = validateSealedEnvelope(sealedEnvelope);
  if (!sealedValidation.valid) {
    return { valid: false, error: `invalid_sealed_envelope:${sealedValidation.error}` };
  }
  return { valid: true };
}

function createMixnetEntry(sealedEnvelope, options = {}) {
  const now = Date.now();
  const delayMs = Number.isFinite(options.delayMs)
    ? Math.max(0, Math.trunc(options.delayMs))
    : randomDelay(MIXNET_DELAY_MIN_MS, MIXNET_DELAY_MAX_MS);
  const entropy = crypto.randomBytes(32).toString('base64url');
  const id = Buffer.from(blake3(Buffer.from(`global:${now}:${entropy}`), { dkLen: 16 })).toString('base64url');
  return {
    id,
    envelope: sealedEnvelope,
    cover: !!options.cover,
    ingressServerId: options.ingressServerId || getServerId(),
    originSocketId: typeof options.originSocketId === 'string' ? options.originSocketId : undefined,
    ingressAt: now,
    releaseAt: now + delayMs,
    hop: 1
  };
}

function shouldDeferToAnotherWriter(entry) {
  if (!MIXNET_AVOID_SAME_WRITER) return false;
  if (!entry?.ingressServerId || entry.ingressServerId !== getServerId()) return false;
  const age = Date.now() - Number(entry.ingressAt || entry.releaseAt || Date.now());
  return age < MIXNET_SAME_WRITER_FALLBACK_MS;
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

export function startMixnetRelay() {
  if (mixnetRelayStarted) return;
  mixnetRelayStarted = true;
  scheduleMixnetFlush(randomDelay(MIXNET_FLUSH_MIN_MS, MIXNET_FLUSH_MAX_MS));
  cryptoLogger.info('[MIXNET] Delay-pool relay started', {
    delayMinMs: MIXNET_DELAY_MIN_MS,
    delayMaxMs: MIXNET_DELAY_MAX_MS,
    avoidSameWriter: MIXNET_AVOID_SAME_WRITER,
    coverMin: MIXNET_COVER_WRITES_MIN,
    coverMax: MIXNET_COVER_WRITES_MAX,
    globalSpoolMaxMessages: GLOBAL_MIX_SPOOL_MAX_MESSAGES,
    globalSpoolMaxBytes: GLOBAL_MIX_SPOOL_MAX_BYTES
  });
}

export function stopMixnetRelay() {
  mixnetRelayStarted = false;
  if (mixnetRelayTimer) {
    clearTimeout(mixnetRelayTimer);
    mixnetRelayTimer = null;
  }
}

function isDuplicateDelivery(hash) {
  if (!hash) return false;
  const now = Date.now();
  const prev = recentDeliveryHashes.get(hash);
  if (prev && (now - prev) < DEDUP_WINDOW_MS) {
    return true;
  }
  recentDeliveryHashes.set(hash, now);
  // Periodic cleanup
  if (recentDeliveryHashes.size > DEDUP_MAX_ENTRIES) {
    for (const [k, ts] of recentDeliveryHashes) {
      if (now - ts > DEDUP_WINDOW_MS) recentDeliveryHashes.delete(k);
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
  return false;
}

function pruneRecentDeliveryHashes(now = Date.now(), force = false) {
  let removed = 0;
  for (const [hash, ts] of recentDeliveryHashes.entries()) {
    if (force || now - ts > DEDUP_WINDOW_MS) {
      recentDeliveryHashes.delete(hash);
      removed += 1;
    }
  }
  return removed;
}

// In-memory socket registry
const localSocketRegistry = new Map();

export function getBlindRouterRuntimeStats() {
  pruneRecentDeliveryHashes();
  let openSockets = 0;
  let closedSockets = 0;
  for (const ws of localSocketRegistry.values()) {
    if (ws?.readyState === 1) openSockets += 1;
    else closedSockets += 1;
  }
  return {
    localSocketCount: localSocketRegistry.size,
    openSockets,
    closedSockets,
    recentDeliveryHashes: recentDeliveryHashes.size,
    mixnetRelayStarted,
    mixnetRelayTimerActive: !!mixnetRelayTimer,
    mixnetRelayFlushInFlight,
    globalSpoolMaxMessages: GLOBAL_MIX_SPOOL_MAX_MESSAGES,
    globalSpoolMaxBytes: GLOBAL_MIX_SPOOL_MAX_BYTES
  };
}

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
    recentDeliveryHashesRemoved: pruneRecentDeliveryHashes(Date.now(), force)
  };
}

/**
 * Register a local WebSocket connection
 */
export function registerLocalSocket(ws) {
  // Generate PQ-secure socket ID
  const entropy = crypto.randomBytes(64);
  const timestamp = Buffer.from(Date.now().toString());
  const socketIdBytes = blake3(Buffer.concat([entropy, timestamp]), { dkLen: 32 });
  const socketId = Buffer.from(socketIdBytes).toString('base64url');

  ws._blindSocketId = socketId;
  localSocketRegistry.set(socketId, ws);

  return socketId;
}

/**
 * Unregister a local WebSocket connection
 */
export function unregisterLocalSocket(ws) {
  const socketId = ws._blindSocketId;
  if (socketId) {
    localSocketRegistry.delete(socketId);
  }
}

/**
 * Claim an already committed rendezvous route for a socket
 */
export async function claimInboxRoute(ws, capabilityToken, routeId, alreadyAuthorized = false) {
  if (!isRouteLookupId(routeId)) {
    return { success: false, error: 'invalid_route_id' };
  }

  if (!alreadyAuthorized) {
    return { success: false, error: 'route_not_authorized' };
  }

  const socketId = ws._blindSocketId;
  if (!socketId) {
    return { success: false, error: 'socket_not_registered' };
  }

  if (!ws._claimedInboxRoutes) {
    ws._claimedInboxRoutes = new Set();
  }
  ws._claimedInboxRoutes.add(routeId);

  return { success: true };
}

export async function routeToGlobalMix(sealedEnvelope, options = {}) {
  const { immediate = false, publish = true, cover = false, originSocketId = null } = options;

  const validation = validateGlobalEnvelope(sealedEnvelope);
  if (!validation.valid) {
    return { queued: false, delivered: 0, error: validation.error };
  }

  const dedupHash = getEnvelopeHash(sealedEnvelope);
  if (!cover && isDuplicateDelivery(dedupHash)) {
    return { queued: true, delivered: 0, deduplicated: true };
  }

  if (MIXNET_ENABLED && !immediate) {
    return enqueueMixnetRelay(sealedEnvelope, { cover, publish, originSocketId });
  }

  return writeToGlobalMixSpool(sealedEnvelope, { publish, cover, originSocketId });
}

export async function enqueueMixnetRelay(sealedEnvelope, options = {}) {
  const { cover = false, originSocketId = null } = options;

  const validation = validateGlobalEnvelope(sealedEnvelope);
  if (!validation.valid) {
    return { queued: false, delivered: 0, error: validation.error };
  }

  const entry = createMixnetEntry(sealedEnvelope, { cover, originSocketId });

  try {
    await withRedisClient(async (client) => {
      await client.zadd(MIXNET_DELAY_POOL_KEY, entry.releaseAt, JSON.stringify(entry));
      await client.expire(MIXNET_DELAY_POOL_KEY, MIXNET_POOL_TTL_SECONDS);
    });
    startMixnetRelay();
    scheduleMixnetFlush();
    return {
      queued: true,
      delivered: 0,
      relay: 'mixnet-delay-pool'
    };
  } catch (error) {
    cryptoLogger.error('[MIXNET] Failed to enqueue ingress relay packet', { error: error.message });
    return { queued: false, delivered: 0, error: 'mixnet_enqueue_failed' };
  }
}

export async function enqueueMixnetCoverWrite() {
  return enqueueMixnetRelay(createCoverSealedEnvelope(), { cover: true });
}

async function writeToGlobalMixSpool(sealedEnvelope, options = {}) {
  const { publish = true, originSocketId = null, cover = false } = options;

  const jitter = crypto.randomInt(DELIVERY_JITTER_MIN_MS, DELIVERY_JITTER_MAX_MS);
  await new Promise(resolve => setTimeout(resolve, jitter));
  if (!cover) {
    await queueGlobalMixMessage(sealedEnvelope);
  }
  const delivered = await tryLocalBroadcastDelivery(sealedEnvelope, { originSocketId });

  if (publish) {
    await publishGlobalMixDelivery(sealedEnvelope).catch(() => { });
  }

  return { queued: true, delivered };
}

async function flushMixnetDelayPool() {
  if (mixnetRelayFlushInFlight) return;
  mixnetRelayFlushInFlight = true;

  const claimed = [];
  try {
    await withRedisClient(async (client) => {
      const rawItems = await client.zrangebyscore(
        MIXNET_DELAY_POOL_KEY,
        '-inf',
        Date.now(),
        'LIMIT',
        0,
        MIXNET_BATCH_MAX_MESSAGES
      );

      for (const raw of rawItems || []) {
        let entry;
        try {
          entry = JSON.parse(raw);
        } catch {
          await client.zrem(MIXNET_DELAY_POOL_KEY, raw);
          continue;
        }

        if (shouldDeferToAnotherWriter(entry)) {
          continue;
        }

        const removed = await client.zrem(MIXNET_DELAY_POOL_KEY, raw);
        if (removed === 1 && entry?.envelope) {
          claimed.push(entry);
        }
      }
    });

    const realClaimedCount = claimed.filter((entry) => !entry.cover).length;
    const coverCount = realClaimedCount > 0 && MIXNET_COVER_WRITES_MAX > 0
      ? crypto.randomInt(MIXNET_COVER_WRITES_MIN, MIXNET_COVER_WRITES_MAX + 1)
      : 0;
    const covers = Array.from({ length: coverCount }, () => ({
      id: crypto.randomBytes(16).toString('base64url'),
      envelope: createCoverSealedEnvelope(),
      cover: true,
      ingressServerId: getServerId(),
      ingressAt: Date.now(),
      releaseAt: Date.now(),
      hop: 2
    }));

    const batch = shuffleArray([...claimed, ...covers]);
    if (batch.length === 0) {
      return;
    }

    for (const entry of batch) {
      if (!entry?.envelope) continue;
      const microDelay = randomDelay(0, 80);
      if (microDelay > 0) {
        await new Promise(resolve => setTimeout(resolve, microDelay));
      }
      try {
        await writeToGlobalMixSpool(entry.envelope, {
          publish: true,
          originSocketId: entry.originSocketId,
          cover: !!entry.cover
        });
      } catch (error) {
        cryptoLogger.warn('[MIXNET] Global writer failed', {
          cover: !!entry.cover,
          error: error?.message
        });
      }
    }

    cryptoLogger.info('[MIXNET] Flushed delayed global writer batch', {
      realCountClass: countClass(realClaimedCount),
      coverCountClass: countClass(batch.filter((entry) => entry.cover).length),
      totalCountClass: countClass(batch.length)
    });
  } catch (error) {
    cryptoLogger.error('[MIXNET] Delay-pool flush failed', { error: error.message });
  } finally {
    mixnetRelayFlushInFlight = false;
  }
}

async function queueGlobalMixMessage(sealedEnvelope) {
  try {
    await withRedisClient(async (client) => {
      const key = GLOBAL_MIX_SPOOL_KEY;
      const score = (Date.now() * 1000) + crypto.randomInt(0, 1000);
      const envelopeHash = getEnvelopeHash(sealedEnvelope) || crypto.randomBytes(16).toString('base64url');
      const memberObject = {
        id: Buffer.from(blake3(Buffer.from(`global:${score}:${envelopeHash}`), { dkLen: 16 })).toString('base64url'),
        envelope: sealedEnvelope,
        queuedAt: Date.now(),
        score
      };
      const member = serializeSpoolMember(memberObject);
      await client.zadd(key, score, member);
      await client.expire(key, GLOBAL_MIX_SPOOL_TTL_SECONDS);
      await client.incrby(GLOBAL_MIX_SPOOL_BYTES_KEY, memberObject.byteSize);
      await client.expire(GLOBAL_MIX_SPOOL_BYTES_KEY, GLOBAL_MIX_SPOOL_TTL_SECONDS);
      await trimGlobalMixSpool(client);
    });
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Global mix spool failed', { error: error.message });
    throw error;
  }
}

function serializedMemberBytes(raw) {
  if (typeof raw !== 'string') return 0;
  try {
    const parsed = JSON.parse(raw);
    const size = Number(parsed?.byteSize);
    if (Number.isFinite(size) && size > 0) return size;
  } catch {
  }
  return Buffer.byteLength(raw, 'utf8');
}

async function removeSpoolMembers(client, members) {
  const selected = (Array.isArray(members) ? members : []).filter((member) => typeof member === 'string');
  if (selected.length === 0) return 0;
  const removedBytes = selected.reduce((total, member) => total + serializedMemberBytes(member), 0);
  await client.zrem(GLOBAL_MIX_SPOOL_KEY, ...selected);
  if (removedBytes > 0) {
    await client.decrby(GLOBAL_MIX_SPOOL_BYTES_KEY, removedBytes);
  }
  return removedBytes;
}

async function recomputeGlobalMixSpoolBytes(client) {
  const rawItems = await client.zrange(GLOBAL_MIX_SPOOL_KEY, 0, -1);
  const totalBytes = (rawItems || []).reduce((total, member) => total + serializedMemberBytes(member), 0);
  await client.set(GLOBAL_MIX_SPOOL_BYTES_KEY, totalBytes, 'EX', GLOBAL_MIX_SPOOL_TTL_SECONDS);
  return totalBytes;
}

async function trimGlobalMixSpool(client) {
  const key = GLOBAL_MIX_SPOOL_KEY;
  const oldestAllowed = ((Date.now() - (GLOBAL_MIX_SPOOL_TTL_SECONDS * 1000)) * 1000);

  for (;;) {
    const expired = await client.zrangebyscore(key, 0, oldestAllowed, 'LIMIT', 0, 256);
    if (!expired || expired.length === 0) break;
    await removeSpoolMembers(client, expired);
    if (expired.length < 256) break;
  }

  const count = Number(await client.zcard(key)) || 0;
  if (count > GLOBAL_MIX_SPOOL_MAX_MESSAGES) {
    const excess = count - GLOBAL_MIX_SPOOL_MAX_MESSAGES;
    const oldest = await client.zrange(key, 0, excess - 1);
    await removeSpoolMembers(client, oldest);
  }

  let totalBytes = Number(await client.get(GLOBAL_MIX_SPOOL_BYTES_KEY));
  if (!Number.isFinite(totalBytes) || totalBytes < 0) {
    totalBytes = await recomputeGlobalMixSpoolBytes(client);
  }

  while (totalBytes > GLOBAL_MIX_SPOOL_MAX_BYTES) {
    const oldest = await client.zrange(key, 0, 127);
    if (!oldest || oldest.length === 0) {
      await client.set(GLOBAL_MIX_SPOOL_BYTES_KEY, 0, 'EX', GLOBAL_MIX_SPOOL_TTL_SECONDS);
      break;
    }
    totalBytes -= await removeSpoolMembers(client, oldest);
  }

  await client.expire(GLOBAL_MIX_SPOOL_BYTES_KEY, GLOBAL_MIX_SPOOL_TTL_SECONDS);
}

async function tryLocalBroadcastDelivery(sealedEnvelope, options = {}) {
  const originSocketId = typeof options.originSocketId === 'string' ? options.originSocketId : null;
  const socketIds = Array.from(localSocketRegistry.keys());
  if (socketIds.length === 0) {
    return 0;
  }

  let delivered = 0;
  let attempts = 0;
  let skippedBackpressure = 0;
  let skippedSuspended = 0;
  let skippedNotReady = 0;
  for (const socketId of socketIds) {
    if (originSocketId && socketId === originSocketId) {
      continue;
    }
    const ws = localSocketRegistry.get(socketId);
    if (!ws || ws.readyState !== 1) {
      localSocketRegistry.delete(socketId);
      continue;
    }
    attempts += 1;
    const now = Date.now();
    if (Number(ws._blindBroadcastSuspendedUntil || 0) > now) {
      skippedSuspended += 1;
      continue;
    }
    if (!ws._pqSessionId) {
      skippedNotReady += 1;
      continue;
    }
    if (!isBroadcastDeliveryReady(ws)) {
      skippedNotReady += 1;
      continue;
    }
    if (LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS > 0) {
      const lastSentAt = Number(ws._lastBlindBroadcastSentAt || 0);
      if (lastSentAt > 0 && now - lastSentAt < LOCAL_BROADCAST_MIN_SEND_INTERVAL_MS) {
        continue;
      }
    }
    if (Number(ws.bufferedAmount || 0) > LOCAL_BROADCAST_BUFFERED_MAX_BYTES) {
      skippedBackpressure += 1;
      if (!Number.isFinite(ws._blindBroadcastBackpressureSince) || ws._blindBroadcastBackpressureSince <= 0) {
        ws._blindBroadcastBackpressureSince = now;
      }
      if (now - ws._blindBroadcastBackpressureSince > LOCAL_BROADCAST_BACKPRESSURE_EVICT_MS) {
        ws._blindBroadcastSuspendedUntil = now + LOCAL_BROADCAST_BACKPRESSURE_SUSPEND_MS;
        ws._blindBroadcastBackpressureSince = 0;
        cryptoLogger.warn('[BLIND-ROUTER] Local privacy broadcast suspended - sustained backpressure', {
          bufferedClass: 'over-limit'
        });
        continue;
      }
      if (shouldLogLocalBroadcastBackpressure(ws)) {
        cryptoLogger.warn('[BLIND-ROUTER] Local privacy broadcast skipped - socket backpressure', {
          bufferedClass: 'over-limit'
        });
      }
      continue;
    }
    ws._blindBroadcastBackpressureSince = 0;
    try {
      await sendToSocket(ws, sealedEnvelope);
      ws._lastBlindBroadcastSentAt = Date.now();
      delivered += 1;
    } catch (error) {
      cryptoLogger.info('[BLIND-ROUTER] Local privacy broadcast delivery skipped', {
        error: error?.message
      });
    }
  }
  recordLocalBroadcast({
    attempts,
    delivered,
    skippedBackpressure,
    skippedSuspended,
    skippedNotReady
  });
  return delivered;
}

function isBroadcastDeliveryReady(ws) {
  return !!(
    ws?._unlinkedSession ||
    hasClaimedInboxRoute(ws)
  );
}

function hasClaimedInboxRoute(ws) {
  return !!(ws?._claimedInboxRoutes && ws._claimedInboxRoutes.size > 0);
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

async function publishGlobalMixDelivery(sealedEnvelope) {
  const originServerId = process.env.SERVER_ID || 'default';
  await withRedisClient(async (client) => {
    await client.publish(GLOBAL_MIX_CHANNEL, JSON.stringify({
      envelope: sealedEnvelope,
      originServerId,
      timestamp: Date.now()
    }));
  });
}

export async function snapshotGlobalMixSpool(limit = 2048) {
  const cappedLimit = Math.min(Math.max(Number(limit) || 2048, 1), 100_000);
  const results = [];

  try {
    await withRedisClient(async (client) => {
      const rawItems = await client.zrevrangebyscore(GLOBAL_MIX_SPOOL_KEY, '+inf', '-inf', 'LIMIT', 0, cappedLimit);
      for (const raw of (rawItems || []).reverse()) {
        try {
          const parsed = JSON.parse(raw);
          if (parsed?.envelope) {
            results.push({
              score: Number(parsed.score || parsed.queuedAt || 0),
              queuedAt: Number(parsed.queuedAt || 0),
              envelope: parsed.envelope
            });
          }
        } catch {
        }
      }
    });
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Global mix PIR snapshot failed', { error: error.message });
  }

  return results;
}

/**
 * Send envelope to socket with PQ encryption if available
 */
async function sendToSocket(ws, sealedEnvelope) {
  const pqSessionId = ws._pqSessionId;

  if (pqSessionId) {
    const { sendPQEncryptedResponse } = await import('../messaging/pq-envelope-handler.js');
    const { getPQSession: getSession } = await import('../session/pq-session-storage.js');
    const session = await getSession(pqSessionId);

    if (session) {
      const messageWrapper = {
        type: SignalType.SEALED_ENVELOPE,
        envelope: sealedEnvelope
      };
      await sendPQEncryptedResponse(ws, session, messageWrapper);
      return;
    }
  }

  throw new Error('No PQ session available for socket delivery');
}

export async function handleGlobalMixDelivery(message) {
  const { envelope, originServerId } = message || {};
  if (originServerId && originServerId === (process.env.SERVER_ID || 'default')) {
    return;
  }
  await tryLocalBroadcastDelivery(envelope);
}

/**
 * Subscribe to global mix delivery channel for this server
 */
export async function subscribeToBlindDelivery() {
  if (blindDeliverySubscriberPromise) {
    return blindDeliverySubscriberPromise;
  }

  blindDeliverySubscriberPromise = (async () => {
    try {
      startMixnetRelay();
      const subscriber = await createSubscriber();

      await subscriber.subscribe(GLOBAL_MIX_CHANNEL, (message) => {
        try {
          const parsed = JSON.parse(message);
          handleGlobalMixDelivery(parsed).catch(() => { });
        } catch (error) {
          cryptoLogger.error('[BLIND-ROUTER] Invalid global mix delivery message');
        }
      });

      cryptoLogger.info('[BLIND-ROUTER] Subscribed to global mix delivery channel', { channel: GLOBAL_MIX_CHANNEL });
    } catch (error) {
      blindDeliverySubscriberPromise = null;
      cryptoLogger.error('[BLIND-ROUTER] Failed to subscribe', { error: error.message });
    }
  })();

  return blindDeliverySubscriberPromise;
}

export async function rotateInboxRoutes(ws, capabilityToken, oldRouteIds, newRouteIds, alreadyAuthorized = false) {
  if (!alreadyAuthorized && capabilityToken) {
    const validation = await validateCapabilityToken(capabilityToken);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }
    alreadyAuthorized = true;
  }
  if (!alreadyAuthorized) {
    return { success: false, error: 'authentication_required' };
  }

  const oldIds = (Array.isArray(oldRouteIds) ? oldRouteIds : []).filter(isRouteLookupId);
  const nextIds = (Array.isArray(newRouteIds) ? newRouteIds : []).filter(isRouteLookupId);
  const socketId = ws._blindSocketId;
  if (!socketId) {
    return { success: false, error: 'socket_not_registered' };
  }

  if (ws._claimedInboxRoutes) {
    for (const routeId of oldIds) {
      ws._claimedInboxRoutes.delete(routeId);
    }
  }
  if (!ws._claimedInboxRoutes) {
    ws._claimedInboxRoutes = new Set();
  }
  for (const routeId of nextIds) {
    ws._claimedInboxRoutes.add(routeId);
  }

  return { success: true, newRouteIds: nextIds };
}

export const BlindRouter = {
  registerLocalSocket,
  unregisterLocalSocket,
  claimInboxRoute,
  routeToGlobalMix,
  enqueueMixnetRelay,
  enqueueMixnetCoverWrite,
  getBlindRouterRuntimeStats,
  pruneBlindRouterRuntimeState,
  rotateInboxRoutes,
  snapshotGlobalMixSpool,
  subscribeToBlindDelivery,
  startMixnetRelay,
  stopMixnetRelay,
  handleGlobalMixDelivery
};
