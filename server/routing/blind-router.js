/**
 * Blind Message Router
 * 
 * Routes messages to inbox IDs without knowing user identity.
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient } from '../session/redis-client.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import {
  validateCapabilityToken,
  lookupInbox,
  registerInbox,
  unregisterInbox,
} from './capability-tokens.js';

// Configuration
const MESSAGE_QUEUE_TTL = 300;
const DELIVERY_JITTER_MIN_MS = 10;
const DELIVERY_JITTER_MAX_MS = 100;
const MESSAGE_BATCH_INTERVAL_MS = 50;
const INBOX_QUEUE_PREFIX = 'inbox:queue:';
const DEDUP_WINDOW_MS = 10000;
const DEDUP_MAX_ENTRIES = 2000;

// Message deduplication cache: hash -> timestamp
const recentDeliveryHashes = new Map();

function getEnvelopeHash(inboxId, sealedEnvelope) {
  try {
    if (!inboxId || typeof inboxId !== 'string') return null;
    if (!sealedEnvelope) return null;

    let snippet;
    if (typeof sealedEnvelope === 'string') {
      snippet = sealedEnvelope.slice(0, 128);
    } else if (typeof sealedEnvelope === 'object') {
      snippet = JSON.stringify(sealedEnvelope).slice(0, 256);
    } else {
      return null;
    }

    const key = `${inboxId}:${snippet}`;
    const hashBytes = blake3(Buffer.from(key), { dkLen: 16 });
    return Buffer.from(hashBytes).toString('base64url');
  } catch {
    return null;
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

// In-memory socket registry
const localSocketRegistry = new Map();

// Maps: inboxId -> socketId
const localInboxMap = new Map();

// Message queue for batching
const pendingDeliveries = [];
let batchTimer = null;

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

    for (const [inboxId, mappedSocketId] of localInboxMap.entries()) {
      if (mappedSocketId === socketId) {
        localInboxMap.delete(inboxId);
        unregisterInbox(inboxId).catch(() => { });
      }
    }
  }
}

/**
 * Claim an inbox for a socket
 * Requires valid capability token that includes this inbox
 */
export async function claimInbox(ws, capabilityToken, inboxId, alreadyAuthorized = false) {
  const tokenResult = await validateCapabilityToken(capabilityToken);
  if (!tokenResult.valid) {
    return { success: false, error: tokenResult.error };
  }

  const isAuthorized = alreadyAuthorized || tokenResult.inboxIds.includes(inboxId);

  if (!isAuthorized) {
    return { success: false, error: 'inbox_not_authorized' };
  }

  const socketId = ws._blindSocketId;
  if (!socketId) {
    return { success: false, error: 'socket_not_registered' };
  }

  localInboxMap.set(inboxId, socketId);

  await registerInbox(inboxId, {
    socketId,
    serverId: process.env.SERVER_ID || 'default'
  });

  if (!ws._claimedInboxes) {
    ws._claimedInboxes = new Set();
  }
  ws._claimedInboxes.add(inboxId);

  // Deliver any queued messages for this inbox
  deliverQueuedMessages(inboxId, ws).catch(() => { });

  return { success: true };
}

/**
 * Route a message to an inbox
 */
export async function routeToInbox(destinationInboxId, sealedEnvelope, options = {}) {
  const { immediate = false, priority = 'normal' } = options;

  if (!destinationInboxId || typeof destinationInboxId !== 'string') {
    return { delivered: false, error: 'invalid_inbox_id' };
  }

  // Deduplicate: reject if same envelope was recently routed to same inbox
  const dedupHash = getEnvelopeHash(destinationInboxId, sealedEnvelope);
  if (isDuplicateDelivery(dedupHash)) {
    cryptoLogger.info('[BLIND-ROUTER] Duplicate delivery suppressed', {
      inboxPrefix: destinationInboxId.slice(0, 8) + '...'
    });
    return { delivered: true, deduplicated: true };
  }

  // Add delivery jitter unless immediate
  if (!immediate) {
    const jitter = crypto.randomInt(DELIVERY_JITTER_MIN_MS, DELIVERY_JITTER_MAX_MS);
    await new Promise(resolve => setTimeout(resolve, jitter));
  }

  // Try local delivery first
  const localResult = await tryLocalDelivery(destinationInboxId, sealedEnvelope);
  if (localResult.delivered) {
    return localResult;
  }

  // Try distributed delivery
  const distributedResult = await tryDistributedDelivery(destinationInboxId, sealedEnvelope);
  if (distributedResult.delivered) {
    return distributedResult;
  }

  // Queue for later delivery
  if (priority !== 'transient') {
    await queueMessage(destinationInboxId, sealedEnvelope);
    return { delivered: false, queued: true };
  }

  return { delivered: false, error: 'inbox_not_found' };
}

/**
 * Try to deliver message to a local socket
 */
async function tryLocalDelivery(inboxId, sealedEnvelope) {
  const socketId = localInboxMap.get(inboxId);
  if (!socketId) {
    return { delivered: false };
  }

  const ws = localSocketRegistry.get(socketId);
  if (!ws || ws.readyState !== 1) {
    localInboxMap.delete(inboxId);
    return { delivered: false };
  }

  try {
    await sendToSocket(ws, sealedEnvelope);
    return { delivered: true, local: true };
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Local delivery failed', { error: error.message });
    return { delivered: false, error: 'send_failed' };
  }
}

/**
 * Try distributed delivery via Redis pub/sub
 */
async function tryDistributedDelivery(inboxId, sealedEnvelope) {
  const inboxInfo = await lookupInbox(inboxId);
  if (!inboxInfo) {
    return { delivered: false };
  }

  const localServerId = process.env.SERVER_ID || 'default';
  if (inboxInfo.serverId === localServerId) {
    return { delivered: false };
  }

  try {
    await withRedisClient(async (client) => {
      const channel = `blind:deliver:${inboxInfo.serverId}`;
      const message = JSON.stringify({
        inboxId,
        envelope: sealedEnvelope,
        timestamp: Date.now()
      });
      await client.publish(channel, message);
    });

    return { delivered: true, remote: true };
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Distributed delivery failed', { error: error.message });
    return { delivered: false, error: 'publish_failed' };
  }
}

/**
 * Queue a message for later delivery
 */
async function queueMessage(inboxId, sealedEnvelope) {
  try {
    await withRedisClient(async (client) => {
      const key = `${INBOX_QUEUE_PREFIX}${inboxId}`;
      const message = JSON.stringify({
        envelope: sealedEnvelope,
        queuedAt: Date.now()
      });
      await client.rpush(key, message);
      await client.expire(key, MESSAGE_QUEUE_TTL);
    });
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Queue failed', { error: error.message });
  }
}

/**
 * Deliver queued messages when inbox comes online
 */
async function deliverQueuedMessages(inboxId, ws) {
  try {
    await withRedisClient(async (client) => {
      const key = `${INBOX_QUEUE_PREFIX}${inboxId}`;

      while (true) {
        const messageJson = await client.lpop(key);
        if (!messageJson) break;

        try {
          const message = JSON.parse(messageJson);
          await sendToSocket(ws, message.envelope);
        } catch (parseError) {
          cryptoLogger.warn('[BLIND-ROUTER] Failed to deliver queued message');
        }
      }
    });
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Queue delivery failed', { error: error.message });
  }
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
        type: 'sealed-envelope',
        envelope: sealedEnvelope
      };
      await sendPQEncryptedResponse(ws, session, messageWrapper);
      return;
    }
  }

  throw new Error('No PQ session available for socket delivery');
}

/**
 * Handle incoming blind delivery from another server
 */
export async function handleBlindDelivery(message) {
  const { inboxId, envelope } = message;

  const result = await tryLocalDelivery(inboxId, envelope);
  if (!result.delivered) {
    await queueMessage(inboxId, envelope);
  }
}

/**
 * Subscribe to blind delivery channel for this server
 */
export async function subscribeToBlindDelivery() {
  const serverId = process.env.SERVER_ID || 'default';
  const channel = `blind:deliver:${serverId}`;

  try {
    await withRedisClient(async (client) => {
      const subscriber = client.duplicate();
      await subscriber.connect();

      await subscriber.subscribe(channel, (message) => {
        try {
          const parsed = JSON.parse(message);
          handleBlindDelivery(parsed).catch(() => { });
        } catch (error) {
          cryptoLogger.error('[BLIND-ROUTER] Invalid delivery message');
        }
      });

      cryptoLogger.info('[BLIND-ROUTER] Subscribed to blind delivery channel', { channel });
    });
  } catch (error) {
    cryptoLogger.error('[BLIND-ROUTER] Failed to subscribe', { error: error.message });
  }
}

/**
 * Batch messages for timing correlation resistance
 */
export function queueForBatchDelivery(inboxId, envelope) {
  pendingDeliveries.push({ inboxId, envelope, queuedAt: Date.now() });

  if (!batchTimer) {
    batchTimer = setTimeout(flushBatch, MESSAGE_BATCH_INTERVAL_MS);
  }
}

async function flushBatch() {
  batchTimer = null;

  if (pendingDeliveries.length === 0) return;

  // Shuffle deliveries to decorrelate order
  const batch = [...pendingDeliveries];
  pendingDeliveries.length = 0;

  for (let i = batch.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [batch[i], batch[j]] = [batch[j], batch[i]];
  }

  // Deliver with random micro-delays
  for (const { inboxId, envelope } of batch) {
    const microDelay = crypto.randomInt(0, 20);
    setTimeout(() => {
      routeToInbox(inboxId, envelope, { immediate: true }).catch(() => { });
    }, microDelay);
  }
}

export const BlindRouter = {
  registerLocalSocket,
  unregisterLocalSocket,
  claimInbox,
  routeToInbox,
  queueForBatchDelivery,
  subscribeToBlindDelivery,
  handleBlindDelivery
};
