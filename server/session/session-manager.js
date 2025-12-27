import crypto from 'node:crypto';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { ConnectionStateManager } from '../presence/connection-state.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { withRedisClient } from '../presence/presence.js';

const BATCH_SIZE = 10;
const BATCH_TIMEOUT = 1000;
const MAX_BATCH_SIZE = 100;
const REDIS_BATCH_QUEUE_KEY = 'session:batch:queue';
let batchTimer = null;
let batchProcessing = false;

// Generate device ID for WebSocket connections
export function generateDeviceId(ws, request = null) {
  const req = request || ws?.upgradeReq || ws?._socket?._httpMessage?.req;
  const hdrId = req?.headers?.['x-device-id'] || ws?.headers?.['x-device-id'];
  const isTLS = !!(req && req.socket && req.socket.encrypted);
  if (isTLS && hdrId && typeof hdrId === 'string') {
    const trimmed = hdrId.trim();
    if (trimmed.length >= 8) {
      return trimmed.length > 64 ? trimmed.slice(0, 64) : trimmed;
    }
  }

  const ua = req?.headers?.['user-agent'] || 'unknown';
  const randomPart = crypto.randomBytes(16).toString('hex');
  const deviceData = `${ua}-${randomPart}-${Date.now()}`;
  const hash = CryptoUtils.Hash.blake3(Buffer.from(deviceData));
  return Buffer.from(hash).slice(0, 16).toString('hex');
}

// Helper for consistent session refresh error handling
export function safeRefreshSession(sessionId) {
  try {
    ConnectionStateManager.refreshSession(sessionId);
  } catch (error) {
    cryptoLogger.error('[SESSION] Error refreshing session', {
      sessionId: sessionId?.slice(0, 8) + '...',
      error: error?.message
    });
  }
}

// Batch processing function for database operations
async function processBatch() {
  if (batchProcessing) {
    return;
  }

  batchProcessing = true;

  try {
    const batchToProcess = await getRedisQueueBatch();

    if (!batchToProcess || batchToProcess.length === 0) {
      batchProcessing = false;
      return;
    }

    cryptoLogger.info('[SESSION] Processing batch of operations', { count: batchToProcess.length });

    const results = await Promise.allSettled(
      batchToProcess.map(operation => operation.execute())
    );

    const failedCount = results.filter(result => result.status === 'rejected').length;
    if (failedCount > 0) {
      cryptoLogger.error('[SESSION] Batch operations failed', {
        failed: failedCount,
        total: batchToProcess.length
      });
    }

    batchToProcess.length = 0;

    if (batchTimer) {
      clearTimeout(batchTimer);
      batchTimer = null;
    }

    const hasMore = await hasRedisQueueItems();
    if (hasMore) {
      setImmediate(processBatch);
    }
  } catch (error) {
    cryptoLogger.error('[SESSION] Error in batch processing', error);
  } finally {
    batchProcessing = false;
  }
}

// Get batch from Redis queue
async function getRedisQueueBatch() {
  try {
    return await withRedisClient(async (client) => {
      const items = [];
      for (let i = 0; i < BATCH_SIZE; i++) {
        const item = await client.rpop(REDIS_BATCH_QUEUE_KEY);
        if (!item) break;
        try {
          items.push(JSON.parse(item));
        } catch (parseError) {
          cryptoLogger.warn('[SESSION] Failed to parse queued operation', parseError);
        }
      }
      return items;
    });
  } catch (error) {
    cryptoLogger.error('[SESSION] Redis queue read error', error);
    return [];
  }
}

// Check if Redis queue has items
async function hasRedisQueueItems() {
  try {
    return await withRedisClient(async (client) => {
      const length = await client.llen(REDIS_BATCH_QUEUE_KEY);
      return length > 0;
    });
  } catch (error) {
    cryptoLogger.warn('[SESSION] Redis queue length check failed', error);
    return false;
  }
}

// Add operation to batch with overflow protection
export async function addToBatch(operation) {
  await addToRedisQueue(operation);
}

// Add operation to Redis queue
async function addToRedisQueue(operation) {
  await withRedisClient(async (client) => {
    const queueLength = await client.llen(REDIS_BATCH_QUEUE_KEY);
    if (queueLength >= MAX_BATCH_SIZE * 10) {
      cryptoLogger.warn('[SESSION] Redis queue at capacity, processing immediately');
      setImmediate(processBatch);
    }

    await client.lpush(REDIS_BATCH_QUEUE_KEY, JSON.stringify(operation));

    if (!batchTimer) {
      batchTimer = setTimeout(processBatch, BATCH_TIMEOUT);
    }
  });
}

// Cleanup function for shutdown
export async function cleanupSessionManager() {
  if (batchTimer) {
    clearTimeout(batchTimer);
    batchTimer = null;
  }

  try {
    const queueLength = await withRedisClient(async (client) => {
      return await client.llen(REDIS_BATCH_QUEUE_KEY);
    });

    if (queueLength > 0) {
      cryptoLogger.info(`[SESSION] Processing ${queueLength} remaining Redis queue operations...`);
      await processBatch();
    }
  } catch (error) {
    cryptoLogger.warn('[SESSION] Redis unavailable during cleanup, skipping queue processing', { error: error.message });
  }

  cryptoLogger.info('[SESSION] Session manager cleanup complete');
}

// Export batch configuration for external monitoring
export const BATCH_CONFIG = {
  BATCH_SIZE,
  BATCH_TIMEOUT,
  MAX_BATCH_SIZE,
  REDIS_BATCH_QUEUE_KEY,
  isProcessing: () => batchProcessing,
};
