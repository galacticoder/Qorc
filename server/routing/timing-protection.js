/**
 * Timing Correlation Protection (Post-Quantum Secure)
 * 
 * Mitigates timing-based metadata leakage through:
 * - Random delivery jitter
 * - Message batching with shuffle
 * - Cover traffic generation
 * - Login/socket decorrelation
 * 
 * Post-Quantum Security:
 * - BLAKE3-based deterministic jitter (reproducible for debugging)
 * - Cryptographically random delays
 * - Cover traffic indistinguishable from real traffic
 * 
 * What is mitigated:
 * - Login time ≠ socket creation time correlation
 * - Message timing patterns between users
 * - Response time analysis
 * - Conversation boundary detection
 * 
 * What remains (fundamental limits):
 * - Long-term traffic volume analysis (months of data)
 * - Active network-level timing attacks (requires Tor/mixnets)
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

// Timing configuration
const JITTER_MIN_MS = 10;
const JITTER_MAX_MS = 150;
const BATCH_WINDOW_MS = 50;
const COVER_TRAFFIC_INTERVAL_MS = envInt('SERVER_COVER_TRAFFIC_INTERVAL_MS', 30000, 5000, 10 * 60 * 1000);
const COVER_TRAFFIC_VARIANCE_MS = envInt('SERVER_COVER_TRAFFIC_VARIANCE_MS', 15000, 0, 10 * 60 * 1000);
const COVER_TRAFFIC_WRITES_MIN = envInt('SERVER_COVER_TRAFFIC_WRITES_MIN', 1, 1, 32);
const COVER_TRAFFIC_WRITES_MAX = envInt('SERVER_COVER_TRAFFIC_WRITES_MAX', 3, COVER_TRAFFIC_WRITES_MIN, 64);
const LOGIN_SOCKET_DELAY_MIN_MS = 100;
const LOGIN_SOCKET_DELAY_MAX_MS = 2000;

// Batch queue for message coalescing
const batchQueue = new Map();
const globalBatchQueue = [];
let globalBatchTimer = null;

// Cover traffic state
let coverTrafficInterval = null;

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function randomRouteLookupId() {
  return crypto.randomBytes(64).toString('base64url');
}

/**
 * Generate cryptographically random jitter
 */
export function generateJitter(minMs = JITTER_MIN_MS, maxMs = JITTER_MAX_MS) {
  return crypto.randomInt(minMs, maxMs + 1);
}

/**
 * Generate deterministic jitter from a seed (for testing/debugging)
 * Uses BLAKE3 to derive jitter from seed
 */
export function generateDeterministicJitter(seed, minMs = JITTER_MIN_MS, maxMs = JITTER_MAX_MS) {
  const hash = blake3(Buffer.from(seed));
  const value = hash[0] | (hash[1] << 8);
  const range = maxMs - minMs;
  return minMs + (value % range);
}

/**
 * Delay execution with random jitter
 */
export async function delayWithJitter(minMs = JITTER_MIN_MS, maxMs = JITTER_MAX_MS) {
  const delay = generateJitter(minMs, maxMs);
  await new Promise(resolve => setTimeout(resolve, delay));
  return delay;
}

/**
 * Decorrelate login from socket creation
 * Adds random delay between authentication and socket registration
 */
export async function decorrelateLoginSocket() {
  const delay = generateJitter(LOGIN_SOCKET_DELAY_MIN_MS, LOGIN_SOCKET_DELAY_MAX_MS);
  await new Promise(resolve => setTimeout(resolve, delay));
  return delay;
}

/**
 * Queue a message for batched delivery
 * Messages are collected and delivered in shuffled batches
 */
export function queueForBatch(inboxId, envelope, callback) {
  if (!batchQueue.has(inboxId)) {
    batchQueue.set(inboxId, { messages: [], callbacks: [] });
  }
  
  const queue = batchQueue.get(inboxId);
  queue.messages.push(envelope);
  queue.callbacks.push(callback);
  
  // Schedule batch flush if not already scheduled
  if (!queue.timer) {
    const delay = generateJitter(BATCH_WINDOW_MS, BATCH_WINDOW_MS * 2);
    queue.timer = setTimeout(() => flushBatch(inboxId), delay);
  }
}

/**
 * Flush a single inbox's batch
 */
async function flushBatch(inboxId) {
  const queue = batchQueue.get(inboxId);
  if (!queue || queue.messages.length === 0) {
    batchQueue.delete(inboxId);
    return;
  }
  
  const { messages, callbacks } = queue;
  batchQueue.delete(inboxId);
  
  // Shuffle messages to decorrelate order
  const shuffled = shuffleArray([...messages]);
  const shuffledCallbacks = shuffleArray([...callbacks]);
  
  // Deliver with micro-jitter between each
  for (let i = 0; i < shuffled.length; i++) {
    const microDelay = generateJitter(0, 20);
    await new Promise(resolve => setTimeout(resolve, microDelay));
    
    try {
      if (shuffledCallbacks[i]) {
        await shuffledCallbacks[i](shuffled[i]);
      }
    } catch (error) {
      cryptoLogger.error('[TIMING] Batch delivery failed', { error: error.message });
    }
  }
}

/**
 * Queue for global batching across all inboxes
 * Provides stronger timing protection by mixing messages from different conversations
 */
export function queueForGlobalBatch(delivery) {
  globalBatchQueue.push({
    ...delivery,
    queuedAt: Date.now()
  });
  
  if (!globalBatchTimer) {
    const delay = generateJitter(BATCH_WINDOW_MS, BATCH_WINDOW_MS * 3);
    globalBatchTimer = setTimeout(flushGlobalBatch, delay);
  }
}

/**
 * Flush global batch with shuffling
 */
async function flushGlobalBatch() {
  globalBatchTimer = null;
  
  if (globalBatchQueue.length === 0) return;
  
  // Take all pending deliveries
  const batch = [...globalBatchQueue];
  globalBatchQueue.length = 0;
  
  // Fisher-Yates shuffle
  const shuffled = shuffleArray(batch);
  
  // Deliver with random micro-delays
  for (const delivery of shuffled) {
    const microDelay = generateJitter(0, 30);
    await new Promise(resolve => setTimeout(resolve, microDelay));
    
    try {
      if (delivery.callback) {
        await delivery.callback(delivery.inboxId, delivery.envelope);
      }
    } catch (error) {
      cryptoLogger.error('[TIMING] Global batch delivery failed', { error: error.message });
    }
  }
}

/**
 * Fisher-Yates shuffle using crypto random
 */
function shuffleArray(array) {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

/**
 * Start cover traffic generation
 * Sends dummy messages at random intervals to hide real traffic patterns
 */
export function startCoverTraffic(sendDummyFn) {
  if (coverTrafficInterval) return;
  if (COVER_TRAFFIC_WRITES_MAX <= 0) {
    cryptoLogger.info('[TIMING] Cover traffic disabled by configuration');
    return;
  }
  
  const scheduleNext = () => {
    const variance = COVER_TRAFFIC_VARIANCE_MS > 0
      ? crypto.randomInt(0, COVER_TRAFFIC_VARIANCE_MS * 2) - COVER_TRAFFIC_VARIANCE_MS
      : 0;
    const delay = Math.max(1000, COVER_TRAFFIC_INTERVAL_MS + variance);
    
    coverTrafficInterval = setTimeout(async () => {
      try {
        const targetCount = crypto.randomInt(COVER_TRAFFIC_WRITES_MIN, COVER_TRAFFIC_WRITES_MAX + 1);
        for (let i = 0; i < targetCount; i += 1) {
          await delayWithJitter(10, 50);
          try {
            await sendDummyFn(randomRouteLookupId());
          } catch {
            // Ignore failures for cover traffic
          }
        }
      } catch (error) {
        cryptoLogger.warn('[TIMING] Cover traffic error', { error: error.message });
      }
      
      scheduleNext();
    }, delay);
  };
  
  scheduleNext();
  cryptoLogger.info('[TIMING] Cover traffic started');
}

/**
 * Stop cover traffic generation
 */
export function stopCoverTraffic() {
  if (coverTrafficInterval) {
    clearTimeout(coverTrafficInterval);
    coverTrafficInterval = null;
    cryptoLogger.info('[TIMING] Cover traffic stopped');
  }
}

export function getTimingRuntimeStats() {
  return {
    batchQueueSize: batchQueue.size,
    globalBatchQueueSize: globalBatchQueue.length,
    globalBatchTimerActive: !!globalBatchTimer,
    coverTrafficRunning: !!coverTrafficInterval,
    coverTrafficWritesMin: COVER_TRAFFIC_WRITES_MIN,
    coverTrafficWritesMax: COVER_TRAFFIC_WRITES_MAX
  };
}

export function clearTimingRuntimeState() {
  let batchQueuesCleared = 0;
  for (const queue of batchQueue.values()) {
    if (queue?.timer) clearTimeout(queue.timer);
    batchQueuesCleared += 1;
  }
  batchQueue.clear();
  const globalBatchQueueCleared = globalBatchQueue.length;
  globalBatchQueue.length = 0;
  const hadGlobalBatchTimer = !!globalBatchTimer;
  if (globalBatchTimer) {
    clearTimeout(globalBatchTimer);
    globalBatchTimer = null;
  }
  return {
    batchQueuesCleared,
    globalBatchQueueCleared,
    globalBatchTimerCleared: hadGlobalBatchTimer
  };
}

/**
 * Wrap a delivery function with timing protection
 */
export function withTimingProtection(deliveryFn, options = {}) {
  const { 
    useGlobalBatch = false,
    minJitter = JITTER_MIN_MS,
    maxJitter = JITTER_MAX_MS
  } = options;
  
  return async (inboxId, envelope, ...args) => {
    // Add initial jitter
    await delayWithJitter(minJitter, maxJitter);
    
    if (useGlobalBatch) {
      return new Promise((resolve, reject) => {
        queueForGlobalBatch({
          inboxId,
          envelope,
          callback: async (id, env) => {
            try {
              const result = await deliveryFn(id, env, ...args);
              resolve(result);
            } catch (error) {
              reject(error);
            }
          }
        });
      });
    }
    
    return deliveryFn(inboxId, envelope, ...args);
  };
}

/**
 * Create a rate-smoothed sender
 * Ensures messages are sent at a consistent rate to hide burst patterns
 */
export function createRateSmoother(targetRateMs = 100) {
  let lastSendTime = 0;
  const pendingQueue = [];
  let processing = false;
  
  const processPending = async () => {
    if (processing || pendingQueue.length === 0) return;
    processing = true;
    
    while (pendingQueue.length > 0) {
      const now = Date.now();
      const timeSinceLast = now - lastSendTime;
      
      if (timeSinceLast < targetRateMs) {
        const jitteredDelay = targetRateMs - timeSinceLast + generateJitter(0, 20);
        await new Promise(resolve => setTimeout(resolve, jitteredDelay));
      }
      
      const { sendFn, resolve, reject } = pendingQueue.shift();
      lastSendTime = Date.now();
      
      try {
        const result = await sendFn();
        resolve(result);
      } catch (error) {
        reject(error);
      }
    }
    
    processing = false;
  };
  
  return {
    send: (sendFn) => {
      return new Promise((resolve, reject) => {
        pendingQueue.push({ sendFn, resolve, reject });
        processPending();
      });
    }
  };
}

/**
 * Timing statistics (anonymized)
 */
const timingStats = {
  jittersApplied: 0,
  batchesFlushed: 0,
  coverTrafficSent: 0,
  avgJitterMs: 0
};

export function recordTimingStat(type, value = 0) {
  switch (type) {
    case 'jitter':
      timingStats.jittersApplied++;
      timingStats.avgJitterMs = 
        (timingStats.avgJitterMs * (timingStats.jittersApplied - 1) + value) / 
        timingStats.jittersApplied;
      break;
    case 'batch': 
      timingStats.batchesFlushed++; 
      break;
    case 'cover': 
      timingStats.coverTrafficSent++; 
      break;
  }
}

export function getTimingStats() {
  return { ...timingStats };
}

export const TimingProtection = {
  generateJitter,
  generateDeterministicJitter,
  delayWithJitter,
  decorrelateLoginSocket,
  queueForBatch,
  queueForGlobalBatch,
  startCoverTraffic,
  stopCoverTraffic,
  getTimingRuntimeStats,
  clearTimingRuntimeState,
  withTimingProtection,
  createRateSmoother,
  recordTimingStat,
  getTimingStats
};
