/**
 * adaptive auth throttle
 *
 * Brute force defense that cant identify clients the server
 * never sees a usable client IP and account
 * login is oblivious by design
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient } from '../session/redis-client.js';
import {
  AUTH_SERVER_BUSY
} from '../config/error-codes.js';
import {
  authConnectionClosedError,
  throwIfAuthConnectionClosed
} from '../authentication/auth-utils.js';
import { createAbortableAdmissionGate } from '../utils/admission-gate.js';
import { envInt } from '../utils/env.js';
import {
  POW_SEED_BASE64_CHARS,
  POW_SEED_BYTES,
  POW_SOLUTION_BASE64_CHARS,
  POW_SOLUTION_BYTES
} from '../utils/crypto-consts.js';
import { REDIS_KEYS } from '../config/redis-keys.js';

const WINDOW_MS = envInt('AUTH_THROTTLE_WINDOW_MS', 60_000, 5_000, 600_000);
const FREE_FAILURES = envInt('AUTH_THROTTLE_FREE_FAILURES', 30, 0, 1_000_000);
const MS_PER_FAILURE = envInt('AUTH_THROTTLE_MS_PER_FAILURE', 150, 0, 60_000);
const MAX_DELAY_MS = envInt('AUTH_THROTTLE_MAX_DELAY_MS', 8_000, 0, 120_000);

const KEY_PREFIX = REDIS_KEYS.AUTH_FAILURE_PREFIX;

function currentBucket() {
  return Math.floor(Date.now() / WINDOW_MS);
}

// Generic anonymous windowed counter
async function recordEvent(prefix) {
  try {
    const bucket = currentBucket();
    const key = `${prefix}${bucket}`;
    const ttlSeconds = Math.ceil((WINDOW_MS * 2) / 1000);
    await withRedisClient((client) => client.eval(
      `
        local count = redis.call('INCR', KEYS[1])
        redis.call('EXPIRE', KEYS[1], ARGV[1])
        return count
      `,
      1,
      key,
      ttlSeconds
    ));
  } catch {
    console.warn('[AUTH-THROTTLE] Anonymous counter unavailable');
    const error = new Error('Authentication throttle unavailable');
    error.code = 'AUTH_THROTTLE_UNAVAILABLE';
    throw error;
  }
}

async function getRecentCount(prefix) {
  try {
    const bucket = currentBucket();
    return await withRedisClient(async (client) => {
      const values = await client.mget(`${prefix}${bucket}`, `${prefix}${bucket - 1}`);
      const cur = Number.parseInt(values?.[0], 10) || 0;
      const prev = Number.parseInt(values?.[1], 10) || 0;
      return cur + prev;
    });
  } catch {
    console.warn('[AUTH-THROTTLE] Anonymous counter unavailable');
    const error = new Error('Authentication throttle unavailable');
    error.code = 'AUTH_THROTTLE_UNAVAILABLE';
    throw error;
  }
}

// Record one failed auth proof
export async function recordAuthFailure() {
  return recordEvent(KEY_PREFIX);
}

// Recent global failure count (current + previous bucket)
export async function getRecentFailureCount() {
  return getRecentCount(KEY_PREFIX);
}

export function computeDelayMs(recentFailures) {
  if (!Number.isFinite(recentFailures) || recentFailures <= FREE_FAILURES) return 0;
  return Math.min(MAX_DELAY_MS, (recentFailures - FREE_FAILURES) * MS_PER_FAILURE);
}

// Compute the delay that should currently apply
export async function getAdaptiveAuthDelayMs() {
  return computeDelayMs(await getRecentFailureCount());
}

function throwIfConnectionClosed(signal) {
  throwIfAuthConnectionClosed(signal);
}

function waitWithSignal(delayMs, signal) {
  if (delayMs <= 0) {
    throwIfConnectionClosed(signal);
    return Promise.resolve();
  }
  if (!signal) return new Promise((resolve) => setTimeout(resolve, delayMs));

  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener('abort', onAbort);
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanup();
      callback();
    };
    const onAbort = () => finish(() => reject(authConnectionClosedError()));
    const timer = setTimeout(() => finish(resolve), delayMs);
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

// Apply current adaptive delay
export async function applyAdaptiveAuthDelay(signal) {
  const delay = await getAdaptiveAuthDelayMs();
  await waitWithSignal(delay, signal);
  return delay;
}

const POW_FREE_FAILURES = envInt('AUTH_POW_FREE_FAILURES', 30, 0, 1_000_000);
const POW_MIN_BITS = envInt('AUTH_POW_MIN_BITS', 10, 0, 28);
const POW_MAX_BITS = envInt('AUTH_POW_MAX_BITS', 22, 22, 28);
const POW_STEP_FAILURES = envInt('AUTH_POW_STEP_FAILURES', 40, 1, 1_000_000);

export function computeDifficulty(recentFailures) {
  if (!Number.isFinite(recentFailures) || recentFailures <= POW_FREE_FAILURES) return 0;
  const over = recentFailures - POW_FREE_FAILURES;
  const bits = POW_MIN_BITS + Math.floor(Math.log2(1 + over / POW_STEP_FAILURES));
  return Math.min(POW_MAX_BITS, Math.max(POW_MIN_BITS, bits));
}

// Current PoW difficulty derived from counter
export async function getAdaptiveDifficulty() {
  return computeDifficulty(await getRecentFailureCount());
}

// Create a fresh PoW challenge for the given difficulty (0 = no work required)
export function createPowChallenge(difficulty) {
  const d = Number.isInteger(difficulty) ? Math.max(0, Math.min(POW_MAX_BITS, difficulty)) : 0;
  return { seed: crypto.randomBytes(POW_SEED_BYTES).toString('base64'), difficulty: d };
}

function leadingZeroBits(bytes) {
  let count = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0) {
      count += 8;
      continue;
    }
    for (let mask = 0x80; mask > 0; mask >>= 1) {
      if ((b & mask) !== 0) return count;
      count++;
    }
  }
  return count;
}

// Verify PoW solution. Difficulty <= 0 means no PoW is required
export function verifyPowSolution(seedB64, difficulty, solutionB64) {
  const d = difficulty;
  if (d <= 0) return true;
  if (!Number.isInteger(d) || d > POW_MAX_BITS) return false;
  if (
    typeof seedB64 !== 'string' || seedB64.length !== POW_SEED_BASE64_CHARS ||
    typeof solutionB64 !== 'string' || solutionB64.length !== POW_SOLUTION_BASE64_CHARS
  ) return false;
  let seed = null;
  let sol = null;
  let digest = null;
  try {
    seed = Buffer.from(seedB64, 'base64');
    sol = Buffer.from(solutionB64, 'base64');
    if (
      seed.length !== POW_SEED_BYTES || seed.toString('base64') !== seedB64 ||
      sol.length !== POW_SOLUTION_BYTES || sol.toString('base64') !== solutionB64
    ) return false;
    digest = blake3(Buffer.concat([seed, sol]));
    return leadingZeroBits(digest) >= d;
  } catch {
    return false;
  } finally {
    seed?.fill(0);
    sol?.fill(0);
    digest?.fill(0);
  }
}

const PIR_KEY_PREFIX = REDIS_KEYS.AUTH_PIR_REQUEST_PREFIX;
const AUTH_PREFLIGHT_BASE_BITS = envInt('AUTH_PREFLIGHT_POW_BITS', 20, 18, POW_MAX_BITS);
const AUTH_FINALIZE_BASE_BITS = envInt('AUTH_FINALIZE_POW_BITS', 22, 22, POW_MAX_BITS);
const AUTH_PREFLIGHT_STEP_REQUESTS = envInt('AUTH_PREFLIGHT_STEP_REQUESTS', 32, 1, 1_000_000);
const MAX_EXPENSIVE_AUTH_CONCURRENCY = 1;
const MAX_EXPENSIVE_AUTH_QUEUE = envInt('AUTH_PIR_MAX_QUEUE', 8, 0, 8);
const EXPENSIVE_AUTH_QUEUE_TIMEOUT_MS = envInt('AUTH_PIR_QUEUE_TIMEOUT_MS', 90_000, 1_000, 120_000);

const expensiveAuthAdmissionGate = createAbortableAdmissionGate({
  maxConcurrent: MAX_EXPENSIVE_AUTH_CONCURRENCY,
  maxQueued: MAX_EXPENSIVE_AUTH_QUEUE,
  queueTimeoutMs: EXPENSIVE_AUTH_QUEUE_TIMEOUT_MS,
  abortedError: authConnectionClosedError,
  fullError: () => Object.assign(new Error('Expensive authentication queue is full'), {
    code: AUTH_SERVER_BUSY
  }),
  timeoutError: () => Object.assign(new Error('Expensive authentication queue timed out'), {
    code: AUTH_SERVER_BUSY
  })
});

function acquireExpensiveAuthSlot(signal) {
  return expensiveAuthAdmissionGate.acquire(signal);
}

// Baseline work always required before private PIR retrieval
export async function getAuthPreflightDifficulty() {
  const recent = await getRecentCount(PIR_KEY_PREFIX);
  const extra = Math.floor(Math.log2(1 + Math.max(0, recent) / AUTH_PREFLIGHT_STEP_REQUESTS));
  return Math.min(POW_MAX_BITS, AUTH_PREFLIGHT_BASE_BITS + extra);
}

// full private auth proof scans all 2048 ML-DSA public keys
export async function getAuthVerificationDifficulty() {
  return Math.max(AUTH_FINALIZE_BASE_BITS, await getAdaptiveDifficulty());
}

export async function recordAuthPreflightCompletion() {
  return recordEvent(PIR_KEY_PREFIX);
}

// Record the work-backed PIR request and acquire a bounded execution slot
export async function throttleExpensiveAuthRequest(signal) {
  await recordAuthPreflightCompletion();
  return acquireExpensiveAuthSlot(signal);
}

// Bound later expensive verification phase that belongs to already work backed authentication attempt
export async function acquireExpensiveAuthVerificationSlot(signal) {
  return acquireExpensiveAuthSlot(signal);
}
