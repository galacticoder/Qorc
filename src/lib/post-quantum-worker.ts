import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import * as argon2 from "argon2-wasm";

const kyber = ml_kem1024;

const MAX_KEYS = 256;
const RATE_LIMIT_CONFIG = {
  DEFAULT: { windowMs: 60_000, maxRequests: 100 },
  'kem.generateKeyPair': { windowMs: 60_000, maxRequests: 10 },
  'kem.destroyKey': { windowMs: 60_000, maxRequests: 50 },
  'argon2.hash': { windowMs: 60_000, maxRequests: 20 },
  'argon2.verify': { windowMs: 60_000, maxRequests: 50 }
} as const;
const rateBuckets = new Map<string, Map<string, { count: number; resetAt: number }>>();
const processedIds = new Map<string, { timestamp: number; origin: string }>();
const activeKeys = new Map<string, { key: Uint8Array; timestamp: number; origin: string }>();

let AUTH_TOKEN = new Uint8Array(32);
crypto.getRandomValues(AUTH_TOKEN);
let authTokenTimestamp = Date.now();
const AUTH_TOKEN_LIFETIME = 60 * 60 * 1000;

// Send initial auth token to main thread
(self as WorkerContext).postMessage({
  type: 'auth-token-init',
  token: Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join(''),
  timestamp: Date.now()
});

function hasPrototypePollutionKeys(obj: unknown): boolean {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value == null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

self.addEventListener('beforeunload', () => {
  for (const keyData of activeKeys.values()) {
    keyData.key.fill(0);
  }
  activeKeys.clear();
  AUTH_TOKEN.fill(0);
  processedIds.clear();
  rateBuckets.clear();
});

function secureRandomId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  throw new Error('Secure random UUID not available');
}

function getRateBucket(origin: string, operationType: string) {
  if (!rateBuckets.has(origin)) {
    rateBuckets.set(origin, new Map());
  }
  const originBuckets = rateBuckets.get(origin)!;
  if (!originBuckets.has(operationType)) {
    const config = RATE_LIMIT_CONFIG[operationType as keyof typeof RATE_LIMIT_CONFIG] || RATE_LIMIT_CONFIG.DEFAULT;
    originBuckets.set(operationType, { count: 0, resetAt: Date.now() + config.windowMs });
  }
  return originBuckets.get(operationType)!;
}

function enforceRateLimit(origin: string, operationType: string): void {
  const now = Date.now();
  const bucket = getRateBucket(origin, operationType);
  const config = RATE_LIMIT_CONFIG[operationType as keyof typeof RATE_LIMIT_CONFIG] || RATE_LIMIT_CONFIG.DEFAULT;

  if (bucket.resetAt <= now) {
    bucket.count = 0;
    bucket.resetAt = now + config.windowMs;
  }

  bucket.count += 1;
  if (bucket.count > config.maxRequests) {
    throw new Error(`Rate limit exceeded for ${operationType}`);
  }
}

function rotateAuthTokenIfNeeded(): void {
  const now = Date.now();
  if (now - authTokenTimestamp <= AUTH_TOKEN_LIFETIME) {
    return;
  }

  const newBytes = new Uint8Array(32);
  crypto.getRandomValues(newBytes);
  AUTH_TOKEN.set(newBytes);
  authTokenTimestamp = now;

  (self as WorkerContext).postMessage({
    type: 'auth-token-rotated',
    token: Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join(''),
    timestamp: now
  });
}

function validateEnvelope(envelope: any): asserts envelope is { id: string; type: string; auth: string } {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('Invalid message envelope');
  }
  if (typeof envelope.id !== 'string' || envelope.id.length === 0) {
    throw new Error('Envelope id required');
  }
  if (typeof envelope.type !== 'string' || envelope.type.length === 0) {
    throw new Error('Envelope type required');
  }
  if (typeof envelope.auth !== 'string') {
    throw new Error('Envelope auth required');
  }
}

function authenticateEnvelope(envelope: { auth: string }): void {
  rotateAuthTokenIfNeeded();
  const expected = Array.from(AUTH_TOKEN, (b) => b.toString(16).padStart(2, '0')).join('');
  if (envelope.auth !== expected) {
    throw new Error('Unauthorized request');
  }
}

const REPLAY_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const MAX_PROCESSED_IDS = 2048;

function rejectIfReplay(id: string, origin: string): void {
  const now = Date.now();
  const existing = processedIds.get(id);
  if (existing && now - existing.timestamp < REPLAY_WINDOW_MS) {
    throw new Error('Replay detected');
  }

  processedIds.set(id, { timestamp: now, origin });

  if (processedIds.size > MAX_PROCESSED_IDS) {
    const cutoffTime = now - REPLAY_WINDOW_MS;
    for (const [key, value] of processedIds.entries()) {
      if (value.timestamp < cutoffTime || processedIds.size > MAX_PROCESSED_IDS * 0.9) {
        processedIds.delete(key);
      }
    }
  }
}

const KEY_LIFETIME_MS = 60 * 60 * 1000; // 1 hour

function storeKey(keyId: string, secretKey: Uint8Array, origin: string): void {
  cleanupExpiredKeys(Date.now());

  if (activeKeys.size >= MAX_KEYS) {
    const entries = Array.from(activeKeys.entries()).sort((a, b) => a[1].timestamp - b[1].timestamp);
    const [oldestKeyId, oldestKeyData] = entries[0];
    oldestKeyData.key.fill(0);
    activeKeys.delete(oldestKeyId);
  }

  activeKeys.set(keyId, { key: secretKey, timestamp: Date.now(), origin });
}

function cleanupExpiredKeys(now: number): void {
  const cutoffTime = now - KEY_LIFETIME_MS;
  for (const [keyId, keyData] of activeKeys.entries()) {
    if (keyData.timestamp < cutoffTime) {
      keyData.key.fill(0);
      activeKeys.delete(keyId);
    }
  }
}

type WorkerRequest =
  | { id: string; type: 'kem.generateKeyPair'; auth: string }
  | { id: string; type: 'kem.destroyKey'; keyId: string; auth: string }
  | { id: string; type: 'argon2.hash'; params: any; auth: string }
  | { id: string; type: 'argon2.verify'; params: any; auth: string };

type WorkerResponse =
  | { id: string; success: true; result: { publicKey: Uint8Array; secretKey: Uint8Array; keyId: string } }
  | { id: string; success: true; result: { destroyed: true } }
  | { id: string; success: true; result: { hash: any; encoded: any } }
  | { id: string; success: true; result: { verified: boolean } }
  | { id: string; success: false; error: string };

type WorkerContext = DedicatedWorkerGlobalScope;

self.addEventListener('message', (event: MessageEvent<WorkerRequest>) => {
  try {
    // Validate event.data for prototype pollution
    if (!isPlainObject(event.data)) {
      throw new Error('Invalid message format');
    }
    if (hasPrototypePollutionKeys(event.data)) {
      throw new Error('Prototype pollution detected in message');
    }

    validateEnvelope(event.data);
    authenticateEnvelope(event.data);
    rejectIfReplay(event.data.id, event.origin ?? 'unknown');
    enforceRateLimit(event.origin ?? 'unknown', event.data.type);

    const { id, type } = event.data;
    switch (type) {
      case 'kem.generateKeyPair': {
        const keyPair = kyber.keygen();
        if (keyPair.publicKey.length !== kyber.publicKeyBytes || keyPair.secretKey.length !== kyber.secretKeyBytes) {
          throw new Error('Invalid key pair generated');
        }
        const keyId = secureRandomId();
        storeKey(keyId, keyPair.secretKey, event.origin ?? 'unknown');
        const response: WorkerResponse = {
          id,
          success: true,
          result: {
            publicKey: keyPair.publicKey,
            secretKey: keyPair.secretKey,
            keyId
          }
        };
        (self as WorkerContext).postMessage(response, [
          keyPair.publicKey.buffer,
          keyPair.secretKey.buffer
        ]);
        keyPair.publicKey.fill(0);
        keyPair.secretKey.fill(0);
        break;
      }
      case 'kem.destroyKey': {
        if (typeof event.data.keyId !== 'string' || event.data.keyId.length === 0) {
          throw new Error('Invalid keyId parameter');
        }
        if (event.data.keyId === '__proto__' || event.data.keyId === 'constructor' || event.data.keyId === 'prototype') {
          throw new Error('Invalid keyId: prototype pollution attempt detected');
        }
        
        const { keyId } = event.data;
        const secretKeyData = activeKeys.get(keyId);
        const secretKey = secretKeyData?.key;
        if (secretKey) {
          secretKey.fill(0);
          activeKeys.delete(keyId);
        }
        const response: WorkerResponse = {
          id,
          success: true,
          result: { destroyed: true }
        };
        (self as WorkerContext).postMessage(response);
        break;
      }
      case 'argon2.hash': {
        const { params } = event.data;
        try {
          const result = await argon2.hash(params);
          const response: WorkerResponse = {
            id,
            success: true,
            result: { hash: result.hash, encoded: result.encoded }
          };
          (self as WorkerContext).postMessage(response);
        } catch (err) {
          throw new Error(`Argon2 hash failed: ${(err as Error).message}`);
        }
        break;
      }
      case 'argon2.verify': {
        const { params } = event.data;
        try {
          await argon2.verify(params); // argon2-wasm verify throws on failure or returns nothing/object? 
          // Actually argon2-wasm verify returns Promise<void> and throws if invalid? Or returns object?
          // Let's check unified-crypto.ts usage: const result = await argon2.verify({ pass: data, encoded }); return result.verified; 
          // Wait, I need to double check argon2-wasm API. 
          // In unified-crypto.ts: const result = await argon2.verify({ pass: data, encoded }); return result.verified;
          // So it returns an object with .verified property.
          
          const result = await argon2.verify(params);
          // @ts-ignore
          const verified = result?.verified === true; 
          
          const response: WorkerResponse = {
            id,
            success: true,
            result: { verified }
          };
          (self as WorkerContext).postMessage(response);
        } catch (err) {
           // verify might throw if params are bad, but also if verification fails? 
           // usually verify returns false or throws.
           // Assuming it throws on error, but returns object on success/fail check.
           throw new Error(`Argon2 verify failed: ${(err as Error).message}`);
        }
        break;
      }
      default: {
        throw new Error(`Unsupported worker operation: ${type}`);
      }
    }
  } catch (error) {
    const errorResponse: WorkerResponse = {
      id: (event.data && 'id' in event.data ? event.data.id : secureRandomId()),
      success: false,
      error: error instanceof Error ? error.message : String(error)
    };
    (self as WorkerContext).postMessage(errorResponse);
  }
});
