import { withRedisClient } from '../presence/presence.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const REDIS_PQ_SESSION_PREFIX = 'pq:session:';
const REDIS_PQ_SESSION_TTL = 3600;
const REDIS_PQ_COUNTER_PREFIX = 'pq:counter:';

function clampInt(value, { min, max, defaultValue }) {
  const parsed = Number.parseInt(value ?? defaultValue, 10);
  if (!Number.isFinite(parsed)) return defaultValue;
  return Math.min(Math.max(parsed, min), max);
}

const PQ_SESSION_CACHE_MAX = clampInt(process.env.PQ_SESSION_CACHE_MAX, {
  min: 0,
  max: 50_000,
  defaultValue: 5000,
});

const PQ_SESSION_CACHE_TTL_MS = clampInt(process.env.PQ_SESSION_CACHE_TTL_MS, {
  min: 1000,
  max: 3_600_000,
  defaultValue: 300_000,
});

const pqSessionCache = new Map();

function getCachedSession(sessionId) {
  if (!PQ_SESSION_CACHE_MAX) return null;
  const entry = pqSessionCache.get(sessionId);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    pqSessionCache.delete(sessionId);
    return null;
  }
  pqSessionCache.delete(sessionId);
  pqSessionCache.set(sessionId, entry);
  return entry.session;
}

function setCachedSession(sessionId, session) {
  if (!PQ_SESSION_CACHE_MAX) return;
  const entry = { session, expiresAt: Date.now() + PQ_SESSION_CACHE_TTL_MS };
  if (pqSessionCache.has(sessionId)) {
    pqSessionCache.delete(sessionId);
  }
  pqSessionCache.set(sessionId, entry);
  while (pqSessionCache.size > PQ_SESSION_CACHE_MAX) {
    const oldestKey = pqSessionCache.keys().next().value;
    if (!oldestKey) break;
    pqSessionCache.delete(oldestKey);
  }
}

// Session key encryption configuration
const SESSION_STORE_INFO = new TextEncoder().encode('pq-session-store-key-v1');
const SESSION_STORE_SALT = new TextEncoder().encode('pq-session-store-salt-v1');
let sessionStoreKeyPromise = null;

async function getSessionStoreKey() {
  if (sessionStoreKeyPromise) return sessionStoreKeyPromise;

  sessionStoreKeyPromise = (async () => {
    const raw = process.env.SESSION_STORE_KEY && process.env.SESSION_STORE_KEY.trim();

    if (!raw) {
      throw new Error('SESSION_STORE_KEY must be set for PQ session key encryption');
    }

    let keyBuf;
    if (/^[A-Fa-f0-9]{64}$/.test(raw)) {
      keyBuf = Buffer.from(raw, 'hex');
    } else {
      try {
        const asBase64 = Buffer.from(raw, 'base64');
        if (asBase64.length >= 32) {
          keyBuf = asBase64;
        } else {
          keyBuf = Buffer.from(raw, 'utf8');
        }
      } catch {
        keyBuf = Buffer.from(raw, 'utf8');
      }
    }

    if (!keyBuf || keyBuf.length < 32) {
      throw new Error('SESSION_STORE_KEY must decode to at least 32 bytes');
    }

    const ikmBytes = CryptoUtils.Hash.toUint8Array(keyBuf, 'session-store-ikm');

    const master = await CryptoUtils.KDF.quantumHKDF(
      ikmBytes,
      SESSION_STORE_SALT,
      SESSION_STORE_INFO,
      32
    );
    return master;
  })();

  return sessionStoreKeyPromise;
}

async function encryptSessionKey(rawKey, sessionId, direction) {
  const masterKey = await getSessionStoreKey();
  const salt = new TextEncoder().encode(`pq-session-store:${sessionId}:${direction}`);
  const perKey = await CryptoUtils.KDF.quantumHKDF(masterKey, salt, SESSION_STORE_INFO, 32);

  const aead = new CryptoUtils.PostQuantumAEAD(perKey);
  const nonce = CryptoUtils.Random.generateRandomBytes(36);
  const aad = new TextEncoder().encode(`pq-session:${sessionId}:${direction}`);

  const keyBytes = CryptoUtils.Hash.toUint8Array(rawKey, `session.${direction}Key`);
  const { ciphertext, tag } = aead.encrypt(keyBytes, nonce, aad);

  const combined = Buffer.concat([
    Buffer.from(nonce),
    Buffer.from(tag),
    Buffer.from(ciphertext)
  ]);
  return combined.toString('base64');
}

async function decryptSessionKey(encoded, sessionId, direction) {
  const data = Buffer.from(encoded, 'base64');
  if (data.length < 36 + 32 + 1) {
    throw new Error('PQ session store payload too short');
  }

  const nonce = data.slice(0, 36);
  const tag = data.slice(36, 68);
  const ciphertext = data.slice(68);

  const masterKey = await getSessionStoreKey();
  const salt = new TextEncoder().encode(`pq-session-store:${sessionId}:${direction}`);
  const perKey = await CryptoUtils.KDF.quantumHKDF(masterKey, salt, SESSION_STORE_INFO, 32);

  const aead = new CryptoUtils.PostQuantumAEAD(perKey);
  const aad = new TextEncoder().encode(`pq-session:${sessionId}:${direction}`);

  const plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
  return new Uint8Array(plaintext);
}

// Store PQ session in Redis
export async function storePQSession(sessionId, sessionData) {
  if (!sessionId || !sessionData) {
    throw new Error('Session ID and data are required');
  }

  const key = `${REDIS_PQ_SESSION_PREFIX}${sessionId}`;
  const recvKeyEnc = await encryptSessionKey(sessionData.recvKey, sessionId, 'recv');
  const sendKeyEnc = await encryptSessionKey(sessionData.sendKey, sessionId, 'send');

  await withRedisClient(async (client) => {
    const serialized = JSON.stringify({
      sessionId: sessionData.sessionId,
      recvKey: recvKeyEnc,
      sendKey: sendKeyEnc,
      fingerprint: sessionData.fingerprint,
      establishedAt: sessionData.establishedAt,
      counter: sessionData.counter || 0
    });
    await client.setex(key, REDIS_PQ_SESSION_TTL, serialized);
    const counterKey = `${REDIS_PQ_COUNTER_PREFIX}${sessionId}`;
    await client.setex(counterKey, REDIS_PQ_SESSION_TTL, String(sessionData.counter || 0));
  });

  try {
    setCachedSession(sessionId, {
      sessionId: sessionData.sessionId,
      recvKey: sessionData.recvKey,
      sendKey: sessionData.sendKey,
      fingerprint: sessionData.fingerprint,
      establishedAt: sessionData.establishedAt,
      counter: sessionData.counter || 0
    });
  } catch {
  }

  cryptoLogger.info('[PQ-SESSION] Stored in Redis (encrypted)', {
    sessionId: sessionId.slice(0, 16) + '...',
    serverId: process.env.SERVER_ID
  });
}

// Retrieve PQ session from Redis
export async function getPQSession(sessionId) {
  if (!sessionId) {
    return null;
  }

  const cached = getCachedSession(sessionId);
  if (cached) {
    return cached;
  }

  return await withRedisClient(async (client) => {
    const key = `${REDIS_PQ_SESSION_PREFIX}${sessionId}`;
    const data = await client.get(key);

    if (!data) {
      cryptoLogger.debug('[PQ-SESSION] Session not found in Redis', {
        sessionId: sessionId.slice(0, 16) + '...',
        serverId: process.env.SERVER_ID
      });
      return null;
    }

    let parsed;
    try {
      parsed = JSON.parse(data);
      if (!parsed || typeof parsed !== 'object') {
        return null;
      }
    } catch {
      return null;
    }

    const recvKey = await decryptSessionKey(parsed.recvKey, parsed.sessionId, 'recv');
    const sendKey = await decryptSessionKey(parsed.sendKey, parsed.sessionId, 'send');

    const session = {
      sessionId: parsed.sessionId,
      recvKey,
      sendKey,
      fingerprint: parsed.fingerprint,
      establishedAt: parsed.establishedAt,
      counter: parsed.counter || 0
    };

    setCachedSession(sessionId, session);
    return session;
  });
}

export async function incrementPQSessionCounter(sessionId) {
  if (!sessionId) {
    return 0;
  }

  let nextCounter = 0;
  try {
    nextCounter = await withRedisClient(async (client) => {
      const counterKey = `${REDIS_PQ_COUNTER_PREFIX}${sessionId}`;
      const pipeline = client.pipeline();
      pipeline.incr(counterKey);
      pipeline.expire(counterKey, REDIS_PQ_SESSION_TTL);
      const results = await pipeline.exec();
      const value = results?.[0]?.[1];
      const parsed = Number.parseInt(String(value ?? '0'), 10);
      return Number.isFinite(parsed) ? parsed : 0;
    });
  } catch {
    nextCounter = 0;
  }

  try {
    const cached = getCachedSession(sessionId);
    if (cached) {
      if (nextCounter > 0) {
        cached.counter = nextCounter;
      } else {
        cached.counter = (cached.counter || 0) + 1;
        nextCounter = cached.counter;
      }
      setCachedSession(sessionId, cached);
    }
  } catch {
  }

  return nextCounter;
}

