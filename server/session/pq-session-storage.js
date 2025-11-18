import { withRedisClient } from '../presence/presence.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';

/**
 */

const REDIS_PQ_SESSION_PREFIX = 'pq:session:';
const REDIS_PQ_SESSION_TTL = 3600; // 1 hour TTL

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

/**
 * Store PQ session in Redis
 * @param {string} sessionId - Session identifier
 * @param {Object} sessionData - Session data containing keys and metadata
 */
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
  });

  cryptoLogger.info('[PQ-SESSION] Stored in Redis (encrypted)', {
    sessionId: sessionId.slice(0, 16) + '...',
    serverId: process.env.SERVER_ID
  });
}

/**
 * Retrieve PQ session from Redis
 * @param {string} sessionId - Session identifier
 * @returns {Object|null} - Session data or null if not found
 */
export async function getPQSession(sessionId) {
  if (!sessionId) {
    return null;
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

    const parsed = JSON.parse(data);

    const recvKey = await decryptSessionKey(parsed.recvKey, parsed.sessionId, 'recv');
    const sendKey = await decryptSessionKey(parsed.sendKey, parsed.sessionId, 'send');

    return {
      sessionId: parsed.sessionId,
      recvKey,
      sendKey,
      fingerprint: parsed.fingerprint,
      establishedAt: parsed.establishedAt,
      counter: parsed.counter || 0
    };
  });
}

/**
 * Update PQ session counter (for replay protection)
 * @param {string} sessionId - Session identifier
 * @param {number} counter - New counter value
 */
export async function updatePQSessionCounter(sessionId, counter) {
  if (!sessionId) {
    return;
  }

  const session = await getPQSession(sessionId);
  if (session) {
    session.counter = counter;
    await storePQSession(sessionId, session);
  }
}

/**
 * Delete PQ session
 * @param {string} sessionId - Session identifier
 */
export async function deletePQSession(sessionId) {
  if (!sessionId) {
    return;
  }

  await withRedisClient(async (client) => {
    const key = `${REDIS_PQ_SESSION_PREFIX}${sessionId}`;
    await client.del(key);
  });

  cryptoLogger.info('[PQ-SESSION] Deleted from Redis', {
    sessionId: sessionId.slice(0, 16) + '...',
    serverId: process.env.SERVER_ID
  });
}

/**
 * Get all PQ session keys from Redis (for monitoring/debugging)
 */
export async function getAllPQSessionKeys() {
  return await withRedisClient(async (client) => {
    const keys = await client.keys(`${REDIS_PQ_SESSION_PREFIX}*`);
    return keys.map(key => key.replace(REDIS_PQ_SESSION_PREFIX, ''));
  });
}

/**
 * Get statistics about PQ sessions
 */
export async function getPQSessionStats() {
  const keys = await getAllPQSessionKeys();
  return {
    sessionCount: keys.length,
    redisPrefix: REDIS_PQ_SESSION_PREFIX,
    sessionTTL: REDIS_PQ_SESSION_TTL
  };
}
