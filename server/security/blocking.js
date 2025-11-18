import { CryptoUtils } from '../crypto/unified-crypto.js';
import { BlockingDatabase } from '../database/database.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { withRedisClient } from '../presence/presence.js';

const BLOCKING_CACHE_TTL = 30; // 30 seconds TTL
const BLOCKING_RATE_LIMIT_WINDOW = 60; // 60 seconds
const BLOCKING_RATE_LIMIT_MAX = 100; // Max 100 checks per minute per user

/**
 * Normalize and validate a client-supplied pseudonymized username hash.
 */
function normalizeUserHash(username) {
  if (typeof username !== 'string') return '';
  const trimmed = username.trim();
  if (/^(?:[a-f0-9]{32}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return '';
}

/**
 * Check if sender is blocked by recipient
 * 
 * @param {string} senderUser - Sender username (pseudonymized hex)
 * @param {string} recipientUser - Recipient username (pseudonymized hex)
 * @returns {Promise<boolean>} - True if blocked, false otherwise
 */
export async function checkBlocking(senderUser, recipientUser) {
  if (!senderUser || !recipientUser || senderUser === recipientUser) {
    return false;
  }

  if (typeof senderUser !== 'string' || typeof recipientUser !== 'string') {
    cryptoLogger.warn('[BLOCKING] Invalid user parameters - not strings');
    return false;
  }

  if (senderUser.length === 0 || recipientUser.length === 0) {
    cryptoLogger.warn('[BLOCKING] Invalid user parameters - empty strings');
    return false;
  }

  if (senderUser.length > 256 || recipientUser.length > 256) {
    cryptoLogger.warn('[BLOCKING] Invalid user parameters - usernames too long');
    return false;
  }

  try {
    await enforceBlockingRateLimit(senderUser);

    // Validate client-supplied pseudonym hashes
    const senderHash = normalizeUserHash(senderUser);
    const recipientHash = normalizeUserHash(recipientUser);
    if (!senderHash || !recipientHash) {
      cryptoLogger.warn('[BLOCKING] Invalid pseudonym hash format');
      return false; 
    }

    const cacheKey = `block:${senderHash}:${recipientHash}`;
    
    // Check Redis cache
    const cached = await getFromRedisCache(cacheKey);
    if (cached !== null) {
      return cached;
    }
    
    // Cache miss - check database with timing attack protection
    const startTime = Date.now();
    const isBlocked = await BlockingDatabase.isMessageBlocked(senderHash, recipientHash);
    const dbTime = Date.now() - startTime;
    
    const minDelay = 50;
    if (dbTime < minDelay) {
      await new Promise(resolve => setTimeout(resolve, minDelay - dbTime));
    }
    
    // Store in Redis cache
    await setInRedisCache(cacheKey, isBlocked);
    
    return isBlocked;
    
  } catch (error) {
    cryptoLogger.error('[BLOCKING] Error in blocking check', error);
    return false;
  }
}

/**
 * Enforce rate limiting on blocking checks
 */
async function enforceBlockingRateLimit(username) {
  const rateLimitKey = `blocking:ratelimit:${Buffer.from(
    CryptoUtils.Hash.blake3(Buffer.from(username))
  ).toString('hex')}`;
  
  await withRedisClient(async (client) => {
    const count = await client.incr(rateLimitKey);
    if (count === 1) {
      await client.expire(rateLimitKey, BLOCKING_RATE_LIMIT_WINDOW);
    }
    if (count > BLOCKING_RATE_LIMIT_MAX) {
      throw new Error('Blocking check rate limit exceeded');
    }
  });
}

/**
 * Get blocking status from Redis cache
 */
async function getFromRedisCache(cacheKey) {
  try {
    return await withRedisClient(async (client) => {
      const value = await client.get(cacheKey);
      if (value === null) return null;
      return value === '1';
    });
  } catch (error) {
    cryptoLogger.warn('[BLOCKING] Redis cache read error', error);
    return null;
  }
}

/**
 * Set blocking status in Redis cache
 */
async function setInRedisCache(cacheKey, isBlocked) {
  try {
    await withRedisClient(async (client) => {
      await client.setex(cacheKey, BLOCKING_CACHE_TTL, isBlocked ? '1' : '0');
    });
  } catch (error) {
    cryptoLogger.warn('[BLOCKING] Redis cache write error', error);
  }
}

/**
 * Clear Redis cache for specific blocker/blocked relationships
 */
export async function clearBlockingCache(blockerHash, blockedHashes = []) {
  try {
    await withRedisClient(async (client) => {
      const keys = [];
      
      // Clear all cache entries for this blocker's relationships
      if (blockerHash && Array.isArray(blockedHashes)) {
        for (const blockedHash of blockedHashes) {
          if (blockedHash) {
            keys.push(`block:${blockerHash}:${blockedHash}`);
            keys.push(`block:${blockedHash}:${blockerHash}`);
          }
        }
      }
      
      if (keys.length > 0) {
        await client.del(...keys);
        cryptoLogger.info('[BLOCKING] Cache cleared', { count: keys.length });
      }
    });
  } catch (error) {
    cryptoLogger.warn('[BLOCKING] Cache clear error', error);
  }
}

/**
 * Export cache configuration for monitoring
 */
export const BLOCKING_CONFIG = {
  BLOCKING_CACHE_TTL,
  BLOCKING_RATE_LIMIT_WINDOW,
  BLOCKING_RATE_LIMIT_MAX,
};
