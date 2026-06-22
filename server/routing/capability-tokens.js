/**
 * Capability Token System
 *
 * Provides anonymous, short lived tokens for WebSocket authentication.
 * Server visible routing uses client committed rendezvous IDs only
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient } from '../session/redis-client.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { privateRedisKey } from '../database/core.js';

const CAPABILITY_TOKEN_TTL = 300;
const CAPABILITY_TOKEN_BYTES = 64;

const CAPABILITY_KEY_PREFIX = 'cap:token:';

function capabilityTokenKey(token) {
  return privateRedisKey(CAPABILITY_KEY_PREFIX, 'capability-token-v2', token);
}

export function isRouteLookupId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{64,128}$/.test(value);
}

export function generateCapabilityToken() {
  const rawBytes = crypto.randomBytes(CAPABILITY_TOKEN_BYTES);
  const additionalEntropy = crypto.randomBytes(32);
  const timestamp = Buffer.from(Date.now().toString());

  const mixed = blake3(Buffer.concat([rawBytes, additionalEntropy, timestamp]));
  const tokenBytes = Buffer.concat([rawBytes, mixed]);
  const token = tokenBytes.toString('base64url');
  const jitter = crypto.randomInt(50, 200);

  return {
    token,
    jitter,
    createdAt: Date.now(),
    expiresAt: Date.now() + (CAPABILITY_TOKEN_TTL * 1000)
  };
}

export async function storeCapabilityToken(token, _claims = [], options = {}) {
  const { ttl = CAPABILITY_TOKEN_TTL } = options;
  const tokenData = {
    createdAt: Date.now(),
    expiresAt: Date.now() + (ttl * 1000)
  };

  await withRedisClient(async (client) => {
    const key = capabilityTokenKey(token);
    await client.setex(key, ttl, JSON.stringify(tokenData));
  });

  return tokenData;
}

export async function validateCapabilityToken(token) {
  if (!token || typeof token !== 'string' || token.length < 32) {
    return { valid: false, error: 'invalid_token_format' };
  }

  try {
    return await withRedisClient(async (client) => {
      const key = capabilityTokenKey(token);
      const data = await client.get(key);

      if (!data) {
        return { valid: false, error: 'token_not_found' };
      }

      const tokenData = JSON.parse(data);

      if (Date.now() > tokenData.expiresAt) {
        await client.del(key);
        return { valid: false, error: 'token_expired' };
      }

      return {
        valid: true,
        expiresAt: tokenData.expiresAt
      };
    });
  } catch (error) {
    cryptoLogger.error('[CAPABILITY] Token validation error', { error: error.message });
    return { valid: false, error: 'validation_error' };
  }
}

export async function revokeCapabilityToken(token) {
  try {
    await withRedisClient(async (client) => {
      const key = capabilityTokenKey(token);
      await client.del(key);
    });
    return true;
  } catch (error) {
    cryptoLogger.error('[CAPABILITY] Token revocation error', { error: error.message });
    return false;
  }
}

export const CapabilityTokens = {
  generateCapabilityToken,
  storeCapabilityToken,
  validateCapabilityToken,
  revokeCapabilityToken,
  isRouteLookupId,
};
