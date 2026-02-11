/**
 * Capability Token System
 * 
 * Provides anonymous, short lived tokens for WebSocket authentication.
 */

import crypto from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient } from '../session/redis-client.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';

// Token configuration
const CAPABILITY_TOKEN_TTL = 300;
const CAPABILITY_TOKEN_BYTES = 64;
const INBOX_ID_BYTES = 64;
const PQ_NONCE_BYTES = 32;

// Inbox rotation configuration
export const INBOX_ROTATION_INTERVAL_MS = parseInt(process.env.INBOX_ROTATION_INTERVAL_MS || String(60 * 60 * 1000), 10);

export const OWNERSHIP_PROOF_VALIDITY_MS = parseInt(process.env.OWNERSHIP_PROOF_VALIDITY_MS || String(5 * 60 * 1000), 10);

// Redis key prefixes
const CAPABILITY_KEY_PREFIX = 'cap:token:';
const INBOX_KEY_PREFIX = 'inbox:';

/**
 * Generate capability token
 */
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

/**
 * Generate inbox ID
 */
export function generateInboxId() {
  const primaryEntropy = crypto.randomBytes(INBOX_ID_BYTES);
  const secondaryEntropy = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(PQ_NONCE_BYTES);
  
  const combined = Buffer.concat([primaryEntropy, secondaryEntropy, nonce]);
  const inboxBytes = blake3(combined, { dkLen: INBOX_ID_BYTES });
  
  return Buffer.from(inboxBytes).toString('base64url');
}

/**
 * Store a capability token with its associated inbox claims
 */
export async function storeCapabilityToken(token, inboxIds, options = {}) {
  const { ttl = CAPABILITY_TOKEN_TTL } = options;
  
  const tokenData = {
    inboxIds: Array.isArray(inboxIds) ? inboxIds : [inboxIds],
    createdAt: Date.now(),
    expiresAt: Date.now() + (ttl * 1000),
  };
  
  await withRedisClient(async (client) => {
    const key = `${CAPABILITY_KEY_PREFIX}${token}`;
    await client.setex(key, ttl, JSON.stringify(tokenData));
  });
  
  return tokenData;
}

/**
 * Validate a capability token and return claimed inbox IDs
 */
export async function validateCapabilityToken(token) {
  if (!token || typeof token !== 'string' || token.length < 32) {
    return { valid: false, error: 'invalid_token_format' };
  }
  
  try {
    return await withRedisClient(async (client) => {
      const key = `${CAPABILITY_KEY_PREFIX}${token}`;
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
        inboxIds: tokenData.inboxIds,
        expiresAt: tokenData.expiresAt
      };
    });
  } catch (error) {
    cryptoLogger.error('[CAPABILITY] Token validation error', { error: error.message });
    return { valid: false, error: 'validation_error' };
  }
}

/**
 * Revoke a capability token
 */
export async function revokeCapabilityToken(token) {
  try {
    await withRedisClient(async (client) => {
      const key = `${CAPABILITY_KEY_PREFIX}${token}`;
      await client.del(key);
    });
    return true;
  } catch (error) {
    cryptoLogger.error('[CAPABILITY] Token revocation error', { error: error.message });
    return false;
  }
}

/**
 * Register an inbox for message delivery
 */
export async function registerInbox(inboxId, socketInfo) {
  const { socketId, serverId } = socketInfo;
  
  const inboxData = {
    socketId,
    serverId: serverId || process.env.SERVER_ID || 'default',
    registeredAt: Date.now(),
  };
  
  await withRedisClient(async (client) => {
    const key = `${INBOX_KEY_PREFIX}${inboxId}`;
    await client.setex(key, 600, JSON.stringify(inboxData));
  });
  
  return inboxData;
}

/**
 * Look up which socket an inbox routes to
 */
export async function lookupInbox(inboxId) {
  if (!inboxId || typeof inboxId !== 'string') {
    return null;
  }
  
  try {
    return await withRedisClient(async (client) => {
      const key = `${INBOX_KEY_PREFIX}${inboxId}`;
      const data = await client.get(key);
      
      if (!data) {
        return null;
      }
      
      return JSON.parse(data);
    });
  } catch (error) {
    cryptoLogger.error('[INBOX] Lookup error', { error: error.message });
    return null;
  }
}

/**
 * Unregister an inbox
 */
export async function unregisterInbox(inboxId) {
  try {
    await withRedisClient(async (client) => {
      const key = `${INBOX_KEY_PREFIX}${inboxId}`;
      await client.del(key);
    });
    return true;
  } catch (error) {
    cryptoLogger.error('[INBOX] Unregister error', { error: error.message });
    return false;
  }
}

/**
 * Create ownership proof challenge for an inbox
 */
export function createOwnershipProofChallenge(inboxId) {
  const nonce = crypto.randomBytes(PQ_NONCE_BYTES).toString('base64');
  const timestamp = Date.now();
  
  const challengeData = `${inboxId}:${timestamp}:${nonce}`;
  
  const commitment = Buffer.from(
    blake3(Buffer.from(challengeData))
  ).toString('base64');
  
  return {
    challenge: challengeData,
    commitment,
    inboxId,
    timestamp,
    nonce,
    expiresAt: timestamp + 30000
  };
}

/**
 * Verify inbox ownership proof
 */
export async function verifyOwnershipProof(challenge, signature, publicKeyBase64) {
  try {
    const parts = challenge.split(':');
    if (parts.length !== 3) {
      return { valid: false, error: 'invalid_challenge_format' };
    }
    
    const [inboxId, timestampStr, nonce] = parts;
    const timestamp = parseInt(timestampStr, 10);
    
    if (Date.now() > timestamp + 30000) {
      return { valid: false, error: 'challenge_expired' };
    }
    
    const signatureBytes = Buffer.from(signature, 'base64');
    if (signatureBytes.length < 2000) {
      return { valid: false, error: 'invalid_signature_size' };
    }
    
    // Verify Dilithium signature
    const challengeBytes = new TextEncoder().encode(challenge);
    const publicKeyBytes = Buffer.from(publicKeyBase64, 'base64');
    
    const isValid = await CryptoUtils.Dilithium.verify(
      challengeBytes,
      signatureBytes,
      publicKeyBytes
    );
    
    if (!isValid) {
      return { valid: false, error: 'dilithium_signature_invalid' };
    }
    
    // Create binding hash
    const bindingHash = Buffer.from(
      blake3(Buffer.concat([challengeBytes, signatureBytes]))
    ).toString('base64');
    
    return {
      valid: true,
      inboxId,
      bindingHash,
    };
  } catch (error) {
    cryptoLogger.error('[OWNERSHIP] Dilithium verification error', { error: error.message });
    return { valid: false, error: 'verification_error' };
  }
}

/**
 * Rotate inbox IDs for a capability token
 */
export async function rotateInboxes(token, oldInboxIds, newInboxIds) {
  try {
    // Validate token first
    const validation = await validateCapabilityToken(token);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }
    
    // Verify old inbox IDs match
    const currentInboxes = new Set(validation.inboxIds);
    for (const oldId of oldInboxIds) {
      if (!currentInboxes.has(oldId)) {
        return { success: false, error: 'inbox_mismatch' };
      }
    }
    
    // Update token with new inbox IDs
    const remainingTtl = Math.floor((validation.expiresAt - Date.now()) / 1000);
    if (remainingTtl <= 0) {
      return { success: false, error: 'token_expired' };
    }
    
    // Replace old with new
    const updatedInboxes = validation.inboxIds.filter(id => !oldInboxIds.includes(id));
    updatedInboxes.push(...newInboxIds);
    
    await storeCapabilityToken(token, updatedInboxes, { ttl: remainingTtl });
    
    // Unregister old inboxes
    for (const oldId of oldInboxIds) {
      await unregisterInbox(oldId);
    }
    
    return { success: true, newInboxIds };
  } catch (error) {
    cryptoLogger.error('[INBOX] Rotation error', { error: error.message });
    return { success: false, error: 'rotation_error' };
  }
}

export const CapabilityTokens = {
  generateCapabilityToken,
  generateInboxId,
  storeCapabilityToken,
  validateCapabilityToken,
  revokeCapabilityToken,
  registerInbox,
  lookupInbox,
  unregisterInbox,
  createOwnershipProofChallenge,
  verifyOwnershipProof,
  rotateInboxes
};
