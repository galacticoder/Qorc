import crypto from 'crypto';

import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { privateLookupId } from '../database/core.js';
import { withRedisClient } from '../session/redis-client.js';
import { SHA_256_ALGORITHM } from '../utils/crypto-consts.js';
import { isCanonicalBase64Bytes } from '../utils/encoding.js';
import { POW_SEED_BYTES } from '../../shared/crypto-sizes.js';

export function deriveAnonymousRequestPowSeed(domain, epoch, powNonce, parts) {
  if (
    typeof domain !== 'string' ||
    !/^[a-z0-9-]{8,64}$/.test(domain) ||
    !isCanonicalBase64Bytes(powNonce, POW_SEED_BYTES) ||
    !Array.isArray(parts) ||
    parts.some((part) => typeof part !== 'string' || part.includes('\0'))
  ) {
    throw new Error('Invalid anonymous proof-of-work binding');
  }
  return crypto.createHash(SHA_256_ALGORITHM)
    .update([domain, String(epoch), powNonce, ...parts].join('\0'))
    .digest()
    .subarray(0, POW_SEED_BYTES)
    .toString('base64');
}

export async function reservePowNullifier(domain, digest, expiresAt) {
  const nullifier = privateLookupId(domain, digest);
  const ttlSeconds = Math.max(60, Math.ceil((expiresAt - Date.now()) / 1000) + 60);
  try {
    const result = await withRedisClient((client) => client.set(
      `${PROTOCOL_KEYS.ANONYMOUS_POW_REDIS_PREFIX}${nullifier}`,
      '1',
      'EX',
      ttlSeconds,
      'NX'
    ));
    return result === 'OK' ? 'claimed' : 'replayed';
  } catch {
    return 'unavailable';
  }
}

export async function claimAnonymousRequestPow(domain, powSeed, powSolution, expiresAt) {
  if (
    typeof domain !== 'string' ||
    typeof powSeed !== 'string' ||
    typeof powSolution !== 'string' ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= Date.now()
  ) return 'unavailable';

  const claimDigest = crypto.createHash(SHA_256_ALGORITHM)
    .update(domain)
    .update('\0')
    .update(powSeed)
    .update('\0')
    .update(powSolution)
    .digest('base64url');
  return reservePowNullifier(PROTOCOL_KEYS.ANONYMOUS_REQUEST_POW_CLAIM, claimDigest, expiresAt);
}
