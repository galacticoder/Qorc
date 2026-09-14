import crypto from 'node:crypto';
import { SHA_256_ALGORITHM } from '../utils/crypto-consts.js';
import { HASH_OUTPUT_BYTES } from '../../shared/crypto-sizes.js';

export function selectRandomRankEvictionIds(ids, cap, validateId) {
  const rankKey = crypto.randomBytes(HASH_OUTPUT_BYTES);
  try {
    const ranked = ids.map((id) => {
      if (!validateId(id)) throw new Error('Invalid eviction candidate');
      const digest = crypto.createHmac(SHA_256_ALGORITHM, rankKey).update(id, 'ascii').digest();
      try {
        return { id, rank: digest.toString('hex') };
      } finally {
        digest.fill(0);
      }
    });
    ranked.sort((a, b) => a.rank.localeCompare(b.rank));
    return ranked.slice(cap).map((entry) => entry.id);
  } finally {
    rankKey.fill(0);
  }
}
