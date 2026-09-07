/**
 * Unlinkable avatar content store
 */

import crypto from 'crypto';
import { getPgPool, withTransaction } from './core.js';
import { selectRandomRankEvictionIds } from './random-rank-eviction.js';
import {
  AES_256_CTR,
  AES_256_CTR_IV_BYTES,
  AVATAR_MISS_SECRET_BYTES,
  BASE64_ALPHABET,
  POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES,
  POST_QUANTUM_AEAD_TAG_BYTES,
  SHA_256_ALGORITHM
} from '../utils/crypto-consts.js';
import { CANONICAL_BASE64_RE, HEX_64_RE } from '../utils/patterns.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

// Expected base64 length of a PURB
export const AVATAR_PURB_WIRE_BYTES =
  POST_QUANTUM_AEAD_NONCE_BYTES +
  POST_QUANTUM_AEAD_TAG_BYTES +
  (256 * 1024 + POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES);
export const AVATAR_BLOB_B64_CHARS = 4 * Math.ceil(AVATAR_PURB_WIRE_BYTES / 3);

export function isValidAvatarBlobId(blobId) {
  return typeof blobId === 'string' && HEX_64_RE.test(blobId);
}

export function isValidAvatarBlobData(data) {
  if (
    typeof data !== 'string' ||
    data.length !== AVATAR_BLOB_B64_CHARS ||
    !CANONICAL_BASE64_RE.test(data)
  ) return false;
  const padding = data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0;
  const decodedBytes = (data.length / 4) * 3 - padding;
  if (decodedBytes !== AVATAR_PURB_WIRE_BYTES) return false;
  if (padding === 2) return (BASE64_ALPHABET.indexOf(data[data.length - 3]) & 0x0f) === 0;
  if (padding === 1) return (BASE64_ALPHABET.indexOf(data[data.length - 2]) & 0x03) === 0;
  return true;
}

/**
 * Deterministic unpredictable miss response identical size to a real blob
 */
export function syntheticMissBlob(blobId, missSecret) {
  if (!isValidAvatarBlobId(blobId)) {
    throw new Error('Invalid avatar blob id');
  }
  if (!Buffer.isBuffer(missSecret) || missSecret.length !== AVATAR_MISS_SECRET_BYTES) {
    throw new Error('Avatar miss secret must be a 32-byte Buffer');
  }

  const want = AVATAR_PURB_WIRE_BYTES;
  const streamKey = crypto.createHmac(SHA_256_ALGORITHM, missSecret)
    .update(PROTOCOL_KEYS.AVATAR_MISS_KEY)
    .update(blobId, 'ascii')
    .digest();
  const streamIvMaterial = crypto.createHmac(SHA_256_ALGORITHM, missSecret)
    .update(PROTOCOL_KEYS.AVATAR_MISS_IV)
    .update(blobId, 'ascii')
    .digest();
  const streamIv = streamIvMaterial.subarray(0, AES_256_CTR_IV_BYTES);
  const zeroes = Buffer.alloc(want);
  let output = null;
  let tail = null;
  let combined = null;

  try {
    const cipher = crypto.createCipheriv(AES_256_CTR, streamKey, streamIv);
    output = cipher.update(zeroes);
    tail = cipher.final();
    if (tail.length === 0) return output.toString('base64');
    combined = Buffer.concat([output, tail], want);
    return combined.toString('base64');
  } finally {
    zeroes.fill(0);
    output?.fill(0);
    tail?.fill(0);
    combined?.fill(0);
    streamKey.fill(0);
    streamIvMaterial.fill(0);
  }
}

export class AvatarBlobDB {
  // Store or refresh one PURB
  static async store(blobId, data, expiresAt) {
    const now = Date.now();
    if (
      !isValidAvatarBlobId(blobId) ||
      !isValidAvatarBlobData(data) ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= now
    ) {
      console.warn('[DB][AVATAR] store rejected - bad blobId/data', {
        hasBlobId: isValidAvatarBlobId(blobId),
        dataLen: typeof data === 'string' ? data.length : null
      });
      return false;
    }
    try {
      const pool = await getPgPool();
      const res = await pool.query(
        `INSERT INTO avatar_blobs ("blobId", "data", "expiresAt")
         VALUES ($1, $2, $3)
         ON CONFLICT ("blobId") DO UPDATE SET
           "expiresAt" = GREATEST(avatar_blobs."expiresAt", EXCLUDED."expiresAt")
         WHERE avatar_blobs."data" = EXCLUDED."data"`,
        [blobId, data, expiresAt]
      );
      return res.rowCount > 0;
    } catch (error) {
      console.error('[DB][AVATAR] store failed', { error: error?.message || String(error) });
      throw error;
    }
  }

  static async getMany(blobIds, now = Date.now()) {
    const valid = Array.from(new Set((Array.isArray(blobIds) ? blobIds : []).filter(isValidAvatarBlobId)));
    const out = new Map();
    if (valid.length === 0) return out;
    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "blobId", "data" FROM avatar_blobs WHERE "blobId" = ANY($1) AND "expiresAt" > $2',
        [valid, now]
      );
      for (const row of rows) {
        if (
          !isValidAvatarBlobId(row?.blobId) ||
          !valid.includes(row.blobId) ||
          out.has(row.blobId) ||
          !isValidAvatarBlobData(row?.data)
        ) {
          throw new Error('invalid_avatar_blob_row');
        }
        out.set(row.blobId, row.data);
      }
      return out;
    } catch (error) {
      console.error('[DB][AVATAR] getMany failed', { error: error?.message || String(error) });
      throw error;
    }
  }

  // random sample of currently valid blobIds for clients to draw cover traffic decoys from
  static async samplePool(limit = 256, now = Date.now()) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024) {
      throw new Error('Invalid avatar pool limit');
    }
    const pivotBytes = crypto.randomBytes(32);
    let pivot;
    try {
      pivot = pivotBytes.toString('hex');
    } finally {
      pivotBytes.fill(0);
    }
    try {
      const pool = await getPgPool();
      const first = await pool.query(
        `SELECT "blobId" FROM avatar_blobs
         WHERE "expiresAt" > $1 AND "blobId" >= $2
         ORDER BY "blobId" ASC LIMIT $3`,
        [now, pivot, limit]
      );
      const ids = first.rows.map((row) => row.blobId);
      if (ids.length < limit) {
        const wrapped = await pool.query(
          `SELECT "blobId" FROM avatar_blobs
           WHERE "expiresAt" > $1 AND "blobId" < $2
           ORDER BY "blobId" ASC LIMIT $3`,
          [now, pivot, limit - ids.length]
        );
        ids.push(...wrapped.rows.map((row) => row.blobId));
      }
      return ids.filter(isValidAvatarBlobId);
    } catch (error) {
      console.error('[DB][AVATAR] samplePool failed', { error: error?.message || String(error) });
      throw error;
    }
  }

  static async pruneExpired(now = Date.now()) {
    try {
      const pool = await getPgPool();
      const res = await pool.query('DELETE FROM avatar_blobs WHERE "expiresAt" < $1', [now]);
      return res.rowCount;
    } catch (error) {
      console.error('[DB][AVATAR] pruneExpired failed', { error: error?.message || String(error) });
      throw error;
    }
  }

  // Bound total disk usage
  static async enforceCap(maxRows) {
    if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 100_000) {
      throw new Error('Invalid avatar storage cap');
    }
    let client;
    try {
      const pool = await getPgPool();
      client = await pool.connect();
      return await withTransaction(client, async () => {
        await client.query('SELECT pg_advisory_xact_lock(1364156997)');
        await client.query('LOCK TABLE avatar_blobs IN SHARE ROW EXCLUSIVE MODE');
        const now = Date.now();
        const expired = await client.query(
          'DELETE FROM avatar_blobs WHERE "expiresAt" <= $1',
          [now]
        );
        const { rows } = await client.query('SELECT "blobId" FROM avatar_blobs');
        if (rows.length <= maxRows) return expired.rowCount;

        const evictedIds = selectRandomRankEvictionIds(
          rows.map((row) => row?.blobId),
          maxRows,
          isValidAvatarBlobId
        );
        const evicted = await client.query(
          'DELETE FROM avatar_blobs WHERE "blobId" = ANY($1)',
          [evictedIds]
        );
        return expired.rowCount + evicted.rowCount;
      });
    } catch (error) {
      console.error('[DB][AVATAR] enforceCap failed', { error: error?.message || String(error) });
      throw error;
    } finally {
      client?.release();
    }
  }
}
