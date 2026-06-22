/**
 * Unlinkable avatar content store (server side).
 *
 * Stores uniform-size, E2E-encrypted avatar PURBs keyed only by an opaque client chosen random
 * blobId. There is intentionally no owner/token/identity column. the server must not be able to
 * link a stored avatar to a user. Uploads are anonymous(Privacy Pass gated at the route. the
 * {blobId, key} pointer lives only inside the discovery keys blob ciphertext the server cannot read
 */

import crypto from 'crypto';
import { getPgPool, cryptoLogger } from './core.js';

// Expected base64 length of a PURB
export const AVATAR_PURB_WIRE_BYTES = 36 + 32 + (256 * 1024 + 32);
export const AVATAR_BLOB_B64_CHARS = 4 * Math.ceil(AVATAR_PURB_WIRE_BYTES / 3);
const B64_TOLERANCE = 4;

const BLOB_ID_RE = /^[a-f0-9]{64}$/;

export function isValidAvatarBlobId(blobId) {
  return typeof blobId === 'string' && BLOB_ID_RE.test(blobId);
}

export function isValidAvatarBlobData(data) {
  return typeof data === 'string'
    && Math.abs(data.length - AVATAR_BLOB_B64_CHARS) <= B64_TOLERANCE;
}

/**
 * Deterministic unpredictable miss response identical size to a real blob
 */
export function syntheticMissBlob(blobId, missSecret) {
  const want = AVATAR_PURB_WIRE_BYTES;
  const out = Buffer.allocUnsafe(want);
  let off = 0;
  let counter = 0;
  const secret = missSecret || 'qor-avatar-miss-v1';
  while (off < want) {
    const chunk = crypto.createHmac('sha256', secret)
      .update(String(blobId))
      .update('\0')
      .update(Buffer.from([counter & 0xff, (counter >> 8) & 0xff, (counter >> 16) & 0xff, (counter >> 24) & 0xff]))
      .digest();
    const n = Math.min(chunk.length, want - off);
    chunk.copy(out, off, 0, n);
    off += n;
    counter += 1;
  }
  return out.toString('base64');
}

export class AvatarBlobDB {
  // Store or refresh one PURB
  static async store(blobId, data, expiresAt, publishedAt = Date.now()) {
    if (!isValidAvatarBlobId(blobId) || !isValidAvatarBlobData(data)) {
      cryptoLogger.warn('[DB][AVATAR] store rejected - bad blobId/data', {
        hasBlobId: isValidAvatarBlobId(blobId),
        dataLen: typeof data === 'string' ? data.length : null
      });
      return false;
    }
    try {
      const pool = await getPgPool();
      const res = await pool.query(
        `INSERT INTO avatar_blobs ("blobId", "data", "expiresAt", "publishedAt")
         VALUES ($1, $2, $3, $4)
         ON CONFLICT ("blobId") DO UPDATE SET
           "data" = EXCLUDED."data",
           "expiresAt" = EXCLUDED."expiresAt",
           "publishedAt" = EXCLUDED."publishedAt"`,
        [blobId, data, expiresAt, publishedAt]
      );
      return (res?.rowCount ?? 0) > 0;
    } catch (error) {
      cryptoLogger.error('[DB][AVATAR] store failed', { error: error?.message || String(error) });
      return false;
    }
  }

  // Fetch one PURB by id
  static async get(blobId, now = Date.now()) {
    if (!isValidAvatarBlobId(blobId)) return null;
    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "data" FROM avatar_blobs WHERE "blobId" = $1 AND "expiresAt" > $2 LIMIT 1',
        [blobId, now]
      );
      return rows.length > 0 ? rows[0].data : null;
    } catch (error) {
      cryptoLogger.error('[DB][AVATAR] get failed', { error: error?.message || String(error) });
      return null;
    }
  }

  // A random sample of currently valid blobIds for clients to draw cover traffic decoys from
  static async samplePool(limit = 256, now = Date.now()) {
    const capped = Math.min(Math.max(Number(limit) || 256, 1), 1024);
    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "blobId" FROM avatar_blobs WHERE "expiresAt" > $1 ORDER BY random() LIMIT $2',
        [now, capped]
      );
      return rows.map((r) => r.blobId);
    } catch (error) {
      cryptoLogger.error('[DB][AVATAR] samplePool failed', { error: error?.message || String(error) });
      return [];
    }
  }

  static async pruneExpired(now = Date.now()) {
    try {
      const pool = await getPgPool();
      const res = await pool.query('DELETE FROM avatar_blobs WHERE "expiresAt" < $1', [now]);
      return res?.rowCount ?? 0;
    } catch (error) {
      cryptoLogger.error('[DB][AVATAR] pruneExpired failed', { error: error?.message || String(error) });
      return 0;
    }
  }
}
