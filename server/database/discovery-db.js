/**
 * OPRF Token Billboard
 * 
 * Stores opaque encrypted discovery blobs indexed by an OPRF-derived token
 */

import { getPgPool, privateLookupId, cryptoLogger } from './core.js';
import crypto from 'crypto';

function discoveryTokenLookup(token) {
  return privateLookupId('discovery-token-v2', token);
}

export function deriveDiscoveryPirSlotKey(token) {
  const normalized = typeof token === 'string' ? token.trim().toLowerCase() : '';
  if (!/^[a-f0-9]{64}$/i.test(normalized)) {
    throw new Error('invalid_discovery_token_for_pir_slot');
  }
  return crypto
    .createHash('sha256')
    .update('qor-discovery-pir-slot-key-v1')
    .update('\0')
    .update(normalized)
    .update('\0')
    .digest('base64url');
}

export class DiscoveryDB {
  // Store or refresh one account's K-anon discovery entry for the current epoch
  static async storeBucketEntry(epochId, bucketId, publishId, encryptedBlob, expiresAt, publishedAt = Date.now()) {
    const eid = typeof epochId === 'string' ? epochId.trim() : '';
    const bid = Number.isInteger(bucketId) ? bucketId : Number.parseInt(bucketId, 10);
    const pid = typeof publishId === 'string' ? publishId.trim() : '';
    if (!eid || !Number.isInteger(bid) || bid < 0 || !pid || !/^[a-f0-9]{16,128}$/i.test(pid) || !encryptedBlob) {
      cryptoLogger.warn('[DB][DISCOVERY] store rejected - missing/invalid fields', {
        hasEpoch: !!eid, bucketIdValid: Number.isInteger(bid) && bid >= 0, hasPublishId: !!pid, hasBlob: !!encryptedBlob
      });
      return 0;
    }

    try {
      const pool = await getPgPool();
      const res = await pool.query(
        `INSERT INTO discovery_billboard ("epochId", "bucketId", "publishId", "encryptedBlob", "expiresAt", "publishedAt")
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT ("epochId", "publishId") DO UPDATE SET
           "bucketId" = EXCLUDED."bucketId",
           "encryptedBlob" = EXCLUDED."encryptedBlob",
           "expiresAt" = EXCLUDED."expiresAt",
           "publishedAt" = EXCLUDED."publishedAt"`,
        [eid, bid, pid, encryptedBlob, expiresAt, publishedAt]
      );
      cryptoLogger.info('[DB][DISCOVERY] store ok', {
        bucketId: bid,
        encryptedBlobLen: typeof encryptedBlob === 'string' ? encryptedBlob.length : null,
        expiresAt, publishedAt, rowCount: res?.rowCount ?? null
      });
      return res?.rowCount ?? 1;
    } catch (error) {
      cryptoLogger.error('[DB][DISCOVERY] store failed', {
        error: error?.message || String(error)
      });
      return 0;
    }
  }

  // Return a target free private retrieval snapshot
  static async snapshotActive(maxRows = 50000) {
    try {
      const capped = Math.min(Math.max(Number(maxRows) || 50000, 1), 200000);
      const pool = await getPgPool();
      const { rows } = await pool.query(
        `SELECT "epochId", "bucketId", "encryptedBlob", "expiresAt", "publishedAt" FROM discovery_billboard
         WHERE "expiresAt" > $1
         ORDER BY "expiresAt" DESC
         LIMIT $2`,
        [Date.now(), capped]
      );
      return rows.map((row) => ({
        epochId: row.epochId,
        bucketId: row.bucketId,
        encryptedBlob: row.encryptedBlob,
        expiresAt: row.expiresAt,
        publishedAt: row.publishedAt
      }));
    } catch (error) {
      cryptoLogger.error('[DB][DISCOVERY] snapshot failed', {
        error: error?.message || String(error)
      });
      return [];
    }
  }

  static async snapshotSince(publishedAfter, maxRows = 50000) {
    try {
      const capped = Math.min(Math.max(Number(maxRows) || 50000, 1), 200000);
      const since = Math.max(0, Math.trunc(Number(publishedAfter) || 0));
      const pool = await getPgPool();
      const { rows } = await pool.query(
        `SELECT "epochId", "bucketId", "encryptedBlob", "expiresAt", "publishedAt" FROM discovery_billboard
         WHERE "expiresAt" > $1 AND "publishedAt" > $2
         ORDER BY "publishedAt" DESC
         LIMIT $3`,
        [Date.now(), since, capped]
      );
      return rows.map((row) => ({
        epochId: row.epochId,
        bucketId: row.bucketId,
        encryptedBlob: row.encryptedBlob,
        expiresAt: row.expiresAt,
        publishedAt: row.publishedAt
      }));
    } catch (error) {
      cryptoLogger.error('[DB][DISCOVERY] delta snapshot failed', {
        error: error?.message || String(error)
      });
      return [];
    }
  }

  // Cleanup expired entries
  static async cleanup() {
    try {
      const pool = await getPgPool();
      const result = await pool.query(
        'DELETE FROM discovery_billboard WHERE "expiresAt" < $1',
        [Date.now()]
      );
      const count = result.rowCount || 0;
      if (count > 0) {
        cryptoLogger.info('[DB] Cleaned up expired discovery entries', { count });
      }
      return count;
    } catch (error) {
      cryptoLogger.error('[DB] Error cleaning up discovery entries', { error: error?.message });
      return 0;
    }
  }

  // Get entry count
  static async getCount() {
    try {
      const pool = await getPgPool();
      const { rows } = await pool.query('SELECT COUNT(*) FROM discovery_billboard');
      return parseInt(rows[0].count, 10);
    } catch (error) {
      cryptoLogger.error('[DB] Error counting discovery entries', { error: error?.message });
      return 0;
    }
  }
}
