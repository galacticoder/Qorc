/**
 * Opaque discovery publication store
 */

import { getPgPool, withTransaction } from './core.js';
import { selectRandomRankEvictionIds } from './random-rank-eviction.js';
import {
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_STORED_PUBLICATION_CAP,
  isCanonicalDiscoveryBlob,
  isCanonicalDiscoveryBucketIds
} from '../discovery/bucket-layout.js';
import { HEX_64_RE } from '../utils/patterns.js';

const DISCOVERY_BLOB_FETCH_MAX = 512;

function isPublishId(value) {
  return typeof value === 'string' && HEX_64_RE.test(value);
}

export class DiscoveryDB {
  static async storePublication(publishId, bucketIds, encryptedBlob, expiresAt) {
    const now = Date.now();
    if (
      !isPublishId(publishId) ||
      !isCanonicalDiscoveryBucketIds(bucketIds) ||
      !isCanonicalDiscoveryBlob(encryptedBlob) ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= now
    ) {
      return 0;
    }

    try {
      const pool = await getPgPool();
      const result = await pool.query(
        `INSERT INTO discovery_billboard ("publishId", "bucketIds", "encryptedBlob", "expiresAt")
         VALUES ($1, $2, $3, $4)
         ON CONFLICT ("publishId") DO UPDATE SET
           "bucketIds" = EXCLUDED."bucketIds",
           "encryptedBlob" = EXCLUDED."encryptedBlob",
           "expiresAt" = EXCLUDED."expiresAt"`,
        [publishId, bucketIds, encryptedBlob, expiresAt]
      );
      return result?.rowCount ?? 0;
    } catch (error) {
      console.error('[DB][DISCOVERY] publication store failed', {
        error: error?.message || String(error)
      });
      return 0;
    }
  }

  static async snapshotActiveMetadata(maxRows = 4096, maxBytes = null) {
    const capped = Number.isSafeInteger(maxRows)
      ? Math.min(Math.max(maxRows, 1), 100_000)
      : 4096;
    const byteCap = Number.isSafeInteger(maxBytes) && maxBytes > 0
      ? maxBytes
      : null;
    const rowLimit = byteCap === null
      ? capped
      : Math.min(capped, Math.floor(byteCap / DISCOVERY_BLOB_BASE64_CHARS));

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        `SELECT "publishId", "bucketIds", "expiresAt"
         FROM discovery_billboard
         WHERE "expiresAt" > $1
         ORDER BY "expiresAt" DESC, "publishId" ASC
         LIMIT $2`,
        [Date.now(), rowLimit]
      );

      const normalized = rows.map((row) => ({
          publishId: row.publishId,
          bucketIds: row.bucketIds,
          expiresAt: Number(row.expiresAt)
        }));
      if (normalized.some((row) => !(
          isPublishId(row.publishId) &&
          isCanonicalDiscoveryBucketIds(row.bucketIds) &&
          Number.isSafeInteger(row.expiresAt)
        ))) {
        throw new Error('invalid_discovery_snapshot_row');
      }
      const validatedAt = Date.now();
      return normalized.filter((row) => row.expiresAt > validatedAt);
    } catch (error) {
      console.error('[DB][DISCOVERY] snapshot failed');
      throw error;
    }
  }

  static async getActiveBlobsByPublishIds(publishIds) {
    if (!Array.isArray(publishIds) || publishIds.length < 1 || publishIds.length > DISCOVERY_BLOB_FETCH_MAX) {
      throw new Error('invalid_discovery_blob_selection');
    }
    const ids = Array.from(new Set(publishIds));
    if (ids.length !== publishIds.length || ids.some((publishId) => !isPublishId(publishId))) {
      throw new Error('invalid_discovery_blob_selection');
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        `SELECT "publishId", "encryptedBlob"
         FROM discovery_billboard
         WHERE "expiresAt" > $1 AND "publishId" = ANY($2::text[])`,
        [Date.now(), ids]
      );
      const blobs = new Map();
      for (const row of rows) {
        if (!isPublishId(row.publishId) || !isCanonicalDiscoveryBlob(row.encryptedBlob)) {
          throw new Error('invalid_discovery_blob_row');
        }
        blobs.set(row.publishId, row.encryptedBlob);
      }
      return blobs;
    } catch (error) {
      console.error('[DB][DISCOVERY] selected blob fetch failed');
      throw error;
    }
  }

  static async cleanup() {
    let removed = 0;
    try {
      const pool = await getPgPool();
      const result = await pool.query(
        'DELETE FROM discovery_billboard WHERE "expiresAt" <= $1',
        [Date.now()]
      );
      removed = result.rowCount || 0;
    } catch (error) {
      console.error('[DB][DISCOVERY] cleanup failed', { error: error?.message || String(error) });
    }
    return removed + await this.enforceCap(DISCOVERY_STORED_PUBLICATION_CAP);
  }

  static async enforceCap(maxRows = DISCOVERY_STORED_PUBLICATION_CAP) {
    const cap = Number.isSafeInteger(maxRows)
      ? Math.min(Math.max(maxRows, 1), 100_000)
      : DISCOVERY_STORED_PUBLICATION_CAP;
    let client;
    try {
      const pool = await getPgPool();
      client = await pool.connect();
      return await withTransaction(client, async () => {
        await client.query('SELECT pg_advisory_xact_lock(1364156996)');
        await client.query('LOCK TABLE discovery_billboard IN SHARE ROW EXCLUSIVE MODE');
        const expired = await client.query(
          'DELETE FROM discovery_billboard WHERE "expiresAt" <= $1',
          [Date.now()]
        );
        const { rows } = await client.query('SELECT "publishId" FROM discovery_billboard');
        if (rows.length <= cap) return expired?.rowCount ?? 0;

        const evictedIds = selectRandomRankEvictionIds(
          rows.map((row) => row?.publishId),
          cap,
          isPublishId
        );
        const evicted = await client.query(
          'DELETE FROM discovery_billboard WHERE "publishId" = ANY($1::text[])',
          [evictedIds]
        );
        return (expired?.rowCount ?? 0) + (evicted?.rowCount ?? 0);
      });
    } catch (error) {
      console.error('[DB][DISCOVERY] enforceCap failed', {
        error: error?.message || String(error)
      });
      return 0;
    } finally {
      client?.release();
    }
  }
}
