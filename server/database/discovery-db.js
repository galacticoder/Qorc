/**
 * OPRF Token Billboard
 * 
 * Stores opaque encrypted discovery blobs indexed by an OPRF-derived token
 */

import { getPgPool } from './core.js';

export class DiscoveryDB {
  // Store discovery entry
  static async store(token, encryptedBlob, expiresAt) {
    if (!token || !encryptedBlob) {
      console.warn('[DB][DISCOVERY] store rejected - missing fields', {
        hasToken: !!token,
        hasEncryptedBlob: !!encryptedBlob
      });
      return false;
    }

    try {
      const pool = await getPgPool();
      const res = await pool.query(
        `INSERT INTO discovery_billboard ("token", "encryptedBlob", "expiresAt")
         VALUES ($1, $2, $3)
         ON CONFLICT ("token") DO UPDATE SET
           "encryptedBlob" = EXCLUDED."encryptedBlob",
           "expiresAt" = EXCLUDED."expiresAt"`,
        [token, encryptedBlob, expiresAt]
      );

      console.log('[DB][DISCOVERY] store ok', {
        tokenPrefix: String(token).slice(0, 8),
        encryptedBlobLen: typeof encryptedBlob === 'string' ? encryptedBlob.length : null,
        expiresAt,
        rowCount: res?.rowCount ?? null
      });
      return true;
    } catch (error) {
      console.error('[DB][DISCOVERY] store failed', {
        tokenPrefix: String(token).slice(0, 8),
        error: error?.message || String(error)
      });
      return false;
    }
  }

  // Lookup discovery entry by token
  static async lookup(token) {
    if (!token) {
      console.warn('[DB][DISCOVERY] lookup rejected - missing token');
      return null;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        `SELECT "encryptedBlob", "expiresAt" FROM discovery_billboard 
         WHERE "token" = $1 AND "expiresAt" > $2`,
        [token, Date.now()]
      );

      const row = rows[0] || null;
      console.log('[DB][DISCOVERY] lookup result', {
        tokenPrefix: String(token).slice(0, 8),
        found: !!row,
        expiresAt: row?.expiresAt ?? null,
        encryptedBlobLen: typeof row?.encryptedBlob === 'string' ? row.encryptedBlob.length : null
      });
      return row;
    } catch (error) {
      console.error('[DB][DISCOVERY] lookup failed', {
        tokenPrefix: String(token).slice(0, 8),
        error: error?.message || String(error)
      });
      return null;
    }
  }

  // Remove discovery entry
  static async remove(token) {
    if (!token) {
      console.warn('[DB][DISCOVERY] remove rejected - missing token');
      return false;
    }

    try {
      const pool = await getPgPool();
      const res = await pool.query('DELETE FROM discovery_billboard WHERE "token" = $1', [token]);
      console.log('[DB][DISCOVERY] remove ok', {
        tokenPrefix: String(token).slice(0, 8),
        rowCount: res?.rowCount ?? null
      });
      return true;
    } catch (error) {
      console.error('[DB][DISCOVERY] remove failed', {
        tokenPrefix: String(token).slice(0, 8),
        error: error?.message || String(error)
      });
      return false;
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
        console.log(`[DB] Cleaned up ${count} expired discovery entries`);
      }
      return count;
    } catch (error) {
      console.error('[DB] Error cleaning up discovery entries:', error);
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
      console.error('[DB] Error counting discovery entries:', error);
      return 0;
    }
  }
}
