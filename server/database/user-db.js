/**
 * User Database
 * 
 * Stores user records indexed by credentialId.
 */

import { getPgPool, crypto, privateLookupId, cryptoLogger } from './core.js';

const PRIVATE_AUTH_SHARD_SIZE = 2048;
const PRIVATE_AUTH_SHARD_COUNT = 1;

export class UserDatabase {
  static credentialLookupId(credentialId) {
    if (!credentialId || typeof credentialId !== 'string') {
      throw new Error('Invalid credential ID');
    }
    return privateLookupId('opaque-credential-id-v2', credentialId);
  }

  static async allocatePrivateAuthSlot(maxAttempts = 64) {
    const pool = await getPgPool();
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const shard_id = crypto.randomInt(0, PRIVATE_AUTH_SHARD_COUNT);
      const credential_index = crypto.randomInt(0, PRIVATE_AUTH_SHARD_SIZE);
      const { rows } = await pool.query(
        'SELECT 1 FROM users WHERE "shard_id" = $1 AND "credential_index" = $2 LIMIT 1',
        [shard_id, credential_index]
      );
      if (!rows[0]) {
        return { shard_id, credential_index, shard_size: PRIVATE_AUTH_SHARD_SIZE };
      }
    }
    throw new Error('Failed to allocate private auth slot');
  }

  static async saveUserRecord(userRecord) {
    const { credentialId, opaqueRecord } = userRecord;

    if (!credentialId || typeof credentialId !== 'string') {
      throw new Error('Invalid credential ID');
    }

    try {
      const pool = await getPgPool();

      let { shard_id, credential_index } = userRecord;

      if (shard_id === undefined || credential_index === undefined) {
        const slot = await this.allocatePrivateAuthSlot();
        shard_id = slot.shard_id;
        credential_index = slot.credential_index;
      }

      const result = await pool.query(
        `
        INSERT INTO users ("credentialId", "opaqueRecord", "shard_id", "credential_index")
        VALUES ($1, $2, $3, $4)
        ON CONFLICT ("credentialId") DO UPDATE SET
          "opaqueRecord" = EXCLUDED."opaqueRecord",
          "shard_id" = COALESCE(users."shard_id", EXCLUDED."shard_id"),
          "credential_index" = COALESCE(users."credential_index", EXCLUDED."credential_index")
        RETURNING "shard_id", "credential_index"
      `,
        [
          credentialId,
          opaqueRecord,
          shard_id,
          credential_index
        ],
      );

      const actualShardId = result.rows[0].shard_id;
      const actualIndex = result.rows[0].credential_index;

      cryptoLogger.info('[DB] Saved/Updated private auth record');
      return { shard_id: actualShardId, credential_index: actualIndex };
    } catch (error) {
      cryptoLogger.error('[DB] Error saving user record', { error: error?.message });
      throw error;
    }
  }

  static async getShardRecords(shardId) {
    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "credentialId", "opaqueRecord", "credential_index" FROM users WHERE "shard_id" = $1 ORDER BY "credential_index"',
        [shardId]
      );
      return rows;
    } catch (error) {
      cryptoLogger.error('[DB] Error loading private auth shard', { error: error?.message });
      return [];
    }
  }
}
