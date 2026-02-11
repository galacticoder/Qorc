/**
 * User Database
 * 
 * Stores user records indexed by credentialId.
 */

import { getPgPool, anonId, safeJsonParseObject, crypto } from './core.js';

export class UserDatabase {

  static async loadUser(credentialId) {
    if (!credentialId || typeof credentialId !== 'string') {
      return null;
    }

    try {
      const pool = await getPgPool();
      const query = 'SELECT * FROM users WHERE "credentialId" = $1';

      const { rows } = await pool.query(query, [credentialId]);
      return rows[0] || null;
    } catch (error) {
      console.error(`[DB] Error loading user ${anonId(credentialId)}:`, error);
      return null;
    }
  }

  static async saveUserRecord(userRecord) {
    const { credentialId, opaqueRecord } = userRecord;

    if (!credentialId || typeof credentialId !== 'string') {
      throw new Error('Invalid credential ID');
    }

    try {
      const pool = await getPgPool();

      // Assign shard and index using randomization
      let { shard_id, credential_index } = userRecord;

      if (shard_id === undefined || credential_index === undefined) {
        const randomBytes = crypto.randomBytes(8);
        const randomValue = randomBytes.readBigUInt64BE(0);
        // Distribute across 1000 shards with 100 slots each (100k capacity, will make more later TODO)
        shard_id = Number(randomValue % 1000n);
        credential_index = Number((randomValue >> 10n) % 100n);
      }

      const result = await pool.query(
        `
        INSERT INTO users ("credentialId", "opaqueRecord", "hybridPublicKeys", "shard_id", "credential_index")
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT ("credentialId") DO UPDATE SET
          "opaqueRecord" = EXCLUDED."opaqueRecord",
          "hybridPublicKeys" = EXCLUDED."hybridPublicKeys",
          "shard_id" = COALESCE(users."shard_id", EXCLUDED."shard_id"),
          "credential_index" = COALESCE(users."credential_index", EXCLUDED."credential_index")
        RETURNING "shard_id", "credential_index"
      `,
        [
          credentialId,
          opaqueRecord,
          JSON.stringify(userRecord.hybridPublicKeys || {}),
          shard_id,
          credential_index
        ],
      );

      const actualShardId = result.rows[0].shard_id;
      const actualIndex = result.rows[0].credential_index;

      console.log(`[DB] Saved/Updated record for ${anonId(credentialId)}. Result: Shard ${actualShardId}, Index ${actualIndex}`);
      return { shard_id: actualShardId, credential_index: actualIndex };
    } catch (error) {
      console.error(`[DB] Error saving user record for ${anonId(credentialId)}:`, error);
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
      console.error(`[DB] Error loading shard ${shardId}:`, error);
      return [];
    }
  }

  static async updateHybridPublicKeys(credentialId, hybridPublicKeys) {
    if (!credentialId || typeof credentialId !== 'string') {
      return false;
    }

    try {
      const pool = await getPgPool();
      await pool.query(
        'UPDATE users SET "hybridPublicKeys" = $1 WHERE "credentialId" = $2',
        [JSON.stringify(hybridPublicKeys), credentialId],
      );
      console.log(`[DB] Updated hybrid keys for ${anonId(credentialId)}`);
      return true;
    } catch (error) {
      console.error(`[DB] Error updating hybrid keys for ${anonId(credentialId)}:`, error);
      return false;
    }
  }

  static async getHybridPublicKeys(credentialId) {
    if (!credentialId || typeof credentialId !== 'string') {
      return null;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "hybridPublicKeys" FROM users WHERE "credentialId" = $1',
        [credentialId],
      );
      if (!rows[0]) return null;
      const parsed = safeJsonParseObject(rows[0].hybridPublicKeys);
      if (!parsed) {
        console.warn('[DB] Failed to parse hybridPublicKeys JSON for user:', credentialId);
        return null;
      }
      return parsed;
    } catch (error) {
      console.error(`[DB] Error loading hybrid keys for ${anonId(credentialId)}:`, error);
      return null;
    }
  }

  // Load stored hybrid public keys
  static async getHybridPublicKeysByInbox(inboxId) {
    if (!inboxId || typeof inboxId !== 'string' || inboxId.length < 32) {
      return null;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "kyberPreKeyPublicBase64", "signedPreKeyPublicBase64", "identityKeyBase64" FROM libsignal_bundles WHERE "inboxId" = $1',
        [inboxId],
      );
      const row = rows[0];
      if (!row) return null;

      return {
        kyberPublicBase64: row.kyberPreKeyPublicBase64,
        dilithiumPublicBase64: row.signedPreKeyPublicBase64,
        inboxId: inboxId
      };
    } catch (error) {
      console.error('[DB] Error loading hybrid keys by inbox:', error);
      return null;
    }
  }
}
