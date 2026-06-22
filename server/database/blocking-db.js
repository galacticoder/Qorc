/**
 * Blocking Database
 * 
 * Stores opaque encrypted block-list blobs by committed lookup ID
 */

import { getPgPool, cryptoLogger } from './core.js';

export class BlockingDatabase {
  // Store encrypted block list using an already committed private lookup ID
  static async storeEncryptedBlockListByLookupId(inboxLookupId, encryptedBlockList, blockListHash, salt) {
    if (!inboxLookupId || !encryptedBlockList) {
      return false;
    }
    try {
      const pool = await getPgPool();
      await pool.query(
        `INSERT INTO user_block_lists ("inboxId", "encryptedBlockList", "blockListHash", salt, "lastUpdated", version)
         VALUES ($1, $2, $3, $4, $5, 1)
         ON CONFLICT ("inboxId") DO UPDATE SET
           "encryptedBlockList" = EXCLUDED."encryptedBlockList",
           "blockListHash" = EXCLUDED."blockListHash",
           salt = EXCLUDED.salt,
           "lastUpdated" = EXCLUDED."lastUpdated",
           version = user_block_lists.version + 1`,
        [inboxLookupId, encryptedBlockList, blockListHash, salt, Date.now()]
      );
      return true;
    } catch (error) {
      cryptoLogger.error('[DB] Error storing encrypted block list', { error: error?.message });
      return false;
    }
  }

  // Retrieve encrypted block list using an already committed private lookup ID
  static async getEncryptedBlockListByLookupId(inboxLookupId) {
    if (!inboxLookupId) {
      return null;
    }
    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "encryptedBlockList", "blockListHash", salt, version FROM user_block_lists WHERE "inboxId" = $1',
        [inboxLookupId]
      );
      return rows[0] || null;
    } catch (error) {
      cryptoLogger.error('[DB] Error retrieving encrypted block list', { error: error?.message });
      return null;
    }
  }

}
