/**
 * Blocking Database
 * 
 * Uses identity key commitments for blocking
 */

import { getPgPool, crypto } from './core.js';

export class BlockingDatabase {
  // Create block commitment from identity key hashes
  static computeBlockCommitment(blockerIdentityKeyHash, blockedIdentityKeyHash) {
    const serverSecret = process.env.BLOCK_SERVER_SECRET;
    if (!serverSecret) {
      throw new Error('BLOCK_SERVER_SECRET not configured');
    }

    return crypto.createHash('blake2b512')
      .update(`${serverSecret}:${blockerIdentityKeyHash}:${blockedIdentityKeyHash}`)
      .digest('hex')
      .slice(0, 64);
  }

  // Add a block using identity key commitment
  static async addBlock(blockerIdentityKeyHash, blockedIdentityKeyHash, expiresAt = null) {
    if (!blockerIdentityKeyHash || !blockedIdentityKeyHash) {
      return false;
    }

    try {
      const commitment = this.computeBlockCommitment(blockerIdentityKeyHash, blockedIdentityKeyHash);
      const pool = await getPgPool();
      await pool.query(
        `INSERT INTO block_tokens ("blockCommitment", "createdAt", "expiresAt")
         VALUES ($1, $2, $3)
         ON CONFLICT ("blockCommitment") DO UPDATE SET "expiresAt" = EXCLUDED."expiresAt"`,
        [commitment, Date.now(), expiresAt]
      );
      return true;
    } catch (error) {
      console.error('[DB] Error adding block:', error);
      return false;
    }
  }

  // Remove a block
  static async removeBlock(blockerIdentityKeyHash, blockedIdentityKeyHash) {
    if (!blockerIdentityKeyHash || !blockedIdentityKeyHash) {
      return false;
    }

    try {
      const commitment = this.computeBlockCommitment(blockerIdentityKeyHash, blockedIdentityKeyHash);
      const pool = await getPgPool();
      await pool.query('DELETE FROM block_tokens WHERE "blockCommitment" = $1', [commitment]);
      return true;
    } catch (error) {
      console.error('[DB] Error removing block:', error);
      return false;
    }
  }

  // Check if blocked using identity key commitment
  static async isBlocked(blockerIdentityKeyHash, blockedIdentityKeyHash) {
    if (!blockerIdentityKeyHash || !blockedIdentityKeyHash) {
      return false;
    }

    try {
      const commitment = this.computeBlockCommitment(blockerIdentityKeyHash, blockedIdentityKeyHash);
      const pool = await getPgPool();
      const { rows } = await pool.query(
        `SELECT 1 FROM block_tokens 
         WHERE "blockCommitment" = $1 
         AND ("expiresAt" IS NULL OR "expiresAt" > $2)`,
        [commitment, Date.now()]
      );
      return rows.length > 0;
    } catch (error) {
      console.error('[DB] Error checking block:', error);
      return false;
    }
  }

  // Store encrypted block list
  static async storeEncryptedBlockList(inboxId, encryptedBlockList, blockListHash, salt) {
    if (!inboxId || !encryptedBlockList) {
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
        [inboxId, encryptedBlockList, blockListHash, salt, Date.now()]
      );
      return true;
    } catch (error) {
      console.error('[DB] Error storing encrypted block list:', error);
      return false;
    }
  }

  // Retrieve encrypted block list
  static async getEncryptedBlockList(inboxId) {
    if (!inboxId) {
      return null;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT "encryptedBlockList", "blockListHash", salt, version FROM user_block_lists WHERE "inboxId" = $1',
        [inboxId]
      );
      return rows[0] || null;
    } catch (error) {
      console.error('[DB] Error retrieving encrypted block list:', error);
      return null;
    }
  }

  // Cleanup expired block tokens
  static async cleanupExpiredBlocks() {
    try {
      const pool = await getPgPool();
      const result = await pool.query(
        'DELETE FROM block_tokens WHERE "expiresAt" IS NOT NULL AND "expiresAt" < $1',
        [Date.now()]
      );
      return result.rowCount || 0;
    } catch (error) {
      console.error('[DB] Error cleaning up expired blocks:', error);
      return 0;
    }
  }
}
