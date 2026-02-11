/**
 * Offline Message Storage
 */

import { getPgPool } from './core.js';

export class MessageDatabase {
  // Queue offline message
  static async queueOfflineMessage(toInboxId, payloadObj) {
    if (!toInboxId || typeof toInboxId !== 'string' || toInboxId.length < 32) {
      console.error('[DB] Invalid toInboxId for offline message');
      return false;
    }

    if (!payloadObj || typeof payloadObj !== 'object') {
      console.error('[DB] Invalid payload for offline message');
      return false;
    }

    try {
      const payload = JSON.stringify(payloadObj);

      if (payload.length > 1048576) {
        console.error('[DB] Offline message payload too large');
        return false;
      }

      const queuedAt = Date.now();
      const pool = await getPgPool();
      await pool.query(
        'INSERT INTO offline_messages (toInboxId, payload, queuedAt) VALUES ($1, $2, $3)',
        [toInboxId, payload, queuedAt],
      );
      return true;
    } catch (error) {
      console.error('[DB] Error queueing offline message:', error);
      return false;
    }
  }

  // Retrieve and delete offline messages
  static async takeOfflineMessages(toInboxId, limit = 100) {
    if (!toInboxId || typeof toInboxId !== 'string' || toInboxId.length < 32) {
      return [];
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'DELETE FROM offline_messages WHERE id IN (SELECT id FROM offline_messages WHERE toInboxId = $1 ORDER BY queuedAt ASC LIMIT $2) RETURNING payload',
        [toInboxId, limit],
      );

      return rows.map(r => {
        try {
          return JSON.parse(r.payload);
        } catch {
          return null;
        }
      }).filter(Boolean);
    } catch (error) {
      console.error('[DB] Error taking offline messages:', error);
      return [];
    }
  }

  // Get count of pending messages for an inbox
  static async getOfflineMessageCount(toInboxId) {
    if (!toInboxId || typeof toInboxId !== 'string' || toInboxId.length < 32) {
      return 0;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT COUNT(*) FROM offline_messages WHERE toInboxId = $1',
        [toInboxId],
      );
      return parseInt(rows[0].count, 10);
    } catch (error) {
      console.error('[DB] Error counting offline messages:', error);
      return 0;
    }
  }

  // Cleanup old offline messages older than 30 days
  static async cleanupOldMessages() {
    try {
      const pool = await getPgPool();
      const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
      const result = await pool.query(
        'DELETE FROM offline_messages WHERE queuedAt < $1',
        [cutoff],
      );
      return result.rowCount || 0;
    } catch (error) {
      console.error('[DB] Error cleaning up old messages:', error);
      return 0;
    }
  }
}
