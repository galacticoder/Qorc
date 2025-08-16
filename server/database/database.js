import path from 'path';
import { fileURLToPath } from 'url';
import DatabaseDriver from 'better-sqlite3';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const DB_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'user_database.sqlite');
const db = new DatabaseDriver(DB_PATH);

console.log('[DB] Initializing database at:', DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    passwordHash TEXT,
    passphraseHash TEXT,
    version INTEGER,
    algorithm TEXT,
    salt TEXT,
    memoryCost INTEGER,
    timeCost INTEGER,
    parallelism INTEGER
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    messageId TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL
  );
`);

console.log('[DB] Database tables initialized');

export class UserDatabase {
  static loadUser(username) {
    console.log(`[DB] Loading user from database: ${username}`);
    const row = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
    if (!row) {
      console.log(`[DB] User not found in database: ${username}`);
      return null;
    }
    console.log(`[DB] User loaded successfully: ${username}`);
    return row;
  }

  static saveUserRecord(userRecord) {
    console.log(`[DB] Saving user record to database: ${userRecord.username}`);
    try {
      db.prepare(`
        INSERT INTO users (
          username, passwordHash, passphraseHash,
          version, algorithm, salt, memoryCost, timeCost, parallelism
        )
        VALUES (@username, @passwordHash, @passphraseHash,
          @version, @algorithm, @salt, @memoryCost, @timeCost, @parallelism)
        ON CONFLICT(username) DO UPDATE SET
          passwordHash = excluded.passwordHash,
          passphraseHash = excluded.passphraseHash,
          version = excluded.version,
          algorithm = excluded.algorithm,
          salt = excluded.salt,
          memoryCost = excluded.memoryCost,
          timeCost = excluded.timeCost,
          parallelism = excluded.parallelism
      `).run(userRecord);
      console.log(`[DB] User record saved successfully: ${userRecord.username}`);
    } catch (error) {
      console.error(`[DB] Error saving user record for ${userRecord.username}:`, error);
      throw error;
    }
  }
}

export class MessageDatabase {
  static async saveMessageInDB(payload, serverHybridKeyPair) {
    console.log('[DB] Starting message save to database');
    try {
      const decryptedPayload = await CryptoUtils.Hybrid.decryptHybridPayload(payload, serverHybridKeyPair);
      const stringifiedPayload = JSON.stringify(decryptedPayload);
      const messageId = decryptedPayload.messageId;

      if (!messageId) {
        console.error('[DB] No messageId found in decrypted payload');
        return;
      }

      console.log(`[DB] Saving message with ID: ${messageId}`);
      console.log(`[DB] Message from: ${decryptedPayload.fromUsername}, to: ${decryptedPayload.toUsername}`);

      db.prepare(`
        INSERT INTO messages (messageId, payload)
        VALUES (?, ?)
        ON CONFLICT(messageId) DO UPDATE SET
          payload = excluded.payload
      `).run(messageId, stringifiedPayload);

      console.log(`[DB] Message saved successfully to database: ${messageId}`);
    } catch (error) {
      console.error('[DB] Error saving message to database:', error);
      throw error;
    }
  }

  static getMessagesForUser(username, limit = 50) {
    console.log(`[DB] Loading messages for user: ${username}, limit: ${limit}`);
    try {
      const stmt = db.prepare(`
        SELECT id, messageId, payload FROM messages
        WHERE json_extract(payload, '$.fromUsername') = ?
           OR json_extract(payload, '$.toUsername') = ?
        ORDER BY COALESCE(json_extract(payload, '$.timestamp'), 0) DESC
        LIMIT ?
      `);

      const rows = stmt.all(username, username, limit);
      console.log(`[DB] Loaded ${rows.length} messages for user: ${username}`);

      return rows.map(row => {
        const payload = JSON.parse(row.payload);
        return {
          dbId: row.id,
          messageId: row.messageId,
          ...payload,
          encryptedContent: payload.encryptedContent,
          replyTo: payload.replyTo ? {
            ...payload.replyTo,
            encryptedContent: payload.replyTo.encryptedContent
          } : undefined
        };
      });
    } catch (error) {
      console.error(`[DB] Error loading messages for user ${username}:`, error);
      return [];
    }
  }
}
