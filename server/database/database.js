import path from 'path';
import { fileURLToPath } from 'url';
import DatabaseDriver from 'better-sqlite3';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const DB_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'user_database.sqlite');
const db = new DatabaseDriver(DB_PATH);

//users info table
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

//message history table
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    messageId TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL
  );
`);

export class UserDatabase {
  static loadUser(username) {
    const row = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
    if (!row) return null;
    return row;
  }

  static saveUserRecord(userRecord) { // save or update user info in db
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
  }
}

export class MessageDatabase {
  static async saveMessageInDB(payload, privateKey) {
    const decryptedPayload = await CryptoUtils.Decrypt.decryptAndFormatPayload(payload, privateKey);
    const stringifiedPayload = JSON.stringify(decryptedPayload);
    const messageId = decryptedPayload.id;

    db.prepare(`
      INSERT INTO messages (messageId, payload)
      VALUES (?, ?)
      ON CONFLICT(messageId) DO UPDATE SET
        payload = excluded.payload
    `).run(messageId, stringifiedPayload);

    console.log(`Saved message '${messageId}' from '${decryptedPayload.from}' to db`);
  }

  static getMessagesForUser(username, limit = 50) {
    const stmt = db.prepare(`
      SELECT id, messageId, payload FROM messages
      WHERE json_extract(payload, '$.from') = ?
         OR json_extract(payload, '$.to') = ?
      ORDER BY COALESCE(json_extract(payload, '$.timestamp'), 0) DESC
      LIMIT ?
    `);

    const rows = stmt.all(username, username, limit);

    return rows.map(row => ({
      dbId: row.id,
      messageId: row.messageId,//payload id
      ...JSON.parse(row.payload)
    }));
  } //add get message by id func later for speed
}
