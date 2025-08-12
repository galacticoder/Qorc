import path from 'path';
import { fileURLToPath } from 'url';
import DatabaseDriver from 'better-sqlite3';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const DB_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'user_database.sqlite');

const db = new DatabaseDriver(DB_PATH);

//create users table
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

//create message history table
db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL
  );
`);

export class UserDatabase {
  static loadUser(username) {
    const row = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
    if (!row) return null;
    return row;
  }

  static saveUserRecord(userRecord) { //save or update user info in db
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
export class MessageDatabase{
  static async saveMessageInDB(payload, privateKey) {
    const decryptedPayload = await CryptoUtils.Decrypt.decryptAndFormatPayload(payload, privateKey);
    const stringifiedPayload = JSON.stringify(decryptedPayload);
    console.log("STRINGIFIED: ", stringifiedPayload)
    db.prepare(`
      INSERT INTO messages (payload)
      VALUES (?)
    `).run(stringifiedPayload);
    console.log(`Saved message from '${decryptedPayload.from}' to db: ${decryptedPayload}`)
  }
  
  static getMessagesForUser(username, limit = 50) {
    const stmt = db.prepare(`
      SELECT id, payload FROM messages
      WHERE json_extract(payload, '$.from') = ?
        OR json_extract(payload, '$.to') = ?
      ORDER BY COALESCE(json_extract(payload, '$.timestamp'), 0) DESC
      LIMIT ?
    `);

    const rows = stmt.all(username, username, limit);

    console.log(`Found ${rows.length} messages for user '${username}':`);
    rows.forEach(row => {
      console.log(` - id: ${row.id}, payload: ${row.payload}`);
    });

    return rows.map(row => ({
      id: row.id,
      ...JSON.parse(row.payload)
    }));
  }
}