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

// offline_messages table removed

db.exec(`
  CREATE TABLE IF NOT EXISTS prekey_bundles (
    username TEXT PRIMARY KEY,
    		identityEd25519PublicBase64 TEXT NOT NULL,
		identityDilithiumPublicBase64 TEXT,
		identityX25519PublicBase64 TEXT NOT NULL,
    signedPreKeyId TEXT NOT NULL,
    signedPreKeyPublicBase64 TEXT NOT NULL,
    		signedPreKeyEd25519SignatureBase64 TEXT NOT NULL,
		signedPreKeyDilithiumSignatureBase64 TEXT,
    ratchetPublicBase64 TEXT NOT NULL,
    updatedAt INTEGER NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS one_time_prekeys (
    username TEXT NOT NULL,
    keyId TEXT NOT NULL,
    publicKeyBase64 TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    consumedAt INTEGER,
    PRIMARY KEY (username, keyId)
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

// OfflineMessageQueue removed

export class PrekeyDatabase {
  static publishBundle(username, bundle) {
    const now = Date.now();
    db.prepare(`
      INSERT INTO prekey_bundles (
        username, 		identityEd25519PublicBase64, identityDilithiumPublicBase64, identityX25519PublicBase64,
		signedPreKeyId, signedPreKeyPublicBase64, signedPreKeyEd25519SignatureBase64, signedPreKeyDilithiumSignatureBase64,
        ratchetPublicBase64, updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        		identityEd25519PublicBase64=excluded.identityEd25519PublicBase64,
		identityDilithiumPublicBase64=excluded.identityDilithiumPublicBase64,
		identityX25519PublicBase64=excluded.identityX25519PublicBase64,
		signedPreKeyId=excluded.signedPreKeyId,
		signedPreKeyPublicBase64=excluded.signedPreKeyPublicBase64,
		signedPreKeyEd25519SignatureBase64=excluded.signedPreKeyEd25519SignatureBase64,
		signedPreKeyDilithiumSignatureBase64=excluded.signedPreKeyDilithiumSignatureBase64,
        ratchetPublicBase64=excluded.ratchetPublicBase64,
        updatedAt=excluded.updatedAt
    `).run(
      username,
      bundle.identityEd25519PublicBase64,
      bundle.identityDilithiumPublicBase64,
      bundle.identityX25519PublicBase64,
      bundle.signedPreKey.id,
      bundle.signedPreKey.publicKeyBase64,
      bundle.signedPreKey.ed25519SignatureBase64,
      bundle.signedPreKey.dilithiumSignatureBase64,
      //prefer ratchet and use signed prekey pub if not available
      bundle.ratchetPublicBase64 || bundle.signedPreKey.publicKeyBase64,
      now
    );

    db.prepare(`DELETE FROM one_time_prekeys WHERE username = ?`).run(username);
    if (Array.isArray(bundle.oneTimePreKeys)) {
      const insertStmt = db.prepare(`INSERT INTO one_time_prekeys (username, keyId, publicKeyBase64, consumed) VALUES (?, ?, ?, 0)`);
      const insertMany = db.transaction((rows) => {
        for (const r of rows) insertStmt.run(username, r.id, r.publicKeyBase64);
      });
      insertMany(bundle.oneTimePreKeys);
    }
  }

  static takeBundleForRecipient(username) {
    const bundle = db.prepare(`SELECT * FROM prekey_bundles WHERE username = ?`).get(username);
    if (!bundle) return null;
    const ot = db.prepare(`SELECT keyId, publicKeyBase64 FROM one_time_prekeys WHERE username = ? AND consumed = 0 ORDER BY keyId LIMIT 1`).get(username);
    if (ot) {
      db.prepare(`UPDATE one_time_prekeys SET consumed = 1, consumedAt = ? WHERE username = ? AND keyId = ?`).run(Date.now(), username, ot.keyId);
    }
    return {
      username,
      identityEd25519PublicBase64: bundle.identityEd25519PublicBase64,
      identityDilithiumPublicBase64: bundle.identityDilithiumPublicBase64,
      identityX25519PublicBase64: bundle.identityX25519PublicBase64,
      signedPreKey: {
        id: bundle.signedPreKeyId,
        publicKeyBase64: bundle.signedPreKeyPublicBase64,
        ed25519SignatureBase64: bundle.signedPreKeyEd25519SignatureBase64,
        dilithiumSignatureBase64: bundle.signedPreKeyDilithiumSignatureBase64
      },
      ratchetPublicBase64: bundle.ratchetPublicBase64,
      oneTimePreKey: ot ? { id: ot.keyId, publicKeyBase64: ot.publicKeyBase64 } : null
    };
  }
}
