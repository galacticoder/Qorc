import path from 'path';
import { fileURLToPath } from 'url';
import DatabaseDriver from 'better-sqlite3';
import { CryptoUtils } from '../crypto/unified-crypto.js';

const DB_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'user_database.sqlite');
const db = new DatabaseDriver(DB_PATH);

console.log('[DB] Initializing database at:', DB_PATH);

// Check if we need to migrate the messages table
const checkMigration = () => {
  try {
    const tableInfo = db.prepare("PRAGMA table_info(messages)").all();
    const hasNewColumns = tableInfo.some(col => col.name === 'fromUsername');

    if (!hasNewColumns) {
      console.log('[DB] Migrating messages table to add performance columns...');

      // Add new columns
      db.exec(`ALTER TABLE messages ADD COLUMN fromUsername TEXT`);
      db.exec(`ALTER TABLE messages ADD COLUMN toUsername TEXT`);
      db.exec(`ALTER TABLE messages ADD COLUMN timestamp INTEGER`);

      // Populate new columns from existing data
      const messages = db.prepare("SELECT id, messageId, payload FROM messages").all();
      const updateStmt = db.prepare(`
        UPDATE messages
        SET fromUsername = ?, toUsername = ?, timestamp = ?
        WHERE id = ?
      `);

      messages.forEach(row => {
        try {
          const payload = JSON.parse(row.payload);
          updateStmt.run(
            payload.fromUsername || '',
            payload.toUsername || '',
            payload.timestamp || Date.now(),
            row.id
          );
        } catch (e) {
          console.warn(`[DB] Failed to migrate message ${row.id}:`, e);
        }
      });

      console.log(`[DB] Migrated ${messages.length} messages`);
    }
  } catch (error) {
    console.warn('[DB] Migration check failed:', error);
  }
};

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
    payload TEXT NOT NULL,
    fromUsername TEXT NOT NULL,
    toUsername TEXT NOT NULL,
    timestamp INTEGER NOT NULL
  );
`);

// Run migration check
checkMigration();

// Create indexes for much faster queries
db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(fromUsername);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(toUsername);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_participants ON messages(fromUsername, toUsername);`);

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
  CREATE TABLE IF NOT EXISTS libsignal_bundles (
    username TEXT PRIMARY KEY,
    registrationId INTEGER NOT NULL,
    deviceId INTEGER NOT NULL,
    identityKeyBase64 TEXT NOT NULL,
    preKeyId INTEGER,
    preKeyPublicBase64 TEXT,
    signedPreKeyId INTEGER NOT NULL,
    signedPreKeyPublicBase64 TEXT NOT NULL,
    signedPreKeySignatureBase64 TEXT NOT NULL,
    kyberPreKeyId INTEGER NOT NULL,
    kyberPreKeyPublicBase64 TEXT NOT NULL,
    kyberPreKeySignatureBase64 TEXT NOT NULL,
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
      const fromUsername = decryptedPayload.fromUsername;
      const toUsername = decryptedPayload.toUsername;
      const timestamp = decryptedPayload.timestamp || Date.now();

      if (!messageId || !fromUsername || !toUsername) {
        console.error('[DB] Missing required fields in decrypted payload:', { messageId, fromUsername, toUsername });
        return;
      }

      console.log(`[DB] Saving message with ID: ${messageId}`);
      console.log(`[DB] Message from: ${fromUsername}, to: ${toUsername}`);

      // Use prepared statement with indexed columns for much faster performance
      db.prepare(`
        INSERT INTO messages (messageId, payload, fromUsername, toUsername, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(messageId) DO UPDATE SET
          payload = excluded.payload,
          fromUsername = excluded.fromUsername,
          toUsername = excluded.toUsername,
          timestamp = excluded.timestamp
      `).run(messageId, stringifiedPayload, fromUsername, toUsername, timestamp);

      console.log(`[DB] Message saved successfully to database: ${messageId}`);
    } catch (error) {
      console.error('[DB] Error saving message to database:', error);
      throw error;
    }
  }

  static getMessagesForUser(username, limit = 50) {
    console.log(`[DB] Loading messages for user: ${username}, limit: ${limit}`);
    try {
      // Use indexed columns instead of JSON extraction for 100x faster queries
      const stmt = db.prepare(`
        SELECT id, messageId, payload, fromUsername, toUsername, timestamp
        FROM messages
        WHERE fromUsername = ? OR toUsername = ?
        ORDER BY timestamp DESC
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

export class LibsignalBundleDB {
  static publish(username, bundle) {
    const now = Date.now();
    db.prepare(`
      INSERT INTO libsignal_bundles (
        username, registrationId, deviceId, identityKeyBase64,
        preKeyId, preKeyPublicBase64,
        signedPreKeyId, signedPreKeyPublicBase64, signedPreKeySignatureBase64,
        kyberPreKeyId, kyberPreKeyPublicBase64, kyberPreKeySignatureBase64,
        updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        registrationId=excluded.registrationId,
        deviceId=excluded.deviceId,
        identityKeyBase64=excluded.identityKeyBase64,
        preKeyId=excluded.preKeyId,
        preKeyPublicBase64=excluded.preKeyPublicBase64,
        signedPreKeyId=excluded.signedPreKeyId,
        signedPreKeyPublicBase64=excluded.signedPreKeyPublicBase64,
        signedPreKeySignatureBase64=excluded.signedPreKeySignatureBase64,
        kyberPreKeyId=excluded.kyberPreKeyId,
        kyberPreKeyPublicBase64=excluded.kyberPreKeyPublicBase64,
        kyberPreKeySignatureBase64=excluded.kyberPreKeySignatureBase64,
        updatedAt=excluded.updatedAt
    `).run(
      username,
      bundle.registrationId,
      bundle.deviceId,
      bundle.identityKeyBase64,
      bundle.preKeyId ?? null,
      bundle.preKeyPublicBase64 ?? null,
      bundle.signedPreKeyId,
      bundle.signedPreKeyPublicBase64,
      bundle.signedPreKeySignatureBase64,
      bundle.kyberPreKeyId,
      bundle.kyberPreKeyPublicBase64,
      bundle.kyberPreKeySignatureBase64,
      now
    );
  }

  static take(username) {
    const row = db.prepare(`SELECT * FROM libsignal_bundles WHERE username = ?`).get(username);
    if (!row) return null;
    return {
      registrationId: row.registrationId,
      deviceId: row.deviceId,
      identityKeyBase64: row.identityKeyBase64,
      preKeyId: row.preKeyId,
      preKeyPublicBase64: row.preKeyPublicBase64,
      signedPreKeyId: row.signedPreKeyId,
      signedPreKeyPublicBase64: row.signedPreKeyPublicBase64,
      signedPreKeySignatureBase64: row.signedPreKeySignatureBase64,
      kyberPreKeyId: row.kyberPreKeyId,
      kyberPreKeyPublicBase64: row.kyberPreKeyPublicBase64,
      kyberPreKeySignatureBase64: row.kyberPreKeySignatureBase64,
    };
  }
}
