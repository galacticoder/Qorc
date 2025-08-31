import path from 'path';
import { fileURLToPath } from 'url';
import DatabaseDriver from 'better-sqlite3';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { randomBytes } from 'crypto';

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

// Offline message queue (encrypted payloads per recipient)
db.exec(`
  CREATE TABLE IF NOT EXISTS offline_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    toUsername TEXT NOT NULL,
    payload TEXT NOT NULL,
    queuedAt INTEGER NOT NULL
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

// Table for securely storing one-time prekey private keys
db.exec(`
  CREATE TABLE IF NOT EXISTS one_time_prekey_private_keys (
    username TEXT NOT NULL,
    keyId TEXT NOT NULL,
    encryptedPrivateKeyBase64 TEXT NOT NULL,
    salt TEXT NOT NULL,
    iv TEXT NOT NULL,
    createdAt INTEGER NOT NULL,
    PRIMARY KEY (username, keyId),
    FOREIGN KEY (username, keyId) REFERENCES one_time_prekeys(username, keyId) ON DELETE CASCADE
  );
`);

console.log('[DB] Database tables initialized');

export class UserDatabase {
  static loadUser(username) {
    // SECURITY: Validate username parameter
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username parameter: ${username}`);
      return null;
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format: ${username}`);
      return null;
    }
    
    console.log(`[DB] Loading user from database: ${username}`);
    try {
      const row = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
      if (!row) {
        console.log(`[DB] User not found in database: ${username}`);
        return null;
      }
      console.log(`[DB] User loaded successfully: ${username}`);
      return row;
    } catch (error) {
      console.error(`[DB] Error loading user ${username}:`, error);
      return null;
    }
  }

  static saveUserRecord(userRecord) {
    // SECURITY: Validate user record structure
    if (!userRecord || typeof userRecord !== 'object') {
      console.error('[DB] Invalid user record structure');
      throw new Error('Invalid user record structure');
    }
    
    const { username, passwordHash, passphraseHash } = userRecord;
    
    // SECURITY: Validate required fields
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username in user record: ${username}`);
      throw new Error('Invalid username in user record');
    }
    
    if (!passwordHash || typeof passwordHash !== 'string' || passwordHash.length < 10) {
      console.error('[DB] Invalid password hash in user record');
      throw new Error('Invalid password hash in user record');
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format in user record: ${username}`);
      throw new Error('Invalid username format in user record');
    }
    
    console.log(`[DB] Saving user record to database: ${username}`);
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
      console.log(`[DB] User record saved successfully: ${username}`);
    } catch (error) {
      console.error(`[DB] Error saving user record for ${username}:`, error);
      throw error;
    }
  }
}

export class MessageDatabase {
  static async saveMessageInDB(payload, serverHybridKeyPair) {
    console.log('[DB] Starting message save to database');
    
    // SECURITY: Validate inputs
    if (!payload || typeof payload !== 'object') {
      console.error('[DB] Invalid payload structure');
      throw new Error('Invalid payload structure');
    }
    
    if (!serverHybridKeyPair) {
      console.error('[DB] Server hybrid key pair not provided');
      throw new Error('Server hybrid key pair not provided');
    }
    
    try {
      const decryptedPayload = await CryptoUtils.Hybrid.decryptHybridPayload(payload, serverHybridKeyPair);
      
      // SECURITY: Validate decrypted payload structure
      if (!decryptedPayload || typeof decryptedPayload !== 'object') {
        console.error('[DB] Invalid decrypted payload structure');
        throw new Error('Invalid decrypted payload structure');
      }
      
      const messageId = decryptedPayload.messageId;
      const fromUsername = decryptedPayload.fromUsername;
      const toUsername = decryptedPayload.toUsername;
      const timestamp = decryptedPayload.timestamp || Date.now();

      // SECURITY: Validate required fields
      if (!messageId || typeof messageId !== 'string' || messageId.length < 1 || messageId.length > 255) {
        console.error('[DB] Invalid messageId in decrypted payload:', messageId);
        throw new Error('Invalid messageId in decrypted payload');
      }
      
      if (!fromUsername || typeof fromUsername !== 'string' || fromUsername.length < 3 || fromUsername.length > 32) {
        console.error('[DB] Invalid fromUsername in decrypted payload:', fromUsername);
        throw new Error('Invalid fromUsername in decrypted payload');
      }
      
      if (!toUsername || typeof toUsername !== 'string' || toUsername.length < 3 || toUsername.length > 32) {
        console.error('[DB] Invalid toUsername in decrypted payload:', toUsername);
        throw new Error('Invalid toUsername in decrypted payload');
      }
      
      // SECURITY: Validate username formats
      if (!/^[a-zA-Z0-9_-]+$/.test(fromUsername)) {
        console.error('[DB] Invalid fromUsername format:', fromUsername);
        throw new Error('Invalid fromUsername format');
      }
      
      if (!/^[a-zA-Z0-9_-]+$/.test(toUsername)) {
        console.error('[DB] Invalid toUsername format:', toUsername);
        throw new Error('Invalid toUsername format');
      }
      
      // SECURITY: Validate timestamp
      if (!Number.isInteger(timestamp) || timestamp < 0 || timestamp > Date.now() + 86400000) { // Allow 1 day future
        console.error('[DB] Invalid timestamp in decrypted payload:', timestamp);
        throw new Error('Invalid timestamp in decrypted payload');
      }

      // SECURITY: Sanitize payload for storage (remove potentially dangerous content)
      const sanitizedPayload = {
        messageId: decryptedPayload.messageId,
        fromUsername: decryptedPayload.fromUsername,
        toUsername: decryptedPayload.toUsername,
        timestamp: timestamp,
        encryptedContent: decryptedPayload.encryptedContent,
        messageType: decryptedPayload.messageType,
        // Only include safe fields, exclude any potentially dangerous ones
      };
      
      const stringifiedPayload = JSON.stringify(sanitizedPayload);
      
      // SECURITY: Validate payload size to prevent DoS
      if (stringifiedPayload.length > 1048576) { // 1MB limit
        console.error('[DB] Payload too large for storage:', stringifiedPayload.length);
        throw new Error('Payload too large for storage');
      }

      console.log(`[DB] Saving message with ID: ${messageId}`);
      console.log(`[DB] Message from: ${fromUsername}, to: ${toUsername}`);

      // Use prepared statement with indexed columns for much faster performance
      const stmt = db.prepare(`
        INSERT INTO messages (messageId, payload, fromUsername, toUsername, timestamp)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(messageId) DO UPDATE SET
          payload = excluded.payload,
          fromUsername = excluded.fromUsername,
          toUsername = excluded.toUsername,
          timestamp = excluded.timestamp
      `);
      
      stmt.run(messageId, stringifiedPayload, fromUsername, toUsername, timestamp);

      console.log(`[DB] Message saved successfully to database: ${messageId}`);
    } catch (error) {
      console.error('[DB] Error saving message to database:', error.message);
      throw new Error(`Failed to save message to database: ${error.message}`);
    }
  }

  static getMessagesForUser(username, limit = 50) {
    // SECURITY: Validate inputs
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error('[DB] Invalid username parameter for getMessagesForUser');
      return [];
    }
    
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
      console.error('[DB] Invalid limit parameter - must be integer between 1 and 1000');
      return [];
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error('[DB] Invalid username format for getMessagesForUser');
      return [];
    }
    
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
        try {
          const payload = JSON.parse(row.payload);
          // SECURITY: Validate parsed payload structure
          if (!payload || typeof payload !== 'object') {
            console.warn('[DB] Invalid message payload structure, skipping');
            return null;
          }
          
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
        } catch (parseError) {
          console.warn('[DB] Failed to parse message payload, skipping:', parseError);
          return null;
        }
      }).filter(Boolean); // Remove null entries
    } catch (error) {
      console.error(`[DB] Error loading messages for user ${username}:`, error);
      return [];
    }
  }

  static queueOfflineMessage(toUsername, payloadObj) {
    // SECURITY: Validate inputs
    if (!toUsername || typeof toUsername !== 'string' || toUsername.length < 3 || toUsername.length > 32) {
      console.error('[DB] Invalid toUsername for offline message');
      return false;
    }
    
    if (!payloadObj || typeof payloadObj !== 'object') {
      console.error('[DB] Invalid payload for offline message');
      return false;
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(toUsername)) {
      console.error('[DB] Invalid toUsername format for offline message');
      return false;
    }
    
    try {
      const payload = JSON.stringify(payloadObj);
      
      // SECURITY: Prevent extremely large payloads that could cause DoS
      if (payload.length > 1048576) { // 1MB limit
        console.error('[DB] Offline message payload too large');
        return false;
      }
      
      const queuedAt = Date.now();
      db.prepare(`INSERT INTO offline_messages (toUsername, payload, queuedAt) VALUES (?, ?, ?)`).run(toUsername, payload, queuedAt);
      return true;
    } catch (error) {
      console.error('[DB] Error queueing offline message:', error);
      return false;
    }
  }

  static takeOfflineMessages(toUsername, max = 100) {
    // SECURITY: Validate inputs to prevent SQL injection and DoS
    if (!toUsername || typeof toUsername !== 'string' || toUsername.length < 3 || toUsername.length > 32) {
      console.error('[DB] Invalid toUsername parameter');
      return [];
    }
    
    if (!Number.isInteger(max) || max < 1 || max > 1000) {
      console.error('[DB] Invalid max parameter - must be integer between 1 and 1000');
      return [];
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(toUsername)) {
      console.error('[DB] Invalid toUsername format');
      return [];
    }
    
    try {
      const rows = db.prepare(`SELECT id, payload FROM offline_messages WHERE toUsername = ? ORDER BY queuedAt ASC LIMIT ?`).all(toUsername, max);
      if (!rows || rows.length === 0) return [];
      
      // SECURITY: Validate that all IDs are integers to prevent injection
      const ids = rows.map(r => r.id);
      if (!ids.every(id => Number.isInteger(id) && id > 0)) {
        console.error('[DB] Invalid message IDs detected');
        return [];
      }
      
      const messages = rows.map(r => {
        try { 
          const parsed = JSON.parse(r.payload);
          // SECURITY: Validate parsed message structure
          if (!parsed || typeof parsed !== 'object') return null;
          return parsed;
        } catch { 
          return null; 
        }
      }).filter(Boolean);
      
      // SECURITY: Use transaction and prepare statement with safe parameterization
      if (ids.length > 0) {
        const placeholders = ids.map(() => '?').join(',');
        const deleteStmt = db.prepare(`DELETE FROM offline_messages WHERE id IN (${placeholders})`);
        const deleteTransaction = db.transaction(() => {
          deleteStmt.run(...ids);
        });
        deleteTransaction();
      }
      
      return messages;
    } catch (error) {
      console.error('[DB] Error taking offline messages:', error);
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

  static async takeBundleForRecipient(username) {
    const bundle = db.prepare(`SELECT * FROM prekey_bundles WHERE username = ?`).get(username);
    if (!bundle) return null;
    const ot = db.prepare(`SELECT keyId, publicKeyBase64 FROM one_time_prekeys WHERE username = ? AND consumed = 0 ORDER BY keyId LIMIT 1`).get(username);
    if (ot) {
      db.prepare(`UPDATE one_time_prekeys SET consumed = 1, consumedAt = ? WHERE username = ? AND keyId = ?`).run(Date.now(), username, ot.keyId);
      
      // Clean up consumed private key immediately after marking as consumed
      try {
        this.cleanupConsumedPrivateKeys(username, ot.keyId);
      } catch (error) {
        console.error(`[DB] Failed to cleanup consumed private key for ${username}:${ot.keyId}:`, error);
      }
      
      // AUTO-REPLENISH: Check if we need to generate more pre-keys after consumption
      try {
        const remainingCount = this.countAvailableOneTimePreKeys(username);
        if (remainingCount < 10) {
          console.log(`[PREKEY] Auto-replenishing pre-keys for ${username} (${remainingCount} remaining)`);
          await this.appendOneTimePreKeys(username, 100);
          console.log(`[PREKEY] Added 100 more pre-keys for ${username}`);
        }
      } catch (error) {
        console.error(`[PREKEY] Failed to auto-replenish pre-keys for ${username}:`, error);
      }
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

  static storeOneTimePreKeys(username, oneTimePreKeys) {
    if (!username || typeof username !== 'string') return;
    try {
      db.prepare(`DELETE FROM one_time_prekeys WHERE username = ?`).run(username);
      if (Array.isArray(oneTimePreKeys) && oneTimePreKeys.length) {
        const insertStmt = db.prepare(`INSERT INTO one_time_prekeys (username, keyId, publicKeyBase64, consumed) VALUES (?, ?, ?, 0)`);
        const insertMany = db.transaction((rows) => {
          for (const r of rows) insertStmt.run(username, r.id, r.publicKeyBase64);
        });
        insertMany(oneTimePreKeys);
      }
    } catch (error) {
      console.error('[DB] Failed to store one-time prekeys:', error);
      throw error;
    }
  }

  static countAvailableOneTimePreKeys(username) {
    try {
      const row = db.prepare(`SELECT COUNT(*) as cnt FROM one_time_prekeys WHERE username = ? AND consumed = 0`).get(username);
      return row?.cnt ?? 0;
    } catch (error) {
      console.error('[DB] Failed to count one-time prekeys:', error);
      return 0;
    }
  }

  static getMaxPrekeyId(username) {
    try {
      const row = db.prepare(`SELECT MAX(keyId) as maxId FROM one_time_prekeys WHERE username = ?`).get(username);
      return row?.maxId ?? 0;
    } catch (error) {
      console.error('[DB] Failed to get max prekey id:', error);
      return 0;
    }
  }

  static async appendOneTimePreKeys(username, count) {
    if (!username || typeof username !== 'string' || count <= 0) return 0;
    try {
      const start = this.getMaxPrekeyId(username) + 1;
      const insertPublicStmt = db.prepare(`INSERT INTO one_time_prekeys (username, keyId, publicKeyBase64, consumed) VALUES (?, ?, ?, 0)`);
      const insertPrivateStmt = db.prepare(`INSERT INTO one_time_prekey_private_keys (username, keyId, encryptedPrivateKeyBase64, salt, iv, createdAt) VALUES (?, ?, ?, ?, ?, ?)`);
      
      const keyPairs = [];
      for (let i = 0; i < count; i++) {
        // Generate proper X25519 key pair
        const keyPair = await CryptoUtils.X25519.generateKeyPair();
        const publicKeyRaw = await CryptoUtils.X25519.exportPublicKeyRaw(keyPair.publicKey);
        const publicKeyBase64 = CryptoUtils.Hash.arrayBufferToBase64(publicKeyRaw);
        
        // Export private key for secure storage
        const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const privateKeyBytes = new Uint8Array(privateKeyRaw);
        
        // Encrypt private key for storage
        const { encryptedPrivateKey, salt, iv } = await this.encryptPrivateKey(privateKeyBytes, `${username}:${start + i}`);
        
        keyPairs.push({
          keyId: start + i,
          publicKeyBase64,
          encryptedPrivateKeyBase64: CryptoUtils.Hash.arrayBufferToBase64(encryptedPrivateKey),
          salt: CryptoUtils.Hash.arrayBufferToBase64(salt),
          iv: CryptoUtils.Hash.arrayBufferToBase64(iv)
        });
      }
      
      const insertMany = db.transaction((keyPairs) => {
        for (const kp of keyPairs) {
          insertPublicStmt.run(username, kp.keyId, kp.publicKeyBase64);
          insertPrivateStmt.run(username, kp.keyId, kp.encryptedPrivateKeyBase64, kp.salt, kp.iv, Date.now());
        }
      });
      insertMany(keyPairs);
      return count;
    } catch (error) {
      console.error('[DB] Failed to append one-time prekeys:', error);
      return 0;
    }
  }

  // Auto-generate initial pre-keys for new users
  static async generateInitialPreKeys(username, count = 100) {
    if (!username || typeof username !== 'string') return 0;
    try {
      console.log(`[PREKEY] Generating ${count} initial pre-keys for user: ${username}`);
      
      const prekeys = [];
      const privateKeys = [];
      
      for (let i = 0; i < count; i++) {
        // Generate proper X25519 key pair
        const keyPair = await CryptoUtils.X25519.generateKeyPair();
        const publicKeyRaw = await CryptoUtils.X25519.exportPublicKeyRaw(keyPair.publicKey);
        const publicKeyBase64 = CryptoUtils.Hash.arrayBufferToBase64(publicKeyRaw);
        
        // Export private key for secure storage
        const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const privateKeyBytes = new Uint8Array(privateKeyRaw);
        
        // Encrypt private key for storage
        const { encryptedPrivateKey, salt, iv } = await this.encryptPrivateKey(privateKeyBytes, `${username}:${i + 1}`);
        
        prekeys.push({
          id: i + 1,
          publicKeyBase64
        });
        
        privateKeys.push({
          keyId: i + 1,
          encryptedPrivateKeyBase64: CryptoUtils.Hash.arrayBufferToBase64(encryptedPrivateKey),
          salt: CryptoUtils.Hash.arrayBufferToBase64(salt),
          iv: CryptoUtils.Hash.arrayBufferToBase64(iv)
        });
      }
      
      this.storeOneTimePreKeys(username, prekeys);
      this.storeOneTimePreKeyPrivateKeys(username, privateKeys);
      
      console.log(`[PREKEY] Successfully generated ${count} pre-keys for user: ${username}`);
      return count;
    } catch (error) {
      console.error(`[PREKEY] Failed to generate initial pre-keys for user ${username}:`, error);
      return 0;
    }
  }

  // Check and replenish pre-keys if below threshold
  static async ensurePreKeyAvailability(username, minThreshold = 10, replenishCount = 100) {
    if (!username || typeof username !== 'string') return false;
    try {
      const currentCount = this.countAvailableOneTimePreKeys(username);
      console.log(`[PREKEY] User ${username} has ${currentCount} available pre-keys`);
      
      if (currentCount < minThreshold) {
        console.log(`[PREKEY] Replenishing pre-keys for user ${username} (${currentCount} < ${minThreshold})`);
        const generated = await this.appendOneTimePreKeys(username, replenishCount);
        console.log(`[PREKEY] Generated ${generated} additional pre-keys for user: ${username}`);
        return generated > 0;
      }
      return true;
    } catch (error) {
      console.error(`[PREKEY] Failed to ensure pre-key availability for user ${username}:`, error);
      return false;
    }
  }

  // Check if user needs pre-key replenishment
  static needsPreKeyReplenishment(username, threshold = 10) {
    try {
      const count = this.countAvailableOneTimePreKeys(username);
      return count < threshold;
    } catch (error) {
      console.error(`[PREKEY] Failed to check pre-key count for user ${username}:`, error);
      return true; // Err on the side of generating more keys
    }
  }

  // Periodic maintenance: Check all users and replenish low pre-key counts
  static async performPreKeyMaintenance(threshold = 10, replenishCount = 100) {
    try {
      console.log('[PREKEY] Starting periodic pre-key maintenance...');
      
      // Get all users who have low pre-key counts
      const lowCountUsers = db.prepare(`
        SELECT DISTINCT u.username, COALESCE(p.available_count, 0) as available_count
        FROM users u
        LEFT JOIN (
          SELECT username, COUNT(*) as available_count 
          FROM one_time_prekeys 
          WHERE consumed = 0 
          GROUP BY username
        ) p ON u.username = p.username
        WHERE COALESCE(p.available_count, 0) < ?
      `).all(threshold);

      let replenishedCount = 0;
      for (const user of lowCountUsers) {
        try {
          console.log(`[PREKEY] Maintenance: Replenishing pre-keys for ${user.username} (${user.available_count} available)`);
          const generated = await this.appendOneTimePreKeys(user.username, replenishCount);
          if (generated > 0) {
            replenishedCount++;
            console.log(`[PREKEY] Maintenance: Added ${generated} pre-keys for ${user.username}`);
          }
        } catch (error) {
          console.error(`[PREKEY] Maintenance: Failed to replenish pre-keys for ${user.username}:`, error);
        }
      }
      
      console.log(`[PREKEY] Maintenance complete: Replenished pre-keys for ${replenishedCount} users`);
      return replenishedCount;
    } catch (error) {
      console.error('[PREKEY] Maintenance: Failed to perform pre-key maintenance:', error);
      return 0;
    }
  }

  // Encrypt private key for secure storage
  static async encryptPrivateKey(privateKeyBytes, aad) {
    // Require a non-empty PREKEY_ENCRYPTION_SECRET from environment
    const serverSecret = process.env.PREKEY_ENCRYPTION_SECRET;
    if (!serverSecret || serverSecret.trim().length === 0) {
      throw new Error('PREKEY_ENCRYPTION_SECRET environment variable is required and must not be empty');
    }
    
    // Generate a random salt and IV for this private key
    const salt = randomBytes(32);
    const iv = randomBytes(12); // Use 12-byte IV (96 bits) for AES-GCM standard
    
    const serverSecretBytes = new TextEncoder().encode(serverSecret);
    
    // Use HKDF to derive encryption key
    const encryptionKey = await CryptoUtils.KDF.blake3Hkdf(
      serverSecretBytes,
      salt,
      new TextEncoder().encode('prekey-private-key-encryption-v1'),
      32
    );
    
    // Import as AES key
    const aesKey = await crypto.subtle.importKey(
      'raw',
      encryptionKey,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    
    // Prepare encryption options with optional AAD
    const encryptOptions = { name: 'AES-GCM', iv: iv };
    if (aad) {
      encryptOptions.additionalData = new TextEncoder().encode(aad);
    }
    
    // Encrypt the private key
    const encryptedBuffer = await crypto.subtle.encrypt(
      encryptOptions,
      aesKey,
      privateKeyBytes
    );
    
    return {
      encryptedPrivateKey: new Uint8Array(encryptedBuffer),
      salt,
      iv
    };
  }
  
  // Decrypt private key for use
  static async decryptPrivateKey(encryptedPrivateKeyBase64, saltBase64, ivBase64, aad) {
    // Input validation
    if (!encryptedPrivateKeyBase64 || typeof encryptedPrivateKeyBase64 !== 'string' || encryptedPrivateKeyBase64.trim().length === 0) {
      throw new Error('encryptedPrivateKeyBase64 must be a non-empty string');
    }
    if (!saltBase64 || typeof saltBase64 !== 'string' || saltBase64.trim().length === 0) {
      throw new Error('saltBase64 must be a non-empty string');
    }
    if (!ivBase64 || typeof ivBase64 !== 'string' || ivBase64.trim().length === 0) {
      throw new Error('ivBase64 must be a non-empty string');
    }
    
    // Decode and validate binary data
    let encryptedPrivateKey, salt, iv;
    try {
      encryptedPrivateKey = CryptoUtils.Hash.base64ToUint8Array(encryptedPrivateKeyBase64);
      salt = CryptoUtils.Hash.base64ToUint8Array(saltBase64);
      iv = CryptoUtils.Hash.base64ToUint8Array(ivBase64);
    } catch (error) {
      throw new Error('Failed to decode base64 input parameters: ' + error.message);
    }
    
    // Validate decoded data lengths
    if (iv.length !== 12) {
      throw new Error(`IV must be exactly 12 bytes (96 bits), got ${iv.length} bytes`);
    }
    if (salt.length < 16) {
      throw new Error(`Salt must be at least 16 bytes, got ${salt.length} bytes`);
    }
    if (encryptedPrivateKey.length < 16) {
      throw new Error(`Encrypted private key must be at least 16 bytes, got ${encryptedPrivateKey.length} bytes`);
    }
    
    // Require a non-empty PREKEY_ENCRYPTION_SECRET from environment
    const serverSecret = process.env.PREKEY_ENCRYPTION_SECRET;
    if (!serverSecret || serverSecret.trim().length === 0) {
      throw new Error('PREKEY_ENCRYPTION_SECRET environment variable is required and must not be empty');
    }
    
    const serverSecretBytes = new TextEncoder().encode(serverSecret);
    
    let encryptionKey;
    try {
      encryptionKey = await CryptoUtils.KDF.blake3Hkdf(
        serverSecretBytes,
        salt,
        new TextEncoder().encode('prekey-private-key-encryption-v1'),
        32
      );
    } catch (error) {
      throw new Error('Failed to derive encryption key: ' + error.message);
    }
    
    let aesKey;
    try {
      aesKey = await crypto.subtle.importKey(
        'raw',
        encryptionKey,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );
    } catch (error) {
      throw new Error('Failed to import AES key: ' + error.message);
    }
    
    // Prepare decryption options with optional AAD
    const decryptOptions = { name: 'AES-GCM', iv: iv };
    if (aad) {
      decryptOptions.additionalData = new TextEncoder().encode(aad);
    }
    
    // Decrypt the private key
    let decryptedBuffer;
    try {
      decryptedBuffer = await crypto.subtle.decrypt(
        decryptOptions,
        aesKey,
        encryptedPrivateKey
      );
    } catch (error) {
      throw new Error('Failed to decrypt private key: ' + error.message);
    }
    
    return new Uint8Array(decryptedBuffer);
  }
  
  // Store private keys securely
  static storeOneTimePreKeyPrivateKeys(username, privateKeys) {
    if (!username || typeof username !== 'string' || !Array.isArray(privateKeys)) return;
    try {
      const insertStmt = db.prepare(`INSERT INTO one_time_prekey_private_keys (username, keyId, encryptedPrivateKeyBase64, salt, iv, createdAt) VALUES (?, ?, ?, ?, ?, ?)`);
      const insertMany = db.transaction((keys) => {
        for (const key of keys) {
          insertStmt.run(username, key.keyId, key.encryptedPrivateKeyBase64, key.salt, key.iv, Date.now());
        }
      });
      insertMany(privateKeys);
    } catch (error) {
      console.error('[DB] Failed to store one-time prekey private keys:', error);
      throw error;
    }
  }
  
  // Retrieve private key for a specific pre-key
  static async getOneTimePreKeyPrivateKey(username, keyId) {
    try {
      const row = db.prepare(`SELECT encryptedPrivateKeyBase64, salt, iv FROM one_time_prekey_private_keys WHERE username = ? AND keyId = ?`).get(username, keyId);
      if (!row) return null;
      
      const privateKeyBytes = await this.decryptPrivateKey(row.encryptedPrivateKeyBase64, row.salt, row.iv, `${username}:${keyId}`);
      
      // Import the private key back to CryptoKey format
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBytes,
        { name: 'X25519' },
        false,
        ['deriveBits']
      );
      
      return privateKey;
    } catch (error) {
      console.error('[DB] Failed to get one-time prekey private key:', error);
      return null;
    }
  }
  
  // Clean up consumed private keys
  static cleanupConsumedPrivateKeys(username, keyId) {
    try {
      db.prepare(`DELETE FROM one_time_prekey_private_keys WHERE username = ? AND keyId = ?`).run(username, keyId);
    } catch (error) {
      console.error('[DB] Failed to cleanup consumed private key:', error);
    }
  }

  // Get stats for monitoring
  static getPreKeyStats() {
    try {
      const stats = db.prepare(`
        SELECT 
          COUNT(DISTINCT u.username) as total_users,
          COUNT(DISTINCT p.username) as users_with_prekeys,
          COALESCE(AVG(p.available_count), 0) as avg_prekeys_per_user,
          COALESCE(MIN(p.available_count), 0) as min_prekeys,
          COALESCE(MAX(p.available_count), 0) as max_prekeys,
          COUNT(CASE WHEN p.available_count < 10 THEN 1 END) as low_prekey_users
        FROM users u
        LEFT JOIN (
          SELECT username, COUNT(*) as available_count 
          FROM one_time_prekeys 
          WHERE consumed = 0 
          GROUP BY username
        ) p ON u.username = p.username
      `).get();
      
      return stats;
    } catch (error) {
      console.error('[PREKEY] Failed to get pre-key stats:', error);
      return null;
    }
  }
}

export class LibsignalBundleDB {
  static publish(username, bundle) {
    // SECURITY: Validate username parameter
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username parameter in LibsignalBundleDB.publish: ${username}`);
      throw new Error('Invalid username parameter');
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format in LibsignalBundleDB.publish: ${username}`);
      throw new Error('Invalid username format');
    }
    
    // SECURITY: Validate bundle structure
    if (!bundle || typeof bundle !== 'object') {
      console.error('[DB] Invalid bundle structure in LibsignalBundleDB.publish');
      throw new Error('Invalid bundle structure');
    }
    
    // SECURITY: Validate required bundle fields
    const requiredFields = ['registrationId', 'deviceId', 'identityKeyBase64', 'signedPreKeyId', 
                           'signedPreKeyPublicBase64', 'signedPreKeySignatureBase64', 
                           'kyberPreKeyId', 'kyberPreKeyPublicBase64', 'kyberPreKeySignatureBase64'];
    
    for (const field of requiredFields) {
      if (bundle[field] === undefined || bundle[field] === null) {
        console.error(`[DB] Missing required field in bundle: ${field}`);
        throw new Error(`Missing required field in bundle: ${field}`);
      }
    }
    
    // SECURITY: Validate numeric fields
    if (!Number.isInteger(bundle.registrationId) || bundle.registrationId < 0) {
      console.error('[DB] Invalid registrationId in bundle');
      throw new Error('Invalid registrationId in bundle');
    }
    
    if (!Number.isInteger(bundle.deviceId) || bundle.deviceId < 0) {
      console.error('[DB] Invalid deviceId in bundle');
      throw new Error('Invalid deviceId in bundle');
    }
    
    const now = Date.now();
    try {
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
    } catch (error) {
      console.error(`[DB] Error publishing libsignal bundle for ${username}:`, error);
      throw error;
    }
  }

  static take(username) {
    // SECURITY: Validate username parameter
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username parameter in LibsignalBundleDB.take: ${username}`);
      return null;
    }
    
    // SECURITY: Validate username format
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format in LibsignalBundleDB.take: ${username}`);
      return null;
    }
    
    try {
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
    } catch (error) {
      console.error(`[DB] Error taking libsignal bundle for ${username}:`, error);
      return null;
    }
  }
}
