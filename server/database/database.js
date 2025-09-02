import path from 'path';
import { fileURLToPath } from 'url';
import DatabaseDriver from 'better-sqlite3';
import { CryptoUtils } from '../crypto/unified-crypto.js';

// Optional Postgres backend for horizontal scalability
const USE_PG = (process.env.DB_BACKEND || '').toLowerCase() === 'postgres' || !!process.env.DATABASE_URL;
let pgPool = null;
async function getPgPool() {
  if (!USE_PG) return null;
  if (pgPool) return pgPool;
  try {
    const { Pool } = await import('pg');
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: parseInt(process.env.DB_POOL_MAX || '20'),
      idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
      connectionTimeoutMillis: parseInt(process.env.DB_CONNECT_TIMEOUT || '2000')
    });
    return pgPool;
  } catch (e) {
    console.error('[DB] Failed to initialize Postgres pool:', e);
    throw e;
  }
}

const DB_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), 'user_database.sqlite');
let db;
let initialized = false;

export async function initDatabase() {
  if (initialized) return;
  initialized = true;

  if (!USE_PG) {
    console.log('[DB] Initializing database at:', DB_PATH);
    db = new DatabaseDriver(DB_PATH);

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

    db.exec(`
      CREATE TABLE IF NOT EXISTS offline_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        toUsername TEXT NOT NULL,
        payload TEXT NOT NULL,
        queuedAt INTEGER NOT NULL
      );
    `);

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

    checkMigration();

    db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(fromUsername);`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(toUsername);`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_participants ON messages(fromUsername, toUsername);`);
  } else {
    // For Postgres, assume tables exist or handle migrations externally
    console.log('[DB] Using Postgres backend - assuming tables exist');
  }

  console.log(`[DB] Database tables initialized (backend=${USE_PG ? 'postgres' : 'sqlite'})`);
}

// Check if we need to migrate the messages table
const checkMigration = () => {
  try {
    if (USE_PG) return; // handled by external migrations
    const tableInfo = db.prepare("PRAGMA table_info(messages)").all();
    const hasNewColumns = tableInfo.some(col => col.name === 'fromUsername');

    if (!hasNewColumns) {
      console.log('[DB] Migrating messages table to add performance columns...');

      // Create pre-migration backup
      let backupTableCreated = false;
      try {
        // Create backup table
        db.exec(`CREATE TABLE messages_backup AS SELECT * FROM messages`);
        backupTableCreated = true;
        console.log('[DB] Pre-migration backup created');

        // Use transaction for atomic migration
        const migration = db.transaction(() => {
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

          let migratedCount = 0;
          let failedCount = 0;

          messages.forEach(row => {
            try {
              const payload = JSON.parse(row.payload);
              updateStmt.run(
                payload.fromUsername || '',
                payload.toUsername || '',
                payload.timestamp || Date.now(),
                row.id
              );
              migratedCount++;
            } catch (e) {
              console.warn(`[DB] Failed to migrate message ${row.id}:`, e);
              failedCount++;
              // Don't throw here - continue with other messages
            }
          });

          console.log(`[DB] Migration completed: ${migratedCount} migrated, ${failedCount} failed`);

          if (failedCount > migratedCount / 2) {
            throw new Error(`Too many migration failures: ${failedCount}/${messages.length}`);
          }
        });

        // Execute the migration transaction
        migration();

        // Clean up backup on success
        db.exec(`DROP TABLE messages_backup`);
        console.log('[DB] Migration successful, backup cleaned up');

      } catch (migrationError) {
        console.error('[DB] Migration failed:', migrationError);

        // Attempt to restore from backup
        if (backupTableCreated) {
          try {
            // Rollback: restore from backup
            db.exec(`DROP TABLE IF EXISTS messages`);
            db.exec(`ALTER TABLE messages_backup RENAME TO messages`);
            console.log('[DB] Successfully restored messages table from backup');
          } catch (restoreError) {
            console.error('[DB] CRITICAL: Failed to restore from backup:', restoreError);
            // Clean up backup table if it exists
            try {
              db.exec(`DROP TABLE IF EXISTS messages_backup`);
            } catch {}
          }
        }

        throw new Error(`Database migration failed: ${migrationError.message}`);
      } finally {
        // Ensure backup is cleaned up in all cases
        try {
          db.exec(`DROP TABLE IF EXISTS messages_backup`);
        } catch {}
      }
    }
  } catch (error) {
    console.error('[DB] Migration failed:', error);
    throw new Error(`Database migration failed: ${error.message}`);
  }
};

// All database initialization moved to initDatabase() function

export class UserDatabase {
  static async loadUser(username) {
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
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        return rows[0] || null;
      } else {
        const row = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
        if (!row) return null;
        return row;
      }
    } catch (error) {
      console.error(`[DB] Error loading user ${username}:`, error);
      return null;
    }
  }

  static async saveUserRecord(userRecord) {
    // SECURITY: Validate user record structure
    if (!userRecord || typeof userRecord !== 'object') {
      console.error('[DB] Invalid user record structure');
      throw new Error('Invalid user record structure');
    }
    
    const { username, passwordHash } = userRecord;
    
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
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query(`
          INSERT INTO users (
            username, passwordHash, passphraseHash,
            version, algorithm, salt, memoryCost, timeCost, parallelism
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          ON CONFLICT (username) DO UPDATE SET
            passwordHash = EXCLUDED.passwordHash,
            passphraseHash = EXCLUDED.passphraseHash,
            version = EXCLUDED.version,
            algorithm = EXCLUDED.algorithm,
            salt = EXCLUDED.salt,
            memoryCost = EXCLUDED.memoryCost,
            timeCost = EXCLUDED.timeCost,
            parallelism = EXCLUDED.parallelism
        `, [
          userRecord.username,
          userRecord.passwordHash,
          userRecord.passphraseHash,
          userRecord.version,
          userRecord.algorithm,
          userRecord.salt,
          userRecord.memoryCost,
          userRecord.timeCost,
          userRecord.parallelism
        ]);
      } else {
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

      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query(`
          INSERT INTO messages (messageId, payload, fromUsername, toUsername, timestamp)
          VALUES ($1,$2,$3,$4,$5)
          ON CONFLICT (messageId) DO UPDATE SET
            payload = EXCLUDED.payload,
            fromUsername = EXCLUDED.fromUsername,
            toUsername = EXCLUDED.toUsername,
            timestamp = EXCLUDED.timestamp
        `, [messageId, stringifiedPayload, fromUsername, toUsername, timestamp]);
      } else {
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
      }

      console.log(`[DB] Message saved successfully to database: ${messageId}`);
    } catch (error) {
      console.error('[DB] Error saving message to database:', error.message);
      throw new Error('Failed to save message to database: Database error');
    }
  }

  static async getMessagesForUser(username, limit = 50) {
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
      let rows;
      if (USE_PG) {
        const pool = await getPgPool();
        const res = await pool.query(`
          SELECT id, messageId, payload, fromUsername, toUsername, timestamp
          FROM messages
          WHERE fromUsername = $1 OR toUsername = $1
          ORDER BY timestamp DESC
          LIMIT $2
        `, [username, limit]);
        rows = res.rows;
      } else {
        const stmt = db.prepare(`
          SELECT id, messageId, payload, fromUsername, toUsername, timestamp
          FROM messages
          WHERE fromUsername = ? OR toUsername = ?
          ORDER BY timestamp DESC
          LIMIT ?
        `);
        rows = stmt.all(username, username, limit);
      }
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
      
      if (payload.length > 1048576) {
        console.error('[DB] Offline message payload too large');
        return false;
      }
      
      const queuedAt = Date.now();
      if (USE_PG) {
        return getPgPool().then(pool => pool.query('INSERT INTO offline_messages (toUsername, payload, queuedAt) VALUES ($1,$2,$3)', [toUsername, payload, queuedAt]).then(() => true).catch(() => false));
      } else {
        try {
          db.prepare(`INSERT INTO offline_messages (toUsername, payload, queuedAt) VALUES (?, ?, ?)`).run(toUsername, payload, queuedAt);
          return Promise.resolve(true);
        } catch (error) {
          console.error('[DB] Error inserting offline message:', error);
          return Promise.resolve(false);
        }
      }
    } catch (error) {
      console.error('[DB] Error queueing offline message:', error);
      return false;
    }
  }

  static async takeOfflineMessages(toUsername, max = 100) {
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
      if (USE_PG) {
        const pool = await getPgPool();
        const res = await pool.query('SELECT id, payload FROM offline_messages WHERE toUsername = $1 ORDER BY queuedAt ASC LIMIT $2', [toUsername, max]);
        const rows = res.rows || [];
        if (rows.length === 0) return [];
        const ids = rows.map(r => Number(r.id)).filter(n => Number.isInteger(n) && n > 0);
        const messages = rows.map(r => { try { const p = JSON.parse(r.payload); return (p && typeof p === 'object') ? p : null; } catch { return null; } }).filter(Boolean);
        if (ids.length > 0) {
          await pool.query('DELETE FROM offline_messages WHERE id = ANY($1::int[])', [ids]);
        }
        return messages;
      } else {
        const rows = db.prepare(`SELECT id, payload FROM offline_messages WHERE toUsername = ? ORDER BY queuedAt ASC LIMIT ?`).all(toUsername, max);
        if (!rows || rows.length === 0) return [];
        const ids = rows.map(r => r.id);
        if (!ids.every(id => Number.isInteger(id) && id > 0)) return [];
        const messages = rows.map(r => { try { const p = JSON.parse(r.payload); return (p && typeof p === 'object') ? p : null; } catch { return null; } }).filter(Boolean);
        if (ids.length > 0) {
          const placeholders = ids.map(() => '?').join(',');
          const deleteStmt = db.prepare(`DELETE FROM offline_messages WHERE id IN (${placeholders})`);
          const deleteTransaction = db.transaction(() => { deleteStmt.run(...ids); });
          deleteTransaction();
        }
        return messages;
      }
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
      
      // No private key cleanup needed - keys are managed client-side
      
      // SECURITY: Auto-replenish removed - client should manage prekey availability
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

  static async storeOneTimePreKeys(username, oneTimePreKeys) {
    if (!username || typeof username !== 'string') return;
    try {
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query('DELETE FROM one_time_prekeys WHERE username=$1', [username]);
        if (Array.isArray(oneTimePreKeys) && oneTimePreKeys.length) {
          // Use parameterized bulk INSERT to prevent SQL injection
          const placeholders = oneTimePreKeys.map((_, index) => {
            const base = index * 4;
            return `($${base + 1},$${base + 2},$${base + 3},$${base + 4})`;
          }).join(',');

          const params = [];
          oneTimePreKeys.forEach((r) => {
            params.push(username, r.id, r.publicKeyBase64, 0);
          });

          await pool.query(`INSERT INTO one_time_prekeys (username, keyId, publicKeyBase64, consumed) VALUES ${placeholders}`, params);
        }
      } else {
        db.prepare(`DELETE FROM one_time_prekeys WHERE username = ?`).run(username);
        if (Array.isArray(oneTimePreKeys) && oneTimePreKeys.length) {
          const insertStmt = db.prepare(`INSERT INTO one_time_prekeys (username, keyId, publicKeyBase64, consumed) VALUES (?, ?, ?, 0)`);
          const insertMany = db.transaction((rows) => {
            for (const r of rows) insertStmt.run(username, r.id, r.publicKeyBase64);
          });
          insertMany(oneTimePreKeys);
        }
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

  // SECURITY: REMOVED - Server-side private key generation violates E2E encryption guarantees
  // These methods have been removed to ensure private keys are only generated client-side
  static async appendOneTimePreKeys() {
    console.error('[DB] SECURITY: appendOneTimePreKeys deprecated - server should not generate private keys');
    console.error('[DB] Use client-side prekey generation instead to maintain E2E security');
    return 0;
  }

  // SECURITY: REMOVED - Server-side private key generation violates E2E encryption guarantees
  static async generateInitialPreKeys() {
    console.error('[DB] SECURITY: generateInitialPreKeys deprecated - server should not generate private keys');
    console.error('[DB] Client should generate prekeys during registration to maintain E2E security');
    return 0;
  }

  // SECURITY: REMOVED - Server should not generate prekeys
  static async ensurePreKeyAvailability() {
    console.warn('[DB] SECURITY: ensurePreKeyAvailability deprecated - client should manage prekeys');
    console.warn('[DB] Server will not generate prekeys to maintain E2E security');
    return false;
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

  // SECURITY: REMOVED - Server should not generate prekeys
  static async performPreKeyMaintenance() {
    console.warn('[DB] SECURITY: performPreKeyMaintenance deprecated - client should manage prekeys');
    console.warn('[DB] Server will not generate prekeys to maintain E2E security');
    return 0;
  }

  // SECURITY: All private key methods removed - client-side key management only

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
  static async publish(username, bundle) {
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
        throw new Error('Missing required field in bundle: [REDACTED]');
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
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query(`
          INSERT INTO libsignal_bundles (
            username, registrationId, deviceId, identityKeyBase64,
            preKeyId, preKeyPublicBase64,
            signedPreKeyId, signedPreKeyPublicBase64, signedPreKeySignatureBase64,
            kyberPreKeyId, kyberPreKeyPublicBase64, kyberPreKeySignatureBase64,
            updatedAt
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          ON CONFLICT(username) DO UPDATE SET
            registrationId=EXCLUDED.registrationId,
            deviceId=EXCLUDED.deviceId,
            identityKeyBase64=EXCLUDED.identityKeyBase64,
            preKeyId=EXCLUDED.preKeyId,
            preKeyPublicBase64=EXCLUDED.preKeyPublicBase64,
            signedPreKeyId=EXCLUDED.signedPreKeyId,
            signedPreKeyPublicBase64=EXCLUDED.signedPreKeyPublicBase64,
            signedPreKeySignatureBase64=EXCLUDED.signedPreKeySignatureBase64,
            kyberPreKeyId=EXCLUDED.kyberPreKeyId,
            kyberPreKeyPublicBase64=EXCLUDED.kyberPreKeyPublicBase64,
            kyberPreKeySignatureBase64=EXCLUDED.kyberPreKeySignatureBase64,
            updatedAt=EXCLUDED.updatedAt
        `, [
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
        ]);
      } else {
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
    } catch (error) {
      console.error(`[DB] Error publishing libsignal bundle for ${username}:`, error);
      throw error;
    }
  }

  static async take(username) {
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
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query('SELECT * FROM libsignal_bundles WHERE username = $1', [username]);
        const row = rows[0];
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
      } else {
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
    } catch (error) {
      console.error(`[DB] Error taking libsignal bundle for ${username}:`, error);
      return null;
    }
  }
}
