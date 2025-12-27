import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { randomBytes, createHmac, timingSafeEqual } from 'crypto';
import { execFileSync } from 'node:child_process';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { PostQuantumHash } from '../crypto/post-quantum-hash.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const RESERVED_JSON_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function sanitizeParsedJson(value) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sanitizeParsedJson);
  const out = Object.create(null);
  for (const [key, v] of Object.entries(value)) {
    if (RESERVED_JSON_KEYS.has(key)) continue;
    out[key] = sanitizeParsedJson(v);
  }
  return out;
}

function safeJsonParseObject(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return sanitizeParsedJson(parsed);
  } catch {
    return null;
  }
}

const PEPPER_FILE_PATH = process.env.PASSWORD_HASH_PEPPER_FILE
  ? path.resolve(process.env.PASSWORD_HASH_PEPPER_FILE)
  : path.resolve(__dirname, '../config/generated-pepper.txt');

const USER_ID_SALT_FILE_PATH = process.env.USER_ID_SALT_FILE
  ? path.resolve(process.env.USER_ID_SALT_FILE)
  : path.resolve(__dirname, '../config/generated-user-id-salt.txt');

const DB_FIELD_KEY_FILE_PATH = process.env.DB_FIELD_KEY_FILE
  ? path.resolve(process.env.DB_FIELD_KEY_FILE)
  : path.resolve(__dirname, '../config/generated-db-field-key.txt');

function generate64bytes() {
  return randomBytes(64).toString('hex');
}

function persistGeneratedSecret(secret, filePath, secretName, description, warning) {
  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const header = `# Auto-generated ${secretName} for ${description}\n`;
    const warnLine = `# ${warning}\n`;
    const backup = '# BACKUP THIS FILE SECURELY - Required for all server instances\n';
    const content = `${header}${warnLine}${backup}${secret}\n`;
    fs.writeFileSync(filePath, content, { mode: 0o600 });
    cryptoLogger.warn(`[DB] AUTO-GENERATED ${secretName}`, {
      path: filePath,
      length: secret.length
    });
  } catch (error) {
    cryptoLogger.error(`[DB] Failed to persist generated ${secretName}`, {
      error: error.message
    });
    throw new Error(`Failed to save auto-generated ${secretName}`);
  }
}

function loadOrGenerateSecret(envVarName, filePath, secretName, description, warning) {
  let secret = process.env[envVarName];

  if (!secret) {
    if (fs.existsSync(filePath)) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n').filter(line => line && !line.startsWith('#'));
        secret = lines[0]?.trim();
        if (secret && secret.length >= 32) {
          cryptoLogger.info(`[DB] Loaded ${secretName} from file`, {
            path: filePath,
            length: secret.length
          });
        } else {
          secret = null;
        }
      } catch (error) {
        cryptoLogger.error(`[DB] Failed to read ${secretName} file`, {
          error: error.message
        });
        secret = null;
      }
    }
  }

  if (!secret || secret.length < 32) {
    secret = generate64bytes();
    persistGeneratedSecret(secret, filePath, secretName, description, warning);
  }

  return secret;
}

const USE_PG = true;

const PASSWORD_PEPPER_ENV = loadOrGenerateSecret(
  'PASSWORD_HASH_PEPPER',
  PEPPER_FILE_PATH,
  'PASSWORD_HASH_PEPPER',
  'password hashing',
  'Losing this pepper will invalidate ALL user passwords'
);
if (!process.env.PASSWORD_HASH_PEPPER) {
  process.env.PASSWORD_HASH_PEPPER = PASSWORD_PEPPER_ENV;
}
const PASSWORD_PEPPER = Buffer.from(PASSWORD_PEPPER_ENV, 'utf8');

const USER_ID_SALT_ENV = loadOrGenerateSecret(
  'USER_ID_SALT',
  USER_ID_SALT_FILE_PATH,
  'USER_ID_SALT',
  'secure user ID hashing',
  'Losing this salt will affect token service user ID hashing'
);
if (!process.env.USER_ID_SALT) {
  process.env.USER_ID_SALT = USER_ID_SALT_ENV;
}

const DB_FIELD_KEY_ENV = loadOrGenerateSecret(
  'DB_FIELD_KEY',
  DB_FIELD_KEY_FILE_PATH,
  'DB_FIELD_KEY',
  'database field encryption',
  'Losing this key will make all encrypted database fields unreadable'
);
if (!process.env.DB_FIELD_KEY) {
  process.env.DB_FIELD_KEY = DB_FIELD_KEY_ENV;
}

const PEPPER_VERSION = 1;
const PEPPER_PREFIX = `v${PEPPER_VERSION}`;

function applyPepper(hashValue) {
  if (!hashValue || typeof hashValue !== 'string') {
    throw new Error('applyPepper requires a non-empty hash string');
  }
  const hmac = createHmac('sha512', PASSWORD_PEPPER);
  hmac.update(hashValue, 'utf8');
  return hmac.digest('base64');
}

function encodeStoredPasswordHash(rawHash) {
  if (!rawHash || typeof rawHash !== 'string') {
    throw new Error('encodeStoredPasswordHash requires a non-empty hash string');
  }
  if (rawHash.startsWith('v') && rawHash.includes(':')) {
    return rawHash;
  }
  const pepperedBase64 = applyPepper(rawHash);
  const rawBase64 = Buffer.from(rawHash, 'utf8').toString('base64');
  return `${PEPPER_PREFIX}:${pepperedBase64}:${rawBase64}`;
}

function decodeStoredPasswordHash(storedValue) {
  if (!storedValue || typeof storedValue !== 'string') {
    return { rawHash: null, storedValue: storedValue || null, isPeppered: false, version: 0 };
  }
  const parts = storedValue.split(':');
  if (parts.length === 3 && parts[0].startsWith('v')) {
    const version = Number.parseInt(parts[0].slice(1), 10) || 0;
    try {
      const rawHash = Buffer.from(parts[2], 'base64').toString('utf8');
      return {
        rawHash,
        storedValue,
        isPeppered: true,
        version,
        pepperedBase64: parts[1]
      };
    } catch { }
  }

  return { rawHash: null, storedValue, isPeppered: false, version: 0 };
}

function verifyPepperedHash(candidateRawHash, storedValue) {
  if (!candidateRawHash || typeof candidateRawHash !== 'string') {
    return false;
  }

  const decoded = decodeStoredPasswordHash(storedValue);
  if (!decoded.isPeppered || !decoded.pepperedBase64) {
    return false;
  }

  const expectedPeppered = applyPepper(candidateRawHash);
  const storedPepperedBuffer = Buffer.from(decoded.pepperedBase64, 'utf8');
  const expectedPepperedBuffer = Buffer.from(expectedPeppered, 'utf8');
  if (storedPepperedBuffer.length !== expectedPepperedBuffer.length) {
    return false;
  }
  return timingSafeEqual(storedPepperedBuffer, expectedPepperedBuffer);
}

function normalizeUserRecord(record) {
  if (!record) return record;
  const storedValue = record.passwordHash ?? record.passwordhash ?? null;
  const decoded = decodeStoredPasswordHash(storedValue);
  record.passwordHashStored = storedValue;
  record.passwordHash = decoded.rawHash;
  record.passwordHashPeppered = decoded.isPeppered;
  record.passwordHashVersion = decoded.version;
  return record;
}

const LIBSIGNAL_FIELD_PREFIX = 'pq2:';

class LibsignalFieldEncryption {
  static deriveFieldKey(fieldName) {
    const masterRaw = process.env.DB_FIELD_KEY || '';
    const masterBuf = Buffer.from(masterRaw, 'utf8');
    if (!masterRaw || masterBuf.length < 32) {
      throw new Error('DB_FIELD_KEY must be set (>= 32 bytes) for libsignal bundle field encryption');
    }

    const ikm = new Uint8Array(masterBuf);
    const salt = new TextEncoder().encode('db-libsignal-field-key-salt-v1');
    const info = `libsignal-field:${fieldName}`;
    const keyBytes = PostQuantumHash.deriveKey(ikm, salt, info, 32);
    return Buffer.from(keyBytes);
  }

  static encryptField(value, fieldName) {
    if (value === null || value === undefined) return null;
    const key = this.deriveFieldKey(fieldName);
    const nonce = randomBytes(36);
    const aad = Buffer.from(`libsignal-field:${fieldName}:v1`, 'utf8');
    const aead = new CryptoUtils.PostQuantumAEAD(key);
    const plaintext = Buffer.from(String(value), 'utf8');
    const { ciphertext, tag } = aead.encrypt(plaintext, nonce, aad);
    const combined = Buffer.concat([nonce, tag, ciphertext]);
    return LIBSIGNAL_FIELD_PREFIX + combined.toString('base64');
  }

  static decryptField(value, fieldName) {
    if (!value || typeof value !== 'string') return value;
    if (!value.startsWith(LIBSIGNAL_FIELD_PREFIX)) return value;

    const base = value.slice(LIBSIGNAL_FIELD_PREFIX.length);
    const data = Buffer.from(base, 'base64');

    if (data.length < 36 + 32 + 1) {
      throw new Error('Encrypted libsignal field payload too short');
    }

    const nonce = data.slice(0, 36);
    const tag = data.slice(36, 68);
    const ciphertext = data.slice(68);
    const key = this.deriveFieldKey(fieldName);
    const aad = Buffer.from(`libsignal-field:${fieldName}:v1`, 'utf8');
    const aead = new CryptoUtils.PostQuantumAEAD(key);
    const plaintext = aead.decrypt(ciphertext, nonce, tag, aad);
    return Buffer.from(plaintext).toString('utf8');
  }
}

function tryCreateDatabaseWithSudo(dbName, user, password) {
  if (!dbName || !user || !password) {
    return;
  }

  const safeUser = String(user).replace(/"/g, '""');
  const safeDb = String(dbName).replace(/"/g, '""');
  const safePassword = String(password).replace(/'/g, "''");

  const options = { stdio: 'inherit' };

  try {
    cryptoLogger.info('[DB] Attempting to create Postgres user via sudo psql', { user: safeUser });
    execFileSync('sudo', [
      '-u',
      'postgres',
      'psql',
      '-c',
      `CREATE USER "${safeUser}" WITH PASSWORD '${safePassword}' CREATEDB;`
    ], options);
  } catch (err) {
    cryptoLogger.warn('[DB] CREATE USER via sudo psql failed (may already exist)', {
      user: safeUser,
      error: err?.message || String(err)
    });
  }

  try {
    cryptoLogger.info('[DB] Attempting to create Postgres database via sudo psql', {
      database: safeDb,
      owner: safeUser
    });
    execFileSync('sudo', [
      '-u',
      'postgres',
      'psql',
      '-c',
      `CREATE DATABASE "${safeDb}" OWNER "${safeUser}";`
    ], options);
  } catch (err) {
    cryptoLogger.warn('[DB] CREATE DATABASE via sudo psql failed (may already exist)', {
      database: safeDb,
      owner: safeUser,
      error: err?.message || String(err)
    });
  }
}

async function tryCreateDatabaseViaConnection(dbName, user, password, host, port, sslConfig) {
  if (!dbName || !user || !password) {
    return false;
  }

  try {
    const { Pool } = await import('pg');
    const maintenancePool = new Pool({
      host,
      port,
      user,
      password,
      database: 'postgres',
      max: 1,
      connectionTimeoutMillis: 5000,
      ssl: sslConfig,
    });

    try {
      const escapedDbName = dbName.replace(/"/g, '""');
      cryptoLogger.info('[DB] Attempting to create database via connection', {
        database: dbName,
        host,
        port,
      });

      await maintenancePool.query(`CREATE DATABASE "${escapedDbName}"`);
      cryptoLogger.info('[DB] Database created successfully', { database: dbName });

      await maintenancePool.end();
      return true;
    } catch (err) {
      const msg = err?.message || String(err);

      if (/already exists/i.test(msg)) {
        cryptoLogger.info('[DB] Database already exists', { database: dbName });
        await maintenancePool.end();
        return true;
      }

      cryptoLogger.warn('[DB] Failed to create database via connection', {
        database: dbName,
        error: msg,
      });

      try { await maintenancePool.end(); } catch { }
      return false;
    }
  } catch (err) {
    cryptoLogger.error('[DB] Failed to connect to maintenance database', {
      error: err?.message || String(err),
    });
    return false;
  }
}

let pgPool = null;
export async function getPgPool() {
  if (!USE_PG) return null;
  if (pgPool) return pgPool;

  const caPathEnv = process.env.DB_CA_CERT_PATH || process.env.PGSSLROOTCERT;
  let sslConfig = { rejectUnauthorized: true };
  if (caPathEnv) {
    try {
      const caPath = path.resolve(caPathEnv);
      const ca = fs.readFileSync(caPath, 'utf8');
      sslConfig = { ca, rejectUnauthorized: true };
      cryptoLogger.info('[DB] Using custom CA for Postgres TLS', { caPath });
    } catch (e) {
      console.error('[DB] Failed to read DB_CA_CERT_PATH/PGSSLROOTCERT for TLS, falling back to system CAs', {
        caPath: caPathEnv,
        error: e?.message || String(e),
      });
      sslConfig = { rejectUnauthorized: true };
    }
  }

  try {
    const { Pool } = await import('pg');

    const dbPoolMax = Number.parseInt(process.env.DB_POOL_MAX || '20', 10);
    const dbIdleTimeout = Number.parseInt(process.env.DB_IDLE_TIMEOUT || '30000', 10);
    const dbConnectTimeout = Number.parseInt(process.env.DB_CONNECT_TIMEOUT || '10000', 10);

    const maxConnections = Number.isNaN(dbPoolMax) ? 20 : Math.max(1, Math.min(dbPoolMax, 100));
    const idleTimeoutMs = Number.isNaN(dbIdleTimeout) ? 30000 : Math.max(1000, Math.min(dbIdleTimeout, 300000));
    const connectTimeoutMs = Number.isNaN(dbConnectTimeout) ? 2000 : Math.max(500, Math.min(dbConnectTimeout, 30000));

    if (Number.isNaN(dbPoolMax)) {
      console.warn(`[DB] Invalid DB_POOL_MAX value '${process.env.DB_POOL_MAX}', using default: ${maxConnections}`);
    }
    if (Number.isNaN(dbIdleTimeout)) {
      console.warn(`[DB] Invalid DB_IDLE_TIMEOUT value '${process.env.DB_IDLE_TIMEOUT}', using default: ${idleTimeoutMs}`);
    }
    if (Number.isNaN(dbConnectTimeout)) {
      console.warn(`[DB] Invalid DB_CONNECT_TIMEOUT value '${process.env.DB_CONNECT_TIMEOUT}', using default: ${connectTimeoutMs}`);
    }

    if (process.env.DATABASE_URL) {
      const poolConfig = {
        connectionString: process.env.DATABASE_URL,
        max: maxConnections,
        idleTimeoutMillis: idleTimeoutMs,
        connectionTimeoutMillis: 30000,
        ssl: {
          ...sslConfig,
          servername: process.env.DB_TLS_SERVERNAME || undefined,
        },
      };

      const maxRetries = 10;
      const retryDelayMs = 3000;
      let lastError = null;

      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          pgPool = new Pool(poolConfig);
          await pgPool.query('SELECT 1');
          cryptoLogger.info('[DB] Database connection established via DATABASE_URL', {
            attempt,
            url: process.env.DATABASE_URL.replace(/:([^:@]+)@/, ':****@')
          });
          return pgPool;
        } catch (err) {
          lastError = err;
          const msg = err?.message || String(err);

          if (pgPool) {
            try { await pgPool.end(); } catch { }
            pgPool = null;
          }

          if (/authentication failed|password|role.*does not exist/i.test(msg)) {
            cryptoLogger.error('[DB] Authentication error, not retrying', { error: msg });
            throw err;
          }

          if (attempt < maxRetries) {
            cryptoLogger.warn(`[DB] Connection attempt ${attempt}/${maxRetries} failed, retrying in ${retryDelayMs}ms...`, {
              error: msg
            });
            await new Promise(resolve => setTimeout(resolve, retryDelayMs));
          }
        }
      }

      console.error('[DB] Failed to connect to database after all retries:', lastError);
      throw lastError;
    }

    // No DATABASE_URL provided: fall back to a local Postgres database and create it if needed.
    const defaultDbName = process.env.PGDATABASE || 'Qor';
    const host = process.env.DB_CONNECT_HOST || process.env.PGHOST || 'localhost';
    const port = process.env.PGPORT ? Number.parseInt(process.env.PGPORT, 10) : 5432;
    const user = process.env.DATABASE_USER || process.env.PGUSER || process.env.USER || undefined;

    const passwordFromEnv =
      (typeof process.env.DATABASE_PASSWORD === 'string' && process.env.DATABASE_PASSWORD.length > 0)
        ? process.env.DATABASE_PASSWORD
        : (typeof process.env.PGPASSWORD === 'string' && process.env.PGPASSWORD.length > 0)
          ? process.env.PGPASSWORD
          : undefined;

    const baseConfig = { host, port, user };
    if (passwordFromEnv !== undefined) {
      baseConfig.password = passwordFromEnv;
    }

    const poolConfig = {
      ...baseConfig,
      database: defaultDbName,
      max: maxConnections,
      idleTimeoutMillis: idleTimeoutMs,
      connectionTimeoutMillis: connectTimeoutMs,
      ssl: {
        ...sslConfig,
        servername: process.env.DB_TLS_SERVERNAME || host,
      },
    };

    let pool = new Pool(poolConfig);
    try {
      await pool.query('SELECT 1');
      cryptoLogger.info('[DB] Database connection established', {
        host,
        port,
        database: defaultDbName,
        user: user || '<default>'
      });
      pgPool = pool;
      console.warn('[DB] DATABASE_URL not set; using local Postgres database with defaults', {
        host,
        port,
        database: defaultDbName,
        user: user || '<default>',
      });
      return pgPool;
    } catch (err) {
      const msg = err?.message || String(err);
      const missingDb = /database "?.+"? does not exist/i.test(msg);
      const missingRole = /role "?.+"? does not exist/i.test(msg);

      if (!missingDb && !missingRole) {
        try { await pool.end(); } catch { }
        throw err;
      }

      cryptoLogger.warn('[DB] Initial connection failed; attempting bootstrap via sudo psql', {
        database: defaultDbName,
        user: user || '<default>',
        error: msg,
      });

      const created = await tryCreateDatabaseViaConnection(defaultDbName, user, passwordFromEnv, host, port, {
        ...sslConfig,
        servername: process.env.DB_TLS_SERVERNAME || host,
      });

      if (!created) {
        tryCreateDatabaseWithSudo(defaultDbName, user, passwordFromEnv);
      }

      try { await pool.end(); } catch { }
      pool = new Pool(poolConfig);
      try {
        await pool.query('SELECT 1');
        cryptoLogger.info('[DB] Database connection established after bootstrap', {
          host,
          port,
          database: defaultDbName,
          user: user || '<default>'
        });
        pgPool = pool;
        console.warn('[DB] DATABASE_URL not set; using local Postgres database with defaults', {
          host,
          port,
          database: defaultDbName,
          user: user || '<default>',
        });
        return pgPool;
      } catch (err2) {
        try { await pool.end(); } catch { }
        throw err2;
      }
    }
  } catch (e) {
    console.error('[DB] Failed to initialize Postgres pool:', e);
    throw e;
  }
}

let initialized = false;

export async function initDatabase() {
  if (initialized) return;
  initialized = true;

  if (!USE_PG) {
    throw new Error('Postgres is required. Please set DATABASE_URL for the server.');
  }

  const pool = await getPgPool();

  // User table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      passwordHash TEXT,
      passphraseHash TEXT,
      version INTEGER,
      algorithm TEXT,
      salt TEXT,
      memoryCost INTEGER,
      timeCost INTEGER,
      parallelism INTEGER,
      passwordVersion INTEGER,
      passwordAlgorithm TEXT,
      passwordSalt TEXT,
      passwordMemoryCost INTEGER,
      passwordTimeCost INTEGER,
      passwordParallelism INTEGER,
      hybridPublicKeys TEXT
    )
  `);

  // Temporary offline message storage
  await pool.query(`
    CREATE TABLE IF NOT EXISTS offline_messages (
      id BIGSERIAL PRIMARY KEY,
      toUsername TEXT NOT NULL,
      payload TEXT NOT NULL,
      queuedAt BIGINT NOT NULL
    )
  `);

  // Libsignal bundle storage
  await pool.query(`
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
      updatedAt BIGINT NOT NULL
    )
  `);

  // Encrypted block lists and block tokens
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_block_lists (
      username TEXT PRIMARY KEY,
      encryptedBlockList TEXT NOT NULL,
      blockListHash TEXT NOT NULL,
      salt TEXT,
      lastUpdated BIGINT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS block_tokens (
      tokenHash TEXT PRIMARY KEY,
      blockerHash TEXT NOT NULL,
      blockedHash TEXT NOT NULL,
      createdAt BIGINT NOT NULL,
      expiresAt BIGINT
    )
  `);

  // Authentication token storage
  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      tokenId TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      deviceId TEXT NOT NULL,
      userIdProtected TEXT,
      deviceIdProtected TEXT,
      family TEXT NOT NULL,
      tokenHash TEXT NOT NULL,
      generation INTEGER NOT NULL DEFAULT 1,
      issuedAt BIGINT NOT NULL,
      expiresAt BIGINT NOT NULL,
      lastUsed BIGINT,
      revokedAt BIGINT,
      revokeReason TEXT,
      deviceFingerprint TEXT,
      securityContext TEXT,
      createdFrom TEXT,
      userAgent TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS token_families (
      familyId TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      deviceId TEXT NOT NULL,
      createdAt BIGINT NOT NULL,
      tokenCount INTEGER NOT NULL DEFAULT 0,
      lastRotation BIGINT,
      revokedAt BIGINT,
      revokeReason TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS token_blacklist (
      tokenId TEXT PRIMARY KEY,
      tokenType TEXT NOT NULL,
      userId TEXT,
      blacklistedAt BIGINT NOT NULL,
      expiresAt BIGINT NOT NULL,
      reason TEXT,
      revokedBy TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_audit_log (
      id BIGSERIAL PRIMARY KEY,
      userId TEXT,
      deviceId TEXT,
      action TEXT NOT NULL,
      tokenType TEXT,
      tokenId TEXT,
      success INTEGER NOT NULL,
      failureReason TEXT,
      ipAddressHash TEXT,
      userAgent TEXT,
      riskScore TEXT,
      securityFlags TEXT,
      timestamp BIGINT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_sessions (
      deviceId TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      deviceName TEXT,
      deviceType TEXT,
      fingerprint TEXT,
      firstSeen BIGINT NOT NULL,
      lastSeen BIGINT NOT NULL,
      isActive INTEGER NOT NULL DEFAULT 1,
      riskScore TEXT,
      location TEXT,
      userAgent TEXT,
      clientVersion TEXT,
      securityFlags TEXT
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_block_tokens_hash ON block_tokens(tokenHash)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_block_tokens_blocker ON block_tokens(blockerHash)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_block_tokens_expires ON block_tokens(expiresAt) WHERE expiresAt IS NOT NULL');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_block_lists_updated ON user_block_lists(lastUpdated)');

  await pool.query('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(userId)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expiresAt)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_refresh_tokens_lastUsed ON refresh_tokens(lastUsed)');

  await pool.query('CREATE INDEX IF NOT EXISTS idx_token_families_user ON token_families(userId)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_token_families_device ON token_families(deviceId)');

  await pool.query('CREATE INDEX IF NOT EXISTS idx_token_blacklist_tokenId ON token_blacklist(tokenId)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires ON token_blacklist(expiresAt)');

  await pool.query('CREATE INDEX IF NOT EXISTS idx_auth_audit_log_timestamp ON auth_audit_log(timestamp)');

  await pool.query('CREATE INDEX IF NOT EXISTS idx_device_sessions_user ON device_sessions(userId)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_device_sessions_lastSeen ON device_sessions(lastSeen)');

  // Encrypted avatar storage
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_avatars (
      username TEXT PRIMARY KEY,
      encryptedEnvelope TEXT NOT NULL,
      shareWithOthers INTEGER NOT NULL DEFAULT 0,
      publicData TEXT,
      updatedAt BIGINT NOT NULL
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_avatars_share ON user_avatars(shareWithOthers) WHERE shareWithOthers = 1');

  console.log('[DB] Database tables initialized');
}

export class UserDatabase {
  static encodeStoredPasswordHash(rawHash) {
    return encodeStoredPasswordHash(rawHash);
  }

  static decodeStoredPasswordHash(storedValue) {
    return decodeStoredPasswordHash(storedValue);
  }

  static async loadUser(username) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username parameter: ${username}`);
      return null;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format: ${username}`);
      return null;
    }

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        let user = rows[0] || null;
        user = normalizeUserRecord(user);
        return user;
      }

      let row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      row = normalizeUserRecord(row);
      return row;
    } catch (error) {
      console.error(`[DB] Error loading user ${username}:`, error);
      return null;
    }
  }

  static async saveUserRecord(userRecord) {
    if (!userRecord || typeof userRecord !== 'object') {
      console.error('[DB] Invalid user record structure');
      throw new Error('Invalid user record structure');
    }

    const { username, passwordHash } = userRecord;

    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username in user record: ${username}`);
      throw new Error('Invalid username in user record');
    }

    if (!passwordHash || typeof passwordHash !== 'string' || passwordHash.length < 10) {
      console.error('[DB] Invalid password hash in user record');
      throw new Error('Invalid password hash in user record');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format in user record: ${username}`);
      throw new Error('Invalid username format in user record');
    }

    try {
      const storedPasswordHash = encodeStoredPasswordHash(passwordHash);
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query(
          `
          INSERT INTO users (
            username, passwordHash, passphraseHash,
            version, algorithm, salt, memoryCost, timeCost, parallelism,
            passwordVersion, passwordAlgorithm, passwordSalt, passwordMemoryCost, passwordTimeCost, passwordParallelism
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          ON CONFLICT (username) DO UPDATE SET
            passwordHash = EXCLUDED.passwordHash,
            passphraseHash = EXCLUDED.passphraseHash,
            version = EXCLUDED.version,
            algorithm = EXCLUDED.algorithm,
            salt = EXCLUDED.salt,
            memoryCost = EXCLUDED.memoryCost,
            timeCost = EXCLUDED.timeCost,
            parallelism = EXCLUDED.parallelism,
            passwordVersion = EXCLUDED.passwordVersion,
            passwordAlgorithm = EXCLUDED.passwordAlgorithm,
            passwordSalt = EXCLUDED.passwordSalt,
            passwordMemoryCost = EXCLUDED.passwordMemoryCost,
            passwordTimeCost = EXCLUDED.passwordTimeCost,
            passwordParallelism = EXCLUDED.passwordParallelism
        `,
          [
            username,
            storedPasswordHash,
            userRecord.passphraseHash,
            userRecord.version,
            userRecord.algorithm,
            userRecord.salt,
            userRecord.memoryCost,
            userRecord.timeCost,
            userRecord.parallelism,
            userRecord.passwordVersion,
            userRecord.passwordAlgorithm,
            userRecord.passwordSalt,
            userRecord.passwordMemoryCost,
            userRecord.passwordTimeCost,
            userRecord.passwordParallelism,
          ],
        );
      } else {
        const recordWithStoredHash = {
          ...userRecord,
          passwordHash: storedPasswordHash,
        };
        db.prepare(
          `
          INSERT INTO users (
            username, passwordHash, passphraseHash,
            version, algorithm, salt, memoryCost, timeCost, parallelism,
            passwordVersion, passwordAlgorithm, passwordSalt, passwordMemoryCost, passwordTimeCost, passwordParallelism
          )
          VALUES (@username, @passwordHash, @passphraseHash,
            @version, @algorithm, @salt, @memoryCost, @timeCost, @parallelism,
            @passwordVersion, @passwordAlgorithm, @passwordSalt, @passwordMemoryCost, @passwordTimeCost, @passwordParallelism)
          ON CONFLICT(username) DO UPDATE SET
            passwordHash = excluded.passwordHash,
            passphraseHash = excluded.passphraseHash,
            version = excluded.version,
            algorithm = excluded.algorithm,
            salt = excluded.salt,
            memoryCost = excluded.memoryCost,
            timeCost = excluded.timeCost,
            parallelism = excluded.parallelism,
            passwordVersion = excluded.passwordVersion,
            passwordAlgorithm = excluded.passwordAlgorithm,
            passwordSalt = excluded.passwordSalt,
            passwordMemoryCost = excluded.passwordMemoryCost,
            passwordTimeCost = excluded.passwordTimeCost,
            passwordParallelism = excluded.passwordParallelism
        `,
        ).run(recordWithStoredHash);
      }
    } catch (error) {
      console.error(`[DB] Error saving user record for ${username}:`, error);
      throw error;
    }
  }

  static async updateUserPassword(username, newPasswordHash) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username for password update: ${username}`);
      throw new Error('Invalid username for password update');
    }

    if (!newPasswordHash || typeof newPasswordHash !== 'string' || newPasswordHash.length < 10) {
      console.error('[DB] Invalid password hash for update');
      throw new Error('Invalid password hash for update');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format for password update: ${username}`);
      throw new Error('Invalid username format for password update');
    }

    const storedHash = encodeStoredPasswordHash(newPasswordHash);

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const result = await pool.query(
          'UPDATE users SET passwordHash = $1 WHERE username = $2',
          [storedHash, username],
        );
        if (result.rowCount === 0) {
          throw new Error('User not found for password update');
        }
      } else {
        const result = db.prepare('UPDATE users SET passwordHash = ? WHERE username = ?')
          .run(storedHash, username);
        if (result.changes === 0) {
          throw new Error('User not found for password update');
        }
      }
    } catch (error) {
      console.error(`[DB] Error updating password for ${username}:`, error);
      throw error;
    }
  }

  static verifyStoredPasswordHash(rawHash, storedValue) {
    return verifyPepperedHash(rawHash, storedValue);
  }

  static async updateUserPasswordParams(updateData) {
    if (!updateData || typeof updateData !== 'object') {
      console.error('[DB] Invalid update data structure');
      throw new Error('Invalid update data structure');
    }

    const { username, passwordVersion, passwordAlgorithm, passwordSalt, passwordMemoryCost, passwordTimeCost, passwordParallelism } = updateData;

    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username for password params update: ${username}`);
      throw new Error('Invalid username for password params update');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format for password params update: ${username}`);
      throw new Error('Invalid username format for password params update');
    }

    console.log(`[DB] Updating password parameters for user: ${username}`);
    try {
      const pool = await getPgPool();
      const result = await pool.query(`
        UPDATE users SET 
          passwordVersion = $1, passwordAlgorithm = $2, passwordSalt = $3,
          passwordMemoryCost = $4, passwordTimeCost = $5, passwordParallelism = $6
        WHERE username = $7
      `, [
        passwordVersion, passwordAlgorithm, passwordSalt,
        passwordMemoryCost, passwordTimeCost, passwordParallelism,
        username
      ]);
      if (result.rowCount === 0) {
        throw new Error('User not found for password params update');
      }
      console.log(`[DB] Password parameters updated successfully for user: ${username}`);
    } catch (error) {
      console.error(`[DB] Error updating password parameters for ${username}:`, error);
      throw error;
    }
  }

  // Store sanitized hybrid public keys for a user
  static async updateHybridPublicKeys(username, hybridPublicKeys) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username for hybrid key update: ${username}`);
      throw new Error('Invalid username for hybrid key update');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format for hybrid key update: ${username}`);
      throw new Error('Invalid username format for hybrid key update');
    }

    try {
      const pool = await getPgPool();
      const result = await pool.query(
        'UPDATE users SET hybridPublicKeys = $1 WHERE username = $2',
        [JSON.stringify(hybridPublicKeys || {}), username],
      );
      if (result.rowCount === 0) {
        throw new Error('User not found for hybrid key update');
      }
      console.log(`[DB] Hybrid public keys updated for user: ${username}`);
    } catch (error) {
      console.error(`[DB] Error updating hybrid keys for ${username}:`, error);
      throw error;
    }
  }

  // Load stored hybrid public keys for a user
  static async getHybridPublicKeys(username) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username for hybrid key lookup: ${username}`);
      return null;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format for hybrid key lookup: ${username}`);
      return null;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query(
        'SELECT hybridPublicKeys FROM users WHERE username = $1',
        [username],
      );
      const row = rows[0];
      if (!row) return null;
      const raw = row.hybridpublickeys ?? row.hybridPublicKeys;
      if (!raw || typeof raw !== 'string') return null;
      const parsed = safeJsonParseObject(raw);
      if (!parsed) {
        console.warn('[DB] Failed to parse hybridPublicKeys JSON for user:', username);
        return null;
      }
      return parsed;
    } catch (error) {
      console.error(`[DB] Error loading hybrid keys for ${username}:`, error);
      return null;
    }
  }
}

export class MessageDatabase {
  static async queueOfflineMessage(toUsername, payloadObj) {
    if (!toUsername || typeof toUsername !== 'string' || toUsername.length < 3 || toUsername.length > 32) {
      console.error('[DB] Invalid toUsername for offline message');
      return false;
    }

    if (!payloadObj || typeof payloadObj !== 'object') {
      console.error('[DB] Invalid payload for offline message');
      return false;
    }

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
        try {
          const pool = await getPgPool();
          await pool.query('INSERT INTO offline_messages (toUsername, payload, queuedAt) VALUES ($1,$2,$3)', [toUsername, payload, queuedAt]);
          return true;
        } catch (error) {
          console.error('[DB] Error inserting offline message (PG):', error);
          return false;
        }
      } else {
        try {
          db.prepare(`INSERT INTO offline_messages (toUsername, payload, queuedAt) VALUES (?, ?, ?)`).run(toUsername, payload, queuedAt);
          return true;
        } catch (error) {
          console.error('[DB] Error inserting offline message:', error);
          return false;
        }
      }
    } catch (error) {
      console.error('[DB] Error queueing offline message:', error);
      return false;
    }
  }

  static async takeOfflineMessages(toUsername, max = 100) {
    if (!toUsername || typeof toUsername !== 'string' || toUsername.length < 3 || toUsername.length > 32) {
      console.error('[DB] Invalid toUsername parameter');
      return [];
    }

    if (!Number.isInteger(max) || max < 1 || max > 1000) {
      console.error('[DB] Invalid max parameter - must be integer between 1 and 1000');
      return [];
    }

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
        const messages = rows.map(r => safeJsonParseObject(r.payload)).filter(Boolean);
        if (ids.length > 0) {
          await pool.query('DELETE FROM offline_messages WHERE id = ANY($1::int[])', [ids]);
        }
        return messages;
      } else {
        const rows = db.prepare(`SELECT id, payload FROM offline_messages WHERE toUsername = ? ORDER BY queuedAt ASC LIMIT ?`).all(toUsername, max);
        if (!rows || rows.length === 0) return [];
        const ids = rows.map(r => r.id);
        if (!ids.every(id => Number.isInteger(id) && id > 0)) return [];
        const messages = rows.map(r => safeJsonParseObject(r.payload)).filter(Boolean);
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

export class LibsignalBundleDB {
  static async publish(username, bundle) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username parameter in LibsignalBundleDB.publish: ${username}`);
      throw new Error('Invalid username parameter');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[DB] Invalid username format in LibsignalBundleDB.publish: ${username}`);
      throw new Error('Invalid username format');
    }

    if (!bundle || typeof bundle !== 'object') {
      console.error('[DB] Invalid bundle structure in LibsignalBundleDB.publish');
      throw new Error('Invalid bundle structure');
    }

    const requiredFields = ['registrationId', 'deviceId', 'identityKeyBase64', 'signedPreKeyId',
      'signedPreKeyPublicBase64', 'signedPreKeySignatureBase64',
      'kyberPreKeyId', 'kyberPreKeyPublicBase64', 'kyberPreKeySignatureBase64'];

    for (const field of requiredFields) {
      if (bundle[field] === undefined || bundle[field] === null) {
        console.error(`[DB] Missing required field in bundle: ${field}`);
        throw new Error('Missing required field in bundle: [REDACTED]');
      }
    }

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
      const encIdentityKey = LibsignalFieldEncryption.encryptField(bundle.identityKeyBase64, 'identityKeyBase64');
      const encPreKeyPublic = bundle.preKeyPublicBase64
        ? LibsignalFieldEncryption.encryptField(bundle.preKeyPublicBase64, 'preKeyPublicBase64')
        : null;
      const encSignedPreKeyPublic = LibsignalFieldEncryption.encryptField(
        bundle.signedPreKeyPublicBase64,
        'signedPreKeyPublicBase64'
      );
      const encSignedPreKeySig = LibsignalFieldEncryption.encryptField(
        bundle.signedPreKeySignatureBase64,
        'signedPreKeySignatureBase64'
      );
      const encKyberPreKeyPublic = LibsignalFieldEncryption.encryptField(
        bundle.kyberPreKeyPublicBase64,
        'kyberPreKeyPublicBase64'
      );
      const encKyberPreKeySig = LibsignalFieldEncryption.encryptField(
        bundle.kyberPreKeySignatureBase64,
        'kyberPreKeySignatureBase64'
      );

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
          encIdentityKey,
          bundle.preKeyId ?? null,
          encPreKeyPublic,
          bundle.signedPreKeyId,
          encSignedPreKeyPublic,
          encSignedPreKeySig,
          bundle.kyberPreKeyId,
          encKyberPreKeyPublic,
          encKyberPreKeySig,
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
          encIdentityKey,
          bundle.preKeyId ?? null,
          encPreKeyPublic,
          bundle.signedPreKeyId,
          encSignedPreKeyPublic,
          encSignedPreKeySig,
          bundle.kyberPreKeyId,
          encKyberPreKeyPublic,
          encKyberPreKeySig,
          now
        );
      }
    } catch (error) {
      console.error(`[DB] Error publishing libsignal bundle for ${username}:`, error);
      throw error;
    }
  }

  static async take(username) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[DB] Invalid username parameter in LibsignalBundleDB.take: ${username}`);
      return null;
    }

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

        const identityRaw = row.identityKeyBase64 ?? row.identitykeybase64;
        const preKeyPublicRaw = row.preKeyPublicBase64 ?? row.prekeypublicbase64;
        const signedPreKeyPublicRaw = row.signedPreKeyPublicBase64 ?? row.signedprekeypublicbase64;
        const signedPreKeySigRaw = row.signedPreKeySignatureBase64 ?? row.signedprekeysignaturebase64;
        const kyberPreKeyPublicRaw = row.kyberPreKeyPublicBase64 ?? row.kyberprekeypublicbase64;
        const kyberPreKeySigRaw = row.kyberPreKeySignatureBase64 ?? row.kyberprekeysignaturebase64;

        return {
          registrationId: row.registrationId ?? row.registrationid,
          deviceId: row.deviceId ?? row.deviceid,
          identityKeyBase64: LibsignalFieldEncryption.decryptField(identityRaw, 'identityKeyBase64'),
          preKeyId: row.preKeyId ?? row.prekeyid,
          preKeyPublicBase64: LibsignalFieldEncryption.decryptField(preKeyPublicRaw, 'preKeyPublicBase64'),
          signedPreKeyId: row.signedPreKeyId ?? row.signedprekeyid,
          signedPreKeyPublicBase64: LibsignalFieldEncryption.decryptField(signedPreKeyPublicRaw, 'signedPreKeyPublicBase64'),
          signedPreKeySignatureBase64: LibsignalFieldEncryption.decryptField(signedPreKeySigRaw, 'signedPreKeySignatureBase64'),
          kyberPreKeyId: row.kyberPreKeyId ?? row.kyberprekeyid,
          kyberPreKeyPublicBase64: LibsignalFieldEncryption.decryptField(kyberPreKeyPublicRaw, 'kyberPreKeyPublicBase64'),
          kyberPreKeySignatureBase64: LibsignalFieldEncryption.decryptField(kyberPreKeySigRaw, 'kyberPreKeySignatureBase64'),
        };
      } else {
        const row = db.prepare(`SELECT * FROM libsignal_bundles WHERE username = ?`).get(username);
        if (!row) return null;

        return {
          registrationId: row.registrationId,
          deviceId: row.deviceId,
          identityKeyBase64: LibsignalFieldEncryption.decryptField(row.identityKeyBase64, 'identityKeyBase64'),
          preKeyId: row.preKeyId,
          preKeyPublicBase64: LibsignalFieldEncryption.decryptField(row.preKeyPublicBase64, 'preKeyPublicBase64'),
          signedPreKeyId: row.signedPreKeyId,
          signedPreKeyPublicBase64: LibsignalFieldEncryption.decryptField(row.signedPreKeyPublicBase64, 'signedPreKeyPublicBase64'),
          signedPreKeySignatureBase64: LibsignalFieldEncryption.decryptField(row.signedPreKeySignatureBase64, 'signedPreKeySignatureBase64'),
          kyberPreKeyId: row.kyberPreKeyId,
          kyberPreKeyPublicBase64: LibsignalFieldEncryption.decryptField(row.kyberPreKeyPublicBase64, 'kyberPreKeyPublicBase64'),
          kyberPreKeySignatureBase64: LibsignalFieldEncryption.decryptField(row.kyberPreKeySignatureBase64, 'kyberPreKeySignatureBase64'),
        };
      }
    } catch (error) {
      console.error(`[DB] Error taking libsignal bundle for ${username}:`, error);
      return null;
    }
  }
}

/**
 * Blocking Database
 */
export class BlockingDatabase {
  // Store encrypted block list for a user
  static async storeEncryptedBlockList(username, encryptedBlockList, blockListHash, salt, version, lastUpdated) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[BLOCKING] Invalid username: ${username}`);
      throw new Error('Invalid username');
    }

    if (!encryptedBlockList || typeof encryptedBlockList !== 'string') {
      console.error('[BLOCKING] Invalid encrypted block list');
      throw new Error('Invalid encrypted block list');
    }

    if (!blockListHash || typeof blockListHash !== 'string') {
      console.error('[BLOCKING] Invalid block list hash');
      throw new Error('Invalid block list hash');
    }

    if (!salt || typeof salt !== 'string') {
      console.error('[BLOCKING] Invalid salt');
      throw new Error('Invalid salt');
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[BLOCKING] Invalid username format: ${username}`);
      throw new Error('Invalid username format');
    }

    const now = lastUpdated || Date.now();
    const blockListVersion = version || 1;

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query(`
          INSERT INTO user_block_lists (username, encryptedBlockList, blockListHash, salt, lastUpdated, version)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (username) DO UPDATE SET
            encryptedBlockList = EXCLUDED.encryptedBlockList,
            blockListHash = EXCLUDED.blockListHash,
            salt = EXCLUDED.salt,
            lastUpdated = EXCLUDED.lastUpdated,
            version = EXCLUDED.version
        `, [username, encryptedBlockList, blockListHash, salt, now, blockListVersion]);
      } else {
        db.prepare(`
          INSERT INTO user_block_lists (username, encryptedBlockList, blockListHash, salt, lastUpdated, version)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(username) DO UPDATE SET
            encryptedBlockList = excluded.encryptedBlockList,
            blockListHash = excluded.blockListHash,
            salt = excluded.salt,
            lastUpdated = excluded.lastUpdated,
            version = excluded.version
        `).run(username, encryptedBlockList, blockListHash, salt, now, blockListVersion);
      }

      console.log(`[BLOCKING] Stored encrypted block list for user: ${username}`);
    } catch (error) {
      console.error(`[BLOCKING] Error storing block list for ${username}:`, error);
      throw error;
    }
  }

  // Retrieve encrypted block list for a user
  static async getEncryptedBlockList(username) {
    if (!username || typeof username !== 'string' || username.length < 3 || username.length > 32) {
      console.error(`[BLOCKING] Invalid username: ${username}`);
      return null;
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      console.error(`[BLOCKING] Invalid username format: ${username}`);
      return null;
    }

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query(
          'SELECT encryptedBlockList, blockListHash, salt, lastUpdated, version FROM user_block_lists WHERE username = $1',
          [username]
        );
        const row = rows[0];
        if (!row) return null;
        return {
          encryptedBlockList: row.encryptedblocklist ?? row.encryptedBlockList,
          blockListHash: row.blocklisthash ?? row.blockListHash,
          salt: row.salt,
          lastUpdated: row.lastupdated ?? row.lastUpdated,
          version: row.version,
        };
      } else {
        const row = db.prepare(
          'SELECT encryptedBlockList, blockListHash, salt, lastUpdated, version FROM user_block_lists WHERE username = ?'
        ).get(username);
        return row || null;
      }
    } catch (error) {
      console.error(`[BLOCKING] Error retrieving block list for ${username}:`, error);
      return null;
    }
  }

  // Store block tokens for server-side filtering
  static async storeBlockTokens(blockTokens, blockerHashForClear) {
    if (Array.isArray(blockTokens) && blockTokens.length === 0) {
      try {
        const validLen = (s) => typeof s === 'string' && /^[a-f0-9]+$/i.test(s) && (s.length === 32 || s.length === 64 || s.length === 128);
        if (!validLen(blockerHashForClear)) return;
        if (USE_PG) {
          const pool = await getPgPool();
          await pool.query('DELETE FROM block_tokens WHERE blockerHash = $1', [blockerHashForClear]);
        } else {
          db.prepare('DELETE FROM block_tokens WHERE blockerHash = ?').run(blockerHashForClear);
        }
      } catch (error) {
        console.error('[BLOCKING] Error clearing block tokens for blocker:', error);
      }
      return;
    }

    if (!Array.isArray(blockTokens) || blockTokens.length === 0) {
      return;
    }

    for (const token of blockTokens) {
      if (!token || typeof token !== 'object') {
        throw new Error('Invalid block token structure');
      }

      const validLen = (s) => typeof s === 'string' && /^[a-f0-9]+$/i.test(s) && (s.length === 32 || s.length === 64 || s.length === 128);
      if (!validLen(token.tokenHash)) {
        throw new Error('Invalid token hash');
      }
      if (!validLen(token.blockerHash)) {
        throw new Error('Invalid blocker hash');
      }
      if (!validLen(token.blockedHash)) {
        throw new Error('Invalid blocked hash');
      }
    }

    const now = Date.now();

    const normalizedTokens = blockTokens.map(token => ({
      tokenHash: token.tokenHash.length > 64 ? token.tokenHash.substring(0, 64) : token.tokenHash,
      blockerHash: token.blockerHash,
      blockedHash: token.blockedHash,
      expiresAt: token.expiresAt
    }));

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const client = await pool.connect();
        try {
          await client.query('BEGIN');

          const blockerHashes = [...new Set(normalizedTokens.map(t => t.blockerHash))];
          if (blockerHashForClear && !blockerHashes.includes(blockerHashForClear)) {
            blockerHashes.push(blockerHashForClear);
          }
          if (blockerHashes.length > 0) {
            const placeholders = blockerHashes.map((_, i) => `$${i + 1}`).join(',');
            await client.query(
              `DELETE FROM block_tokens WHERE blockerHash IN (${placeholders})`,
              blockerHashes
            );
          }

          for (const token of normalizedTokens) {
            await client.query(`
              INSERT INTO block_tokens (tokenHash, blockerHash, blockedHash, createdAt, expiresAt)
              VALUES ($1, $2, $3, $4, $5)
            `, [token.tokenHash, token.blockerHash, token.blockedHash, now, token.expiresAt || null]);
          }

          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK');
          throw error;
        } finally {
          client.release();
        }
      } else {
        const insertStmt = db.prepare(`
          INSERT INTO block_tokens (tokenHash, blockerHash, blockedHash, createdAt, expiresAt)
          VALUES (?, ?, ?, ?, ?)
        `);

        const transaction = db.transaction((tokens) => {
          const blockerHashes = [...new Set(tokens.map(t => t.blockerHash))];
          if (blockerHashForClear && !blockerHashes.includes(blockerHashForClear)) {
            blockerHashes.push(blockerHashForClear);
          }
          for (const blockerHash of blockerHashes) {
            db.prepare('DELETE FROM block_tokens WHERE blockerHash = ?').run(blockerHash);
          }

          for (const token of tokens) {
            insertStmt.run(
              token.tokenHash,
              token.blockerHash,
              token.blockedHash,
              now,
              token.expiresAt || null
            );
          }
        });

        transaction(normalizedTokens);
      }

      console.log(`[BLOCKING] Stored ${blockTokens.length} block tokens`);
    } catch (error) {
      console.error('[BLOCKING] Error storing block tokens:', error);
      throw error;
    }
  }

  // Check if a message should be blocked based on block tokens
  static async isMessageBlocked(fromHash, toHash) {
    const validLen = (s) => typeof s === 'string' && /^[a-f0-9]+$/i.test(s) && (s.length === 32 || s.length === 64 || s.length === 128);
    if (!validLen(fromHash) || !validLen(toHash)) {
      return false;
    }

    const norm = (s) => (s.length === 128 ? s.substring(0, 64) : s);
    const normalizedFromHash = norm(fromHash);
    const normalizedToHash = norm(toHash);

    try {
      const now = Date.now();
      // Case 1: recipient has blocked sender
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query(
          'SELECT 1 FROM block_tokens WHERE blockerHash = $1 AND blockedHash = $2 AND (expiresAt IS NULL OR expiresAt > $3) LIMIT 1',
          [normalizedToHash, normalizedFromHash, now]
        );
        if (rows.length > 0) return true;
      } else {
        const row = db.prepare(
          'SELECT 1 FROM block_tokens WHERE blockerHash = ? AND blockedHash = ? AND (expiresAt IS NULL OR expiresAt > ?) LIMIT 1'
        ).get(normalizedToHash, normalizedFromHash, now);
        if (row) return true;
      }

      // Case 2: sender has blocked recipient
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query(
          'SELECT 1 FROM block_tokens WHERE blockerHash = $1 AND blockedHash = $2 AND (expiresAt IS NULL OR expiresAt > $3) LIMIT 1',
          [normalizedFromHash, normalizedToHash, now]
        );
        if (rows.length > 0) return true;
      } else {
        const row2 = db.prepare(
          'SELECT 1 FROM block_tokens WHERE blockerHash = ? AND blockedHash = ? AND (expiresAt IS NULL OR expiresAt > ?) LIMIT 1'
        ).get(normalizedFromHash, normalizedToHash, now);
        if (row2) return true;
      }

      return false;
    } catch (error) {
      console.error('[BLOCKING] Error checking block status:', error);
      return false;
    }
  }

  // Clean up expired block tokens
  static async cleanupExpiredTokens() {
    const now = Date.now();

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const { rowCount } = await pool.query(
          'DELETE FROM block_tokens WHERE expiresAt IS NOT NULL AND expiresAt <= $1',
          [now]
        );
        if (rowCount > 0) {
          console.log(`[BLOCKING] Cleaned up ${rowCount} expired block tokens`);
        }
      } else {
        const result = db.prepare(
          'DELETE FROM block_tokens WHERE expiresAt IS NOT NULL AND expiresAt <= ?'
        ).run(now);
        if (result.changes > 0) {
          console.log(`[BLOCKING] Cleaned up ${result.changes} expired block tokens`);
        }
      }
    } catch (error) {
      console.error('[BLOCKING] Error cleaning up expired tokens:', error);
    }
  }
}

// Avatar storage
export class AvatarDatabase {
  // Store or update an encrypted avatar
  static async storeAvatar(username, encryptedEnvelope, shareWithOthers = false, publicData = null) {
    if (!username || typeof username !== 'string') {
      throw new Error('Invalid username');
    }
    if (!encryptedEnvelope || typeof encryptedEnvelope !== 'string') {
      throw new Error('Invalid encrypted envelope');
    }

    const now = Date.now();

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query(`
          INSERT INTO user_avatars (username, encryptedEnvelope, shareWithOthers, publicData, updatedAt)
          VALUES ($1, $2, $3, $4, $5)
          ON CONFLICT (username) DO UPDATE SET
            encryptedEnvelope = EXCLUDED.encryptedEnvelope,
            shareWithOthers = EXCLUDED.shareWithOthers,
            publicData = EXCLUDED.publicData,
            updatedAt = EXCLUDED.updatedAt
        `, [username, encryptedEnvelope, shareWithOthers ? 1 : 0, publicData, now]);
      }
      cryptoLogger.info('[AVATAR] Stored avatar', {
        username: username.slice(0, 8) + '...',
        shareWithOthers
      });
    } catch (error) {
      cryptoLogger.error('[AVATAR] Failed to store avatar', {
        username: username.slice(0, 8) + '...',
        error: error.message
      });
      throw error;
    }
  }

  // Get own encrypted avatar
  static async getOwnAvatar(username) {
    if (!username || typeof username !== 'string') {
      return null;
    }

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query(
          'SELECT encryptedEnvelope, updatedAt FROM user_avatars WHERE username = $1',
          [username]
        );
        if (rows.length === 0) return null;
        return {
          encryptedEnvelope: rows[0].encryptedenvelope,
          updatedAt: rows[0].updatedat
        };
      }
      return null;
    } catch (error) {
      cryptoLogger.error('[AVATAR] Failed to get own avatar', {
        username: username.slice(0, 8) + '...',
        error: error.message
      });
      return null;
    }
  }

  // Get a peer's public avatar
  static async getPeerAvatar(username) {
    if (!username || typeof username !== 'string') {
      return null;
    }

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        const { rows } = await pool.query(
          'SELECT publicData, updatedAt FROM user_avatars WHERE username = $1 AND shareWithOthers = 1',
          [username]
        );
        if (rows.length === 0 || !rows[0].publicdata) return null;
        return {
          publicData: rows[0].publicdata,
          updatedAt: rows[0].updatedat
        };
      }
      return null;
    } catch (error) {
      cryptoLogger.error('[AVATAR] Failed to get peer avatar', {
        username: username.slice(0, 8) + '...',
        error: error.message
      });
      return null;
    }
  }

  // Delete avatar
  static async deleteAvatar(username) {
    if (!username || typeof username !== 'string') {
      return;
    }

    try {
      if (USE_PG) {
        const pool = await getPgPool();
        await pool.query('DELETE FROM user_avatars WHERE username = $1', [username]);
      }
      cryptoLogger.info('[AVATAR] Deleted avatar', {
        username: username.slice(0, 8) + '...'
      });
    } catch (error) {
      cryptoLogger.error('[AVATAR] Failed to delete avatar', {
        username: username.slice(0, 8) + '...',
        error: error.message
      });
    }
  }
}