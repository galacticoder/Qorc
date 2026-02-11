/**
 * Database Connection Pool and Utilities
 * 
 * Shared database infrastructure used by all database modules
 */

import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto, { randomBytes } from 'crypto';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { PostQuantumHash } from '../crypto/post-quantum-hash.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Anonymize identifiers in logs
const logSalt = crypto.randomBytes(16).toString('hex');
export function anonId(id) {
  if (!id) return '[none]';
  return crypto.createHash('blake2b512').update(`${logSalt}:${id}`).digest('hex').slice(0, 8);
}

const RESERVED_JSON_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

export function sanitizeParsedJson(value) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sanitizeParsedJson);
  const out = Object.create(null);
  for (const [key, v] of Object.entries(value)) {
    if (RESERVED_JSON_KEYS.has(key)) continue;
    out[key] = sanitizeParsedJson(v);
  }
  return out;
}

export function safeJsonParseObject(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return sanitizeParsedJson(parsed);
  } catch {
    return null;
  }
}

// Secret file paths
const USER_ID_SALT_FILE_PATH = process.env.USER_ID_SALT_FILE
  ? path.resolve(process.env.USER_ID_SALT_FILE)
  : path.resolve(__dirname, '../config/generated-user-id-salt.txt');

const DB_FIELD_KEY_FILE_PATH = process.env.DB_FIELD_KEY_FILE
  ? path.resolve(process.env.DB_FIELD_KEY_FILE)
  : path.resolve(__dirname, '../config/generated-db-field-key.txt');

const BLOCK_SERVER_SECRET_FILE_PATH = process.env.BLOCK_SERVER_SECRET_FILE
  ? path.resolve(process.env.BLOCK_SERVER_SECRET_FILE)
  : path.resolve(__dirname, '../config/generated-block-server-secret.txt');

/**
 * Load or generate a secret from file
 */
function loadOrGenerateSecret(envVarName, filePath, label, purpose, warningMessage) {
  // Check environment first
  if (process.env[envVarName]) {
    return process.env[envVarName];
  }

  // Try to load from file
  try {
    if (fs.existsSync(filePath)) {
      const secret = fs.readFileSync(filePath, 'utf8').trim();
      if (secret.length >= 32) {
        console.log(`[SECURITY] Loaded ${label} from ${filePath}`);
        return secret;
      }
    }
  } catch (e) {
    console.warn(`[SECURITY] Could not read ${label} from file: ${e.message}`);
  }

  // Generate new secret
  console.log(`[SECURITY] Generating new ${label} for ${purpose}`);
  console.warn(`[SECURITY] WARNING: ${warningMessage}`);

  const newSecret = crypto.randomBytes(64).toString('hex');

  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(filePath, newSecret, { mode: 0o600 });
    console.log(`[SECURITY] Saved ${label} to ${filePath}`);
  } catch (e) {
    console.error(`[SECURITY] Could not save ${label} to file: ${e.message}`);
  }

  return newSecret;
}

// Load secrets
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

const BLOCK_SERVER_SECRET_ENV = loadOrGenerateSecret(
  'BLOCK_SERVER_SECRET',
  BLOCK_SERVER_SECRET_FILE_PATH,
  'BLOCK_SERVER_SECRET',
  'blocking system identity key commitments',
  'Losing this secret will invalidate all existing block commitments'
);
if (!process.env.BLOCK_SERVER_SECRET) {
  process.env.BLOCK_SERVER_SECRET = BLOCK_SERVER_SECRET_ENV;
}

// Field encryption for libsignal bundles
const LIBSIGNAL_FIELD_PREFIX = 'pq2:';

export class LibsignalFieldEncryption {
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
    if (!value) return null;
    const key = this.deriveFieldKey(fieldName);
    const valueBytes = Buffer.from(value, 'utf8');
    const nonce = randomBytes(36);
    const aead = new CryptoUtils.PostQuantumAEAD(key);
    const { ciphertext, tag } = aead.encrypt(valueBytes, nonce);
    const combined = Buffer.concat([nonce, tag, ciphertext]);
    return LIBSIGNAL_FIELD_PREFIX + combined.toString('base64');
  }

  static decryptField(encrypted, fieldName) {
    if (!encrypted) return null;
    if (!encrypted.startsWith(LIBSIGNAL_FIELD_PREFIX)) {
      return encrypted;
    }
    const key = this.deriveFieldKey(fieldName);
    const payload = encrypted.slice(LIBSIGNAL_FIELD_PREFIX.length);
    const combined = Buffer.from(payload, 'base64');
    const nonce = combined.slice(0, 36);
    const tag = combined.slice(36, 68);
    const ciphertext = combined.slice(68);
    const aead = new CryptoUtils.PostQuantumAEAD(key);
    const decrypted = aead.decrypt(ciphertext, nonce, tag);
    return Buffer.from(decrypted).toString('utf8');
  }
}

// Database connection
const USE_PG = !!process.env.DATABASE_URL;
let pgPool = null;

export async function getPgPool() {
  if (pgPool) return pgPool;

  const { default: pg } = await import('pg');
  const Pool = pg.Pool || pg.default?.Pool;
  if (!Pool) throw new Error('pg.Pool not found');

  let config;
  if (typeof process.env.DATABASE_URL === 'string') {
    const dbUrl = process.env.DATABASE_URL;
    config = {
      connectionString: dbUrl,
      ssl: false,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    };

    if (dbUrl.includes('sslmode=require') || dbUrl.includes('ssl=true')) {
      config.ssl = { rejectUnauthorized: false };
    }
  } else {
    config = {
      host: process.env.PGHOST || 'localhost',
      port: parseInt(process.env.PGPORT || '5432', 10),
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'postgres',
      database: process.env.PGDATABASE || 'qor_chat',
      ssl: false,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    };
  }

  try {
    pgPool = new Pool(config);
    await pgPool.query('SELECT 1');
    console.log('[DB] PostgreSQL pool initialized');
    return pgPool;
  } catch (e) {
    console.error('[DB] PostgreSQL connection failed:', e.message);
    throw e;
  }
}

export { USE_PG, crypto, randomBytes, cryptoLogger };
