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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

function getPrivateIdentifierSecret() {
  const secret = process.env.ROUTING_ID_SECRET || process.env.DB_FIELD_KEY || process.env.USER_ID_SALT;
  if (!secret || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('ROUTING_ID_SECRET or DB_FIELD_KEY must be at least 32 bytes for private identifier storage');
  }
  return secret;
}

export function privateLookupId(namespace, identifier) {
  if (typeof namespace !== 'string' || namespace.length === 0) {
    throw new Error('privateLookupId requires a namespace');
  }
  if (typeof identifier !== 'string' || identifier.length === 0) {
    throw new Error('privateLookupId requires an identifier');
  }

  return crypto
    .createHmac('sha512', Buffer.from(getPrivateIdentifierSecret(), 'utf8'))
    .update(namespace)
    .update('\0')
    .update(identifier)
    .digest('base64url');
}

export function privateRedisKey(prefix, namespace, identifier) {
  return `${prefix}${privateLookupId(namespace, identifier)}`;
}

// Secret file paths
const USER_ID_SALT_FILE_PATH = process.env.USER_ID_SALT_FILE
  ? path.resolve(process.env.USER_ID_SALT_FILE)
  : path.resolve(__dirname, '../config/generated-user-id-salt.txt');

const DB_FIELD_KEY_FILE_PATH = process.env.DB_FIELD_KEY_FILE
  ? path.resolve(process.env.DB_FIELD_KEY_FILE)
  : path.resolve(__dirname, '../config/generated-db-field-key.txt');

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
        cryptoLogger.info('[SECURITY] Loaded secret from configured storage', { label });
        return secret;
      }
    }
  } catch (e) {
    cryptoLogger.warn('[SECURITY] Could not read configured secret file', { label, error: e?.message });
  }

  // Generate new secret
  cryptoLogger.info('[SECURITY] Generating new secret', { label, purpose });
  cryptoLogger.warn('[SECURITY] Secret rotation warning', { label, warning: warningMessage });

  const newSecret = crypto.randomBytes(64).toString('hex');

  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(filePath, newSecret, { mode: 0o600 });
    cryptoLogger.info('[SECURITY] Saved generated secret to configured storage', { label });
  } catch (e) {
    cryptoLogger.error('[SECURITY] Could not save generated secret', { label, error: e?.message });
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
    cryptoLogger.info('[DB] PostgreSQL pool initialized');
    return pgPool;
  } catch (e) {
    cryptoLogger.error('[DB] PostgreSQL connection failed', { error: e?.message });
    throw e;
  }
}

export { USE_PG, crypto, randomBytes, cryptoLogger };
