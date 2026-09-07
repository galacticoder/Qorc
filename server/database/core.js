/**
 * Database Connection Pool and Utilities
 */

import crypto from 'crypto';
import path from 'node:path';

import { deriveAuthRootKey } from '../crypto/auth-root.js';
import { envInt } from '../utils/env.js';
import { SHA_512_ALGORITHM } from '../utils/crypto-consts.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { recordStorageOperation } from '../telemetry/server-telemetry.js';
import { readSecureTlsFile } from '../utils/secure-file.js';

const ROUTING_IDENTIFIER_KEY = deriveAuthRootKey(PROTOCOL_KEYS.ROUTING_IDENTIFIER_ROOT);
let routingIdentifierKeyDestroyed = false;

export function destroyDatabaseSecrets() {
  if (routingIdentifierKeyDestroyed) return;
  routingIdentifierKeyDestroyed = true;
  ROUTING_IDENTIFIER_KEY.fill(0);
}

export function privateLookupId(namespace, identifier) {
  if (routingIdentifierKeyDestroyed) {
    throw new Error('Database routing secrets have been destroyed');
  }
  if (typeof namespace !== 'string' || namespace.length === 0) {
    throw new Error('privateLookupId requires a namespace');
  }
  if (typeof identifier !== 'string' || identifier.length === 0) {
    throw new Error('privateLookupId requires an identifier');
  }

  return crypto
    .createHmac(SHA_512_ALGORITHM, ROUTING_IDENTIFIER_KEY)
    .update(namespace)
    .update('\0')
    .update(identifier)
    .digest('base64url');
}

let pgPool = null;
let pgPoolInitialization = null;
const INSTRUMENTED_POSTGRES_CLIENT = Symbol('instrumentedPostgresClient');

function instrumentPostgresClient(client) {
  if (!client || client[INSTRUMENTED_POSTGRES_CLIENT]) return client;
  client[INSTRUMENTED_POSTGRES_CLIENT] = true;
  const originalQuery = client.query;
  client.query = function instrumentedQuery(...arguments_) {
    const started = performance.now();
    let result;
    try {
      result = originalQuery.apply(this, arguments_);
    } catch (error) {
      recordStorageOperation('postgres', performance.now() - started, true);
      throw error;
    }
    if (!result || typeof result.then !== 'function') {
      recordStorageOperation('postgres', performance.now() - started, false);
      return result;
    }
    return result.then(
      (value) => {
        recordStorageOperation('postgres', performance.now() - started, false);
        return value;
      },
      (error) => {
        recordStorageOperation('postgres', performance.now() - started, true);
        throw error;
      }
    );
  };
  return client;
}

function requiredDatabaseValue(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} is required for PostgreSQL`);
  }
  return value;
}

function buildPgSslConfig(serverName) {
  const ssl = {
    rejectUnauthorized: true,
    servername: requiredDatabaseValue(serverName, 'DB_TLS_SERVERNAME')
  };

  const caPath = process.env.PGSSLROOTCERT;
  requiredDatabaseValue(caPath, 'PGSSLROOTCERT');
  try {
    ssl.ca = readSecureTlsFile(path.resolve(caPath));
  } catch (e) {
    throw new Error(`Failed to read Postgres CA certificate at ${caPath}: ${e?.message}`);
  }
  return ssl;
}

function databaseConnectionConfig() {
  const rawUrl = requiredDatabaseValue(process.env.DATABASE_URL, 'DATABASE_URL');
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('DATABASE_URL is invalid');
  }
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error('DATABASE_URL must use postgres:// or postgresql://');
  }

  const host = requiredDatabaseValue(url.hostname, 'DATABASE_URL host');
  const user = requiredDatabaseValue(decodeURIComponent(url.username), 'DATABASE_URL user');
  const password = requiredDatabaseValue(decodeURIComponent(url.password), 'DATABASE_URL password');
  const database = requiredDatabaseValue(
    decodeURIComponent(url.pathname.replace(/^\//, '')),
    'DATABASE_URL database'
  );
  const parsedPort = Number(requiredDatabaseValue(url.port, 'DATABASE_URL port'));
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error('DATABASE_URL port must be an integer from 1 through 65535');
  }

  const statementTimeoutMs = envInt('PG_STATEMENT_TIMEOUT_MS', 15_000, 1_000, 30_000);
  const queryTimeoutMs = envInt(
    'PG_QUERY_TIMEOUT_MS',
    20_000,
    statementTimeoutMs,
    30_000
  );

  return {
    host,
    port: parsedPort,
    user,
    password,
    database,
    ssl: buildPgSslConfig(process.env.DB_TLS_SERVERNAME),
    max: envInt('PG_POOL_MAX', 20, 2, 100),
    idleTimeoutMillis: envInt('PG_IDLE_TIMEOUT_MS', 30_000, 10_000, 10 * 60_000),
    connectionTimeoutMillis: envInt('PG_CONNECTION_TIMEOUT_MS', 10_000, 1_000, 30_000),
    statement_timeout: statementTimeoutMs,
    query_timeout: queryTimeoutMs,
    lock_timeout: envInt('PG_LOCK_TIMEOUT_MS', 5_000, 500, statementTimeoutMs),
    idle_in_transaction_session_timeout: envInt(
      'PG_IDLE_TRANSACTION_TIMEOUT_MS',
      20_000,
      1_000,
      30_000
    )
  };
}

export async function getPgPool() {
  if (pgPool) return pgPool;
  if (pgPoolInitialization) return pgPoolInitialization;

  const initialization = (async () => {
    const { default: pg } = await import('pg');
    const Pool = pg.Pool;
    if (!Pool) throw new Error('pg.Pool not found');

    const config = databaseConnectionConfig();
    const candidate = new Pool(config);
    candidate.on('connect', instrumentPostgresClient);

    try {
      await candidate.query('SELECT 1');
      pgPool = candidate;
      console.log('[DB] PostgreSQL pool initialized');
      return candidate;
    } catch (error) {
      try {
        await candidate.end();
      } catch {
      }
      console.error('[DB] PostgreSQL connection failed');
      throw error;
    }
  })();

  pgPoolInitialization = initialization;
  try {
    return await initialization;
  } finally {
    if (pgPoolInitialization === initialization) pgPoolInitialization = null;
  }
}

export async function closePgPool() {
  const initialization = pgPoolInitialization;
  if (initialization) await initialization.catch(() => { });

  const pool = pgPool;
  pgPool = null;
  if (pool) await pool.end();
}

export async function withTransaction(client, operation) {
  await client.query('BEGIN');
  let shouldRollback = false;
  const rollback = (value) => {
    shouldRollback = true;
    return value;
  };
  try {
    const result = await operation({ rollback });
    await client.query(shouldRollback ? 'ROLLBACK' : 'COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  }
}

export { crypto };
