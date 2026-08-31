/**
 * Database Connection Pool and Utilities
 */

import fs from 'fs';
import crypto from 'crypto';

import { deriveAuthRootKey } from '../crypto/auth-root.js';
import { envInt } from '../utils/env.js';
import { SHA_512_ALGORITHM } from '../utils/crypto-consts.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { recordStorageOperation } from '../telemetry/server-telemetry.js';

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
  if (caPath) {
    try {
      ssl.ca = fs.readFileSync(caPath, 'utf8');
    } catch (e) {
      throw new Error(`Failed to read Postgres CA certificate at ${caPath}: ${e?.message}`);
    }
  } else if (process.env.DATABASE_CA_CERT) {
    ssl.ca = process.env.DATABASE_CA_CERT;
  } else {
    throw new Error('PGSSLROOTCERT or DATABASE_CA_CERT is required');
  }
  return ssl;
}

function databaseConnectionConfig() {
  let host;
  let port;
  let user;
  let password;
  let database;
  let certificateName;

  if (typeof process.env.DATABASE_URL === 'string' && process.env.DATABASE_URL.length > 0) {
    let url;
    try {
      url = new URL(process.env.DATABASE_URL);
    } catch {
      throw new Error('DATABASE_URL is invalid');
    }
    if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
      throw new Error('DATABASE_URL must use postgres:// or postgresql://');
    }
    host = process.env.DB_CONNECT_HOST || url.hostname;
    port = url.port || '5432';
    user = decodeURIComponent(url.username);
    password = decodeURIComponent(url.password);
    database = decodeURIComponent(url.pathname.replace(/^\//, ''));
    certificateName = process.env.DB_TLS_SERVERNAME || url.hostname;
  } else {
    host = process.env.DB_CONNECT_HOST || process.env.PGHOST || process.env.DB_HOST;
    port = process.env.PGPORT || process.env.DB_PORT;
    user = process.env.PGUSER || process.env.DATABASE_USER;
    password = process.env.PGPASSWORD || process.env.DATABASE_PASSWORD;
    database = process.env.PGDATABASE || process.env.DB_NAME;
    certificateName = process.env.DB_TLS_SERVERNAME || process.env.PGHOST || process.env.DB_HOST;
  }

  requiredDatabaseValue(host, 'PGHOST/DB_HOST');
  requiredDatabaseValue(user, 'PGUSER/DATABASE_USER');
  requiredDatabaseValue(password, 'PGPASSWORD/DATABASE_PASSWORD');
  requiredDatabaseValue(database, 'PGDATABASE/DB_NAME');
  const parsedPort = Number(port);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error('PGPORT/DB_PORT must be an integer from 1 through 65535');
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
    ssl: buildPgSslConfig(certificateName),
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
    const Pool = pg.Pool || pg.default?.Pool;
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
