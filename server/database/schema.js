/**
 * Database Schema
 */

import { getPgPool } from './core.js';
import { PRIVATE_AUTH_ANONYMITY_SET_SIZE } from '../../shared/private-auth-protocol.js';

let initializationPromise = null;

export async function initDatabase() {
  if (initializationPromise) return initializationPromise;
  initializationPromise = initializeSchema();
  try {
    await initializationPromise;
  } catch (error) {
    initializationPromise = null;
    throw error;
  }
}

async function initializeSchema() {
  const pool = await getPgPool();

  // User table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      "recordId" TEXT PRIMARY KEY,
      "opaqueRecord" TEXT NOT NULL,
      "credential_index" INTEGER NOT NULL CHECK (
        "credential_index" >= 0 AND "credential_index" < ${PRIVATE_AUTH_ANONYMITY_SET_SIZE}
      )
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_cred_index ON users("credential_index")');
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_user_private_auth_slot ON users("credential_index")');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pending_registrations (
      "recordId" TEXT PRIMARY KEY,
      "opaqueRecord" TEXT NOT NULL,
      "credential_index" INTEGER NOT NULL CHECK (
        "credential_index" >= 0 AND "credential_index" < ${PRIVATE_AUTH_ANONYMITY_SET_SIZE}
      ),
      "expiresAt" BIGINT NOT NULL
    )
  `);
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_registration_slot ON pending_registrations("credential_index")');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_pending_registration_expiry ON pending_registrations("expiresAt")');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS discovery_billboard (
      "publishId" TEXT PRIMARY KEY,
      "bucketIds" INTEGER[] NOT NULL,
      "encryptedBlob" TEXT NOT NULL,
      "expiresAt" BIGINT NOT NULL
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_discovery_expires ON discovery_billboard("expiresAt")');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS key_transparency_log (
      "logIndex" BIGINT PRIMARY KEY CHECK ("logIndex" >= 0 AND "logIndex" < 10000000),
      epoch BIGINT NOT NULL CHECK (epoch >= 0),
      "epochLabel" TEXT NOT NULL CHECK ("epochLabel" ~ '^[a-f0-9]{128}$'),
      version INTEGER NOT NULL CHECK (version >= 1),
      "recordHash" TEXT NOT NULL CHECK ("recordHash" ~ '^[a-f0-9]{128}$'),
      "rootHash" TEXT NOT NULL CHECK ("rootHash" ~ '^[a-f0-9]{128}$'),
      UNIQUE (epoch, "epochLabel")
    )
  `);
  
  await pool.query('CREATE INDEX IF NOT EXISTS idx_key_transparency_log_epoch ON key_transparency_log(epoch, "logIndex")');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS key_transparency_log_state (
      singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
      "entryCount" BIGINT NOT NULL CHECK ("entryCount" >= 0 AND "entryCount" <= 10000000),
      "rootHash" TEXT NOT NULL CHECK ("rootHash" ~ '^[a-f0-9]{128}$')
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS avatar_blobs (
      "blobId" TEXT PRIMARY KEY,
      "data" TEXT NOT NULL,
      "expiresAt" BIGINT NOT NULL
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_avatar_blobs_expires ON avatar_blobs("expiresAt")');
  // Privacy Pass nullifier store
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nullifiers (
      nullifier_hash TEXT PRIMARY KEY,
      expires_epoch INTEGER NOT NULL
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_nullifiers_expires_epoch ON nullifiers(expires_epoch)');

  console.log('[DB] Database tables initialized');
}
