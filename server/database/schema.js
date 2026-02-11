/**
 * Database Schema
 */

import { getPgPool } from './core.js';

let initialized = false;

export async function initDatabase() {
  if (initialized) return;
  initialized = true;

  const pool = await getPgPool();

  // User table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      "credentialId" TEXT PRIMARY KEY,
      "opaqueRecord" TEXT,
      "hybridPublicKeys" TEXT,
      "credential_index" INTEGER,
      "shard_id" INTEGER DEFAULT 0
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_shard ON users("shard_id")');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_cred_index ON users("credential_index")');

  // Temporary offline message storage
  await pool.query(`
    CREATE TABLE IF NOT EXISTS offline_messages (
      id BIGSERIAL PRIMARY KEY,
      toInboxId TEXT NOT NULL,
      payload TEXT NOT NULL,
      queuedAt BIGINT NOT NULL
    )
  `);

  // Libsignal bundle storage
  await pool.query(`
    CREATE TABLE IF NOT EXISTS libsignal_bundles (
      "inboxId" TEXT PRIMARY KEY,
      "identityKeyHash" TEXT NOT NULL,
      "identityKeyBase64" TEXT NOT NULL,
      "preKeyPublicBase64" TEXT,
      "signedPreKeyPublicBase64" TEXT NOT NULL,
      "signedPreKeySignatureBase64" TEXT NOT NULL,
      "kyberPreKeyPublicBase64" TEXT NOT NULL,
      "kyberPreKeySignatureBase64" TEXT NOT NULL,
      "updatedAt" BIGINT NOT NULL
    )
  `);

  // Encrypted block lists
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_block_lists (
      "inboxId" TEXT PRIMARY KEY,
      "encryptedBlockList" TEXT NOT NULL,
      "blockListHash" TEXT NOT NULL,
      salt TEXT,
      "lastUpdated" BIGINT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1
    )
  `);

  // Block tokens using identity key commitment
  await pool.query(`
    CREATE TABLE IF NOT EXISTS block_tokens (
      "blockCommitment" TEXT PRIMARY KEY,
      "createdAt" BIGINT NOT NULL,
      "expiresAt" BIGINT
    )
  `);

  // Anonymized audit logging
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_audit_log (
      id BIGSERIAL PRIMARY KEY,
      "sessionNonce" TEXT,
      action TEXT NOT NULL,
      "tokenType" TEXT,
      success INTEGER NOT NULL,
      "failureReason" TEXT,
      timestamp BIGINT NOT NULL
    )
  `);

  // Discovery billboard: OPRF token -> encrypted blob mapping
  await pool.query('DROP TABLE IF EXISTS discovery_billboard');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discovery_billboard (
      "token" TEXT PRIMARY KEY,
      "encryptedBlob" TEXT NOT NULL,
      "expiresAt" BIGINT NOT NULL
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_discovery_expires ON discovery_billboard("expiresAt")');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_block_tokens_expires ON block_tokens("expiresAt") WHERE "expiresAt" IS NOT NULL');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_user_block_lists_updated ON user_block_lists("lastUpdated")');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_auth_audit_log_timestamp ON auth_audit_log(timestamp)');

  // Privacy Pass nullifier store
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nullifiers (
      nullifier_hash TEXT PRIMARY KEY,
      recorded_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_nullifiers_recorded_at ON nullifiers(recorded_at)');

  // Device ring key commitments for ZK proof verification
  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_key_commitments (
      commitment_hash TEXT PRIMARY KEY,
      ring_public_key TEXT NOT NULL,
      registered_at TIMESTAMP NOT NULL DEFAULT NOW(),
      revoked BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  console.log('[DB] Database tables initialized');
}
