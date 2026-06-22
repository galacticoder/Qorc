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
  await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_user_private_auth_slot ON users("shard_id", "credential_index")');

  await pool.query('DROP TABLE IF EXISTS offline_messages');
  await pool.query('DROP TABLE IF EXISTS offline_mailbox_messages');
  await pool.query('DROP TABLE IF EXISTS offline_mailbox_bindings');
  await pool.query('DROP TABLE IF EXISTS offline_mailboxes');

  // Libsignal prekey bundles are distributed via the discovery blob (and in-band), not a server
  // table — the old write-only libsignal_bundles store was never read, so it is removed here.
  await pool.query('DROP TABLE IF EXISTS libsignal_bundles');

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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discovery_billboard (
      "epochId" TEXT NOT NULL,
      "bucketId" INTEGER NOT NULL,
      "publishId" TEXT NOT NULL,
      "encryptedBlob" TEXT NOT NULL,
      "expiresAt" BIGINT NOT NULL,
      "publishedAt" BIGINT NOT NULL,
      PRIMARY KEY ("epochId", "publishId")
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_discovery_expires ON discovery_billboard("expiresAt")');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_discovery_published ON discovery_billboard("publishedAt")');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_discovery_bucket ON discovery_billboard("epochId", "bucketId")');

  // Unlinkable avatar content store. opaque random blobId to uniform-size E2E-encrypted PURB
  await pool.query(`
    CREATE TABLE IF NOT EXISTS avatar_blobs (
      "blobId" TEXT PRIMARY KEY,
      "data" TEXT NOT NULL,
      "expiresAt" BIGINT NOT NULL,
      "publishedAt" BIGINT NOT NULL
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS idx_avatar_blobs_expires ON avatar_blobs("expiresAt")');
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS device_key_images (
      key_image_hash TEXT PRIMARY KEY,
      recorded_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query('CREATE INDEX IF NOT EXISTS idx_device_key_images_recorded_at ON device_key_images(recorded_at)');

  console.log('[DB] Database tables initialized');
}
