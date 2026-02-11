/**
 * LibSignal Key Bundle Storage
 * 
 * Stores Signal Protocol key bundles
 */

import { getPgPool, LibsignalFieldEncryption, crypto } from './core.js';

export class LibsignalBundleDB {
  // Publish bundle
  static async publish(inboxId, bundle) {
    if (!inboxId || typeof inboxId !== 'string' || inboxId.length < 32) {
      console.error('[DB] Invalid inboxId parameter in LibsignalBundleDB.publish');
      throw new Error('Invalid inboxId parameter');
    }

    if (!bundle || typeof bundle !== 'object') {
      console.error('[DB] Invalid bundle structure in LibsignalBundleDB.publish');
      throw new Error('Invalid bundle structure');
    }

    // Only require key material
    const requiredFields = ['identityKeyBase64',
      'signedPreKeyPublicBase64', 'signedPreKeySignatureBase64',
      'kyberPreKeyPublicBase64', 'kyberPreKeySignatureBase64'];

    for (const field of requiredFields) {
      if (bundle[field] === undefined || bundle[field] === null) {
        console.error(`[DB] Missing required field in bundle: ${field}`);
        throw new Error('Missing required field in bundle: [REDACTED]');
      }
    }

    // Add jitter to timestamp
    const jitter = Math.floor(Math.random() * 60000);
    const now = Date.now() + jitter;

    // Compute identity key hash for blocking system
    const identityKeyHash = crypto.createHash('blake2b512')
      .update(bundle.identityKeyBase64)
      .digest('hex')
      .slice(0, 64);

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

      const pool = await getPgPool();
      await pool.query(`
        INSERT INTO libsignal_bundles (
          "inboxId", "identityKeyHash", "identityKeyBase64",
          "preKeyPublicBase64",
          "signedPreKeyPublicBase64", "signedPreKeySignatureBase64",
          "kyberPreKeyPublicBase64", "kyberPreKeySignatureBase64",
          "updatedAt"
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        ON CONFLICT ("inboxId") DO UPDATE SET
          "identityKeyHash" = EXCLUDED."identityKeyHash",
          "identityKeyBase64" = EXCLUDED."identityKeyBase64",
          "preKeyPublicBase64" = EXCLUDED."preKeyPublicBase64",
          "signedPreKeyPublicBase64" = EXCLUDED."signedPreKeyPublicBase64",
          "signedPreKeySignatureBase64" = EXCLUDED."signedPreKeySignatureBase64",
          "kyberPreKeyPublicBase64" = EXCLUDED."kyberPreKeyPublicBase64",
          "kyberPreKeySignatureBase64" = EXCLUDED."kyberPreKeySignatureBase64",
          "updatedAt" = EXCLUDED."updatedAt"
      `, [
        inboxId,
        identityKeyHash,
        encIdentityKey,
        encPreKeyPublic,
        encSignedPreKeyPublic,
        encSignedPreKeySig,
        encKyberPreKeyPublic,
        encKyberPreKeySig,
        now
      ]);

      console.log(`[DB] Published bundle for inbox: ${inboxId.slice(0, 8)}...`);
      return { success: true, identityKeyHash };
    } catch (error) {
      console.error('[DB] Error publishing bundle:', error);
      throw error;
    }
  }

  // Take bundle
  static async take(inboxId) {
    if (!inboxId || typeof inboxId !== 'string' || inboxId.length < 32) {
      console.error('[DB] Invalid inboxId parameter in LibsignalBundleDB.take');
      return null;
    }

    try {
      const pool = await getPgPool();
      const { rows } = await pool.query('SELECT * FROM libsignal_bundles WHERE "inboxId" = $1', [inboxId]);
      const row = rows[0];
      if (!row) return null;

      // Decrypt fields
      const identityKeyRaw = row.identityKeyBase64;
      const preKeyPublicRaw = row.preKeyPublicBase64;
      const signedPreKeyPublicRaw = row.signedPreKeyPublicBase64;
      const signedPreKeySigRaw = row.signedPreKeySignatureBase64;
      const kyberPreKeyPublicRaw = row.kyberPreKeyPublicBase64;
      const kyberPreKeySigRaw = row.kyberPreKeySignatureBase64;

      return {
        inboxId: row.inboxId,
        identityKeyHash: row.identityKeyHash,
        identityKeyBase64: LibsignalFieldEncryption.decryptField(identityKeyRaw, 'identityKeyBase64'),
        preKeyPublicBase64: preKeyPublicRaw ? LibsignalFieldEncryption.decryptField(preKeyPublicRaw, 'preKeyPublicBase64') : null,
        signedPreKeyPublicBase64: LibsignalFieldEncryption.decryptField(signedPreKeyPublicRaw, 'signedPreKeyPublicBase64'),
        signedPreKeySignatureBase64: LibsignalFieldEncryption.decryptField(signedPreKeySigRaw, 'signedPreKeySignatureBase64'),
        kyberPreKeyPublicBase64: LibsignalFieldEncryption.decryptField(kyberPreKeyPublicRaw, 'kyberPreKeyPublicBase64'),
        kyberPreKeySignatureBase64: LibsignalFieldEncryption.decryptField(kyberPreKeySigRaw, 'kyberPreKeySignatureBase64'),
        updatedAt: row.updatedAt,
      };
    } catch (error) {
      console.error('[DB] Error taking bundle:', error);
      return null;
    }
  }

  // Delete bundle
  static async delete(inboxId) {
    if (!inboxId || typeof inboxId !== 'string' || inboxId.length < 32) {
      return false;
    }

    try {
      const pool = await getPgPool();
      await pool.query('DELETE FROM libsignal_bundles WHERE "inboxId" = $1', [inboxId]);
      return true;
    } catch (error) {
      console.error('[DB] Error deleting bundle:', error);
      return false;
    }
  }
}
