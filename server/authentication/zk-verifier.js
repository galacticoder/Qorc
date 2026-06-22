/**
 * ZK Device Proof Verifier (LSAG Ring Signature over Ed25519)
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ed25519, ed25519_hasher } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, concatBytes, equalBytes } from '@noble/curves/utils.js';

// Configuration
const ZK_CONFIG = {
  CHALLENGE_SIZE: 32,
  RING_SIZE_MIN: 128,
  RING_SIZE_MAX: 1024,
  PROOF_VERSION: 2,
  CHALLENGE_EXPIRY_MS: 60000,
  SCALAR_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,
  KEY_IMAGE_SIZE: 32,
};

// Labels for domain separation
const ZK_LABELS = {
  CHALLENGE: 'ZKDeviceProof-Challenge-v2',
  HASH_TO_POINT: 'ZKDeviceProof-HashToPoint-v2',
  RING: 'ZKDeviceProof-RingSig-v2',
  COMMITMENT: 'ZKDeviceProof-Commitment-v2',
};

const encodeU16 = (value) => new Uint8Array([(value >> 8) & 0xff, value & 0xff]);

const modN = (x) => {
  const order = ed25519.Point.Fn.ORDER;
  const r = x % order;
  return r >= 0n ? r : r + order;
};

const hashToScalar = (msg) => {
  const digest = blake3(msg, { dkLen: 64 });
  return modN(bytesToNumberLE(digest));
};

const hashToPoint = (input) => {
  const msg = concatBytes(new TextEncoder().encode(ZK_LABELS.HASH_TO_POINT), input);
  return ed25519_hasher.hashToCurve(msg);
};

/**
 * ZK Proof structure
 */
class ZKProofData {
  constructor(data) {
    this.version = data.version;
    this.challenge = Buffer.from(data.challenge, 'base64');
    this.c0 = Buffer.from(data.c0, 'base64');
    this.s = (data.s || []).map((r) => Buffer.from(r, 'base64'));
    this.keyImage = Buffer.from(data.keyImage, 'base64');
  }
}

const pendingChallenges = new Map();

/**
 * ZK Device Proof Verifier
 */
export class ZKDeviceProofVerifier {
  #db = null;

  constructor(db) {
    this.#db = db;
  }

  /**
   * Generate a new challenge for proof request
   */
  async generateChallenge() {
    const challenge = randomBytes(ZK_CONFIG.CHALLENGE_SIZE);
    const challengeId = Buffer.from(randomBytes(16)).toString('hex');
    const expiresAt = Date.now() + ZK_CONFIG.CHALLENGE_EXPIRY_MS;

    // Store pending challenge
    pendingChallenges.set(challengeId, {
      challenge,
      expiresAt,
      used: false,
    });

    // Cleanup old challenges
    this.#cleanupExpiredChallenges();

    // Get all active device commitments
    const commitments = await this.#getActiveCommitments();
    if (commitments.length < ZK_CONFIG.RING_SIZE_MIN) {
      throw new Error('Device anonymity set too small');
    }

    return {
      challengeId,
      challenge: Buffer.from(challenge).toString('base64'),
      commitments: commitments.map(c => ({
        commitmentHash: c.commitment_hash,
        ringPublicKey: c.ring_public_key,
        registeredAt: c.registered_at,
        revoked: c.revoked,
      })),
      expiresAt,
    };
  }

  /**
   * Verify a ZK device proof
   */
  async verifyProof(challengeId, proofData) {
    const pending = pendingChallenges.get(challengeId);
    if (!pending) return { valid: false, error: 'Invalid challenge ID' };
    if (pending.used) return { valid: false, error: 'Challenge already used' };
    if (Date.now() > pending.expiresAt) {
      pendingChallenges.delete(challengeId);
      return { valid: false, error: 'Challenge expired' };
    }

    pending.used = true;

    try {
      const proof = new ZKProofData(proofData);
      if (!equalBytes(proof.challenge, pending.challenge)) {
        return { valid: false, error: 'Challenge mismatch' };
      }

      const commitments = await this.#getActiveCommitments();
      if (commitments.length === 0) {
        return { valid: false, error: 'No registered devices' };
      }
      if (commitments.length < ZK_CONFIG.RING_SIZE_MIN) {
        return { valid: false, error: 'Device anonymity set too small' };
      }

      const isValid = await this.#verifyRingSignature(proof, commitments, pending.challenge);
      if (!isValid) {
        return { valid: false, error: 'Invalid proof' };
      }

      const keyImageHash = Buffer.from(proof.keyImage).toString('hex');
      const inserted = await this.#recordKeyImage(keyImageHash);
      if (!inserted) {
        return { valid: false, error: 'Key image already used' };
      }

      return { valid: true, proofId: Buffer.from(randomBytes(16)).toString('hex') };
    } catch (error) {
      console.error('[ZKVerifier] Proof verification failed:', error.message);
      return { valid: false, error: 'Verification error' };
    } finally {
      pendingChallenges.delete(challengeId);
    }
  }

  /**
   * Register a new device ring public key
   */
  async registerDeviceCommitment(ringPublicKey) {
    if (!ringPublicKey || ringPublicKey.length !== ZK_CONFIG.PUBLIC_KEY_SIZE) {
      throw new Error('Invalid ring public key');
    }

    const commitment = blake3(
      Buffer.concat([
        Buffer.from(ZK_LABELS.COMMITMENT),
        Buffer.from(ringPublicKey),
      ]),
      { dkLen: 32 }
    );

    const commitmentHex = Buffer.from(commitment).toString('hex');
    const ringPublicKeyBase64 = Buffer.from(ringPublicKey).toString('base64');

    await this.#db.query(
      `INSERT INTO device_key_commitments (commitment_hash, ring_public_key, registered_at, revoked)
       VALUES ($1, $2, NOW(), FALSE)
       ON CONFLICT (commitment_hash) DO NOTHING`,
      [commitmentHex, ringPublicKeyBase64]
    );

    return commitmentHex;
  }

  /**
   * Revoke a device commitment
   */
  async revokeCommitment(commitmentHash) {
    await this.#db.query(
      `UPDATE device_key_commitments SET revoked = TRUE WHERE commitment_hash = $1`,
      [commitmentHash]
    );
  }

  /**
   * Get all active device commitments
   */
  async #getActiveCommitments() {
    const result = await this.#db.query(
      `SELECT commitment_hash, ring_public_key, registered_at, revoked
       FROM device_key_commitments
       WHERE revoked = FALSE
       ORDER BY registered_at ASC
       LIMIT $1`,
      [ZK_CONFIG.RING_SIZE_MAX]
    );
    return result.rows;
  }

  async #recordKeyImage(keyImageHash) {
    const result = await this.#db.query(
      `INSERT INTO device_key_images (key_image_hash, recorded_at)
       VALUES ($1, NOW())
       ON CONFLICT (key_image_hash) DO NOTHING`,
      [keyImageHash]
    );
    return result.rowCount > 0;
  }

  /**
   * Verify ring signature
   */
  async #verifyRingSignature(proof, commitments, challenge) {
    const n = commitments.length;

    if (n < ZK_CONFIG.RING_SIZE_MIN) return false;
    if (proof.s.length !== n) return false;
    for (const resp of proof.s) {
      if (resp.length !== ZK_CONFIG.SCALAR_SIZE) return false;
    }
    if (proof.c0.length !== ZK_CONFIG.SCALAR_SIZE) return false;
    if (proof.keyImage.length !== ZK_CONFIG.KEY_IMAGE_SIZE) return false;

    let keyImagePoint;
    try {
      keyImagePoint = ed25519.Point.fromBytes(proof.keyImage);
      if (keyImagePoint.equals(ed25519.Point.ZERO)) return false;
    } catch {
      return false;
    }

    const ringPublicKeys = commitments.map(c => Buffer.from(c.ring_public_key, 'base64'));
    for (const pk of ringPublicKeys) {
      if (pk.length !== ZK_CONFIG.PUBLIC_KEY_SIZE) return false;
    }

    const ringSizeBytes = encodeU16(n);
    const msgPrefix = concatBytes(new TextEncoder().encode(ZK_LABELS.RING), challenge, ringSizeBytes);

    let c = bytesToNumberLE(proof.c0);
    try {
      const P = ringPublicKeys.map(pk => ed25519.Point.fromBytes(pk));
      const Hp = ringPublicKeys.map(pk => hashToPoint(pk));

      for (let i = 0; i < n; i++) {
        const s = bytesToNumberLE(proof.s[i]);
        const Ri = ed25519.Point.BASE.multiply(s).add(P[i].multiply(c));
        const Ri2 = Hp[i].multiply(s).add(keyImagePoint.multiply(c));
        c = hashToScalar(concatBytes(msgPrefix, Ri.toBytes(), Ri2.toBytes()));
      }

      const c0 = bytesToNumberLE(proof.c0);
      return c === c0;
    } catch {
      return false;
    }
  }

  /**
   * Cleanup expired challenges
   */
  #cleanupExpiredChallenges() {
    const now = Date.now();
    for (const [id, data] of pendingChallenges.entries()) {
      if (now > data.expiresAt) {
        pendingChallenges.delete(id);
      }
    }
  }
}

/**
 * Device commitment management helpers
 */
export const DeviceCommitmentHelpers = {
  parseRegistrationRequest(data) {
    if (!data.ringPublicKey) {
      throw new Error('Missing ring public key');
    }
    return {
      ringPublicKey: Buffer.from(data.ringPublicKey, 'base64'),
    };
  },

  formatChallengeResponse(challengeData) {
    return {
      challengeId: challengeData.challengeId,
      challenge: challengeData.challenge,
      commitments: challengeData.commitments,
      expiresAt: challengeData.expiresAt,
    };
  },
};

export { ZK_CONFIG };
