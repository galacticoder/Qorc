/**
 * ZK Device Proof (LSAG Ring Signature over Ed25519)
 *
 * Allows clients to prove they own a registered ring key
 * without revealing which key in the ring was used.
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ed25519, ed25519_hasher } from '@noble/curves/ed25519.js';
import { bytesToNumberLE, numberToBytesLE, concatBytes, equalBytes } from '@noble/curves/utils.js';
import { PostQuantumUtils } from '../utils/pq-utils';
import { storage } from '../tauri-bindings';

// ZK Proof configuration
const ZK_CONFIG = {
  CHALLENGE_SIZE: 32,
  RING_SIZE_MIN: 128,
  RING_SIZE_MAX: 1024,
  PROOF_VERSION: 2,
  SCALAR_SIZE: 32,
  PUBLIC_KEY_SIZE: 32,
  KEY_IMAGE_SIZE: 32,
};

// Labels for domain separation
const ZK_LABELS = {
  CHALLENGE: 'ZKDeviceProof-Challenge-v2',
  HASH_TO_POINT: 'ZKDeviceProof-HashToPoint-v2',
  RING: 'ZKDeviceProof-RingSig-v2',
  KEY_IMAGE: 'ZKDeviceProof-KeyImage-v2',
};

const RING_KEY_STORAGE_PREFIX = 'zk_ring_key_v2:';

const encodeU16 = (value: number): Uint8Array => new Uint8Array([(value >> 8) & 0xff, value & 0xff]);

const modN = (x: bigint): bigint => {
  const order = ed25519.Point.Fn.ORDER;
  const r = x % order;
  return r >= 0n ? r : r + order;
};

const randomScalar = (): bigint => {
  const order = ed25519.Point.Fn.ORDER;
  while (true) {
    const bytes = randomBytes(64);
    const num = bytesToNumberLE(bytes);
    const res = num % order;
    if (res !== 0n) return res;
  }
};

const hashToScalar = (msg: Uint8Array): bigint => {
  const digest = blake3(msg, { dkLen: 64 });
  return modN(bytesToNumberLE(digest));
};

const hashToPoint = (input: Uint8Array) => {
  const msg = concatBytes(new TextEncoder().encode(ZK_LABELS.HASH_TO_POINT), input);
  return ed25519_hasher.hashToCurve(msg);
};

const deriveSecretScalar = (secretKey: Uint8Array): bigint => {
  const hash = sha512(secretKey);
  // Clamp according to Ed25519 spec
  hash[0] &= 248;
  hash[31] &= 63;
  hash[31] |= 64;
  return modN(bytesToNumberLE(hash.slice(0, 32)));
};

export interface DeviceCommitment {
  ringPublicKey: Uint8Array;
  registeredAt: number;
  revoked: boolean;
  commitmentHash?: string;
}

export interface ZKDeviceProof {
  version: number;
  challenge: Uint8Array;
  c0: Uint8Array;
  s: Uint8Array[];
  keyImage: Uint8Array;
}

export async function getOrCreateRingKeyPair(deviceId: string): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
  if (!deviceId) throw new Error('Missing deviceId');
  await storage.init();
  const key = `${RING_KEY_STORAGE_PREFIX}${deviceId}`;
  const raw = await storage.get(key);
  if (raw && typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      const secretKey = PostQuantumUtils.base64ToUint8Array(parsed.secretKey);
      const publicKey = PostQuantumUtils.base64ToUint8Array(parsed.publicKey);
      if (secretKey.length === 32 && publicKey.length === 32) {
        const derived = ed25519.getPublicKey(secretKey);
        if (equalBytes(derived, publicKey)) {
          return { publicKey, secretKey };
        }
      }
    } catch { }
  }

  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  await storage.set(key, JSON.stringify({
    version: 1,
    publicKey: PostQuantumUtils.uint8ArrayToBase64(publicKey),
    secretKey: PostQuantumUtils.uint8ArrayToBase64(secretKey)
  }));

  return { publicKey, secretKey };
}

/**
 * ZK Device Proof Generator
 */
export class ZKDeviceProofGenerator {
  static async generateProof(
    ringPrivateKey: Uint8Array,
    ringPublicKey: Uint8Array,
    allCommitments: DeviceCommitment[],
    challenge: Uint8Array
  ): Promise<ZKDeviceProof> {
    const activeCommitments = allCommitments.filter(c => !c.revoked);
    if (activeCommitments.length === 0) {
      throw new Error('No active device commitments');
    }
    if (activeCommitments.length < ZK_CONFIG.RING_SIZE_MIN) {
      throw new Error('Device anonymity set too small');
    }
    if (activeCommitments.length > ZK_CONFIG.RING_SIZE_MAX) {
      throw new Error('Ring size exceeds maximum');
    }

    const ringPublicKeys = activeCommitments.map(c => c.ringPublicKey);
    for (const pk of ringPublicKeys) {
      if (pk.length !== ZK_CONFIG.PUBLIC_KEY_SIZE) {
        throw new Error('Invalid ring public key');
      }
    }
    const ourIndex = ringPublicKeys.findIndex(pk => equalBytes(pk, ringPublicKey));
    if (ourIndex === -1) {
      throw new Error('Ring key not found in commitments');
    }

    const { c0, s, keyImage } = this.generateRingSignature(
      ringPrivateKey,
      ringPublicKeys,
      ourIndex,
      challenge
    );

    return {
      version: ZK_CONFIG.PROOF_VERSION,
      challenge,
      c0,
      s,
      keyImage
    };
  }

  private static generateRingSignature(
    ringPrivateKey: Uint8Array,
    ringPublicKeys: Uint8Array[],
    realIndex: number,
    challenge: Uint8Array
  ): { c0: Uint8Array; s: Uint8Array[]; keyImage: Uint8Array } {
    const n = ringPublicKeys.length;
    const ringSizeBytes = encodeU16(n);
    const msgPrefix = concatBytes(new TextEncoder().encode(ZK_LABELS.RING), challenge, ringSizeBytes);

    const x = deriveSecretScalar(ringPrivateKey);
    const P = ringPublicKeys.map(pk => ed25519.Point.fromBytes(pk));
    const Hp = ringPublicKeys.map(pk => hashToPoint(pk));
    const keyImagePoint = Hp[realIndex].multiply(x);

    const c: bigint[] = new Array(n);
    const s: bigint[] = new Array(n);

    const u = randomScalar();
    const R = ed25519.Point.BASE.multiply(u);
    const R2 = Hp[realIndex].multiply(u);
    c[(realIndex + 1) % n] = hashToScalar(concatBytes(msgPrefix, R.toBytes(), R2.toBytes()));

    for (let i = (realIndex + 1) % n; i !== realIndex; i = (i + 1) % n) {
      s[i] = randomScalar();
      const Ri = ed25519.Point.BASE.multiply(s[i]).add(P[i].multiply(c[i]));
      const Ri2 = Hp[i].multiply(s[i]).add(keyImagePoint.multiply(c[i]));
      c[(i + 1) % n] = hashToScalar(concatBytes(msgPrefix, Ri.toBytes(), Ri2.toBytes()));
    }

    s[realIndex] = modN(u - c[realIndex] * x);

    const c0 = numberToBytesLE(c[0], ZK_CONFIG.SCALAR_SIZE);
    const sBytes = s.map(val => numberToBytesLE(val, ZK_CONFIG.SCALAR_SIZE));
    const keyImage = keyImagePoint.toBytes();

    return { c0, s: sBytes, keyImage };
  }
}

/**
 * ZK Device Proof Verifier
 */
export class ZKDeviceProofVerifier {
  static async verifyProof(
    proof: ZKDeviceProof,
    allCommitments: DeviceCommitment[],
    challenge: Uint8Array
  ): Promise<boolean> {
    if (proof.version !== ZK_CONFIG.PROOF_VERSION) return false;
    if (!equalBytes(proof.challenge, challenge)) return false;

    const activeCommitments = allCommitments.filter(c => !c.revoked);
    if (activeCommitments.length < ZK_CONFIG.RING_SIZE_MIN) return false;
    if (proof.s.length !== activeCommitments.length) return false;
    for (const resp of proof.s) {
      if (resp.length !== ZK_CONFIG.SCALAR_SIZE) return false;
    }
    if (proof.c0.length !== ZK_CONFIG.SCALAR_SIZE) return false;
    if (proof.keyImage.length !== ZK_CONFIG.KEY_IMAGE_SIZE) return false;
    if (proof.keyImage.every(byte => byte === 0)) return false;

    const ringPublicKeys = activeCommitments.map(c => c.ringPublicKey);
    return this.verifyRingSignature(proof, ringPublicKeys, challenge);
  }

  private static verifyRingSignature(
    proof: ZKDeviceProof,
    ringPublicKeys: Uint8Array[],
    challenge: Uint8Array
  ): boolean {
    const n = ringPublicKeys.length;
    const ringSizeBytes = encodeU16(n);
    const msgPrefix = concatBytes(new TextEncoder().encode(ZK_LABELS.RING), challenge, ringSizeBytes);

    let c = bytesToNumberLE(proof.c0);
    try {
      const keyImagePoint = ed25519.Point.fromBytes(proof.keyImage);
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

  static generateChallenge(): Uint8Array {
    return randomBytes(ZK_CONFIG.CHALLENGE_SIZE);
  }
}

export { ZK_CONFIG };
