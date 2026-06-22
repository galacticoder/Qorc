/**
 * Post-Quantum Key Encapsulation Mechanism
 */

import { PostQuantumUtils } from '../utils/pq-utils';
import {
  PQ_KEM_PUBLIC_KEY_SIZE,
  PQ_KEM_SECRET_KEY_SIZE,
  PQ_KEM_CIPHERTEXT_SIZE,
  PQ_KEM_SHARED_SECRET_SIZE
} from '../constants';
import { PostQuantumWorker } from './worker-bridge';

export class PostQuantumKEM {
  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    try {
      return await PostQuantumWorker.generateKemKeyPair();
    } catch (err) {
      console.warn('[PostQuantumKEM] Worker failed, falling back to local keygen', err);
      return this.generateKeyPairLocal();
    }
  }

  static async generateKeyPairLocal(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
    const kp = ml_kem1024.keygen();
    const publicKey = PostQuantumUtils.asUint8Array(kp.publicKey);
    const secretKey = PostQuantumUtils.asUint8Array(kp.secretKey);
    if (publicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE) {
      throw new Error('Invalid public key size generated');
    }
    if (secretKey.length !== PQ_KEM_SECRET_KEY_SIZE) {
      throw new Error('Invalid secret key size generated');
    }
    return { publicKey, secretKey };
  }

  static generateKeyPairFromSeed(_seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
    throw new Error('Deterministic ML-KEM key generation is not supported by the underlying library');
  }

  static async encapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
    if (!publicKey) throw new Error('Public key required');
    if (publicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE) throw new Error(`Invalid public key size: ${publicKey.length}`);

    const result = await PostQuantumWorker.kemEncapsulate(publicKey);

    if (result.ciphertext.length !== PQ_KEM_CIPHERTEXT_SIZE) throw new Error('Invalid ciphertext size');
    if (result.sharedSecret.length !== PQ_KEM_SHARED_SECRET_SIZE) throw new Error('Invalid shared secret size');

    return result;
  }

  static async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (!ciphertext || !secretKey) throw new Error('Ciphertext and secret key required');
    if (ciphertext.length !== PQ_KEM_CIPHERTEXT_SIZE) throw new Error(`Invalid ciphertext size: ${ciphertext.length}`);
    if (secretKey.length !== PQ_KEM_SECRET_KEY_SIZE) throw new Error(`Invalid secret key size: ${secretKey.length}`);

    const sharedSecret = await PostQuantumWorker.kemDecapsulate(ciphertext, secretKey);

    if (sharedSecret.length !== PQ_KEM_SHARED_SECRET_SIZE) throw new Error('Invalid shared secret size');

    return sharedSecret;
  }
}
