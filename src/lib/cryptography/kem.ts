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
import { kyber } from '../utils/crypto-utils';

export class PostQuantumKEM {
  static generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const kp = kyber.keygen();
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

  static encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
    if (!publicKey) throw new Error('Public key required');
    if (publicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE) throw new Error(`Invalid public key size: ${publicKey.length}`);
    const result = kyber.encapsulate(publicKey);
    try {
      if (result.cipherText.length !== PQ_KEM_CIPHERTEXT_SIZE) throw new Error('Invalid ciphertext size');
      if (result.sharedSecret.length !== PQ_KEM_SHARED_SECRET_SIZE) throw new Error('Invalid shared secret size');
      const ciphertext = new Uint8Array(result.cipherText);
      const sharedSecret = new Uint8Array(result.sharedSecret);
      return { ciphertext, sharedSecret };
    } finally {
      PostQuantumUtils.clearMemory(result.cipherText);
      PostQuantumUtils.clearMemory(result.sharedSecret);
    }
  }

  static decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (!ciphertext || !secretKey) throw new Error('Ciphertext and secret key required');
    if (ciphertext.length !== PQ_KEM_CIPHERTEXT_SIZE) throw new Error(`Invalid ciphertext size: ${ciphertext.length}`);
    if (secretKey.length !== PQ_KEM_SECRET_KEY_SIZE) throw new Error(`Invalid secret key size: ${secretKey.length}`);
    const sharedSecret = kyber.decapsulate(ciphertext, secretKey);
    try {
      if (sharedSecret.length !== PQ_KEM_SHARED_SECRET_SIZE) throw new Error('Invalid shared secret size');
      return new Uint8Array(sharedSecret);
    } finally {
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }
}
