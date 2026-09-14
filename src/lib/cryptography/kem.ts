/**
 * Post-Quantum Key Encapsulation Mechanism
 */

import { PostQuantumWorker } from './worker-bridge';
import {
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SECRET_KEY_BYTES,
  ML_KEM_1024_SHARED_SECRET_BYTES,
} from '../../../shared/crypto-sizes.js';

export class PostQuantumKEM {
  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const result = await PostQuantumWorker.generateKemKeyPair();
    if (result.publicKey.length !== ML_KEM_1024_PUBLIC_KEY_BYTES || result.secretKey.length !== ML_KEM_1024_SECRET_KEY_BYTES) {
      result.publicKey.fill(0);
      result.secretKey.fill(0);
      throw new Error('Worker returned an invalid ML-KEM key pair');
    }
    return result;
  }

  static async encapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
    if (!publicKey) throw new Error('Public key required');
    if (publicKey.length !== ML_KEM_1024_PUBLIC_KEY_BYTES) throw new Error(`Invalid public key size: ${publicKey.length}`);

    const result = await PostQuantumWorker.kemEncapsulate(publicKey);

    if (result.ciphertext.length !== ML_KEM_1024_CIPHERTEXT_BYTES) throw new Error('Invalid ciphertext size');
    if (result.sharedSecret.length !== ML_KEM_1024_SHARED_SECRET_BYTES) throw new Error('Invalid shared secret size');

    return result;
  }

  static async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (!ciphertext || !secretKey) throw new Error('Ciphertext and secret key required');
    if (ciphertext.length !== ML_KEM_1024_CIPHERTEXT_BYTES) throw new Error(`Invalid ciphertext size: ${ciphertext.length}`);
    if (secretKey.length !== ML_KEM_1024_SECRET_KEY_BYTES) throw new Error(`Invalid secret key size: ${secretKey.length}`);

    const sharedSecret = await PostQuantumWorker.kemDecapsulate(ciphertext, secretKey);

    if (sharedSecret.length !== ML_KEM_1024_SHARED_SECRET_BYTES) throw new Error('Invalid shared secret size');

    return sharedSecret;
  }
}
