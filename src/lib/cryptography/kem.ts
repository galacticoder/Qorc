/**
 * Post-Quantum Key Encapsulation Mechanism
 */

import {
  PQ_KEM_PUBLIC_KEY_SIZE,
  PQ_KEM_SECRET_KEY_SIZE,
  PQ_KEM_CIPHERTEXT_SIZE,
  PQ_KEM_SHARED_SECRET_SIZE
} from '../constants';
import { PostQuantumWorker } from './worker-bridge';

export class PostQuantumKEM {
  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const result = await PostQuantumWorker.generateKemKeyPair();
    if (result.publicKey.length !== PQ_KEM_PUBLIC_KEY_SIZE || result.secretKey.length !== PQ_KEM_SECRET_KEY_SIZE) {
      result.publicKey.fill(0);
      result.secretKey.fill(0);
      throw new Error('Worker returned an invalid ML-KEM key pair');
    }
    return result;
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
