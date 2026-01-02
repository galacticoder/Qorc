/**
 * Post-Quantum Digital Signatures
 */

import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { PostQuantumRandom } from './random';
import { PostQuantumUtils } from '../utils/pq-utils';
import {
  PQ_SIG_PUBLIC_KEY_SIZE,
  PQ_SIG_SECRET_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE
} from '../constants';

export class PostQuantumSignature {
  private static readonly dilithium = ml_dsa87;

  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const seed = PostQuantumRandom.randomBytes(32);
    const { publicKey, secretKey } = await this.dilithium.keygen(seed);
    return {
      publicKey: PostQuantumUtils.asUint8Array(publicKey),
      secretKey: PostQuantumUtils.asUint8Array(secretKey)
    };
  }

  static sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== PostQuantumSignature.sizes.secretKey) {
      throw new Error('Invalid secret key for Dilithium');
    }
    
    return this.dilithium.sign(message, secretKey);
  }

  static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
    if (!(signature instanceof Uint8Array) || signature.length !== PostQuantumSignature.sizes.signature) {
      throw new Error('Invalid signature size for Dilithium');
    }
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== PostQuantumSignature.sizes.publicKey) {
      throw new Error('Invalid public key for Dilithium');
    }
    
    return this.dilithium.verify(signature, message, publicKey);
  }

  static get sizes() {
    return {
      publicKey: PQ_SIG_PUBLIC_KEY_SIZE,
      secretKey: PQ_SIG_SECRET_KEY_SIZE,
      signature: PQ_SIG_SIGNATURE_SIZE
    };
  }
}
