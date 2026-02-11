/**
 * Post-Quantum Digital Signatures
 */

import { PostQuantumRandom } from './random';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumWorker } from './worker-bridge';
import {
  PQ_SIG_PUBLIC_KEY_SIZE,
  PQ_SIG_SECRET_KEY_SIZE,
  PQ_SIG_SIGNATURE_SIZE
} from '../constants';

export class PostQuantumSignature {
  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    try {
      return await PostQuantumWorker.generateSigKeyPair();
    } catch (err) {
      console.warn('[PostQuantumSignature] Worker failed, falling back to local keygen', err);
      return this.generateKeyPairLocal();
    }
  }

  static async generateKeyPairLocal(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
    const seed = PostQuantumRandom.randomBytes(32);
    const { publicKey, secretKey } = await ml_dsa87.keygen(seed);
    return {
      publicKey: PostQuantumUtils.asUint8Array(publicKey),
      secretKey: PostQuantumUtils.asUint8Array(secretKey)
    };
  }

  static async sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== PostQuantumSignature.sizes.secretKey) {
      throw new Error('Invalid secret key for Dilithium');
    }
    
    try {
      return await PostQuantumWorker.sigSign(message, secretKey);
    } catch (err) {
      console.warn('[PostQuantumSignature] Worker failed, falling back to local signing', err);
      return this.signLocal(message, secretKey);
    }
  }

  static async signLocal(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
    return ml_dsa87.sign(message, secretKey);
  }

  static async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    if (!(signature instanceof Uint8Array) || signature.length !== PostQuantumSignature.sizes.signature) {
      throw new Error('Invalid signature size for Dilithium');
    }
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== PostQuantumSignature.sizes.publicKey) {
      throw new Error('Invalid public key for Dilithium');
    }
    
    try {
      return await PostQuantumWorker.sigVerify(signature, message, publicKey);
    } catch (err) {
      console.warn('[PostQuantumSignature] Worker failed, falling back to local verification', err);
      return this.verifyLocal(signature, message, publicKey);
    }
  }

  static async verifyLocal(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
    return ml_dsa87.verify(signature, message, publicKey);
  }

  static get sizes() {
    return {
      publicKey: PQ_SIG_PUBLIC_KEY_SIZE,
      secretKey: PQ_SIG_SECRET_KEY_SIZE,
      signature: PQ_SIG_SIGNATURE_SIZE
    };
  }
}
