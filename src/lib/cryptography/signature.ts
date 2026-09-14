/**
 * Post-Quantum Digital Signatures
 */

import { PostQuantumWorker } from './worker-bridge';
import { ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SECRET_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES } from '../../../shared/crypto-sizes.js';

export class PostQuantumSignature {
  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const result = await PostQuantumWorker.generateSigKeyPair();
    if (
      result.publicKey.length !== ML_DSA_87_PUBLIC_KEY_BYTES ||
      result.secretKey.length !== ML_DSA_87_SECRET_KEY_BYTES
    ) {
      result.publicKey.fill(0);
      result.secretKey.fill(0);
      throw new Error('Worker returned an invalid ML-DSA key pair');
    }
    return result;
  }

  static async sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== PostQuantumSignature.sizes.secretKey) {
      throw new Error('Invalid secret key for Dilithium');
    }
    
    return await PostQuantumWorker.sigSign(message, secretKey);
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
    
    return await PostQuantumWorker.sigVerify(signature, message, publicKey);
  }

  static get sizes() {
    return {
      publicKey: ML_DSA_87_PUBLIC_KEY_BYTES,
      secretKey: ML_DSA_87_SECRET_KEY_BYTES,
      signature: ML_DSA_87_SIGNATURE_BYTES
    };
  }
}
