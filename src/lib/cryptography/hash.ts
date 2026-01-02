/**
 * Post-Quantum Hash Functions
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';

export class PostQuantumHash {
  static blake3(data: Uint8Array, options?: { dkLen?: number }): Uint8Array {
    return blake3(data, options);
  }

  static deriveKey(inputKey: Uint8Array, salt: Uint8Array, info: string, length: number = 32): Uint8Array {
    const infoBytes = new TextEncoder().encode(info || '');
    return hkdf(blake3, inputKey, salt, infoBytes, length);
  }
}
