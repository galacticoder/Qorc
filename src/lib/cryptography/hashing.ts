import { blake3 as nobleBlake3 } from '@noble/hashes/blake3.js';
import { SecureMemory } from './secure-memory';

export class HashingService {
  static async generateBlake3Mac(message: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) throw new Error('Message must be Uint8Array');
    if (!(key instanceof Uint8Array)) throw new Error('Key must be Uint8Array');

    let normalizedKey = key;
    if (key.length !== 32) normalizedKey = nobleBlake3(key, { dkLen: 32 });
    try {
      const keyedHash = nobleBlake3.create({ key: normalizedKey });
      keyedHash.update(message);
      return keyedHash.digest();
    } finally {
      if (normalizedKey !== key) SecureMemory.zeroBuffer(normalizedKey);
    }
  }

  static async verifyBlake3Mac(
    message: Uint8Array,
    key: Uint8Array,
    expectedMac: Uint8Array,
  ): Promise<boolean> {
    if (!(expectedMac instanceof Uint8Array) || expectedMac.length !== 32) return false;
    const computedMac = await this.generateBlake3Mac(message, key);
    try {
      return SecureMemory.constantTimeCompare(computedMac, expectedMac);
    } finally {
      SecureMemory.zeroBuffer(computedMac);
    }
  }
}
