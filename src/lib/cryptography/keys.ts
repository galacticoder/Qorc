/**
 * Key Service AES key generation and management
 */

import { KEYS_SOURCE_BYTES_EXPECTED } from '../constants';
const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;

export class KeyService {
  static async importAESKey(keyBytes: ArrayBuffer | Uint8Array, algorithm: string = 'AES-GCM'): Promise<CryptoKey> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    const source = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);
    if (source.byteLength !== KEYS_SOURCE_BYTES_EXPECTED) throw new Error('AES-256 key must be exactly 32 bytes');
    const rawKey = new Uint8Array(source);
    try {
      return await subtle.importKey('raw', rawKey, { name: algorithm, length: 256 }, true, ['encrypt', 'decrypt']);
    } finally {
      rawKey.fill(0);
    }
  }

  static async exportAESKey(aesKey: CryptoKey): Promise<ArrayBuffer> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    return await subtle.exportKey('raw', aesKey);
  }

}
