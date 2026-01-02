/**
 * Key Service AES key generation and management
 */

import { Base64 } from './base64';
import { PostQuantumWorker } from './worker-bridge';
import {
  ARGON2_DEFAULT_TIME,
  ARGON2_DEFAULT_MEM,
  ARGON2_DEFAULT_PARALLELISM,
  ARGON2_VERSION,
  ARGON2_HASH_LEN
} from '../constants';
import { mapArgon2Algorithm } from '../utils/crypto-utils';

const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;

export class KeyService {
  static async generateAESKey(): Promise<CryptoKey> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    return await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  static async importAESKey(keyBytes: ArrayBuffer | Uint8Array, algorithm: string = 'AES-GCM'): Promise<CryptoKey> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    const rawKey = keyBytes instanceof Uint8Array ? keyBytes.buffer as ArrayBuffer : keyBytes;
    return await subtle.importKey('raw', rawKey, { name: algorithm, length: 256 }, true, ['encrypt', 'decrypt']);
  }

  static async exportAESKey(aesKey: CryptoKey): Promise<ArrayBuffer> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    return await subtle.exportKey('raw', aesKey);
  }

  static async deriveAESKeyFromPassphrase(
    passphrase: string,
    options?: {
      saltBase64?: string;
      time?: number;
      memoryCost?: number;
      parallelism?: number;
      algorithm?: number | string;
      version?: number;
      hashLen?: number;
    }
  ) {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    const saltBytes = options?.saltBase64
      ? Base64.base64ToUint8Array(options.saltBase64)
      : crypto.getRandomValues(new Uint8Array(16));

    const {
      time = ARGON2_DEFAULT_TIME,
      memoryCost = ARGON2_DEFAULT_MEM,
      parallelism = ARGON2_DEFAULT_PARALLELISM,
      algorithm = 2,
      version = ARGON2_VERSION,
      hashLen = ARGON2_HASH_LEN
    } = options || {};

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: mapArgon2Algorithm(algorithm),
      version,
      hashLen
    };

    const result = await PostQuantumWorker.argon2Hash(hashOptions);
    const rawKeyBytes = result.hash;
    const aesKey = await this.importAESKey(rawKeyBytes);
    return {
      aesKey,
      encodedHash: result.encoded
    };
  }

  static async importRawAesKey(rawBytes: Uint8Array): Promise<CryptoKey> {
    return await this.importAESKey(rawBytes);
  }
}
