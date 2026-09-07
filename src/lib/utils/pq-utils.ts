/**
 * Post-Quantum Utilities
 */

import { SecureMemory } from '../cryptography/secure-memory';
import { PostQuantumRandom } from '../cryptography/random';
import { PQ_UTILS_MAX_DATA_SIZE } from '../constants';
import { bytesToHex as encodeBytesToHex, concatUint8Arrays } from './byte-utils';
import { Base64 } from '../cryptography/base64';

export class PostQuantumUtils {
  static timingSafeEqual = SecureMemory.constantTimeCompare;

  static clearMemory(data: Uint8Array): void {
    data.fill(0);
  }

  static stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  static bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  }

  static bytesToHex(bytes: Uint8Array): string {
    if (bytes.length > PQ_UTILS_MAX_DATA_SIZE) {
      throw new Error(`Data too large: ${bytes.length} bytes exceeds limit`);
    }
    return encodeBytesToHex(bytes);
  }

  static hexToBytes(hex: string): Uint8Array {
    if (typeof hex !== 'string') {
      throw new Error('Hex input must be a string');
    }
    if (!/^[0-9a-f]*$/.test(hex)) {
      throw new Error('Invalid hex characters');
    }
    if (hex.length % 2 !== 0) {
      throw new Error('Hex string must have even length');
    }
    if (hex.length > PQ_UTILS_MAX_DATA_SIZE * 2) {
      throw new Error(`Hex string too long: ${hex.length} chars exceeds limit`);
    }

    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      const byteStr = hex.slice(i, i + 2);
      const val = parseInt(byteStr, 16);
      if (Number.isNaN(val)) {
        throw new Error(`Invalid hex byte: ${byteStr}`);
      }
      bytes[i / 2] = val;
    }
    return bytes;
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    try {
      return Base64.base64ToUint8Array(base64);
    } catch {
      throw new Error('Failed to decode base64');
    }
  }

  static uint8ArrayToBase64(bytes: Uint8Array): string {
    return Base64.arrayBufferToBase64(bytes);
  }

  static concatBytes(...arrays: Uint8Array[]): Uint8Array {
    return concatUint8Arrays(...arrays);
  }

  static randomBytes(length: number): Uint8Array {
    return PostQuantumRandom.randomBytes(length);
  }
}
