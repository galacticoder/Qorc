/**
 * Random Number Generation
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { PQ_RANDOM_MAX_BYTES_LIMIT, PQ_RANDOM_DEFAULT_MAX_BYTES } from '../constants';

export class PostQuantumRandom {
  private static maxRandomBytes = PQ_RANDOM_DEFAULT_MAX_BYTES;

  private static ensureSecureRandom(): void {
    if (typeof globalThis === 'undefined' || !globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
      throw new Error('Secure random number generator not available. Requires a secure context (HTTPS).');
    }
  }

  static setMaxRandomBytes(maxBytes: number): void {
    if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
      throw new Error('maxRandomBytes must be a positive integer');
    }
    if (maxBytes > PQ_RANDOM_MAX_BYTES_LIMIT) {
      throw new Error(`maxRandomBytes must not exceed ${PQ_RANDOM_MAX_BYTES_LIMIT} bytes`);
    }
    PostQuantumRandom.maxRandomBytes = maxBytes;
  }

  static randomBytes(length: number): Uint8Array {
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error('Length must be a positive integer');
    }
    if (length > PostQuantumRandom.maxRandomBytes) {
      throw new Error(`Requested random byte length exceeds ${PostQuantumRandom.maxRandomBytes} byte limit`);
    }
    PostQuantumRandom.ensureSecureRandom();

    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }

  static randomUUID(): string {
    PostQuantumRandom.ensureSecureRandom();
    if (typeof globalThis.crypto?.randomUUID === 'function') {
      return globalThis.crypto.randomUUID();
    }

    const base = PostQuantumRandom.randomBytes(32);
    const uuidBytes = blake3(base, { dkLen: 16 });
    uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40;
    uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80;
    const hex = Array.from(uuidBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
}
