/**
 * Random Number Generation
 */

import { PQ_RANDOM_MAX_BYTES_LIMIT, PQ_RANDOM_DEFAULT_MAX_BYTES } from '../constants';

export class PostQuantumRandom {
  private static maxRandomBytes = PQ_RANDOM_DEFAULT_MAX_BYTES;

  private static validateSecureRandom(): void {
    if (typeof globalThis === 'undefined' || !globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
      throw new Error('Secure random number generator not available. Requires secure context.');
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
    const bytes = new Uint8Array(length);
    PostQuantumRandom.fillRandomBytes(bytes);
    return bytes;
  }

  static randomInt(maxExclusive: number): number {
    if (!Number.isSafeInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 0x100000000) {
      throw new Error('Invalid random range');
    }
    const range = 0x100000000;
    const limit = range - (range % maxExclusive);
    const sample = new Uint32Array(1);
    do globalThis.crypto.getRandomValues(sample); while (sample[0] >= limit);
    return sample[0] % maxExclusive;
  }

  static shuffleInPlace<T>(values: T[]): T[] {
    for (let index = values.length - 1; index > 0; index -= 1) {
      const swapIndex = PostQuantumRandom.randomInt(index + 1);
      [values[index], values[swapIndex]] = [values[swapIndex], values[index]];
    }
    return values;
  }

  static fillRandomBytes(bytes: Uint8Array): void {
    if (!(bytes instanceof Uint8Array) || bytes.length <= 0) {
      throw new Error('Random target must be a non-empty Uint8Array');
    }
    if (bytes.length > PQ_RANDOM_MAX_BYTES_LIMIT) {
      throw new Error(`Random target exceeds ${PQ_RANDOM_MAX_BYTES_LIMIT} byte limit`);
    }
    PostQuantumRandom.validateSecureRandom();

    const maxChunk = 65536;
    for (let offset = 0; offset < bytes.length; offset += maxChunk) {
      const slice = bytes.subarray(offset, Math.min(offset + maxChunk, bytes.length));
      globalThis.crypto.getRandomValues(slice);
    }
  }

  static randomUUID(): string {
    PostQuantumRandom.validateSecureRandom();
    if (typeof globalThis.crypto.randomUUID !== 'function') {
      throw new Error('Secure UUID generator not available. Requires current desktop WebView support.');
    }
    return globalThis.crypto.randomUUID();
  }
}
