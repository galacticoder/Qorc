/**
 * Secure Memory Management Service
 * Provides controlled creation, zeroing, and tracking of sensitive memory
 */

const globalScope = (() => {
  if (typeof globalThis !== 'undefined') return globalThis;
  if (typeof self !== 'undefined') return self as unknown as typeof globalThis;
  if (typeof window !== 'undefined') return window as unknown as typeof globalThis;
  if (typeof global !== 'undefined') return global as unknown as typeof globalThis;
  throw new Error('Unable to locate global execution context');
})();

let cachedCrypto: Crypto | null = null;

function resolveCrypto(): Crypto {
  if (cachedCrypto) {
    return cachedCrypto;
  }

  const candidate = (globalScope as Partial<Window> & { crypto?: Crypto }).crypto;
  if (candidate && typeof candidate.getRandomValues === 'function') {
    cachedCrypto = candidate;
    return cachedCrypto;
  }

  const maybeRequire = (globalScope as Record<string, unknown>).require as undefined | ((module: string) => any);
  if (typeof maybeRequire === 'function') {
    try {
      const nodeCrypto = maybeRequire('crypto')?.webcrypto as Crypto | undefined;
      if (nodeCrypto && typeof nodeCrypto.getRandomValues === 'function') {
        cachedCrypto = nodeCrypto;
        return cachedCrypto;
      }
    } catch {
    }
  }

  throw new Error('Secure environment missing required crypto implementation');
}

export class SecureMemory {
  private static readonly allocatedBuffers = new WeakSet<Uint8Array>();
  private static readonly MAX_BUFFER_SIZE = 1_048_576;

  /**
   * Create a secure buffer
   */
  static createSecureBuffer(size: number): Uint8Array {
    if (!Number.isInteger(size) || size < 0) {
      throw new Error('Invalid buffer size');
    }
    
    if (size > this.MAX_BUFFER_SIZE) {
      throw new Error(`Buffer size exceeds maximum ${this.MAX_BUFFER_SIZE} bytes`);
    }
    
    const buffer = new Uint8Array(size);
    this.allocatedBuffers.add(buffer);
    return buffer;
  }

  /**
   * Securely zero out a buffer with anti-forensics
   */
  static zeroBuffer(buffer: Uint8Array): void {
    if (!(buffer instanceof Uint8Array)) {
      throw new TypeError('Buffer must be Uint8Array');
    }

    if (buffer.length === 0) {
      return;
    }

    const crypto = resolveCrypto();

    let hasNonZero = false;
    for (let i = 0; i < buffer.length; i++) {
      if (buffer[i] !== 0) {
        hasNonZero = true;
        break;
      }
    }

    if (!hasNonZero) {
      return;
    }

    const randomBytes = new Uint8Array(buffer.length);
    crypto.getRandomValues(randomBytes);
    buffer.set(randomBytes);
    randomBytes.fill(0);

    if (buffer.length > 1) {
      const indexArray = new Uint32Array(1);
      crypto.getRandomValues(indexArray);
      const randomIndex = indexArray[0] % buffer.length;
      indexArray.fill(0);
      void buffer[randomIndex];
    } else {
      void buffer[0];
    }

    const entropyLength = Math.min(buffer.length, 64);
    if (entropyLength > 0) {
      const entropy = new Uint8Array(entropyLength);
      crypto.getRandomValues(entropy);
      for (let i = 0; i < entropyLength; i++) {
        buffer[i] ^= entropy[i];
      }
      entropy.fill(0);
    }

    buffer.fill(0);
  }

  /**
   * Secure copy of buffer data
   */
  static secureBufferCopy(source: Uint8Array): Uint8Array {
    const copy = this.createSecureBuffer(source.length);
    copy.set(source);
    return copy;
  }

  /**
   * Compare two buffers in constant time to prevent timing attacks
   */
  static constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    const maxLength = Math.max(a.length, b.length);
    let result = a.length ^ b.length;
    for (let i = 0; i < maxLength; i++) {
      const aVal = i < a.length ? a[i] : 0;
      const bVal = i < b.length ? b[i] : 0;
      result |= aVal ^ bVal;
    }
    return result === 0;
  }
}