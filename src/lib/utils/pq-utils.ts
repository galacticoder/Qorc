/**
 * Post-Quantum Utilities
 */

import { SecureMemory } from '../cryptography/secure-memory';
import { PQ_UTILS_MAX_DATA_SIZE } from '../constants';

export class PostQuantumUtils {
  static timingSafeEqual = SecureMemory.constantTimeCompare;

  static asUint8Array(value: Uint8Array | ArrayBuffer | Buffer | ArrayLike<number>): Uint8Array {
    if (value instanceof Uint8Array) {
      return value;
    }
    if (typeof Buffer !== 'undefined' && value instanceof Buffer) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (Array.isArray(value)) {
      return Uint8Array.from(value);
    }
    throw new Error('Uint8Array-compatible input required');
  }

  static clearMemory(data: Uint8Array): void {
    if (data) {
      data.fill(0);
    }
  }

  static deepClearSensitiveData(root: unknown, seen: Set<unknown> = new Set()): void {
    if (root === null || root === undefined) {
      return;
    }

    const rootType = typeof root;
    if (rootType !== 'object') {
      return;
    }

    if (seen.has(root)) {
      return;
    }
    seen.add(root);

    if (root instanceof Uint8Array) {
      PostQuantumUtils.clearMemory(root);
      return;
    }

    if (ArrayBuffer.isView(root)) {
      const view = root as ArrayBufferView;
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      PostQuantumUtils.clearMemory(bytes);
      return;
    }

    if (root instanceof ArrayBuffer) {
      const bytes = new Uint8Array(root);
      PostQuantumUtils.clearMemory(bytes);
      return;
    }

    const maybeZeroize = (root as any).zeroize;
    if (typeof maybeZeroize === 'function') {
      try {
        maybeZeroize.call(root);
      } catch {
      }
    }

    if (Array.isArray(root)) {
      for (const item of root) {
        PostQuantumUtils.deepClearSensitiveData(item, seen);
      }
      return;
    }

    if (root instanceof Map) {
      for (const [k, v] of root.entries()) {
        PostQuantumUtils.deepClearSensitiveData(k, seen);
        PostQuantumUtils.deepClearSensitiveData(v, seen);
      }
      return;
    }

    if (root instanceof Set) {
      for (const v of root.values()) {
        PostQuantumUtils.deepClearSensitiveData(v, seen);
      }
      return;
    }

    const obj = root as Record<string | symbol, unknown>;
    for (const key of Object.keys(obj)) {
      try {
        PostQuantumUtils.deepClearSensitiveData(obj[key], seen);
      } catch {
      }
    }

    for (const sym of Object.getOwnPropertySymbols(obj)) {
      try {
        PostQuantumUtils.deepClearSensitiveData(obj[sym], seen);
      } catch {
      }
    }
  }

  static stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  static bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  }

  static bytesToHex(bytes: Uint8Array | ArrayBuffer | Buffer): string {
    bytes = PostQuantumUtils.asUint8Array(bytes);
    if (bytes.length > PQ_UTILS_MAX_DATA_SIZE) {
      throw new Error(`Data too large: ${bytes.length} bytes exceeds limit`);
    }
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  static hexToBytes(hex: string): Uint8Array {
    if (typeof hex !== 'string') {
      throw new Error('Hex input must be a string');
    }
    const clean = hex.replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error('Invalid hex characters');
    }
    if (clean.length % 2 !== 0) {
      throw new Error('Hex string must have even length');
    }
    if (clean.length > PQ_UTILS_MAX_DATA_SIZE * 2) {
      throw new Error(`Hex string too long: ${clean.length} chars exceeds limit`);
    }

    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      const byteStr = clean.slice(i, i + 2);
      const val = parseInt(byteStr, 16);
      if (Number.isNaN(val)) {
        throw new Error(`Invalid hex byte: ${byteStr}`);
      }
      bytes[i / 2] = val;
    }
    return bytes;
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    if (typeof base64 !== 'string' || base64.length === 0) {
      throw new Error('Base64 input must be a non-empty string');
    }

    const sanitized = base64.replace(/\s+/g, '');
    if (!/^[-A-Za-z0-9_+/=]*$/.test(sanitized)) {
      throw new Error('Invalid base64 characters');
    }

    try {
      const binary = atob(sanitized);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch {
      throw new Error('Failed to decode base64');
    }
  }

  static uint8ArrayToBase64(bytes: Uint8Array | ArrayBuffer | Buffer): string {
    bytes = PostQuantumUtils.asUint8Array(bytes);

    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  static concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  static randomBytes(length: number): Uint8Array {
    const { PostQuantumRandom } = require('./random');
    return PostQuantumRandom.randomBytes(length);
  }
}
