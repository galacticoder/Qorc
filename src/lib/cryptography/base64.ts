/**
 * Base64 Encoding/Decoding Utilities
 */

const textEncoder = new TextEncoder();

export class Base64 {
  static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const chunkSize = 8192;
    if (bytes.length <= chunkSize) {
      return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
    }
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
      binary += String.fromCharCode.apply(null, Array.from(chunk));
    }
    return btoa(binary);
  }

  static arrayBufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
    return this.arrayBufferToBase64(buffer)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    try {
      if (!base64 || typeof base64 !== 'string') {
        throw new Error('Invalid base64 input: must be a non-empty string');
      }
      if (
        base64.length % 4 !== 0 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)
      ) {
        throw new Error('Invalid base64 format: contains invalid characters');
      }
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (error) {
      throw new Error(`Base64 decoding failed: ${(error as Error)?.message ?? String(error)}`);
    }
  }

  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    return this.base64ToUint8Array(base64).buffer as ArrayBuffer;
  }

  static stringToArrayBuffer(str: string): ArrayBuffer {
    return textEncoder.encode(str).buffer;
  }
}

export type CanonicalBase64Options = {
  exactBytes?: number;
  maxBytes?: number;
  allowEmpty?: boolean;
};

export function decodeCanonicalBase64(
  value: unknown,
  label: string,
  options: CanonicalBase64Options = {}
): Uint8Array {
  if (
    typeof value !== 'string' ||
    (!options.allowEmpty && value.length === 0) ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    throw new Error(`Invalid ${label}`);
  }
  if (value.length === 0) {
    if (options.exactBytes !== undefined && options.exactBytes !== 0) {
      throw new Error(`Invalid ${label} length`);
    }
    return new Uint8Array(0);
  }
  let bytes: Uint8Array;
  try {
    bytes = Base64.base64ToUint8Array(value);
  } catch {
    throw new Error(`Invalid ${label}`);
  }
  if (Base64.arrayBufferToBase64(bytes) !== value) {
    bytes.fill(0);
    throw new Error(`Non-canonical ${label}`);
  }
  if (options.exactBytes !== undefined && bytes.length !== options.exactBytes) {
    bytes.fill(0);
    throw new Error(`Invalid ${label} length`);
  }
  if (options.maxBytes !== undefined && bytes.length > options.maxBytes) {
    bytes.fill(0);
    throw new Error(`${label} is too large`);
  }
  return bytes;
}

export function tryDecodeCanonicalBase64(
  value: unknown,
  label: string,
  options: CanonicalBase64Options = {}
): Uint8Array | null {
  try {
    return decodeCanonicalBase64(value, label, options);
  } catch {
    return null;
  }
}
