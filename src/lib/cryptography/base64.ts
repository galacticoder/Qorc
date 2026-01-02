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

  static base64ToUint8Array(base64: string): Uint8Array {
    try {
      if (!base64 || typeof base64 !== 'string') {
        throw new Error('Invalid base64 input: must be a non-empty string');
      }
      let normalized = base64.trim();
      normalized = normalized.replace(/-/g, '+').replace(/_/g, '/');
      normalized = normalized.replace(/\s+/g, '');

      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
        throw new Error('Invalid base64 format: contains invalid characters');
      }

      const padLen = normalized.length % 4;
      if (padLen === 1) {
        throw new Error('Invalid base64 length');
      } else if (padLen === 2) {
        normalized += '==';
      } else if (padLen === 3) {
        normalized += '=';
      }
      const binary = atob(normalized);
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
