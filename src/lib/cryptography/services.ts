/**
 * Crypto Services
 */

import { Base64 } from './base64';
import { AES } from './aes-gcm';
import { PostQuantumKEM } from './kem';
import { PostQuantumSignature } from './signature';

const textEncoder = new TextEncoder();

export class DilithiumService {
  static async generateKeyPair() {
    return await PostQuantumSignature.generateKeyPair();
  }

  static async sign(secretKey: Uint8Array, message: Uint8Array) {
    return await PostQuantumSignature.sign(message, secretKey);
  }

  static async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
    return await PostQuantumSignature.verify(signature, message, publicKey);
  }

  static serializePublicKey(publicKey: Uint8Array): string {
    return Base64.arrayBufferToBase64(publicKey);
  }

  static deserializePublicKey(base64: string): Uint8Array {
    return Base64.base64ToUint8Array(base64);
  }

  static serializeSecretKey(secretKey: Uint8Array): string {
    return Base64.arrayBufferToBase64(secretKey);
  }

  static deserializeSecretKey(base64: string): Uint8Array {
    return Base64.base64ToUint8Array(base64);
  }
}

export class KyberService {
  static async generateKeyPair() {
    return await PostQuantumKEM.generateKeyPair();
  }

  static async encapsulate(publicKey: Uint8Array) {
    const { ciphertext, sharedSecret } = await PostQuantumKEM.encapsulate(publicKey);
    return {
      ciphertext,
      sharedSecret,
      version: 1024
    };
  }

  static async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array) {
    return await PostQuantumKEM.decapsulate(ciphertext, secretKey);
  }
}

export class EncryptService {
  static async encryptWithAES(data: string, aesKey: CryptoKey): Promise<string> {
    const { iv, authTag, encrypted } = await AES.encryptBinaryWithAES(textEncoder.encode(data), aesKey);
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptBinaryWithAES(
    data: Uint8Array,
    aesKey: CryptoKey
  ): Promise<{ iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array }> {
    return await AES.encryptBinaryWithAES(data, aesKey);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }
}

export class DecryptService {
  static deserializeEncryptedDataFromUint8Array(encryptedBytes: Uint8Array) {
    if (!encryptedBytes || encryptedBytes.length < 7) {
      throw new Error('Invalid encrypted data: insufficient length');
    }
    const combined = new Uint8Array(encryptedBytes);
    try {
      let off = 0;
      const version = combined[off++];
      if (version !== 1) throw new Error('Unsupported version');
      const ivLen = combined[off++];
      if (ivLen !== 12 || off + ivLen > combined.length) {
        throw new Error('Invalid IV length');
      }
      const iv = combined.slice(off, off + ivLen);
      off += ivLen;
      const tagLen = combined[off++];
      if (tagLen !== 16 || off + tagLen > combined.length) {
        iv.fill(0);
        throw new Error('Invalid auth tag length');
      }
      const authTag = combined.slice(off, off + tagLen);
      off += tagLen;
      if (off + 4 > combined.length) {
        iv.fill(0);
        authTag.fill(0);
        throw new Error('Invalid encrypted data: missing length header');
      }
      const encLen = new DataView(combined.buffer, combined.byteOffset + off, 4).getUint32(0, false);
      off += 4;
      if (encLen === 0 || off + encLen !== combined.length) {
        iv.fill(0);
        authTag.fill(0);
        throw new Error('Invalid encrypted data length');
      }
      const encrypted = combined.slice(off);
      return { iv, authTag, encrypted };
    } finally {
      combined.fill(0);
    }
  }

  static async decryptWithAESRaw(
    iv: Uint8Array,
    authTag: Uint8Array,
    encrypted: Uint8Array,
    aesKey: CryptoKey
  ): Promise<string> {
    return await AES.decryptWithAesGcmRaw(iv, authTag, encrypted, aesKey);
  }
}
