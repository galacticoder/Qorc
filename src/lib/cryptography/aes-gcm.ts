/**
 * AES-GCM Encryption/Decryption
 */

import { Base64 } from './base64';
import { KeyService } from './keys';
import { CRYPTO_IV_LENGTH, CRYPTO_AUTH_TAG_LENGTH } from '../constants';
import { concatUint8Arrays } from '../utils/shared-utils';

const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;

export class AES {
  static async importAesKey(raw: Uint8Array | ArrayBuffer): Promise<CryptoKey> {
    return await KeyService.importAESKey(raw);
  }

  static async encryptBinaryWithAES(
    data: Uint8Array,
    aesKey: CryptoKey,
    aad?: Uint8Array
  ): Promise<{ iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array }> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_IV_LENGTH));
    const params: AesGcmParams = { name: 'AES-GCM', iv, tagLength: CRYPTO_AUTH_TAG_LENGTH * 8 } as AesGcmParams;
    if (aad && aad.byteLength) {
      (params as any).additionalData = aad;
    }
    const ciphertextWithTag = new Uint8Array(await subtle.encrypt(params, aesKey, data.buffer as ArrayBuffer));
    const authTag = ciphertextWithTag.slice(-CRYPTO_AUTH_TAG_LENGTH);
    const encrypted = ciphertextWithTag.slice(0, -CRYPTO_AUTH_TAG_LENGTH);
    return { iv, authTag, encrypted };
  }

  static async decryptBinaryWithAES(
    iv: Uint8Array,
    authTag: Uint8Array,
    encrypted: Uint8Array,
    aesKey: CryptoKey,
    aad?: Uint8Array
  ): Promise<Uint8Array> {
    if (!subtle) {
      throw new Error('SubtleCrypto not available');
    }
    const params: AesGcmParams = { name: 'AES-GCM', iv, tagLength: CRYPTO_AUTH_TAG_LENGTH * 8 } as AesGcmParams;
    if (aad && aad.byteLength) {
      (params as any).additionalData = aad;
    }
    const ciphertextWithTag = concatUint8Arrays(encrypted, authTag);
    const plaintext = new Uint8Array(await subtle.decrypt(params, aesKey, ciphertextWithTag.buffer as ArrayBuffer));
    return plaintext;
  }

  static async decryptWithAesGcmRaw(
    iv: Uint8Array,
    authTag: Uint8Array,
    encrypted: Uint8Array,
    aesKey: CryptoKey,
    aad?: Uint8Array
  ): Promise<string> {
    const plaintext = await this.decryptBinaryWithAES(iv, authTag, encrypted, aesKey, aad);
    return new TextDecoder().decode(plaintext);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
    const totalLength = 1 + 1 + iv.length + 1 + authTag.length + 4 + encrypted.length;
    const output = new Uint8Array(totalLength);
    let offset = 0;
    output[offset++] = 1;
    output[offset++] = iv.length;
    output.set(iv, offset);
    offset += iv.length;
    output[offset++] = authTag.length;
    output.set(authTag, offset);
    offset += authTag.length;
    output[offset++] = (encrypted.length >> 24) & 0xff;
    output[offset++] = (encrypted.length >> 16) & 0xff;
    output[offset++] = (encrypted.length >> 8) & 0xff;
    output[offset++] = encrypted.length & 0xff;
    output.set(encrypted, offset);
    return Base64.arrayBufferToBase64(output);
  }
}
