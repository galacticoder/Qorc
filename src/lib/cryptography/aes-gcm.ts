/**
 * AES-GCM Encryption/Decryption
 */

import { Base64 } from './base64';
import { KeyService } from './keys';
import { AEAD_LAYER_TAG_BYTES, AES_GCM_NONCE_BYTES } from '../../../shared/crypto-sizes.js';
import { concatUint8Arrays } from '../../../shared/bytes.js';

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
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
    const ivView = new Uint8Array(iv);
    const aadView = aad?.byteLength ? new Uint8Array(aad) : null;
    const params: AesGcmParams = { name: 'AES-GCM', iv: ivView.buffer, tagLength: AEAD_LAYER_TAG_BYTES * 8 };
    if (aadView) params.additionalData = aadView.buffer;
    const dataView = new Uint8Array(data);
    let ciphertextWithTag: Uint8Array | null = null;
    let succeeded = false;
    try {
      ciphertextWithTag = new Uint8Array(await subtle.encrypt(params, aesKey, dataView.buffer));
      const authTag = ciphertextWithTag.slice(-AEAD_LAYER_TAG_BYTES);
      const encrypted = ciphertextWithTag.slice(0, -AEAD_LAYER_TAG_BYTES);
      succeeded = true;
      return { iv, authTag, encrypted };
    } finally {
      ciphertextWithTag?.fill(0);
      dataView.fill(0);
      ivView.fill(0);
      aadView?.fill(0);
      if (!succeeded) iv.fill(0);
    }
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
    const ivView = new Uint8Array(iv);
    const aadView = aad?.byteLength ? new Uint8Array(aad) : null;
    const params: AesGcmParams = { name: 'AES-GCM', iv: ivView.buffer, tagLength: AEAD_LAYER_TAG_BYTES * 8 };
    if (aadView) params.additionalData = aadView.buffer;
    const ciphertextWithTag = concatUint8Arrays(encrypted, authTag);
    try {
      const ownedCiphertext = new Uint8Array(ciphertextWithTag);
      try {
        return new Uint8Array(await subtle.decrypt(params, aesKey, ownedCiphertext.buffer));
      } finally {
        ownedCiphertext.fill(0);
      }
    } finally {
      ciphertextWithTag.fill(0);
      ivView.fill(0);
      aadView?.fill(0);
    }
  }

  static async decryptWithAesGcmRaw(
    iv: Uint8Array,
    authTag: Uint8Array,
    encrypted: Uint8Array,
    aesKey: CryptoKey,
    aad?: Uint8Array
  ): Promise<string> {
    const plaintext = await this.decryptBinaryWithAES(iv, authTag, encrypted, aesKey, aad);
    try {
      return new TextDecoder().decode(plaintext);
    } finally {
      plaintext.fill(0);
    }
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
    try {
      return Base64.arrayBufferToBase64(output);
    } finally {
      output.fill(0);
    }
  }
}
