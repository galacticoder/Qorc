/**
 * Post-Quantum AEAD
 * Dual-layer encryption: AES-256-GCM + XChaCha20-Poly1305 + BLAKE3 MAC
 */

import { sha3_512 } from '@noble/hashes/sha3.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { PostQuantumRandom } from './random';
import { PostQuantumWorker } from './worker-bridge';
import { PostQuantumUtils } from '../utils/pq-utils';
import {
  PQ_AEAD_NONCE_SIZE,
  PQ_AEAD_GCM_IV_SIZE,
  PQ_AEAD_MAC_SIZE
} from '../constants';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export class PostQuantumAEAD {
  static extractNonceContext(nonce: Uint8Array): Uint8Array {
    if (nonce.length !== PQ_AEAD_NONCE_SIZE) {
      throw new Error(`Nonce must be ${PQ_AEAD_NONCE_SIZE} bytes`);
    }
    return nonce.slice(PQ_AEAD_GCM_IV_SIZE);
  }

  private static deriveDoubleKey(inputKey: Uint8Array): { k1: Uint8Array; k2: Uint8Array; macKey: Uint8Array } {
    if (inputKey.length !== 32) {
      throw new Error('Input key must be 32 bytes');
    }
    let expanded: Uint8Array | null = null;
    let k1: Uint8Array | null = null;
    let k2: Uint8Array | null = null;
    let macInput: Uint8Array | null = null;
    let macKey: Uint8Array | null = null;
    try {
      expanded = sha3_512(inputKey);
      k1 = expanded.slice(0, 32);
      k2 = expanded.slice(32, 64);
      macInput = PostQuantumUtils.concatBytes(
        new TextEncoder().encode(PROTOCOL_KEYS.UNIFIED_CRYPTO_MAC),
        inputKey
      );
      macKey = blake3(macInput, { dkLen: 32 });
      return { k1, k2, macKey };
    } catch (error) {
      k1?.fill(0);
      k2?.fill(0);
      macKey?.fill(0);
      throw error;
    } finally {
      expanded?.fill(0);
      macInput?.fill(0);
    }
  }

  static encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array,
    explicitNonce?: Uint8Array
  ): { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array } {
    if (key.length !== 32) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    if (explicitNonce && explicitNonce.length !== PQ_AEAD_NONCE_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PQ_AEAD_NONCE_SIZE}-byte nonce`);
    }

    const aadBytes = additionalData || new Uint8Array(0);
    let nonce: Uint8Array | null = null;
    let k1: Uint8Array | null = null;
    let k2: Uint8Array | null = null;
    let macKey: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    let layer1: Uint8Array | null = null;
    let xnonce: Uint8Array | null = null;
    let layer2: Uint8Array | null = null;
    let macInput: Uint8Array | null = null;
    let mac: Uint8Array | null = null;
    let succeeded = false;
    try {
      const derived = PostQuantumAEAD.deriveDoubleKey(key);
      k1 = derived.k1;
      k2 = derived.k2;
      macKey = derived.macKey;
      nonce = explicitNonce ?? PostQuantumAEAD.generateNonce();

      iv = nonce.slice(0, PQ_AEAD_GCM_IV_SIZE);
      const cipher = gcm(k1, iv, aadBytes);
      layer1 = cipher.encrypt(plaintext);

      xnonce = nonce.slice(PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_NONCE_SIZE);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      layer2 = xchacha.encrypt(layer1);

      macInput = PostQuantumUtils.concatBytes(layer2, aadBytes, nonce);
      mac = blake3(macInput, { key: macKey });

      succeeded = true;
      return { ciphertext: layer2, nonce, tag: mac };
    } finally {
      k1?.fill(0);
      k2?.fill(0);
      macKey?.fill(0);
      iv?.fill(0);
      layer1?.fill(0);
      xnonce?.fill(0);
      macInput?.fill(0);
      if (!succeeded) {
        layer2?.fill(0);
        mac?.fill(0);
        if (!explicitNonce) nonce?.fill(0);
      }
      if (!additionalData) aadBytes.fill(0);
    }
  }

  private static generateNonce(): Uint8Array {
    return PostQuantumRandom.randomBytes(PQ_AEAD_NONCE_SIZE);
  }

  static decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array
  ): Uint8Array {
    if (key.length !== 32) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    if (nonce.length !== PQ_AEAD_NONCE_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PQ_AEAD_NONCE_SIZE}-byte nonce`);
    }
    if (tag.length !== PQ_AEAD_MAC_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PQ_AEAD_MAC_SIZE}-byte authentication tag`);
    }

    const aadBytes = additionalData || new Uint8Array(0);
    const { k1, k2, macKey } = PostQuantumAEAD.deriveDoubleKey(key);
    let macInput: Uint8Array | null = null;
    let expectedMac: Uint8Array | null = null;
    let xnonce: Uint8Array | null = null;
    let layer1: Uint8Array | null = null;
    let iv: Uint8Array | null = null;
    try {
      macInput = PostQuantumUtils.concatBytes(ciphertext, aadBytes, nonce);
      expectedMac = blake3(macInput, { key: macKey });

      if (!PostQuantumUtils.timingSafeEqual(tag, expectedMac)) {
        throw new Error('BLAKE3 MAC verification failed');
      }

      xnonce = nonce.slice(PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_NONCE_SIZE);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      layer1 = xchacha.decrypt(ciphertext);

      iv = nonce.slice(0, PQ_AEAD_GCM_IV_SIZE);
      const decipher = gcm(k1, iv, aadBytes);
      const plaintext = decipher.decrypt(layer1);

      return plaintext;
    } finally {
      PostQuantumUtils.clearMemory(k1);
      PostQuantumUtils.clearMemory(k2);
      PostQuantumUtils.clearMemory(macKey);
      macInput?.fill(0);
      expectedMac?.fill(0);
      xnonce?.fill(0);
      layer1?.fill(0);
      iv?.fill(0);
      if (!additionalData) aadBytes.fill(0);
    }
  }

  /**
   * Async encrypt
   */
  static async encryptAsync(
    plaintext: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array,
    explicitNonce?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array }> {
    return await PostQuantumWorker.aeadEncrypt(plaintext, key, additionalData, explicitNonce);
  }

  /**
   * Async decrypt
   */
  static async decryptAsync(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    return await PostQuantumWorker.aeadDecrypt(ciphertext, nonce, tag, key, additionalData);
  }
}
