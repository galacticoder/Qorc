/**
 * Post-Quantum AEAD (Authenticated Encryption with Associated Data)
 * Dual-layer encryption: AES-256-GCM + XChaCha20-Poly1305 + BLAKE3 MAC
 */

import { sha3_512 } from '@noble/hashes/sha3.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { PostQuantumRandom } from './random';
import { PostQuantumUtils } from '../utils/pq-utils';
import {
  PQ_AEAD_NONCE_SIZE,
  PQ_AEAD_GCM_IV_SIZE,
  PQ_AEAD_MAC_SIZE
} from '../constants';

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
    const expanded = sha3_512(inputKey);
    const k1 = expanded.slice(0, 32);
    const k2 = expanded.slice(32, 64);
    
    const macKey = blake3(PostQuantumUtils.concatBytes(
      new TextEncoder().encode('quantum-secure-mac-v1'),
      inputKey
    ), { dkLen: 32 });
    
    return { k1, k2, macKey };
  }

  static encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array,
    explicitNonce?: Uint8Array
  ): { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array } {
    const nonce = explicitNonce ?? PostQuantumAEAD.generateNonce();
    if (key.length !== 32) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    if (nonce.length !== PQ_AEAD_NONCE_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PQ_AEAD_NONCE_SIZE}-byte nonce`);
    }

    const aadBytes = additionalData || new Uint8Array(0);
    const { k1, k2, macKey } = PostQuantumAEAD.deriveDoubleKey(key);

    try {
      const iv = nonce.slice(0, PQ_AEAD_GCM_IV_SIZE);
      const cipher = gcm(k1, iv, aadBytes);
      const layer1 = cipher.encrypt(plaintext);
      
      const xnonce = nonce.slice(PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_NONCE_SIZE);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      const layer2 = xchacha.encrypt(layer1);
      
      const macInput = PostQuantumUtils.concatBytes(layer2, aadBytes, nonce);
      const mac = blake3(macInput, { key: macKey });
      
      return { ciphertext: layer2, nonce, tag: mac };
    } finally {
      PostQuantumUtils.clearMemory(k1);
      PostQuantumUtils.clearMemory(k2);
      PostQuantumUtils.clearMemory(macKey);
    }
  }

  private static generateNonce(): Uint8Array {
    const nonce = new Uint8Array(PQ_AEAD_NONCE_SIZE);
    const randomBytes = PostQuantumRandom.randomBytes(PQ_AEAD_NONCE_SIZE);
    nonce.set(randomBytes, 0);
    return nonce;
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

    try {
      const macInput = PostQuantumUtils.concatBytes(ciphertext, aadBytes, nonce);
      const expectedMac = blake3(macInput, { key: macKey });
      
      if (!PostQuantumUtils.timingSafeEqual(tag, expectedMac)) {
        throw new Error('BLAKE3 MAC verification failed');
      }
      
      const xnonce = nonce.slice(PQ_AEAD_GCM_IV_SIZE, PQ_AEAD_NONCE_SIZE);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      const layer1 = xchacha.decrypt(ciphertext);
      
      const iv = nonce.slice(0, PQ_AEAD_GCM_IV_SIZE);
      const decipher = gcm(k1, iv, aadBytes);
      const plaintext = decipher.decrypt(layer1);
      
      return plaintext;
    } finally {
      PostQuantumUtils.clearMemory(k1);
      PostQuantumUtils.clearMemory(k2);
      PostQuantumUtils.clearMemory(macKey);
    }
  }
}
