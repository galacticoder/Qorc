/**
 * Client-Server Protocol for Post-Quantum Encrypted Communication
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { PostQuantumKEM } from './kem';
import { PostQuantumHash } from './hash';
import { PostQuantumAEAD } from './aead';
import { PostQuantumUtils } from '../utils/pq-utils';
import type { EncryptedMessagePayload } from '../types/crypto-types';
import {
  PQ_PROTOCOL_MAX_MESSAGE_AGE_MS,
  PQ_PROTOCOL_MAX_SEEN_ENTRIES,
  PQ_PROTOCOL_SEEN_BUFFER_RATIO
} from '../constants';

export class ClientServerProtocol {
  private static MAX_MESSAGE_AGE_MS = PQ_PROTOCOL_MAX_MESSAGE_AGE_MS;
  private static readonly MAX_SEEN_ENTRIES = PQ_PROTOCOL_MAX_SEEN_ENTRIES;
  private static readonly SEEN_BUFFER_RATIO = PQ_PROTOCOL_SEEN_BUFFER_RATIO;
  private static readonly SHARED_SECRET_SALT_BYTES = Object.freeze([
    0x45, 0x6e, 0x64, 0x32, 0x45, 0x6e, 0x64, 0x2d,
    0x43, 0x68, 0x61, 0x74, 0x2d, 0x50, 0x51, 0x2d,
    0x48, 0x79, 0x62, 0x72, 0x69, 0x64, 0x2d, 0x4b,
    0x45, 0x4d, 0x2d, 0x4b, 0x65, 0x79, 0x2d, 0x31
  ]);
  private static readonly seenCiphertexts = new Map<string, number>();

  private static getSharedSecretSalt(): Uint8Array {
    return Uint8Array.from(ClientServerProtocol.SHARED_SECRET_SALT_BYTES);
  }

  static async encryptForServer(
    message: Uint8Array,
    serverPublicKey: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<EncryptedMessagePayload> {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    const { ciphertext: kemCiphertext, sharedSecret } = PostQuantumKEM.encapsulate(serverPublicKey);

    try {
      const contextInfo = `client-to-server-v1:length:${message.length}:ts:${Date.now()}`;
      const encryptionKey = PostQuantumHash.deriveKey(
        sharedSecret,
        ClientServerProtocol.getSharedSecretSalt(),
        contextInfo,
        32
      );

      const { ciphertext: aeadCiphertext, nonce: aeadNonce, tag: aeadTag } = PostQuantumAEAD.encrypt(
        message,
        encryptionKey,
        additionalData
      );

      return {
        version: 1,
        kemCiphertext,
        aeadCiphertext,
        aeadNonce,
        aeadTag,
        timestamp: Date.now()
      };
    } finally {
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }

  static async decryptFromServer(
    encryptedMessage: EncryptedMessagePayload,
    mySecretKey: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    if (!encryptedMessage || typeof encryptedMessage !== 'object') {
      throw new Error('Encrypted message payload required');
    }

    if (encryptedMessage.version !== 1) {
      throw new Error(`Unsupported encrypted payload version: ${encryptedMessage.version}`);
    }

    const age = Date.now() - encryptedMessage.timestamp;
    if (age > ClientServerProtocol.MAX_MESSAGE_AGE_MS) {
      throw new Error('Message too old; possible replay attack');
    }

    const sharedSecret = PostQuantumKEM.decapsulate(encryptedMessage.kemCiphertext, mySecretKey);
    try {
      ClientServerProtocol.recordCiphertext(encryptedMessage.kemCiphertext);
      const contextInfo = `server-to-client-v1:length:${encryptedMessage.aeadCiphertext.length}:ts:${encryptedMessage.timestamp}`;
      const decryptionKey = PostQuantumHash.deriveKey(
        sharedSecret,
        ClientServerProtocol.getSharedSecretSalt(),
        contextInfo,
        32
      );

      return PostQuantumAEAD.decrypt(
        encryptedMessage.aeadCiphertext,
        encryptedMessage.aeadNonce,
        encryptedMessage.aeadTag,
        decryptionKey,
        additionalData
      );
    } finally {
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }

  private static recordCiphertext(ciphertext: Uint8Array): void {
    const now = Date.now();
    const hash = blake3(ciphertext, { dkLen: 32 });
    const key = PostQuantumUtils.bytesToHex(hash);
    PostQuantumUtils.clearMemory(hash);

    if (ClientServerProtocol.seenCiphertexts.has(key)) {
      throw new Error('Replay detected: ciphertext already processed');
    }

    ClientServerProtocol.seenCiphertexts.set(key, now);
    ClientServerProtocol.evictOldCiphertexts(now);
  }

  private static evictOldCiphertexts(now: number): void {
    const cutoffTime = now - ClientServerProtocol.MAX_MESSAGE_AGE_MS;

    if (ClientServerProtocol.seenCiphertexts.size > ClientServerProtocol.MAX_SEEN_ENTRIES) {
      const entries = Array.from(ClientServerProtocol.seenCiphertexts.entries()).sort((a, b) => a[1] - b[1]);
      const targetSize = Math.floor(ClientServerProtocol.MAX_SEEN_ENTRIES * ClientServerProtocol.SEEN_BUFFER_RATIO);
      const maxToRemove = ClientServerProtocol.seenCiphertexts.size - targetSize;
      let removedCount = 0;

      for (const [key, timestamp] of entries) {
        if (timestamp < cutoffTime || removedCount < maxToRemove) {
          ClientServerProtocol.seenCiphertexts.delete(key);
          removedCount += 1;
          continue;
        }

        if (ClientServerProtocol.seenCiphertexts.size <= ClientServerProtocol.MAX_SEEN_ENTRIES && timestamp >= cutoffTime) {
          break;
        }
      }
    } else {
      for (const [key, timestamp] of Array.from(ClientServerProtocol.seenCiphertexts.entries())) {
        if (timestamp < cutoffTime) {
          ClientServerProtocol.seenCiphertexts.delete(key);
        }
      }
    }
  }

  static getSeenCiphertextsSize(): number {
    return ClientServerProtocol.seenCiphertexts.size;
  }

  static setMaxMessageAge(ageMs: number): void {
    if (!Number.isFinite(ageMs) || ageMs < 0) {
      throw new Error('maxMessageAgeMs must be a non-negative finite number');
    }
    ClientServerProtocol.MAX_MESSAGE_AGE_MS = ageMs;
  }

  static getMaxMessageAge(): number {
    return ClientServerProtocol.MAX_MESSAGE_AGE_MS;
  }
}
