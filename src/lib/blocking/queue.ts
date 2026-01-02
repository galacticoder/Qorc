/**
 * Message Queue for Blocking System
 */

import { CryptoUtils } from '../utils/crypto-utils';
import { SecureMemory } from '../cryptography/secure-memory';
import { SecureDB } from '../secureDB';
import { STORAGE_KEYS } from '../storage-keys';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { QueuedMessage, PersistedQueue, StoredSessionKey } from '../types/blocking-types';
import { QUEUE_STORAGE_VERSION, QUEUE_SESSION_KEY_ID, BLOCK_QUEUE_OVERFLOW_LIMIT, BLOCK_MAX_QUEUE_AGE_MS } from '../constants';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class BlockingMessageQueue {
  private queueKeyPromise: Promise<CryptoKey> | null = null;
  private queuedMessages: QueuedMessage[] = [];
  private queueLoaded = false;
  private readonly overflowLimit = BLOCK_QUEUE_OVERFLOW_LIMIT;
  private readonly maxQueueAge = BLOCK_MAX_QUEUE_AGE_MS;
  private secureDB: SecureDB | null = null;
  private log: (action: string, metadata?: Record<string, unknown>) => void;

  constructor(logger: (action: string, metadata?: Record<string, unknown>) => void) {
    this.log = logger;
  }

  setSecureDB(db: SecureDB | null): void {
    this.secureDB = db;
  }

  private secureDbHasKey(): boolean {
    if (!this.secureDB) return false;
    return this.secureDB.isInitialized();
  }

  private getActiveSecureDB(): SecureDB {
    if (!this.secureDB) {
      throw new Error('SecureDB not initialized - call setSecureDB first');
    }
    return this.secureDB;
  }

  async getQueueKey(): Promise<CryptoKey> {
    if (!this.queueKeyPromise) {
      this.queueKeyPromise = this.loadQueueKey().catch((error) => {
        this.queueKeyPromise = null;
        throw error;
      });
    }
    return this.queueKeyPromise;
  }

  private async loadQueueKey(): Promise<CryptoKey> {
    if (!this.secureDbHasKey()) {
      throw new Error('SecureDB not initialized');
    }

    try {
      const db = this.getActiveSecureDB();
      const stored = await db.retrieve(STORAGE_KEYS.BLOCKING_QUEUE, QUEUE_SESSION_KEY_ID);
      if (stored && typeof stored === 'object') {
        const { key } = stored as StoredSessionKey;
        if (typeof key === 'string' && key.length > 0) {
          const rawKeyArray = CryptoUtils.Base64.base64ToUint8Array(key);
          try {
            const cryptoKey = await crypto.subtle.importKey('raw', rawKeyArray as BufferSource, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
            return cryptoKey;
          } finally {
            SecureMemory.zeroBuffer(rawKeyArray);
          }
        }
      }
    } catch (error) {
      this.log('queue.key.load.error', { error: error instanceof Error ? error.message : String(error) });
    }

    const raw = crypto.getRandomValues(new Uint8Array(32));
    const newKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    const encoded = CryptoUtils.Base64.arrayBufferToBase64(raw);
    SecureMemory.zeroBuffer(raw);
    const db = this.getActiveSecureDB();
    await db.store(STORAGE_KEYS.BLOCKING_QUEUE, QUEUE_SESSION_KEY_ID, { key: encoded });
    return newKey;
  }

  async encryptMessage(payload: Record<string, unknown>): Promise<QueuedMessage> {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const sessionKey = await this.getQueueKey();
    const plaintext = encoder.encode(JSON.stringify(payload));
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, sessionKey, plaintext);
    return {
      ciphertext: CryptoUtils.Base64.arrayBufferToBase64(new Uint8Array(cipherBuf)),
      nonce: CryptoUtils.Base64.arrayBufferToBase64(nonce),
      queuedAt: Date.now(),
      expiresAt: Date.now() + this.maxQueueAge
    };
  }

  async decryptMessage(message: QueuedMessage): Promise<Record<string, unknown> | null> {
    try {
      const sessionKey = await this.getQueueKey();
      const ciphertext = CryptoUtils.Base64.base64ToUint8Array(message.ciphertext);
      const nonce = CryptoUtils.Base64.base64ToUint8Array(message.nonce);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce as BufferSource }, sessionKey, ciphertext as BufferSource);
      const parsed = JSON.parse(decoder.decode(plaintext));

      if (!isPlainObject(parsed)) {
        throw new Error('Decrypted message is not a plain object');
      }
      if (hasPrototypePollutionKeys(parsed)) {
        throw new Error('Prototype pollution detected');
      }

      return parsed;
    } catch {
      this.log('queue.decrypt.error', { error: 'Failed to decrypt queued message' });
      return null;
    }
  }

  async queueMessage(payload: Record<string, unknown>): Promise<void> {
    const encrypted = await this.encryptMessage(payload);
    this.queuedMessages.push(encrypted);
    if (this.queuedMessages.length > this.overflowLimit) {
      this.queuedMessages.splice(0, this.queuedMessages.length - this.overflowLimit);
    }
    await this.persist();
  }

  async persist(): Promise<void> {
    if (!this.secureDbHasKey()) {
      return;
    }

    const validMessages = this.queuedMessages.filter((msg) => Date.now() < msg.expiresAt);
    this.queuedMessages = validMessages.slice(-this.overflowLimit);

    const payload: PersistedQueue = {
      version: QUEUE_STORAGE_VERSION,
      messages: this.queuedMessages
    };

    const db = this.getActiveSecureDB();
    await db.store(STORAGE_KEYS.BLOCKING_QUEUE, 'queue', payload);
  }

  async loadFromStorage(): Promise<void> {
    if (this.queueLoaded || !this.secureDbHasKey()) {
      return;
    }

    try {
      const db = this.getActiveSecureDB();
      const stored = await db.retrieve(STORAGE_KEYS.BLOCKING_QUEUE, 'queue');
      if (stored && typeof stored === 'object') {
        const payload = stored as PersistedQueue;
        if (payload.version === QUEUE_STORAGE_VERSION && Array.isArray(payload.messages)) {
          const now = Date.now();
          this.queuedMessages = payload.messages.filter((msg) =>
            typeof msg === 'object' && typeof msg.ciphertext === 'string' && typeof msg.nonce === 'string' &&
            typeof msg.queuedAt === 'number' && typeof msg.expiresAt === 'number' &&
            now < msg.expiresAt
          );
        }
      }
    } catch {
      this.log('queue.load.error', { error: 'Failed to load queue from storage' });
      this.queuedMessages = [];
    } finally {
      this.queueLoaded = true;
    }
  }

  getQueuedMessages(): QueuedMessage[] {
    return this.queuedMessages;
  }

  setQueuedMessages(messages: QueuedMessage[]): void {
    this.queuedMessages = messages;
  }

  getMaxQueueAge(): number {
    return this.maxQueueAge;
  }

  async processQueuedMessages(
    sendToServer: (payload: Record<string, unknown>) => Promise<void>
  ): Promise<void> {
    await this.loadFromStorage();
    const messages = this.getQueuedMessages();
    if (messages.length === 0) return;

    const nextQueue: QueuedMessage[] = [];
    while (messages.length > 0) {
      const message = messages.shift();
      if (!message) break;
      if (Date.now() - message.queuedAt > this.maxQueueAge) continue;
      const payload = await this.decryptMessage(message);
      if (!payload) continue;
      try {
        await sendToServer(payload);
      } catch {
        nextQueue.push(message);
      }
    }
    this.setQueuedMessages(nextQueue);
    await this.persist();
  }
}
