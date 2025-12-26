/**
 * Blocking System
 */

import { pseudonymizeUsernameWithCache } from './username-hash';
import { SecureDB } from './secureDB';
import { CryptoUtils } from './unified-crypto';
import { SecureMemory } from './secure-memory';
import { blockStatusCache } from './block-status-cache';
import { EventType } from './event-types';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const TOKEN_CONTEXT = encoder.encode('block-token-v2');
const BLOCKLIST_CONTEXT = encoder.encode('block-list-v3');

// Optimized helper functions
const hexToBytes = (hex: string): Uint8Array => {
  const len = hex.length;
  const bytes = new Uint8Array(len >>> 1);
  for (let i = 0; i < len; i += 2) {
    bytes[i >>> 1] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
};

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value == null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
};

const NOTIFICATION_TITLE = 'Message Blocked';
const NOTIFICATION_BODY = 'A message was blocked. See app for details.';

const MESSAGE_QUEUE_KEY = 'secure_block_queue';
const QUEUE_STORAGE_VERSION = 1;
const QUEUE_SESSION_KEY_ID = 'queue_session_key';

interface RateLimitConfig {
  windowMs: number;
  maxEvents: number;
}

interface QueuedMessage {
  ciphertext: string;
  nonce: string;
  queuedAt: number;
  expiresAt: number;
}

interface PersistedQueue {
  version: number;
  messages: QueuedMessage[];
}

interface StoredSessionKey {
  key: string;
}

export interface BlockedUser {
  username: string;
  blockedAt: number;
}

export interface EncryptedBlockList {
  version: number;
  encryptedData: string;
  salt: string;
  lastUpdated: number;
}

export interface BlockToken {
  tokenHash: string;
  blockerHash: string;
  blockedHash: string;
  expiresAt?: number;
}

type KeyMaterial = { passphrase?: string; kyberSecret?: Uint8Array };

export class BlockingSystem {
  private static instance: BlockingSystem | null = null;
  private static readonly DEFAULT_RATE_LIMIT: RateLimitConfig = { windowMs: 60_000, maxEvents: 10 };
  private static readonly TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
  private static readonly MAX_BLOCK_LIST_SIZE = 10000;
  private readonly rateLimitConfig: Record<string, RateLimitConfig>;
  private cachedBlockList: BlockedUser[] | null = null;
  private auditLogger: ((event: string, payload?: Record<string, unknown>) => void) | null;
  private readonly queueOverflowLimit = 1000;
  private readonly rateLimiter = new Map<string, number[]>();
  private secureDB: SecureDB | null = null;
  private readonly circuitBreaker = {
    failures: 0,
    lastFailure: 0,
    state: 'CLOSED' as 'CLOSED' | 'OPEN' | 'HALF_OPEN',
    threshold: 5,
    timeout: 30000
  };
  private queueKeyPromise: Promise<CryptoKey> | null = null;
  private queuedMessages: QueuedMessage[] = [];
  private readonly maxQueueAge = 5 * 60 * 1000;
  private notificationsEnabled = false;
  private queueLoaded = false;

  private constructor() {
    if (BlockingSystem.instance) {
      throw new Error('Use BlockingSystem.getInstance()');
    }
    this.auditLogger = null;
    this.rateLimitConfig = {
      block: BlockingSystem.DEFAULT_RATE_LIMIT,
      unblock: BlockingSystem.DEFAULT_RATE_LIMIT,
      sync: { windowMs: 30_000, maxEvents: 3 }
    };
  }

  static getInstance(): BlockingSystem {
    if (!BlockingSystem.instance) {
      BlockingSystem.instance = new BlockingSystem();
    }
    return BlockingSystem.instance;
  }

  setSecureDB(secureDB: SecureDB | null): void {
    this.secureDB = secureDB;
    // Clear cache when SecureDB changes to force reload from new DB instance
    this.cachedBlockList = null;
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

  private async getQueueKey(): Promise<CryptoKey> {
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
      const stored = await db.retrieve(MESSAGE_QUEUE_KEY, QUEUE_SESSION_KEY_ID);
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
    await db.store(MESSAGE_QUEUE_KEY, QUEUE_SESSION_KEY_ID, { key: encoded });
    return newKey;
  }

  private async ensureDb(): Promise<void> {
    if (!this.secureDbHasKey()) {
      throw new Error('SecureDB not initialized - ensure user is logged in');
    }

    await this.loadQueueFromStorage();
  }

  private log(action: string, metadata?: Record<string, unknown>): void {
    // Route block-related events through the configured audit logger.
    if (this.auditLogger) {
      this.auditLogger(action, { ...metadata, timestamp: Date.now() });
    }
  }

  setAuditLogger(logger: (event: string, payload?: Record<string, unknown>) => void): void {
    this.auditLogger = logger;
  }

  private checkRateLimit(action: string): void {
    const now = Date.now();
    const config = this.rateLimitConfig[action] ?? BlockingSystem.DEFAULT_RATE_LIMIT;
    const timestamps = this.rateLimiter.get(action) ?? [];
    const recent = timestamps.filter((t) => now - t < config.windowMs);
    if (recent.length >= config.maxEvents) {
      throw new Error('Rate limit exceeded');
    }
    recent.push(now);
    if (recent.length > config.maxEvents) {
      recent.splice(0, recent.length - config.maxEvents);
    }
    this.rateLimiter.set(action, recent);
  }

  configureRateLimit(action: string, config: RateLimitConfig): void {
    if (!config || typeof config.windowMs !== 'number' || typeof config.maxEvents !== 'number') {
      throw new Error('Invalid rate limit configuration');
    }
    if (config.windowMs <= 0 || config.maxEvents <= 0) {
      throw new Error('Rate limit configuration must be positive');
    }
    this.rateLimitConfig[action] = { windowMs: config.windowMs, maxEvents: config.maxEvents };
  }

  getRateLimitConfig(action?: string): RateLimitConfig | Record<string, RateLimitConfig> {
    if (!action) {
      return { ...this.rateLimitConfig };
    }
    return this.rateLimitConfig[action] ?? BlockingSystem.DEFAULT_RATE_LIMIT;
  }

  private recordCircuitFailure(): void {
    const breaker = this.circuitBreaker;
    breaker.failures += 1;
    breaker.lastFailure = Date.now();
    if (breaker.failures >= breaker.threshold) {
      breaker.state = 'OPEN';
    }
  }

  private circuitBreakerAllows(): boolean {
    const breaker = this.circuitBreaker;
    if (breaker.state === 'OPEN') {
      if (Date.now() - breaker.lastFailure > breaker.timeout) {
        breaker.state = 'HALF_OPEN';
        return true;
      }
      return false;
    }
    return true;
  }

  private resetCircuitBreaker(): void {
    const breaker = this.circuitBreaker;
    breaker.state = 'CLOSED';
    breaker.failures = 0;
    breaker.lastFailure = 0;
  }

  private validateUsername(username: string): void {
    if (typeof username !== 'string' || username.length < 3 || username.length > 128) {
      throw new Error('Invalid username');
    }

    if (/[\x00-\x1F\x7F]/.test(username)) {
      throw new Error('Username contains invalid control characters');
    }

    const isPseudonym = /^[a-f0-9]{32,}$/i.test(username);

    if (isPseudonym) {
      if (username.length > 128) {
        throw new Error('Invalid pseudonymized username length');
      }
      return;
    }

    if (!/^(?!__)[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])$/.test(username)) {
      throw new Error('Username contains invalid characters');
    }
    if (['__proto__', 'constructor', 'prototype'].includes(username)) {
      throw new Error('Username contains reserved identifier');
    }
  }

  private async generateUserHash(username: string): Promise<string> {
    this.validateUsername(username);
    if (/^(?:[a-f0-9]{32}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(username)) {
      return username.toLowerCase();
    }
    return pseudonymizeUsernameWithCache(username, this.secureDB || undefined);
  }

  private async generateBlockToken(blockerUsername: string, blockedUsername: string): Promise<BlockToken> {
    const blockerHash = await this.generateUserHash(blockerUsername);
    const blockedHash = await this.generateUserHash(blockedUsername);

    const blockerBytes = hexToBytes(blockerHash);
    const blockedBytes = hexToBytes(blockedHash);
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));

    const combined = new Uint8Array(blockerBytes.length + blockedBytes.length + saltBytes.length + TOKEN_CONTEXT.length);
    let offset = 0;
    combined.set(blockerBytes, offset);
    offset += blockerBytes.length;
    combined.set(blockedBytes, offset);
    offset += blockedBytes.length;
    combined.set(saltBytes, offset);
    offset += saltBytes.length;
    combined.set(TOKEN_CONTEXT, offset);

    const { blake3 } = await import('@noble/hashes/blake3.js');
    const hashOutput = blake3(combined, { dkLen: 32 });
    const tokenHash = Array.from(hashOutput).map((b) => b.toString(16).padStart(2, '0')).join('').substring(0, 64);

    return {
      tokenHash,
      blockerHash,
      blockedHash,
      expiresAt: Date.now() + BlockingSystem.TOKEN_TTL_MS
    };
  }

  private async encryptBlockList(blockList: BlockedUser[], key: KeyMaterial): Promise<EncryptedBlockList> {
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Derive 32-byte key from either passphrase (Argon2id) or master key (BLAKE3-MAC)
    let derivedKey: Uint8Array;
    if (key?.passphrase) {
      derivedKey = await CryptoUtils.KDF.argon2id(key.passphrase, {
        salt,
        time: 4,
        memoryCost: 2 ** 18,
        parallelism: 2,
        hashLen: 32
      });
    } else if (key?.kyberSecret) {
      const label = new TextEncoder().encode('block-list-v3');
      const combined = new Uint8Array(label.length + salt.length);
      combined.set(label, 0);
      combined.set(salt, label.length);
      const mac = await (CryptoUtils as any).Hash.generateBlake3Mac(combined, key.kyberSecret);
      derivedKey = mac instanceof Uint8Array ? mac : new Uint8Array(mac as ArrayBuffer);
    } else {
      throw new Error('No key material provided for block list encryption');
    }

    const plaintext = encoder.encode(JSON.stringify(blockList));
    const nonce = crypto.getRandomValues(new Uint8Array(36));
    const { PostQuantumAEAD } = CryptoUtils;

    const { ciphertext, tag } = PostQuantumAEAD.encrypt(plaintext, derivedKey, BLOCKLIST_CONTEXT, nonce);

    const encryptedDataArray = new Uint8Array(nonce.length + ciphertext.length + tag.length);
    encryptedDataArray.set(nonce, 0);
    encryptedDataArray.set(ciphertext, nonce.length);
    encryptedDataArray.set(tag, nonce.length + ciphertext.length);

    return {
      version: 3,
      encryptedData: CryptoUtils.Base64.arrayBufferToBase64(encryptedDataArray),
      salt: CryptoUtils.Base64.arrayBufferToBase64(salt),
      lastUpdated: Date.now()
    };
  }

  private async decryptBlockList(encryptedBlockList: EncryptedBlockList, key: KeyMaterial): Promise<BlockedUser[]> {
    // Require key material
    if ((!key?.passphrase || key.passphrase.length === 0) && !key?.kyberSecret) {
      throw new Error('Key material is required');
    }

    if (encryptedBlockList.version < 3) {
      throw new Error(`Unsupported block list version: ${encryptedBlockList.version}. v3 required.`);
    }

    const encryptedData = CryptoUtils.Base64.base64ToUint8Array(encryptedBlockList.encryptedData);
    const salt = CryptoUtils.Base64.base64ToUint8Array(encryptedBlockList.salt);

    // Require at minimum 36-byte nonce + 16-byte tag
    if (encryptedData.length < 52) {
      throw new Error('Invalid encrypted data: too short');
    }

    let derivedKey: Uint8Array;
    if (key?.passphrase) {
      derivedKey = await CryptoUtils.KDF.argon2id(key.passphrase, {
        salt,
        time: 4,
        memoryCost: 2 ** 18,
        parallelism: 2,
        hashLen: 32
      });
    } else {
      const label = new TextEncoder().encode('block-list-v3');
      const combined = new Uint8Array(label.length + salt.length);
      combined.set(label, 0);
      combined.set(salt, label.length);
      const mac = await (CryptoUtils as any).Hash.generateBlake3Mac(combined, key.kyberSecret!);
      derivedKey = mac instanceof Uint8Array ? mac : new Uint8Array(mac as ArrayBuffer);
    }

    const { PostQuantumAEAD } = CryptoUtils;

    const nonce = encryptedData.slice(0, 36);
    const ciphertext = encryptedData.slice(36, -16);
    const tag = encryptedData.slice(-16);

    try {
      const plaintext = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, derivedKey, BLOCKLIST_CONTEXT);
      const decryptedText = decoder.decode(plaintext);
      const blockList = JSON.parse(decryptedText);

      if (!isPlainObject(blockList) && !Array.isArray(blockList)) {
        throw new Error('Invalid block list format');
      }
      if (hasPrototypePollutionKeys(blockList)) {
        throw new Error('Prototype pollution detected in block list');
      }

      if (!Array.isArray(blockList)) {
        throw new Error('Invalid block list format: expected array');
      }

      for (const user of blockList) {
        if (!isPlainObject(user)) {
          throw new Error('Invalid blocked user entry');
        }
        if (hasPrototypePollutionKeys(user)) {
          throw new Error('Prototype pollution detected in blocked user entry');
        }
        if (!user.username || typeof user.username !== 'string' ||
          !user.blockedAt || typeof user.blockedAt !== 'number') {
          throw new Error('Invalid blocked user entry format');
        }
      }

      this.resetCircuitBreaker();
      return blockList;
    } catch {
      this.recordCircuitFailure();
      throw new Error('Failed to decrypt block list: invalid passphrase or corrupted data');
    }
  }

  private async loadBlockList(_key: KeyMaterial | string): Promise<BlockedUser[]> {
    if (this.cachedBlockList !== null) {
      this.log('loadBlockList.cache', { count: this.cachedBlockList.length });
      return this.cachedBlockList;
    }

    await this.ensureDb();
    try {
      const db = this.getActiveSecureDB();
      const currentUser = await this.getCurrentAuthenticatedUser();
      const storageKey = currentUser ? `blocklist:${currentUser}` : 'blocklist:__global__';
      this.log('loadBlockList.attempt', { currentUser: currentUser?.slice(0, 8), storageKey });

      const storedData = await db.retrieve('blockListData', storageKey);
      if (!storedData || typeof storedData !== 'object') {
        this.log('loadBlockList.empty', { storageKey });
        this.cachedBlockList = [];
        return [];
      }

      const { blockList, version: _version } = storedData as { blockList: BlockedUser[]; version: number; lastUpdated: number };

      if (!Array.isArray(blockList)) {
        this.log('loadBlockList.invalid', { storageKey });
        this.cachedBlockList = [];
        return [];
      }

      this.cachedBlockList = blockList;
      this.log('loadBlockList.success', { count: blockList.length });
      this.resetCircuitBreaker();
      return blockList;
    } catch (error) {
      // On decryption failure, prefer last known cache to avoid UI flicker
      const msg = error instanceof Error ? error.message : String(error);
      this.log('loadBlockList.error', { error: msg });
      if (this.cachedBlockList !== null) {
        return this.cachedBlockList;
      }
      if (msg.includes('decrypt') || msg.includes('passphrase') || msg.includes('corrupted')) {
        this.cachedBlockList = [];
        return [];
      }
      throw error;
    }
  }

  private async saveBlockList(blockList: BlockedUser[], _key: KeyMaterial | string): Promise<void> {
    await this.ensureDb();
    try {
      const db = this.getActiveSecureDB();
      const currentUser = await this.getCurrentAuthenticatedUser();
      const storageKey = currentUser ? `blocklist:${currentUser}` : 'blocklist:__global__';
      this.log('saveBlockList.attempt', { count: blockList.length, currentUser: currentUser?.slice(0, 8), storageKey });

      await db.store('blockListData', storageKey, {
        version: 3,
        blockList,
        lastUpdated: Date.now()
      });

      this.cachedBlockList = blockList;
      this.log('saveBlockList.success', { count: blockList.length });
      await this.updateBlockTokens(blockList);
      await this.persistQueue();
      this.resetCircuitBreaker();
    } catch {
      this.log('save.error', { error: 'Failed to save block list' });
      throw new Error('Failed to save block list');
    }
  }

  private async updateBlockTokens(blockList: BlockedUser[]): Promise<void> {
    try {
      const currentUser = await this.getCurrentAuthenticatedUser();
      if (!currentUser) {
        this.log('updateBlockTokens.noUser', { message: 'No current user found' });
        return;
      }

      const tokens: BlockToken[] = [];

      for (const blockedUser of blockList) {
        const token = await this.generateBlockToken(currentUser, blockedUser.username);
        tokens.push(token);
      }

      const blockerHash = await this.generateUserHash(currentUser);

      this.log('updateBlockTokens.generated', { count: tokens.length, currentUser: currentUser.slice(0, 8) + '...' });

      await this.sendToServer({
        type: 'block-tokens-update',
        blockerHash,
        blockTokens: tokens
      });

      this.log('updateBlockTokens.sent', { count: tokens.length });
    } catch {
      this.log('updateBlockTokens.error', { error: 'Failed to update block tokens' });
    }
  }

  private async getCurrentAuthenticatedUser(): Promise<string | null> {
    try {
      try {
        const { syncEncryptedStorage } = await import('./encrypted-storage');
        const last = syncEncryptedStorage.getItem('last_authenticated_username');
        if (last && typeof last === 'string') {
          return last;
        }
      } catch { }

      if (this.secureDbHasKey()) {
        try {
          const db = this.getActiveSecureDB();
          const stored = await db.retrieve('auth_metadata', 'current_user');
          if (stored && typeof stored === 'string') {
            return stored;
          }
        } catch { }
      }
      return null;
    } catch {
      this.log('getCurrentAuthenticatedUser.error', { error: 'Failed to get current authenticated user' });
      return null;
    }
  }

  private async encryptQueuedMessage(payload: Record<string, unknown>): Promise<QueuedMessage> {
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

  private async decryptQueuedMessage(message: QueuedMessage): Promise<Record<string, unknown> | null> {
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

  private async queueMessage(payload: Record<string, unknown>): Promise<void> {
    const encrypted = await this.encryptQueuedMessage(payload);
    this.queuedMessages.push(encrypted);
    if (this.queuedMessages.length > this.queueOverflowLimit) {
      this.queuedMessages.splice(0, this.queuedMessages.length - this.queueOverflowLimit);
    }
    await this.persistQueue();
  }

  private async persistQueue(): Promise<void> {
    if (!this.secureDbHasKey()) {
      return;
    }

    const validMessages = this.queuedMessages.filter((msg) => Date.now() < msg.expiresAt);
    this.queuedMessages = validMessages.slice(-this.queueOverflowLimit);

    const payload: PersistedQueue = {
      version: QUEUE_STORAGE_VERSION,
      messages: this.queuedMessages
    };

    const db = this.getActiveSecureDB();
    await db.store(MESSAGE_QUEUE_KEY, 'queue', payload);
  }

  private async loadQueueFromStorage(): Promise<void> {
    if (this.queueLoaded || !this.secureDbHasKey()) {
      return;
    }

    try {
      const db = this.getActiveSecureDB();
      const stored = await db.retrieve(MESSAGE_QUEUE_KEY, 'queue');
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

  private async sendToServer(message: Record<string, unknown>): Promise<void> {
    try {
      const { default: websocketClient } = await import('./websocket');
      websocketClient.send(message);
      if (this.circuitBreaker.state !== 'CLOSED') {
        this.resetCircuitBreaker();
      }
      void this.persistQueue();
      return;
    } catch { }

    await this.queueMessage(message);
  }

  async processQueuedMessages(): Promise<void> {
    await this.loadQueueFromStorage();
    if (this.queuedMessages.length === 0) return;

    const nextQueue: QueuedMessage[] = [];
    while (this.queuedMessages.length > 0) {
      const message = this.queuedMessages.shift();
      if (!message) break;
      if (Date.now() - message.queuedAt > this.maxQueueAge) continue;
      const payload = await this.decryptQueuedMessage(message);
      if (!payload) continue;
      try {
        await this.sendToServer(payload);
      } catch {
        nextQueue.push(message);
      }
    }
    this.queuedMessages = nextQueue;
    await this.persistQueue();
  }

  async blockUser(username: string, key: KeyMaterial | string): Promise<void> {
    this.checkRateLimit('block');
    this.validateUsername(username);
    const blockList = await this.loadBlockList(key);
    if (blockList.length >= BlockingSystem.MAX_BLOCK_LIST_SIZE) {
      throw new Error('Block list size limit reached');
    }

    if (blockList.some(user => user.username === username)) {
      await this.updateBlockTokens(blockList);
      return;
    }

    blockList.push({
      username,
      blockedAt: Date.now()
    });

    await this.saveBlockList(blockList, key);
    blockStatusCache.set(username, true);
    this.log('block.success', { username: username.slice(0, 8) + '...', totalBlocked: blockList.length });

    window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
      detail: { username, isBlocked: true }
    }));
    window.dispatchEvent(new CustomEvent(EventType.USER_BLOCKED, {
      detail: { username }
    }));
  }

  async unblockUser(username: string, key: KeyMaterial | string): Promise<void> {
    this.checkRateLimit('unblock');
    this.validateUsername(username);
    const blockList = await this.loadBlockList(key);
    const filteredList = blockList.filter(user => user.username !== username);

    if (filteredList.length !== blockList.length) {
      await this.saveBlockList(filteredList, key);
      blockStatusCache.set(username, false);
      this.log('unblock.success', { username: username.slice(0, 8) + '...', totalBlocked: filteredList.length });

      // Dispatch event to update UI
      window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
        detail: { username, isBlocked: false }
      }));
    } else {
      blockStatusCache.set(username, false);
      this.log('unblock.notFound', { username: username.slice(0, 8) + '...' });

      window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
        detail: { username, isBlocked: false }
      }));
    }
  }

  async isUserBlocked(username: string, key: KeyMaterial | string): Promise<boolean> {
    this.validateUsername(username);
    try {
      const blockList = await this.loadBlockList(key);
      return blockList.some(user => user.username === username);
    } catch (_error) {
      this.log('isUserBlocked.error', { error: _error instanceof Error ? _error.message : String(_error) });
      if (this.cachedBlockList) {
        return this.cachedBlockList.some(user => user.username === username);
      }
      return false;
    }
  }

  async getBlockedUsers(key: KeyMaterial | string): Promise<BlockedUser[]> {
    return await this.loadBlockList(key);
  }

  async filterIncomingMessage(message: Record<string, unknown>, key: KeyMaterial | string): Promise<boolean> {
    if (!isPlainObject(message)) {
      this.log('incoming.invalid', { reason: 'not a plain object' });
      return false;
    }
    if (hasPrototypePollutionKeys(message)) {
      this.log('incoming.invalid', { reason: 'prototype pollution' });
      return false;
    }

    const sender = typeof message.sender === 'string' ? message.sender : undefined;
    if (!sender) return true;

    const isBlocked = await this.isUserBlocked(sender, key);
    if (isBlocked) {
      this.log('incoming.blocked', { sender });
      return false;
    }

    return true;
  }

  async canSendMessage(recipientUsername: string, key: KeyMaterial | string): Promise<boolean> {
    try {
      const isBlocked = await this.isUserBlocked(recipientUsername, key);
      if (isBlocked) {
        this.log('outgoing.blocked', { recipient: recipientUsername });
        return false;
      }

      return true;
    } catch (error) {
      this.log('outgoing.check.error', { error: error instanceof Error ? error.message : String(error) });
      return true;
    }
  }

  async filterOutgoingMessage(message: Record<string, unknown>, key: KeyMaterial | string): Promise<Record<string, unknown> | null> {
    try {
      if (!isPlainObject(message)) {
        this.log('outgoing.invalid', { reason: 'not a plain object' });
        return null;
      }
      if (hasPrototypePollutionKeys(message)) {
        this.log('outgoing.invalid', { reason: 'prototype pollution' });
        return null;
      }

      const recipient = typeof message.recipient === 'string'
        ? message.recipient
        : typeof message.to === 'string'
          ? message.to
          : undefined;

      if (!recipient) {
        return message;
      }

      const canSend = await this.canSendMessage(recipient, key);

      if (!canSend) {
        this.showBlockedMessageNotification();
        return null;
      }

      return message;
    } catch (error) {
      this.log('outgoing.filter.error', { error: error instanceof Error ? error.message : String(error) });
      return message;
    }
  }

  private showBlockedMessageNotification(): void {
    // Always show UI feedback when trying to send to blocked user
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(NOTIFICATION_TITLE, {
        body: NOTIFICATION_BODY,
        icon: '/favicon.ico',
        tag: 'blocked-message',
        silent: true
      });
    }

    window.dispatchEvent(new CustomEvent(EventType.BLOCKED_MESSAGE, {
      detail: { timestamp: Date.now() }
    }));

    // Also show a simple alert for immediate feedback
    alert('Cannot send message to blocked user.');
  }

  setNotificationsEnabled(enabled: boolean): void {
    this.notificationsEnabled = enabled;
  }

  async syncWithServer(key: KeyMaterial | string): Promise<void> {
    this.checkRateLimit('sync');
    try {
      this.log('sync.start');

      const localBlockList = await this.loadBlockList(key);
      const km = typeof key === 'string' ? { passphrase: key } : key;
      const encrypted = await this.encryptBlockList(localBlockList, km as KeyMaterial);

      // Compute a deterministic integrity hash for server-side storage (32-hex)
      let blockListHash = '';
      try {
        const { blake3 } = await import('@noble/hashes/blake3.js');
        const input = new TextEncoder().encode(`${encrypted.salt}|${encrypted.encryptedData}|v${encrypted.version}|${encrypted.lastUpdated}`);
        const digest = blake3(input, { dkLen: 16 }); // 16 bytes -> 32 hex chars
        blockListHash = Array.from(digest).map((b) => b.toString(16).padStart(2, '0')).join('');
      } catch {
        blockListHash = '';
      }

      await this.queueMessage({
        type: 'block-list-sync',
        encryptedBlockList: encrypted.encryptedData,
        blockListHash,
        salt: encrypted.salt,
        version: encrypted.version,
        lastUpdated: encrypted.lastUpdated
      });

      await this.updateBlockTokens(localBlockList);

      this.log('sync.completed');
      this.resetCircuitBreaker();
    } catch (error) {
      this.recordCircuitFailure();
      this.log('sync.error', { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }

  async downloadFromServer(_key: KeyMaterial | string): Promise<void> {
    try {
      this.log('download.request');

      // Request the encrypted block list from the server
      await this.sendToServer({
        type: 'retrieve-block-list'
      });
    } catch (error) {
      this.log('download.error', { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }

  async handleServerBlockListData(
    encryptedData: string | null,
    salt: string | null,
    lastUpdated: number | null,
    version: number,
    key: KeyMaterial | string
  ): Promise<void> {
    try {
      if (!encryptedData || !salt) {
        this.log('server.missing');
        return;
      }

      // Use the same per-user storage key as load/save paths
      let storageKey = 'encrypted:__global__';
      try {
        const currentUser = await this.getCurrentAuthenticatedUser();
        storageKey = currentUser ? `encrypted:${currentUser}` : storageKey;
      } catch { }

      try {
        const db = this.getActiveSecureDB();
        const localMeta = await db.retrieve('blockListMeta', storageKey);
        if (localMeta && (localMeta as EncryptedBlockList).lastUpdated >= (lastUpdated ?? 0)) {
          this.log('local.up_to_date');
          return;
        }
      } catch {
      }

      const serverBlockList: EncryptedBlockList = {
        version,
        encryptedData,
        salt,
        lastUpdated: lastUpdated ?? Date.now()
      };

      const km = typeof key === 'string' ? { passphrase: key } : key;
      const blockList = await this.decryptBlockList(serverBlockList, km as KeyMaterial);
      const db = this.getActiveSecureDB();
      await db.store('blockListMeta', storageKey, serverBlockList);
      this.cachedBlockList = blockList;

      await this.updateBlockTokens(blockList);

      this.log('download.success', { count: blockList.length });
      this.resetCircuitBreaker();
    } catch (error) {
      this.recordCircuitFailure();
      this.log('download.apply.error', { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }

  clearCache(): void {
    this.cachedBlockList = null;
  }
}

export const blockingSystem = BlockingSystem.getInstance();
