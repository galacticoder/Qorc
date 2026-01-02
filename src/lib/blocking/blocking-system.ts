/**
 * User Blocking System
 */

import { SecureDB } from '../secureDB';
import { blockStatusCache } from './block-status-cache';
import { EventType } from '../types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { validateUsername } from '../utils/blocking-utils';
import { BlockToken, BlockedUser, EncryptedBlockList, KeyMaterial, RateLimitConfig } from '../types/blocking-types';
import { NOTIFICATION_TITLE, NOTIFICATION_BODY, MAX_BLOCK_LIST_SIZE } from '../constants';
import {
  CircuitBreakerState,
  createCircuitBreaker,
  recordCircuitFailure,
  resetCircuitBreaker
} from './circuit-breaker';
import { BlockingRateLimiter } from './rate-limiter';
import { BlockingMessageQueue } from './queue';
import {
  generateUserHash,
  generateBlockToken,
  encryptBlockList,
  decryptBlockList,
  computeBlockListHash
} from './crypto';
import { SignalType } from '../types/signal-types';

export class BlockingSystem {
  private static instance: BlockingSystem | null = null;
  private cachedBlockList: BlockedUser[] | null = null;
  private auditLogger: ((event: string, payload?: Record<string, unknown>) => void) | null;
  private secureDB: SecureDB | null = null;
  private readonly circuitBreaker: CircuitBreakerState;
  private readonly rateLimiter: BlockingRateLimiter;
  private readonly messageQueue: BlockingMessageQueue;
  private notificationsEnabled = false;

  private constructor() {
    if (BlockingSystem.instance) {
      throw new Error('Use BlockingSystem.getInstance()');
    }
    this.auditLogger = null;
    this.circuitBreaker = createCircuitBreaker();
    this.rateLimiter = new BlockingRateLimiter();
    this.messageQueue = new BlockingMessageQueue((action, metadata) => this.log(action, metadata));
  }

  static getInstance(): BlockingSystem {
    if (!BlockingSystem.instance) {
      BlockingSystem.instance = new BlockingSystem();
    }
    return BlockingSystem.instance;
  }

  setSecureDB(secureDB: SecureDB | null): void {
    this.secureDB = secureDB;
    this.messageQueue.setSecureDB(secureDB);
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

  private async ensureDb(): Promise<void> {
    if (!this.secureDbHasKey()) {
      throw new Error('SecureDB not initialized - ensure user is logged in');
    }
    await this.messageQueue.loadFromStorage();
  }

  private log(action: string, metadata?: Record<string, unknown>): void {
    if (this.auditLogger) {
      this.auditLogger(action, { ...metadata, timestamp: Date.now() });
    }
  }

  setAuditLogger(logger: (event: string, payload?: Record<string, unknown>) => void): void {
    this.auditLogger = logger;
  }

  configureRateLimit(action: string, config: RateLimitConfig): void {
    this.rateLimiter.configureRateLimit(action, config);
  }

  getRateLimitConfig(action?: string): RateLimitConfig | Record<string, RateLimitConfig> {
    return this.rateLimiter.getRateLimitConfig(action);
  }

  private async getCurrentAuthenticatedUser(): Promise<string | null> {
    try {
      try {
        const { syncEncryptedStorage } = await import('../encrypted-storage');
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

  private async updateBlockTokens(blockList: BlockedUser[]): Promise<void> {
    try {
      const currentUser = await this.getCurrentAuthenticatedUser();
      if (!currentUser) {
        this.log('updateBlockTokens.noUser', { message: 'No current user found' });
        return;
      }

      const tokens: BlockToken[] = [];

      for (const blockedUser of blockList) {
        const token = await generateBlockToken(currentUser, blockedUser.username, this.secureDB || undefined);
        tokens.push(token);
      }

      const blockerHash = await generateUserHash(currentUser, this.secureDB || undefined);

      await this.sendToServer({
        type: SignalType.BLOCK_TOKENS_UPDATE,
        blockerHash,
        blockTokens: tokens
      });
    } catch {
      this.log('updateBlockTokens.error', { error: 'Failed to update block tokens' });
    }
  }

  private async loadBlockList(_key: KeyMaterial | string): Promise<BlockedUser[]> {
    if (this.cachedBlockList !== null) {
      return this.cachedBlockList;
    }

    await this.ensureDb();
    try {
      const db = this.getActiveSecureDB();
      const currentUser = await this.getCurrentAuthenticatedUser();
      const storageKey = currentUser ? `blocklist:${currentUser}` : 'blocklist:__global__';
      const storedData = await db.retrieve('blockListData', storageKey);
      if (!storedData || typeof storedData !== 'object') {
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
      return blockList;
    } catch (error) {
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

      await db.store('blockListData', storageKey, {
        version: 3,
        blockList,
        lastUpdated: Date.now()
      });

      this.cachedBlockList = blockList;

      await this.updateBlockTokens(blockList);
      await this.messageQueue.persist();
      resetCircuitBreaker(this.circuitBreaker);
    } catch {
      this.log('save.error', { error: 'Failed to save block list' });
      throw new Error('Failed to save block list');
    }
  }

  private async sendToServer(message: Record<string, unknown>): Promise<void> {
    try {
      const { default: websocketClient } = await import('../websocket');
      websocketClient.send(message);
      resetCircuitBreaker(this.circuitBreaker);
      void this.messageQueue.persist();
      return;
    } catch { }

    await this.messageQueue.queueMessage(message);
  }

  async processQueuedMessages(): Promise<void> {
    await this.messageQueue.processQueuedMessages((payload) => this.sendToServer(payload));
  }

  async blockUser(username: string, key: KeyMaterial | string): Promise<void> {
    this.rateLimiter.checkRateLimit('block');
    validateUsername(username);
    const blockList = await this.loadBlockList(key);
    if (blockList.length >= MAX_BLOCK_LIST_SIZE) {
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

    window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
      detail: { username, isBlocked: true }
    }));
    window.dispatchEvent(new CustomEvent(EventType.USER_BLOCKED, {
      detail: { username }
    }));
  }

  async unblockUser(username: string, key: KeyMaterial | string): Promise<void> {
    this.rateLimiter.checkRateLimit('unblock');
    validateUsername(username);
    const blockList = await this.loadBlockList(key);
    const filteredList = blockList.filter(user => user.username !== username);

    if (filteredList.length !== blockList.length) {
      await this.saveBlockList(filteredList, key);
      blockStatusCache.set(username, false);

      window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
        detail: { username, isBlocked: false }
      }));
    } else {
      blockStatusCache.set(username, false);
      
      window.dispatchEvent(new CustomEvent(EventType.BLOCK_STATUS_CHANGED, {
        detail: { username, isBlocked: false }
      }));
    }
  }

  async isUserBlocked(username: string, key: KeyMaterial | string): Promise<boolean> {
    validateUsername(username);
    try {
      const blockList = await this.loadBlockList(key);
      return blockList.some(user => user.username === username);
    } catch (_error) {
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
      return false;
    }

    return true;
  }

  async canSendMessage(recipientUsername: string, key: KeyMaterial | string): Promise<boolean> {
    try {
      const isBlocked = await this.isUserBlocked(recipientUsername, key);
      if (isBlocked) {
        return false;
      }
      return true;
    } catch (error) {
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
      return message;
    }
  }

  private showBlockedMessageNotification(): void {
    if (this.notificationsEnabled && 'Notification' in window && Notification.permission === 'granted') {
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

    if (this.notificationsEnabled) {
      alert('Cannot send message to blocked user.');
    }
  }

  setNotificationsEnabled(enabled: boolean): void {
    this.notificationsEnabled = enabled;
  }

  async syncWithServer(key: KeyMaterial | string): Promise<void> {
    this.rateLimiter.checkRateLimit('sync');
    try {
      const localBlockList = await this.loadBlockList(key);
      const km = typeof key === 'string' ? { passphrase: key } : key;
      const encrypted = await encryptBlockList(localBlockList, km as KeyMaterial);
      const blockListHash = await computeBlockListHash(encrypted);

      await this.messageQueue.queueMessage({
        type: SignalType.BLOCK_LIST_SYNC,
        encryptedBlockList: encrypted.encryptedData,
        blockListHash,
        salt: encrypted.salt,
        version: encrypted.version,
        lastUpdated: encrypted.lastUpdated
      });

      await this.updateBlockTokens(localBlockList);
      resetCircuitBreaker(this.circuitBreaker);
    } catch (error) {
      recordCircuitFailure(this.circuitBreaker);
      this.log('sync.error', { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }

  async downloadFromServer(_key: KeyMaterial | string): Promise<void> {
    try {
      await this.sendToServer({
        type: SignalType.RETRIEVE_BLOCK_LIST
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
        return;
      }

      let storageKey = 'encrypted:__global__';
      try {
        const currentUser = await this.getCurrentAuthenticatedUser();
        storageKey = currentUser ? `encrypted:${currentUser}` : storageKey;
      } catch { }

      try {
        const db = this.getActiveSecureDB();
        const localMeta = await db.retrieve('blockListMeta', storageKey);
        if (localMeta && (localMeta as EncryptedBlockList).lastUpdated >= (lastUpdated ?? 0)) {
          return;
        }
      } catch { }

      const serverBlockList: EncryptedBlockList = {
        version,
        encryptedData,
        salt,
        lastUpdated: lastUpdated ?? Date.now()
      };

      const km = typeof key === 'string' ? { passphrase: key } : key;
      const blockList = await decryptBlockList(serverBlockList, km as KeyMaterial);
      const db = this.getActiveSecureDB();
      await db.store('blockListMeta', storageKey, serverBlockList);
      this.cachedBlockList = blockList;

      await this.updateBlockTokens(blockList);

      resetCircuitBreaker(this.circuitBreaker);
    } catch (error) {
      recordCircuitFailure(this.circuitBreaker);
      this.log('download.apply.error', { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }

  clearCache(): void {
    this.cachedBlockList = null;
  }
}

export const blockingSystem = BlockingSystem.getInstance();
