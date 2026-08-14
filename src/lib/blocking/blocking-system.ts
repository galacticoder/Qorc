/**
 * User Blocking System
 */

import { SecureDB } from '../database/secureDB';
import { blockStatusCache } from './block-status-cache';
import { EventType } from '../types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { validateUsername } from '../utils/blocking-utils';
import { BlockedUser } from '../types/blocking-types';
export type { BlockedUser };
import { MAX_BLOCK_LIST_SIZE } from '../constants';
import { BlockingRateLimiter } from './rate-limiter';
import { STORAGE_KEYS, STORAGE_STORES } from '../database/storage-keys';

export class BlockingSystem {
  private static instance: BlockingSystem | null = null;
  private cachedBlockList: BlockedUser[] | null = null;
  private secureDB: SecureDB | null = null;
  private readonly rateLimiter: BlockingRateLimiter;
  private bindingGeneration = 0;
  private mutationChain: Promise<void> = Promise.resolve();
  private blockCleanupHandlers = new Set<(username: string) => Promise<void>>();

  private constructor() {
    if (BlockingSystem.instance) {
      throw new Error('Use BlockingSystem.getInstance()');
    }
    this.rateLimiter = new BlockingRateLimiter();
  }

  static getInstance(): BlockingSystem {
    if (!BlockingSystem.instance) {
      BlockingSystem.instance = new BlockingSystem();
    }
    return BlockingSystem.instance;
  }

  setSecureDB(secureDB: SecureDB | null): void {
    this.bindingGeneration += 1;
    this.secureDB = secureDB;
    this.cachedBlockList = null;
    this.mutationChain = Promise.resolve();
    this.rateLimiter.reset();
    blockStatusCache.clear();
  }

  private secureDbHasKey(): boolean {
    if (!this.secureDB) return false;
    return this.secureDB.isInitialized();
  }

  private captureBinding(): { secureDB: SecureDB; generation: number } {
    if (!this.secureDB || !this.secureDB.isInitialized()) {
      throw new Error('SecureDB not initialized - call setSecureDB first');
    }
    return { secureDB: this.secureDB, generation: this.bindingGeneration };
  }

  private isCurrentBinding(binding: { secureDB: SecureDB; generation: number }): boolean {
    return this.secureDB === binding.secureDB &&
      this.bindingGeneration === binding.generation &&
      binding.secureDB.isInitialized();
  }

  private assertCurrentBinding(binding: { secureDB: SecureDB; generation: number }): void {
    if (!this.isCurrentBinding(binding)) {
      throw new Error('Blocking operation crossed an account transition');
    }
  }

  private enqueueMutation(operation: () => Promise<void>): Promise<void> {
    const queued = this.mutationChain.catch(() => undefined).then(operation);
    this.mutationChain = queued.catch(() => undefined);
    return queued;
  }

  registerBlockCleanupHandler(handler: (username: string) => Promise<void>): () => void {
    this.blockCleanupHandlers.add(handler);
    return () => this.blockCleanupHandlers.delete(handler);
  }

  private async clearOutgoingRecovery(
    target: string,
    binding: { secureDB: SecureDB; generation: number }
  ): Promise<void> {
    this.assertCurrentBinding(binding);
    await binding.secureDB.clearAllUnacknowledgedMessagesForPeer(target);
    this.assertCurrentBinding(binding);

    if (this.blockCleanupHandlers.size === 0) {
      throw new Error('Blocked-recipient retry cleanup is unavailable');
    }
    const outcomes = await Promise.allSettled(
      Array.from(this.blockCleanupHandlers, (handler) => handler(target))
    );
    this.assertCurrentBinding(binding);
    if (outcomes.some((outcome) => outcome.status === 'rejected')) {
      throw new Error('Failed to clear blocked-recipient recovery state');
    }
  }

  private normalizeUsername(username: string): string {
    const normalized = typeof username === 'string' ? username.trim().toLowerCase() : '';
    validateUsername(normalized);
    return normalized;
  }

  private async loadBlockList(
    binding: { secureDB: SecureDB; generation: number }
  ): Promise<BlockedUser[]> {
    this.assertCurrentBinding(binding);
    if (this.cachedBlockList !== null) {
      return this.cachedBlockList.map((entry) => ({ ...entry }));
    }

    try {
      const storedData = await binding.secureDB.retrieve(STORAGE_STORES.BLOCK_LIST, STORAGE_KEYS.BLOCK_LIST_GLOBAL);
      this.assertCurrentBinding(binding);
      if (storedData === null || storedData === undefined) {
        this.cachedBlockList = [];
        return [];
      }

      if (
        !isPlainObject(storedData) ||
        hasPrototypePollutionKeys(storedData) ||
        Object.keys(storedData).sort().join(',') !== 'blockList,version' ||
        storedData.version !== 4 ||
        !Array.isArray(storedData.blockList) ||
        storedData.blockList.length > MAX_BLOCK_LIST_SIZE
      ) {
        throw new Error('Stored block list is invalid');
      }

      const seen = new Set<string>();
      const blockList = storedData.blockList.map((entry): BlockedUser => {
        if (
          !isPlainObject(entry) ||
          hasPrototypePollutionKeys(entry) ||
          Object.keys(entry).sort().join(',') !== 'blockedAt,username' ||
          typeof entry.username !== 'string' ||
          typeof entry.blockedAt !== 'number' ||
          !Number.isSafeInteger(entry.blockedAt) ||
          entry.blockedAt < 0 ||
          entry.blockedAt > Date.now() + 5 * 60_000
        ) {
          throw new Error('Stored block list entry is invalid');
        }
        const username = this.normalizeUsername(entry.username);
        if (username !== entry.username || seen.has(username)) {
          throw new Error('Stored block list entry is not canonical');
        }
        seen.add(username);
        return { username, blockedAt: entry.blockedAt };
      });

      this.cachedBlockList = blockList;
      return blockList.map((entry) => ({ ...entry }));
    } catch (error) {
      this.assertCurrentBinding(binding);
      if (this.cachedBlockList !== null) {
        return this.cachedBlockList;
      }
      throw error;
    }
  }

  private async saveBlockList(
    blockList: BlockedUser[],
    binding: { secureDB: SecureDB; generation: number }
  ): Promise<void> {
    this.assertCurrentBinding(binding);
    try {
      await binding.secureDB.store(STORAGE_STORES.BLOCK_LIST, STORAGE_KEYS.BLOCK_LIST_GLOBAL, {
        version: 4,
        blockList,
      });
      this.assertCurrentBinding(binding);

      this.cachedBlockList = blockList.map((entry) => ({ ...entry }));

    } catch {
      throw new Error('Failed to save block list');
    }
  }

  async blockUser(username: string): Promise<void> {
    this.rateLimiter.checkRateLimit('block');
    username = this.normalizeUsername(username);
    const target = username;
    const binding = this.captureBinding();
    return this.enqueueMutation(async () => {
      this.assertCurrentBinding(binding);
      const blockList = await this.loadBlockList(binding);
      if (blockList.some(user => user.username === target)) {
        blockStatusCache.set(target, true);
        window.dispatchEvent(new CustomEvent(EventType.USER_BLOCKED, {
          detail: { username: target }
        }));
        await this.clearOutgoingRecovery(target, binding);
        return;
      }
      if (blockList.length >= MAX_BLOCK_LIST_SIZE) {
        throw new Error('Block list size limit reached');
      }

      const nextBlockList = [...blockList, {
        username: target,
        blockedAt: Date.now()
      }];

      try {
        await this.saveBlockList(nextBlockList, binding);
      } catch (error) {
        if (this.isCurrentBinding(binding)) {
          this.cachedBlockList = nextBlockList;
          blockStatusCache.set(target, true);
          window.dispatchEvent(new CustomEvent(EventType.USER_BLOCKED, {
            detail: { username: target }
          }));
        }
        try {
          await this.clearOutgoingRecovery(target, binding);
        } catch {
          throw new Error('Block is active for this session, but durable enforcement cleanup failed');
        }
        throw error;
      }
      blockStatusCache.set(target, true);

      window.dispatchEvent(new CustomEvent(EventType.USER_BLOCKED, {
        detail: { username: target }
      }));
      await this.clearOutgoingRecovery(target, binding);
    });
  }

  async unblockUser(username: string): Promise<void> {
    this.rateLimiter.checkRateLimit('unblock');
    username = this.normalizeUsername(username);
    const target = username;
    const binding = this.captureBinding();
    return this.enqueueMutation(async () => {
      this.assertCurrentBinding(binding);
      const blockList = await this.loadBlockList(binding);
      const filteredList = blockList.filter(user => user.username !== target);

      if (filteredList.length !== blockList.length) {
        await this.clearOutgoingRecovery(target, binding);
        await this.saveBlockList(filteredList, binding);
      }
      this.assertCurrentBinding(binding);
      blockStatusCache.set(target, false);

      window.dispatchEvent(new CustomEvent(EventType.USER_UNBLOCKED, {
        detail: { username: target }
      }));
    });
  }

  async isUserBlocked(username: string): Promise<boolean> {
    username = this.normalizeUsername(username);
    const target = username;
    const binding = this.captureBinding();
    const pendingMutations = this.mutationChain;
    await pendingMutations.catch(() => undefined);
    this.assertCurrentBinding(binding);
    try {
      const blockList = await this.loadBlockList(binding);
      return blockList.some(user => user.username === target);
    } catch {
      this.assertCurrentBinding(binding);
      if (this.cachedBlockList) {
        return this.cachedBlockList.some(user => user.username === target);
      }
      throw new Error('Block status unavailable');
    }
  }

  isBlockedSync(username: string): boolean {
    if (!username) return false;
    return !!this.cachedBlockList?.some(user => user.username === username);
  }

  isEnforcementReady(): boolean {
    return this.secureDbHasKey() && this.cachedBlockList !== null;
  }

  async getBlockedUsers(): Promise<BlockedUser[]> {
    const binding = this.captureBinding();
    const pendingMutations = this.mutationChain;
    await pendingMutations.catch(() => undefined);
    this.assertCurrentBinding(binding);
    return await this.loadBlockList(binding);
  }

  async filterIncomingMessage(message: Record<string, unknown>): Promise<boolean> {
    if (!isPlainObject(message)) {
      return false;
    }
    if (hasPrototypePollutionKeys(message)) {
      return false;
    }

    const sender = typeof message.sender === 'string' ? message.sender : undefined;
    if (!sender) return true;

    const isBlocked = await this.isUserBlocked(sender);
    if (isBlocked) {
      return false;
    }

    return true;
  }
}

export const blockingSystem = BlockingSystem.getInstance();
