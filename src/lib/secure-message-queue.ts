/** Encrypted offline message queue stored in SecureDB. */

import { SecureAuditLogger } from './secure-error-handler';
import { SecureDB } from './secureDB';

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

const validateUsername = (username: string): void => {
  if (typeof username !== 'string' || username.length < 3 || username.length > 128) {
    throw new Error('Invalid username length');
  }
  if (/[\x00-\x1F\x7F]/.test(username)) {
    throw new Error('Username contains invalid control characters');
  }
  if (['__proto__', 'constructor', 'prototype'].includes(username)) {
    throw new Error('Username is a reserved identifier');
  }
};

const sanitizeContent = (content: string): string => {
  if (typeof content !== 'string') {
    throw new Error('Content must be a string');
  }
  if (/\x00/.test(content)) {
    throw new Error('Content contains null bytes');
  }
  if (content.length > 1024 * 1024) {
    throw new Error('Content exceeds maximum size');
  }
  return content;
};

interface QueuedMessage {
  id: string;
  to: string;
  content: string;
  timestamp: number;
  replyTo?: { id: string; sender?: string; content?: string };
  fileData?: string;
  messageSignalType?: string;
  originalMessageId?: string;
  editMessageId?: string;
  expiresAt: number;
}

const STORAGE_KEY = 'secure_message_queue_v1';
const MESSAGE_EXPIRY = 7 * 24 * 60 * 60 * 1000;
const MAX_MESSAGES_PER_USER = 100;
const MAX_PROCESSED_IDS = 10000;
const CLEANUP_INTERVAL = 60 * 60 * 1000;
const SAVE_DEBOUNCE_MS = 1000;

class SecureMessageQueue {
  private queue: Map<string, QueuedMessage[]> = new Map();
  private processedIds: Set<string> = new Set();
  private secureDB: SecureDB | null = null;
  private loadPromise: Promise<void> | null = null;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingSave: boolean = false;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), CLEANUP_INTERVAL);
  }

/**
   * Initialize with SecureDB instance for encrypted storage.
   */
  async initialize(_username: string, secureDB: SecureDB): Promise<void> {
    this.secureDB = secureDB;
    await this.loadFromStorage();
  }

  /**
   * Queue a message for an offline recipient
   */
  async queueMessage(
    to: string,
    content: string,
    options?: {
      messageId?: string;
      replyTo?: { id: string; sender?: string; content?: string };
      fileData?: string;
      messageSignalType?: string;
      originalMessageId?: string;
      editMessageId?: string;
    }
  ): Promise<string> {
    if (!this.secureDB) {
      throw new Error('SecureMessageQueue not initialized');
    }
    
    validateUsername(to);
    const sanitized = sanitizeContent(content);
    
    const messageId = options?.messageId ?? crypto.randomUUID();

    if (this.processedIds.has(messageId)) {
      return messageId;
    }

    const userQueue = this.queue.get(to) ?? [];
    if (userQueue.length >= MAX_MESSAGES_PER_USER) {
      throw new Error(`Message queue limit reached for recipient`);
    }

    const now = Date.now();
    const queuedMessage: QueuedMessage = {
      id: messageId,
      to,
      content: sanitized,
      timestamp: now,
      expiresAt: now + MESSAGE_EXPIRY,
      replyTo: options?.replyTo,
      fileData: options?.fileData,
      messageSignalType: options?.messageSignalType,
      originalMessageId: options?.originalMessageId,
      editMessageId: options?.editMessageId,
    };

    userQueue.push(queuedMessage);
    this.queue.set(to, userQueue);
    
    this.processedIds.add(messageId);
    if (this.processedIds.size > MAX_PROCESSED_IDS) {
      const idsArray = Array.from(this.processedIds);
      this.processedIds = new Set(idsArray.slice(-MAX_PROCESSED_IDS / 2));
    }

    this.scheduleSave();

    return messageId;
  }

  /**
   * Get all queued messages for a specific user
   */
  getMessagesForUser(username: string): QueuedMessage[] {
    return this.queue.get(username) ?? [];
  }

  /**
   * Remove a specific message from the queue
   */
  async removeMessage(messageId: string, username: string): Promise<boolean> {
    const userQueue = this.queue.get(username);
    if (!userQueue) return false;

    const index = userQueue.findIndex(msg => msg.id === messageId);
    if (index === -1) return false;

    userQueue.splice(index, 1);

    if (userQueue.length === 0) {
      this.queue.delete(username);
    } else {
      this.queue.set(username, userQueue);
    }

    this.scheduleSave();
    return true;
  }

  /**
   * Clear all messages for a specific user
   */
  async clearUserQueue(username: string): Promise<number> {
    const userQueue = this.queue.get(username);
    if (!userQueue) return 0;

    const count = userQueue.length;
    this.queue.delete(username);
    this.scheduleSave();

    return count;
  }

  /**
   * Get total number of queued messages
   */
  getTotalQueuedMessages(): number {
    let total = 0;
    for (const userQueue of this.queue.values()) {
      total += userQueue.length;
    }
    return total;
  }

  /**
   * Get users with queued messages
   */
  getUsersWithQueuedMessages(): string[] {
    return Array.from(this.queue.keys());
  }

  /**
   * Process queued messages when recipient comes online
   */
  async processQueueForUser(username: string): Promise<QueuedMessage[]> {
    const userQueue = this.queue.get(username);
    if (!userQueue || userQueue.length === 0) {
      return [];
    }

    const now = Date.now();
    const validMessages = userQueue.filter(msg => msg.expiresAt > now);

    this.queue.delete(username);
    this.scheduleSave();

    return validMessages;
  }

  /**
   * Clean up expired messages
   */
  private async cleanupExpired(): Promise<void> {
    const now = Date.now();
    let expiredCount = 0;

    for (const [username, userQueue] of this.queue.entries()) {
      const validMessages = userQueue.filter(msg => {
        if (msg.expiresAt <= now) {
          expiredCount++;
          return false;
        }
        return true;
      });

      if (validMessages.length === 0) {
        this.queue.delete(username);
      } else if (validMessages.length !== userQueue.length) {
        this.queue.set(username, validMessages);
      }
    }

    if (expiredCount > 0) {
      this.scheduleSave();
    }
  }

  /**
   * Schedule a debounced save operation
   */
  private scheduleSave(): void {
    if (this.saveTimer) {
      return;
    }

    this.pendingSave = true;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      if (this.pendingSave) {
        this.pendingSave = false;
        this.saveToStorage().catch(err => {
          console.error('[SecureMessageQueue] Scheduled save failed:', err);
        });
      }
    }, SAVE_DEBOUNCE_MS);
  }

  /**
   * Save queue to encrypted SecureDB
   */
  private async saveToStorage(): Promise<void> {
    if (!this.secureDB) {
      return;
    }

    try {
      const queueData = {
        queue: Array.from(this.queue.entries()),
        processedIds: Array.from(this.processedIds),
        version: 'v1',
        timestamp: Date.now()
      };
      
      await this.secureDB.storeEphemeral(STORAGE_KEY, queueData);
      
    } catch (_error) {
      console.error('[SecureMessageQueue] Storage save failed:', _error);
      SecureAuditLogger.error('secureMessageQueue', 'save-storage', 'failed', {
        error: (_error as Error)?.message
      });
    }
  }

  /**
   * Load queue from encrypted SecureDB
   */
  private async loadFromStorage(): Promise<void> {
    if (!this.secureDB) {
      return;
    }

    if (this.loadPromise) {
      await this.loadPromise;
      return;
    }

    this.loadPromise = (async () => {
      try {
        const stored = await this.secureDB!.retrieveEphemeral<{
          queue: [string, QueuedMessage[]][];
          processedIds: string[];
          version: string;
          timestamp: number;
        }>(STORAGE_KEY);
        
        if (!stored) {
          return;
        }
        
        if (!isPlainObject(stored)) {
          console.error('[SecureMessageQueue] Invalid storage structure');
          return;
        }
        if (hasPrototypePollutionKeys(stored)) {
          console.error('[SecureMessageQueue] Prototype pollution detected');
          return;
        }

        if (stored.version !== 'v1') {
          console.error('[SecureMessageQueue] Unsupported storage version');
          return;
        }

        this.queue = new Map(stored.queue ?? []);
        this.processedIds = new Set(stored.processedIds ?? []);

        await this.cleanupExpired();
      } catch (_error) {
        console.error('[SecureMessageQueue] Storage load failed:', _error);
        SecureAuditLogger.error('secureMessageQueue', 'load-storage', 'failed', {
          error: (_error as Error)?.message
        });
      } finally {
        this.loadPromise = null;
      }
    })();

    await this.loadPromise;
  }

  /**
   * Cleanup on destruction
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }
    if (this.pendingSave) {
      this.pendingSave = false;
      this.saveToStorage().catch(() => {});
    }
  }
}

export const secureMessageQueue = new SecureMessageQueue();