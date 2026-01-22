/** 
 * Encrypted offline message queue stored in database
*/

import { SecureDB } from './secureDB';
import { STORAGE_KEYS } from './storage-keys';
import { isPlainObject, hasPrototypePollutionKeys, isValidUsername, sanitizeContent } from '../sanitizers';
import {
  SECURE_QUEUE_MESSAGE_EXPIRY_MS,
  SECURE_QUEUE_MAX_MESSAGES_PER_USER,
  SECURE_QUEUE_MAX_PROCESSED_IDS,
  SECURE_QUEUE_CLEANUP_INTERVAL_MS,
  SECURE_QUEUE_SAVE_DEBOUNCE_MS
} from '../constants';
import { messageVault } from '../security/message-vault';

interface QueuedMessage {
  id: string;
  to: string;
  content: string;
  timestamp: number;
  secureContentId?: string;
  replyTo?: { id: string; sender?: string; content?: string; secureContentId?: string };
  fileData?: string;
  messageSignalType?: string;
  originalMessageId?: string;
  editMessageId?: string;
  expiresAt: number;
}

// Normalize queued message
const normalizeQueuedMessage = (value: unknown, username: string): QueuedMessage | null => {
  if (!isPlainObject(value)) return null;
  if (hasPrototypePollutionKeys(value)) return null;

  const record = value as Record<string, unknown>;

  const id = typeof record.id === 'string' ? record.id : null;
  if (!id) return null;

  if (!isValidUsername(username)) return null;

  if (typeof record.content !== 'string') return null;
  const content = sanitizeContent(record.content);
  if (!content) {
    return null;
  }

  if (typeof record.timestamp !== 'number' || !Number.isFinite(record.timestamp)) return null;
  const timestamp = record.timestamp;

  const expiresAt =
    typeof record.expiresAt === 'number' && Number.isFinite(record.expiresAt)
      ? record.expiresAt
      : timestamp + SECURE_QUEUE_MESSAGE_EXPIRY_MS;

  let replyTo: { id: string; sender?: string; content?: string } | undefined;
  if (record.replyTo != null) {
    if (!isPlainObject(record.replyTo) || hasPrototypePollutionKeys(record.replyTo)) return null;
    const replyRec = record.replyTo as Record<string, unknown>;
    if (typeof replyRec.id !== 'string' || !replyRec.id) return null;

    const sender = typeof replyRec.sender === 'string' ? replyRec.sender : undefined;
    const replyContent = typeof replyRec.content === 'string' ? replyRec.content : undefined;
    replyTo = {
      id: replyRec.id,
      ...(sender ? { sender } : {}),
      ...(replyContent ? { content: replyContent } : {}),
    };
  }

  const fileData = typeof record.fileData === 'string' ? record.fileData : undefined;
  const messageSignalType = typeof record.messageSignalType === 'string' ? record.messageSignalType : undefined;
  const originalMessageId = typeof record.originalMessageId === 'string' ? record.originalMessageId : undefined;
  const editMessageId = typeof record.editMessageId === 'string' ? record.editMessageId : undefined;

  return {
    id,
    to: username,
    content,
    timestamp,
    expiresAt,
    ...(replyTo ? { replyTo } : {}),
    ...(fileData ? { fileData } : {}),
    ...(messageSignalType ? { messageSignalType } : {}),
    ...(originalMessageId ? { originalMessageId } : {}),
    ...(editMessageId ? { editMessageId } : {}),
  };
};

class SecureMessageQueue {
  private queue: Map<string, QueuedMessage[]> = new Map();
  private processedIds: Set<string> = new Set();
  private secureDB: SecureDB | null = null;
  private loadPromise: Promise<void> | null = null;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  private pendingSave: boolean = false;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanupExpired(), SECURE_QUEUE_CLEANUP_INTERVAL_MS);
  }

  // Initialize with SecureDB instance
  async initialize(_username: string, secureDB: SecureDB): Promise<void> {
    this.secureDB = secureDB;
    await this.loadFromStorage();
  }

  // Queue a message for an offline recipient
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

    if (!isValidUsername(to)) {
      throw new Error('Invalid username format or reserved identifier');
    }
    const sanitized = sanitizeContent(content);
    if (!sanitized) {
      throw new Error('Content invalid or empty');
    }
    if (sanitized.length > 1024 * 1024) {
      throw new Error('Content exceeds maximum size');
    }

    const messageId = options?.messageId ?? crypto.randomUUID();

    if (this.processedIds.has(messageId)) {
      return messageId;
    }

    // Store content in vault not in memory queue
    await messageVault.store(messageId, sanitized);

    const userQueue = this.queue.get(to) ?? [];
    if (userQueue.length >= SECURE_QUEUE_MAX_MESSAGES_PER_USER) {
      throw new Error(`Message queue limit reached for recipient`);
    }

    const now = Date.now();
    const queuedMessage: QueuedMessage = {
      id: messageId,
      to,
      content: '',
      secureContentId: messageId,
      timestamp: now,
      expiresAt: now + SECURE_QUEUE_MESSAGE_EXPIRY_MS,
      replyTo: options?.replyTo,
      fileData: options?.fileData,
      messageSignalType: options?.messageSignalType,
      originalMessageId: options?.originalMessageId,
      editMessageId: options?.editMessageId,
    };

    userQueue.push(queuedMessage);
    this.queue.set(to, userQueue);

    this.processedIds.add(messageId);
    if (this.processedIds.size > SECURE_QUEUE_MAX_PROCESSED_IDS) {
      const idsArray = Array.from(this.processedIds);
      this.processedIds = new Set(idsArray.slice(-SECURE_QUEUE_MAX_PROCESSED_IDS / 2));
    }

    this.scheduleSave();

    return messageId;
  }

  // Get all queued messages for a specific user
  getMessagesForUser(username: string): QueuedMessage[] {
    return this.queue.get(username) ?? [];
  }

  // Remove a specific message from the queue
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

  // Clear all messages for a specific user
  async clearUserQueue(username: string): Promise<number> {
    const userQueue = this.queue.get(username);
    if (!userQueue) return 0;

    const count = userQueue.length;
    this.queue.delete(username);
    this.scheduleSave();

    return count;
  }

  // Get total number of queued messages
  getTotalQueuedMessages(): number {
    let total = 0;
    for (const userQueue of this.queue.values()) {
      total += userQueue.length;
    }
    return total;
  }

  // Get users with queued messages
  getUsersWithQueuedMessages(): string[] {
    return Array.from(this.queue.keys());
  }

  // Process queued messages when recipient comes online
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

  // Clean up expired messages and notify if any were dropped
  private async cleanupExpired(): Promise<void> {
    const now = Date.now();
    const expiredByUser: Map<string, number> = new Map();

    for (const [username, userQueue] of this.queue.entries()) {
      const validMessages = userQueue.filter(msg => {
        if (msg.expiresAt <= now) {
          expiredByUser.set(username, (expiredByUser.get(username) ?? 0) + 1);
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

    const totalExpired = Array.from(expiredByUser.values()).reduce((a, b) => a + b, 0);
    if (totalExpired > 0) {
      this.scheduleSave();
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('secure-queue-messages-expired', {
          detail: { count: totalExpired, byUser: Object.fromEntries(expiredByUser) }
        }));
      }
    }
  }

  // Schedule a debounced save operation
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
    }, SECURE_QUEUE_SAVE_DEBOUNCE_MS);
  }

  // Save queue to database
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

      await this.secureDB.storeEphemeral(STORAGE_KEYS.SECURE_MESSAGE_QUEUE, queueData);

    } catch (_error) {
      console.error('[SecureMessageQueue] Storage save failed:', _error);
    }
  }

  // Load queue from database
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
        const stored = await this.secureDB!.retrieveEphemeral(STORAGE_KEYS.SECURE_MESSAGE_QUEUE);

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

        const storedRecord = stored as Record<string, unknown>;

        if (storedRecord.version !== 'v1') {
          console.error('[SecureMessageQueue] Unsupported storage version');
          return;
        }

        const queueRaw = storedRecord.queue;
        const processedIdsRaw = storedRecord.processedIds;

        const nextQueue = new Map<string, QueuedMessage[]>();
        if (Array.isArray(queueRaw)) {
          for (const entry of queueRaw) {
            if (!Array.isArray(entry) || entry.length !== 2) continue;
            const username = entry[0];
            const messagesRaw = entry[1];
            if (typeof username !== 'string') continue;
            if (!isValidUsername(username)) continue;
            if (!Array.isArray(messagesRaw)) continue;

            const sanitizedMessages: QueuedMessage[] = [];
            for (const msg of messagesRaw) {
              const normalized = normalizeQueuedMessage(msg, username);
              if (normalized) {
                sanitizedMessages.push(normalized);
              }
              if (sanitizedMessages.length >= SECURE_QUEUE_MAX_MESSAGES_PER_USER) {
                break;
              }
            }

            if (sanitizedMessages.length > 0) {
              nextQueue.set(username, sanitizedMessages);
            }
          }
        }
        this.queue = nextQueue;

        const nextProcessedIds = new Set<string>();
        if (Array.isArray(processedIdsRaw)) {
          const ids: string[] = [];
          for (const id of processedIdsRaw) {
            if (typeof id === 'string' && id) {
              ids.push(id);
            }
          }
          const start = Math.max(0, ids.length - SECURE_QUEUE_MAX_PROCESSED_IDS);
          for (let i = start; i < ids.length; i++) {
            nextProcessedIds.add(ids[i]);
          }
        }
        this.processedIds = nextProcessedIds;

        await this.cleanupExpired();
      } catch (_error) {
        console.error('[SecureMessageQueue] Storage load failed:', _error);
      } finally {
        this.loadPromise = null;
      }
    })();

    await this.loadPromise;
  }

  // Cleanup on destruction
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
      this.saveToStorage().catch(() => { });
    }
  }
}

export const secureMessageQueue = new SecureMessageQueue();