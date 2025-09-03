/**
 * Client-side offline message queue for handling messages to offline users
 * Stores messages locally and retries delivery when users come online
 */

import { Message } from '../components/chat/types';

interface QueuedMessage {
  id: string;
  to: string;
  encryptedPayload: any;
  timestamp: number;
  retryCount: number;
  maxRetries: number;
  expiresAt: number;
}

interface UserStatus {
  username: string;
  isOnline: boolean;
  lastSeen: number;
}

export class OfflineMessageQueue {
  private queue: Map<string, QueuedMessage[]> = new Map();
  private userStatuses: Map<string, UserStatus> = new Map();
  private sendCallback?: (payload: any) => Promise<boolean>;
  private maxRetries = 3;
  private messageExpiry = 7 * 24 * 60 * 60 * 1000; // 7 days
  private retryInterval = 30000; // 30 seconds
  private retryTimer?: NodeJS.Timeout;

  constructor(sendCallback?: (payload: any) => Promise<boolean>) {
    this.sendCallback = sendCallback;
    this.startRetryLoop();
    this.loadFromStorage();
  }

  /**
   * Set the callback function for sending messages
   */
  setSendCallback(callback: (payload: any) => Promise<boolean>) {
    this.sendCallback = callback;
  }

  /**
   * Update user online status
   */
  updateUserStatus(username: string, isOnline: boolean) {
    this.userStatuses.set(username, {
      username,
      isOnline,
      lastSeen: Date.now()
    });

    // If user came online, try to deliver their queued messages
    if (isOnline) {
      this.processQueueForUser(username);
    }
  }

  /**
   * Queue a message for offline delivery
   */
  queueMessage(to: string, encryptedPayload: any): string {
    const messageId = encryptedPayload?.encryptedPayload?.messageId || crypto.randomUUID();
    
    const queuedMessage: QueuedMessage = {
      id: messageId,
      to,
      encryptedPayload,
      timestamp: Date.now(),
      retryCount: 0,
      maxRetries: this.maxRetries,
      expiresAt: Date.now() + this.messageExpiry
    };

    if (!this.queue.has(to)) {
      this.queue.set(to, []);
    }

    this.queue.get(to)!.push(queuedMessage);
    this.saveToStorage();

    console.log(`[OfflineQueue] Queued message for offline user: ${to}`, {
      messageId,
      queueSize: this.queue.get(to)!.length
    });

    return messageId;
  }

  /**
   * Check if a user is online
   */
  isUserOnline(username: string): boolean {
    const status = this.userStatuses.get(username);
    return status?.isOnline || false;
  }

  /**
   * Process queued messages for a specific user
   */
  private async processQueueForUser(username: string) {
    const userQueue = this.queue.get(username);
    if (!userQueue || userQueue.length === 0) {
      return;
    }

    console.log(`[OfflineQueue] Processing ${userQueue.length} queued messages for user: ${username}`);

    const messagesToRetry: QueuedMessage[] = [];
    const now = Date.now();

    for (const message of userQueue) {
      // Skip expired messages
      if (message.expiresAt < now) {
        console.log(`[OfflineQueue] Message expired, removing: ${message.id}`);
        continue;
      }

      // Skip messages that exceeded retry limit
      if (message.retryCount >= message.maxRetries) {
        console.log(`[OfflineQueue] Message exceeded retry limit, removing: ${message.id}`);
        continue;
      }

      try {
        if (this.sendCallback) {
          const success = await this.sendCallback(message.encryptedPayload);
          if (success) {
            console.log(`[OfflineQueue] Successfully delivered queued message: ${message.id}`);
          } else {
            message.retryCount++;
            messagesToRetry.push(message);
            console.log(`[OfflineQueue] Failed to deliver message, will retry: ${message.id} (attempt ${message.retryCount}/${message.maxRetries})`);
          }
        } else {
          // No send callback available, keep in queue
          messagesToRetry.push(message);
        }
      } catch (error) {
        // Differentiate between network errors and other failures
        const isNetworkError = error instanceof TypeError || 
                               (error as any)?.code === 'ECONNREFUSED' ||
                               (error as any)?.code === 'ETIMEDOUT';
        
        if (isNetworkError && message.retryCount < message.maxRetries) {
          message.retryCount++;
          messagesToRetry.push(message);
          console.error(`[OfflineQueue] Network error delivering message ${message.id}, will retry:`, error);
        } else {
          console.error(`[OfflineQueue] Fatal error delivering message ${message.id}, removing:`, error);
        }
      }
    }

    // Update queue with messages that need retry
    if (messagesToRetry.length === 0) {
      this.queue.delete(username);
    } else {
      this.queue.set(username, messagesToRetry);
    }

    this.saveToStorage();
  }

  /**
   * Start the retry loop for processing queued messages
   */
  private startRetryLoop() {
    this.retryTimer = setInterval(() => {
      this.processAllQueues();
    }, this.retryInterval);
  }

  /**
   * Stop the retry loop and cleanup resources
   */
  public stop() {
    if (this.retryTimer) {
      clearInterval(this.retryTimer);
      this.retryTimer = undefined;
    }
  }

  /**
   * Process all queued messages for online users
   */
  private async processAllQueues() {
    for (const [username, messages] of this.queue.entries()) {
      if (this.isUserOnline(username) && messages.length > 0) {
        await this.processQueueForUser(username);
      }
    }

    // Clean up expired messages
    this.cleanupExpiredMessages();
  }

  /**
   * Clean up expired messages from all queues
   */
  private cleanupExpiredMessages() {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [username, messages] of this.queue.entries()) {
      const validMessages = messages.filter(msg => {
        const isValid = msg.expiresAt > now && msg.retryCount < msg.maxRetries;
        if (!isValid) cleanedCount++;
        return isValid;
      });

      if (validMessages.length === 0) {
        this.queue.delete(username);
      } else {
        this.queue.set(username, validMessages);
      }
    }

    if (cleanedCount > 0) {
      console.log(`[OfflineQueue] Cleaned up ${cleanedCount} expired/failed messages`);
      this.saveToStorage();
    }
  }

  /**
   * Get queue statistics
   */
  getStats() {
    const totalMessages = Array.from(this.queue.values()).reduce((sum, messages) => sum + messages.length, 0);
    const onlineUsers = Array.from(this.userStatuses.values()).filter(status => status.isOnline).length;
    const totalUsers = this.userStatuses.size;

    return {
      totalQueuedMessages: totalMessages,
      usersWithQueuedMessages: this.queue.size,
      onlineUsers,
      totalUsers
    };
  }

  /**
   * Save queue to localStorage
   */
  private saveToStorage() {
    try {
      const queueData = {
        queue: Array.from(this.queue.entries()),
        userStatuses: Array.from(this.userStatuses.entries()),
        timestamp: Date.now()
      };
      
      const serializedData = JSON.stringify(queueData);
      const dataSizeBytes = new Blob([serializedData]).size;
      const maxSizeBytes = 4.5 * 1024 * 1024; // 4.5MB safe threshold
      
      if (dataSizeBytes > maxSizeBytes) {
        console.warn(`[OfflineQueue] Queue data size (${Math.round(dataSizeBytes / 1024)}KB) exceeds safe localStorage limit. Trimming oldest entries.`);
        
        // Trim oldest messages from each user's queue
        let trimmedEntries = 0;
        for (const [username, messages] of this.queue.entries()) {
          if (messages.length > 10) {
            // Keep only the 10 most recent messages per user
            const trimmed = messages.slice(-10);
            this.queue.set(username, trimmed);
            trimmedEntries += messages.length - trimmed.length;
          }
        }
        
        if (trimmedEntries > 0) {
          console.log(`[OfflineQueue] Trimmed ${trimmedEntries} oldest messages to reduce storage size`);
          // Retry with trimmed data
          const trimmedQueueData = {
            queue: Array.from(this.queue.entries()),
            userStatuses: Array.from(this.userStatuses.entries()),
            timestamp: Date.now()
          };
          const trimmedSerialized = JSON.stringify(trimmedQueueData);
          const trimmedSize = new Blob([trimmedSerialized]).size;
          
          if (trimmedSize > maxSizeBytes) {
            console.warn('[OfflineQueue] Even after trimming, data is too large. Skipping localStorage save.');
            return;
          }
          localStorage.setItem('offlineMessageQueue', trimmedSerialized);
        } else {
          console.warn('[OfflineQueue] Unable to reduce data size sufficiently. Skipping localStorage save.');
          return;
        }
      } else {
        localStorage.setItem('offlineMessageQueue', serializedData);
      }
    } catch (error) {
      console.error('[OfflineQueue] Failed to save to storage:', error);
    }
  }

  /**
   * Load queue from localStorage
   */
  private loadFromStorage() {
    try {
      const stored = localStorage.getItem('offlineMessageQueue');
      if (stored) {
        const queueData = JSON.parse(stored);
        
        // Restore queue
        this.queue = new Map(queueData.queue || []);
        
        // Restore user statuses (but mark all as offline initially)
        const userStatuses = queueData.userStatuses || [];
        for (const [username, status] of userStatuses) {
          this.userStatuses.set(username, {
            ...status,
            isOnline: false // Reset to offline on app restart
          });
        }

        console.log('[OfflineQueue] Loaded from storage:', this.getStats());
      }
    } catch (error) {
      console.error('[OfflineQueue] Failed to load from storage:', error);
    }
  }

  /**
   * Clear all queued messages (for testing/debugging)
   */
  clearQueue() {
    this.queue.clear();
    this.saveToStorage();
    console.log('[OfflineQueue] Queue cleared');
  }
}

// Export singleton instance
export const offlineMessageQueue = new OfflineMessageQueue();
