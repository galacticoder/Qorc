import { setOnline, setOffline, createSubscriber, publishToUser, withRedisClient, isOnline, clearAllPresenceData } from './presence.js';
import crypto from 'node:crypto';
import { ConnectionStateManager } from './connection-state.js';

// Presence service
export class PresenceService {
  constructor({ logger = console } = {}) {
    this.logger = logger;
    this.patternSubscriber = null;
  }

  normalizeUsername(username) {
    if (typeof username !== 'string') return null;
    const trimmed = username.trim();
    const USERNAME_REGEX = /^[A-Za-z0-9_-]{3,64}$/;
    return USERNAME_REGEX.test(trimmed) ? trimmed : null;
  }

  hashUsername(username) {
    const normalized = this.normalizeUsername(username);
    if (!normalized) throw new Error('Invalid username');
    return crypto.createHash('sha256').update(normalized).digest('hex');
  }

  onlineSessionsKey(username) {
    return `online:sessions:${this.hashUsername(username)}`;
  }

  // Set user as online with session tracking
  async setUserOnline(username, sessionId, _metadata = {}) {
    if (!this.normalizeUsername(username)) {
      throw new Error('Invalid username');
    }
    if (!sessionId || typeof sessionId !== 'string' || sessionId.length < 10 || sessionId.length > 128) {
      throw new Error('Invalid session identifier');
    }

    try {
      await withRedisClient(async (client) => {
        const key = this.onlineSessionsKey(username);
        await client.sadd(key, sessionId);
        await client.expire(key, 300);
      });
      await setOnline(username);
      this.logger.log('[PRESENCE] User set online:', {
        username: this.anonymize(username),
        sessionId: this.anonymize(sessionId)
      });
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to set user online:', {
        username: this.anonymize(username),
        error: error.message
      });
      throw error;
    }
  }

  // Set user as offline
  async setUserOffline(username, sessionId) {
    if (!this.normalizeUsername(username)) {
      throw new Error('Invalid username');
    }
    if (!sessionId || typeof sessionId !== 'string' || sessionId.length < 10 || sessionId.length > 128) {
      throw new Error('Invalid session identifier');
    }

    try {
      let remaining = 0;
      let deliveryCount = 0;
      let shouldSetOffline = false;
      await withRedisClient(async (client) => {
        const key = this.onlineSessionsKey(username);
        await client.srem(key, sessionId);
        remaining = await client.scard(key);

        if (remaining === 0) {
          await client.del(key);
          try {
            deliveryCount = await client.hlen(`ws:delivery:${username}`);
          } catch {
            deliveryCount = 0;
          }
          if (!deliveryCount) {
            try {
              await client.del(`ws:delivery:${username}`);
            } catch {
            }
            shouldSetOffline = true;
          }
        } else {
          await client.expire(key, 300);
        }
      });

      if (shouldSetOffline) {
        await setOffline(username);
        this.logger.log('[PRESENCE] User set offline:', {
          username: this.anonymize(username),
          sessionId: this.anonymize(sessionId),
          remainingSessions: 0
        });
      } else if (remaining === 0 && deliveryCount > 0) {
        await setOnline(username);
        this.logger.log('[PRESENCE] Session removed, keeping online for pending deliveries:', {
          username: this.anonymize(username),
          sessionId: this.anonymize(sessionId),
          pendingDeliveries: deliveryCount
        });
      } else {
        this.logger.log('[PRESENCE] Session removed:', {
          username: this.anonymize(username),
          sessionId: this.anonymize(sessionId),
          remainingSessions: remaining
        });
      }
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to set user offline:', {
        username: this.anonymize(username),
        error: error.message
      });
      throw error;
    }
  }

  // Check if user is online
  async isUserOnline(username) {
    if (!this.normalizeUsername(username)) {
      throw new Error('Invalid username');
    }

    try {
      const online = await isOnline(username);
      this.logger.debug('[PRESENCE] User online check:', {
        username: this.anonymize(username),
        online
      });
      return online;
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to check user online status:', {
        username: this.anonymize(username),
        error: error.message
      });
      throw error;
    }
  }

  // Publish message to user using Redis pub-sub
  async publishToUser(username, message, metadata = {}) {
    if (!this.normalizeUsername(username)) {
      throw new Error('Invalid username');
    }
    if (!message || typeof message !== 'string' || message.length === 0 || message.length > 1048576) {
      throw new Error('Invalid message: must be string between 1 and 1MB');
    }

    try {
      const receivers = await publishToUser(username, message);
      this.logger.log('[PRESENCE] Message published to user:', {
        username: this.anonymize(username),
        messageLength: message.length,
        receivers,
        ...metadata
      });
      return receivers;
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to publish message to user:', {
        username: this.anonymize(username),
        error: error.message
      });
      throw error;
    }
  }

  // Create Redis pattern subscriber for cross-instance message delivery
  async createPatternSubscriber(messageHandler, pattern = 'deliver:*') {
    if (typeof messageHandler !== 'function') {
      throw new Error('Message handler must be a function');
    }
    if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > 128) {
      throw new Error('Invalid pattern');
    }

    try {
      this.patternSubscriber = await createSubscriber();
      await this.patternSubscriber.psubscribe(pattern);

      this.patternSubscriber.on('pmessage', async (matchedPattern, channel, message) => {
        try {
          if (!channel || typeof channel !== 'string' || !channel.startsWith('deliver:')) {
            this.logger.warn('[PRESENCE] Invalid channel format received', { channel: this.anonymize(channel) });
            return;
          }

          if (!message || typeof message !== 'string' || message.length === 0 || message.length > 1048576) {
            this.logger.warn('[PRESENCE] Invalid message received', { channel: this.anonymize(channel) });
            return;
          }

          await messageHandler({
            pattern: matchedPattern,
            channel,
            username: null,
            message,
            timestamp: Date.now()
          });
        } catch (error) {
          this.logger.error('[PRESENCE] Error in pattern message handler:', {
            error: error.message,
            channel: this.anonymize(channel)
          });
        }
      });

      this.logger.log('[PRESENCE] Pattern subscriber created:', { pattern });
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to create pattern subscriber:', {
        error: error.message,
        pattern
      });
      throw error;
    }
  }

  // Refresh user session to keep them online
  async refreshUserSession(sessionId) {
    if (!sessionId || typeof sessionId !== 'string' || sessionId.length < 10 || sessionId.length > 128) {
      throw new Error('Invalid session identifier');
    }

    try {
      await ConnectionStateManager.refreshSession(sessionId);
      this.logger.debug('[PRESENCE] User session refreshed:', {
        sessionId: this.anonymize(sessionId)
      });
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to refresh user session:', {
        sessionId: this.anonymize(sessionId),
        error: error.message
      });
      throw error;
    }
  }

  // Get user authentication state
  async getUserAuthState(username) {
    if (!this.normalizeUsername(username)) {
      throw new Error('Invalid username');
    }

    try {
      const authState = await ConnectionStateManager.getUserAuthState(username);
      this.logger.debug('[PRESENCE] User auth state retrieved:', {
        username: this.anonymize(username),
        hasAuth: !!authState?.hasAuthenticated
      });
      return authState;
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to get user auth state:', {
        username: this.anonymize(username),
        error: error.message
      });
      return null;
    }
  }

  // Clean up all presence data
  async clearAllPresenceData() {
    try {
      const clearedCount = await clearAllPresenceData();
      this.logger.log('[PRESENCE] All presence data cleared:', {
        clearedCount
      });
      return clearedCount;
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to clear all presence data:', {
        error: error.message
      });
      throw error;
    }
  }

  // Clean up stale session data
  async cleanupStaleSessions() {
    try {
      const results = {
        expiredSessions: 0,
        staleMappings: 0,
        staleFromRestart: 0
      };

      results.expiredSessions = await ConnectionStateManager.cleanupExpiredSessions();
      results.staleMappings = await ConnectionStateManager.cleanupStaleUsernameMappings();
      results.staleFromRestart = await ConnectionStateManager.cleanupStaleSessionsFromRestart();

      this.logger.log('[PRESENCE] Stale sessions cleaned up:', results);
      return results;
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to cleanup stale sessions:', {
        error: error.message
      });
      throw error;
    }
  }

  // Record server startup time for stale session detection
  async recordServerStartup() {
    try {
      await ConnectionStateManager.recordServerStartup();
      this.logger.log('[PRESENCE] Server startup time recorded');
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to record server startup:', {
        error: error.message
      });
    }
  }

  // Close pattern subscriber and cleanup resources
  async close() {
    try {
      if (this.patternSubscriber) {
        await this.patternSubscriber.quit();
        this.patternSubscriber = null;
        this.logger.log('[PRESENCE] Pattern subscriber closed');
      }
    } catch (error) {
      this.logger.error('[PRESENCE] Failed to close pattern subscriber:', {
        error: error.message
      });
    }
  }

  // Anonymize identifier for logging
  anonymize(identifier) {
    if (!identifier || typeof identifier !== 'string') return 'unknown';
    if (identifier.length <= 4) return '****';
    return identifier.slice(0, 2) + '****' + identifier.slice(-2);
  }
}

export const presenceService = new PresenceService();
