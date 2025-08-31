import { withRedisClient } from './presence.js';
import crypto from 'crypto';

// Redis key patterns for connection state
const CONNECTION_STATE_KEY = (sessionId) => `connection_state:${sessionId}`;
const USER_SESSION_KEY = (username) => `user_session:${username}`;
const SESSION_TTL = 300; // 5 minutes TTL for connection state

/**
 * Redis-based connection state manager for millions of concurrent users
 * Replaces in-memory ws.clientState to prevent memory exhaustion
 */
export class ConnectionStateManager {
  /**
   * Create a new session and return session ID
   */
  static async createSession(username = null) {
    const sessionId = `sess_${Date.now()}_${crypto.randomUUID().replace(/-/g, '')}`;
    
    const initialState = {
      username: username,
      hasPassedAccountLogin: false,
      hasAuthenticated: false,
      pendingPassphrase: false,
      createdAt: Date.now(),
      lastActivity: Date.now()
    };

    await withRedisClient(async (client) => {
      await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(initialState));
      
      // If username provided, link user to session for duplicate login prevention
      if (username) {
        await client.setex(USER_SESSION_KEY(username), SESSION_TTL, sessionId);
      }
    });

    return sessionId;
  }

  /**
   * Get connection state by session ID
   */
  static async getState(sessionId) {
    if (!sessionId) return null;

    try {
      return await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        return stateJson ? JSON.parse(stateJson) : null;
      });
    } catch (error) {
      console.error(`[CONNECTION-STATE] Error getting state for session ${sessionId}:`, error);
      return null;
    }
  }

  /**
   * Update connection state
   */
  static async updateState(sessionId, updates) {
    if (!sessionId) return false;

    try {
      return await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (!stateJson) return false;

        const currentState = JSON.parse(stateJson);
        const newState = {
          ...currentState,
          ...updates,
          lastActivity: Date.now()
        };

        // Handle username changes with race condition protection
        if ('username' in updates && updates.username !== currentState.username) {
          const oldUsername = currentState.username;
          const newUsername = updates.username;

          // Case 1: Clearing username (setting to null/empty)
          if (!newUsername && oldUsername) {
            // Only remove old mapping if it belongs to this session
            const currentOwner = await client.get(USER_SESSION_KEY(oldUsername));
            if (currentOwner === sessionId) {
              await client.del(USER_SESSION_KEY(oldUsername));
            }
          }
          // Case 2: Setting/changing to a new username
          else if (newUsername) {
            // Check if new username is available or owned by this session
            const currentOwner = await client.get(USER_SESSION_KEY(newUsername));
            let canClaimUsername = false;
            
            if (!currentOwner || currentOwner === sessionId) {
              canClaimUsername = true;
            } else {
              // Check if the owning session still exists (cleanup stale mappings)
              const ownerSessionExists = await client.exists(CONNECTION_STATE_KEY(currentOwner));
              if (!ownerSessionExists) {
                console.log(`[CONNECTION-STATE] Cleaning up stale username mapping for ${newUsername} (owner session ${currentOwner} no longer exists)`);
                await client.del(USER_SESSION_KEY(newUsername));
                canClaimUsername = true;
              }
            }
            
            if (canClaimUsername) {
              // Safe to claim the new username
              await client.setex(USER_SESSION_KEY(newUsername), SESSION_TTL, sessionId);
              
              // Remove old username mapping if it belongs to this session
              if (oldUsername && oldUsername !== newUsername) {
                const oldOwner = await client.get(USER_SESSION_KEY(oldUsername));
                if (oldOwner === sessionId) {
                  await client.del(USER_SESSION_KEY(oldUsername));
                }
              }
            } else {
              // Username is taken by another active session - reject the change
              throw new Error(`Username '${newUsername}' is already taken by another active session`);
            }
          }
        }
        // Case 3: No username change but refresh TTL if username exists
        else if (currentState.username && !('username' in updates)) {
          // Refresh TTL for existing username mapping if we own it
          const currentOwner = await client.get(USER_SESSION_KEY(currentState.username));
          if (currentOwner === sessionId) {
            await client.setex(USER_SESSION_KEY(currentState.username), SESSION_TTL, sessionId);
          }
        }

        await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(newState));
        return true;
      });
    } catch (error) {
      console.error(`[CONNECTION-STATE] Error updating state for session ${sessionId}:`, error);
      return false;
    }
  }

  /**
   * Refresh session TTL (call on activity)
   */
  static async refreshSession(sessionId) {
    if (!sessionId) return false;

    try {
      return await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (!stateJson) return false;

        const state = JSON.parse(stateJson);
        state.lastActivity = Date.now();

        await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(state));
        
        // Also refresh user session mapping if exists
        if (state.username) {
          await client.setex(USER_SESSION_KEY(state.username), SESSION_TTL, sessionId);
        }

        return true;
      });
    } catch (error) {
      console.error(`[CONNECTION-STATE] Error refreshing session ${sessionId}:`, error);
      return false;
    }
  }

  /**
   * Delete session (on disconnect)
   */
  static async deleteSession(sessionId) {
    if (!sessionId) return;

    try {
      await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (stateJson) {
          const state = JSON.parse(stateJson);
          
          // Remove user session mapping only if it belongs to this session
          if (state.username) {
            const currentOwner = await client.get(USER_SESSION_KEY(state.username));
            if (currentOwner === sessionId) {
              await client.del(USER_SESSION_KEY(state.username));
            } else if (currentOwner) {
              // Check if the owning session still exists (cleanup stale mappings)
              const ownerSessionExists = await client.exists(CONNECTION_STATE_KEY(currentOwner));
              if (!ownerSessionExists) {
                console.log(`[CONNECTION-STATE] Cleaning up stale username mapping for ${state.username} during session deletion`);
                await client.del(USER_SESSION_KEY(state.username));
              }
            }
          }
        }
        
        // Remove session state
        await client.del(CONNECTION_STATE_KEY(sessionId));
      });
    } catch (error) {
      console.error(`[CONNECTION-STATE] Error deleting session ${sessionId}:`, error);
    }
  }

  /**
   * Check if user already has an active session (prevent duplicate logins)
   */
  static async getUserActiveSession(username) {
    if (!username) return null;

    try {
      return await withRedisClient(async (client) => {
        const sessionId = await client.get(USER_SESSION_KEY(username));
        if (!sessionId) return null;

        // Verify session still exists
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        return stateJson ? sessionId : null;
      });
    } catch (error) {
      console.error(`[CONNECTION-STATE] Error checking user session for ${username}:`, error);
      return null;
    }
  }

  /**
   * Get session statistics (for monitoring)
   */
  static async getSessionStats() {
    try {
      return await withRedisClient(async (client) => {
        let totalSessions = 0;
        let authenticatedUsers = 0;
        const batchSize = 100;
        
        // Count connection_state keys using SCAN
        let cursor = '0';
        do {
          const result = await client.scan(cursor, 'MATCH', 'connection_state:*', 'COUNT', batchSize);
          cursor = result[0];
          totalSessions += result[1].length;
        } while (cursor !== '0');
        
        // Count user_session keys using SCAN
        cursor = '0';
        do {
          const result = await client.scan(cursor, 'MATCH', 'user_session:*', 'COUNT', batchSize);
          cursor = result[0];
          authenticatedUsers += result[1].length;
        } while (cursor !== '0');
        
        return {
          totalSessions,
          authenticatedUsers,
          timestamp: Date.now()
        };
      });
    } catch (error) {
      console.error('[CONNECTION-STATE] Error getting session stats:', error);
      return { totalSessions: 0, authenticatedUsers: 0, timestamp: Date.now() };
    }
  }

  /**
   * Cleanup expired sessions (periodic maintenance)
   */
  static async cleanupExpiredSessions() {
    try {
      return await withRedisClient(async (client) => {
        const sessionKeys = await client.keys('connection_state:*');
        let cleanedCount = 0;

        for (const key of sessionKeys) {
          const ttl = await client.ttl(key);
          if (ttl === -1 || ttl === -2) { // No TTL or expired
            await client.del(key);
            cleanedCount++;
          }
        }

        console.log(`[CONNECTION-STATE] Cleaned up ${cleanedCount} expired sessions`);
        return cleanedCount;
      });
    } catch (error) {
      console.error('[CONNECTION-STATE] Error during session cleanup:', error);
      return 0;
    }
  }

  /**
   * Cleanup stale username mappings (for server startup)
   */
  static async cleanupStaleUsernameMappings() {
    try {
      return await withRedisClient(async (client) => {
        const userSessionKeys = await client.keys('user_session:*');
        let cleanedCount = 0;

        for (const key of userSessionKeys) {
          const sessionId = await client.get(key);
          if (sessionId) {
            // Check if the session still exists
            const sessionExists = await client.exists(CONNECTION_STATE_KEY(sessionId));
            if (!sessionExists) {
              // Session doesn't exist, remove the stale username mapping
              await client.del(key);
              cleanedCount++;
              const username = key.replace('user_session:', '');
              console.log(`[CONNECTION-STATE] Cleaned up stale username mapping for ${username} (session ${sessionId} no longer exists)`);
            }
          } else {
            // Empty mapping, remove it
            await client.del(key);
            cleanedCount++;
          }
        }

        console.log(`[CONNECTION-STATE] Cleaned up ${cleanedCount} stale username mappings`);
        return cleanedCount;
      });
    } catch (error) {
      console.error('[CONNECTION-STATE] Error during stale username cleanup:', error);
      return 0;
    }
  }
}
