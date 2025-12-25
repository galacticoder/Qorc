import { withRedisClient } from './presence.js';
import { TTL_CONFIG } from '../config/config.js';
import crypto from 'crypto';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

const SESSION_ID_BYTES = 32;
const SESSION_ID_REGEX = /^[A-Za-z0-9_-]{43}$/;
const USERNAME_REGEX = /^[A-Za-z0-9_-]{3,32}$/;
const MAX_STATE_JSON_SIZE = 32 * 1024;
const MAX_SCAN_ITERATIONS = 1000;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 200;

const SERVER_STARTUP_KEY = 'server_startup_timestamp';
const SESSION_TTL = sanitizeTtl(TTL_CONFIG.SESSION_TTL, 900, 86_400);
const AUTH_STATE_TTL = sanitizeTtl(TTL_CONFIG.AUTH_STATE_TTL, 1800, 86_400);
const PRESENCE_TTL = sanitizeTtl(TTL_CONFIG.PRESENCE_TTL, 300, 3600);

// Track server startup time for stale session detection
const serverStartupTime = Date.now();

function sanitizeTtl(value, fallback, maxValue) {
  const ttl = Number.parseInt(value ?? fallback, 10);
  if (!Number.isFinite(ttl) || ttl <= 0) {
    cryptoLogger.warn('Invalid TTL configuration value detected; using fallback', { fallback });
    return fallback;
  }
  return Math.min(ttl, maxValue);
}

function generateSessionId() {
  return crypto.randomBytes(SESSION_ID_BYTES).toString('base64url');
}

function isValidSessionId(sessionId) {
  return typeof sessionId === 'string' && SESSION_ID_REGEX.test(sessionId);
}

function normalizeUsername(username) {
  if (typeof username !== 'string') return null;
  const trimmed = username.trim();
  return USERNAME_REGEX.test(trimmed) ? trimmed : null;
}

function hashIdentifier(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeJsonParse(raw) {
  if (typeof raw !== 'string') return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function CONNECTION_STATE_KEY(sessionId) {
  return `connection_state:${sessionId}`;
}

function USER_SESSION_KEY(username) {
  return `user_session:${hashIdentifier(username)}`;
}

function AUTH_STATE_KEY(username) {
  return `auth_state:${hashIdentifier(username)}`;
}

/**
 * Enforces rate limits across all cluster servers
 * 
 * @param {string} key - Rate limit key (e.g., "session:update:sessionId")
 * @param {number} limit - Maximum requests allowed in window
 * @param {number} windowMs - Time window in milliseconds
 * @throws {Error} - If rate limit exceeded
 */
async function enforceRateLimit(key, limit = RATE_LIMIT_MAX_REQUESTS, windowMs = RATE_LIMIT_WINDOW_MS) {
  try {
    await withRedisClient(async (client) => {
      const rateLimitKey = `ratelimit:${key}`;
      const count = await client.incr(rateLimitKey);

      // Set expiry on first request (atomic with INCR)
      if (count === 1) {
        await client.pexpire(rateLimitKey, windowMs);
      }

      if (count > limit) {
        throw new Error('Rate limit exceeded');
      }
    });
  } catch (error) {
    if (error.message === 'Rate limit exceeded') {
      throw error;
    }
    cryptoLogger.warn('[CONNECTION-STATE] Rate limit check failed, allowing request', {
      key: key?.slice(0, 20),
      error: error?.message
    });
  }
}

/**
 * Connection state manager
 */
export class ConnectionStateManager {
  static async recordServerStartup() {
    try {
      await withRedisClient(async (client) => {
        await client.setex(SERVER_STARTUP_KEY, SESSION_TTL, serverStartupTime.toString());
        cryptoLogger.info('Recorded server startup time', { timestamp: serverStartupTime });
      });
    } catch (error) {
      cryptoLogger.warn('Failed to record server startup time', { error: error?.message });
    }
  }

  /**
   * Create a new session and return session ID
   */
  static async createSession(username = null) {
    const normalizedUsername = normalizeUsername(username);
    const sessionId = generateSessionId();

    const initialState = {
      username: normalizedUsername,
      hasPassedAccountLogin: false,
      hasAuthenticated: false,
      pendingPassphrase: false,
      createdAt: Date.now(),
      lastActivity: Date.now()
    };

    await withRedisClient(async (client) => {
      await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(initialState));

      if (normalizedUsername) {
        await client.setex(USER_SESSION_KEY(normalizedUsername), SESSION_TTL, sessionId);
      }
    });

    return sessionId;
  }

  /**
   * Get connection state by session ID
   */
  static async getState(sessionId) {
    if (!isValidSessionId(sessionId)) return null;

    try {
      return await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (!stateJson || stateJson.length > MAX_STATE_JSON_SIZE) return null;
        return safeJsonParse(stateJson);
      });
    } catch (error) {
      cryptoLogger.error('Failed to get session state', error, { sessionId });
      return null;
    }
  }

  /**
   * Get authentication state for a user (for reconnection recovery)
   */
  static async getUserAuthState(username) {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) return null;

    try {
      return await withRedisClient(async (client) => {
        const authStateJson = await client.get(AUTH_STATE_KEY(normalizedUsername));
        if (!authStateJson || authStateJson.length > MAX_STATE_JSON_SIZE) return null;
        return safeJsonParse(authStateJson);
      });
    } catch (error) {
      cryptoLogger.error('Failed to get user auth state', error, { username: normalizedUsername });
      return null;
    }
  }

  /**
   * Store authentication state for a user
   */
  static async storeUserAuthState(username, authState) {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) return false;

    try {
      const stateToStore = {
        ...authState,
        storedAt: Date.now(),
        lastActivity: Date.now()
      };

      return await withRedisClient(async (client) => {
        await client.setex(AUTH_STATE_KEY(normalizedUsername), AUTH_STATE_TTL, JSON.stringify(stateToStore));
        return true;
      });
    } catch (error) {
      cryptoLogger.error('Failed to store user auth state', error, { username: normalizedUsername });
      return false;
    }
  }

  /**
   * Clear authentication state for a user (on explicit logout)
   */
  static async clearUserAuthState(username) {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) return;

    try {
      await withRedisClient(async (client) => {
        await client.del(AUTH_STATE_KEY(normalizedUsername));
      });
    } catch (error) {
      cryptoLogger.error('Failed to clear auth state', error, { username: normalizedUsername });
    }
  }

  /**
   * Refresh user auth state TTL (call on activity)
   */
  static async refreshUserAuthState(username) {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) return false;

    try {
      return await withRedisClient(async (client) => {
        const authStateJson = await client.get(AUTH_STATE_KEY(normalizedUsername));
        if (!authStateJson) return false;

        const authState = safeJsonParse(authStateJson);
        if (!authState) return false;
        authState.lastActivity = Date.now();

        await client.setex(AUTH_STATE_KEY(normalizedUsername), AUTH_STATE_TTL, JSON.stringify(authState));
        return true;
      });
    } catch (error) {
      cryptoLogger.error('Failed to refresh auth state', error, { username: normalizedUsername });
      return false;
    }
  }

  /**
   * Update connection state atomically using Lua
   */
  static async updateState(sessionId, updates) {
    if (!isValidSessionId(sessionId)) return false;
    try {
      await enforceRateLimit(`session:update:${sessionId}`, 500);
      return await withRedisClient(async (client) => {
        // Prepare the Lua script
        const luaScript = `
          local sessionKey = KEYS[1]
          local sessionId = ARGV[1]
          local updatesJson = ARGV[2]
          local ttl = tonumber(ARGV[3])

          -- Get current state
          local currentStateJson = redis.call('GET', sessionKey)
          if not currentStateJson then
            return 0 -- Session not found
          end

          local currentState = cjson.decode(currentStateJson)
          local updates = cjson.decode(updatesJson)
          
          -- Merge updates
          for k, v in pairs(updates) do
            currentState[k] = v
          end
          currentState['lastActivity'] = tonumber(ARGV[4]) -- Update lastActivity

          -- Handle username changes
          local oldUsername = currentState['username']
          local newUsername = updates['username']
          
          -- Hashes passed from JS 
          local oldUsernameHash = ARGV[5]
          local newUsernameHash = ARGV[6]

          -- If username is being updated (explicitly present in updates)
          if newUsername ~= nil then
            -- Normalize empty string to nil/null logic
            if newUsername == "" then newUsername = nil end
            
            if newUsername ~= oldUsername then
              -- 1. Release old username if we owned it
              if oldUsername and oldUsername ~= cjson.null then
                local oldUserKey = 'user_session:' .. oldUsernameHash
                local currentOwner = redis.call('GET', oldUserKey)
                if currentOwner == sessionId then
                  redis.call('DEL', oldUserKey)
                end
              end

              -- 2. Claim new username if specified
              if newUsername and newUsername ~= cjson.null then
                local newUserKey = 'user_session:' .. newUsernameHash
                local currentOwner = redis.call('GET', newUserKey)
                local canClaim = false

                if not currentOwner or currentOwner == sessionId then
                  canClaim = true
                else
                  -- Check if the owning session still exists (stale check)
                  local ownerSessionKey = 'connection_state:' .. currentOwner
                  local ownerSessionExists = redis.call('EXISTS', ownerSessionKey)
                  if ownerSessionExists == 0 then
                    canClaim = true -- Steal from stale session
                  end
                end

                if canClaim then
                  redis.call('SETEX', newUserKey, ttl, sessionId)
                else
                  return -1 -- Username taken
                end
              end
            end
          elseif oldUsername and oldUsername ~= cjson.null then
             -- No username change, but refresh the TTL on the user mapping
             local userKey = 'user_session:' .. oldUsernameHash
             local currentOwner = redis.call('GET', userKey)
             if currentOwner == sessionId then
               redis.call('EXPIRE', userKey, ttl)
             end
          end

          -- Save updated state
          local newStateJson = cjson.encode(currentState)
          redis.call('SETEX', sessionKey, ttl, newStateJson)
          return 1
        `;

        const currentStateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        let oldUsernameHash = '';
        if (currentStateJson) {
          const current = safeJsonParse(currentStateJson);
          if (current.username) {
            oldUsernameHash = hashIdentifier(current.username);
          }
        }

        const newUsername = updates.username;
        const newUsernameHash = newUsername ? hashIdentifier(newUsername) : '';

        const result = await client.eval(
          luaScript,
          1,
          CONNECTION_STATE_KEY(sessionId),
          sessionId,
          JSON.stringify(updates),
          SESSION_TTL,
          Date.now(),
          oldUsernameHash,
          newUsernameHash
        );

        if (result === -1) {
          throw new Error('Username already in use by another active session');
        }

        return result === 1;
      });
    } catch (error) {
      if (error?.message === 'Rate limit exceeded') return false;
      cryptoLogger.error('Failed to update connection state', error, { sessionId });
      return false;
    }
  }

  /**
   * Cleanup session state when connection closes
   */
  static async cleanupConnection(sessionId) {
    if (!isValidSessionId(sessionId)) return false;

    try {
      return await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (!stateJson) {
          return false;
        }

        const state = safeJsonParse(stateJson);
        if (!state) {
          await client.del(CONNECTION_STATE_KEY(sessionId));
          return true;
        }
        const pipeline = client.pipeline();
        pipeline.del(CONNECTION_STATE_KEY(sessionId));

        if (state.username) {
          const usernameKey = USER_SESSION_KEY(state.username);
          const luaScript = `
            local key = KEYS[1]
            local sessionId = ARGV[1]
            if redis.call('GET', key) == sessionId then
              redis.call('DEL', key)
              return 1
            end
            return 0
          `;
          pipeline.eval(luaScript, 1, usernameKey, sessionId);
        }

        await pipeline.exec();
        return true;
      });
    } catch (error) {
      if (error.message?.includes('pool is draining') || error.message?.includes('cannot accept work')) {
        cryptoLogger.debug('Connection cleanup skipped - pool shutting down', { sessionId });
      } else {
        cryptoLogger.error('Failed to cleanup connection state', error, { sessionId });
      }
      return false;
    }
  }

  /**
   * Refresh session TTL (call on activity)
   */
  static async refreshSession(sessionId) {
    if (!isValidSessionId(sessionId)) return false;
    try {
      await enforceRateLimit(`session:refresh:${sessionId}`, 1000);
      return await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (!stateJson) return false;

        const state = safeJsonParse(stateJson);
        if (!state) return false;
        state.lastActivity = Date.now();

        const pipeline = client.pipeline();
        pipeline.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(state));

        if (state.username) {
          pipeline.setex(USER_SESSION_KEY(state.username), SESSION_TTL, sessionId);
        }

        await pipeline.exec();
        if (state.username) {
          try {
            const { bumpOnline } = await import('./presence.js');
            await bumpOnline(state.username, PRESENCE_TTL);
          } catch (_e) {
          }
        }

        return true;
      });
    } catch (error) {
      if (error?.message === 'Rate limit exceeded') return false;
      cryptoLogger.error('Failed to refresh session', error, { sessionId });
      return false;
    }
  }

  /**
   * Delete session (on disconnect)
   */
  static async deleteSession(sessionId) {
    if (!isValidSessionId(sessionId)) return;

    try {
      await withRedisClient(async (client) => {
        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        if (stateJson) {
          const state = safeJsonParse(stateJson);
          if (!state) {
            await client.del(CONNECTION_STATE_KEY(sessionId));
            return;
          }

          // Remove user session mapping only if it belongs to this session
          if (state.username) {
            const currentOwner = await client.get(USER_SESSION_KEY(state.username));
            if (currentOwner === sessionId) {
              await client.del(USER_SESSION_KEY(state.username));
            } else if (currentOwner) {
              const ownerSessionExists = await client.exists(CONNECTION_STATE_KEY(currentOwner));
              if (!ownerSessionExists) {
                cryptoLogger.debug('Cleaning up stale username mapping during session deletion', { username: state.username });
                await client.del(USER_SESSION_KEY(state.username));
              }
            }
          }
        }

        await client.del(CONNECTION_STATE_KEY(sessionId));
      });
    } catch (error) {
      cryptoLogger.error('Failed to delete session', error, { sessionId });
    }
  }

  /**
   * Check if user already has an active session (prevent duplicate logins)
   */
  static async getUserActiveSession(username) {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) return null;
    try {
      await enforceRateLimit(`user:getActive:${normalizedUsername}`, 300);
      return await withRedisClient(async (client) => {
        const sessionId = await client.get(USER_SESSION_KEY(normalizedUsername));
        if (!sessionId) return null;

        const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
        return stateJson ? sessionId : null;
      });
    } catch (error) {
      if (error?.message === 'Rate limit exceeded') return null;
      cryptoLogger.error('Failed to get active session for user', error, { username: normalizedUsername });
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
        let iterations = 0;

        let cursor = '0';
        do {
          const result = await client.scan(cursor, 'MATCH', 'connection_state:*', 'COUNT', batchSize);
          cursor = result[0];
          totalSessions += result[1].length;
          iterations++;
        } while (cursor !== '0' && iterations < MAX_SCAN_ITERATIONS);

        cursor = '0';
        iterations = 0;
        do {
          const result = await client.scan(cursor, 'MATCH', 'user_session:*', 'COUNT', batchSize);
          cursor = result[0];
          authenticatedUsers += result[1].length;
          iterations++;
        } while (cursor !== '0' && iterations < MAX_SCAN_ITERATIONS);

        return {
          totalSessions,
          authenticatedUsers,
          timestamp: Date.now()
        };
      });
    } catch (error) {
      cryptoLogger.error('Failed to compute session stats', error);
      return { totalSessions: 0, authenticatedUsers: 0, timestamp: Date.now() };
    }
  }

  /**
   * Cleanup expired sessions (periodic maintenance)
   */
  static async cleanupExpiredSessions() {
    try {
      return await withRedisClient(async (client) => {
        let cleanedCount = 0;
        let cursor = '0';
        const batchSize = 100;

        do {
          const result = await client.scan(cursor, 'MATCH', 'connection_state:*', 'COUNT', batchSize);
          cursor = result[0];
          const keys = result[1];

          if (keys.length > 0) {
            const pipeline = client.pipeline();
            for (const key of keys) {
              pipeline.ttl(key);
            }
            const ttlResults = await pipeline.exec();
            const toDelete = [];
            for (let i = 0; i < keys.length; i += 1) {
              const ttl = ttlResults?.[i]?.[1];
              if (ttl === -1 || ttl === -2) {
                toDelete.push(keys[i]);
              }
            }
            if (toDelete.length > 0) {
              await client.del(...toDelete);
              cleanedCount += toDelete.length;
            }
          }
        } while (cursor !== '0');

        cryptoLogger.info('Expired session cleanup completed', { cleanedCount });
        return cleanedCount;
      });
    } catch (error) {
      cryptoLogger.error('Error during expired session cleanup', error);
      return 0;
    }
  }

  /**
   * Clean up sessions that might be stale from a server restart
   */
  static async cleanupStaleSessionsFromRestart() {
    try {
      return await withRedisClient(async (client) => {
        let cleanedCount = 0;
        let cursor = '0';
        const batchSize = 100;
        const now = Date.now();
        const staleThreshold = 10 * 60 * 1000;

        cryptoLogger.info('Checking for stale sessions from server restart');

        let currentServerStartup = serverStartupTime;
        try {
          const startupTimeStr = await client.get(SERVER_STARTUP_KEY);
          if (startupTimeStr) {
            const parsed = Number.parseInt(startupTimeStr, 10);
            if (Number.isFinite(parsed)) {
              currentServerStartup = parsed;
            }
          }
        } catch (error) {
          cryptoLogger.warn('Could not read server startup time from Redis', { error: error?.message });
        }

        do {
          const result = await client.scan(cursor, 'MATCH', 'connection_state:*', 'COUNT', batchSize);
          cursor = result[0];
          const keys = result[1];

          if (keys.length > 0) {
            const getPipe = client.pipeline();
            for (const key of keys) {
              getPipe.get(key);
            }
            const stateResults = await getPipe.exec();

            const stale = [];
            const invalidKeys = [];

            for (let i = 0; i < keys.length; i += 1) {
              const key = keys[i];
              const stateJson = stateResults?.[i]?.[1];
              if (!stateJson) continue;

              const state = safeJsonParse(stateJson);
              if (!state) {
                invalidKeys.push(key);
                continue;
              }

              const createdAt = Number(state.createdAt || 0);
              const sessionAge = now - createdAt;
              const isStale = sessionAge > staleThreshold || createdAt < currentServerStartup;
              if (!isStale) continue;

              const sessionId = key.replace('connection_state:', '');
              const reason = sessionAge > staleThreshold ? 'age' : 'pre-restart';
              cryptoLogger.debug('Removing stale session', { sessionId, reason, ageSeconds: Math.round(sessionAge / 1000) });
              stale.push({ key, sessionId, username: state.username || null });
            }

            if (invalidKeys.length > 0) {
              try {
                await client.del(...invalidKeys);
                cleanedCount += invalidKeys.length;
              } catch {
              }
            }

            if (stale.length > 0) {
              const ownerPipe = client.pipeline();
              const ownerLookups = [];
              for (const item of stale) {
                if (item.username) {
                  const userKey = USER_SESSION_KEY(item.username);
                  ownerLookups.push({ userKey, sessionId: item.sessionId });
                  ownerPipe.get(userKey);
                }
              }
              const ownerResults = ownerLookups.length > 0 ? await ownerPipe.exec() : [];

              const userKeysToDelete = [];
              for (let i = 0; i < ownerLookups.length; i += 1) {
                const currentOwner = ownerResults?.[i]?.[1];
                if (currentOwner === ownerLookups[i].sessionId) {
                  userKeysToDelete.push(ownerLookups[i].userKey);
                }
              }

              const toDelete = stale.map(s => s.key);
              const delPipe = client.pipeline();
              if (userKeysToDelete.length > 0) {
                delPipe.del(...userKeysToDelete);
              }
              delPipe.del(...toDelete);
              await delPipe.exec();
              cleanedCount += toDelete.length;
            }
          }
        } while (cursor !== '0');

        if (cleanedCount > 0) {
          cryptoLogger.info('Stale session cleanup after restart', { cleanedCount });
        }

        return cleanedCount;
      });
    } catch (error) {
      cryptoLogger.error('Error during stale session cleanup', error);
      return 0;
    }
  }

  /**
   * Force cleanup all sessions for a specific user (for login conflicts)
   */
  static async forceCleanupUserSessions(username) {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) return;
    try {
      await enforceRateLimit(`user:forceCleanup:${normalizedUsername}`, 10, 60_000);
      return await withRedisClient(async (client) => {
        cryptoLogger.info('Force cleaning up user sessions', { username: normalizedUsername });

        // Get the current session ID for this username
        const currentSessionId = await client.get(USER_SESSION_KEY(normalizedUsername));

        if (currentSessionId) {
          const sessionExists = await client.exists(CONNECTION_STATE_KEY(currentSessionId));

          if (sessionExists) {
            await client.del(CONNECTION_STATE_KEY(currentSessionId));
          }

          await client.del(USER_SESSION_KEY(normalizedUsername));
        }

        const { setOffline } = await import('./presence.js');
        await setOffline(normalizedUsername);

        return true;
      });
    } catch (error) {
      if (error?.message === 'Rate limit exceeded') return false;
      cryptoLogger.error('Error during force user session cleanup', error, { username: normalizedUsername });
      return false;
    }
  }

  /**
   * Cleanup stale username mappings (for server startup)
   */
  static async cleanupStaleUsernameMappings() {
    try {
      return await withRedisClient(async (client) => {
        let cleanedCount = 0;
        let cursor = '0';
        const batchSize = 100;

        let iterations = 0;
        do {
          const result = await client.scan(cursor, 'MATCH', 'user_session:*', 'COUNT', batchSize);
          cursor = result[0];
          const keys = result[1];

          if (keys.length > 0) {
            const getPipe = client.pipeline();
            for (const key of keys) {
              getPipe.get(key);
            }
            const getResults = await getPipe.exec();

            const toDelete = [];
            const toCheck = [];

            for (let i = 0; i < keys.length; i += 1) {
              const key = keys[i];
              const sessionId = getResults?.[i]?.[1];
              if (!sessionId) {
                toDelete.push(key);
              } else {
                toCheck.push({ key, sessionId });
              }
            }

            if (toCheck.length > 0) {
              const existsPipe = client.pipeline();
              for (const item of toCheck) {
                existsPipe.exists(CONNECTION_STATE_KEY(item.sessionId));
              }
              const existsResults = await existsPipe.exec();
              for (let i = 0; i < toCheck.length; i += 1) {
                const exists = existsResults?.[i]?.[1];
                if (!exists) {
                  toDelete.push(toCheck[i].key);
                }
              }
            }

            if (toDelete.length > 0) {
              await client.del(...toDelete);
              cleanedCount += toDelete.length;
            }
          }

          iterations++;
        } while (cursor !== '0' && iterations < MAX_SCAN_ITERATIONS);

        if (cleanedCount > 0) {
          cryptoLogger.info('Stale username mapping cleanup', { cleanedCount });
        }
        return cleanedCount;
      });
    } catch (error) {
      cryptoLogger.error('Error during stale username cleanup', error);
      return 0;
    }
  }
}