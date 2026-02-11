import { withRedisClient } from './redis-client.js';
import { TTL_CONFIG } from '../config/config.js';
import crypto from 'crypto';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

const SESSION_ID_BYTES = 32;
const SESSION_ID_REGEX = /^[A-Za-z0-9_-]{43}$/;
const USER_ID_REGEX = /^[A-Za-z0-9]+$/;
const MAX_STATE_JSON_SIZE = 32 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 200;

const SERVER_STARTUP_KEY = 'server_startup_timestamp';
const SESSION_TTL = sanitizeTtl(TTL_CONFIG.SESSION_TTL, 900, 86_400);
const AUTH_STATE_TTL = sanitizeTtl(TTL_CONFIG.AUTH_STATE_TTL, 1800, 86_400);

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

function normalizeCredentialId(credentialId) {
    if (typeof credentialId !== 'string') return null;
    const trimmed = credentialId.trim();
    return USER_ID_REGEX.test(trimmed) ? trimmed : null;
}

function hashIdentifier(value) {
    const secret = process.env.USER_ID_SALT || crypto.randomBytes(32).toString('hex');
    return crypto.createHash('blake2b512').update(`${secret}:${value}`).digest('hex').slice(0, 64);
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

function USER_SESSION_KEY(credentialId) {
    return `user_session:${hashIdentifier(credentialId)}`;
}

function AUTH_STATE_KEY(credentialId) {
    return `auth_state:${hashIdentifier(credentialId)}`;
}

function anonId(id) {
    if (!id) return '[unknown]';
    return id.slice(0, 8);
}

async function enforceRateLimit(key, limit = RATE_LIMIT_MAX_REQUESTS, windowMs = RATE_LIMIT_WINDOW_MS) {
    try {
        await withRedisClient(async (client) => {
            const rateLimitKey = `ratelimit:${key}`;
            const count = await client.incr(rateLimitKey);

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

    static async createSession(credentialId = null) {
        const normalizedCredentialId = normalizeCredentialId(credentialId);
        const sessionId = generateSessionId();

        const initialState = {
            credentialId: normalizedCredentialId,
            hasPassedAccountLogin: false,
            hasAuthenticated: false,
            pendingPassphrase: false,
            createdAt: Date.now(),
            lastActivity: Date.now()
        };

        await withRedisClient(async (client) => {
            await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(initialState));

            if (normalizedCredentialId) {
                await client.setex(USER_SESSION_KEY(normalizedCredentialId), SESSION_TTL, sessionId);
            }
        });

        return sessionId;
    }

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

    static async getUserAuthState(credentialId) {
        const normalizedCredentialId = normalizeCredentialId(credentialId);
        if (!normalizedCredentialId) return null;

        try {
            return await withRedisClient(async (client) => {
                const authStateJson = await client.get(AUTH_STATE_KEY(normalizedCredentialId));
                if (!authStateJson || authStateJson.length > MAX_STATE_JSON_SIZE) return null;
                return safeJsonParse(authStateJson);
            });
        } catch (error) {
            cryptoLogger.error('Failed to get user auth state', error, { credentialId: anonId(normalizedCredentialId) });
            return null;
        }
    }

    static async storeUserAuthState(credentialId, authState) {
        const normalizedCredentialId = normalizeCredentialId(credentialId);
        if (!normalizedCredentialId) return false;

        try {
            const stateToStore = {
                ...authState,
                storedAt: Date.now(),
                lastActivity: Date.now()
            };

            return await withRedisClient(async (client) => {
                await client.setex(AUTH_STATE_KEY(normalizedCredentialId), AUTH_STATE_TTL, JSON.stringify(stateToStore));
                return true;
            });
        } catch (error) {
            cryptoLogger.error('Failed to store user auth state', error, { credentialId: anonId(normalizedCredentialId) });
            return false;
        }
    }

    static async clearUserAuthState(credentialId) {
        const normalizedCredentialId = normalizeCredentialId(credentialId);
        if (!normalizedCredentialId) return;

        try {
            await withRedisClient(async (client) => {
                await client.del(AUTH_STATE_KEY(normalizedCredentialId));
            });
        } catch (error) {
            cryptoLogger.error('Failed to clear auth state', error, { credentialId: anonId(normalizedCredentialId) });
        }
    }

    static async updateState(sessionId, updates) {
        if (!isValidSessionId(sessionId)) return false;
        try {
            await enforceRateLimit(`session:update:${sessionId}`, 500);
            return await withRedisClient(async (client) => {
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

          -- Handle credentialId changes
          local oldCredentialId = currentState['credentialId']
          local newCredentialId = updates['credentialId']
          
          -- Hashes passed from JS 
          local oldCredentialIdHash = ARGV[5]
          local newCredentialIdHash = ARGV[6]

          -- If credentialId is being updated
          if newCredentialId ~= nil then
            if newCredentialId == "" then newCredentialId = nil end
            
            if newCredentialId ~= oldCredentialId then
              -- 1. Release old credentialId session mapping
              if oldCredentialId and oldCredentialId ~= cjson.null then
                local oldUserKey = 'user_session:' .. oldCredentialIdHash
                local currentOwner = redis.call('GET', oldUserKey)
                if currentOwner == sessionId then
                  redis.call('DEL', oldUserKey)
                end
              end

              -- 2. Claim new credentialId mapping
              if newCredentialId and newCredentialId ~= cjson.null then
                local newUserKey = 'user_session:' .. newCredentialIdHash
                local currentOwner = redis.call('GET', newUserKey)
                local canClaim = false

                if not currentOwner or currentOwner == sessionId then
                  canClaim = true
                else
                  local ownerSessionKey = 'connection_state:' .. currentOwner
                  local ownerSessionExists = redis.call('EXISTS', ownerSessionKey)
                  if ownerSessionExists == 0 then
                    canClaim = true 
                  end
                end

                if canClaim then
                  redis.call('SETEX', newUserKey, ttl, sessionId)
                else
                  return -1 -- Credential ID taken by another active session
                end
              end
            end
          elseif oldCredentialId and oldCredentialId ~= cjson.null then
             local userKey = 'user_session:' .. oldCredentialIdHash
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
                let oldCredentialIdHash = '';
                if (currentStateJson) {
                    const current = safeJsonParse(currentStateJson);
                    if (current.credentialId) {
                        oldCredentialIdHash = hashIdentifier(current.credentialId);
                    }
                }

                const newCredentialId = updates.credentialId;
                const newCredentialIdHash = newCredentialId ? hashIdentifier(newCredentialId) : '';

                const result = await client.eval(
                    luaScript,
                    1,
                    CONNECTION_STATE_KEY(sessionId),
                    sessionId,
                    JSON.stringify(updates),
                    SESSION_TTL,
                    Date.now(),
                    oldCredentialIdHash,
                    newCredentialIdHash
                );

                if (result === -1) {
                    throw new Error('Credential ID already in use by another active session');
                }

                return result === 1;
            });
        } catch (error) {
            if (error?.message === 'Rate limit exceeded') return false;
            cryptoLogger.error('Failed to update connection state', error, { sessionId });
            return false;
        }
    }

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

                if (state.credentialId) {
                    const userKey = USER_SESSION_KEY(state.credentialId);
                    const luaScript = `
            local key = KEYS[1]
            local sessionId = ARGV[1]
            if redis.call('GET', key) == sessionId then
              redis.call('DEL', key)
              return 1
            end
            return 0
          `;
                    pipeline.eval(luaScript, 1, userKey, sessionId);
                }

                await pipeline.exec();
                return true;
            });
        } catch (error) {
            if (error.message?.includes('pool is draining')) {
            } else {
                cryptoLogger.error('Failed to cleanup connection state', error, { sessionId });
            }
            return false;
        }
    }

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

                if (state.credentialId) {
                    pipeline.setex(USER_SESSION_KEY(state.credentialId), SESSION_TTL, sessionId);
                }

                await pipeline.exec();
                return true;
            });
        } catch (error) {
            if (error?.message === 'Rate limit exceeded') return false;
            cryptoLogger.error('Failed to refresh session', error, { sessionId });
            return false;
        }
    }

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

                    if (state.credentialId) {
                        const currentOwner = await client.get(USER_SESSION_KEY(state.credentialId));
                        if (currentOwner === sessionId) {
                            await client.del(USER_SESSION_KEY(state.credentialId));
                        } else if (currentOwner) {
                            const ownerSessionExists = await client.exists(CONNECTION_STATE_KEY(currentOwner));
                            if (!ownerSessionExists) {
                                await client.del(USER_SESSION_KEY(state.credentialId));
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

    static async getUserActiveSession(credentialId) {
        const normalizedCredentialId = normalizeCredentialId(credentialId);
        if (!normalizedCredentialId) return null;
        try {
            await enforceRateLimit(`user:getActive:${normalizedCredentialId}`, 300);
            return await withRedisClient(async (client) => {
                const sessionId = await client.get(USER_SESSION_KEY(normalizedCredentialId));
                if (!sessionId) return null;

                const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
                return stateJson ? sessionId : null;
            });
        } catch (error) {
            if (error?.message === 'Rate limit exceeded') return null;
            cryptoLogger.error('Failed to get active session for user', error, { credentialId: anonId(normalizedCredentialId) });
            return null;
        }
    }

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

                return cleanedCount;
            });
        } catch (error) {
            cryptoLogger.error('Error during expired session cleanup', error);
            return 0;
        }
    }

    static async cleanupStaleSessionsFromRestart() {
        try {
            return await withRedisClient(async (client) => {
                let cleanedCount = 0;
                let cursor = '0';
                const batchSize = 100;
                const now = Date.now();
                const staleThreshold = 10 * 60 * 1000;

                let currentServerStartup = serverStartupTime;
                try {
                    const startupTimeStr = await client.get(SERVER_STARTUP_KEY);
                    if (startupTimeStr) {
                        const parsed = Number.parseInt(startupTimeStr, 10);
                        if (Number.isFinite(parsed)) {
                            currentServerStartup = parsed;
                        }
                    }
                } catch { }

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

                            stale.push({ key, sessionId: key.replace('connection_state:', ''), credentialId: state.credentialId || null });
                        }

                        if (invalidKeys.length > 0) {
                            try { await client.del(...invalidKeys); cleanedCount += invalidKeys.length; } catch { }
                        }

                        if (stale.length > 0) {
                            const ownerPipe = client.pipeline();
                            const ownerLookups = [];
                            for (const item of stale) {
                                if (item.credentialId) {
                                    const userKey = USER_SESSION_KEY(item.credentialId);
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

                return cleanedCount;
            });
        } catch (error) {
            cryptoLogger.error('Error during stale session cleanup', error);
            return 0;
        }
    }
}
