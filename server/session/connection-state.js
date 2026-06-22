import { withRedisClient } from './redis-client.js';
import { TTL_CONFIG } from '../config/config.js';
import crypto from 'crypto';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { privateLookupId } from '../database/core.js';

const SESSION_ID_BYTES = 32;
const SESSION_ID_REGEX = /^[A-Za-z0-9_-]{43}$/;
const MAX_STATE_JSON_SIZE = 32 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 200;

const SERVER_STARTUP_KEY = 'server_startup_timestamp';
const SESSION_TTL = sanitizeTtl(TTL_CONFIG.SESSION_TTL, 900, 86_400);
const STATE_UPDATE_ALLOWLIST = new Set([
    'hasPassedAccountLogin',
    'hasAuthenticated',
    'hasServerAuth',
    'pendingPassphrase',
    'pqSessionId',
    'connectedAt',
    'lastActivity',
    'scopes',
]);

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

function safeJsonParse(raw) {
    if (typeof raw !== 'string') return null;
    try {
        return JSON.parse(raw);
    } catch {
        return null;
    }
}

function CONNECTION_STATE_KEY(sessionId) {
    return `connection_state:${privateLookupId('connection-state-session-v2', sessionId)}`;
}

function SESSION_RATE_KEY(kind, sessionId) {
    return `session:${kind}:${privateLookupId(`connection-state-${kind}-rate-v2`, sessionId)}`;
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

    static async createSession() {
        const sessionId = generateSessionId();

        const initialState = {
            hasPassedAccountLogin: false,
            hasAuthenticated: false,
            pendingPassphrase: false,
            createdAt: Date.now(),
            lastActivity: Date.now()
        };

        await withRedisClient(async (client) => {
            await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(initialState));
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

    static async updateState(sessionId, updates) {
        if (!isValidSessionId(sessionId)) return false;
        try {
            await enforceRateLimit(SESSION_RATE_KEY('update', sessionId), 500);
            return await withRedisClient(async (client) => {
                const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
                if (!stateJson || stateJson.length > MAX_STATE_JSON_SIZE) {
                    return false;
                }
                const currentState = safeJsonParse(stateJson);
                if (!currentState || typeof currentState !== 'object') {
                    return false;
                }
                const sanitizedUpdates = {};
                for (const [key, value] of Object.entries(updates || {})) {
                    if (STATE_UPDATE_ALLOWLIST.has(key)) {
                        sanitizedUpdates[key] = value;
                    }
                }
                const nextState = {
                    ...currentState,
                    ...sanitizedUpdates,
                    lastActivity: Date.now()
                };
                delete nextState.credentialId;
                delete nextState.userId;

                await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(nextState));
                return true;
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

                await client.del(CONNECTION_STATE_KEY(sessionId));
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
            await enforceRateLimit(SESSION_RATE_KEY('refresh', sessionId), 1000);
            return await withRedisClient(async (client) => {
                const stateJson = await client.get(CONNECTION_STATE_KEY(sessionId));
                if (!stateJson) return false;

                const state = safeJsonParse(stateJson);
                if (!state) return false;
                state.lastActivity = Date.now();

                delete state.credentialId;
                delete state.userId;

                await client.setex(CONNECTION_STATE_KEY(sessionId), SESSION_TTL, JSON.stringify(state));
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
                await client.del(CONNECTION_STATE_KEY(sessionId));
            });
        } catch (error) {
            cryptoLogger.error('Failed to delete session', error, { sessionId });
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

                            stale.push({ key });
                        }

                        if (invalidKeys.length > 0) {
                            try { await client.del(...invalidKeys); cleanedCount += invalidKeys.length; } catch { }
                        }

                        if (stale.length > 0) {
                            const toDelete = stale.map(s => s.key);
                            await client.del(...toDelete);
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
