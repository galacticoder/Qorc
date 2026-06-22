import Redis from 'ioredis';
import { createPool } from 'generic-pool';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import fs from 'fs';

const REDIS_URL = process.env.REDIS_URL;
if (!REDIS_URL) {
    throw new Error('REDIS_URL must be explicitly configured via environment variable');
}
const REDIS_CLUSTER_NODES = (process.env.REDIS_CLUSTER_NODES || '').trim();
const USING_CLUSTER = REDIS_CLUSTER_NODES.length > 0;

const REDIS_QUIET_ERRORS = (process.env.REDIS_QUIET_ERRORS || '').toLowerCase() === 'true';
const REDIS_ERROR_THROTTLE_MS = clampNumber(process.env.REDIS_ERROR_THROTTLE_MS, {
    min: 1000,
    max: 60000,
    defaultValue: 5000,
});
let lastRedisErrorMessage = null;
let lastRedisErrorTime = 0;

function logRedisError(context, error) {
    const msg = error?.message || String(error || '');
    const now = Date.now();

    if (REDIS_QUIET_ERRORS) {
        if (lastRedisErrorMessage === msg && (now - lastRedisErrorTime) < REDIS_ERROR_THROTTLE_MS) {
            return;
        }
    }

    lastRedisErrorMessage = msg;
    lastRedisErrorTime = now;
    cryptoLogger.error(context, error);
}

function clampNumber(value, defaults) {
    const parsed = Number.parseInt(value ?? defaults.defaultValue, 10);
    if (!Number.isFinite(parsed)) return defaults.defaultValue;
    return Math.min(Math.max(parsed, defaults.min), defaults.max);
}

const POOL_CONFIG = {
    min: clampNumber(process.env.REDIS_POOL_MIN, { min: 1, max: 100, defaultValue: 4 }),
    max: clampNumber(process.env.REDIS_POOL_MAX, { min: 10, max: 500, defaultValue: 50 }),
    acquireTimeoutMillis: clampNumber(process.env.REDIS_POOL_ACQUIRE_TIMEOUT, { min: 1000, max: 60_000, defaultValue: 15_000 }),
    idleTimeoutMillis: clampNumber(process.env.REDIS_POOL_IDLE_TIMEOUT, { min: 10_000, max: 600_000, defaultValue: 180_000 }),
    evictionRunIntervalMillis: clampNumber(process.env.REDIS_POOL_EVICTION_INTERVAL, { min: 10_000, max: 600_000, defaultValue: 60_000 })
};

let cachedTlsOptions = null;

function getTlsOptions() {
    if (cachedTlsOptions) {
        return cachedTlsOptions;
    }

    const tlsOptions = {
        servername: process.env.REDIS_TLS_SERVERNAME || 'redis',
        rejectUnauthorized: true
    };

    if (process.env.REDIS_CA_CERT_PATH) {
        tlsOptions.ca = [fs.readFileSync(process.env.REDIS_CA_CERT_PATH)];
    }
    if (process.env.REDIS_CLIENT_CERT_PATH) {
        tlsOptions.cert = fs.readFileSync(process.env.REDIS_CLIENT_CERT_PATH);
    }
    if (process.env.REDIS_CLIENT_KEY_PATH) {
        tlsOptions.key = fs.readFileSync(process.env.REDIS_CLIENT_KEY_PATH);
    }

    cachedTlsOptions = tlsOptions;
    return tlsOptions;
}

function getRedisOptions() {
    return {
        maxRetriesPerRequest: 3,
        retryDelayOnFailover: 100,
        enableAutoPipelining: true,
        reconnectOnError: (err) => /READONLY|ECONNRESET|ENOTFOUND|ECONNREFUSED/.test(err.message),
        connectTimeout: clampNumber(process.env.REDIS_CONNECT_TIMEOUT, { min: 1000, max: 60_000, defaultValue: 15_000 }),
        commandTimeout: clampNumber(process.env.REDIS_COMMAND_TIMEOUT, { min: 1000, max: 30_000, defaultValue: 10_000 }),
        socket: {
            keepAlive: clampNumber(process.env.REDIS_KEEPALIVE, { min: 0, max: 300_000, defaultValue: 30_000 }),
            noDelay: true,
            timeout: clampNumber(process.env.REDIS_SOCKET_TIMEOUT, { min: 30_000, max: 600_000, defaultValue: 120_000 })
        },
        tls: getTlsOptions()
    };
}

function parseRedisClusterNodes(redisClusterNodes) {
    if (!redisClusterNodes) return [];
    return redisClusterNodes.split(',').map(s => {
        const [host, portStr] = s.trim().split(':');
        return { host, port: Number.parseInt(portStr || '6379', 10) };
    }).filter(n => n.host);
}

let clusterClient = null;
const duplicateConnectionPool = new Set();
const MAX_DUPLICATE_CONNECTIONS = clampNumber(process.env.REDIS_DUPLICATE_POOL_MAX, { min: 1, max: 20, defaultValue: 5 });

if (USING_CLUSTER) {
    try {
        const nodes = parseRedisClusterNodes(REDIS_CLUSTER_NODES);
        clusterClient = new Redis.Cluster(nodes, {
            redisOptions: {
                ...getRedisOptions(),
                username: process.env.REDIS_USERNAME,
                password: process.env.REDIS_PASSWORD
            }
        });
        clusterClient.on('ready', () => cryptoLogger.info('Redis cluster client ready'));
        clusterClient.on('error', (error) => logRedisError('Redis cluster error', error));
    } catch (e) {
        cryptoLogger.error('Failed to initialize Redis cluster client', e);
    }
}

const factory = {
    create: async () => {
        if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
            throw new Error('REDIS_URL must use rediss:// and TLS; plaintext redis:// is not supported');
        }

        const client = new Redis(REDIS_URL, {
            ...getRedisOptions(),
            username: process.env.REDIS_USERNAME,
            password: process.env.REDIS_PASSWORD
        });

        client.on('error', (error) => logRedisError('Redis client error', error));
        client.on('close', () => cryptoLogger.warn('Redis client closed'));
        client.on('reconnecting', () => cryptoLogger.warn('Redis client reconnecting'));

        await new Promise((resolve, reject) => {
            if (client.status === 'ready') {
                resolve();
                return;
            }

            let timeout;
            let readyHandler;
            let errorHandler;

            const cleanup = () => {
                if (timeout) clearTimeout(timeout);
                if (readyHandler) client.off('ready', readyHandler);
                if (errorHandler) client.off('error', errorHandler);
            };

            readyHandler = () => {
                cleanup();
                resolve();
            };

            errorHandler = (error) => {
                cleanup();
                reject(error);
            };

            timeout = setTimeout(() => {
                cleanup();
                reject(new Error('Redis client connection timeout - neither ready nor error event received within 15 seconds'));
            }, 15000);

            client.once('ready', readyHandler);
            client.once('error', errorHandler);
        });

        return client;
    },
    destroy: async (client) => {
        try {
            await client.quit();
        } catch (error) {
            cryptoLogger.error('Error destroying Redis client', error);
            try {
                client.disconnect();
            } catch (disconnectError) {
                cryptoLogger.error('Error disconnecting Redis client', disconnectError);
            }
        }
    }
};

export const redisPool = USING_CLUSTER ? null : createPool(factory, POOL_CONFIG);

export async function withRedisClient(operation) {
    if (USING_CLUSTER && clusterClient) {
        return operation(clusterClient);
    }

    if (!redisPool) {
        throw new Error('Redis pool not available');
    }

    try {
        const client = await redisPool.acquire();
        try {
            return await operation(client);
        } finally {
            await redisPool.release(client);
        }
    } catch (error) {
        if (error.message && error.message.includes('draining')) {
            throw new Error('Redis pool is shutting down - operation cannot be completed');
        }
        throw error;
    }
}

export async function createSubscriber() {
    if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
        throw new Error('REDIS_URL must use rediss:// and TLS; plaintext redis:// is not allowed');
    }

    const sub = new Redis(REDIS_URL, {
        ...getRedisOptions(),
        username: process.env.REDIS_USERNAME,
        password: process.env.REDIS_PASSWORD
    });

    sub.on('error', (error) => logRedisError('Redis subscriber error', error));
    sub.on('close', () => cryptoLogger.warn('Redis subscriber closed'));

    await new Promise((resolve, reject) => {
        if (sub.status === 'ready') {
            resolve();
            return;
        }

        let timeout;
        let readyHandler;
        let errorHandler;

        const cleanup = () => {
            if (timeout) clearTimeout(timeout);
            if (readyHandler) sub.off('ready', readyHandler);
            if (errorHandler) sub.off('error', errorHandler);
        };

        readyHandler = () => {
            cleanup();
            resolve();
        };

        errorHandler = (error) => {
            cleanup();
            reject(error);
        };

        timeout = setTimeout(() => {
            cleanup();
            reject(new Error('Redis subscriber connection timeout - neither ready nor error event received within 15 seconds'));
        }, 15000);

        sub.once('ready', readyHandler);
        sub.once('error', errorHandler);
    });

    return sub;
}

export async function closeSubscriber(subscriber) {
    if (subscriber) {
        try {
            if (subscriber.status !== 'end' && subscriber.status !== 'close') {
                await subscriber.quit();
            }
        } catch (error) {
            cryptoLogger.error('Error closing subscriber', error);
        }
    }
}

export const cleanup = async () => {
    cryptoLogger.info('Cleaning up Redis resources');

    if (redisPool) {
        try {
            await redisPool.drain();
            await redisPool.clear();
            cryptoLogger.info('Redis connection pool cleaned up');
        } catch (error) {
            cryptoLogger.error('Error cleaning up Redis pool', error);
        }
    }

    if (duplicateConnectionPool.size > 0) {
        cryptoLogger.info('Cleaning up duplicate Redis connections', { count: duplicateConnectionPool.size });
        const cleanupPromises = Array.from(duplicateConnectionPool).map(async (client) => {
            try {
                if (client && client._originalQuit && typeof client._originalQuit === 'function') {
                    await client._originalQuit();
                } else if (client && typeof client.quit === 'function') {
                    await client.quit();
                }
            } catch (err) {
                cryptoLogger.error('Error quitting duplicate connection', err);
            }
        });
        await Promise.all(cleanupPromises);
        duplicateConnectionPool.clear();
    }

    if (clusterClient) {
        try {
            await clusterClient.quit();
        } catch (err) {
            cryptoLogger.error('Error quitting cluster client in cleanup', err);
        }
    }
};
