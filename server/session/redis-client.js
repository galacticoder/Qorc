import Redis from 'ioredis';
import { createPool } from 'generic-pool';
import fs from 'fs';
import { envInt } from '../utils/env.js';

const REDIS_URL = process.env.REDIS_URL;
if (!REDIS_URL) {
    throw new Error('REDIS_URL must be explicitly configured using an environment variable');
}
const REDIS_CLUSTER_NODES = (process.env.REDIS_CLUSTER_NODES || '').trim();
const USING_CLUSTER = REDIS_CLUSTER_NODES.length > 0;

const REDIS_QUIET_ERRORS = (process.env.REDIS_QUIET_ERRORS || '').toLowerCase() === 'true';
const REDIS_ERROR_THROTTLE_MS = envInt('REDIS_ERROR_THROTTLE_MS', 5000, 1000, 60000);
const REDIS_CLIENT_HEALTHY = Symbol('redisClientHealthy');
const REDIS_CLIENT_INTENTIONAL_CLOSE = Symbol('redisClientIntentionalClose');
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
    console.error(context, error);
}

const REDIS_POOL_MAX = envInt('REDIS_POOL_MAX', 50, 10, 500);
const POOL_CONFIG = {
    min: Math.min(
        REDIS_POOL_MAX,
        envInt('REDIS_POOL_MIN', 4, 1, 100)
    ),
    max: REDIS_POOL_MAX,
    acquireTimeoutMillis: envInt('REDIS_POOL_ACQUIRE_TIMEOUT', 15_000, 1000, 60_000),
    idleTimeoutMillis: envInt('REDIS_POOL_IDLE_TIMEOUT', 180_000, 10_000, 600_000),
    evictionRunIntervalMillis: envInt('REDIS_POOL_EVICTION_INTERVAL', 60_000, 10_000, 600_000)
};

let cachedTlsOptions = null;

function wipeCachedTlsPrivateKey() {
    const key = cachedTlsOptions?.key;
    if (Buffer.isBuffer(key)) key.fill(0);
    cachedTlsOptions = null;
}

export function buildRedisTlsOptions() {
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

    return tlsOptions;
}

function getTlsOptions() {
    if (!cachedTlsOptions) cachedTlsOptions = buildRedisTlsOptions();
    return cachedTlsOptions;
}

function getRedisOptions() {
    return {
        maxRetriesPerRequest: 3,
        retryDelayOnFailover: 100,
        enableAutoPipelining: true,
        reconnectOnError: (err) => /READONLY|ECONNRESET|ENOTFOUND|ECONNREFUSED/.test(err.message),
        connectTimeout: envInt('REDIS_CONNECT_TIMEOUT', 15_000, 1000, 60_000),
        commandTimeout: envInt('REDIS_COMMAND_TIMEOUT', 10_000, 1000, 30_000),
        keepAlive: envInt('REDIS_KEEPALIVE', 30_000, 0, 300_000),
        noDelay: true,
        socketTimeout: envInt('REDIS_SOCKET_TIMEOUT', 120_000, 30_000, 600_000),
        tls: getTlsOptions()
    };
}

function attachRedisClientLifecycle(client, label) {
    client[REDIS_CLIENT_HEALTHY] = true;
    client[REDIS_CLIENT_INTENTIONAL_CLOSE] = false;
    client.on('ready', () => {
        if (!client[REDIS_CLIENT_INTENTIONAL_CLOSE]) {
            client[REDIS_CLIENT_HEALTHY] = true;
        }
    });
    client.on('error', (error) => {
        client[REDIS_CLIENT_HEALTHY] = false;
        logRedisError(`${label} error`, error);
    });
    client.on('close', () => {
        client[REDIS_CLIENT_HEALTHY] = false;
        if (!client[REDIS_CLIENT_INTENTIONAL_CLOSE]) {
            console.warn(`${label} connection closed; reconnecting`);
        }
    });
    client.on('reconnecting', () => {
        client[REDIS_CLIENT_HEALTHY] = false;
    });
}

function isRedisClientReusable(client) {
    return Boolean(
        client &&
        client[REDIS_CLIENT_HEALTHY] === true &&
        client[REDIS_CLIENT_INTENTIONAL_CLOSE] !== true &&
        client.status === 'ready'
    );
}

function disconnectRedisClient(client) {
    if (!client) return;
    client[REDIS_CLIENT_INTENTIONAL_CLOSE] = true;
    client[REDIS_CLIENT_HEALTHY] = false;
    client.disconnect(false);
}

function parseRedisClusterNodes(redisClusterNodes) {
    if (!redisClusterNodes) return [];
    return redisClusterNodes.split(',').map(s => {
        const [host, portStr] = s.trim().split(':');
        return { host, port: Number.parseInt(portStr || '6379', 10) };
    }).filter(n => n.host);
}

let clusterClient = null;

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
        clusterClient.on('ready', () => console.log('Redis cluster client ready'));
        clusterClient.on('error', (error) => logRedisError('Redis cluster error', error));
    } catch (e) {
        console.error('Failed to initialize Redis cluster client', e);
    }
}

const factory = {
    create: async () => {
        if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
            throw new Error('REDIS_URL must use rediss://');
        }

        const client = new Redis(REDIS_URL, {
            ...getRedisOptions(),
            username: process.env.REDIS_USERNAME,
            password: process.env.REDIS_PASSWORD
        });

        attachRedisClientLifecycle(client, 'Redis client');

        try {
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
                    reject(new Error('Redis client connection timeout'));
                }, 15000);

                client.once('ready', readyHandler);
                client.once('error', errorHandler);
            });
        } catch (error) {
            disconnectRedisClient(client);
            throw error;
        }

        return client;
    },
    validate: async (client) => isRedisClientReusable(client),
    destroy: async (client) => {
        const graceful = isRedisClientReusable(client);
        client[REDIS_CLIENT_INTENTIONAL_CLOSE] = true;
        client[REDIS_CLIENT_HEALTHY] = false;
        try {
            if (graceful) {
                await client.quit();
            } else {
                client.disconnect(false);
            }
        } catch (error) {
            console.error('Error destroying Redis client', error);
            try {
                client.disconnect(false);
            } catch (disconnectError) {
                console.error('Error disconnecting Redis client', disconnectError);
            }
        }
    }
};

const redisPool = USING_CLUSTER ? null : createPool(factory, {
    ...POOL_CONFIG,
    testOnBorrow: true
});

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
            if (isRedisClientReusable(client)) {
                await redisPool.release(client);
            } else {
                await redisPool.destroy(client);
            }
        }
    } catch (error) {
        if (error.message && error.message.includes('draining')) {
            throw new Error('Redis pool is shutting down ');
        }
        throw error;
    }
}

export async function createSubscriber() {
    if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
        throw new Error('REDIS_URL must use rediss://');
    }

    const sub = new Redis(REDIS_URL, {
        ...getRedisOptions(),
        username: process.env.REDIS_USERNAME,
        password: process.env.REDIS_PASSWORD
    });

    attachRedisClientLifecycle(sub, 'Redis subscriber');

    try {
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
                reject(new Error('Redis subscriber connection timeout'));
            }, 15000);

            sub.once('ready', readyHandler);
            sub.once('error', errorHandler);
        });
    } catch (error) {
        disconnectRedisClient(sub);
        throw error;
    }

    return sub;
}

export async function closeSubscriber(subscriber) {
    if (subscriber) {
        subscriber[REDIS_CLIENT_INTENTIONAL_CLOSE] = true;
        subscriber[REDIS_CLIENT_HEALTHY] = false;
        try {
            if (subscriber.status !== 'end' && subscriber.status !== 'close') {
                await subscriber.quit();
            }
        } catch (error) {
            console.error('Error closing subscriber', error);
            try {
                subscriber.disconnect(false);
            } catch {
            }
        }
    }
}

export const cleanup = async () => {
    console.log('Cleaning up Redis resources');

    if (redisPool) {
        try {
            await redisPool.drain();
            await redisPool.clear();
            console.log('Redis connection pool cleaned up');
        } catch (error) {
            console.error('Error cleaning up Redis pool', error);
        }
    }

    const activeClusterClient = clusterClient;
    clusterClient = null;
    if (activeClusterClient) {
        try {
            await activeClusterClient.quit();
        } catch (err) {
            console.error('Error quitting cluster client in cleanup', err);
        }
    }
    wipeCachedTlsPrivateKey();
};
