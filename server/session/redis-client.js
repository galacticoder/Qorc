import Redis from 'ioredis';
import { createPool } from 'generic-pool';
import path from 'node:path';
import { envInt } from '../utils/env.js';
import { readSecureTlsFile } from '../utils/secure-file.js';
import { recordStorageOperation } from '../telemetry/server-telemetry.js';

const REDIS_URL = process.env.REDIS_URL;
let parsedRedisUrl;
try {
    parsedRedisUrl = new URL(REDIS_URL);
} catch {
    throw new Error('REDIS_URL must be a valid rediss:// URL');
}
if (
    parsedRedisUrl.protocol !== 'rediss:' ||
    !parsedRedisUrl.hostname ||
    !parsedRedisUrl.port ||
    parsedRedisUrl.username ||
    parsedRedisUrl.password ||
    parsedRedisUrl.search ||
    parsedRedisUrl.hash
) {
    throw new Error('REDIS_URL must be a credential-free rediss:// URL with an explicit host and port');
}

export function redisConnectionPassword() {
    const password = process.env.REDIS_PASSWORD;
    if (typeof password !== 'string' || password.length < 32 || !/^[A-Za-z0-9_-]+$/.test(password)) {
        throw new Error('REDIS_PASSWORD must contain at least 32 base64url characters');
    }
    return password;
}

const REDIS_QUIET_ERRORS = (process.env.REDIS_QUIET_ERRORS || '').toLowerCase() === 'true';
const REDIS_ERROR_THROTTLE_MS = envInt('REDIS_ERROR_THROTTLE_MS', 5000, 1000, 60000);
const REDIS_CLIENT_HEALTHY = Symbol('redisClientHealthy');
const REDIS_CLIENT_INTENTIONAL_CLOSE = Symbol('redisClientIntentionalClose');
const REDIS_CLIENT_INSTRUMENTED = Symbol('redisClientInstrumented');
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

function wipeCachedTlsOptions() {
    const buffers = [
        ...(Array.isArray(cachedTlsOptions?.ca) ? cachedTlsOptions.ca : []),
        cachedTlsOptions?.cert,
        cachedTlsOptions?.key,
    ];
    for (const buffer of buffers) {
        if (Buffer.isBuffer(buffer)) buffer.fill(0);
    }
    cachedTlsOptions = null;
}

export function buildRedisTlsOptions() {
    const servername = process.env.REDIS_TLS_SERVERNAME;
    const caPath = process.env.REDIS_CA_CERT_PATH;
    const certPath = process.env.REDIS_CLIENT_CERT_PATH;
    const keyPath = process.env.REDIS_CLIENT_KEY_PATH;
    if (!servername || !caPath || !certPath || !keyPath) {
        throw new Error('Redis mutual TLS configuration is incomplete');
    }
    const tlsOptions = { servername, rejectUnauthorized: true };
    try {
        tlsOptions.ca = [readSecureTlsFile(path.resolve(caPath))];
        tlsOptions.cert = readSecureTlsFile(path.resolve(certPath));
        tlsOptions.key = readSecureTlsFile(path.resolve(keyPath), { privateKey: true });
        return tlsOptions;
    } catch (error) {
        for (const buffer of [
            ...(Array.isArray(tlsOptions.ca) ? tlsOptions.ca : []),
            tlsOptions.cert,
            tlsOptions.key,
        ]) {
            if (Buffer.isBuffer(buffer)) buffer.fill(0);
        }
        throw error;
    }
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
    if (!client[REDIS_CLIENT_INSTRUMENTED] && typeof client.sendCommand === 'function') {
        client[REDIS_CLIENT_INSTRUMENTED] = true;
        const originalSendCommand = client.sendCommand;
        client.sendCommand = function instrumentedSendCommand(...arguments_) {
            const started = performance.now();
            let result;
            try {
                result = originalSendCommand.apply(this, arguments_);
            } catch (error) {
                recordStorageOperation('redis', performance.now() - started, true);
                throw error;
            }
            if (!result || typeof result.then !== 'function') {
                recordStorageOperation('redis', performance.now() - started, false);
                return result;
            }
            return result.then(
                (value) => {
                    recordStorageOperation('redis', performance.now() - started, false);
                    return value;
                },
                (error) => {
                    recordStorageOperation('redis', performance.now() - started, true);
                    throw error;
                }
            );
        };
    }
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

const factory = {
    create: async () => {
        if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
            throw new Error('REDIS_URL must use rediss://');
        }

        const client = new Redis(REDIS_URL, {
            ...getRedisOptions(),
            password: redisConnectionPassword()
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

const redisPool = createPool(factory, {
    ...POOL_CONFIG,
    testOnBorrow: true
});

export async function withRedisClient(operation) {
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
        password: redisConnectionPassword()
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

    try {
        await redisPool.drain();
        await redisPool.clear();
        console.log('Redis connection pool cleaned up');
    } catch (error) {
        console.error('Error cleaning up Redis pool', error);
    }
    wipeCachedTlsOptions();
};
