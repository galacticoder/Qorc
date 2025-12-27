import Redis from 'ioredis';
import { createPool } from 'generic-pool';
import crypto from 'crypto';
import { TTL_CONFIG } from '../config/config.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import fs from 'fs';

const REDIS_URL = process.env.REDIS_URL;
if (!REDIS_URL) {
  throw new Error('REDIS_URL must be explicitly configured via environment variable');
}
const REDIS_CLUSTER_NODES = (process.env.REDIS_CLUSTER_NODES || '').trim();
const USING_CLUSTER = REDIS_CLUSTER_NODES.length > 0;

const REDIS_QUIET_ERRORS = (process.env.PRESENCE_REDIS_QUIET_ERRORS || '').toLowerCase() === 'true';
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
    console.log('[PRESENCE] Reading CA cert from:', process.env.REDIS_CA_CERT_PATH);
    tlsOptions.ca = [fs.readFileSync(process.env.REDIS_CA_CERT_PATH)];
  }
  if (process.env.REDIS_CLIENT_CERT_PATH) {
    console.log('[PRESENCE] Reading client cert from:', process.env.REDIS_CLIENT_CERT_PATH);
    tlsOptions.cert = fs.readFileSync(process.env.REDIS_CLIENT_CERT_PATH);
  }
  if (process.env.REDIS_CLIENT_KEY_PATH) {
    console.log('[PRESENCE] Reading client key from:', process.env.REDIS_CLIENT_KEY_PATH);
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
    clusterClient.on('connect', () => cryptoLogger.debug('Redis cluster client connected'));
    clusterClient.on('ready', () => cryptoLogger.info('Redis cluster client ready'));
    clusterClient.on('error', (error) => logRedisError('Redis cluster error', error));
  } catch (e) {
    cryptoLogger.error('Failed to initialize Redis cluster client', e);
  }
}

// Factory for creating Redis clients
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
    client.on('connect', () => cryptoLogger.debug('Redis pool client connected'));
    client.on('ready', () => cryptoLogger.debug('Redis pool client ready'));
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

const redis = {
  set: (...args) => withRedisClient(client => client.set(...args)),
  get: (...args) => withRedisClient(client => client.get(...args)),
  del: (...args) => withRedisClient(client => client.del(...args)),
  exists: (...args) => withRedisClient(client => client.exists(...args)),
  expire: (...args) => withRedisClient(client => client.expire(...args)),
  incr: (...args) => withRedisClient(client => client.incr(...args)),
  decr: (...args) => withRedisClient(client => client.decr(...args)),
  publish: (...args) => withRedisClient(client => client.publish(...args)),
  eval: (...args) => withRedisClient(client => client.eval(...args)),
  duplicate: async () => {
    if (USING_CLUSTER && clusterClient) {
      const iterator = duplicateConnectionPool.values();
      let result = iterator.next();
      while (!result.done) {
        const cachedClient = result.value;
        duplicateConnectionPool.delete(cachedClient);

        if (cachedClient && cachedClient.status === 'ready') {
          try {
            await cachedClient.ping();
            return cachedClient;
          } catch (_error) {
            try {
              if (cachedClient._originalQuit) {
                await cachedClient._originalQuit();
              } else {
                await cachedClient.quit();
              }
            } catch (quitError) {
              cryptoLogger.debug('[PRESENCE] Error disposing unhealthy cached client:', { error: quitError.message });
            }
          }
        } else {
          try {
            if (cachedClient && cachedClient._originalQuit) {
              await cachedClient._originalQuit();
            } else if (cachedClient) {
              await cachedClient.quit();
            }
          } catch (quitError) {
            cryptoLogger.debug('[PRESENCE] Error disposing invalid cached client:', { error: quitError.message });
          }
        }
      }

      const nodes = parseRedisClusterNodes(REDIS_CLUSTER_NODES);
      const newClient = new Redis.Cluster(nodes, { redisOptions: getRedisOptions() });

      const originalQuit = newClient.quit.bind(newClient);
      newClient._originalQuit = originalQuit;

      const removeFromPool = () => {
        duplicateConnectionPool.delete(newClient);
      };

      newClient.on('error', removeFromPool);
      newClient.on('close', removeFromPool);
      newClient.on('end', removeFromPool);

      newClient.quit = async () => {
        newClient.removeListener('error', removeFromPool);
        newClient.removeListener('close', removeFromPool);
        newClient.removeListener('end', removeFromPool);

        if (newClient.status === 'ready' && duplicateConnectionPool.size < MAX_DUPLICATE_CONNECTIONS) {
          try {
            await newClient.ping();
            duplicateConnectionPool.add(newClient);
            return Promise.resolve();
          } catch (_error) {
            return originalQuit();
          }
        } else {
          return originalQuit();
        }
      };

      return newClient;
    }

    if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
      throw new Error('REDIS_URL must use rediss:// and TLS; plaintext redis:// is not allowed');
    }
    return new Redis(REDIS_URL, getRedisOptions());
  }
};
export async function createSubscriber() {
  if (typeof REDIS_URL !== 'string' || !REDIS_URL.startsWith('rediss://')) {
    throw new Error('REDIS_URL must use rediss:// and TLS; plaintext redis:// is not allowed');
  }

  // Dedicated subscriber connection (not pooled)
  const sub = new Redis(REDIS_URL, {
    ...getRedisOptions(),
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD
  });

  sub.on('error', (error) => logRedisError('Redis subscriber error', error));
  sub.on('ready', () => cryptoLogger.debug('Redis subscriber ready for user notifications'));
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

// Global cleanup on process termination
export const cleanup = async () => {
  cryptoLogger.info('Cleaning up Redis presence resources');

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
      cryptoLogger.error('Error quitting cluster client in presence cleanup', err);
    }
  }
};

const USERNAME_REGEX = /^[A-Za-z0-9_-]{3,32}$/;
const MAX_SCAN_ITERATIONS = 1000;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_ACTIONS = 200;

function normalizeUsername(username) {
  if (typeof username !== 'string') return null;
  const trimmed = username.trim();
  return USERNAME_REGEX.test(trimmed) ? trimmed : null;
}

function hashUsername(username) {
  const normalized = normalizeUsername(username);
  if (!normalized) {
    throw new Error('Invalid username');
  }
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

// Enforces rate limits across all cluster servers
async function enforceRateLimit(key) {
  try {
    await withRedisClient(async (client) => {
      const rateLimitKey = `ratelimit:${key}`;
      const count = await client.incr(rateLimitKey);

      if (count === 1) {
        await client.pexpire(rateLimitKey, RATE_LIMIT_WINDOW_MS);
      }

      if (count > RATE_LIMIT_MAX_ACTIONS) {
        throw new Error('Rate limit exceeded');
      }
    });
  } catch (error) {
    if (error.message === 'Rate limit exceeded') {
      throw error;
    }
    cryptoLogger.warn('[PRESENCE] Rate limit check failed, allowing request', {
      key: key?.slice(0, 20),
      error: error?.message
    });
  }
}

const ONLINE_KEY = (u) => `online:${hashUsername(u)}`;
const DELIVER_CH = (u) => `deliver:${hashUsername(u)}`;

export async function setOnline(username, ttlSeconds = TTL_CONFIG.PRESENCE_TTL) {
  try {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) {
      throw new Error('Invalid username');
    }
    enforceRateLimit(`presence:set:${normalizedUsername}`);
    const safeTtl = clampNumber(ttlSeconds, { min: 10, max: 86_400, defaultValue: TTL_CONFIG.PRESENCE_TTL || 300 });
    await redis.set(ONLINE_KEY(normalizedUsername), '1', 'EX', safeTtl);
    cryptoLogger.debug('User presence set online', { username: normalizedUsername });
  } catch (error) {
    cryptoLogger.error('Error setting user online', error, { username });
    throw error;
  }
}

export async function bumpOnline(username, ttlSeconds = TTL_CONFIG.PRESENCE_TTL) {
  const normalizedUsername = normalizeUsername(username);
  if (!normalizedUsername) {
    throw new Error('Invalid username');
  }

  try {
    enforceRateLimit(`presence:bump:${normalizedUsername}`);
    const safeTtl = clampNumber(ttlSeconds, { min: 10, max: 86_400, defaultValue: TTL_CONFIG.PRESENCE_TTL || 300 });
    await redis.expire(ONLINE_KEY(normalizedUsername), safeTtl);
  } catch (error) {
    cryptoLogger.debug('Failed to bump online status', { username: normalizedUsername, error: error?.message });
  }
}

export async function setOffline(username) {
  try {
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) {
      throw new Error('Invalid username');
    }
    enforceRateLimit(`presence:clear:${normalizedUsername}`);
    await redis.del(ONLINE_KEY(normalizedUsername));
    cryptoLogger.debug('User presence set offline', { username: normalizedUsername });
  } catch (error) {
    cryptoLogger.error('Error setting user offline', error, { username });
    throw error;
  }
}

export async function isOnline(username) {
  const normalizedUsername = normalizeUsername(username);
  if (!normalizedUsername) {
    throw new Error('Invalid username');
  }

  try {
    const ex = await redis.exists(ONLINE_KEY(normalizedUsername));
    return ex === 1;
  } catch (error) {
    cryptoLogger.error('Error checking online status', error, { username });
    throw error;
  }
}

export async function publishToUser(username, payloadObj) {
  const normalizedUsername = normalizeUsername(username);
  if (!normalizedUsername) {
    throw new Error('Invalid username');
  }

  if (payloadObj === null || payloadObj === undefined) {
    throw new Error('Payload cannot be null or undefined');
  }

  try {
    enforceRateLimit(`presence:publish:${normalizedUsername}`);
    const msg = typeof payloadObj === 'string' ? payloadObj : JSON.stringify(payloadObj);
    if (Buffer.byteLength(msg) > MAX_PAYLOAD_BYTES) {
      throw new Error(`Payload too large: ${Buffer.byteLength(msg)} bytes (max: ${MAX_PAYLOAD_BYTES})`);
    }
    const receivers = await redis.publish(DELIVER_CH(normalizedUsername), msg);
    cryptoLogger.debug('Message published to user', { username: normalizedUsername, size: Buffer.byteLength(msg) });
    return receivers;
  } catch (error) {
    cryptoLogger.error('Error publishing message to user', error, { username });
    throw error;
  }
}

export async function subscribeUserChannel(subscriber, username, onMessage) {
  const normalizedUsername = normalizeUsername(username);
  if (!normalizedUsername) {
    throw new Error('Invalid username');
  }
  if (!subscriber || typeof subscriber.subscribe !== 'function') {
    throw new Error('Invalid subscriber object');
  }
  if (typeof onMessage !== 'function') {
    throw new Error('onMessage must be a function');
  }

  await subscriber.subscribe(DELIVER_CH(normalizedUsername));

  const handler = (channel, message) => {
    try {
      if (channel === DELIVER_CH(normalizedUsername)) {
        if (message && typeof message === 'string' && message.length > 0 && message.length <= MAX_PAYLOAD_BYTES) {
          onMessage(message);
        } else {
          cryptoLogger.warn('Invalid message received on channel', { username: normalizedUsername });
        }
      }
    } catch (error) {
      cryptoLogger.error('Error handling subscriber message', error, { username });
    }
  };

  subscriber.on('message', handler);

  return async () => {
    try {
      subscriber.off('message', handler);
      await subscriber.unsubscribe(DELIVER_CH(normalizedUsername));
    } catch (error) {
      cryptoLogger.error('Error unsubscribing from channel', error, { username });
      throw error;
    }
  };
}

// Clear all presence data on server startup to prevent hanging sessions
export async function clearAllPresenceData() {
  try {
    return await withRedisClient(async (client) => {
      let cleanedCount = 0;
      let cursor = '0';
      const batchSize = 100;
      let iterations = 0;

      do {
        const result = await client.scan(cursor, 'MATCH', 'online:*', 'COUNT', batchSize);
        cursor = result[0];
        const keys = result[1];

        if (keys.length > 0) {
          await client.del(...keys);
          cleanedCount += keys.length;
        }
        iterations++;
      } while (cursor !== '0' && iterations < MAX_SCAN_ITERATIONS);

      cryptoLogger.info('Cleared presence keys on startup', { cleanedCount });
      return cleanedCount;
    });
  } catch (error) {
    cryptoLogger.error('Error during presence cleanup', error);
    return 0;
  }
}