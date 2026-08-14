import Redis from 'ioredis';
import { RateLimiterRedis } from 'rate-limiter-flexible';

import { RATE_LIMIT_CONFIG } from '../config/config.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { buildRedisTlsOptions } from '../session/redis-client.js';
import { envInt } from '../utils/env.js';

const REDIS_TLS_OPTIONS = Symbol('redisTlsOptions');

function wipeRedisTlsPrivateKey(client) {
  const key = client?.[REDIS_TLS_OPTIONS]?.key;
  if (Buffer.isBuffer(key)) key.fill(0);
  if (client?.[REDIS_TLS_OPTIONS]) client[REDIS_TLS_OPTIONS] = null;
}

export async function createRedisClient(redisUrl) {
  if (typeof redisUrl !== 'string' || !redisUrl.startsWith('rediss://')) {
    throw new Error('RATE_LIMIT_REDIS_URL/REDIS_URL must use rediss:// and TLS');
  }

  const tls = buildRedisTlsOptions();

  const client = new Redis(redisUrl, {
    maxRetriesPerRequest: 2,
    enableAutoPipelining: true,
    retryDelayOnFailover: 100,
    connectTimeout: envInt('RATE_LIMIT_REDIS_CONNECT_TIMEOUT', 10_000, 1000, 60_000),
    commandTimeout: envInt('RATE_LIMIT_REDIS_COMMAND_TIMEOUT', 10_000, 1000, 30_000),
    lazyConnect: true,
    keepAlive: 30_000,
    enableReadyCheck: true,
    reconnectOnError: (error) => /READONLY|ECONNRESET/.test(error.message),
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD,
    tls
  });

  client.on('error', () => console.error('Rate limit Redis error'));
  client.on('connect', () => console.log('Rate limit Redis connected'));
  client.on('close', () => console.warn('Rate limit Redis connection closed'));
  client[REDIS_TLS_OPTIONS] = tls;
  try {
    await client.ping();
    return client;
  } catch (error) {
    client.disconnect(false);
    wipeRedisTlsPrivateKey(client);
    throw error;
  }
}

export class DistributedRateLimiter {
  static async create({ redisClientFactory = createRedisClient } = {}) {
    const redisUrl = process.env.RATE_LIMIT_REDIS_URL || process.env.REDIS_URL;
    if (!redisUrl) throw new Error('RATE_LIMIT_REDIS_URL or REDIS_URL is required');

    const redis = await redisClientFactory(redisUrl);
    try {
      const config = RATE_LIMIT_CONFIG.CONNECTION;
      const globalConnectionLimiter = new RateLimiterRedis({
        points: Math.max(1, config.MAX_NEW_CONNECTIONS),
        duration: Math.ceil(config.WINDOW_MS / 1000),
        blockDuration: Math.ceil(config.BLOCK_DURATION_MS / 1000),
        keyPrefix: PROTOCOL_KEYS.RATE_LIMIT_CONNECTION_REDIS_PREFIX,
        storeClient: redis
      });
      return new DistributedRateLimiter(redis, globalConnectionLimiter);
    } catch (error) {
      redis.disconnect(false);
      wipeRedisTlsPrivateKey(redis);
      throw error;
    }
  }

  constructor(redis, globalConnectionLimiter) {
    this.redis = redis;
    this.globalConnectionLimiter = globalConnectionLimiter;
  }

  async checkGlobalConnectionLimit() {
    if (!this.globalConnectionLimiter) {
      throw new Error('Global connection limiter is unavailable');
    }
    try {
      await this.globalConnectionLimiter.consume('all', 1);
      return { allowed: true };
    } catch {
      return { allowed: false };
    }
  }

  async close() {
    const redis = this.redis;
    this.redis = null;
    if (redis) {
      try {
        await redis.quit();
      } catch {
        redis.disconnect();
      } finally {
        wipeRedisTlsPrivateKey(redis);
      }
    }
  }
}

let sharedLimiterPromise;

export function getDistributedRateLimiter() {
  if (!sharedLimiterPromise) {
    const initialization = DistributedRateLimiter.create();
    sharedLimiterPromise = initialization;
    initialization.catch(() => {
      if (sharedLimiterPromise === initialization) sharedLimiterPromise = undefined;
    });
  }
  return sharedLimiterPromise;
}

export async function closeDistributedRateLimiter() {
  const initialization = sharedLimiterPromise;
  sharedLimiterPromise = undefined;
  const limiter = initialization ? await initialization.catch(() => null) : null;
  if (limiter?.close) await limiter.close();
}
