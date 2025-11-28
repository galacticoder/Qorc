import Redis from 'ioredis';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { RATE_LIMIT_CONFIG } from '../config/config.js';
import crypto from 'crypto';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import fs from 'fs';

function sanitizeRedisUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.password) {
      parsed.password = '***';
    }
    return parsed.toString();
  } catch {
    return 'invalid-url';
  }
}

function clampNumber(value, defaults) {
  const parsed = Number.parseInt(value ?? defaults.defaultValue, 10);
  if (!Number.isFinite(parsed)) return defaults.defaultValue;
  return Math.min(Math.max(parsed, defaults.min), defaults.max);
}

const USERNAME_REGEX = /^[A-Za-z0-9_-]{3,64}$/;

function hashUsername(username) {
  if (!username || typeof username !== 'string') {
    throw new Error('Invalid username');
  }
  if (!USERNAME_REGEX.test(username)) {
    throw new Error('Invalid username format');
  }
  return crypto.createHash('sha256').update(username).digest('hex');
}


function addSecurityJitter(ms) {
  const base = Math.max(1, ms);
  const jitterRange = Math.min(10_000, Math.floor(base * 0.1));
  const random = crypto.randomBytes(4).readUInt32BE(0) / 0xFFFFFFFF;
  const offset = Math.floor((random - 0.5) * jitterRange);
  return Math.max(1, base + offset);
}

export async function createRedisClient(redisUrl) {
  if (typeof redisUrl !== 'string' || !redisUrl.startsWith('rediss://')) {
    throw new Error('RATE_LIMIT_REDIS_URL/REDIS_URL must use rediss:// and TLS; plaintext redis:// is not supported');
  }

  const tlsOptions = {};
  if (process.env.REDIS_TLS_SERVERNAME) {
    tlsOptions.servername = process.env.REDIS_TLS_SERVERNAME;
  } else {
    tlsOptions.servername = 'redis';
  }
  
  if (process.env.REDIS_CA_CERT_PATH) {
    tlsOptions.ca = [fs.readFileSync(process.env.REDIS_CA_CERT_PATH)];
  }
  if (process.env.REDIS_CLIENT_CERT_PATH) {
    tlsOptions.cert = fs.readFileSync(process.env.REDIS_CLIENT_CERT_PATH);
  }
  if (process.env.REDIS_CLIENT_KEY_PATH) {
    tlsOptions.key = fs.readFileSync(process.env.REDIS_CLIENT_KEY_PATH);
  }
  
  tlsOptions.rejectUnauthorized = true;

  const options = {
    maxRetriesPerRequest: 2,
    enableAutoPipelining: true,
    retryDelayOnFailover: 100,
    connectTimeout: clampNumber(process.env.RATE_LIMIT_REDIS_CONNECT_TIMEOUT, { min: 1000, max: 60_000, defaultValue: 10_000 }),
    lazyConnect: true,
    keepAlive: 30_000,
    enableReadyCheck: true,
    reconnectOnError: (err) => /READONLY|ECONNRESET/.test(err.message),
    username: process.env.REDIS_USERNAME,
    password: process.env.REDIS_PASSWORD,
    tls: tlsOptions
  };

  const client = new Redis(redisUrl, options);

  client.on('error', (error) => cryptoLogger.error('Rate limit Redis error', error));
  client.on('connect', () => cryptoLogger.info('Rate limit Redis connected'));
  client.on('close', () => cryptoLogger.warn('Rate limit Redis connection closed'));

  await client.ping();
  return client;
}

export class DistributedRateLimiter {
  static async create({ redisClientFactory = createRedisClient } = {}) {
    const redisUrl = process.env.RATE_LIMIT_REDIS_URL || process.env.REDIS_URL;

    if (!redisUrl) {
      throw new Error('RATE_LIMIT_REDIS_URL or REDIS_URL must be configured - rate limiting is required for security');
    }

    cryptoLogger.info('Initializing distributed rate limiter', { redisUrl: sanitizeRedisUrl(redisUrl) });

    const redis = await redisClientFactory(redisUrl);

    const cfg = RATE_LIMIT_CONFIG;

    const cats = cfg.AUTH_CATEGORIES;

    // Per-IP limiter : fixed defaults
    const IP_POINTS = 40;           // total failures per minute
    const IP_DURATION_S = 60;       // 60s window
    const IP_BLOCK_S = 600;         // 10 minutes block on abuse

    const configs = {
      globalConnection: {
        points: Math.max(1, cfg.CONNECTION.MAX_NEW_CONNECTIONS),
        duration: Math.ceil(cfg.CONNECTION.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cfg.CONNECTION.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:global:conn'
      },
      userMessage: {
        points: Math.max(1, cfg.MESSAGES.MAX_MESSAGES),
        duration: Math.ceil(cfg.MESSAGES.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cfg.MESSAGES.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:user:msg'
      },
      userBundle: {
        points: Math.max(1, cfg.BUNDLE_OPERATIONS.MAX_OPERATIONS),
        duration: Math.ceil(cfg.BUNDLE_OPERATIONS.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cfg.BUNDLE_OPERATIONS.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:user:bundle'
      },
      userAuth: {
        points: Math.max(1, cfg.AUTH_PER_USER.MAX_ATTEMPTS),
        duration: Math.ceil(cfg.AUTH_PER_USER.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cfg.AUTH_PER_USER.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:user:auth'
      },
      connectionAuth: {
        points: Math.max(1, cfg.AUTHENTICATION.MAX_ATTEMPTS_PER_CONNECTION),
        duration: Math.ceil(cfg.AUTHENTICATION.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cfg.AUTHENTICATION.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:conn:auth'
      },
      authAccountPassword: {
        points: Math.max(1, cats.ACCOUNT_PASSWORD.MAX_ATTEMPTS),
        duration: Math.ceil(cats.ACCOUNT_PASSWORD.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cats.ACCOUNT_PASSWORD.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:user:auth:accpwd'
      },
      authPassphrase: {
        points: Math.max(1, cats.PASSPHRASE.MAX_ATTEMPTS),
        duration: Math.ceil(cats.PASSPHRASE.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cats.PASSPHRASE.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:user:auth:pass'
      },
      authServerPassword: {
        points: Math.max(1, cats.SERVER_PASSWORD.MAX_ATTEMPTS),
        duration: Math.ceil(cats.SERVER_PASSWORD.WINDOW_MS / 1000),
        blockDuration: Math.ceil(cats.SERVER_PASSWORD.BLOCK_DURATION_MS / 1000),
        keyPrefix: 'rl:user:auth:srvpwd'
      },
      ipAuth: {
        points: Math.max(1, IP_POINTS),
        duration: Math.ceil(IP_DURATION_S),
        blockDuration: Math.ceil(IP_BLOCK_S),
        keyPrefix: 'rl:ip:auth'
      }
    };

    const limiters = {
      globalConnection: new RateLimiterRedis({ ...configs.globalConnection, storeClient: redis }),
      userMessage: new RateLimiterRedis({ ...configs.userMessage, storeClient: redis }),
      userBundle: new RateLimiterRedis({ ...configs.userBundle, storeClient: redis }),
      userAuth: new RateLimiterRedis({ ...configs.userAuth, storeClient: redis }),
      connectionAuth: new RateLimiterRedis({ ...configs.connectionAuth, storeClient: redis }),
      authAccountPassword: new RateLimiterRedis({ ...configs.authAccountPassword, storeClient: redis }),
      authPassphrase: new RateLimiterRedis({ ...configs.authPassphrase, storeClient: redis }),
      authServerPassword: new RateLimiterRedis({ ...configs.authServerPassword, storeClient: redis }),
      ipAuth: new RateLimiterRedis({ ...configs.ipAuth, storeClient: redis })
    };

    const disableGlobal = false;

    return new DistributedRateLimiter(redis, limiters, disableGlobal);
  }

  constructor(redis, limiters, disableGlobal) {
    this.redis = redis;
    this.usingRedis = !!redis;
    this.globalConnectionLimiter = limiters.globalConnection;
    this.userMessageLimiter = limiters.userMessage;
    this.userBundleLimiter = limiters.userBundle;
    this.userAuthLimiter = limiters.userAuth;
    this.connectionAuthLimiter = limiters.connectionAuth;
    this.authAccountPasswordLimiter = limiters.authAccountPassword;
    this.authPassphraseLimiter = limiters.authPassphrase;
    this.authServerPasswordLimiter = limiters.authServerPassword;
    this.ipAuthLimiter = limiters.ipAuth;

    this.disableGlobal = disableGlobal;
  }

  _getUserLimiterKey(username) {
    try {
      return hashUsername(username);
    } catch (error) {
      cryptoLogger.warn('Invalid username provided for rate limiter operation', { reason: error?.message });
      return null;
    }
  }

  _getAttemptKey(username) {
    const key = this._getUserLimiterKey(username);
    if (key) return key;
    const base = typeof username === 'string' ? username : String(username ?? '');
    return 'invalid_' + crypto.createHash('sha256').update(base).digest('hex');
  }

  _getCategoryLimiter(category) {
    switch (category) {
      case 'account_password':
      case 'credentials':
        return this.authAccountPasswordLimiter;
      case 'passphrase':
        return this.authPassphraseLimiter;
      case 'server_password':
        return this.authServerPasswordLimiter;
      default:
        return this.authAccountPasswordLimiter;
    }
  }

  _getIpKey(ip) {
    try {
      const raw = typeof ip === 'string' ? ip.trim().toLowerCase() : '';
      if (!raw) return null;
      const normalized = raw.startsWith('::ffff:') ? raw.replace('::ffff:', '') : raw;
      const pepper = (process.env.USER_ID_SALT || process.env.PASSWORD_HASH_PEPPER || '').toString();
      if (pepper && pepper.length >= 8) {
        return crypto.createHmac('sha256', Buffer.from(pepper, 'utf8')).update(normalized).digest('hex');
      }
      return crypto.createHash('sha256').update(normalized).digest('hex');
    } catch {
      return null;
    }
  }

  _formatDuration(ms) {
    const s = Math.max(1, Math.ceil(ms / 1000));
    const hrs = Math.floor(s / 3600);
    const mins = Math.floor((s % 3600) / 60);
    const secs = s % 60;
    const parts = [];
    if (hrs) parts.push(`${hrs} hour${hrs === 1 ? '' : 's'}`);
    if (mins) parts.push(`${mins} minute${mins === 1 ? '' : 's'}`);
    if (!hrs && secs) parts.push(`${secs} second${secs === 1 ? '' : 's'}`);
    return parts.join(' ');
  }


  _addSecurityJitter(ms) {
    return addSecurityJitter(ms);
  }

  async checkGlobalConnectionLimit() {
    if (this.disableGlobal) return { allowed: true };
    if (!this.globalConnectionLimiter) {
      cryptoLogger.warn('Global connection limiter not initialized; allowing request');
      return { allowed: true };
    }
    try {
      await this.globalConnectionLimiter.consume('global-conn', 1);
      return { allowed: true };
    } catch (res) {
      const ms = res.msBeforeNext || 1000;
      const safeMs = Math.max(1000, ms || 1000);
      const friendly = this._formatDuration(safeMs);

      return {
        allowed: false,
        reason: `Server connection rate limit exceeded. Try again in ${friendly}.`,
        remainingBlockTime: Math.max(1, Math.ceil(safeMs / 1000))
      };
    }
  }

  async checkConnectionAuthLimit(ws) {
    if (!ws._connectionId) {
      ws._connectionId = `conn_${crypto.randomUUID()}`;
    }

    // Check if rate limiter is initialized
    if (!this.connectionAuthLimiter) {
      cryptoLogger.warn('Connection auth limiter not initialized; allowing request');
      return { allowed: true };
    }

    try {
      await this.connectionAuthLimiter.consume(ws._connectionId, 1);
      return { allowed: true };
    } catch (res) {
      const safeMs = Math.max(1000, res.msBeforeNext || 1000);
      const friendly = this._formatDuration(safeMs);

      return {
        allowed: false,
        reason: `Authentication rate limit exceeded on this connection. Try again in ${friendly}.`,
        remainingBlockTime: Math.max(1, Math.ceil(safeMs / 1000))
      };
    }
  }

  async checkUserAuthLimit(username) {
    const key = this._getUserLimiterKey(username);
    if (!this.userAuthLimiter) {
      return { allowed: true };
    }
    try {
      if (!key) {
        return { allowed: false, reason: 'Invalid user' };
      }
      await this.userAuthLimiter.consume(key, 1);
      return { allowed: true };
    } catch (res) {
      const ms = res.msBeforeNext || 1000;
      const friendly = this._formatDuration(ms);
      return {
        allowed: false,
        reason: friendly ? 'Too many failed authentication attempts. Please wait before retrying.' : 'Too many failed attempts.',
        remainingBlockTime: Math.max(1, Math.ceil(ms / 1000))
      };
    }
  }

  // Consume a user auth attempt and return UI-relevant info
  async consumeUserAuthAttempt(username, category = 'account_password', ip) {
    const keyForAttempts = this._getAttemptKey(username);

    const categoryLimiter = this._getCategoryLimiter(category);
    let attemptsRemaining = null;
    let categoryBlocked = false;
    let categoryBlockMs = 0;

    // Per-IP limiter (if IP available)
    let ipBlocked = false;
    let ipBlockMs = 0;
    try {
      const ipKey = this._getIpKey(ip);
      if (ipKey && this.ipAuthLimiter) {
        await this.ipAuthLimiter.consume(ipKey, 1);
      }
    } catch (res) {
      ipBlocked = true;
      ipBlockMs = Math.max(1000, res?.msBeforeNext || 1000);
    }

    if (ipBlocked) {
      return { attemptsRemaining: 0, locked: true, remainingBlockTime: Math.ceil(ipBlockMs / 1000) };
    }

    try {
      const res = await categoryLimiter.consume(keyForAttempts, 1);
      const consumed = res?.consumedPoints ?? (typeof res?.remainingPoints === 'number' ? (categoryLimiter.points - res.remainingPoints) : 0);
      const max = categoryLimiter.points ?? 5;
      attemptsRemaining = Math.max(0, max - consumed);
    } catch (res) {
      categoryBlocked = true;
      categoryBlockMs = Math.max(1000, res?.msBeforeNext || 1000);
      attemptsRemaining = 0;
    }

    // Always record in long-window per-user limiter (aggregated abuse tracking)
    let globalBlocked = false;
    let globalBlockMs = 0;
    try {
      const perUserKey = this._getUserLimiterKey(username);
      if (perUserKey) {
        await this.userAuthLimiter.consume(perUserKey, 1);
      }
    } catch (res) {
      globalBlocked = true;
      globalBlockMs = Math.max(1000, res?.msBeforeNext || 1000);
    }

    const locked = categoryBlocked || globalBlocked;
    const remainingBlockTime = Math.max(0, Math.ceil(Math.max(categoryBlockMs, globalBlockMs) / 1000));

    return { attemptsRemaining, locked, remainingBlockTime };
  }

  // Non-consuming check for a specific category
  async getUserCategoryStatus(username, category = 'account_password', ip) {
    try {
      try {
        const ipKey = this._getIpKey(ip);
        if (ipKey && this.ipAuthLimiter) {
          const ipRes = await this.ipAuthLimiter.get(ipKey);
          if (ipRes && (ipRes.consumedPoints || 0) >= (this.ipAuthLimiter.points || 1) && (ipRes.msBeforeNext || 0) > 0) {
            return { allowed: false, attemptsRemaining: 0, remainingBlockTime: Math.max(1, Math.ceil((ipRes.msBeforeNext || 0) / 1000)) };
          }
        }
      } catch { }

      const key = this._getAttemptKey(username);
      const lim = this._getCategoryLimiter(category);
      const res = await lim.get(key);
      if (!res) return { allowed: true };
      const isBlocked = (res.consumedPoints || 0) >= (lim.points || 5) && (res.msBeforeNext || 0) > 0;
      if (!isBlocked) return { allowed: true, attemptsRemaining: Math.max(0, (lim.points || 5) - (res.consumedPoints || 0)) };
      return {
        allowed: false,
        attemptsRemaining: 0,
        remainingBlockTime: Math.max(1, Math.ceil((res.msBeforeNext || 0) / 1000))
      };
    } catch {
      return { allowed: true };
    }
  }

  // Non-consuming status check for per-user auth limit
  async getUserAuthStatus(username) {
    const key = this._getUserLimiterKey(username);
    if (!this.userAuthLimiter) {
      return { allowed: true };
    }
    try {
      if (!key) {
        return { allowed: false, reason: 'Invalid user' };
      }
      const res = await this.userAuthLimiter.get(key);
      if (!res) return { allowed: true };
      const cfg = RATE_LIMIT_CONFIG.AUTH_PER_USER;
      const consumed = res.consumedPoints || 0;
      const msBeforeNext = res.msBeforeNext || 0;
      const isBlocked = consumed >= Math.max(1, cfg.MAX_ATTEMPTS) && msBeforeNext > 0;
      if (!isBlocked) return { allowed: true };
      return {
        allowed: false,
        reason: msBeforeNext ? 'Too many failed authentication attempts. Please wait before retrying.' : 'Too many failed attempts.',
        remainingBlockTime: Math.max(1, Math.ceil(msBeforeNext / 1000))
      };
    } catch {
      return { allowed: true };
    }
  }

  async checkMessageLimit(username) {
    const key = this._getUserLimiterKey(username);
    if (!this.userMessageLimiter) {
      return { allowed: true };
    }
    if (!key) {
      return { allowed: false, reason: 'Invalid user' };
    }
    try {
      await this.userMessageLimiter.consume(key, 1);
      return { allowed: true };
    } catch (res) {
      const ms = res.msBeforeNext || 1000;
      const friendly = this._formatDuration(ms);
      return {
        allowed: false,
        reason: `Message rate limit exceeded. Try again in ${friendly}.`,
        remainingBlockTime: Math.max(1, Math.ceil(ms / 1000))
      };
    }
  }

  async checkBundleLimit(username) {
    const key = this._getUserLimiterKey(username);
    if (!this.userBundleLimiter) {
      return { allowed: true };
    }
    if (!key) {
      return { allowed: false, reason: 'Invalid user' };
    }
    try {
      await this.userBundleLimiter.consume(key, 1);
      return { allowed: true };
    } catch (res) {
      const ms = res.msBeforeNext || 1000;
      const friendly = this._formatDuration(ms);
      return {
        allowed: false,
        reason: `Bundle operation rate limit exceeded. Try again in ${friendly}.`,
        remainingBlockTime: Math.max(1, Math.ceil(ms / 1000))
      };
    }
  }

  async getGlobalConnectionStatus() {
    try {
      const connCfg = RATE_LIMIT_CONFIG.CONNECTION;
      const res = this.globalConnectionLimiter ? await this.globalConnectionLimiter.get('global-conn') : null;
      const consumed = res?.consumedPoints || 0;
      const isBlocked = res ? consumed > Math.max(1, connCfg.MAX_NEW_CONNECTIONS) : false;
      return {
        attempts: consumed,
        blockedUntil: isBlocked ? Date.now() + (res.msBeforeNext || 0) : 0,
        isBlocked,
        maxConnections: connCfg.MAX_NEW_CONNECTIONS,
        windowMs: connCfg.WINDOW_MS,
      };
    } catch {
      return {
        attempts: 0,
        blockedUntil: 0,
        isBlocked: false,
        maxConnections: RATE_LIMIT_CONFIG.CONNECTION.MAX_NEW_CONNECTIONS,
        windowMs: RATE_LIMIT_CONFIG.CONNECTION.WINDOW_MS,
      };
    }
  }

  /**
   * Get rate limiting statistics from Redis
   */
  async getStats() {
    const stats = {
      timestamp: Date.now(),
      backend: this.usingRedis ? 'redis' : 'memory',
      redis: {
        connected: this.redis?.status === 'ready',
        status: this.redis?.status || 'unknown'
      },
      global: {},
      users: {
        activeLimiters: 0,
        blocked: 0,
        topAbusers: []
      },
      connections: {
        activeLimiters: 0,
        blocked: 0
      }
    };

    if (!this.redis || this.redis.status !== 'ready') {
      stats.error = 'Redis not available';
      return stats;
    }

    try {
      // Get global connection stats
      const globalConn = await this.getGlobalConnectionStatus();
      stats.global = {
        connections: globalConn.attempts,
        isBlocked: globalConn.isBlocked,
        blockedUntil: globalConn.blockedUntil,
        maxConnections: globalConn.maxConnections,
        windowMs: globalConn.windowMs
      };

      // Scan for active user message limiters
      const msgKeys = await this._scanKeys('rl:user:msg:*');
      stats.users.messageLimiters = msgKeys.length;

      // Scan for active user bundle limiters
      const bundleKeys = await this._scanKeys('rl:user:bundle:*');
      stats.users.bundleLimiters = bundleKeys.length;

      // Scan for active user auth limiters
      const authKeys = await this._scanKeys('rl:user:auth:*');
      stats.users.authLimiters = authKeys.length;

      stats.users.activeLimiters = msgKeys.length + bundleKeys.length + authKeys.length;

      // Get blocked users count and top abusers
      const blockedUsers = await this._getBlockedUsers(msgKeys, bundleKeys, authKeys);
      stats.users.blocked = blockedUsers.count;
      stats.users.topAbusers = blockedUsers.top;

      // Get active connection limiters
      const connKeys = await this._scanKeys('rl:conn:auth:*');
      stats.connections.activeLimiters = connKeys.length;

    } catch (error) {
      cryptoLogger.error('[RATE-LIMIT-STATS] Failed to gather stats', {
        error: error.message
      });
      stats.error = error.message;
    }

    return stats;
  }

  /**
   * Scan Redis for keys matching pattern
   */
  async _scanKeys(pattern, maxKeys = 1000) {
    const keys = [];
    let cursor = '0';
    const startTime = Date.now();
    const timeout = 5000;

    try {
      do {
        // Check timeout to prevent long-running scans
        if (Date.now() - startTime > timeout) {
          cryptoLogger.warn('[RATE-LIMIT-STATS] Scan timeout reached', {
            pattern,
            keysFound: keys.length
          });
          break;
        }

        const result = await this.redis.scan(
          cursor,
          'MATCH', pattern,
          'COUNT', 100
        );

        cursor = result[0];
        keys.push(...result[1]);

        // Limit total keys to prevent memory issues
        if (keys.length >= maxKeys) {
          cryptoLogger.info('[RATE-LIMIT-STATS] Max keys limit reached', {
            pattern,
            limit: maxKeys
          });
          break;
        }
      } while (cursor !== '0');
    } catch (error) {
      cryptoLogger.error('[RATE-LIMIT-STATS] Scan failed', {
        pattern,
        error: error.message
      });
    }

    return keys;
  }

  /**
   * Get blocked users and top abusers from rate limiter keys
   */
  async _getBlockedUsers(msgKeys, bundleKeys, authKeys) {
    const allKeys = [...msgKeys, ...bundleKeys, ...authKeys];
    const blocked = [];
    const now = Date.now();

    // Sample up to 100 keys to find blocked users
    const sampleSize = Math.min(100, allKeys.length);
    const sampled = allKeys
      .sort(() => Math.random() - 0.5)
      .slice(0, sampleSize);

    try {
      // Use pipeline for efficiency
      const pipeline = this.redis.pipeline();
      sampled.forEach(key => pipeline.get(key));
      const results = await pipeline.exec();

      results.forEach(([err, data], idx) => {
        if (err || !data) return;

        try {
          const parsed = JSON.parse(data);
          const key = sampled[idx];
          const keyType = key.includes(':msg:') ? 'message'
            : key.includes(':bundle:') ? 'bundle'
              : 'auth';

          if (parsed.msBeforeNext && parsed.msBeforeNext > 0) {
            const blockedUntil = now + parsed.msBeforeNext;
            blocked.push({
              keyHash: key.split(':').pop().slice(0, 12),
              type: keyType,
              attempts: parsed.consumedPoints || 0,
              blockedUntil,
              remainingMs: parsed.msBeforeNext
            });
          }
        } catch (_parseError) {
        }
      });
    } catch (error) {
      cryptoLogger.error('[RATE-LIMIT-STATS] Failed to get blocked users', {
        error: error.message
      });
    }

    blocked.sort((a, b) => b.attempts - a.attempts);

    return {
      count: blocked.length,
      top: blocked.slice(0, 10)
    };
  }

  // Clean up connection-specific rate limiting data
  async cleanupConnectionLimit(ws) {
    if (ws._connectionId && this.connectionAuthLimiter) {
      try {
        await this.connectionAuthLimiter.delete(ws._connectionId);
      } catch (error) {
        cryptoLogger.debug('[RATE-LIMIT] Error cleaning up connection limit', { error: error.message });
      }
      delete ws._connectionId;
    }
  }
}

let sharedLimiterPromise;

export function __resetDistributedRateLimiterSingleton() {
  sharedLimiterPromise = undefined;
}

export function getDistributedRateLimiter() {
  if (!sharedLimiterPromise) {
    sharedLimiterPromise = DistributedRateLimiter.create();
  }
  return sharedLimiterPromise;
}