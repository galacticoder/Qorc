import Redis from 'ioredis';
import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import { RATE_LIMIT_CONFIG } from '../config/config.js';
import crypto from 'crypto';

// Distributed rate limiter using Redis with memory fallback
class DistributedRateLimiter {
	constructor() {
		// REMOVED: metrics object to prevent memory issues with millions of users
		// All rate limiting handled by Redis-based limiters

		// Redis client (optional)
		this.redis = null;
		this.usingRedis = false;
		this.globalConnectionLimiter = null;
		this.userMessageLimiter = null;
		this.userBundleLimiter = null;
		this.connectionAuthLimiter = null;

		// REMOVED: Per-connection auth limiters WeakMap to prevent memory leaks
		// Now using Redis-based connection auth limiter with connection IDs

		this._initStores();
	}

	_initStores() {
		const redisUrl = process.env.REDIS_URL || process.env.RATE_LIMIT_REDIS_URL || null;
		if (redisUrl) {
			try {
				this.redis = new Redis(redisUrl, {
					maxRetriesPerRequest: 2,
					enableAutoPipelining: true,
				});
				this.usingRedis = true;
			} catch (e) {
				console.warn('[RATE-LIMIT] Failed to init Redis, falling back to memory:', e?.message || e);
				this.usingRedis = false;
			}
		}

		const connCfg = RATE_LIMIT_CONFIG.CONNECTION;
		const msgCfg = RATE_LIMIT_CONFIG.MESSAGES;
		const bunCfg = RATE_LIMIT_CONFIG.BUNDLE_OPERATIONS;
		const authUserCfg = RATE_LIMIT_CONFIG.AUTH_PER_USER;

		// Allow env overrides for connection limiter and dev toggle
		const envConnWindowMs = Number.parseInt(process.env.CONNECTION_WINDOW_MS || '', 10);
		const envConnPoints = Number.parseInt(process.env.CONNECTION_MAX_NEW || '', 10);
		const envConnBlockMs = Number.parseInt(process.env.CONNECTION_BLOCK_MS || '', 10);
		const effectiveConnWindowMs = Number.isFinite(envConnWindowMs) ? envConnWindowMs : connCfg.WINDOW_MS;
		const effectiveConnPoints = Number.isFinite(envConnPoints) ? envConnPoints : connCfg.MAX_NEW_CONNECTIONS;
		const effectiveConnBlockMs = Number.isFinite(envConnBlockMs) ? envConnBlockMs : connCfg.BLOCK_DURATION_MS;

		this.disableGlobal = (process.env.DISABLE_CONNECTION_LIMIT || '').toLowerCase() === 'true' || process.env.DISABLE_CONNECTION_LIMIT === '1';

		// Shared configuration objects for rate limiters
		const authCfg = RATE_LIMIT_CONFIG.AUTHENTICATION;
		const configs = {
			globalConnection: {
				points: Math.max(1, effectiveConnPoints),
				duration: Math.ceil(effectiveConnWindowMs / 1000),
				blockDuration: Math.ceil(effectiveConnBlockMs / 1000),
				keyPrefix: 'rl:global:conn'
			},
			userMessage: {
				points: Math.max(1, msgCfg.MAX_MESSAGES),
				duration: Math.ceil(msgCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(msgCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:msg'
			},
			userBundle: {
				points: Math.max(1, bunCfg.MAX_OPERATIONS),
				duration: Math.ceil(bunCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(bunCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:bundle'
			},
			userAuth: {
				points: Math.max(1, authUserCfg.MAX_ATTEMPTS),
				duration: Math.ceil(authUserCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(authUserCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:auth'
			},
			connectionAuth: {
				points: Math.max(1, authCfg.MAX_ATTEMPTS_PER_CONNECTION),
				duration: Math.ceil(authCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(authCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:conn:auth'
			}
		};

		if (this.usingRedis) {
			// Add storeClient to each config for Redis
			this.globalConnectionLimiter = new RateLimiterRedis({ ...configs.globalConnection, storeClient: this.redis });
			this.userMessageLimiter = new RateLimiterRedis({ ...configs.userMessage, storeClient: this.redis });
			this.userBundleLimiter = new RateLimiterRedis({ ...configs.userBundle, storeClient: this.redis });
			this.userAuthLimiter = new RateLimiterRedis({ ...configs.userAuth, storeClient: this.redis });
			this.connectionAuthLimiter = new RateLimiterRedis({ ...configs.connectionAuth, storeClient: this.redis });
		} else {
			// Use memory-based limiters
			this.globalConnectionLimiter = new RateLimiterMemory(configs.globalConnection);
			this.userMessageLimiter = new RateLimiterMemory(configs.userMessage);
			this.userBundleLimiter = new RateLimiterMemory(configs.userBundle);
			this.userAuthLimiter = new RateLimiterMemory(configs.userAuth);
			this.connectionAuthLimiter = new RateLimiterMemory(configs.connectionAuth);
		}

		console.log('[RATE-LIMIT] Backend:', this.usingRedis ? 'redis' : 'memory');
		if (this.disableGlobal) {
			console.log('[RATE-LIMIT] Global connection limiting: disabled');
		} else {
			console.log('[RATE-LIMIT] Global connection limiting: enabled', {
				windowMs: effectiveConnWindowMs,
				maxNewConnections: effectiveConnPoints,
				blockDurationMs: effectiveConnBlockMs
			});
		}
	}

	// Utility: add small jitter to avoid precise timing attacks
	_addSecurityJitter(ms) {
		const jitter = Math.floor(ms * 0.1);
		// SECURITY: Use cryptographically secure random for jitter
		const randomValue = crypto.randomBytes(1)[0] / 255; // 0-1 range
		const randomJitter = Math.floor((randomValue - 0.5) * jitter);
		return Math.max(1, ms + randomJitter);
	}

	async checkGlobalConnectionLimit() {
		if (this.disableGlobal) return { allowed: true };
		try {
			await this.globalConnectionLimiter.consume('global-conn', 1);
			return { allowed: true };
		} catch (res) {
			// Blocked connection logged (metrics removed for memory efficiency)
			const ms = res.msBeforeNext || 1000;
			// SECURITY: Prevent division by zero and ensure positive values
			const safeMs = Math.max(1000, ms || 1000);
			const remainingSeconds = Math.max(1, Math.ceil(safeMs / 1000));

			return {
				allowed: false,
				reason: `Server connection rate limit exceeded. Try again in ${remainingSeconds} seconds.`,
				remainingBlockTime: remainingSeconds
			};
		}
	}

	async checkConnectionAuthLimit(ws) {
		// SECURITY: Generate a unique connection ID for rate limiting
		// Use a combination of connection time and random data to avoid collisions
		if (!ws._connectionId) {
			const timestamp = Date.now();
			const randomBytes = crypto.randomBytes(8).toString('hex');
			ws._connectionId = `conn_${timestamp}_${randomBytes}`;
		}

		try {
			await this.connectionAuthLimiter.consume(ws._connectionId, 1);
			return { allowed: true };
		} catch (res) {
			// Blocked auth logged (metrics removed for memory efficiency)
			// SECURITY: Prevent division by zero and ensure positive values
			const safeMs = Math.max(1000, res.msBeforeNext || 1000);
			const remainingSeconds = Math.max(1, Math.ceil(safeMs / 1000));

			return {
				allowed: false,
				reason: `Authentication rate limit exceeded on this connection. Try again in ${remainingSeconds} seconds.`,
				remainingBlockTime: remainingSeconds
			};
		}
	}

	async checkUserAuthLimit(username) {
		try {
			await this.userAuthLimiter.consume(username, 1);
			return { allowed: true };
		} catch (res) {
			const ms = res.msBeforeNext || 1000;
			return {
				allowed: false,
				reason: `Too many failed authentication attempts. Try again in ${Math.ceil(ms / 1000)} seconds.`,
				remainingBlockTime: Math.ceil(ms / 1000)
			};
		}
	}

	async checkMessageLimit(username) {
		try {
			await this.userMessageLimiter.consume(username, 1);
			return { allowed: true };
		} catch (res) {
			// Blocked message logged (metrics removed for memory efficiency)
			const ms = res.msBeforeNext || 1000;
			return {
				allowed: false,
				reason: `Message rate limit exceeded. Try again in ${Math.ceil(ms / 1000)} seconds.`,
				remainingBlockTime: Math.ceil(ms / 1000)
			};
		}
	}

	async checkBundleLimit(username) {
		try {
			await this.userBundleLimiter.consume(username, 1);
			return { allowed: true };
		} catch (res) {
			// Blocked bundle logged (metrics removed for memory efficiency)
			const ms = res.msBeforeNext || 1000;
			return {
				allowed: false,
				reason: `Bundle operation rate limit exceeded. Try again in ${Math.ceil(ms / 1000)} seconds.`,
				remainingBlockTime: Math.ceil(ms / 1000)
			};
		}
	}

	async getGlobalConnectionStatus() {
		try {
			const connCfg = RATE_LIMIT_CONFIG.CONNECTION;
			const res = await this.globalConnectionLimiter.get('global-conn');
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

	getStats() {
		return {
			timestamp: Date.now(),
			backend: this.usingRedis ? 'redis' : 'memory',
			note: "Individual metrics removed for memory efficiency with millions of users"
		};
	}

	// Clean up connection-specific rate limiting data
	async cleanupConnectionLimit(ws) {
		if (ws._connectionId && this.connectionAuthLimiter) {
			try {
				// Reset the limiter for this connection if needed
				await this.connectionAuthLimiter.delete(ws._connectionId);
			} catch (error) {
				console.debug('[RATE-LIMIT] Error cleaning up connection limit:', error.message);
			}
			delete ws._connectionId;
		}
	}
}

export const distributedRateLimiter = new DistributedRateLimiter();


