import Redis from 'ioredis';
import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import { RATE_LIMIT_CONFIG } from '../config/config.js';

// Distributed rate limiter using Redis with memory fallback
class DistributedRateLimiter {
	constructor() {
		this.metrics = {
			totalBlockedConnections: 0,
			totalBlockedAuths: 0,
			totalBlockedMessages: 0,
			totalBlockedBundles: 0,
		};

		// Redis client (optional)
		this.redis = null;
		this.usingRedis = false;
		this.globalConnectionLimiter = null;
		this.userMessageLimiter = null;
		this.userBundleLimiter = null;

		// Per-connection auth limiters (lifetime of ws)
		this.connectionAuthLimiters = new WeakMap();

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

		if (this.usingRedis) {
			this.globalConnectionLimiter = new RateLimiterRedis({
				storeClient: this.redis,
				points: Math.max(1, effectiveConnPoints),
				duration: Math.ceil(effectiveConnWindowMs / 1000),
				blockDuration: Math.ceil(effectiveConnBlockMs / 1000),
				keyPrefix: 'rl:global:conn'
			});

			this.userMessageLimiter = new RateLimiterRedis({
				storeClient: this.redis,
				points: Math.max(1, msgCfg.MAX_MESSAGES),
				duration: Math.ceil(msgCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(msgCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:msg'
			});

			this.userBundleLimiter = new RateLimiterRedis({
				storeClient: this.redis,
				points: Math.max(1, bunCfg.MAX_OPERATIONS),
				duration: Math.ceil(bunCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(bunCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:bundle'
			});

			this.userAuthLimiter = new RateLimiterRedis({
				storeClient: this.redis,
				points: Math.max(1, authUserCfg.MAX_ATTEMPTS),
				duration: Math.ceil(authUserCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(authUserCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:auth'
			});
		} else {
			this.globalConnectionLimiter = new RateLimiterMemory({
				points: Math.max(1, effectiveConnPoints),
				duration: Math.ceil(effectiveConnWindowMs / 1000),
				blockDuration: Math.ceil(effectiveConnBlockMs / 1000),
				keyPrefix: 'rl:global:conn'
			});

			this.userMessageLimiter = new RateLimiterMemory({
				points: Math.max(1, msgCfg.MAX_MESSAGES),
				duration: Math.ceil(msgCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(msgCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:msg'
			});

			this.userBundleLimiter = new RateLimiterMemory({
				points: Math.max(1, bunCfg.MAX_OPERATIONS),
				duration: Math.ceil(bunCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(bunCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:bundle'
			});

			this.userAuthLimiter = new RateLimiterMemory({
				points: Math.max(1, authUserCfg.MAX_ATTEMPTS),
				duration: Math.ceil(authUserCfg.WINDOW_MS / 1000),
				blockDuration: Math.ceil(authUserCfg.BLOCK_DURATION_MS / 1000),
				keyPrefix: 'rl:user:auth'
			});
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
		const randomJitter = Math.floor((Math.random() - 0.5) * jitter);
		return Math.max(1, ms + randomJitter);
	}

	async checkGlobalConnectionLimit() {
		if (this.disableGlobal) return { allowed: true };
		try {
			await this.globalConnectionLimiter.consume('global-conn', 1);
			return { allowed: true };
		} catch (res) {
			this.metrics.totalBlockedConnections++;
			const ms = res.msBeforeNext || 1000;
			return {
				allowed: false,
				reason: `Server connection rate limit exceeded. Try again in ${Math.ceil(ms / 1000)} seconds.`,
				remainingBlockTime: Math.ceil(ms / 1000)
			};
		}
	}

	async checkConnectionAuthLimit(ws) {
		const cfg = RATE_LIMIT_CONFIG.AUTHENTICATION;
		if (!this.connectionAuthLimiters.has(ws)) {
			this.connectionAuthLimiters.set(
				ws,
				new RateLimiterMemory({
					points: Math.max(1, cfg.MAX_ATTEMPTS_PER_CONNECTION),
					duration: Math.ceil(cfg.WINDOW_MS / 1000),
					blockDuration: Math.ceil(cfg.BLOCK_DURATION_MS / 1000),
					keyPrefix: 'rl:conn:auth'
				})
			);
		}
		const limiter = this.connectionAuthLimiters.get(ws);
		try {
			await limiter.consume('auth', 1);
			return { allowed: true };
		} catch (res) {
			this.metrics.totalBlockedAuths++;
			const ms = res.msBeforeNext || 1000;
			return {
				allowed: false,
				reason: `Authentication rate limit exceeded on this connection. Try again in ${Math.ceil(ms / 1000)} seconds.`,
				remainingBlockTime: Math.ceil(ms / 1000)
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
			this.metrics.totalBlockedMessages++;
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
			this.metrics.totalBlockedBundles++;
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
			securityMetrics: { ...this.metrics },
			timestamp: Date.now(),
			backend: this.usingRedis ? 'redis' : 'memory'
		};
	}
}

export const distributedRateLimiter = new DistributedRateLimiter();


