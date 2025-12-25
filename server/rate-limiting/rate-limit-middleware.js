import { getDistributedRateLimiter } from './distributed-rate-limiter.js';
import { SignalType } from '../signals.js';
import crypto from 'crypto';
import { RATE_LIMIT_CONFIG } from '../config/config.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';

// Rate limiting middleware for WebSocket connections
export class RateLimitMiddleware {
  constructor(limiters, { lazy = false } = {}) {
    this._limiter = null;
    this._limiterFactory = limiters
      ? async () => limiters
      : () => getDistributedRateLimiter();

    if (!lazy && !limiters) {
      this._initializePromise = this._limiterFactory().then((value) => {
        this._limiter = value;
        return value;
      });
    }
  }

  async #limiter() {
    if (this._limiter) {
      return this._limiter;
    }

    if (this._initializePromise) {
      return this._initializePromise;
    }

    this._initializePromise = this._limiterFactory().then((value) => {
      this._limiter = value;
      return value;
    });

    return this._initializePromise;
  }

	// Check global connection rate limit
	async checkConnectionLimit(ws) {
		if (!this.isValidWebSocket(ws)) {
			cryptoLogger.warn('[RATE-LIMIT] Invalid WebSocket in connection check');
			return false;
		}

		const limiter = await this.#limiter();
		const result = await limiter.checkGlobalConnectionLimit();

     if (!result.allowed) {
			cryptoLogger.warn('[RATE-LIMIT] Global connection blocked', { reason: result.reason });

			await sendSecureMessage(ws, {
				type: SignalType.ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			});

			ws.close(1008, 'Rate limit exceeded');
			return false;
		}

		cryptoLogger.debug('[RATE-LIMIT] Global connection allowed');
		return true;
	}

	// Check auth rate limit for connection
	async checkAuthLimit(ws) {
		if (!this.isValidWebSocket(ws)) {
			cryptoLogger.warn('[RATE-LIMIT] Invalid WebSocket in auth check');
			return false;
		}

		const limiter = await this.#limiter();
		const result = await limiter.checkConnectionAuthLimit(ws);

		if (!result.allowed) {
			cryptoLogger.warn('[RATE-LIMIT] Authentication blocked for connection', { reason: result.reason });

			await sendSecureMessage(ws, {
				type: SignalType.AUTH_ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			});
			return false;
		}

		cryptoLogger.debug('[RATE-LIMIT] Authentication allowed for connection');
		return true;
	}

	// Non-consuming per-user auth status check (long-window, aggregated)
	async checkUserAuthStatus(username) {
		if (!this.isValidUsername(username)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid username format in user auth check');
			return { allowed: false, reason: 'Invalid user' };
		}
		const limiter = await this.#limiter();
		return limiter.getUserAuthStatus(username);
	}

  // Non-consuming category status (short-window)
  async getUserCredentialStatus(username, category, ws = undefined) {
    const limiter = await this.#limiter();
    const ip = this._getClientIp(ws);
    return limiter.getUserCategoryStatus(username, category, ip);
  }

  // Record a credential failure (persisted in Redis) and get attempts/cooldown info
  async recordCredentialFailure(username, category, ws = undefined) {
    const limiter = await this.#limiter();
    const ip = this._getClientIp(ws);
    return limiter.consumeUserAuthAttempt(username, category, ip);
  }

	// Check message rate limit
	async checkMessageLimit(ws, username) {
		if (!this.isValidWebSocket(ws)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid WebSocket object in message check');
			return false;
		}

		if (!username) {
			cryptoLogger.warn('[RATE-LIMIT] No username provided for message rate limit check');
			return false;
		}

		if (!this.isValidUsername(username)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid username format in message check');
			return false;
		}

		const limiter = await this.#limiter();
		const result = await limiter.checkMessageLimit(username);

		if (!result.allowed) {
			cryptoLogger.warn('[RATE-LIMIT] Message blocked for user', { username, reason: result.reason });

			await sendSecureMessage(ws, {
				type: SignalType.ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			});
			return false;
		}

		cryptoLogger.debug('[RATE-LIMIT] Message allowed for user', { username });
		return true;
	}

	/**
	 * Check bundle operation rate limit for authenticated users
	 */
	async checkBundleLimit(ws, username) {
		if (!this.isValidWebSocket(ws)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid WebSocket object in bundle check');
			return false;
		}

		if (!username) {
			cryptoLogger.warn('[RATE-LIMIT] No username provided for bundle rate limit check');
			return false;
		}

		if (!this.isValidUsername(username)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid username format in bundle check');
			return false;
		}

		const limiter = await this.#limiter();
		const result = await limiter.checkBundleLimit(username);

		if (!result.allowed) {
			cryptoLogger.warn('[RATE-LIMIT] Bundle operation blocked for user', { username, reason: result.reason });

			await sendSecureMessage(ws, {
				type: SignalType.ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			});
			return false;
		}

		cryptoLogger.debug('[RATE-LIMIT] Bundle operation allowed for user', { username });
		return true;
	}

	/**
	 * Apply rate limiting to WebSocket message based on message type
	 */
	async applyMessageRateLimiting(ws, messageType, username) {
		if (!this.isValidMessageType(messageType)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid message type provided');
			return false;
		}

		switch (messageType) {
			case SignalType.ACCOUNT_SIGN_IN:
			case SignalType.ACCOUNT_SIGN_UP:
				return this.checkAuthLimit(ws);

			case SignalType.ENCRYPTED_MESSAGE:
			case SignalType.FILE_MESSAGE_CHUNK:
			case SignalType.DR_SEND:
				return this.checkMessageLimit(ws, username);

			case SignalType.X3DH_PUBLISH_BUNDLE:
			case SignalType.X3DH_REQUEST_BUNDLE:
				return this.checkBundleLimit(ws, username);

			default:
				return true;
		}
	}

	/**
	 * Get rate limiting statistics with security metrics
	 */
	async getStats() {
		const limiter = await this.#limiter();
		const baseStats = await limiter.getStats();

		const securityHealth = await this.getSecurityHealth(baseStats);

		return {
			...baseStats,
			securityHealth,
			recommendations: this._generateRecommendations(baseStats, securityHealth)
		};
	}

	/**
	 * Get real-time security health status from Redis
	 */
	async getSecurityHealth(precomputedStats = null) {
		try {
			const stats = precomputedStats || (await (await this.#limiter()).getStats());
			
			const health = {
				status: 'operational',
				rateLimiterActive: true,
				redisConnected: stats.redis?.connected || false,
				alerts: [],
				metrics: {
					activeUsers: stats.users?.activeLimiters || 0,
					blockedUsers: stats.users?.blocked || 0,
					globalBlocked: stats.global?.isBlocked || false,
					activeConnections: stats.connections?.activeLimiters || 0
				}
			};

			// Generate alerts based on thresholds
			if (!stats.redis?.connected) {
				health.status = 'degraded';
				health.alerts.push({
					severity: 'critical',
					message: 'Redis connection lost - rate limiting may be impaired'
				});
			}

			if (stats.users?.blocked > 0) {
				health.alerts.push({
					severity: 'warning',
					message: `${stats.users.blocked} users currently blocked by rate limits`
				});
			}

			if (stats.global?.isBlocked) {
				health.status = 'degraded';
				health.alerts.push({
					severity: 'critical',
					message: 'Global connection limit exceeded - new connections blocked'
				});
			}

			// Check for suspicious activity (many blocked users)
			const blockRatio = stats.users.activeLimiters > 0
				? stats.users.blocked / stats.users.activeLimiters
				: 0;

			if (blockRatio > 0.1) { // More than 10% blocked
				health.alerts.push({
					severity: 'warning',
					message: `High block rate detected: ${(blockRatio * 100).toFixed(1)}% of active users blocked`
				});
			}

			return health;
		} catch (error) {
			cryptoLogger.error('[RATE-LIMIT-HEALTH] Failed to get security health', {
				error: error.message
			});
			
			return {
				status: 'error',
				rateLimiterActive: false,
				error: error.message,
				alerts: [{
					severity: 'critical',
					message: 'Failed to retrieve security metrics'
				}]
			};
		}
	}

	/**
	 * Generate actionable recommendations based on current state
	 */
	_generateRecommendations(stats, _health) {
		const recommendations = [];

		if (!stats.redis?.connected) {
			recommendations.push({
				priority: 'critical',
				action: 'Restore Redis connection immediately',
				impact: 'Rate limiting may be bypassed'
			});
		}

		if (stats.users?.blocked > 10) {
			recommendations.push({
				priority: 'high',
				action: 'Review blocked users for potential attack',
				impact: `${stats.users.blocked} users currently blocked`,
				details: stats.users?.topAbusers || []
			});
		}

		if (stats.global?.isBlocked) {
			recommendations.push({
				priority: 'critical',
				action: 'Investigate connection flood',
				impact: 'New connections being rejected',
				blockedUntil: new Date(stats.global.blockedUntil).toISOString()
			});
		}

		if (stats.users?.activeLimiters > 10000) {
			recommendations.push({
				priority: 'medium',
				action: 'Monitor Redis memory usage',
				impact: `${stats.users.activeLimiters} active rate limiters in Redis`
			});
		}

		if (recommendations.length === 0) {
			recommendations.push({
				priority: 'info',
				action: 'System operating normally',
				impact: 'No immediate action required'
			});
		}

		return recommendations;
	}

	/**
	 * Reset rate limits for a specific user (admin function)
	 */
	async resetUserLimits(username) {
		if (!this.isValidUsername(username)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid username provided for reset');
			return false;
		}

		const limiter = await this.#limiter();
    try {
      const hashed = (await (async () => {
        try { return crypto.createHash('sha256').update(username).digest('hex'); } catch { return null; }
      })());
      if (hashed) {
        await limiter.userMessageLimiter.delete(hashed);
        await limiter.userBundleLimiter.delete(hashed);
        await limiter.userAuthLimiter.delete(hashed);
        await limiter.authAccountPasswordLimiter.delete(hashed);
        await limiter.authPassphraseLimiter.delete(hashed);
        await limiter.authServerPasswordLimiter.delete(hashed);
        return true;
      }
    } catch {}
		return false;
	}

	/**
	 * Reset global connection limits (admin function)
	 */
	async resetGlobalConnectionLimits() {
		const limiter = await this.#limiter();
		await limiter.globalConnectionLimiter.delete('global-conn');
		return true;
	}

	/**
	 * Get current rate limit status for a user
	 */
	async getUserStatus(username) {
		if (!this.isValidUsername(username)) {
			cryptoLogger.warn('[RATE-LIMIT-SECURITY] Invalid username provided for status check');
			return null;
		}

		const limiter = await this.#limiter();
		const msgInfo = await limiter.userMessageLimiter.get(username);
		const bunInfo = await limiter.userBundleLimiter.get(username);
		const msgCfg = RATE_LIMIT_CONFIG.MESSAGES;
		const bunCfg = RATE_LIMIT_CONFIG.BUNDLE_OPERATIONS;

		return {
			username,
			messages: msgInfo ? {
				attempts: msgInfo.consumedPoints || 0,
				blockedUntil: msgInfo.msBeforeNext ? Date.now() + msgInfo.msBeforeNext : 0,
				isBlocked: (msgInfo.consumedPoints || 0) >= msgCfg.MAX_MESSAGES && (msgInfo.msBeforeNext || 0) > 0,
				windowMs: msgCfg.WINDOW_MS
			} : null,
			bundleOperations: bunInfo ? {
				attempts: bunInfo.consumedPoints || 0,
				blockedUntil: bunInfo.msBeforeNext ? Date.now() + bunInfo.msBeforeNext : 0,
				isBlocked: (bunInfo.consumedPoints || 0) >= bunCfg.MAX_OPERATIONS && (bunInfo.msBeforeNext || 0) > 0,
				windowMs: bunCfg.WINDOW_MS
			} : null
		};
	}

	/**
	 * Get global connection rate limit status
	 */
	async getGlobalConnectionStatus() {
		const limiter = await this.#limiter();
		return limiter.getGlobalConnectionStatus();
	}

	/**
	 * Security utility functions
	 */
	isValidWebSocket(ws) {
		return ws && typeof ws === 'object' && typeof ws.send === 'function' && typeof ws.close === 'function';
	}

  _getClientIp(ws) {
    try {
      if (!this.isValidWebSocket(ws)) return undefined;
      const req = ws.upgradeReq || ws._socket || {};
      const direct = (req.socket && req.socket.remoteAddress) || req.remoteAddress || undefined;
      return direct || undefined;
    } catch { return undefined; }
  }

	isValidUsername(username) {
		if (!username || typeof username !== 'string') return false;
		const USERNAME_REGEX = /^[A-Za-z0-9_-]{3,32}$/;
		return USERNAME_REGEX.test(username);
	}

	isValidMessageType(messageType) {
		return messageType && typeof messageType === 'string' && messageType.length > 0;
	}

	generateSecureRequestId() {
		// Generate a cryptographically secure request ID for tracking
		return crypto.randomBytes(16).toString('hex');
	}

	/**
	 * Perform security audit with Redis metrics
	 */
	async performSecurityAudit() {
		try {
			const limiter = await this.#limiter();
			const stats = await limiter.getStats();
			const health = await this.getSecurityHealth();

			const audit = {
				timestamp: Date.now(),
				timestampISO: new Date().toISOString(),
				
				// Real-time metrics from Redis
				metrics: {
					backend: stats.backend,
					redis: stats.redis,
					global: stats.global,
					users: stats.users,
					connections: stats.connections
				},

				// Security health assessment
				securityHealth: health,

				// Top abusers requiring investigation
				topAbusers: stats.users?.topAbusers || [],

				// Actionable recommendations
				recommendations: this._generateRecommendations(stats, health),

				// Compliance notes
				compliance: {
					rateLimitingActive: stats.redis?.connected || false,
					ddosProtection: true,
					abnormalActivity: (stats.users?.blocked || 0) > 10,
					note: 'All rate limiting data persisted in Redis for cluster-wide enforcement'
				}
			};

			cryptoLogger.info('[RATE-LIMIT-SECURITY] Security Audit Complete', {
				activeUsers: audit.metrics.users.activeLimiters,
				blockedUsers: audit.metrics.users.blocked,
				globalBlocked: audit.metrics.global.isBlocked,
				alertCount: health.alerts?.length || 0
			});

			return audit;
		} catch (error) {
			cryptoLogger.error('[RATE-LIMIT-SECURITY] Audit failed', {
				error: error.message,
				stack: error.stack
			});

			return {
				timestamp: Date.now(),
				error: error.message,
				status: 'failed',
				recommendations: [{
					priority: 'critical',
					action: 'Fix rate limiter immediately',
					impact: 'Security monitoring unavailable'
				}]
			};
		}
	}

	async close() {
		if (this._limiter && typeof this._limiter.close === 'function') {
			await this._limiter.close();
		}
		this._limiter = null;
		this._initializePromise = null;
	}
}

export const rateLimitMiddleware = new RateLimitMiddleware(undefined, { lazy: false });
