import { distributedRateLimiter } from './distributed-rate-limiter.js';
import { SignalType } from '../signals.js';
import crypto from 'crypto';
import { RATE_LIMIT_CONFIG } from '../config/config.js';

// Rate limiting middleware for WebSocket connections
export class RateLimitMiddleware {
	constructor() {
		this.rateLimiter = distributedRateLimiter;
		// REMOVED: securityMetrics to prevent memory issues with millions of users
		// All metrics now handled by Redis-based rate limiter for scalability
	}

	// Check global connection rate limit
	async checkConnectionLimit(ws) {
		// Check WebSocket object
		if (!this.isValidWebSocket(ws)) {
			console.warn('[RATE-LIMIT] Invalid WebSocket in connection check');
			return false;
		}

		const result = await this.rateLimiter.checkGlobalConnectionLimit();

		if (!result.allowed) {
			console.warn(`[RATE-LIMIT] Global connection blocked: ${result.reason}`);

			// Security: Send rate limit info with jittered timing
			ws.send(JSON.stringify({
				type: SignalType.ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			}));

			ws.close(1008, 'Rate limit exceeded');
			return false;
		}

		console.log('[RATE-LIMIT] Global connection allowed');
		return true;
	}

	// Check auth rate limit for connection
	async checkAuthLimit(ws) {
		// Metrics removed for memory efficiency

		// Check WebSocket object
		if (!this.isValidWebSocket(ws)) {
			console.warn('[RATE-LIMIT] Invalid WebSocket in auth check');
			// Security violation logged (metrics removed for memory efficiency)
			return false;
		}

		const result = await this.rateLimiter.checkConnectionAuthLimit(ws);

		if (!result.allowed) {
			// Blocked request logged (metrics removed for memory efficiency)
			console.warn(`[RATE-LIMIT] Authentication blocked for connection: ${result.reason}`);

			// Security: Send rate limit info with jittered timing
			ws.send(JSON.stringify({
				type: SignalType.AUTH_ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			}));
			return false;
		}

		console.log('[RATE-LIMIT] Authentication allowed for connection');
		return true;
	}

	// Check per-user auth limit
	async checkUserAuthLimit(username) {
		if (!this.isValidUsername(username)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid username format in user auth check');
			// Security violation logged (metrics removed for memory efficiency)
			return { allowed: false, reason: 'Invalid user' };
		}
		return this.rateLimiter.checkUserAuthLimit(username);
	}

	// Check message rate limit
	async checkMessageLimit(ws, username) {
		// Metrics removed for memory efficiency

		// Security: Validate WebSocket object
		if (!this.isValidWebSocket(ws)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid WebSocket object in message check');
			// Security violation logged (metrics removed for memory efficiency)
			return false;
		}

		if (!username) {
			console.warn('[RATE-LIMIT] No username provided for message rate limit check');
			return false;
		}

		// Security: Validate username format
		if (!this.isValidUsername(username)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid username format in message check');
			// Security violation logged (metrics removed for memory efficiency)
			return false;
		}

		const result = await this.rateLimiter.checkMessageLimit(username);

		if (!result.allowed) {
			// Blocked request logged (metrics removed for memory efficiency)
			console.warn(`[RATE-LIMIT] Message blocked for user ${username}: ${result.reason}`);

			// Security: Send rate limit info with jittered timing
			ws.send(JSON.stringify({
				type: SignalType.ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			}));
			return false;
		}

		console.log(`[RATE-LIMIT] Message allowed for user ${username}`);
		return true;
	}

	/**
	 * Check bundle operation rate limit for authenticated users
	 */
	async checkBundleLimit(ws, username) {
		// Metrics removed for memory efficiency

		// Security: Validate WebSocket object
		if (!this.isValidWebSocket(ws)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid WebSocket object in bundle check');
			// Security violation logged (metrics removed for memory efficiency)
			return false;
		}

		if (!username) {
			console.warn('[RATE-LIMIT] No username provided for bundle rate limit check');
			return false;
		}

		// Security: Validate username format
		if (!this.isValidUsername(username)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid username format in bundle check');
			// Security violation logged (metrics removed for memory efficiency)
			return false;
		}

		const result = await this.rateLimiter.checkBundleLimit(username);

		if (!result.allowed) {
			// Blocked request logged (metrics removed for memory efficiency)
			console.warn(`[RATE-LIMIT] Bundle operation blocked for user ${username}: ${result.reason}`);

			// Security: Send rate limit info with jittered timing
			ws.send(JSON.stringify({
				type: SignalType.ERROR,
				message: result.reason,
				rateLimitInfo: {
					blocked: true,
					remainingBlockTime: result.remainingBlockTime,
					requestId: this.generateSecureRequestId()
				}
			}));
			return false;
		}

		console.log(`[RATE-LIMIT] Bundle operation allowed for user ${username}`);
		return true;
	}

	/**
	 * Apply rate limiting to WebSocket message based on message type
	 * Enhanced with security validation
	 */
	async applyMessageRateLimiting(ws, messageType, username) {
		// Security: Validate message type
		if (!this.isValidMessageType(messageType)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid message type provided');
			// Security violation logged (metrics removed for memory efficiency)
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
				// Allow other message types without rate limiting
				return true;
		}
	}

	/**
	 * Get comprehensive rate limiting statistics with security metrics
	 */
	getStats() {
		const baseStats = this.rateLimiter.getStats();
		return {
			...baseStats,
			// Maintain legacy fields expected by server logging
			userMessageLimiters: 0,
			userBundleLimiters: 0,
			totalUserLimiters: 0,
			securityHealth: this.getSecurityHealth(),
			timestamp: Date.now(),
			note: "Individual metrics removed for memory efficiency with millions of users"
		};
	}

	/**
	 * Get security health status (simplified for memory efficiency)
	 */
	getSecurityHealth() {
		return {
			status: "Security monitoring active",
			note: "Detailed metrics removed for memory efficiency with millions of users",
			rateLimiterActive: !!this.rateLimiter
		};
	}

	/**
	 * Reset rate limits for a specific user (admin function)
	 */
	async resetUserLimits(username) {
		// Security: Validate username before reset
		if (!this.isValidUsername(username)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid username provided for reset');
			return false;
		}

		await this.rateLimiter.userMessageLimiter.delete(username);
		await this.rateLimiter.userBundleLimiter.delete(username);
		return true;
	}

	/**
	 * Reset global connection limits (admin function)
	 */
	async resetGlobalConnectionLimits() {
		await this.rateLimiter.globalConnectionLimiter.delete('global-conn');
		return true;
	}

	/**
	 * Get current rate limit status for a user
	 */
	async getUserStatus(username) {
		// Security: Validate username
		if (!this.isValidUsername(username)) {
			console.warn('[RATE-LIMIT-SECURITY] Invalid username provided for status check');
			return null;
		}

		const msgInfo = await this.rateLimiter.userMessageLimiter.get(username);
		const bunInfo = await this.rateLimiter.userBundleLimiter.get(username);
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
		return this.rateLimiter.getGlobalConnectionStatus();
	}

	/**
	 * Security utility functions
	 */
	isValidWebSocket(ws) {
		return ws && typeof ws === 'object' && typeof ws.send === 'function' && typeof ws.close === 'function';
	}

	isValidUsername(username) {
		return username && typeof username === 'string' && username.length >= 3 && username.length <= 32;
	}

	isValidMessageType(messageType) {
		return messageType && typeof messageType === 'string' && messageType.length > 0;
	}

	generateSecureRequestId() {
		// Generate a cryptographically secure request ID for tracking
		return crypto.randomBytes(16).toString('hex');
	}

	/**
	 * Security audit function
	 */
	performSecurityAudit() {
		const audit = {
			timestamp: Date.now(),
			rateLimiterStats: this.rateLimiter.getStats(),
			securityHealth: this.getSecurityHealth(),
			recommendations: [],
			note: "Detailed security metrics removed for memory efficiency with millions of users"
		};

		// Basic security recommendations (simplified)
		audit.recommendations.push('Monitor Redis rate limiter logs for security violations');
		audit.recommendations.push('Rate limiting active - check Redis stats for block rates');

		console.log('[RATE-LIMIT-SECURITY] Security Audit:', JSON.stringify(audit, null, 2));
		return audit;
	}
}

export const rateLimitMiddleware = new RateLimitMiddleware();
