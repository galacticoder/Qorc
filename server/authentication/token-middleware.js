import { TokenService } from './token-service.js';
import { TokenDatabase } from './token-database.js';
import { blake3 } from '@noble/hashes/blake3.js';
import crypto from 'crypto';
import { withRedisClient } from '../presence/presence.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * JWT authentication middleware
 */
class TokenMiddleware {
  /**
   * Check rate limit with exponential backoff
   */
  static async checkRateLimit(identifier) {
    const bucketKey = `auth:rl:${identifier}`;
    const blockKey = `auth:block:${identifier}`;
    const nowSec = Math.floor(Date.now() / 1000);

    return await withRedisClient(async (client) => {
      const blocked = await client.ttl(blockKey);
      if (blocked && blocked > 0) {
        throw new Error('Rate limited');
      }
      const count = await client.incr(bucketKey);
      if (count === 1) {
        await client.expire(bucketKey, 60);
      }
      if (count > 3) {
        const backoff = Math.min(300, Math.pow(2, count - 3));
        await client.set(blockKey, '1', 'EX', backoff, 'NX');
        throw new Error(`Rate limited for ${backoff * 1000}ms`);
      }
      return { count, resetAt: (nowSec + (await client.ttl(bucketKey))) * 1000 };
    });
  }
  
  /**
   * WebSocket token authentication middleware
   * Validates tokens on connection and handles automatic refresh
   */
  static async authenticateWebSocket(ws, request, next) {
    const startTime = Date.now();
    
    try {
      // Rate limiting check
      const userId = request.headers['x-user-id'] || 'anonymous';
      await this.checkRateLimit(userId);
      
      // Extract token from different possible sources
      const token = this.extractTokenFromRequest(request);
      
      if (!token) {
        return this.handleAuthFailure(ws, 'no_token', 'No authentication token provided');
      }

      // Validate token format and extract payload
      const authResult = await this.validateToken(token, request);
      
      if (!authResult.valid) {
        return this.handleAuthFailure(ws, authResult.error, authResult.message, authResult.metadata);
      }

      // Enhance connection with authentication context
      this.enhanceConnectionContext(ws, authResult, request);

      // Log successful authentication
      await this.logAuthSuccess(authResult, request, 'websocket_auth');

      console.log(`[TOKEN-MW] WebSocket authenticated: user=${authResult.userId}, device=${authResult.deviceId}, duration=${Date.now() - startTime}ms`);
      
      return next();
      
    } catch (error) {
      console.error('[TOKEN-MW] WebSocket authentication error:', error);
      const sanitizedError = this.sanitizeErrorForClient(error);
      return this.handleAuthFailure(ws, sanitizedError.error, sanitizedError.message, { code: sanitizedError.code });
    }
  }

  /**
   * HTTP request token authentication middleware
   */
  static async authenticateHTTP(req, res, next) {
    const startTime = Date.now();
    
    try {
      // Set security headers
      this.setSecurityHeaders(res);
      
      // Rate limiting check
      const userId = req.headers['x-user-id'] || 'anonymous';
      await this.checkRateLimit(userId);
      
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        const csrfResult = this.validateCSRFToken(req);
        if (!csrfResult.valid) {
          return res.status(403).json({
            error: 'csrf_violation',
            message: 'Invalid CSRF token',
            code: 'CSRF_FAILED'
          });
        }
      }
      
      const token = this.extractTokenFromHTTPRequest(req);
      
      if (!token) {
        return res.status(401).json({
          error: 'unauthorized',
          message: 'No authentication token provided',
          code: 'NO_TOKEN'
        });
      }

      const authResult = await this.validateToken(token, req);
      
      if (!authResult.valid) {
        const statusCode = this.getHTTPStatusFromError(authResult.error);
        return res.status(statusCode).json({
          error: authResult.error,
          message: authResult.message,
          code: authResult.code,
          ...authResult.metadata
        });
      }

      // Add auth context to request
      req.auth = authResult;
      req.userId = authResult.userId;
      req.deviceId = authResult.deviceId;

      await this.logAuthSuccess(authResult, req, 'http_auth');
      
      console.log(`[TOKEN-MW] HTTP authenticated: user=${authResult.userId}, duration=${Date.now() - startTime}ms`);
      next();
      
    } catch (error) {
      console.error('[TOKEN-MW] HTTP authentication error:', error);
      const sanitizedError = this.sanitizeErrorForClient(error);
      res.status(500).json({
        error: sanitizedError.error,
        message: sanitizedError.message,
        code: sanitizedError.code
      });
    }
  }

  /**
   * Validate JWT token with security checks
   */
  static async validateToken(token, request) {
    const startTime = Date.now();
    const randomDelay = crypto.randomInt(50, 150);
    
    try {
      // Add random delay to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, randomDelay));
      
      // Parse token without verification first for blacklist check
      const unsafePayload = TokenService.parseTokenUnsafe(token);
      
      if (!unsafePayload) {
        return {
          valid: false,
          error: 'invalid_token',
          message: 'Invalid token format',
          code: 'INVALID_FORMAT'
        };
      }

      // Check if token is blacklisted
      const isBlacklisted = await TokenDatabase.isTokenBlacklisted(unsafePayload.jti);
      if (isBlacklisted) {
        return {
          valid: false,
          error: 'token_revoked',
          message: 'Token has been revoked',
          code: 'TOKEN_BLACKLISTED'
        };
      }

      // Verify token signature and claims
      const payload = await TokenService.verifyToken(token, 'access');
      
      // TLS required and binding enforced always
      if (!request || !request.socket || !request.socket.encrypted) {
        return {
          valid: false,
          error: 'tls_required',
          message: 'TLS is required',
          code: 'TLS_REQUIRED'
        };
      }
      let tlsFingerprint;
      try {
        tlsFingerprint = this.getTLSFingerprint(request);
      } catch (_e) {
        return {
          valid: false,
          error: 'tls_binding_violation',
          message: 'TLS fingerprint unavailable',
          code: 'TLS_FINGERPRINT_UNAVAILABLE'
        };
      }
      if (!payload.tlsBinding) {
        return {
          valid: false,
          error: 'tls_binding_missing',
          message: 'Token missing TLS binding',
          code: 'TLS_BINDING_MISSING'
        };
      }
      if (payload.tlsBinding !== tlsFingerprint) {
        return {
          valid: false,
          error: 'tls_binding_violation',
          message: 'Token bound to different TLS session',
          code: 'TLS_MISMATCH'
        };
      }
      
      // security validations
      const securityCheck = await this.performSecurityChecks(payload, request);
      if (!securityCheck.valid) {
        return securityCheck;
      }

      // Check if token is close to expiration and needs refresh
      const refreshMetadata = this.checkTokenRefreshNeeds(payload);

      const authResult = {
        valid: true,
        userId: payload.sub,
        deviceId: payload.deviceId,
        scopes: payload.scopes || [],
        tokenId: payload.jti,
        issuedAt: payload.iat,
        expiresAt: payload.exp,
        securityContext: payload.sec || {},
        needsRefresh: refreshMetadata.needsRefresh,
        refreshUrgency: refreshMetadata.urgency
      };
      
      // Detect anomalous usage patterns
      const anomalyResult = await this.detectAnomalousUsage(authResult, request);
      if (anomalyResult.requiresReauth) {
        return {
          valid: false,
          error: 'security_check_required',
          message: 'Additional security verification required',
          code: 'REAUTH_REQUIRED'
        };
      }
      
      authResult.anomalies = anomalyResult.anomalies || [];
      return authResult;

    } catch (error) {
      if (error.message.includes('expired')) {
        return {
          valid: false,
          error: 'token_expired',
          message: 'Access token has expired',
          code: 'TOKEN_EXPIRED',
          metadata: { needsRefresh: true }
        };
      }
      
      if (error.message.includes('signature')) {
        return {
          valid: false,
          error: 'invalid_signature',
          message: 'Invalid token signature',
          code: 'INVALID_SIGNATURE'
        };
      }

      return {
        valid: false,
        error: 'validation_failed',
        message: 'Token validation failed',
        code: 'VALIDATION_ERROR'
      };
    } finally {
      const elapsed = Date.now() - startTime;
      const minTime = 200;
      if (elapsed < minTime) {
        await new Promise(resolve => setTimeout(resolve, minTime - elapsed));
      }
    }
  }

  /**
   * security checks on token
   */
  static async performSecurityChecks(payload, request) {
    const now = Math.floor(Date.now() / 1000);
    
    // Check token freshness using centralized policy (max age per token type)
    try {
      const { TokenSecurityManager } = await import('./token-security.js');
      const maxAge = TokenSecurityManager.getMaxTokenAge(payload.type || 'access');
      if (payload.iat && (now - payload.iat) > maxAge) {
        return {
          valid: false,
          error: 'token_too_old',
          message: 'Token was issued too long ago',
          code: 'TOKEN_STALE'
        };
      }
    } catch (_e) {
    }

    // Validate nonce for replay protection
    if (payload.nonce) {
      const nonceResult = await this.validateNonce(payload.nonce, payload.jti, payload.exp);
      if (!nonceResult.valid) {
        return nonceResult;
      }
    }

    // Validate device binding if present
    if (payload.deviceId && request) {
      const deviceValidation = await this.validateDeviceBinding(payload, request);
      if (!deviceValidation.valid) {
        return deviceValidation;
      }
    }

    // Check risk score and enforce additional security measures
    if (payload.sec && payload.sec.risk === 'high') {
      console.warn(`[TOKEN-MW] High-risk token detected: ${payload.jti} for user ${payload.sub}`);
      
      // Increment high-risk access counter in Redis
      await this.trackHighRiskAccess(payload.sub, payload.jti);
      
      // Check if user has exceeded high-risk access threshold
      const riskCheck = await this.checkHighRiskThreshold(payload.sub);
      if (riskCheck.exceeded) {
        console.error(`[TOKEN-MW] High-risk threshold exceeded for user ${payload.sub}`);
        return {
          valid: false,
          error: 'security_check_required',
          message: 'Additional security verification required',
          code: 'REAUTH_REQUIRED_RISK',
          metadata: {
            reason: 'high_risk_threshold',
            cooldownSeconds: riskCheck.cooldownSeconds
          }
        };
      }
      
      // Apply stricter rate limiting for high-risk tokens
      const riskRateLimit = await this.checkHighRiskRateLimit(payload.sub);
      if (!riskRateLimit.allowed) {
        return {
          valid: false,
          error: 'rate_limit_exceeded',
          message: 'High-risk access rate limit exceeded',
          code: 'RISK_RATE_LIMITED'
        };
      }
    }

    // Validate scopes are not escalated
    if (!this.validateScopes(payload.scopes)) {
      return {
        valid: false,
        error: 'invalid_scopes',
        message: 'Invalid or escalated token scopes',
        code: 'SCOPE_VIOLATION'
      };
    }

    return { valid: true };
  }

  /**
   * Validate nonce for replay attack protection
   */
  static async validateNonce(nonce, tokenId, expiresAt) {
    try {
      const nonceKey = `nonce:${nonce}`;
      const nonceUsed = await this.checkNonceUsed(nonceKey);
      
      if (nonceUsed) {
        console.error(`[TOKEN-MW] Nonce replay detected: ${nonce}`);
        return {
          valid: false,
          error: 'replay_attack',
          message: 'Token replay detected',
          code: 'NONCE_REUSED'
        };
      }
      
      // Mark nonce as used with TTL matching token expiry
      const ttlSeconds = Math.max(1, expiresAt - Math.floor(Date.now() / 1000));
      await this.markNonceUsed(nonceKey, ttlSeconds);
      
      return { valid: true };
    } catch (error) {
      console.error('[TOKEN-MW] Nonce validation error:', error);
      // Fail open for nonce validation errors to avoid DoS
      return { valid: true };
    }
  }
  
  /**
   * Check if nonce has been used 
   */
  static async checkNonceUsed(nonceKey) {
    return await withRedisClient(async (client) => {
      const exists = await client.exists(nonceKey);
      return exists === 1;
    });
  }
  
  /**
   * Mark nonce as used with TTL 
   */
  static async markNonceUsed(nonceKey, ttlSeconds) {
    await withRedisClient(async (client) => {
      await client.set(nonceKey, '1', 'EX', Math.max(1, ttlSeconds), 'NX');
    });
  }
  
  /**
   * Track high-risk token access in Redis
   */
  static async trackHighRiskAccess(userId, tokenId) {
    const key = `highrisk:${userId}`;
    const now = Math.floor(Date.now() / 1000);
    
    try {
      await withRedisClient(async (client) => {
        // Add timestamp to sorted set (score = timestamp)
        await client.zadd(key, now, `${tokenId}:${now}`);
        // Set expiry to 1 hour
        await client.expire(key, 3600);
      });
    } catch (error) {
      console.error('[TOKEN-MW] Failed to track high-risk access:', error);
    }
  }
  
  /**
   * Check if user has exceeded high-risk access threshold
   * Threshold: More than 10 high-risk accesses in 10 minutes
   */
  static async checkHighRiskThreshold(userId) {
    const key = `highrisk:${userId}`;
    const now = Math.floor(Date.now() / 1000);
    const tenMinutesAgo = now - 600;
    
    try {
      return await withRedisClient(async (client) => {
        // Count high-risk accesses in the last 10 minutes
        const count = await client.zcount(key, tenMinutesAgo, now);
        
        if (count > 10) {
          // Set a cooldown period
          const cooldownKey = `highrisk:cooldown:${userId}`;
          const cooldownSeconds = 300; // 5 minutes
          await client.set(cooldownKey, '1', 'EX', cooldownSeconds, 'NX');
          
          return {
            exceeded: true,
            count,
            cooldownSeconds
          };
        }
        
        return { exceeded: false, count };
      });
    } catch (error) {
      console.error('[TOKEN-MW] Failed to check high-risk threshold:', error);
      return { exceeded: false, count: 0 };
    }
  }
  
  /**
   * Apply stricter rate limiting for high-risk tokens
   * Limit: 30 requests per minute for high-risk tokens
   */
  static async checkHighRiskRateLimit(userId) {
    const key = `highrisk:ratelimit:${userId}`;
    
    try {
      return await withRedisClient(async (client) => {
        const count = await client.incr(key);
        
        if (count === 1) {
          // Set expiry to 60 seconds on first request
          await client.expire(key, 60);
        }
        
        if (count > 30) {
          const ttl = await client.ttl(key);
          return {
            allowed: false,
            resetIn: ttl > 0 ? ttl : 60
          };
        }
        
        return {
          allowed: true,
          remaining: Math.max(0, 30 - count)
        };
      });
    } catch (error) {
      console.error('[TOKEN-MW] Failed to check high-risk rate limit:', error);
      return { allowed: true };
    }
  }
  
  /**
   * Validate device binding for more security
   */
  static async validateDeviceBinding(payload, request) {
    if (!payload.device_binding) {
      return { valid: true };
    }

    // Extract device context from request
    const deviceContext = this.extractDeviceContext(request);
    const expectedBinding = await this.calculateDeviceBinding(payload.deviceId, deviceContext);

    if (payload.device_binding !== expectedBinding) {
      await TokenDatabase.logAuthEvent({
        userId: payload.sub,
        deviceId: payload.deviceId,
        action: 'device_binding_violation',
        tokenId: payload.jti,
        success: false,
        failureReason: 'Device binding mismatch',
        securityFlags: JSON.stringify({ 
          expected: expectedBinding.substring(0, 8) + '...',
          received: payload.device_binding.substring(0, 8) + '...'
        })
      });

      return {
        valid: false,
        error: 'device_binding_violation',
        message: 'Device binding validation failed',
        code: 'DEVICE_MISMATCH'
      };
    }

    return { valid: true };
  }

  /**
   * Check if token needs refresh
   */
  static checkTokenRefreshNeeds(payload) {
    const now = Math.floor(Date.now() / 1000);
    const timeToExpiration = payload.exp - now;
    const tokenLifetime = payload.exp - payload.iat;
    
    // Token needs refresh if less than 25% of lifetime remains
    const refreshThreshold = tokenLifetime * 0.25;
    const needsRefresh = timeToExpiration <= refreshThreshold;
    
    let urgency = 'none';
    if (timeToExpiration <= 60) urgency = 'critical'; // Less than 1 minute
    else if (timeToExpiration <= 300) urgency = 'high'; // Less than 5 minutes
    else if (needsRefresh) urgency = 'medium';
    
    return { needsRefresh, urgency, timeToExpiration };
  }

  /**
   * Handle token refresh for WebSocket connections
   */
  static async handleTokenRefresh(ws, refreshToken) {
    try {
      // Verify refresh token
      const refreshPayload = await TokenService.verifyToken(refreshToken, 'refresh');
      
      // Check if refresh token is still valid in database
      const tokenRecord = await TokenDatabase.getRefreshToken(refreshPayload.jti, refreshToken);
      if (!tokenRecord) {
        throw new Error('Refresh token not found or invalid');
      }

      // Generate new access token
      const newTokens = await TokenService.refreshAccessToken(refreshToken);
      
      // Send new tokens to client
      await sendSecureMessage(ws, {
        type: 'token_refreshed',
        accessToken: newTokens.accessToken,
        expiresIn: newTokens.expiresIn,
        tokenType: newTokens.tokenType
      });

      await TokenDatabase.logAuthEvent({
        userId: refreshPayload.sub,
        deviceId: refreshPayload.deviceId,
        action: 'token_refreshed',
        tokenType: 'access',
        success: true
      });

      console.log(`[TOKEN-MW] Token refreshed for user ${refreshPayload.sub}`);
      return true;
      
    } catch (error) {
      console.error('[TOKEN-MW] Token refresh failed:', error);
      
      await sendSecureMessage(ws, {
        type: 'token_refresh_failed',
        error: 'refresh_failed',
        message: 'Failed to refresh token',
        requiresReauth: true
      });
      
      return false;
    }
  }

  /**
   * Extract token from various request sources
   */
  static extractTokenFromRequest(request) {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null; 
    }
    return authHeader.slice(7);
  }

  static extractTokenFromHTTPRequest(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.slice(7);
  }

  /**
   * Extract device context from request
   */
  static extractDeviceContext(_request) {
    return {
      timestamp: Math.floor(Date.now() / 86400000)
    };
  }


  /**
   * Calculate device binding hash
   */
  static async calculateDeviceBinding(deviceId, context) {
    const bindingData = {
      deviceId,
      userAgent: context.userAgent,
      clientVersion: context.clientVersion,
      timestamp: context.timestamp,
      acceptLanguage: context.acceptLanguage,
      acceptEncoding: context.acceptEncoding,
      dnt: context.dnt,
      secFetchSite: context.secFetchSite,
      tlsCipher: context.tlsCipher,
      tlsVersion: context.tlsVersion,
      httpVersion: context.httpVersion,
      canvasFingerprint: context.canvasFingerprint
    };
    
    const secret = await this.getDeviceBindingSecret();
    const key = blake3(Buffer.from(secret)).slice(0, 32);
    const mac = blake3(Buffer.from(JSON.stringify(bindingData)), { key });
    return Buffer.from(mac).toString('hex').slice(0, 16);
  }
  
  /**
   * Detect anomalous token usage patterns (device-based)
   */
  static async detectAnomalousUsage(authResult, request) {
    try {
      const usage = await this.getTokenUsagePattern(authResult.tokenId);
      const anomalies = [];
      
      // Detect device changes - check if current device differs from token's device
      if (authResult.deviceId && request.deviceId && authResult.deviceId !== request.deviceId) {
        anomalies.push('device_mismatch');
      }
      
      // Unusual request rate (possible automated attack)
      if (usage.requestsLastHour > 1000) {
        anomalies.push('high_request_rate');
      }
      
      if (anomalies.length > 0) {
        await TokenDatabase.logAuthEvent({
          userId: authResult.userId,
          deviceId: authResult.deviceId,
          action: 'anomaly_detected',
          tokenId: authResult.tokenId,
          success: false,
          securityFlags: JSON.stringify({ anomalies })
        });
        
        // Trigger more security measures for device mismatch
        if (anomalies.includes('device_mismatch')) {
          return { requiresReauth: true, reason: 'device_changed', anomalies };
        }
      }
      
      return { anomalies };
    } catch (error) {
      console.error('[TOKEN-MW] Anomaly detection error:', error);
      return { anomalies: [] };
    }
  }
  
  /**
   * Get token usage pattern from auth audit logs
   */
  static async getTokenUsagePattern(tokenId) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const oneHourAgo = now - 3600;
      const oneDayAgo = now - 86400;

      const { getPgPool } = await import('../database/database.js');
      const pool = await getPgPool();

      // Get recent usage stats for this token (last 24h)
      const recentRes = await pool.query(
        `
        SELECT MAX(timestamp) AS lastSeen, COUNT(*) AS totalRequests
        FROM auth_audit_log
        WHERE tokenId = $1 AND timestamp > $2
        `,
        [tokenId, oneDayAgo],
      );

      // Get requests in last hour
      const hourlyRes = await pool.query(
        `
        SELECT COUNT(*) AS requestCount
        FROM auth_audit_log
        WHERE tokenId = $1 AND timestamp > $2
        `,
        [tokenId, oneHourAgo],
      );

      const recentStats = recentRes.rows[0] || {};
      const hourlyStats = hourlyRes.rows[0] || {};

      return {
        lastSeen: Number(recentStats.lastSeen ?? recentStats.lastseen ?? 0),
        requestsLastHour: Number(hourlyStats.requestCount ?? hourlyStats.requestcount ?? 0),
      };
    } catch (error) {
      console.error('[TOKEN-MW] Failed to get token usage pattern:', error);
      // Return safe defaults on error
      return {
        lastSeen: 0,
        requestsLastHour: 0,
      };
    }
  }
  
  /**
   * Get device binding secret for HMAC
   */
  static async getDeviceBindingSecret() {
    const env = process.env.DEVICE_BINDING_SECRET;
    if (env && Buffer.from(env).length >= 32) return Buffer.from(env);
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const configDir = path.join(__dirname, '../config');
    const secretPath = path.join(configDir, 'device_binding.secret');
    try {
      const b = await fs.readFile(secretPath);
      if (b.length >= 32) return b;
    } catch (_e) {}
    await fs.mkdir(configDir, { recursive: true });
    const strong = crypto.randomBytes(64);
    await fs.writeFile(secretPath, strong, { mode: 0o600 });
    return strong;
  }

  /**
   * Validate token scopes
   */
  static validateScopes(scopes) {
    if (!Array.isArray(scopes)) return false;
    
    const allowedScopes = [
      'chat:read', 'chat:write', 'chat:delete', 'chat:reconnect',
      'user:profile', 'user:settings', 'admin:users', 'admin:server'
    ];
    
    return scopes.every(scope => 
      typeof scope === 'string' && 
      allowedScopes.includes(scope) && 
      scope.length <= 50
    );
  }

  /**
   *  better the WebSocket connection with authentication context
   */
  static enhanceConnectionContext(ws, authResult) {
    ws.auth = authResult;
    ws.userId = authResult.userId;
    ws.deviceId = authResult.deviceId;
    ws.tokenId = authResult.tokenId;
    ws.scopes = authResult.scopes;
    ws.authenticated = true;
    ws.authTime = Date.now();
    
    // Set up token refresh monitoring
    if (authResult.needsRefresh) {
      ws.needsTokenRefresh = true;
      ws.refreshUrgency = authResult.refreshUrgency;
    }
  }

  /**
   * Handle authentication failures
   */
  static async handleAuthFailure(ws, error, message, metadata = {}) {
    const response = {
      type: 'auth_error',
      error,
      message,
      code: error.toUpperCase(),
      timestamp: Date.now(),
      ...metadata
    };

    await sendSecureMessage(ws, response);
    
    const nonFatalErrors = ['token_expired', 'needs_refresh'];
    if (!nonFatalErrors.includes(error)) {
      setTimeout(() => {
        ws.close(1008, message);
      }, 1000);
    }

    console.warn(`[TOKEN-MW] WebSocket auth failure: ${error} - ${message}`);
  }

  /**
   * Set security headers for HTTP responses
   */
  static setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  }
  
  /**
   * Validate CSRF token for state-changing operations
   */
  static validateCSRFToken(req) {
    const csrfToken = req.headers['x-csrf-token'];
    const sessionCsrf = req.session?.csrfToken;
    
    if (!csrfToken || !sessionCsrf) {
      return { valid: false, reason: 'missing_csrf_token' };
    }
    
    if (!this.constantTimeCompare(csrfToken, sessionCsrf)) {
      return { valid: false, reason: 'csrf_token_mismatch' };
    }
    
    return { valid: true };
  }
  
  /**
   * Constant-time string comparison to prevent timing attacks
   */
  static constantTimeCompare(a, b) {
    if (!a || !b) return false;
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }
  
  /**
   * Sanitize error messages to prevent information leakage
   */
  static sanitizeErrorForClient(error) {
    const genericMessage = 'Authentication failed';
    
    // Only return specific messages for known safe errors
    const safeErrors = {
      'Token expired': { message: 'Token expired', code: 'TOKEN_EXPIRED', error: 'token_expired' },
      'Invalid token format': { message: 'Invalid token format', code: 'INVALID_FORMAT', error: 'invalid_token' },
      'Token has been revoked': { message: 'Token revoked', code: 'TOKEN_REVOKED', error: 'token_revoked' },
      'Rate limited': { message: 'Rate limited', code: 'RATE_LIMITED', error: 'rate_limited' },
      'Token was issued too long ago': { message: 'Token was issued too long ago', code: 'TOKEN_STALE', error: 'token_too_old' }
    };
    
    for (const [match, result] of Object.entries(safeErrors)) {
      if (error.message && error.message.includes(match)) {
        return result;
      }
    }
    
    // Log full error internally, return generic to client
    console.error('[TOKEN-MW] Auth error:', error);
    return { 
      message: genericMessage, 
      code: 'AUTH_FAILED', 
      error: 'auth_failed' 
    };
  }
  
  /**
   * Get appropriate HTTP status code for auth errors
   */
  static getHTTPStatusFromError(error) {
    const statusMap = {
      'no_token': 401,
      'invalid_token': 401,
      'token_expired': 401,
      'invalid_signature': 401,
      'token_revoked': 401,
      'device_binding_violation': 403,
      'invalid_scopes': 403,
      'token_too_old': 401,
      'validation_failed': 400,
      'tls_binding_violation': 403,
      'rate_limited': 429
    };
    
    return statusMap[error] || 401;
  }

  /**
   * Log successful authentication
   */
  static async logAuthSuccess(authResult, request, action) {
    const context = this.extractDeviceContext(request);
    
    await TokenDatabase.logAuthEvent({
      userId: authResult.userId,
      deviceId: authResult.deviceId,
      action,
      tokenType: 'access',
      tokenId: authResult.tokenId,
      success: true,
      userAgent: context.userAgent,
      riskScore: authResult.securityContext.risk || 'low'
    });
  }

  /**
   * Get TLS fingerprint for session binding
   */
  static getTLSFingerprint(request) {
    const socket = (request && request.socket) ? request.socket : request;
    if (!socket || !socket.encrypted) {
      throw new Error('TLS_REQUIRED');
    }
    try {
      const cert = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate() : null;
      const certRaw = cert && cert.raw && cert.raw.byteLength ? cert.raw : null;
      const cipher = typeof socket.getCipher === 'function' ? socket.getCipher() : null;
      const session = typeof socket.getSession === 'function' ? socket.getSession() : null;
      const protocol = typeof socket.getProtocol === 'function' ? socket.getProtocol() : null;

      const tlsData = {
        sessionId: session && Buffer.isBuffer(session) ? session.toString('hex') : null,
        cipher: cipher && typeof cipher.name === 'string' ? cipher.name : null,
        protocol: protocol || null,
        serverName: socket.servername || null,
        certFingerprint: certRaw ? crypto.createHash('sha256').update(certRaw).digest('hex') : null
      };

      const hasAny = Object.values(tlsData).some(v => v !== null);
      if (!hasAny) {
        throw new Error('TLS_FINGERPRINT_UNAVAILABLE');
      }

      return blake3(Buffer.from(JSON.stringify(tlsData))).slice(0, 16).toString('hex');
    } catch (error) {
      console.warn('[TOKEN-MW] Failed to get TLS fingerprint:', error?.message || error);
      throw new Error('TLS_FINGERPRINT_UNAVAILABLE');
    }
  }
  

  /**
   * Create authentication context for new connections
   */
  static async createAuthContext(_userId, _deviceId, _request) {
    const deviceFingerprint = null;
    const securityContext = {};
    return {
      deviceFingerprint,
      securityContext,
      userAgent: null
    };
  }
}

export { TokenMiddleware };
export default TokenMiddleware;
