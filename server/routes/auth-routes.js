import express from 'express';
import crypto from 'crypto';
import { TokenService } from '../authentication/token-service.js';
import { TokenDatabase } from '../authentication/token-database.js';
import { TokenSecurityManager } from '../authentication/token-security.js';
import { TokenMiddleware } from '../authentication/token-middleware.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { UserDatabase } from '../database/database.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { withRedisClient } from '../presence/presence.js';

const router = express.Router();

const USERNAME_REGEX = /^[A-Za-z0-9_-]{3,32}$/;

function normalizeUsername(username) {
  if (typeof username !== 'string') return null;
  const trimmed = username.trim();
  return USERNAME_REGEX.test(trimmed) ? trimmed : null;
}

// Anonymize identifier using BLAKE3
function anonymizeIdentifier(identifier) {
  if (!identifier || typeof identifier !== 'string') {
    return 'anon';
  }
  const hash = CryptoUtils.Hash.blake3(Buffer.from(identifier));
  return Buffer.from(hash).slice(0, 12).toString('hex');
}

let rateLimit;
try {
  rateLimit = (await import('express-rate-limit')).default;
} catch (_error) {
  cryptoLogger.error('[AUTH-ROUTES] FATAL: express-rate-limit package is required but not available');
  cryptoLogger.error('[AUTH-ROUTES] FATAL: Install express-rate-limit: npm install express-rate-limit');
  process.emit('SIGINT');
  throw new Error('express-rate-limit package is required');
}

const rateLimitMiddleware = {
  checkAuthRateLimit: rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
      error: 'Too many authentication attempts',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        error: 'Too many authentication attempts',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
      });
    },
    keyGenerator: (req) => {
      const username = req.body?.username;
      if (username && typeof username === 'string') {
        return `user:${anonymizeIdentifier(username)}`;
      }
      return 'anonymous';
    }
  }),
  checkTokenVerificationRateLimit: rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        error: 'Too many token verification attempts',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
      });
    },
    keyGenerator: (req) => {
      const token = req.body?.token;
      if (token && typeof token === 'string') {
        const hash = CryptoUtils.Hash.blake3(Buffer.from(token));
        return `token:${Buffer.from(hash).slice(0, 12).toString('hex')}`;
      }
      return 'anonymous';
    }
  })
};

/**
 * POST /api/auth/login
 * User login 
 */
router.post('/login', rateLimitMiddleware.checkAuthRateLimit, async (req, res) => {
  try {
    const { username, password, deviceInfo } = req.body || {};
    if (!(req.socket && req.socket.encrypted)) {
      return res.status(403).json({ error: 'TLS is required', code: 'TLS_REQUIRED' });
    }
    const deviceId = deriveDeviceId(req);
    let tlsBinding;
    try {
      tlsBinding = TokenMiddleware.getTLSFingerprint(req);
    } catch (_e) {
      return res.status(403).json({ error: 'TLS fingerprint required', code: 'TLS_FINGERPRINT_REQUIRED' });
    }

    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername || typeof password !== 'string') {
      return res.status(400).json({
        error: 'Invalid username or password format.',
        code: 'INVALID_CREDENTIALS_FORMAT'
      });
    }

    if (password.length === 0 || password.length > 1024) {
      return res.status(400).json({
        error: 'Invalid username or password format.',
        code: 'INVALID_CREDENTIALS_FORMAT'
      });
    }

    const userData = await UserDatabase.loadUser(normalizedUsername);
    if (!userData) {
      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Verify password 
    const isPasswordValid = await CryptoUtils.Password.verifyPassword(userData.passwordHash, password);
    if (!isPasswordValid) {
      return res.status(401).json({
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }


    // Issue tokens 
    if (!tlsBinding) {
      return res.status(403).json({ error: 'TLS binding missing', code: 'TLS_BINDING_MISSING' });
    }

    const tokenResult = await TokenService.createTokenPair(
      userData.username,
      deviceId,
      tlsBinding
    );

    if (!tokenResult.success) {
      return res.status(500).json({
        error: 'Token generation failed',
        code: 'TOKEN_GENERATION_ERROR'
      });
    }

    const suspiciousActivity = await TokenSecurityManager.detectSuspiciousActivity(
      userData.username,
      tokenResult.tokenId,
      {
        newDevice: !deviceInfo?.knownDevice,
        loginAttempt: true,
        userAgent: req.headers['user-agent']
      }
    );

    if (suspiciousActivity.suspicious) {
      cryptoLogger.warn('[AUTH-API] Suspicious login activity detected', {
        user: anonymizeIdentifier(userData.username),
        flags: suspiciousActivity.flags
      });
    }

    res.json({
      success: true,
      user: {
        id: userData.username,
        username: userData.username,
      },
      tokens: {
        accessToken: tokenResult.accessToken,
        refreshToken: tokenResult.refreshToken,
        expiresIn: tokenResult.expiresIn,
        tokenType: tokenResult.tokenType,
        quantumSecure: true
      },
      security: {
        riskScore: suspiciousActivity.riskScore,
        deviceId,
        suspicious: suspiciousActivity.suspicious
      }
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Login error', error);
    res.status(500).json({
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
});

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh', rateLimitMiddleware.checkAuthRateLimit, async (req, res) => {
  try {
    const { refreshToken, deviceInfo: _deviceInfo } = req.body || {};
    const deviceId = req.headers['x-device-id'];
    if (!(req.socket && req.socket.encrypted)) {
      return res.status(403).json({ error: 'TLS is required', code: 'TLS_REQUIRED' });
    }

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token required',
        code: 'MISSING_REFRESH_TOKEN'
      });
    }

    // Parse refresh token to extract tokenId
    const parsedToken = TokenService.parseTokenUnsafe(refreshToken);
    if (!parsedToken || !parsedToken.jti) {
      return res.status(400).json({
        error: 'Invalid refresh token format',
        code: 'INVALID_TOKEN_FORMAT'
      });
    }

    // Validate refresh token using tokenId
    const tokenInfo = await TokenDatabase.getRefreshToken(parsedToken.jti, refreshToken);
    if (!tokenInfo || tokenInfo.isRevoked) {
      return res.status(401).json({
        error: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    if (!deviceId || deviceId !== tokenInfo.deviceId) {
      return res.status(401).json({ error: 'Device mismatch', code: 'DEVICE_MISMATCH' });
    }

    const nonceKey = `refresh:nonce:${parsedToken.jti}`;
    const nonce = await withRedisClient(async (client) => await client.get(nonceKey));

    if (!nonce) {
      return res.status(400).json({ error: 'Nonce required', code: 'NONCE_REQUIRED' });
    }

    const signatureBase64 = req.headers['x-device-proof'];
    if (!signatureBase64 || typeof signatureBase64 !== 'string') {
      return res.status(401).json({ error: 'Missing device proof', code: 'DEVICE_PROOF_REQUIRED' });
    }

    const sessions = await TokenDatabase.getUserSessions(tokenInfo.userId);
    const session = (sessions || []).find(s => s.deviceId === tokenInfo.deviceId);
    const devicePubPem = session?.securityFlags?.deviceEd25519PublicKey;
    if (!devicePubPem || typeof devicePubPem !== 'string') {
      return res.status(401).json({ error: 'Device key not registered', code: 'DEVICE_KEY_MISSING' });
    }
    try {
      const keyObj = crypto.createPublicKey({ key: devicePubPem, format: 'pem', type: 'spki' });
      const msg = Buffer.from(`device-proof:refresh:v1|${nonce}|${parsedToken.jti}|${tokenInfo.deviceId}`, 'utf8');
      const sig = Buffer.from(signatureBase64, 'base64');
      const ok = crypto.verify(null, msg, keyObj, sig);
      if (!ok) {
        return res.status(401).json({ error: 'Invalid device proof', code: 'DEVICE_PROOF_INVALID' });
      }

      await withRedisClient(async (client) => { await client.del(nonceKey); });
    } catch (_e) {
      return res.status(401).json({ error: 'Device proof error', code: 'DEVICE_PROOF_ERROR' });
    }

    const securityValidation = await TokenSecurityManager.validateTokenSecurity(refreshToken, {});

    if (!securityValidation.valid) {
      cryptoLogger.warn('[AUTH-API] Token security validation failed', {
        reason: securityValidation.reason,
        token: anonymizeIdentifier(tokenInfo?.id || 'unknown')
      });
      await TokenSecurityManager.revokeToken(tokenInfo.id, `security_violation:${securityValidation.reason}`);

      return res.status(401).json({
        error: 'Token security validation failed',
        code: 'SECURITY_VALIDATION_FAILED'
      });
    }

    const suspiciousActivity = await TokenSecurityManager.detectSuspiciousActivity(
      tokenInfo.userId,
      tokenInfo.id,
      {
        tokenRefresh: true,
        userAgent: req.headers['user-agent'] || 'unknown',
        deviceId: deviceId || 'unknown'
      }
    );

    if (suspiciousActivity.suspicious) {
      cryptoLogger.warn('[AUTH-API] Suspicious refresh activity detected', {
        user: anonymizeIdentifier(tokenInfo.userId),
        flags: suspiciousActivity.flags
      });

      if (suspiciousActivity.riskScore === 'high' || suspiciousActivity.riskScore === 'critical') {
        await TokenSecurityManager.revokeToken(tokenInfo.id, 'suspicious_activity_detected');

        return res.status(401).json({
          error: 'Suspicious activity detected',
          code: 'SUSPICIOUS_ACTIVITY'
        });
      }
    }

    // Issue new tokens 
    let tlsBinding;
    try {
      tlsBinding = TokenMiddleware.getTLSFingerprint(req);
    } catch (_e) {
      return res.status(403).json({ error: 'TLS fingerprint required', code: 'TLS_FINGERPRINT_REQUIRED' });
    }
    if (!tlsBinding) {
      return res.status(403).json({ error: 'TLS binding missing', code: 'TLS_BINDING_MISSING' });
    }
    const tokenResult = await TokenService.createTokenPair(
      tokenInfo.userId,
      tokenInfo.deviceId,
      tlsBinding
    );

    if (!tokenResult.success) {
      return res.status(500).json({
        error: 'Token generation failed',
        code: 'TOKEN_GENERATION_ERROR'
      });
    }

    // Revoke old refresh token (rotation)
    await TokenDatabase.revokeRefreshToken(tokenInfo.id, 'token_rotation');

    res.json({
      success: true,
      tokens: {
        accessToken: tokenResult.accessToken,
        refreshToken: tokenResult.refreshToken,
        expiresIn: tokenResult.expiresIn,
        tokenType: tokenResult.tokenType,
        quantumSecure: true
      },
      security: {
        riskScore: suspiciousActivity.riskScore,
        suspicious: suspiciousActivity.suspicious
      }
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Token refresh error', error);
    res.status(500).json({
      error: 'Token refresh failed',
      code: 'REFRESH_ERROR'
    });
  }
});

/**
 * POST /api/auth/logout
 * Logout from current device
 */
router.post('/logout', TokenMiddleware.authenticateHTTP, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const _userId = req.user?.sub;

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token required',
        code: 'MISSING_REFRESH_TOKEN'
      });
    }

    const parsedToken = TokenService.parseTokenUnsafe(refreshToken);
    if (parsedToken && parsedToken.jti) {
      const tokenInfo = await TokenDatabase.getRefreshToken(parsedToken.jti, refreshToken);
      if (tokenInfo) {
        await TokenSecurityManager.revokeToken(tokenInfo.id, 'user_logout', 'user');
      }
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Logout error', error);
    res.status(500).json({
      error: 'Logout failed',
      code: 'LOGOUT_ERROR'
    });
  }
});

/**
 * POST /api/auth/logout-all
 * Logout from all devices
 */
router.post('/logout-all', TokenMiddleware.authenticateHTTP, async (req, res) => {
  try {
    const userId = req.user?.sub;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const result = await TokenSecurityManager.logoutFromAllDevices(userId, 'user_request', 'user');

    if (result.success) {
      res.json({
        success: true,
        message: 'Logged out from all devices successfully',
        devicesLoggedOut: result.devicesLoggedOut,
        tokensRevoked: result.tokensRevoked
      });
    } else {
      res.status(500).json({
        error: 'Logout from all devices failed',
        code: 'LOGOUT_ALL_ERROR'
      });
    }

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Logout all error', error);
    res.status(500).json({
      error: 'Logout from all devices failed',
      code: 'LOGOUT_ALL_ERROR'
    });
  }
});

/**
 * GET /api/auth/profile
 * Get user profile
 */
router.get('/profile', TokenMiddleware.authenticateHTTP, async (req, res) => {
  try {
    const userId = req.user?.sub;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Get user from database
    const user = await UserDatabase.loadUser(userId);
    if (!user) {
      return res.status(404).json({
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Return user profile 
    res.json({
      success: true,
      user: {
        id: user.username,
        username: user.username,
      }
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Profile error', error);
    res.status(500).json({
      error: 'Profile retrieval failed',
      code: 'PROFILE_ERROR'
    });
  }
});

/**
 * GET /api/auth/sessions
 * Get user's active sessions
 */
router.get('/sessions', TokenMiddleware.authenticateHTTP, async (req, res) => {
  try {
    const userId = req.user?.sub;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const sessions = await TokenDatabase.getUserSessions(userId);

    res.json({
      success: true,
      sessions: sessions.map(session => ({
        deviceId: session.deviceId,
        deviceName: session.deviceName,
        deviceType: session.deviceType,
        lastSeen: session.lastSeen,
        createdAt: session.createdAt,
        isCurrent: session.deviceId === req.headers['x-device-id'],
        riskScore: session.riskScore,
        clientVersion: session.clientVersion
      }))
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Sessions error', error);
    res.status(500).json({
      error: 'Failed to retrieve sessions',
      code: 'SESSIONS_ERROR'
    });
  }
});

/**
 * DELETE /api/auth/sessions/:deviceId
 * Revoke session for specific device
 */
router.delete('/sessions/:deviceId', TokenMiddleware.authenticateHTTP, async (req, res) => {
  try {
    const userId = req.user?.sub;
    const { deviceId } = req.params;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    if (!deviceId) {
      return res.status(400).json({
        error: 'Device ID required',
        code: 'MISSING_DEVICE_ID'
      });
    }

    const revokedCount = await TokenDatabase.revokeDeviceTokens(userId, deviceId, 'device_revocation');

    res.json({
      success: true,
      message: 'Session revoked successfully',
      tokensRevoked: revokedCount
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Session revocation error', error);
    res.status(500).json({
      error: 'Session revocation failed',
      code: 'SESSION_REVOCATION_ERROR'
    });
  }
});

/**
 * GET /api/auth/security-report
 * Get security report for the user
 */
router.get('/security-report', TokenMiddleware.authenticateHTTP, async (req, res) => {
  try {
    const userId = req.user?.sub;

    let timeframeHours = 24;
    if (req.query.hours !== undefined) {
      const parsedHours = parseInt(req.query.hours, 10);
      if (isNaN(parsedHours) || parsedHours < 1 || parsedHours > 8760) {
        return res.status(400).json({
          error: 'Invalid hours parameter. Must be an integer between 1 and 8760.',
          code: 'INVALID_HOURS_PARAMETER'
        });
      }
      timeframeHours = parsedHours;
    }

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    // Generate security report filtered for current user
    const report = await TokenSecurityManager.generateSecurityReport(timeframeHours, userId);

    res.json({
      success: true,
      report: report
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Security report error', error);
    res.status(500).json({
      error: 'Security report generation failed',
      code: 'SECURITY_REPORT_ERROR'
    });
  }
});

/**
 * POST /api/auth/verify-token
 * Verify token validity
 */
router.post('/refresh-challenge', async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required', code: 'MISSING_REFRESH_TOKEN' });
    }
    const parsed = TokenService.parseTokenUnsafe(refreshToken);
    if (!parsed || !parsed.jti) {
      return res.status(400).json({ error: 'Invalid token', code: 'INVALID_TOKEN' });
    }
    const nonce = crypto.randomBytes(32).toString('base64');
    await withRedisClient(async (client) => {
      await client.set(`refresh:nonce:${parsed.jti}`, nonce, 'EX', 60, 'NX');
    });
    res.json({ success: true, nonce });
  } catch (e) {
    cryptoLogger.error('[AUTH-API] Refresh challenge error', e);
    res.status(500).json({ error: 'Challenge error', code: 'CHALLENGE_ERROR' });
  }
});

router.post('/verify-token', rateLimitMiddleware.checkTokenVerificationRateLimit, async (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token) {
      return res.status(400).json({
        error: 'Token required',
        code: 'MISSING_TOKEN'
      });
    }

    const payload = await TokenService.verifyAccessToken(token);
    if (!payload) {
      return res.status(401).json({
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }

    const securityValidation = await TokenSecurityManager.validateTokenSecurity(token, {
      deviceId: req.headers['x-device-id'] || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown'
    });

    res.json({
      success: true,
      valid: true,
      payload: {
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        deviceId: payload.deviceId,
        quantumSecure: payload.quantumSecure || true
      },
      security: {
        valid: securityValidation.valid,
        riskScore: securityValidation.metadata?.riskScore || 'low'
      }
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Token verification error', error);
    res.status(401).json({
      error: 'Token verification failed',
      code: 'TOKEN_VERIFICATION_FAILED'
    });
  }
});

// Generate device ID from request context
function generateDeviceId(_req) {
  return crypto.randomBytes(16).toString('hex');
}

function deriveDeviceId(req) {
  try {
    const hdr = req?.headers?.['x-device-id'];
    const isTLS = !!(req && req.socket && req.socket.encrypted);
    if (isTLS && typeof hdr === 'string') {
      const trimmed = hdr.trim();
      if (trimmed.length >= 8) {
        return trimmed.length > 64 ? trimmed.slice(0, 64) : trimmed;
      }
    }
  } catch (_e) { }
  return generateDeviceId(req);
}

export default router;
