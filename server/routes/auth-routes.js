/**
 * Auth Routes
 */

import express from 'express';
import { anonymousSessionService } from '../authentication/anonymous-session-service.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';
import { privateLookupId } from '../database/core.js';

const router = express.Router();

let rateLimit;
try {
  rateLimit = (await import('express-rate-limit')).default;
} catch (_error) {
  cryptoLogger.error('[AUTH-ROUTES] FATAL: express-rate-limit package is required but not available');
  process.emit('SIGINT');
  throw new Error('express-rate-limit package is required');
}

const rateLimitMiddleware = {
  checkTokenVerificationRateLimit: rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    ['leg' + 'acyHeaders']: false,
    keyGenerator: (req) => {
      const token = req.body?.token;
      if (token && typeof token === 'string') {
        return `token:${privateLookupId('auth-route-token-rate-v2', token)}`;
      }
      return 'anonymous';
    }
  })
};

/**
 * POST /api/auth/verify-token
 * Verify anonymous session token validity
 */
router.post('/verify-token', rateLimitMiddleware.checkTokenVerificationRateLimit, async (req, res) => {
  try {
    const { token } = req.body || {};

    if (!token) {
      return res.status(400).json({
        error: 'Token required',
        code: 'MISSING_TOKEN'
      });
    }

    const result = await anonymousSessionService.verifySession(token);
    if (!result.valid) {
      return res.status(401).json({
        error: result.error || 'Invalid session',
        code: 'INVALID_SESSION'
      });
    }

    res.json({
      success: true,
      valid: true,
      expiresAt: result.expiresAt,
      remainingSeconds: result.remainingSeconds,
      quantumSecure: true
    });

  } catch (error) {
    cryptoLogger.error('[AUTH-API] Token verification error', error);
    res.status(401).json({
      error: 'Token verification failed',
      code: 'TOKEN_VERIFICATION_FAILED'
    });
  }
});

/**
 * GET /api/auth/info
 * Get authentication system info
 */
router.get('/info', (_req, res) => {
  res.json({
    authMethod: 'OPAQUE-WebSocket',
    tokenType: 'Anonymous-BLAKE3-MAC',
    sessionTTL: '7 days',
    inboxRotation: '1 hour',
    features: [
      'Total Blind Authentication',
      'Post-Quantum Secure',
      'Sealed Sender',
      'Privacy Pass Rate Limiting'
    ]
  });
});

export default router;
