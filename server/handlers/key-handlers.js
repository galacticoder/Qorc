/**
 * Rate Limit Handlers
 *
 * Responds to rate-limit status requests. (Hybrid public keys are published via the certified
 * discovery identity bundle, not a server-side key-update message.)
 */

import {
  SignalType,
  sendSecureMessage,
  cryptoLogger
} from './core.js';

export async function handleRateLimitStatus({ ws, state }) {
  try {
    const { rateLimitMiddleware } = await import('../rate-limiting/rate-limit-middleware.js');
    const stats = rateLimitMiddleware.getStats();
    const globalStatus = await rateLimitMiddleware.getGlobalConnectionStatus();

    await sendSecureMessage(ws, {
      type: SignalType.RATE_LIMIT_STATUS,
      stats,
      globalConnectionStatus: globalStatus,
      userStatus: null,
    });
  } catch (error) {
    cryptoLogger.error('[RATE-LIMIT] Status request failed', { error: error?.message });
    await sendSecureMessage(ws, { type: SignalType.ERROR, message: 'Error getting rate limit status' });
  }
}
