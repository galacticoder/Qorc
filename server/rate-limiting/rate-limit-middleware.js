import {
  closeDistributedRateLimiter,
  getDistributedRateLimiter
} from './distributed-rate-limiter.js';
import {
  isAccountAuthSignalType,
  isRateLimitedAuthSignalType,
  isServerEntrySignalType,
  SignalType
} from '../signals.js';

import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import { RATE_LIMIT_CONFIG } from '../config/config.js';
import {
  PUBLICATION_ID_RE as PUBLISH_REQUEST_ID_RE,
  UUID_V4_RE as AUTH_REQUEST_ID_RE
} from '../utils/patterns.js';

export class RateLimitMiddleware {
  constructor(limiter, { lazy = false } = {}) {
    this._limiter = limiter || null;
    this._usesSharedLimiter = !limiter;
    this._limiterFactory = limiter ? async () => limiter : () => getDistributedRateLimiter();
    this._initializePromise = null;
    this._socketWindows = new WeakMap();
    if (!lazy && !limiter) this._initializePromise = this._initialize();
  }

  async _initialize() {
    const limiter = await this._limiterFactory();
    this._limiter = limiter;
    return limiter;
  }

  async limiter() {
    if (this._limiter) return this._limiter;
    if (!this._initializePromise) {
      const initialization = this._initialize();
      this._initializePromise = initialization;
      initialization.catch(() => {
        if (this._initializePromise === initialization) this._initializePromise = null;
      });
    }
    return this._initializePromise;
  }

  async checkConnectionLimit(ws) {
    if (!ws || typeof ws.send !== 'function' || typeof ws.close !== 'function') return false;

    let result;
    try {
      result = await (await this.limiter()).checkGlobalConnectionLimit();
    } catch {
      result = { allowed: false };
    }
    if (result.allowed) return true;

    console.warn('[RATE-LIMIT] Global connection admission denied');
    try {
      await sendSecureMessage(ws, {
        type: SignalType.ERROR,
        code: 'CONNECTION_ADMISSION_DENIED',
        message: 'Connection admission unavailable'
      });
    } catch {
    }
    ws.close(1013, 'Connection admission unavailable');
    return false;
  }

  async applyMessageRateLimiting(ws, messageType, message = undefined) {
    if (!ws || typeof ws.send !== 'function' || typeof messageType !== 'string') return false;
    const isAuth = isRateLimitedAuthSignalType(messageType);
    const isPublish = messageType === SignalType.PUBLISH_DISCOVERY;
    if (!isAuth && !isPublish) return true;

    const now = Date.now();
    let window = this._socketWindows.get(ws);
    if (!window || now - window.startedAt >= 60_000) {
      window = { startedAt: now, auth: 0, publish: 0 };
      this._socketWindows.set(ws, window);
    }

    const key = isAuth ? 'auth' : 'publish';
    const limit = isAuth
      ? Math.max(1, RATE_LIMIT_CONFIG.AUTHENTICATION.MAX_ATTEMPTS_PER_CONNECTION)
      : Math.max(1, RATE_LIMIT_CONFIG.DISCOVERY_PUBLISH.MAX_ATTEMPTS_PER_CONNECTION);
    window[key] += 1;
    if (window[key] <= limit) return true;

    const authRequestId = isAccountAuthSignalType(messageType) &&
      typeof message?.authRequestId === 'string' &&
      AUTH_REQUEST_ID_RE.test(message.authRequestId)
      ? message.authRequestId
      : undefined;
    const requestId = isServerEntrySignalType(messageType) &&
      typeof message?.requestId === 'string' &&
      AUTH_REQUEST_ID_RE.test(message.requestId)
      ? message.requestId
      : undefined;
      
    const publishRequestId = isPublish &&
      typeof message?.requestId === 'string' &&
      PUBLISH_REQUEST_ID_RE.test(message.requestId)
      ? message.requestId
      : undefined;
    if (publishRequestId) {
      await sendSecureMessage(ws, {
        type: SignalType.OK,
        requestId: publishRequestId,
        op: SignalType.PUBLISH_DISCOVERY,
        success: false,
        error: 'rate_limited'
      });
      return false;
    }

    const response = {
      type: isAuth ? SignalType.AUTH_ERROR : SignalType.ERROR,
      code: 'SOCKET_RATE_LIMITED',
      message: 'Request rate exceeded for this connection'
    };
    if (authRequestId) response.authRequestId = authRequestId;
    if (requestId) response.requestId = requestId;
    await sendSecureMessage(ws, response);
    return false;
  }

  async close() {
    const initialization = this._initializePromise;
    this._initializePromise = null;
    const limiter = this._limiter || (initialization ? await initialization.catch(() => null) : null);
    this._limiter = null;
    if (this._usesSharedLimiter) {
      await closeDistributedRateLimiter();
    } else if (limiter?.close) {
      await limiter.close();
    }
  }
}

export const rateLimitMiddleware = new RateLimitMiddleware(undefined, { lazy: true });
