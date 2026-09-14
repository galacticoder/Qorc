/**
 * OPRF Discovery Service
 */

import { ristretto255_oprf } from '@noble/curves/ed25519.js';

import { deriveAuthRootKey } from './auth-root.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { SESSION_FINGERPRINT_RE } from '../../shared/patterns.js';

const OPRF_KEY_INFO = UTF8_ENCODER.encode(PROTOCOL_KEYS.DISCOVERY_VOPRF_AUTHORITY);
export const OPRF_DISCOVERY_POW_DIFFICULTY = 18;
const RATE_LIMIT_WINDOW_MS = 60000;
const parsedGlobalMax = Number.parseInt(process.env.OPRF_GLOBAL_MAX_PER_MIN || '1200', 10);
const GLOBAL_MAX_REQUESTS_PER_WINDOW = Math.min(
  60_000,
  Math.max(60, Number.isFinite(parsedGlobalMax) ? parsedGlobalMax : 1200)
);

class OPRFRateLimiter {
  constructor() {
    this.globalTimestamps = [];
    this.globalTimestampHead = 0;
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    this.cleanupInterval.unref?.();
  }

  checkGlobalOnly() {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    this.pruneBefore(windowStart);
    const activeCount = this.globalTimestamps.length - this.globalTimestampHead;
    if (activeCount >= GLOBAL_MAX_REQUESTS_PER_WINDOW) {
      console.warn('[OPRF-RATE-LIMIT] Global rate limit exceeded');
      return false;
    }
    this.globalTimestamps.push(now);
    return true;
  }

  cleanup() {
    this.pruneBefore(Date.now() - RATE_LIMIT_WINDOW_MS);
  }

  pruneBefore(windowStart) {
    while (
      this.globalTimestampHead < this.globalTimestamps.length &&
      this.globalTimestamps[this.globalTimestampHead] <= windowStart
    ) {
      this.globalTimestampHead += 1;
    }
    if (
      this.globalTimestampHead >= 1024 &&
      this.globalTimestampHead * 2 >= this.globalTimestamps.length
    ) {
      this.globalTimestamps = this.globalTimestamps.slice(this.globalTimestampHead);
      this.globalTimestampHead = 0;
    }
  }

  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.globalTimestamps.length = 0;
    this.globalTimestampHead = 0;
  }
}

class OPRFDiscoveryServer {
  constructor() {
    this.secretKey = null;
    this.publicKey = null;
    this.initialized = false;
    this.rateLimiter = new OPRFRateLimiter();
  }

  async initialize() {
    if (this.initialized) return;

    try {
      const seed = deriveAuthRootKey(PROTOCOL_KEYS.DISCOVERY_OPRF_ROOT);
      try {
        const keyPair = ristretto255_oprf.voprf.deriveKeyPair(seed, OPRF_KEY_INFO);
        this.secretKey = keyPair.secretKey;
        this.publicKey = keyPair.publicKey;
      } finally {
        seed.fill(0);
      }

      this.initialized = true;
      console.log('[OPRF-DISCOVERY] Initialized OPRF discovery server');
    } catch (error) {
      console.error('[OPRF-DISCOVERY] Failed to initialize', { errorType: error?.name || 'Error' });
      throw error;
    }
  }

  getPublicKey() {
    if (!this.initialized) {
      throw new Error('OPRF server not initialized');
    }
    return Buffer.from(this.publicKey).toString('hex');
  }

  blindEvaluate(blindedPointHex) {
    if (!this.initialized) {
      throw new Error('OPRF server not initialized');
    }

    if (!this.rateLimiter.checkGlobalOnly()) {
      throw new Error('Rate limit exceeded for OPRF evaluations');
    }
    if (typeof blindedPointHex !== 'string' || !SESSION_FINGERPRINT_RE.test(blindedPointHex)) {
      throw new Error('Invalid blinded OPRF point');
    }

    const blindedPoint = Buffer.from(blindedPointHex, 'hex');
    let result = null;
    try {
      result = ristretto255_oprf.voprf.blindEvaluate(
        this.secretKey,
        this.publicKey,
        blindedPoint
      );

      return {
        evaluated: Buffer.from(result.evaluated).toString('hex'),
        proof: Buffer.from(result.proof).toString('hex'),
        publicKey: Buffer.from(this.publicKey).toString('hex')
      };
    } catch (error) {
      console.error('[OPRF-DISCOVERY] Blind evaluation failed', { errorType: error?.name || 'Error' });
      throw new Error('OPRF evaluation failed');
    } finally {
      blindedPoint.fill(0);
      result?.evaluated?.fill(0);
      result?.proof?.fill(0);
    }
  }

  destroy() {
    if (this.secretKey) {
      this.secretKey.fill(0);
      this.secretKey = null;
    }
    this.publicKey?.fill(0);
    this.publicKey = null;
    this.initialized = false;
    this.rateLimiter.destroy();
  }
}

export const oprfDiscoveryServer = new OPRFDiscoveryServer();
