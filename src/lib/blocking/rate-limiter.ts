/**
 * Rate Limiter for Blocking Operations
 */

import { RateLimitConfig } from '../types/blocking-types';
import {
  BLOCK_RATE_LIMIT_WINDOW_MS,
  BLOCK_RATE_LIMIT_MAX_EVENTS,
  BLOCK_SYNC_RATE_LIMIT_WINDOW_MS,
  BLOCK_SYNC_RATE_LIMIT_MAX_EVENTS
} from '../constants';

export const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  windowMs: BLOCK_RATE_LIMIT_WINDOW_MS,
  maxEvents: BLOCK_RATE_LIMIT_MAX_EVENTS
};

export const SYNC_RATE_LIMIT: RateLimitConfig = {
  windowMs: BLOCK_SYNC_RATE_LIMIT_WINDOW_MS,
  maxEvents: BLOCK_SYNC_RATE_LIMIT_MAX_EVENTS
};

export class BlockingRateLimiter {
  private readonly rateLimiter = new Map<string, number[]>();
  private readonly config: Record<string, RateLimitConfig>;

  constructor() {
    this.config = {
      block: DEFAULT_RATE_LIMIT,
      unblock: DEFAULT_RATE_LIMIT,
      sync: SYNC_RATE_LIMIT
    };
  }

  checkRateLimit(action: string): void {
    const now = Date.now();
    const config = this.config[action] ?? DEFAULT_RATE_LIMIT;
    const timestamps = this.rateLimiter.get(action) ?? [];
    const recent = timestamps.filter((t) => now - t < config.windowMs);
    if (recent.length >= config.maxEvents) {
      throw new Error('Rate limit exceeded');
    }
    recent.push(now);
    if (recent.length > config.maxEvents) {
      recent.splice(0, recent.length - config.maxEvents);
    }
    this.rateLimiter.set(action, recent);
  }

  configureRateLimit(action: string, config: RateLimitConfig): void {
    if (!config || typeof config.windowMs !== 'number' || typeof config.maxEvents !== 'number') {
      throw new Error('Invalid rate limit configuration');
    }
    if (config.windowMs <= 0 || config.maxEvents <= 0) {
      throw new Error('Rate limit configuration must be positive');
    }
    this.config[action] = { windowMs: config.windowMs, maxEvents: config.maxEvents };
  }

  getRateLimitConfig(action?: string): RateLimitConfig | Record<string, RateLimitConfig> {
    if (!action) {
      return { ...this.config };
    }
    return this.config[action] ?? DEFAULT_RATE_LIMIT;
  }
}
