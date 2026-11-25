/**
 * Rate Limiter for Blocking Operations
 */

import { DEFAULT_RATE_LIMIT } from '../constants';

type BlockingAction = 'block' | 'unblock';

export class BlockingRateLimiter {
  private readonly rateLimiter = new Map<string, number[]>();

  checkRateLimit(action: BlockingAction): void {
    const now = Date.now();
    const timestamps = this.rateLimiter.get(action) ?? [];
    const recent = timestamps.filter((t) => now - t < DEFAULT_RATE_LIMIT.windowMs);
    if (recent.length >= DEFAULT_RATE_LIMIT.maxEvents) {
      throw new Error('Rate limit exceeded');
    }
    recent.push(now);
    this.rateLimiter.set(action, recent);
  }

  reset(): void {
    this.rateLimiter.clear();
  }
}
