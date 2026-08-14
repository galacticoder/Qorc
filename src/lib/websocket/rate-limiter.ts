/**
 * WebSocket Rate Limiter
 */

import {
  RATE_LIMIT_WINDOW_MS,
  MAX_BURST_MESSAGES,
  MAX_MESSAGES_PER_MINUTE,
} from '../constants';

interface RateLimitState {
  messageTimestamps: number[];
}

export class WebSocketRateLimiter {
  private rateLimitState: RateLimitState = {
    messageTimestamps: [],
  };

  // Check if message is within rate limits
  checkRateLimit(): boolean {
    const now = Date.now();

    this.rateLimitState.messageTimestamps = this.rateLimitState.messageTimestamps.filter(
      ts => now - ts < RATE_LIMIT_WINDOW_MS
    );

    // Check burst limit
    const recentMessages = this.rateLimitState.messageTimestamps.filter(
      ts => now - ts < 1000
    ).length;

    if (recentMessages >= MAX_BURST_MESSAGES) {
      return false;
    }

    // Check window limit
    if (this.rateLimitState.messageTimestamps.length >= MAX_MESSAGES_PER_MINUTE) {
      return false;
    }

    this.rateLimitState.messageTimestamps.push(now);
    return true;
  }

  // Reset rate limit state
  reset(): void {
    this.rateLimitState = {
      messageTimestamps: [],
    };
  }
}
