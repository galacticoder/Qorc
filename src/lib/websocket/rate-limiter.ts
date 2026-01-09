/**
 * WebSocket Rate Limiter
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import type { RateLimitState, ConnectionMetrics } from '../types/websocket-types';
import {
  RATE_LIMIT_WINDOW_MS,
  MAX_BURST_MESSAGES,
  MAX_MESSAGES_PER_MINUTE,
  RATE_LIMIT_VIOLATION_THRESHOLD,
} from '../constants';

export class WebSocketRateLimiter {
  private rateLimitState: RateLimitState = {
    messageTimestamps: [],
    lastResetTime: Date.now(),
    violationCount: 0
  };

  constructor(private metrics: ConnectionMetrics) {}

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
      this.rateLimitState.violationCount += 1;
      this.metrics.securityEvents.rateLimitHits += 1;
      SecurityAuditLogger.log('warn', 'ws-rate-limit-burst', {
        recentMessages,
        limit: MAX_BURST_MESSAGES,
        violations: this.rateLimitState.violationCount
      });

      if (this.rateLimitState.violationCount >= RATE_LIMIT_VIOLATION_THRESHOLD) {
        SecurityAuditLogger.log('warn', 'ws-rate-limit-threshold-exceeded', {
          violations: this.rateLimitState.violationCount
        });
      }

      return false;
    }

    // Check window limit
    if (this.rateLimitState.messageTimestamps.length >= MAX_MESSAGES_PER_MINUTE) {
      this.rateLimitState.violationCount += 1;
      this.metrics.securityEvents.rateLimitHits += 1;
      SecurityAuditLogger.log('warn', 'ws-rate-limit-window', {
        messagesInWindow: this.rateLimitState.messageTimestamps.length,
        limit: MAX_MESSAGES_PER_MINUTE,
        violations: this.rateLimitState.violationCount
      });
      return false;
    }

    if (this.rateLimitState.violationCount > 0 && now - this.rateLimitState.lastResetTime > RATE_LIMIT_WINDOW_MS) {
      this.rateLimitState.violationCount = 0;
      this.rateLimitState.lastResetTime = now;
    }

    this.rateLimitState.messageTimestamps.push(now);
    return true;
  }

  // Reset rate limit state
  reset(): void {
    this.rateLimitState = {
      messageTimestamps: [],
      lastResetTime: Date.now(),
      violationCount: 0
    };
  }

  // Get current rate limit state
  getState(): RateLimitState {
    return { ...this.rateLimitState };
  }
}
