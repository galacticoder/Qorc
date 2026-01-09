/**
 * WebSocket Circuit Breaker
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { SignalType } from '../types/signal-types';
import {
  CIRCUIT_BREAKER_THRESHOLD,
  CIRCUIT_BREAKER_TIMEOUT_MS,
} from '../constants';

export class WebSocketCircuitBreaker {
  private failures = 0;
  private openUntil = 0;

  // Check if circuit breaker allows operation
  check(): boolean {
    const now = Date.now();

    if (now < this.openUntil) {
      return false;
    }

    return true;
  }

  // Record a failure
  recordFailure(): void {
    this.failures += 1;
    if (this.failures >= CIRCUIT_BREAKER_THRESHOLD) {
      this.openUntil = Date.now() + CIRCUIT_BREAKER_TIMEOUT_MS;

      SecurityAuditLogger.log(SignalType.ERROR, 'ws-circuit-breaker-triggered', {
        failures: this.failures,
        openDurationMs: CIRCUIT_BREAKER_TIMEOUT_MS
      });

      this.failures = 0;
    }
  }

  // Reset circuit breaker on successful operation
  reset(): void {
    if (this.failures > 0) {
      this.failures = 0;
    }
  }

  // Full reset including open state
  fullReset(): void {
    this.failures = 0;
    this.openUntil = 0;
  }

  // Get the time when the circuit will be open until
  getOpenUntil(): number {
    return this.openUntil;
  }
}