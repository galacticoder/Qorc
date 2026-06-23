/**
 * Circuit Breaker Pattern
 */

import { CIRCUIT_BREAKER_THRESHOLD, CIRCUIT_BREAKER_TIMEOUT_MS } from '../constants';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerState {
  failures: number;
  lastFailure: number;
  state: CircuitState;
  threshold: number;
  timeout: number;
}

export const createCircuitBreaker = (): CircuitBreakerState => ({
  failures: 0,
  lastFailure: 0,
  state: 'CLOSED',
  threshold: CIRCUIT_BREAKER_THRESHOLD,
  timeout: CIRCUIT_BREAKER_TIMEOUT_MS
});

export const recordCircuitFailure = (breaker: CircuitBreakerState): void => {
  breaker.failures += 1;
  breaker.lastFailure = Date.now();
  if (breaker.failures >= breaker.threshold) {
    breaker.state = 'OPEN';
  }
};

export const resetCircuitBreaker = (breaker: CircuitBreakerState): void => {
  breaker.state = 'CLOSED';
  breaker.failures = 0;
  breaker.lastFailure = 0;
};
