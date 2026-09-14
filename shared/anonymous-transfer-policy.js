export const ANONYMOUS_HEADER_TIMEOUT_MS = 180_000;
export const ANONYMOUS_IDLE_TIMEOUT_MS = 180_000;
export const ANONYMOUS_MIN_BODY_TIMEOUT_MS = 300_000;
export const ANONYMOUS_MIN_TRANSFER_BYTES_PER_SECOND = 16 * 1024;
export const ANONYMOUS_DISCOVERY_RESPONSE_BYTES = 8_912_896;
export const DISCOVERY_LOOKUP_TIMEOUT_MS = 20 * 60_000;

export function anonymousBodyTimeoutMs(bytes) {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > ANONYMOUS_DISCOVERY_RESPONSE_BYTES) {
    throw new Error('Invalid anonymous response size');
  }
  return Math.max(ANONYMOUS_MIN_BODY_TIMEOUT_MS,
    ANONYMOUS_IDLE_TIMEOUT_MS + Math.ceil(bytes / ANONYMOUS_MIN_TRANSFER_BYTES_PER_SECOND) * 1000);
}

export function isAnonymousResponseTimestampValid(timestamp, requestedAt, receivedAt, clockSkewMs) {
  return Number.isSafeInteger(timestamp) && Number.isSafeInteger(requestedAt) &&
    Number.isSafeInteger(receivedAt) && timestamp >= requestedAt - clockSkewMs &&
    receivedAt >= requestedAt - clockSkewMs && receivedAt - requestedAt <= DISCOVERY_LOOKUP_TIMEOUT_MS &&
    timestamp <= receivedAt + clockSkewMs;
}
