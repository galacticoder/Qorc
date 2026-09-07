import { envInt } from '../utils/env.js';

function parsePort(portValue) {
  if (typeof portValue !== 'string' || !/^\d{1,5}$/.test(portValue)) return Number.NaN;
  return Number(portValue);
}

export const PORT = parsePort(process.env.PORT);
let _serverPasswordGateReady = false;

// Rate limiting config
export const RATE_LIMIT_CONFIG = {
  CONNECTION: {
    WINDOW_MS: 60000,
    MAX_NEW_CONNECTIONS: envInt('MAX_NEW_CONNECTIONS_PER_MIN', 600, 1, 100_000),
    BLOCK_DURATION_MS: envInt('CONNECTION_BLOCK_MS', 1_000, 1_000, 60_000)
  },

  AUTHENTICATION: {
    MAX_ATTEMPTS_PER_CONNECTION: 10
  },

  DISCOVERY_PUBLISH: {
    MAX_ATTEMPTS_PER_CONNECTION: envInt('DISCOVERY_PUBLISH_MAX_PER_MIN', 12, 1, 1_000)
  },

  CONTROL: {
    MAX_BOOTSTRAP_REQUESTS_PER_CONNECTION: 24,
    MAX_HEARTBEATS_PER_MINUTE: 6,
    MAX_APPLICATION_REQUESTS_PER_MINUTE: 30,
  }
};


export function setServerPasswordGateReady() {
  _serverPasswordGateReady = true;
}

export function isServerPasswordGateReady() {
  return _serverPasswordGateReady;
}

export function validateConfig() {
  const connection = RATE_LIMIT_CONFIG.CONNECTION;
  if (
    connection.WINDOW_MS < 1_000 ||
    connection.BLOCK_DURATION_MS < 1_000 ||
    connection.MAX_NEW_CONNECTIONS < 1
  ) {
    throw new Error('Invalid connection rate-limit configuration');
  }

  for (const limit of [
    RATE_LIMIT_CONFIG.AUTHENTICATION.MAX_ATTEMPTS_PER_CONNECTION,
    RATE_LIMIT_CONFIG.DISCOVERY_PUBLISH.MAX_ATTEMPTS_PER_CONNECTION,
    RATE_LIMIT_CONFIG.CONTROL.MAX_BOOTSTRAP_REQUESTS_PER_CONNECTION,
    RATE_LIMIT_CONFIG.CONTROL.MAX_HEARTBEATS_PER_MINUTE,
    RATE_LIMIT_CONFIG.CONTROL.MAX_APPLICATION_REQUESTS_PER_MINUTE,
  ]) {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      throw new Error('Invalid per-connection rate-limit configuration');
    }
  }

  if (!Number.isSafeInteger(PORT) || PORT < 1 || PORT > 65535) {
    throw new Error('Invalid PORT configuration');
  }
}
