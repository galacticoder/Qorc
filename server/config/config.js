import crypto from 'crypto';
import fs from 'fs';

function parsePort(portValue) {
  if (!portValue) return 8443;
  if (typeof portValue === 'string' && portValue.toLowerCase() === 'dynamic') return 0;
  const parsed = parseInt(portValue, 10);
  return isNaN(parsed) ? 8443 : parsed;
}

// Generates random number of attempts between min and max
function getRandomizedAttempts(min = 5, max = 10) {
  const range = max - min + 1;
  const randomBytes = crypto.randomBytes(4);
  const randomValue = randomBytes.readUInt32BE(0) / 0xFFFFFFFF;
  return Math.floor(randomValue * range) + min;
}

const isDocker = fs.existsSync('/.dockerenv');
export const PORT = isDocker ? 3000 : parsePort(process.env.PORT);
export const MAX_CLIENTS = 100;
export const SERVER_ID = 'Qor-Chat-Server';

export const TTL_CONFIG = {
  SESSION_TTL: 31536000,
  CONNECTION_COUNTER_TTL: 31536000,
  RATE_LIMIT_TTL: 31536000,
  AUTH_STATE_TTL: 604800
};
let _serverPasswordHash = null;

// Rate limiting config
export const RATE_LIMIT_CONFIG = {
  CONNECTION: {
    WINDOW_MS: 60000,
    MAX_NEW_CONNECTIONS: 30,
    BLOCK_DURATION_MS: 300000
  },

  AUTHENTICATION: {
    WINDOW_MS: 60000,
    MAX_ATTEMPTS_PER_CONNECTION: 10,
    BLOCK_DURATION_MS: 60000
  },

  AUTH_PER_USER: {
    WINDOW_MS: 600000,
    MAX_ATTEMPTS: 50,
    BLOCK_DURATION_MS: 900000
  },

  AUTH_CATEGORIES: {
    ACCOUNT_PASSWORD: {
      WINDOW_MS: 60000,
      MAX_ATTEMPTS: getRandomizedAttempts(5, 10),
      BLOCK_DURATION_MS: 60000
    },
    PASSPHRASE: {
      WINDOW_MS: 30000,
      MAX_ATTEMPTS: getRandomizedAttempts(5, 10),
      BLOCK_DURATION_MS: 30000
    },
    SERVER_PASSWORD: {
      WINDOW_MS: 60000,
      MAX_ATTEMPTS: getRandomizedAttempts(5, 10),
      BLOCK_DURATION_MS: 60000
    }
  },

  MESSAGES: {
    WINDOW_MS: 60000,
    MAX_MESSAGES: 500,
    BLOCK_DURATION_MS: 60000
  },

  BUNDLE_OPERATIONS: {
    WINDOW_MS: 60000,
    MAX_OPERATIONS: 200,
    BLOCK_DURATION_MS: 60000
  }
};

export const DEVICE_MAX_ACCOUNTS = 2;


export function setServerPassword(passwordHash) {
  if (!passwordHash || typeof passwordHash !== 'string') {
    throw new Error('Invalid password hash - must be non-empty string');
  }

  if (passwordHash.length < 16) {
    throw new Error('Invalid password hash - hash too short');
  }

  if (passwordHash === 'null' || passwordHash === 'undefined') {
    throw new Error('Invalid password hash - cannot be null/undefined string');
  }

  _serverPasswordHash = passwordHash;
}

export function getServerPasswordHash() {
  return _serverPasswordHash;
}

export function validateConfig() {
  const configs = [RATE_LIMIT_CONFIG.CONNECTION, RATE_LIMIT_CONFIG.AUTHENTICATION,
  RATE_LIMIT_CONFIG.AUTH_PER_USER, RATE_LIMIT_CONFIG.MESSAGES,
  RATE_LIMIT_CONFIG.BUNDLE_OPERATIONS];

  for (const config of configs) {
    if (!config.WINDOW_MS || config.WINDOW_MS < 1000) {
      throw new Error('Invalid rate limit config - WINDOW_MS must be >= 1000ms');
    }
    if (!config.BLOCK_DURATION_MS || config.BLOCK_DURATION_MS < 1000) {
      throw new Error('Invalid rate limit config - BLOCK_DURATION_MS must be >= 1000ms');
    }
  }

  // Validate category configs
  const cats = RATE_LIMIT_CONFIG.AUTH_CATEGORIES || {};
  for (const key of Object.keys(cats)) {
    const c = cats[key];
    if (!c || typeof c !== 'object') throw new Error(`Invalid AUTH_CATEGORIES entry for ${key}`);
    if (!c.WINDOW_MS || c.WINDOW_MS < 1000) throw new Error(`Invalid ${key}.WINDOW_MS`);
    if (!c.BLOCK_DURATION_MS || c.BLOCK_DURATION_MS < 1000) throw new Error(`Invalid ${key}.BLOCK_DURATION_MS`);
    if (!Number.isFinite(c.MAX_ATTEMPTS) || c.MAX_ATTEMPTS < 1) throw new Error(`Invalid ${key}.MAX_ATTEMPTS`);
  }

  if (PORT < 0 || PORT > 65535) {
    throw new Error('Invalid PORT - must be between 0 (dynamic) and 65535');
  }

  if (MAX_CLIENTS < 1 || MAX_CLIENTS > 100000) {
    throw new Error('Invalid MAX_CLIENTS - must be between 1 and 100000');
  }

}