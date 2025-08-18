export const PORT = 8443;
export const MAX_CLIENTS = 100;
export const SERVER_ID = 'SecureChat-Server';
export let SERVER_PASSWORD = null;

// Rate limiting config
export const RATE_LIMIT_CONFIG = {
  CONNECTION: {
    WINDOW_MS: 60000, // 1 minute window
    MAX_NEW_CONNECTIONS: 30, // max connections per minute
    BLOCK_DURATION_MS: 300000 // block time (5 minutes)
  },

  AUTHENTICATION: {
    WINDOW_MS: 60000, // 1 minute
    MAX_ATTEMPTS_PER_CONNECTION: 10, // max auth tries per connection
    BLOCK_DURATION_MS: 60000 // block time (60 seconds / 1 minute)
  },

  AUTH_PER_USER: {
    WINDOW_MS: 600000, // 10 minutes
    MAX_ATTEMPTS: 10, // max failed tries per user
    BLOCK_DURATION_MS: 900000 // block time (900 seconds / 15 minutes)
  },

  MESSAGES: {
    WINDOW_MS: 60000, // 1 minute
    MAX_MESSAGES: 500, // max messages per user per minute
    BLOCK_DURATION_MS: 60000 // block time (60 seconds / 1 minute)
  },

  BUNDLE_OPERATIONS: {
    WINDOW_MS: 60000, // 1 minute
    MAX_OPERATIONS: 200, // max bundle ops per user per minute
    BLOCK_DURATION_MS: 60000 // block time (60 seconds / 1 minute)
  }
};

export function setServerPassword(pw) {
  SERVER_PASSWORD = pw;
}