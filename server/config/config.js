export const PORT = 8443;
export const MAX_CLIENTS = 100;
export const SERVER_ID = 'end2end-Server';

// SECURITY: Standardized TTL values to prevent inconsistencies
export const TTL_CONFIG = {
  SESSION_TTL: 300,        // 5 minutes - Redis session state
  PRESENCE_TTL: 180,       // 3 minutes - User online status
  CONNECTION_COUNTER_TTL: 3600, // 1 hour - Connection counting
  RATE_LIMIT_TTL: 3600     // 1 hour - Rate limiting data
};
// SECURITY: Private password storage with validation
let _serverPasswordHash = null;

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

// SECURITY: Validate and securely store password hash
export function setServerPassword(passwordHash) {
  // SECURITY: Validate password hash format (should be bcrypt/argon2)
  if (!passwordHash || typeof passwordHash !== 'string') {
    throw new Error('Invalid password hash - must be non-empty string');
  }
  
  // SECURITY: Validate hash format (basic check for common hash formats)
  if (passwordHash.length < 16) {
    throw new Error('Invalid password hash - hash too short');
  }
  
  // SECURITY: Prevent setting empty/weak hashes
  if (passwordHash === 'null' || passwordHash === 'undefined') {
    throw new Error('Invalid password hash - cannot be null/undefined string');
  }
  
  _serverPasswordHash = passwordHash;
  console.log('[CONFIG] Server password hash updated securely');
}

// SECURITY: Read-only access to password hash
export function getServerPasswordHash() {
  return _serverPasswordHash;
}

// SECURITY: Validate rate limit configuration on startup
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
  
  if (PORT < 1 || PORT > 65535) {
    throw new Error('Invalid PORT - must be between 1 and 65535');
  }
  
  if (MAX_CLIENTS < 1 || MAX_CLIENTS > 100000) {
    throw new Error('Invalid MAX_CLIENTS - must be between 1 and 100000');
  }
  
  console.log('[CONFIG] Configuration validation passed');
}