// Server configuration constants
export const SERVER_CONSTANTS = {
  // Bandwidth and rate limiting
  BANDWIDTH_QUOTA: 5 * 1024 * 1024, // 5MB per minute
  BANDWIDTH_WINDOW: 60 * 1000, // 1 minute window
  MESSAGE_HARD_LIMIT_PER_MINUTE: 1000,
  MESSAGE_RATE_RESET_INTERVAL: 60000, // 1 minute
  
  // WebSocket configuration
  HEARTBEAT_INTERVAL: 30000, // 30 seconds
  CONNECTION_TIMEOUT: 30000, // 30 seconds
  
  // Batch processing
  BATCH_SIZE: 10,
  BATCH_TIMEOUT: 1000, // 1 second
  MAX_BATCH_SIZE: 100,
  
  // Blocking cache
  BLOCKING_CACHE_TTL: 30000, // 30 seconds
  BLOCKING_CACHE_MAX_SIZE: 1000,
  BLOCKING_MIN_DELAY: 50, // 50ms minimum delay for timing attack protection
  
  // Cleanup intervals
  BLOCK_TOKEN_CLEANUP_INTERVAL: 60 * 60 * 1000, // 1 hour
  STATUS_LOG_INTERVAL: 60000, // 1 minute
  
  // History request cooldown
  HISTORY_REQUEST_COOLDOWN: 1000, // 1 second between requests
  MAX_HISTORY_LIMIT: 100,
  DEFAULT_HISTORY_LIMIT: 50,
  
  // Message size limits
  MAX_MESSAGE_SIZE: 5 * 1024 * 1024, // 5MB
  MAX_JSON_PAYLOAD_SIZE: 5 * 1024 * 1024, // 5MB
  
  // Certificate validation
  MAX_CERT_PATH_LENGTH: 1000,
  ALLOWED_CERT_EXTENSIONS: ['.pem', '.crt', '.key'],
  DANGEROUS_PATH_PATTERNS: ['../', '..\\', '%2e%2e', '%2f', '%5c', '\0'],
  
  // Cluster configuration
  MAX_CLUSTER_WORKERS: 32,
  DEFAULT_CLUSTER_WORKERS: 1,
  WORKER_BOOTSTRAP_TIMEOUT: 30000, // 30 seconds
  
  // Security timeouts
  AUTH_LOCK_TTL: 5000, // 5 seconds
  SESSION_CLEANUP_TIMEOUT: 10000, // 10 seconds
  TUNNEL_CLEANUP_TIMEOUT: 10000, // 10 seconds
};

// Rate limiting configuration
export const RATE_LIMIT_CONFIG = {
  // Connection limits
  MAX_CONNECTIONS_PER_IP: 10,
  CONNECTION_WINDOW: 60000, // 1 minute
  
  // Message limits
  MAX_MESSAGES_PER_USER_PER_MINUTE: 100,
  MAX_MESSAGES_PER_CONNECTION_PER_MINUTE: 1000,
  
  // Auth attempt limits
  MAX_AUTH_ATTEMPTS_PER_USER: 5,
  AUTH_LOCKOUT_DURATION: 3600000, // 1 hour
  AUTH_ATTEMPT_WINDOW: 3600000, // 1 hour
  
  // Backoff configuration
  MAX_BACKOFF_MINUTES: 60,
  BACKOFF_MULTIPLIER: 2,
};

// Database configuration
export const DATABASE_CONFIG = {
  // Message storage
  MAX_OFFLINE_MESSAGES_PER_USER: 1000,
  MESSAGE_RETENTION_DAYS: 30,
  
  // Session storage
  SESSION_TTL: 24 * 60 * 60 * 1000, // 24 hours
  SESSION_CLEANUP_INTERVAL: 60 * 60 * 1000, // 1 hour
  
  // Blocking storage
  BLOCK_LIST_VERSION: 1,
  BLOCK_LIST_MAX_SIZE: 10000,
};

// WebSocket message types for validation
export const VALID_MESSAGE_TYPES = [
  'ENCRYPTED_MESSAGE',
  'STORE_OFFLINE_MESSAGE',
  'RETRIEVE_OFFLINE_MESSAGES',
  'RATE_LIMIT_STATUS',
  'PASSWORD_HASH_RESPONSE',
  'SERVER_LOGIN',
  'REQUEST_MESSAGE_HISTORY',
  'BLOCK_LIST_SYNC',
  'RETRIEVE_BLOCK_LIST',
  'request-server-public-key',
];

// Security headers
export const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

// CORS configuration
export const CORS_CONFIG = {
  ALLOWED_ORIGINS: (() => {
    const rawOrigins = process.env.ALLOWED_CORS_ORIGINS || '';
    return rawOrigins
      .split(',')
      .map(origin => origin.trim())
      .filter(origin => origin.length > 0);
  })(),
  ALLOWED_METHODS: 'GET, POST, PUT, DELETE, OPTIONS',
  ALLOWED_HEADERS: 'Content-Type, Authorization, X-Device-ID',
  ALLOW_CREDENTIALS: true,
  MAX_AGE_SECONDS: 86400, // 24 hours
};
