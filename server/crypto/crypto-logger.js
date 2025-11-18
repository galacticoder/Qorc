/**
 * Secure Crypto Logger Utility
 * 
 * Provides structured logging for cryptographic operations with:
 * - Configurable log levels (debug/info/warn/error)
 * - Runtime-controlled debug flag
 * - Automatic sanitization of sensitive data
 * - Environment-based configuration
 */

export class CryptoLogger {
  constructor() {
    this.debugEnabled = process.env.CRYPTO_DEBUG === 'true';
    this.logLevel = process.env.CRYPTO_LOG_LEVEL || (this.debugEnabled ? 'debug' : 'info');
    
    // Log levels in order of priority
    this.levels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    
    this.currentLevel = this.levels[this.logLevel] || this.levels.info;
  }

  maskUsername(value) {
    if (!value || typeof value !== 'string') {
      return '[REDACTED]';
    }
    const trimmed = value.trim();
    if (trimmed.length <= 2) {
      return '[REDACTED]';
    }
    return `${trimmed[0]}***${trimmed[trimmed.length - 1]}`;
  }

  /**
   * Sanitize sensitive data from log messages
   * Removes or masks cryptographic keys, secrets, and sensitive payloads
   */
  sanitizeMessage(message, data = {}) {
    // Remove sensitive keys from data objects
    const sensitiveKeys = [
      'privateKey', 'secretKey', 'sharedSecret', 'password', 'token',
      'key', 'salt', 'iv', 'authTag', 'encrypted', 'kyberSecret',
      'x25519Shared', 'kyberShared', 'ikm', 'macKey', 'blake3Mac',
      'username', 'user', 'account', 'email'
    ];
    
    let sanitized = { ...data };
    
    for (const key of sensitiveKeys) {
      if (!sanitized[key]) continue;

      if (key === 'username' || key === 'user' || key === 'account' || key === 'email') {
        sanitized[key] = this.maskUsername(String(sanitized[key]));
        continue;
      }

      if (typeof sanitized[key] === 'string') {
        sanitized[key] = sanitized[key].length > 8 
          ? `${sanitized[key].substring(0, 4)}...${sanitized[key].substring(sanitized[key].length - 4)}`
          : '[REDACTED]';
      } else if (sanitized[key] instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(sanitized[key]))) {
        sanitized[key] = `[BINARY:${sanitized[key].length}bytes]`;
      } else {
        sanitized[key] = '[REDACTED]';
      }
    }
    
    // Also sanitize message text for common sensitive patterns
    let sanitizedMessage = message;
    
    // Mask hex strings longer than 16 chars (likely keys/hashes)
    sanitizedMessage = sanitizedMessage.replace(/[0-9a-fA-F]{17,}/g, (match) => 
      `${match.substring(0, 8)}...[${match.length-16}chars]...${match.substring(match.length - 8)}`
    );
    
    // Mask base64 strings longer than 24 chars (likely encoded keys/data)
    sanitizedMessage = sanitizedMessage.replace(/[A-Za-z0-9+/]{25,}={0,2}/g, (match) => 
      `${match.substring(0, 12)}...[${match.length-24}chars]...${match.substring(match.length - 12)}`
    );
    
    return { message: sanitizedMessage, data: sanitized };
  }

  /**
   * Check if a log level should be output
   */
  shouldLog(level) {
    return this.levels[level] >= this.currentLevel;
  }

  /**
   * Format log output with timestamp and level
   */
  formatLog(level, message, data) {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [CRYPTO:${level.toUpperCase()}]`;
    
    if (Object.keys(data).length > 0) {
      return `${prefix} ${message}`;
    }
    return `${prefix} ${message}`;
  }

  /**
   * Debug level logging - only shown when debug is enabled
   */
  debug(message, data = {}) {
    if (!this.shouldLog('debug') || !this.debugEnabled) return;
    
    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, data);
    const formatted = this.formatLog('debug', sanitizedMessage, sanitizedData);
    
    console.log(formatted, Object.keys(sanitizedData).length > 0 ? sanitizedData : '');
  }

  /**
   * Info level logging
   */
  info(message, data = {}) {
    if (!this.shouldLog('info')) return;
    
    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, data);
    const formatted = this.formatLog('info', sanitizedMessage, sanitizedData);
    
    console.log(formatted, Object.keys(sanitizedData).length > 0 ? sanitizedData : '');
  }

  /**
   * Warning level logging
   */
  warn(message, data = {}) {
    if (!this.shouldLog('warn')) return;
    
    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, data);
    const formatted = this.formatLog('warn', sanitizedMessage, sanitizedData);
    
    console.warn(formatted, Object.keys(sanitizedData).length > 0 ? sanitizedData : '');
  }

  /**
   * Error level logging
   */
  error(message, error = null, data = {}) {
    if (!this.shouldLog('error')) return;
    
    // Handle Error objects
    let errorData = { ...data };
    if (error instanceof Error) {
      errorData.errorMessage = error.message;
      errorData.errorStack = this.debugEnabled ? error.stack : '[Stack trace hidden]';
    } else if (error) {
      errorData.error = error;
    }
    
    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, errorData);
    const formatted = this.formatLog('error', sanitizedMessage, sanitizedData);
    
    console.error(formatted, Object.keys(sanitizedData).length > 0 ? sanitizedData : '');
  }

  /**
   * Performance timing helper
   */
  time(label) {
    if (this.debugEnabled) {
      console.time(`[CRYPTO:TIMING] ${label}`);
    }
  }

  /**
   * End performance timing
   */
  timeEnd(label) {
    if (this.debugEnabled) {
      console.timeEnd(`[CRYPTO:TIMING] ${label}`);
    }
  }
}

// Export singleton instance
export const logger = new CryptoLogger();
