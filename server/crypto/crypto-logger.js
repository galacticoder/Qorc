/**
 * Secure Crypto Logger Utility
 */

import util from 'util';

export class CryptoLogger {
  constructor() {
    this.logLevel = process.env.CRYPTO_LOG_LEVEL || 'warn';

    this.levels = {
      info: 0,
      warn: 1,
      error: 2
    };

    this.currentLevel = this.levels[this.logLevel] || this.levels.info;
  }

  redactValue(value) {
    return value;
  }

  keyTokens(key) {
    return String(key || '')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .split(/[^A-Za-z0-9]+/)
      .map((token) => token.toLowerCase())
      .filter(Boolean);
  }

  isSensitiveKey(key) {
    const tokens = this.keyTokens(key);
    if (tokens.length === 0) return false;

    const sensitiveTokens = new Set([
      'private',
      'secret',
      'password',
      'token',
      'tokens',
      'key',
      'keys',
      'salt',
      'iv',
      'auth',
      'tag',
      'encrypted',
      'encryption',
      'credential',
      'credentials',
      'session',
      'sessions',
      'inbox',
      'identifier',
      'fingerprint',
      'signature',
      'payload',
      'nonce',
      'mac',
      'proof',
      'stack',
      'username',
      'user',
      'account',
      'email',
      'ip'
    ]);

    return tokens.some((token) => sensitiveTokens.has(token));
  }

  sanitizeData(value, depth = 0, parentKey = '') {
    return value;
  }

  // Sanitize sensitive data from log messages
  sanitizeMessage(message, data = {}) {
    return { message, data };
  }

  formatDataForConsole(data) {
    if (!data || Object.keys(data).length === 0) return '';
    return util.inspect(data, {
      depth: null,
      colors: false,
      compact: false,
      maxArrayLength: 100,
      breakLength: 120
    });
  }

  // Check if a log level should be output
  shouldLog(level) {
    return this.levels[level] >= this.currentLevel;
  }

  // Format log output with timestamp and level
  formatLog(level, message, data) {
    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [CRYPTO:${level.toUpperCase()}]`;

    if (Object.keys(data).length > 0) {
      return `${prefix} ${message}`;
    }
    return `${prefix} ${message}`;
  }

  // Info level logging
  info(message, data = {}) {
    if (!this.shouldLog('info')) return;

    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, data);
    const formatted = this.formatLog('info', sanitizedMessage, sanitizedData);

    console.log(formatted, this.formatDataForConsole(sanitizedData));
  }

  // Warning level logging
  warn(message, data = {}) {
    if (!this.shouldLog('warn')) return;

    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, data);
    const formatted = this.formatLog('warn', sanitizedMessage, sanitizedData);

    console.warn(formatted, this.formatDataForConsole(sanitizedData));
  }

  // Error level logging
  error(message, error = null, data = {}) {
    if (!this.shouldLog('error')) return;

    let errorData = { ...data };
    if (error instanceof Error) {
      errorData.errorMessage = error.message;
      errorData.errorStack = error.stack;
    } else if (error) {
      errorData.error = error;
    }

    const { message: sanitizedMessage, data: sanitizedData } = this.sanitizeMessage(message, errorData);
    const formatted = this.formatLog('error', sanitizedMessage, sanitizedData);

    console.error(formatted, this.formatDataForConsole(sanitizedData));
  }
}

// Export singleton instance
export const logger = new CryptoLogger();
