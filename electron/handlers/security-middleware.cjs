/**
 * Security Middleware
 * IPC request validation, rate limiting, and security controls
 */

class SecurityMiddleware {
  constructor() {
    this.requestCounts = new Map();
    
    this.SIZE_LIMITS = {
      'secure:set': 65536,
      'secure:get': 512,
      'file:save': 100 * 1024 * 1024,
      'edge:ws-send': 10 * 1024 * 1024,
      'default': 1024 * 1024
    };
    
    this.RATE_LIMITS = {
      'secure:set': 300,
      'secure:get': 1000,
      'file:save': 10,
      'edge:ws-send': 500,
      'default': 100
    };
    
    this.auditLog = [];
    this.MAX_AUDIT_ENTRIES = 5000;
  }

  async initialize() {
    return { success: true };
  }

  cleanup() {
    this.clearRateLimits();
    this.auditLog = [];
  }

  // Validate and rate limit IPC request
  async validateRequest(channel, args) {
    const now = Date.now();
    
    if (!this.checkRateLimit(channel, now)) {
      this.logSecurityEvent('rate-limit-exceeded', channel, { timestamp: now });
      throw new Error('Rate limit exceeded');
    }
    
    const requestSize = this.calculateRequestSize(args);
    const sizeLimit = this.SIZE_LIMITS[channel] || this.SIZE_LIMITS.default;
    
    if (requestSize > sizeLimit) {
      this.logSecurityEvent('size-limit-exceeded', channel, {
        size: requestSize,
        limit: sizeLimit
      });
      throw new Error(`Request size ${requestSize} exceeds limit ${sizeLimit}`);
    }
    
    this.validateRequestStructure(channel, args);
    
    return true;
  }

  // Check rate limit for channel
  checkRateLimit(channel, now) {
    const limit = this.RATE_LIMITS[channel] || this.RATE_LIMITS.default;
    const windowMs = 60000;
    
    if (!this.requestCounts.has(channel)) {
      this.requestCounts.set(channel, []);
    }
    
    const counts = this.requestCounts.get(channel);
    while (counts.length > 0 && counts[0] < now - windowMs) {
      counts.shift();
    }
    
    if (counts.length >= limit) {
      return false;
    }
    
    counts.push(now);
    return true;
  }

  // Calculate request size
  calculateRequestSize(args) {
    try {
      return JSON.stringify(args).length;
    } catch {
      return 0;
    }
  }

  // Validate request structure based on channel
  validateRequestStructure(channel, args) {
    switch (channel) {
      case 'secure:set':
        if (!args[0] || typeof args[0] !== 'string' || args[0].length > 512) {
          throw new Error('Invalid key');
        }
        if (!args[1] || typeof args[1] !== 'string' || args[1].length === 0) {
          throw new Error('Invalid value');
        }
        break;
        
      case 'secure:get':
      case 'secure:remove':
        if (!args[0] || typeof args[0] !== 'string' || args[0].length > 512) {
          throw new Error('Invalid key');
        }
        break;
        
      case 'file:save':
        if (!args[0] || !args[0].filename || typeof args[0].filename !== 'string') {
          throw new Error('Invalid filename');
        }
        if (!args[0].data) {
          throw new Error('Invalid data');
        }

        const sanitized = this.sanitizeFilename(args[0].filename);
        if (sanitized !== args[0].filename) {
          throw new Error('Invalid characters in filename');
        }
        break;
        
      case 'edge:set-server-url':
        if (!args[0] || typeof args[0] !== 'string') {
          throw new Error('Invalid server URL');
        }
        try {
          const url = new URL(args[0]);
          if (!['wss:', 'ws:'].includes(url.protocol)) {
            throw new Error('Invalid protocol');
          }
        } catch {
          throw new Error('Invalid URL format');
        }
        break;
    }
  }

  // Sanitize filename
  sanitizeFilename(filename) {
    return filename
      .replace(/[\/\\]/g, '')
      .replace(/\.\./g, '')
      .replace(/[<>:"|?*\x00-\x1f]/g, '')
      .trim();
  }

  logSecurityEvent(type, channel, details) {
    const event = {
      type,
      channel,
      details,
      timestamp: Date.now()
    };
    
    this.auditLog.push(event);
    
    if (this.auditLog.length > this.MAX_AUDIT_ENTRIES) {
      this.auditLog = this.auditLog.slice(-Math.floor(this.MAX_AUDIT_ENTRIES * 0.8));
    }
  }

  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit);
  }

  clearRateLimits() {
    this.requestCounts.clear();
  }
}

module.exports = { SecurityMiddleware };