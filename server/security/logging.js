
// Helper function for anonymization in logs
function anonymizeForLogging(identifier) {
  if (!identifier || typeof identifier !== 'string') return 'unknown';
  if (identifier.length <= 4) return '****';
  return identifier.slice(0, 2) + '****' + identifier.slice(-2);
}

export class InputValidator {
  static validateUsername(username) {
    if (!username || typeof username !== 'string') return false;
    if (username.length < 3 || username.length > 32) return false;
    return /^[a-zA-Z0-9_-]+$/.test(username);
  }

  static validateMessageType(messageType) {
    if (!messageType || typeof messageType !== 'string') return false;
    if (messageType.length === 0 || messageType.length > 100) return false;
    return /^[a-zA-Z0-9_-]+$/.test(messageType);
  }

  static validateMessageSize(message) {
    if (!message) return false;
    return true;
  }

  static validateJsonStructure(obj) {
    if (!obj || typeof obj !== 'object') return false;
    if (Array.isArray(obj)) return false;
    return true;
  }

  static sanitizeString(str, maxLength = 1000) {
    if (!str || typeof str !== 'string') return '';
    return str.slice(0, maxLength).replace(/[\x00-\x1F\x7F]/g, '');
  }
}

// Anonymized logging helper for security-sensitive operations
export function logEvent(type, payload, { logger = console } = {}) {
  const sanitizedPayload = { ...payload };

  if (sanitizedPayload.username) {
    sanitizedPayload.username = anonymizeForLogging(sanitizedPayload.username);
  }
  if (sanitizedPayload.senderUser) {
    sanitizedPayload.senderUser = anonymizeForLogging(sanitizedPayload.senderUser);
  }
  if (sanitizedPayload.recipientUser) {
    sanitizedPayload.recipientUser = anonymizeForLogging(sanitizedPayload.recipientUser);
  }
  if (sanitizedPayload.sessionId) {
    sanitizedPayload.sessionId = anonymizeForLogging(sanitizedPayload.sessionId);
  }
  if (sanitizedPayload.ip) {
    sanitizedPayload.ip = anonymizeForLogging(sanitizedPayload.ip);
  }

  logger.log(`[SECURITY] ${type}:`, sanitizedPayload);
}

// Rate limiting event logger
export function logRateLimitEvent(event, details, { logger = console } = {}) {
  const sanitizedDetails = { ...details };

  if (sanitizedDetails.username) {
    sanitizedDetails.username = anonymizeForLogging(sanitizedDetails.username);
  }
  if (sanitizedDetails.ip) {
    sanitizedDetails.ip = anonymizeForLogging(sanitizedDetails.ip);
  }

  logger.warn(`[RATE-LIMIT] ${event}:`, sanitizedDetails);
}

// Authentication event logger
export function logAuthEvent(event, details, { logger = console } = {}) {
  const sanitizedDetails = { ...details };

  if (sanitizedDetails.username) {
    sanitizedDetails.username = anonymizeForLogging(sanitizedDetails.username);
  }
  if (sanitizedDetails.sessionId) {
    sanitizedDetails.sessionId = anonymizeForLogging(sanitizedDetails.sessionId);
  }

  logger.log(`[AUTH] ${event}:`, sanitizedDetails);
}

// Message delivery event logger
export function logDeliveryEvent(event, details, { logger = console } = {}) {
  const sanitizedDetails = { ...details };

  if (sanitizedDetails.from) {
    sanitizedDetails.from = anonymizeForLogging(sanitizedDetails.from);
  }
  if (sanitizedDetails.to) {
    sanitizedDetails.to = anonymizeForLogging(sanitizedDetails.to);
  }
  if (sanitizedDetails.username) {
    sanitizedDetails.username = anonymizeForLogging(sanitizedDetails.username);
  }

  logger.log(`[DELIVERY] ${event}:`, sanitizedDetails);
}

// Error logger
export function logError(error, context = {}, { logger = console } = {}) {
  const sanitizedContext = { ...context };

  if (sanitizedContext.username) {
    sanitizedContext.username = anonymizeForLogging(sanitizedContext.username);
  }
  if (sanitizedContext.sessionId) {
    sanitizedContext.sessionId = anonymizeForLogging(sanitizedContext.sessionId);
  }
  if (sanitizedContext.ip) {
    sanitizedContext.ip = anonymizeForLogging(sanitizedContext.ip);
  }

  logger.error('[ERROR]', {
    message: error?.message || error,
    stack: error?.stack,
    context: sanitizedContext,
    timestamp: new Date().toISOString(),
  });
}
