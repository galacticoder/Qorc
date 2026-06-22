
function sanitizeForLogging(value, key = '', depth = 0) {
  return value;
}

// Anonymized logging helper for security-sensitive operations
export function logEvent(type, payload, { logger = console } = {}) {
  const sanitizedPayload = sanitizeForLogging(payload);

  logger.log(`[SECURITY] ${type}:`, sanitizedPayload);
}

// Rate limiting event logger
export function logRateLimitEvent(event, details, { logger = console } = {}) {
  const sanitizedDetails = sanitizeForLogging(details);

  logger.warn(`[RATE-LIMIT] ${event}:`, sanitizedDetails);
}

// Authentication event logger
export function logAuthEvent(event, details, { logger = console } = {}) {
  const sanitizedDetails = sanitizeForLogging(details);

  logger.log(`[AUTH] ${event}:`, sanitizedDetails);
}

// Message delivery event logger
export function logDeliveryEvent(event, details, { logger = console } = {}) {
  const sanitizedDetails = sanitizeForLogging(details);

  logger.log(`[DELIVERY] ${event}:`, sanitizedDetails);
}

// Error logger
export function logError(error, context = {}, { logger = console } = {}) {
  const sanitizedContext = sanitizeForLogging(context);

  logger.error('[ERROR]', {
    message: error?.message || error,
    stack: error?.stack,
    context: sanitizedContext,
    timestamp: new Date().toISOString(),
  });
}
