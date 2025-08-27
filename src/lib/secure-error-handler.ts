/**
 * Secure Error Handler
 * Prevents information disclosure through error messages and stack traces
 */

export enum ErrorSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum ErrorCategory {
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  VALIDATION = 'validation',
  CRYPTOGRAPHY = 'cryptography',
  NETWORK = 'network',
  STORAGE = 'storage',
  P2P = 'p2p',
  SYSTEM = 'system'
}

interface SecureError {
  id: string;
  category: ErrorCategory;
  severity: ErrorSeverity;
  userMessage: string;
  internalMessage: string;
  timestamp: number;
  context?: Record<string, any>;
}

interface ErrorMetrics {
  totalErrors: number;
  errorsByCategory: Record<ErrorCategory, number>;
  errorsBySeverity: Record<ErrorSeverity, number>;
  recentErrors: SecureError[];
}

export class SecureErrorHandler {
  private static instance: SecureErrorHandler;
  private errors: SecureError[] = [];
  private readonly MAX_ERROR_HISTORY = 1000;
  private readonly isDevelopment = process.env.NODE_ENV === 'development';

  private constructor() {}

  static getInstance(): SecureErrorHandler {
    if (!SecureErrorHandler.instance) {
      SecureErrorHandler.instance = new SecureErrorHandler();
    }
    return SecureErrorHandler.instance;
  }

  /**
   * Handle error with secure logging and user-safe messages
   */
  handleError(
    error: Error | string,
    category: ErrorCategory,
    severity: ErrorSeverity,
    context?: Record<string, any>
  ): SecureError {
    const errorId = this.generateErrorId();
    const timestamp = Date.now();
    
    const internalMessage = error instanceof Error ? error.message : error;
    const userMessage = this.generateUserSafeMessage(category, severity);
    
    const secureError: SecureError = {
      id: errorId,
      category,
      severity,
      userMessage,
      internalMessage,
      timestamp,
      context: this.sanitizeContext(context)
    };

    // Store error for metrics
    this.errors.push(secureError);
    if (this.errors.length > this.MAX_ERROR_HISTORY) {
      this.errors.shift();
    }

    // Log appropriately based on environment
    this.logError(secureError, error);

    // Alert on critical errors
    if (severity === ErrorSeverity.CRITICAL) {
      this.handleCriticalError(secureError);
    }

    return secureError;
  }

  /**
   * Generate user-safe error messages that don't leak sensitive information
   */
  private generateUserSafeMessage(category: ErrorCategory, severity: ErrorSeverity): string {
    const messages = {
      [ErrorCategory.AUTHENTICATION]: {
        [ErrorSeverity.LOW]: 'Authentication issue occurred',
        [ErrorSeverity.MEDIUM]: 'Authentication failed',
        [ErrorSeverity.HIGH]: 'Authentication error - please try again',
        [ErrorSeverity.CRITICAL]: 'Authentication system unavailable'
      },
      [ErrorCategory.AUTHORIZATION]: {
        [ErrorSeverity.LOW]: 'Access denied',
        [ErrorSeverity.MEDIUM]: 'Insufficient permissions',
        [ErrorSeverity.HIGH]: 'Authorization failed',
        [ErrorSeverity.CRITICAL]: 'Security violation detected'
      },
      [ErrorCategory.VALIDATION]: {
        [ErrorSeverity.LOW]: 'Invalid input provided',
        [ErrorSeverity.MEDIUM]: 'Data validation failed',
        [ErrorSeverity.HIGH]: 'Invalid request format',
        [ErrorSeverity.CRITICAL]: 'Malformed request detected'
      },
      [ErrorCategory.CRYPTOGRAPHY]: {
        [ErrorSeverity.LOW]: 'Encryption issue',
        [ErrorSeverity.MEDIUM]: 'Cryptographic operation failed',
        [ErrorSeverity.HIGH]: 'Security operation failed',
        [ErrorSeverity.CRITICAL]: 'Critical security error'
      },
      [ErrorCategory.NETWORK]: {
        [ErrorSeverity.LOW]: 'Network issue',
        [ErrorSeverity.MEDIUM]: 'Connection problem',
        [ErrorSeverity.HIGH]: 'Network error',
        [ErrorSeverity.CRITICAL]: 'Network unavailable'
      },
      [ErrorCategory.STORAGE]: {
        [ErrorSeverity.LOW]: 'Storage issue',
        [ErrorSeverity.MEDIUM]: 'Data storage failed',
        [ErrorSeverity.HIGH]: 'Storage error',
        [ErrorSeverity.CRITICAL]: 'Storage system unavailable'
      },
      [ErrorCategory.P2P]: {
        [ErrorSeverity.LOW]: 'P2P connection issue',
        [ErrorSeverity.MEDIUM]: 'Peer connection failed',
        [ErrorSeverity.HIGH]: 'P2P network error',
        [ErrorSeverity.CRITICAL]: 'P2P system unavailable'
      },
      [ErrorCategory.SYSTEM]: {
        [ErrorSeverity.LOW]: 'System issue',
        [ErrorSeverity.MEDIUM]: 'System error occurred',
        [ErrorSeverity.HIGH]: 'System malfunction',
        [ErrorSeverity.CRITICAL]: 'System failure'
      }
    };

    return messages[category]?.[severity] || 'An error occurred';
  }

  /**
   * Sanitize context to remove sensitive information
   */
  private sanitizeContext(context?: Record<string, any>): Record<string, any> | undefined {
    if (!context) return undefined;

    const sensitiveKeys = [
      'password', 'passphrase', 'key', 'secret', 'token', 'auth',
      'private', 'seed', 'mnemonic', 'signature', 'hash'
    ];

    const sanitized: Record<string, any> = {};
    
    for (const [key, value] of Object.entries(context)) {
      const keyLower = key.toLowerCase();
      const isSensitive = sensitiveKeys.some(sensitive => keyLower.includes(sensitive));
      
      if (isSensitive) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'string' && value.length > 100) {
        sanitized[key] = value.substring(0, 100) + '...[TRUNCATED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = '[OBJECT]';
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  /**
   * Log error appropriately based on environment
   */
  private logError(secureError: SecureError, originalError: Error | string): void {
    const logData = {
      id: secureError.id,
      category: secureError.category,
      severity: secureError.severity,
      timestamp: new Date(secureError.timestamp).toISOString(),
      context: secureError.context
    };

    if (this.isDevelopment) {
      // In development, log more details
      console.error('[SecureErrorHandler]', {
        ...logData,
        internalMessage: secureError.internalMessage,
        stack: originalError instanceof Error ? originalError.stack : undefined
      });
    } else {
      // In production, log minimal information
      console.error('[SecureErrorHandler]', logData);
      
      // Log internal details separately for debugging (without stack traces)
      if (secureError.severity === ErrorSeverity.CRITICAL || secureError.severity === ErrorSeverity.HIGH) {
        console.error('[SecureErrorHandler-Internal]', {
          id: secureError.id,
          message: secureError.internalMessage
        });
      }
    }
  }

  /**
   * Handle critical errors with immediate attention
   */
  private handleCriticalError(error: SecureError): void {
    console.error('[CRITICAL ERROR]', {
      id: error.id,
      category: error.category,
      timestamp: new Date(error.timestamp).toISOString()
    });

    // In a production system, this would trigger alerts
    // For now, we'll just ensure it's prominently logged
  }

  /**
   * Generate unique error ID
   */
  private generateErrorId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `err_${timestamp}_${random}`;
  }

  /**
   * Get error metrics for monitoring
   */
  getMetrics(): ErrorMetrics {
    const now = Date.now();
    const recentThreshold = now - (24 * 60 * 60 * 1000); // Last 24 hours

    const recentErrors = this.errors.filter(error => error.timestamp > recentThreshold);
    
    const errorsByCategory = Object.values(ErrorCategory).reduce((acc, category) => {
      acc[category] = recentErrors.filter(error => error.category === category).length;
      return acc;
    }, {} as Record<ErrorCategory, number>);

    const errorsBySeverity = Object.values(ErrorSeverity).reduce((acc, severity) => {
      acc[severity] = recentErrors.filter(error => error.severity === severity).length;
      return acc;
    }, {} as Record<ErrorSeverity, number>);

    return {
      totalErrors: recentErrors.length,
      errorsByCategory,
      errorsBySeverity,
      recentErrors: recentErrors.slice(-10) // Last 10 errors
    };
  }

  /**
   * Clear error history (for testing or maintenance)
   */
  clearHistory(): void {
    this.errors = [];
  }
}

/**
 * Convenience functions for common error handling
 */
export const secureErrorHandler = SecureErrorHandler.getInstance();

export function handleAuthError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.AUTHENTICATION, ErrorSeverity.MEDIUM, context);
}

export function handleCryptoError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.CRYPTOGRAPHY, ErrorSeverity.HIGH, context);
}

export function handleValidationError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.VALIDATION, ErrorSeverity.LOW, context);
}

export function handleNetworkError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.NETWORK, ErrorSeverity.MEDIUM, context);
}

export function handleP2PError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.P2P, ErrorSeverity.MEDIUM, context);
}

export function handleCriticalError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL, context);
}
