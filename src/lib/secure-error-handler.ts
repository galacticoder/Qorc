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

export class SecureErrorHandler {
  private static instance: SecureErrorHandler;
  private errors: SecureError[] = [];
  private readonly MAX_ERROR_HISTORY = 1000;
  private readonly CRITICAL_ALERT_ENDPOINT = '/api/security/critical-error';
  private readonly CRITICAL_LOCAL_KEY = 'secure_critical_errors_v1';
  private readonly MAX_LOCAL_CRITICAL = 100;
  private readonly MIN_ALERT_INTERVAL_MS = 5000;
  private lastAlertSentAt = 0;

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
   * Log error with secure information disclosure control
   */
  private logError(secureError: SecureError, _originalError: Error | string): void {
    const logData = {
      id: secureError.id,
      category: secureError.category,
      severity: secureError.severity,
      timestamp: new Date(secureError.timestamp).toISOString(),
      context: secureError.context
    };

    console.error('[SecureErrorHandler]', logData);
    
    // Log internal details only for critical/high severity
    if (secureError.severity === ErrorSeverity.CRITICAL || secureError.severity === ErrorSeverity.HIGH) {
      console.error('[SecureErrorHandler-Internal]', {
        id: secureError.id,
        message: secureError.internalMessage
      });
    }
  }

  private handleCriticalError(error: SecureError): void {
    console.error('[CRITICAL ERROR]', {
      id: error.id,
      category: error.category,
      timestamp: new Date(error.timestamp).toISOString()
    });

    // Throttle duplicate alerts to avoid alert storms
    const now = Date.now();
    if (now - this.lastAlertSentAt < this.MIN_ALERT_INTERVAL_MS) {
      this.persistCriticalMeta(error);
      this.dispatchBrowserEvent(error);
      return;
    }
    this.lastAlertSentAt = now;

    try {
      const payload = JSON.stringify({
        id: error.id,
        category: error.category,
        severity: error.severity,
        timestamp: error.timestamp,
        context: error.context
      });

      let sent = false;
      if (typeof navigator !== 'undefined' && 'sendBeacon' in navigator) {
        try {
          const blob = new Blob([payload], { type: 'application/json' });
          sent = navigator.sendBeacon(this.CRITICAL_ALERT_ENDPOINT, blob);
        } catch {
          sent = false;
        }
      }

      if (!sent && typeof fetch === 'function') {
        try {
          void fetch(this.CRITICAL_ALERT_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            keepalive: true,
            body: payload,
            credentials: 'omit',
            cache: 'no-store',
            mode: 'same-origin'
          }).catch(() => {});
        } catch {}
      }
    } finally {
      this.persistCriticalMeta(error);
      this.dispatchBrowserEvent(error);
    }
  }

  private dispatchBrowserEvent(error: SecureError): void {
    try {
      if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
        const payload = {
          id: error.id,
          category: error.category,
          severity: error.severity,
          timestamp: error.timestamp,
          context: error.context
        };
        window.dispatchEvent(new CustomEvent('secure-critical-error', { detail: payload }));
      }
    } catch {}
  }

  private persistCriticalMeta(error: SecureError): void {
    try {
      (async () => {
        try {
          const { encryptedStorage } = await import('./encrypted-storage');
          const existing = await encryptedStorage.getItem(this.CRITICAL_LOCAL_KEY);
          let list: Array<{ id: string; category: string; severity: string; ts: number }> = [];
          if (existing) {
            try { list = typeof existing === 'string' ? JSON.parse(existing) : existing; } catch { list = []; }
          }
          list.push({ id: error.id, category: error.category, severity: error.severity, ts: error.timestamp });
          if (list.length > this.MAX_LOCAL_CRITICAL) {
            list = list.slice(list.length - this.MAX_LOCAL_CRITICAL);
          }
          await encryptedStorage.setItem(this.CRITICAL_LOCAL_KEY, JSON.stringify(list));
        } catch {}
      })();
    } catch {}
  }

  /**
   * Generate unique error ID
   */
  private generateErrorId(): string {
    const timestamp = Date.now().toString(36);
    const randomBytes = crypto.getRandomValues(new Uint8Array(4));
    const secureRandom = Array.from(randomBytes, byte => byte.toString(36)).join('');
    return `err_${timestamp}_${secureRandom}`;
  }
}

/**
 * Convenience functions for common error handling
 */
export const secureErrorHandler = SecureErrorHandler.getInstance();

export function handleCryptoError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.CRYPTOGRAPHY, ErrorSeverity.HIGH, context);
}

export function handleNetworkError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.NETWORK, ErrorSeverity.MEDIUM, context);
}

export function handleP2PError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.P2P, ErrorSeverity.MEDIUM, context);
}

export class SecureAuditLogger {
  private static readonly CHANNEL = 'secure-audit';

  static info(namespace: string, event: string, action: string, details?: Record<string, unknown>): void {
  }

  static warn(namespace: string, event: string, action: string, details?: Record<string, unknown>): void {
  }

  static error(namespace: string, event: string, action: string, details?: Record<string, unknown>): void {
  }

  private static sanitize(details?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!details) return undefined;
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(details)) {
      const lowerKey = key.toLowerCase();
      const isSensitive = lowerKey.includes('key') || lowerKey.includes('secret') || lowerKey.includes('token');
      sanitized[key] = isSensitive ? '[REDACTED]' : value;
    }
    return sanitized;
  }
}

export function handleCriticalError(error: Error | string, context?: Record<string, any>): SecureError {
  return secureErrorHandler.handleError(error, ErrorCategory.SYSTEM, ErrorSeverity.CRITICAL, context);
}