/**
 * Security Audit Logger
 */
import { SignalType } from '../types/signal-types';

export class SecurityAuditLogger {
  private static readonly MAX_LOG_ENTRIES = 1000;
  private static readonly SENSITIVE_KEY_PATTERN = /(id|token|key|secret|credential|session|fingerprint|signature|payload|nonce|mac|proof|username|user|peer|inbox|ip|email|account)/i;
  private static logEntries: Array<{
    timestamp: number;
    level: 'info' | 'warn' | SignalType.ERROR;
    event: string;
    details: Record<string, unknown>;
  }> = [];

  private static sanitize(value: unknown, key = '', depth = 0): unknown {
    if (value === null || value === undefined) return value;
    if (depth > 4) return '[REDACTED]';
    if (SecurityAuditLogger.SENSITIVE_KEY_PATTERN.test(key)) return '[REDACTED]';
    if (value instanceof Uint8Array) return `[BINARY:${value.length}bytes]`;
    if (Array.isArray(value)) return value.map((item) => SecurityAuditLogger.sanitize(item, key, depth + 1));
    if (typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
        out[childKey] = SecurityAuditLogger.sanitize(childValue, childKey, depth + 1);
      }
      return out;
    }
    return value;
  }

  static log(level: 'info' | 'warn' | SignalType.ERROR, event: string, details: Record<string, unknown> = {}): void {
    const timestamp = Date.now();
    const entry = {
      timestamp,
      level,
      event,
      details: SecurityAuditLogger.sanitize(details) as Record<string, unknown>
    };

    SecurityAuditLogger.logEntries.push(entry);
    if (SecurityAuditLogger.logEntries.length > SecurityAuditLogger.MAX_LOG_ENTRIES) {
      SecurityAuditLogger.logEntries = SecurityAuditLogger.logEntries.slice(-SecurityAuditLogger.MAX_LOG_ENTRIES);
    }
  }

  static getRecentLogs(count: number = 100): Array<{
    timestamp: number;
    level: 'info' | 'warn' | SignalType.ERROR;
    event: string;
    details: Record<string, unknown>;
  }> {
    if (!Number.isInteger(count) || count <= 0) {
      count = 100;
    }
    return SecurityAuditLogger.logEntries.slice(-count);
  }
}
