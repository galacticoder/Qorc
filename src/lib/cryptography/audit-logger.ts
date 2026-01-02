/**
 * Security Audit Logger
 */
import { SignalType } from '../types/signal-types';

export class SecurityAuditLogger {
  private static readonly MAX_LOG_ENTRIES = 1000;
  private static logEntries: Array<{
    timestamp: number;
    level: 'info' | 'warn' | SignalType.ERROR;
    event: string;
    details: Record<string, unknown>;
  }> = [];

  static log(level: 'info' | 'warn' | SignalType.ERROR, event: string, details: Record<string, unknown> = {}): void {
    const timestamp = Date.now();
    const entry = {
      timestamp,
      level,
      event,
      details: { ...details }
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
