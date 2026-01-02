/**
 * Post-Quantum Session Management
 */

import { PostQuantumUtils } from '../utils/pq-utils';
import { PQ_SESSION_DEFAULT_TIMEOUT_MS } from '../constants';
import type { SessionRecord } from '../types/crypto-types';

export class PostQuantumSession {
  private static readonly sessions = new Map<string, SessionRecord>();
  private static sessionTimeout = PQ_SESSION_DEFAULT_TIMEOUT_MS;

  static createSession<T>(sessionId: string, keys: T, timeoutMs: number = PostQuantumSession.sessionTimeout): void {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new Error('Session ID must be a non-empty string');
    }
    const now = Date.now();
    PostQuantumSession.sessions.set(sessionId, {
      keys,
      created: now,
      lastUsed: now
    });
    PostQuantumSession.cleanup(timeoutMs ?? PostQuantumSession.sessionTimeout);
  }

  static getSession<T>(sessionId: string, timeoutMs: number = PostQuantumSession.sessionTimeout): T | null {
    const record = PostQuantumSession.sessions.get(sessionId);
    if (!record) {
      return null;
    }
    const now = Date.now();
    if (now - record.created > timeoutMs) {
      PostQuantumSession.destroySession(sessionId);
      return null;
    }
    record.lastUsed = now;
    return record.keys as T;
  }

  private static securelyEraseKeys(keys: unknown): void {
    try {
      PostQuantumUtils.deepClearSensitiveData(keys);
    } catch {
    }
  }

  static destroySession(sessionId: string): void {
    const record = PostQuantumSession.sessions.get(sessionId);
    if (!record) {
      return;
    }

    try {
      PostQuantumSession.securelyEraseKeys(record.keys);
    } finally {
      PostQuantumSession.sessions.delete(sessionId);
    }
  }

  private static cleanup(timeoutMs: number): void {
    const now = Date.now();
    for (const [sessionId, record] of PostQuantumSession.sessions.entries()) {
      if (now - record.lastUsed > timeoutMs) {
        PostQuantumSession.destroySession(sessionId);
      }
    }
  }

  static getSessionCount(): number {
    return PostQuantumSession.sessions.size;
  }

  static setSessionTimeout(timeoutMs: number): void {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
      throw new Error('sessionTimeout must be a non-negative finite number');
    }
    PostQuantumSession.sessionTimeout = timeoutMs;
  }

  static getSessionTimeout(): number {
    return PostQuantumSession.sessionTimeout;
  }
}
