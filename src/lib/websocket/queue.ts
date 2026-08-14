/**
 * WebSocket Pending Queue Manager
 */

import { v4 as uuidv4 } from 'uuid';
import type { PendingSend } from '../types/websocket-types';
import {
  MAX_PENDING_QUEUE,
  MAX_PENDING_QUEUE_BYTES,
  OUTBOUND_RETRY_MAX_AGE_MS,
  QUEUE_FLUSH_INTERVAL_MS,
  RATE_LIMIT_BACKOFF_MS,
} from '../constants';

export class WebSocketQueue {
  private pendingQueue: PendingSend[] = [];
  private flushTimer?: ReturnType<typeof setTimeout>;
  private flushTimerDueAt: number | null = null;
  private flushInFlight = false;
  private pendingBytes = 0;
  private lifecycleGeneration = 0;

  constructor(
    private dispatchPayload: (data: unknown, allowQueue: boolean) => Promise<void>,
    private getLifecycleState: () => string
  ) {}

  private pruneExpired(now: number = Date.now()): void {
    const retained: PendingSend[] = [];
    let retainedBytes = 0;
    for (const entry of this.pendingQueue) {
      if (
        !Number.isSafeInteger(entry.createdAt) ||
        entry.createdAt <= 0 ||
        entry.createdAt > now ||
        now - entry.createdAt >= OUTBOUND_RETRY_MAX_AGE_MS
      ) continue;
      retained.push(entry);
      retainedBytes += entry.byteLength;
    }
    this.pendingQueue = retained;
    this.pendingBytes = retainedBytes;
  }

  // Enqueue a pending send entry
  enqueuePending(entry: PendingSend): boolean {
    const now = Date.now();
    this.pruneExpired(now);
    if (
      !Number.isSafeInteger(entry.createdAt) ||
      entry.createdAt <= 0 ||
      entry.createdAt > now ||
      now - entry.createdAt >= OUTBOUND_RETRY_MAX_AGE_MS
    ) return false;
    if (entry.byteLength <= 0 || entry.byteLength > MAX_PENDING_QUEUE_BYTES) {
      return false;
    }

    while (
      this.pendingQueue.length >= MAX_PENDING_QUEUE ||
      this.pendingBytes + entry.byteLength > MAX_PENDING_QUEUE_BYTES
    ) {
      const unprivilegedIndex = this.pendingQueue.findIndex(candidate => candidate.highPriority !== true);
      const dropIndex = unprivilegedIndex >= 0
        ? unprivilegedIndex
        : (entry.highPriority === true ? 0 : -1);
      if (dropIndex < 0) {
        return false;
      }
      const [dropped] = this.pendingQueue.splice(dropIndex, 1);
      this.pendingBytes = Math.max(0, this.pendingBytes - dropped.byteLength);
    }

    this.pendingQueue.push(entry);
    this.pendingBytes += entry.byteLength;
    this.pendingQueue.sort((a, b) => a.flushAfter - b.flushAfter);
    this.scheduleFlush();
    return true;
  }

  // Schedule a flush of the pending queue
  scheduleFlush(delayMs?: number): void {
    this.pruneExpired();
    if (this.pendingQueue.length === 0) return;

    const now = Date.now();
    const nextDue = Math.max(0, this.pendingQueue[0].flushAfter - now);
    const effectiveDelay = delayMs !== undefined ? delayMs : Math.min(QUEUE_FLUSH_INTERVAL_MS, nextDue);
    const dueAt = now + Math.max(0, effectiveDelay);
    if (this.flushTimer) {
      if (this.flushTimerDueAt !== null && this.flushTimerDueAt <= dueAt) return;
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    this.flushTimerDueAt = dueAt;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      this.flushTimerDueAt = null;
      void this.flush();
    }, Math.max(0, dueAt - Date.now()));
  }

  // Flush the pending queue
  async flush(): Promise<void> {
    this.pruneExpired();
    if (this.flushInFlight || this.pendingQueue.length === 0) {
      return;
    }

    if (this.getLifecycleState() !== 'connected') {
      this.scheduleFlush(500);
      return;
    }

    const generation = this.lifecycleGeneration;
    this.flushInFlight = true;

    try {
      while (generation === this.lifecycleGeneration && this.pendingQueue.length > 0) {
        const entry = this.pendingQueue[0];

        if (entry.flushAfter > Date.now()) {
          this.scheduleFlush(entry.flushAfter - Date.now());
          break;
        }

        this.pendingQueue.shift();
        this.pendingBytes = Math.max(0, this.pendingBytes - entry.byteLength);

        try {
          await this.dispatchPayload(entry.payload, false);
          if (generation !== this.lifecycleGeneration) break;
        } catch {
          if (generation !== this.lifecycleGeneration) break;
          entry.attempt += 1;
          if (entry.attempt < 3) {
            entry.flushAfter = Date.now() + RATE_LIMIT_BACKOFF_MS * entry.attempt;
            this.pendingQueue.unshift(entry);
            this.pendingBytes += entry.byteLength;
            this.scheduleFlush(entry.flushAfter - Date.now());
          }
          break;
        }
      }
    } finally {
      this.flushInFlight = false;
      if (this.pendingQueue.length > 0 && this.getLifecycleState() === 'connected') {
        this.scheduleFlush();
      }
    }
  }

  // Create a pending send entry
  createEntry(payload: unknown, flushAfter: number, highPriority?: boolean): PendingSend {
    let serialized: string;
    try {
      serialized = typeof payload === 'string' ? payload : JSON.stringify(payload);
    } catch {
      serialized = '';
    }
    const entry = {
      id: uuidv4(),
      payload,
      createdAt: Date.now(),
      attempt: 0,
      flushAfter,
      highPriority,
      byteLength: new TextEncoder().encode(serialized).byteLength,
    };
    return entry;
  }

  // Clear the pending queue
  clear(): void {
    this.lifecycleGeneration += 1;
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    this.flushTimerDueAt = null;
    this.pendingQueue = [];
    this.pendingBytes = 0;
  }
}
