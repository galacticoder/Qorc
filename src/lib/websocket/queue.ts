/**
 * WebSocket Pending Queue Manager
 */

import { v4 as uuidv4 } from 'uuid';
import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { SignalType } from '../types/signal-types';
import type { PendingSend } from '../types/websocket-types';
import {
  MAX_PENDING_QUEUE,
  QUEUE_FLUSH_INTERVAL_MS,
  RATE_LIMIT_BACKOFF_MS,
} from '../constants';

export class WebSocketQueue {
  private pendingQueue: PendingSend[] = [];
  private flushTimer?: ReturnType<typeof setTimeout>;
  private flushInFlight = false;

  constructor(
    private dispatchPayload: (data: unknown, allowQueue: boolean) => Promise<void>,
    private getLifecycleState: () => string
  ) {}

  // Enqueue a pending send entry
  enqueuePending(entry: PendingSend): void {
    if (this.pendingQueue.length >= MAX_PENDING_QUEUE) {
      const dropped = this.pendingQueue.shift();
      SecurityAuditLogger.log('warn', 'ws-queue-drop', {
        reason: 'capacity',
        droppedId: dropped?.id,
        queueSize: this.pendingQueue.length
      });
    }

    this.pendingQueue.push(entry);
    this.pendingQueue.sort((a, b) => a.flushAfter - b.flushAfter);
    this.scheduleFlush();
  }

  // Schedule a flush of the pending queue
  scheduleFlush(delayMs?: number): void {
    if (this.flushTimer || this.pendingQueue.length === 0) {
      return;
    }

    const now = Date.now();
    const nextDue = Math.max(0, this.pendingQueue[0].flushAfter - now);
    const effectiveDelay = delayMs !== undefined ? delayMs : Math.min(QUEUE_FLUSH_INTERVAL_MS, nextDue);

    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flush();
    }, effectiveDelay);
  }

  // Flush the pending queue
  async flush(): Promise<void> {
    if (this.flushInFlight || this.pendingQueue.length === 0) {
      return;
    }

    if (this.getLifecycleState() !== 'connected') {
      this.scheduleFlush(500);
      return;
    }

    this.flushInFlight = true;

    try {
      while (this.pendingQueue.length > 0) {
        const entry = this.pendingQueue[0];

        if (entry.flushAfter > Date.now()) {
          this.scheduleFlush(entry.flushAfter - Date.now());
          break;
        }

        this.pendingQueue.shift();

        try {
          await this.dispatchPayload(entry.payload, false);
          SecurityAuditLogger.log('info', 'ws-queue-flushed', {
            entryId: entry.id,
            attempts: entry.attempt
          });
        } catch (_error) {
          entry.attempt += 1;
          if (entry.attempt >= 3) {
            SecurityAuditLogger.log(SignalType.ERROR, 'ws-queue-dropped', {
              entryId: entry.id,
              error: _error instanceof Error ? _error.message : String(_error)
            });
          } else {
            entry.flushAfter = Date.now() + RATE_LIMIT_BACKOFF_MS * entry.attempt;
            this.pendingQueue.unshift(entry);
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
    const entry = {
      id: uuidv4(),
      payload,
      createdAt: Date.now(),
      attempt: 0,
      flushAfter,
      highPriority
    };
    return entry;
  }

  // Get the current queue length
  getQueueLength(): number {
    return this.pendingQueue.length;
  }

  // Clear the pending queue
  clear(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    this.pendingQueue = [];
    this.flushInFlight = false;
  }
}
