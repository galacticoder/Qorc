/**
 * WebSocket Heartbeat Manager
 */

import { SignalType } from '../types/signal-types';
import type { HeartbeatCallbacks } from '../types/websocket-types';
import {
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_TIMEOUT_MS,
  MAX_MISSED_HEARTBEATS,
} from '../constants';


export class WebSocketHeartbeat {
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private heartbeatTimeoutTimer?: ReturnType<typeof setTimeout>;
  private missedHeartbeats = 0;
  private lifecycleGeneration = 0;
  private inFlightGeneration?: number;

  constructor(private callbacks: HeartbeatCallbacks) {}

  // Start heartbeat mechanism
  start(): void {
    if (this.heartbeatTimer) {
      return;
    }

    this.lifecycleGeneration += 1;
    this.inFlightGeneration = undefined;
    this.missedHeartbeats = 0;
    this.heartbeatTimer = setInterval(() => {
      if (this.callbacks.getLifecycleState() === 'connected') {
        void this.sendHeartbeat();
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  // Stop heartbeat mechanism
  stop(): void {
    this.lifecycleGeneration += 1;
    this.inFlightGeneration = undefined;
    this.missedHeartbeats = 0;
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = undefined;
    }
  }

  // Send heartbeat ping
  private async sendHeartbeat(): Promise<void> {
    const generation = this.lifecycleGeneration;
    if (this.inFlightGeneration === generation) {
      return;
    }
    this.inFlightGeneration = generation;

    let ownedDeadline: ReturnType<typeof setTimeout> | undefined;
    if (!this.heartbeatTimeoutTimer) {
      ownedDeadline = setTimeout(() => {
        if (this.lifecycleGeneration !== generation) return;
        this.heartbeatTimeoutTimer = undefined;
        this.handleMissedHeartbeat();
      }, HEARTBEAT_TIMEOUT_MS);
      this.heartbeatTimeoutTimer = ownedDeadline;
    }

    try {
      await this.callbacks.onSendHeartbeat();
    } catch {
      if (this.lifecycleGeneration !== generation) return;
      if (ownedDeadline && this.heartbeatTimeoutTimer === ownedDeadline) {
        clearTimeout(ownedDeadline);
        this.heartbeatTimeoutTimer = undefined;
      }
      this.handleMissedHeartbeat();
    } finally {
      if (this.inFlightGeneration === generation) {
        this.inFlightGeneration = undefined;
      }
    }
  }

  // Handle heartbeat response
  handleResponse(message: any): void {
    if (message?.type === SignalType.PQ_HEARTBEAT_PONG) {
      const currentSessionId = this.callbacks.getSessionId();
      if (!currentSessionId || message.sessionId !== currentSessionId) {
        this.callbacks.onRehandshakeNeeded();
        return;
      }
    }

    this.missedHeartbeats = 0;

    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = undefined;
    }
  }

  // Handle missed heartbeat
  private handleMissedHeartbeat(): void {
    this.missedHeartbeats += 1;

    if (this.missedHeartbeats >= MAX_MISSED_HEARTBEATS) {
      // Connection appears dead trigger reconnect
      this.callbacks.onConnectionLost(new Error('Heartbeat timeout'));
    }
  }

  // Reset heartbeat state
  reset(): void {
    this.lifecycleGeneration += 1;
    this.inFlightGeneration = undefined;
    this.missedHeartbeats = 0;
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = undefined;
    }
  }
}
