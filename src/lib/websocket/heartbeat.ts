/**
 * WebSocket Heartbeat Manager
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { SignalType } from '../types/signal-types';
import type { ConnectionMetrics, HeartbeatCallbacks } from '../types/websocket-types';
import {
  HEARTBEAT_INTERVAL_MS,
  HEARTBEAT_TIMEOUT_MS,
  MAX_MISSED_HEARTBEATS,
  LATENCY_SAMPLE_WEIGHT,
} from '../constants';


export class WebSocketHeartbeat {
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private heartbeatTimeoutTimer?: ReturnType<typeof setTimeout>;
  private lastHeartbeatSent: number | null = null;
  private lastHeartbeatReceived: number | null = null;
  private missedHeartbeats = 0;

  constructor(
    private metrics: ConnectionMetrics,
    private callbacks: HeartbeatCallbacks
  ) {}

  // Start heartbeat mechanism
  start(): void {
    if (this.heartbeatTimer) {
      return;
    }

    this.heartbeatTimer = setInterval(() => {
      if (this.callbacks.getLifecycleState() === 'connected') {
        void this.sendHeartbeat();
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  // Stop heartbeat mechanism
  stop(): void {
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
    try {
      this.lastHeartbeatSent = Date.now();

      await this.callbacks.onSendHeartbeat();

      // Set timeout for response
      if (this.heartbeatTimeoutTimer) {
        clearTimeout(this.heartbeatTimeoutTimer);
      }

      this.heartbeatTimeoutTimer = setTimeout(() => {
        this.handleMissedHeartbeat();
      }, HEARTBEAT_TIMEOUT_MS);

    } catch {
      this.handleMissedHeartbeat();
    }
  }

  // Handle heartbeat response
  handleResponse(message: any): void {
    if (message?.type === 'pq-heartbeat-pong') {
      const currentSessionId = this.callbacks.getSessionId();
      if (!currentSessionId || message.sessionId !== currentSessionId) {
        this.callbacks.onRehandshakeNeeded();
        return;
      }
    }

    const now = Date.now();
    this.lastHeartbeatReceived = now;
    this.missedHeartbeats = 0;

    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = undefined;
    }

    if (this.lastHeartbeatSent) {
      const latency = now - this.lastHeartbeatSent;
      this.updateLatencyMetrics(latency);
    }
  }

  // Handle missed heartbeat
  private handleMissedHeartbeat(): void {
    this.missedHeartbeats += 1;

    if (this.missedHeartbeats >= MAX_MISSED_HEARTBEATS) {
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-heartbeat-connection-lost', {
        missedCount: this.missedHeartbeats
      });

      // Connection appears dead trigger reconnect
      this.callbacks.onConnectionLost(new Error('Heartbeat timeout'));
    }
  }

  // Update latency metrics with exponential moving average
  private updateLatencyMetrics(latency: number): void {
    this.metrics.lastLatencyMs = latency;

    if (this.metrics.averageLatencyMs === 0) {
      this.metrics.averageLatencyMs = latency;
    } else {
      this.metrics.averageLatencyMs =
        this.metrics.averageLatencyMs * (1 - LATENCY_SAMPLE_WEIGHT) +
        latency * LATENCY_SAMPLE_WEIGHT;
    }
  }

  // Get connection quality assessment
  assessConnectionQuality(lifecycleState: string): 'excellent' | 'good' | 'fair' | 'poor' | 'unknown' {
    if (lifecycleState !== 'connected' || this.metrics.averageLatencyMs === 0) {
      return 'unknown';
    }

    const latency = this.metrics.averageLatencyMs;

    if (latency < 100) return 'excellent';
    if (latency < 300) return 'good';
    if (latency < 1000) return 'fair';
    return 'poor';
  }

  // Get missed heartbeats count
  getMissedHeartbeats(): number {
    return this.missedHeartbeats;
  }

  // Get last heartbeat received timestamp
  getLastHeartbeatReceived(): number | null {
    return this.lastHeartbeatReceived;
  }

  // Reset heartbeat state
  reset(): void {
    this.missedHeartbeats = 0;
    this.lastHeartbeatSent = null;
    this.lastHeartbeatReceived = null;
  }
}
