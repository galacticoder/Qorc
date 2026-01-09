/**
 * WebSocket Tor Integration
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { torNetworkManager } from '../transport/tor-network';

export class WebSocketTorIntegration {
  private torReady = false;
  private torListener?: (connected: boolean) => void;
  private lastTorCircuitRotation: number | null = null;
  private torCircuitListener?: () => void;
  private torCircuitInterval?: ReturnType<typeof setInterval>;

  constructor(private onTorDisconnect: () => void) {}

  // Ensure Tor connection listener is attached
  ensureTorListener(): void {
    if (this.torListener) {
      return;
    }

    const listener = (connected: boolean) => {
      this.torReady = connected;
      if (!connected) {
        SecurityAuditLogger.log('warn', 'ws-tor-disconnected', {});
        this.onTorDisconnect();
      }
    };

    try {
      torNetworkManager.onConnectionChange(listener);
      this.torListener = listener;
    } catch {
      SecurityAuditLogger.log('warn', 'ws-tor-listener-attach-failed', {});
    }
  }

  // Check if Tor is ready
  ensureTorReady(): boolean {
    try {
      if (!torNetworkManager.isSupported()) {
        this.torReady = true;
        return true;
      }
      const connected = torNetworkManager.isConnected();
      this.torReady = connected;
      return connected;
    } catch {
      return false;
    }
  }

  // Attach Tor circuit rotation listener
  attachCircuitListener(onCircuitRotation: () => void): void {
    if (!torNetworkManager.isSupported() || this.torCircuitListener) {
      return;
    }

    const checkCircuitRotation = () => {
      try {
        const stats = torNetworkManager.getStats?.();
        if (stats && stats.lastCircuitRotation) {
          if (this.lastTorCircuitRotation &&
            stats.lastCircuitRotation > this.lastTorCircuitRotation) {
            this.handleCircuitRotation();
            onCircuitRotation();
          }
          this.lastTorCircuitRotation = stats.lastCircuitRotation;
        }
      } catch { }
    };

    this.torCircuitListener = checkCircuitRotation;
    this.torCircuitInterval = setInterval(checkCircuitRotation, 10000);
  }

  // Handle Tor circuit rotation
  private handleCircuitRotation(): void {
    this.lastTorCircuitRotation = Date.now();
  }

  // Adapt timeouts for Tor network conditions
  getAdaptedTimeout(baseTimeout: number): number {
    if (!torNetworkManager.isSupported() || !this.torReady) {
      return baseTimeout;
    }

    try {
      const stats = torNetworkManager.getStats?.();
      if (!stats) {
        return baseTimeout;
      }

      let multiplier = 1.0;
      switch (stats.circuitHealth) {
        case 'poor':
          multiplier = 3.0;
          break;
        case 'degraded':
          multiplier = 2.0;
          break;
        case 'good':
          multiplier = 1.5;
          break;
        default:
          multiplier = 1.0;
      }

      if (stats.averageLatency > 1000) {
        multiplier *= 1.5;
      } else if (stats.averageLatency > 2000) {
        multiplier *= 2.0;
      }

      const adapted = Math.floor(baseTimeout * multiplier);

      return adapted;
    } catch {
      return baseTimeout;
    }
  }

  // Check if Tor circuit is healthy for WebSocket
  isCircuitHealthy(): boolean {
    if (!torNetworkManager.isSupported()) {
      return true;
    }

    try {
      const stats = torNetworkManager.getStats?.();
      if (!stats) {
        return false;
      }

      if (stats.circuitHealth === 'poor') {
        SecurityAuditLogger.log('warn', 'ws-tor-circuit-unhealthy', {
          health: stats.circuitHealth,
          avgLatency: stats.averageLatency
        });
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  // Check if Tor is ready
  isTorReady(): boolean {
    return this.torReady;
  }

  // Get current Tor circuit health
  getCircuitHealth(): string {
    if (!torNetworkManager.isSupported()) {
      return 'unknown';
    }
    return torNetworkManager.getStats?.()?.circuitHealth ?? 'unknown';
  }

  // Cleanup resources
  cleanup(): void {
    if (this.torCircuitInterval) {
      clearInterval(this.torCircuitInterval);
      this.torCircuitInterval = undefined;
    }

    if (this.torListener) {
      try {
        torNetworkManager.offConnectionChange(this.torListener);
      } catch { }
      this.torListener = undefined;
    }
  }
}
