/**
 * WebSocket Tor Integration
 */

import { torNetworkManager } from '../transport/tor-network';

export class WebSocketTorIntegration {
  private torReady = false;
  private torListener?: (connected: boolean) => void;

  constructor(private onTorConnectionChange: (connected: boolean) => void) {}

  checkTorListener(): void {
    if (this.torListener) {
      return;
    }

    const listener = (connected: boolean) => {
      this.torReady = connected;
      this.onTorConnectionChange(connected);
    };

    torNetworkManager.onConnectionChange(listener);
    this.torListener = listener;
  }

  checkTorReady(): boolean {
    const connected = torNetworkManager.isConnected();
    this.torReady = connected;
    return connected;
  }

  async checkTorReadyAsync(): Promise<boolean> {
    if (this.checkTorReady()) {
      return true;
    }

    const synced = await torNetworkManager.syncWithDaemon();
    this.torReady = synced && torNetworkManager.isConnected();
    return this.torReady;
  }

  // Adapt timeouts for Tor network conditions
  getAdaptedTimeout(baseTimeout: number): number {
    if (!this.torReady) {
      return baseTimeout;
    }

    const stats = torNetworkManager.getStats();
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

    if (stats.averageLatency > 2000) {
      multiplier *= 2.0;
    } else if (stats.averageLatency > 1000) {
      multiplier *= 1.5;
    }

    return Math.floor(baseTimeout * multiplier);
  }

  // Check if Tor circuit is healthy for WebSocket
  isCircuitHealthy(): boolean {
    return torNetworkManager.getStats().circuitHealth !== 'poor';
  }

  // Check if Tor is ready
  isTorReady(): boolean {
    return this.torReady;
  }

  markTorNotReady(): void {
    this.torReady = false;
  }

  // Get current Tor circuit health
  getCircuitHealth(): string {
    return torNetworkManager.getStats().circuitHealth;
  }

  // Cleanup resources
  cleanup(): void {
    if (this.torListener) {
      torNetworkManager.offConnectionChange(this.torListener);
      this.torListener = undefined;
    }
    this.torReady = false;
  }
}
