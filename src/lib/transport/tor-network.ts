/**
 * Tor network manager
 */

import {
  TorConfig,
  TorConnectionStats,
  TorCircuitHealth
} from '../types/tor-types';
import {
  TOR_DEFAULT_MONITOR_INTERVAL_MS,
  TOR_MAX_BACKOFF_MS
} from '../constants';
import { tor, websocket } from '../tauri-bindings';
import type { TorStatus } from '../tauri-bindings';

const TOR_DEEP_HEALTH_CHECK_INTERVAL_MS = 5 * 60 * 1000;
const TOR_BOOTSTRAP_TIMEOUT_MS = 150_000;
const TOR_BOOTSTRAP_POLL_MS = 1_000;

export class TorNetworkManager {
  private config: TorConfig;
  private stats: TorConnectionStats;
  private isInitialized = false;
  private readonly connectionCallbacks = new Set<(connected: boolean) => void>();
  private connectionMonitorTimer: ReturnType<typeof setInterval> | null = null;
  private reinitializationTimer: ReturnType<typeof setTimeout> | null = null;
  private connectionMonitorInFlight = false;
  private initializePromise: Promise<boolean> | null = null;
  private initializePromiseGeneration: number | null = null;
  private lifecycleGeneration = 0;
  private monitorBackoffMs = 0;
  private lastDeepHealthCheckAt = 0;

  constructor(config?: Partial<TorConfig>) {
    this.config = {
      enabled: false,
      socksPort: 9150,
      controlPort: 9151,
      host: '127.0.0.1',
      maxRetries: 3,
      connectionTimeout: 30_000,
      ...config
    };

    this.stats = {
      isConnected: false,
      isBootstrapped: false,
      connectionAttempts: 0,
      failedConnections: 0,
      bytesTransmitted: 0,
      bytesReceived: 0,
      averageLatency: 0,
      lastHealthCheck: 0,
      circuitHealth: 'unknown',
      bootstrapProgress: 0
    };

  }

  private async readDaemonState(): Promise<TorStatus> {
    return tor.status();
  }

  private applyDaemonState(status: TorStatus): boolean {
    const running = status.is_running;
    const bootstrapped = running && status.bootstrapped;
    const progress = status.bootstrap_progress;
    const socksPort = status.socks_port;
    const controlPort = status.control_port;
    const wasConnected = this.stats.isConnected;

    if (socksPort) {
      this.config.socksPort = socksPort;
    }
    if (controlPort) {
      this.config.controlPort = controlPort;
    }
    if (running) {
      this.config.enabled = true;
    }

    this.isInitialized = running;
    this.stats.isConnected = running && bootstrapped;
    this.stats.isBootstrapped = bootstrapped;
    this.stats.bootstrapProgress = progress;

    if (!running) {
      this.stats.circuitHealth = 'unknown';
      this.stats.averageLatency = 0;
    } else if (!bootstrapped) {
      this.stats.circuitHealth = 'poor';
      this.stats.averageLatency = Number.POSITIVE_INFINITY;
    } else if (this.stats.circuitHealth === 'unknown' || this.stats.circuitHealth === 'poor') {
      this.stats.circuitHealth = 'good';
      this.stats.averageLatency = Number.isFinite(this.stats.averageLatency) ? this.stats.averageLatency : 0;
    }

    if (wasConnected !== this.stats.isConnected) {
      this.notifyConnectionCallbacks(this.stats.isConnected);
    } else {
      this.notifyStatsCallbacks();
    }

    return this.stats.isConnected;
  }

  private markDisconnected(): void {
    this.isInitialized = false;
    this.stats.isConnected = false;
    this.stats.isBootstrapped = false;
    this.stats.bootstrapProgress = 0;
    this.stats.circuitHealth = 'unknown';
    this.stats.averageLatency = 0;
    this.notifyConnectionCallbacks(false);
  }

  private async syncBackendTorState(): Promise<void> {
    await websocket.syncTorState();
  }

  async syncWithDaemon(): Promise<boolean> {
    const generation = this.lifecycleGeneration;
    const status = await this.readDaemonState();
    if (generation !== this.lifecycleGeneration) return false;
    const connected = this.applyDaemonState(status);
    await this.syncBackendTorState();
    if (generation !== this.lifecycleGeneration) return false;

    if (status.is_running || connected) {
      this.startConnectionMonitoring();
    }

    return connected;
  }

  private async waitForBootstrap(
    timeoutMs = TOR_BOOTSTRAP_TIMEOUT_MS,
    generation = this.lifecycleGeneration
  ): Promise<TorStatus | null> {
    const deadline = Date.now() + timeoutMs;
    let latestStatus: TorStatus | null = null;

    while (Date.now() < deadline) {
      if (generation !== this.lifecycleGeneration) return null;
      const status = await this.readDaemonState();
      if (generation !== this.lifecycleGeneration) return null;
      latestStatus = status;
      if (this.applyDaemonState(status)) {
        return status;
      }
      if (!status.is_running) {
        return null;
      }
      await new Promise((resolve) => setTimeout(resolve, TOR_BOOTSTRAP_POLL_MS));
    }

    return latestStatus?.bootstrapped ? latestStatus : null;
  }

  // Retry with exponential backoff
  private async retryWithBackoff<T>(
    operation: () => Promise<T>,
    maxRetries = this.config.maxRetries,
    isCurrent: () => boolean = () => true
  ): Promise<T> {
    let attempt = 0;
    let lastError: unknown;

    while (attempt <= maxRetries) {
      if (!isCurrent()) throw new Error('Tor operation was cancelled');
      try {
        return await operation();
      } catch (_error) {
        if (!isCurrent()) throw new Error('Tor operation was cancelled');
        lastError = _error;
        attempt += 1;
        if (attempt > maxRetries) break;

        const delay = Math.min(1000 * 2 ** (attempt - 1), TOR_MAX_BACKOFF_MS);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    throw lastError ?? new Error('Unknown Tor operation failure');
  }

  // Start connection monitoring
  private startConnectionMonitoring(): void {
    if (this.connectionMonitorTimer) {
      clearInterval(this.connectionMonitorTimer);
    }

    const generation = this.lifecycleGeneration;
    const timer = setInterval(async () => {
      if (generation !== this.lifecycleGeneration) return;
      if (!this.isInitialized) {
        return;
      }
      if (this.connectionMonitorInFlight) {
        return;
      }

      this.connectionMonitorInFlight = true;

      try {
        const wasConnected = this.stats.isConnected;
        const status = await this.readDaemonState();
        if (generation !== this.lifecycleGeneration) return;
        const connected = this.applyDaemonState(status);
        await this.syncBackendTorState();
        if (generation !== this.lifecycleGeneration) return;
        await this.checkCircuitHealth(connected, {
          forceDeep: connected && !wasConnected,
          generation
        });
        if (generation !== this.lifecycleGeneration) return;

        if (!connected && wasConnected) {
          this.scheduleReinitialization();
        }
      } catch (_error) {
        if (generation !== this.lifecycleGeneration) return;
        console.error('[TOR] Connection monitoring failed:', _error);
      } finally {
        if (generation === this.lifecycleGeneration) {
          this.connectionMonitorInFlight = false;
        }
      }
    }, TOR_DEFAULT_MONITOR_INTERVAL_MS);

    this.connectionMonitorTimer = timer;
  }

  private initializingGeneration: number | null = null;

  // Schedule reinitialization
  private scheduleReinitialization(): void {
    if (this.reinitializationTimer || !this.config.enabled) return;
    const generation = this.lifecycleGeneration;
    if (this.monitorBackoffMs === 0) {
      this.monitorBackoffMs = 1000;
    } else {
      this.monitorBackoffMs = Math.min(this.monitorBackoffMs * 2, TOR_MAX_BACKOFF_MS);
    }

    this.reinitializationTimer = setTimeout(async () => {
      this.reinitializationTimer = null;
      if (generation !== this.lifecycleGeneration) return;
      if (this.isInitialized && this.stats.isConnected) {
        return;
      }

      if (this.initializingGeneration === generation) {
        return;
      }

      const success = await this.initialize();
      if (generation === this.lifecycleGeneration && success) {
        this.monitorBackoffMs = 0;
      }
    }, this.monitorBackoffMs);
  }

  // Stop all timers
  private stopAllTimers(): void {
    if (this.connectionMonitorTimer) {
      clearInterval(this.connectionMonitorTimer);
      this.connectionMonitorTimer = null;
    }
    this.connectionMonitorInFlight = false;

    if (this.reinitializationTimer) {
      clearTimeout(this.reinitializationTimer);
      this.reinitializationTimer = null;
    }
  }

  // Check circuit health
  private async checkCircuitHealth(
    connected: boolean,
    options: { forceDeep?: boolean; generation?: number } = {}
  ): Promise<void> {
    const generation = options.generation ?? this.lifecycleGeneration;
    if (generation !== this.lifecycleGeneration) return;
    this.stats.connectionAttempts += 1;
    this.stats.lastHealthCheck = Date.now();

    if (!connected) {
      this.stats.circuitHealth = 'poor';
      this.stats.averageLatency = Number.POSITIVE_INFINITY;
      this.notifyStatsCallbacks();
      return;
    }

    const shouldRunDeepCheck =
      !!options.forceDeep ||
      this.lastDeepHealthCheckAt === 0 ||
      (Date.now() - this.lastDeepHealthCheckAt) >= TOR_DEEP_HEALTH_CHECK_INTERVAL_MS;

    if (!shouldRunDeepCheck) {
      if (this.stats.circuitHealth === 'unknown') {
        this.stats.circuitHealth = 'good';
      } else if (this.stats.circuitHealth === 'poor') {
        this.stats.circuitHealth = 'degraded';
      }
      this.notifyStatsCallbacks();
      return;
    }

    const start = performance.now();
    const test = await tor.verifyConnection();
    if (generation !== this.lifecycleGeneration) return;
    const latency = performance.now() - start;
    this.lastDeepHealthCheckAt = Date.now();

    if (!test.success) {
      this.stats.circuitHealth = 'degraded';
      this.stats.averageLatency = Number.POSITIVE_INFINITY;
      this.notifyStatsCallbacks();
      return;
    }

    if (latency > 5000) {
      this.stats.circuitHealth = 'degraded';
    } else {
      this.stats.circuitHealth = 'good';
    }
    this.stats.averageLatency = Number.isFinite(this.stats.averageLatency)
      ? this.stats.averageLatency * 0.8 + latency * 0.2
      : latency;
    this.notifyStatsCallbacks();
  }

  // Initialize Tor network
  async initialize(): Promise<boolean> {
    const generation = this.lifecycleGeneration;
    if (!this.config.enabled) {
      return false;
    }

    if (this.initializePromise && this.initializePromiseGeneration === generation) {
      return this.initializePromise;
    }

    if (this.isInitialized && this.stats.isConnected) {
      await this.syncBackendTorState();
      return true;
    }

    if (this.initializingGeneration === generation) {
      if (!this.initializePromise) throw new Error('Tor initialization state is inconsistent');
      return this.initializePromise;
    }

    const initialization = (async () => {
      this.initializingGeneration = generation;
      const isCurrent = () => generation === this.lifecycleGeneration;

      try {
        if (await this.syncWithDaemon()) {
          return true;
        }
        if (!isCurrent()) return false;

        const status = await this.readDaemonState();
        if (!isCurrent()) return false;
        if (!status.is_running) {
          const result = await this.retryWithBackoff(
            () => tor.start(),
            this.config.maxRetries,
            isCurrent
          );
          if (!isCurrent()) return false;
          if (!result.success) {
            throw new Error(result.error || 'Failed to start Tor');
          }
        }

        const statusAfterBootstrap = await this.waitForBootstrap(
          Math.max(TOR_BOOTSTRAP_TIMEOUT_MS, this.config.connectionTimeout || 0),
          generation
        );
        if (!isCurrent()) return false;

        if (!statusAfterBootstrap?.bootstrapped) {
          this.stats.failedConnections += 1;
          const latest = await this.readDaemonState();
          if (!isCurrent()) return false;
          if (latest.is_running) {
            this.applyDaemonState(latest);
            this.startConnectionMonitoring();
          } else {
            this.markDisconnected();
          }
          await this.syncBackendTorState();
          if (!isCurrent()) return false;
          return false;
        }

        this.config.socksPort = statusAfterBootstrap.socks_port;
        this.config.controlPort = statusAfterBootstrap.control_port;

        this.isInitialized = true;
        this.stats.isConnected = true;
        this.stats.isBootstrapped = true;
        this.stats.bootstrapProgress = statusAfterBootstrap.bootstrap_progress;
        this.stats.circuitHealth = 'good';
        this.stats.failedConnections = 0;

        await this.syncBackendTorState();
        if (!isCurrent()) return false;
        this.startConnectionMonitoring();

        this.testTorConnection(generation).then(verified => {
          if (!isCurrent()) return;
          this.stats.lastHealthCheck = Date.now();
          if (!verified) {
            this.stats.circuitHealth = 'degraded';
            this.stats.averageLatency = Number.POSITIVE_INFINITY;
            this.notifyStatsCallbacks();
          } else {
            this.stats.isConnected = true;
            this.stats.isBootstrapped = true;
            this.stats.circuitHealth = 'good';
            this.notifyConnectionCallbacks(true);
          }
          this.notifyStatsCallbacks();
        });

        return true;
      } catch (_error) {
        if (!isCurrent()) return false;
        console.error('[TOR] Failed to initialize Tor connection:', _error);
        this.stats.failedConnections += 1;
        this.markDisconnected();
        await this.syncBackendTorState();
        return false;
      } finally {
        if (this.initializingGeneration === generation) {
          this.initializingGeneration = null;
        }
      }
    })();
    this.initializePromise = initialization;
    this.initializePromiseGeneration = generation;

    try {
      return await initialization;
    } finally {
      if (this.initializePromise === initialization) {
        this.initializePromise = null;
        this.initializePromiseGeneration = null;
      }
    }
  }

  // Test Tor connection
  private async testTorConnection(generation = this.lifecycleGeneration): Promise<boolean> {
    try {
      if (generation !== this.lifecycleGeneration) return false;
      const startedAt = performance.now();
      const result = await tor.verifyConnection();
      if (generation !== this.lifecycleGeneration) return false;
      const latency = performance.now() - startedAt;
      this.lastDeepHealthCheckAt = Date.now();

      if (!result.success && result.error) {
        console.error('[TOR] Connection test failed:', result.error);
      } else if (result.success) {
        this.stats.circuitHealth = latency > 5000 ? 'degraded' : 'good';
        this.stats.averageLatency = Number.isFinite(this.stats.averageLatency)
          ? this.stats.averageLatency * 0.8 + latency * 0.2
          : latency;
      }
      return result.success;
    } catch (_error) {
      console.error('[TOR] Connection test error:', _error);
      return false;
    }
  }

  // Get Tor stats
  getStats(): TorConnectionStats {
    return { ...this.stats };
  }

  // Check if Tor is bootstrapped
  isBootstrapped(): boolean {
    return this.stats.isBootstrapped;
  }

  // Check if Tor is connected
  isConnected(): boolean {
    return this.config.enabled && this.stats.isConnected;
  }

  // Register connection change callback
  onConnectionChange(callback: (connected: boolean) => void): void {
    this.connectionCallbacks.add(callback);
  }

  // Unregister connection change callback
  offConnectionChange(callback: (connected: boolean) => void): void {
    this.connectionCallbacks.delete(callback);
  }

  // Notify connection callbacks
  private notifyConnectionCallbacks(connected: boolean): void {
    this.connectionCallbacks.forEach((callback) => {
      try {
        callback(connected);
      } catch (_error) {
        console.error('[TOR] Error in connection callback:', _error);
      }
    });
    this.notifyStatsCallbacks();
  }

  // Notify stats callbacks
  private readonly statsCallbacks = new Set<(stats: TorConnectionStats) => void>();

  // Register stats change callback
  onStatsChange(callback: (stats: TorConnectionStats) => void): void {
    this.statsCallbacks.add(callback);
  }

  // Unregister stats change callback
  offStatsChange(callback: (stats: TorConnectionStats) => void): void {
    this.statsCallbacks.delete(callback);
  }

  // Notify stats callbacks
  private notifyStatsCallbacks(): void {
    const currentStats = this.getStats();
    this.statsCallbacks.forEach((callback) => {
      try {
        callback(currentStats);
      } catch (_error) {
        console.error('[TOR] Error in stats callback:', _error);
      }
    });
  }

  // Update Tor configuration
  updateConfig(newConfig: Partial<TorConfig>): void {
    const validatedConfig: Partial<TorConfig> = {};

    if (newConfig.enabled !== undefined) {
      validatedConfig.enabled = Boolean(newConfig.enabled);
    }
    if (newConfig.socksPort !== undefined && Number.isInteger(newConfig.socksPort) && newConfig.socksPort > 0) {
      validatedConfig.socksPort = newConfig.socksPort;
    }
    if (newConfig.controlPort !== undefined && Number.isInteger(newConfig.controlPort) && newConfig.controlPort > 0) {
      validatedConfig.controlPort = newConfig.controlPort;
    }
    if (newConfig.host !== undefined && typeof newConfig.host === 'string') {
      validatedConfig.host = newConfig.host;
    }
    if (newConfig.maxRetries !== undefined && Number.isInteger(newConfig.maxRetries) && newConfig.maxRetries >= 0) {
      validatedConfig.maxRetries = newConfig.maxRetries;
    }
    if (newConfig.connectionTimeout !== undefined && Number.isInteger(newConfig.connectionTimeout) && newConfig.connectionTimeout > 0) {
      validatedConfig.connectionTimeout = newConfig.connectionTimeout;
    }

    this.config = { ...this.config, ...validatedConfig };
  }

  // Shutdown Tor network
  async shutdown(): Promise<void> {
    this.lifecycleGeneration += 1;
    this.initializePromise = null;
    this.initializePromiseGeneration = null;
    this.initializingGeneration = null;
    this.stopAllTimers();
    this.markDisconnected();
    await this.syncBackendTorState();

    this.monitorBackoffMs = 0;
  }

  // Get connection health
  getConnectionHealth(): {
    isHealthy: boolean;
    circuitHealth: TorCircuitHealth;
    averageLatency: number;
    lastHealthCheck: number;
  } {
    return {
      isHealthy: this.stats.isConnected && this.stats.circuitHealth !== 'poor',
      circuitHealth: this.stats.circuitHealth,
      averageLatency: this.stats.averageLatency,
      lastHealthCheck: this.stats.lastHealthCheck
    };
  }
}

export const torNetworkManager = new TorNetworkManager();
