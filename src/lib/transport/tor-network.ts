/**
 * Tor network manager
 */

import {
  TorConfig,
  TorConnectionStats,
  TorRequestResult,
  TorCircuitHealth
} from '../types/tor-types';
import {
  TOR_DEFAULT_MONITOR_INTERVAL_MS,
  TOR_MAX_BACKOFF_MS,
  TOR_CIRCUIT_ROTATION_RATE_LIMIT_MS
} from '../constants';
import { tor as tauriTor, websocket as tauriWebsocket, isTauri } from '../tauri-bindings';
import type { TorInfo, TorStatus } from '../tauri-bindings';

const TOR_DEEP_HEALTH_CHECK_INTERVAL_MS = 5 * 60 * 1000;
const TOR_BOOTSTRAP_TIMEOUT_MS = 150_000;
const TOR_BOOTSTRAP_POLL_MS = 1_000;

export class TorNetworkManager {
  private config: TorConfig;
  private stats: TorConnectionStats;
  private isInitialized = false;
  private readonly connectionCallbacks = new Set<(connected: boolean) => void>();
  private circuitRotationTimer: ReturnType<typeof setInterval> | null = null;
  private connectionMonitorTimer: ReturnType<typeof setInterval> | null = null;
  private connectionMonitorInFlight = false;
  private initializePromise: Promise<boolean> | null = null;
  private monitorBackoffMs = 0;
  private lastManualRotation = 0;
  private lastDeepHealthCheckAt = 0;

  constructor(config?: Partial<TorConfig>) {
    this.config = {
      enabled: false,
      socksPort: 9150,
      controlPort: 9151,
      host: '127.0.0.1',
      circuitRotationInterval: 10,
      maxRetries: 3,
      connectionTimeout: 30_000,
      ...config
    };

    this.stats = {
      isConnected: false,
      isBootstrapped: false,
      circuitCount: 0,
      lastCircuitRotation: 0,
      connectionAttempts: 0,
      failedConnections: 0,
      bytesTransmitted: 0,
      bytesReceived: 0,
      averageLatency: 0,
      lastHealthCheck: 0,
      circuitHealth: 'unknown',
      bootstrapProgress: 0
    };

    if (typeof window !== 'undefined') { }
  }

  // Check if Tauri is available
  private checkTauriAvailable(): boolean {
    return isTauri();
  }

  private async readDaemonState(): Promise<{ status: TorStatus | null; info: TorInfo | null }> {
    if (!this.checkTauriAvailable()) {
      return { status: null, info: null };
    }

    const [status, info] = await Promise.all([
      tauriTor.status().catch(() => null),
      tauriTor.info().catch(() => null)
    ]);

    return { status, info };
  }

  private applyDaemonState(status: TorStatus | null, info: TorInfo | null): boolean {
    const running = Boolean(status?.is_running || info?.bootstrapped);
    const bootstrapped = Boolean(status?.bootstrapped || info?.bootstrapped);
    const progress = status?.bootstrap_progress ?? info?.bootstrap_progress ?? 0;
    const socksPort = info?.socks_port || status?.socks_port;
    const controlPort = info?.control_port || status?.control_port;
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

  private async setBackendTorReady(ready: boolean, socksPort?: number): Promise<void> {
    if (!this.checkTauriAvailable()) {
      return;
    }

    try {
      await tauriWebsocket.setTorReady(ready, socksPort);
    } catch {
      // websocket bridge may not be registered during early startup
    }
  }

  async syncWithDaemon(): Promise<boolean> {
    const { status, info } = await this.readDaemonState();
    const connected = this.applyDaemonState(status, info);
    await this.setBackendTorReady(connected, info?.socks_port || status?.socks_port);

    if (connected) {
      this.startCircuitRotation();
    }
    if (status?.is_running || connected) {
      this.startConnectionMonitoring();
    }

    return connected;
  }

  private async waitForBootstrap(timeoutMs = TOR_BOOTSTRAP_TIMEOUT_MS): Promise<TorInfo | null> {
    const deadline = Date.now() + timeoutMs;
    let latestInfo: TorInfo | null = null;

    while (Date.now() < deadline) {
      const { status, info } = await this.readDaemonState();
      latestInfo = info;
      if (this.applyDaemonState(status, info)) {
        return info;
      }
      if (status && !status.is_running) {
        return null;
      }
      await new Promise((resolve) => setTimeout(resolve, TOR_BOOTSTRAP_POLL_MS));
    }

    return latestInfo?.bootstrapped ? latestInfo : null;
  }

  // Retry with exponential backoff
  private async retryWithBackoff<T>(operation: () => Promise<T>, maxRetries = this.config.maxRetries): Promise<T> {
    let attempt = 0;
    let lastError: unknown;

    while (attempt <= maxRetries) {
      try {
        return await operation();
      } catch (_error) {
        lastError = _error;
        attempt += 1;
        if (attempt > maxRetries) break;

        const delay = Math.min(1000 * 2 ** (attempt - 1), TOR_MAX_BACKOFF_MS);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    throw lastError ?? new Error('Unknown Tor operation failure');
  }

  // Start circuit rotation
  private startCircuitRotation(): void {
    if (this.circuitRotationTimer) {
      clearInterval(this.circuitRotationTimer);
    }

    if (this.config.circuitRotationInterval <= 0) {
      this.circuitRotationTimer = null;
      return;
    }

    const intervalMs = Math.max(1, this.config.circuitRotationInterval) * 60 * 1000;
    const timer = setInterval(async () => {
      await this.rotateCircuit();
    }, intervalMs);

    this.circuitRotationTimer = timer;
  }

  // Stop circuit rotation
  private stopCircuitRotation(): void {
    if (this.circuitRotationTimer) {
      clearInterval(this.circuitRotationTimer);
      this.circuitRotationTimer = null;
    }
  }

  // Start connection monitoring
  private startConnectionMonitoring(): void {
    if (this.connectionMonitorTimer) {
      clearInterval(this.connectionMonitorTimer);
    }

    const timer = setInterval(async () => {
      if (!this.isInitialized) {
        return;
      }
      if (this.connectionMonitorInFlight) {
        return;
      }

      this.connectionMonitorInFlight = true;

      try {
        const wasConnected = this.stats.isConnected;
        const { status, info } = await this.readDaemonState();
        const connected = this.applyDaemonState(status, info);
        await this.setBackendTorReady(connected, info?.socks_port || status?.socks_port);
        await this.checkCircuitHealth(connected, { forceDeep: connected && !wasConnected });

        if (!connected && wasConnected) {
          this.scheduleReinitialization();
        }
      } catch (_error) {
        console.error('[TOR] Connection monitoring failed:', _error);
        this.markDisconnected();
        await this.setBackendTorReady(false);
        this.scheduleReinitialization();
      } finally {
        this.connectionMonitorInFlight = false;
      }
    }, TOR_DEFAULT_MONITOR_INTERVAL_MS);

    this.connectionMonitorTimer = timer;
  }

  private isInitializing = false;

  // Schedule reinitialization
  private scheduleReinitialization(): void {
    if (this.monitorBackoffMs === 0) {
      this.monitorBackoffMs = 1000;
    } else {
      this.monitorBackoffMs = Math.min(this.monitorBackoffMs * 2, TOR_MAX_BACKOFF_MS);
    }

    setTimeout(async () => {
      if (this.isInitialized && this.stats.isConnected) {
        return;
      }

      if (this.isInitializing) {
        return;
      }

      const success = await this.initialize();
      if (success) {
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

    this.stopCircuitRotation();
  }

  // Check circuit health
  private async checkCircuitHealth(
    connected: boolean,
    options: { forceDeep?: boolean } = {}
  ): Promise<void> {
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
    const test = await tauriTor.testConnection();
    const latency = performance.now() - start;
    this.lastDeepHealthCheckAt = Date.now();

    if (!test.success) {
      this.stats.circuitHealth = 'poor';
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
    if (!this.config.enabled) {
      return false;
    }

    if (!this.checkTauriAvailable()) {
      return false;
    }

    if (this.initializePromise) {
      return this.initializePromise;
    }

    if (this.isInitialized && this.stats.isConnected) {
      await this.setBackendTorReady(true, this.config.socksPort);
      return true;
    }

    if (this.isInitializing) {
      return this.initializePromise ?? false;
    }

    this.initializePromise = (async () => {
      this.isInitializing = true;

      try {
        if (await this.syncWithDaemon()) {
          return true;
        }

        const { status } = await this.readDaemonState();
        if (!status?.is_running) {
          let result = await this.retryWithBackoff(() => tauriTor.start());
          if (!result.success && /not configured|torrc|configuration/i.test(result.error || '')) {
            await tauriTor.configure(`SocksPort ${this.config.socksPort}\nControlPort ${this.config.controlPort}`);
            result = await this.retryWithBackoff(() => tauriTor.start());
          }
          if (!result.success) {
            throw new Error(result.error || 'Failed to start Tor');
          }
        }

        const info = await this.waitForBootstrap(
          Math.max(TOR_BOOTSTRAP_TIMEOUT_MS, this.config.connectionTimeout || 0)
        );

        if (!info?.bootstrapped) {
          this.stats.failedConnections += 1;
          const latest = await this.readDaemonState();
          if (latest.status?.is_running) {
            this.applyDaemonState(latest.status, latest.info);
            this.startConnectionMonitoring();
          } else {
            this.markDisconnected();
          }
          await this.setBackendTorReady(false);
          return false;
        }

        if (info.socks_port) this.config.socksPort = info.socks_port;
        if (info.control_port) this.config.controlPort = info.control_port;

        this.isInitialized = true;
        this.stats.isConnected = true;
        this.stats.isBootstrapped = true;
        this.stats.bootstrapProgress = info.bootstrap_progress || 0;
        this.stats.circuitHealth = 'good';
        this.stats.failedConnections = 0;

        await this.setBackendTorReady(true, info.socks_port);
        this.startCircuitRotation();
        this.startConnectionMonitoring();

        this.testTorConnection().then(verified => {
          this.stats.lastHealthCheck = Date.now();
          if (!verified) {
            this.stats.isConnected = false;
            this.stats.isBootstrapped = false;
            this.stats.circuitHealth = 'poor';
            this.notifyConnectionCallbacks(false);
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
        console.error('[TOR] Failed to initialize Tor connection:', _error);
        this.stats.failedConnections += 1;
        this.markDisconnected();
        await this.setBackendTorReady(false);
        return false;
      } finally {
        this.isInitializing = false;
      }
    })();

    try {
      return await this.initializePromise;
    } finally {
      this.initializePromise = null;
    }
  }

  // Test Tor connection
  private async testTorConnection(): Promise<boolean> {
    try {
      const startedAt = performance.now();
      const result = await tauriTor.testConnection();
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

  // Create Tor WebSocket
  async createTorWebSocket(url: string): Promise<WebSocket | null> {
    if (!this.isInitialized) {
      console.error('[TOR] Tor not initialized cannot create WebSocket');
      return null;
    }

    try {
      const lowerUrl = url.toLowerCase();
      if (!lowerUrl.startsWith('ws://') && !lowerUrl.startsWith('wss://')) {
        throw new Error(`Invalid WebSocket URL scheme: ${url.split(':')[0]}. Only ws:// or wss:// allowed.`);
      }
      return new WebSocket(url);
    } catch (_error) {
      console.error('[TOR] Failed to create Tor WebSocket:', _error);
      return null;
    }
  }

  // Make Tor request
  async makeRequest(options: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  }): Promise<TorRequestResult> {
    if (!this.isInitialized) {
      throw new Error('Tor network not initialized');
    }

    if (!options.url || typeof options.url !== 'string') {
      throw new Error('Invalid URL provided');
    }

    throw new Error('Direct Tor HTTP requests not supported - use Tauri backend');
  }

  // Rotate Tor circuit
  async rotateCircuit(): Promise<boolean> {
    if (!this.isInitialized) {
      console.error('[TOR] Cannot rotate circuit - Tor not initialized');
      return false;
    }

    const now = Date.now();
    if (now - this.lastManualRotation < TOR_CIRCUIT_ROTATION_RATE_LIMIT_MS) {
      return false;
    }

    try {
      const result = await this.retryWithBackoff(() => tauriTor.rotateCircuit());

      if (!result.success) {
        console.error('[TOR] Circuit rotation failed');
        return false;
      }

      this.stats.circuitCount += 1;
      this.stats.lastCircuitRotation = now;
      this.lastManualRotation = now;
      this.notifyStatsCallbacks();

      return true;
    } catch (_error) {
      console.error('[TOR] Circuit rotation error:', _error);
      return false;
    }
  }

  // Get Tor stats
  getStats(): TorConnectionStats {
    return { ...this.stats };
  }

  // Check if Tor is bootstrapped
  isBootstrapped(): boolean {
    return this.stats.isBootstrapped || false;
  }

  // Check if Tor is connected
  isConnected(): boolean {
    return this.config.enabled && this.stats.isConnected;
  }

  // Check if Tor is supported
  isSupported(): boolean {
    return this.checkTauriAvailable();
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
    if (newConfig.circuitRotationInterval !== undefined && Number.isInteger(newConfig.circuitRotationInterval) && newConfig.circuitRotationInterval >= 0) {
      validatedConfig.circuitRotationInterval = newConfig.circuitRotationInterval;
    }
    if (newConfig.maxRetries !== undefined && Number.isInteger(newConfig.maxRetries) && newConfig.maxRetries >= 0) {
      validatedConfig.maxRetries = newConfig.maxRetries;
    }
    if (newConfig.connectionTimeout !== undefined && Number.isInteger(newConfig.connectionTimeout) && newConfig.connectionTimeout > 0) {
      validatedConfig.connectionTimeout = newConfig.connectionTimeout;
    }

    this.config = { ...this.config, ...validatedConfig };

    if (this.isInitialized && validatedConfig.circuitRotationInterval !== undefined) {
      this.startCircuitRotation();
    }
  }

  // Shutdown Tor network
  async shutdown(): Promise<void> {
    this.stopAllTimers();
    this.markDisconnected();
    await this.setBackendTorReady(false);

    this.lastManualRotation = 0;
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
