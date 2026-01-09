/**
 * Tor network manager
 */

import { 
  TorConfig,
  TorConnectionStats,
  TorElectronNetworkAPI,
  TorRequestResult,
  TorCircuitHealth,
  REQUIRED_ELECTRON_METHODS
 } from '../types/tor-types';
import { 
  TOR_DEFAULT_MONITOR_INTERVAL_MS,
  TOR_MAX_BACKOFF_MS,
  TOR_CIRCUIT_ROTATION_RATE_LIMIT_MS
 } from '../constants';

export class TorNetworkManager {
  private config: TorConfig;
  private stats: TorConnectionStats;
  private isInitialized = false;
  private readonly connectionCallbacks = new Set<(connected: boolean) => void>();
  private circuitRotationTimer: ReturnType<typeof setInterval> | null = null;
  private connectionMonitorTimer: ReturnType<typeof setInterval> | null = null;
  private monitorBackoffMs = 0;
  private lastManualRotation = 0;

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
      circuitHealth: 'unknown'
    };

    if (typeof window !== 'undefined') {
      this.validateElectronAPI();
    }
  }

  // Validate Electron API
  private validateElectronAPI(): TorElectronNetworkAPI {
    if (typeof window === 'undefined') {
      throw new Error('[TOR] Electron APIs unavailable outside renderer environment');
    }

    const api = window.electronAPI as any;
    if (!api) {
      throw new Error('[TOR] Electron API not available');
    }

    for (const method of REQUIRED_ELECTRON_METHODS) {
      if (typeof api[method] !== 'function') {
        throw new Error(`[TOR] Missing required Electron API method: ${method}`);
      }
    }

    return api as TorElectronNetworkAPI;
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

      try {
        const wasConnected = this.stats.isConnected;
        const connected = await this.testTorConnection();
        this.stats.isConnected = connected;
        this.notifyConnectionCallbacks(connected);
        await this.checkCircuitHealth();

        if (!connected && wasConnected) {
          this.scheduleReinitialization();
        }
      } catch (_error) {
        console.error('[TOR] Connection monitoring failed:', _error);
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

    this.stopCircuitRotation();
  }

  // Check circuit health
  private async checkCircuitHealth(): Promise<void> {
    const start = performance.now();
    const test = await this.validateElectronAPI().testTorConnection();
    const latency = performance.now() - start;

    this.stats.connectionAttempts += 1;
    this.stats.lastHealthCheck = Date.now();

    if (!test.success) {
      this.stats.circuitHealth = 'poor';
      this.stats.averageLatency = Number.POSITIVE_INFINITY;
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

    if (this.isInitializing) {
      return false;
    }

    this.isInitializing = true;
    const api = this.validateElectronAPI();

    try {
      const result = await this.retryWithBackoff(() => api.initializeTor(this.config));

      if (!result.success) {
        throw new Error(result.error ?? 'Failed to initialize Tor');
      }

      if (result.socksPort) {
        this.config.socksPort = result.socksPort;
      }
      if (result.controlPort) {
        this.config.controlPort = result.controlPort;
      }

      this.isInitialized = true;
      this.stats.isConnected = false;
      this.stats.failedConnections = 0;

      this.startCircuitRotation();
      this.startConnectionMonitoring();

      this.testTorConnection().then(verified => {
        if (!verified) {
          this.stats.isConnected = false;
          this.stats.isBootstrapped = false;
          this.notifyConnectionCallbacks(false);
        } else {
          this.stats.isConnected = true;
          this.stats.isBootstrapped = true;
          this.notifyConnectionCallbacks(true);
          this.checkCircuitHealth();
        }
      });

      return true;
    } catch (_error) {
      console.error('[TOR] Failed to initialize Tor connection:', _error);
      this.stats.failedConnections += 1;
      this.notifyConnectionCallbacks(false);
      return false;
    } finally {
      this.isInitializing = false;
    }
  }

  // Test Tor connection
  private async testTorConnection(): Promise<boolean> {
    const api = this.validateElectronAPI();

    try {
      const result = await api.testTorConnection();
      if (!result.success && result.error) {
        console.error('[TOR] Connection test failed:', result.error);
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

    const api = this.validateElectronAPI();

    try {
      const result = await api.getTorWebSocketUrl(url);
      let torUrl: string | null = null;
      if (typeof result === 'string') {
        torUrl = result;
      } else if (result && typeof result === 'object') {
        const candidate = (result as { url?: unknown }).url;
        if (typeof candidate === 'string' && candidate) {
          torUrl = candidate;
        } else {
          const error = (result as { error?: unknown }).error;
          if (typeof error === 'string' && error) {
            throw new Error(error);
          }
        }
      }

      if (!torUrl) {
        throw new Error('Invalid Tor WebSocket URL result');
      }

      if (!torUrl || typeof torUrl !== 'string') {
        throw new Error('Invalid Tor WebSocket URL: empty or non-string');
      }

      const lowerUrl = torUrl.toLowerCase();
      if (!lowerUrl.startsWith('ws://') && !lowerUrl.startsWith('wss://')) {
        throw new Error(`Invalid Tor WebSocket URL scheme: ${torUrl.split(':')[0]}. Only ws:// or wss:// allowed.`);
      }

      return new WebSocket(torUrl);
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

    const api = this.validateElectronAPI();

    return this.retryWithBackoff(async () => {
      const result = await api.makeTorRequest({
        url: options.url,
        method: options.method ?? 'GET',
        headers: options.headers ?? {},
        body: options.body,
        timeout: options.timeout ?? this.config.connectionTimeout
      });

      if (!result || typeof result !== 'object') {
        throw new Error('Invalid Tor request result');
      }
      if (typeof result.body !== 'string') {
        throw new Error('Unexpected Tor response body type');
      }

      if (result.body) {
        this.stats.bytesReceived += result.body.length;
      }
      if (options.body) {
        this.stats.bytesTransmitted += options.body.length;
      }
      this.notifyStatsCallbacks();

      return result;
    });
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

    const api = this.validateElectronAPI();

    try {
      const result = await this.retryWithBackoff(() => api.rotateTorCircuit());

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
    try {
      this.validateElectronAPI();
      return true;
    } catch {
      return false;
    }
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
    this.stats.isConnected = false;
    this.isInitialized = false;

    this.lastManualRotation = 0;
    this.monitorBackoffMs = 0;

    this.notifyConnectionCallbacks(false);
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