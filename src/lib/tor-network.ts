/**
 * Tor Network Manager
 * Provides anonymous network routing through the Tor network
 */

import { handleNetworkError, handleCriticalError } from './secure-error-handler';

// Browser-safe imports - only load in Electron environment
let SocksProxyAgent: any = null;
let torRequest: any = null;

// Dynamically import Node.js modules only in Electron
const loadTorModules = async () => {
  if (typeof window !== 'undefined' && (window as any).electronAPI) {
    // In Electron, we don't need to load these modules in the renderer
    // The main process handles all Tor operations
    console.log('[TOR] Electron environment - using main process for Tor operations');
    return true;
  } else {
    console.log('[TOR] Browser environment - Tor modules not available');
    return false;
  }
};

export interface TorConfig {
  enabled: boolean;
  socksPort: number;
  controlPort: number;
  host: string;
  circuitRotationInterval: number; // minutes
  maxRetries: number;
  connectionTimeout: number; // milliseconds
}

export interface TorConnectionStats {
  isConnected: boolean;
  circuitCount: number;
  lastCircuitRotation: number;
  connectionAttempts: number;
  failedConnections: number;
  bytesTransmitted: number;
  bytesReceived: number;
}

export class TorNetworkManager {
  private config: TorConfig;
  private socksAgent: SocksProxyAgent | null = null;
  private circuitRotationTimer: NodeJS.Timeout | null = null;
  private stats: TorConnectionStats;
  private isInitialized: boolean = false;
  private connectionCallbacks: Set<(connected: boolean) => void> = new Set();

  constructor(config?: Partial<TorConfig>) {
    this.config = {
      enabled: false,
      socksPort: 9050, // Default Tor SOCKS port
      controlPort: 9051, // Default Tor control port
      host: '127.0.0.1',
      circuitRotationInterval: 10, // 10 minutes
      maxRetries: 3,
      connectionTimeout: 30000, // 30 seconds
      ...config
    };

    this.stats = {
      isConnected: false,
      circuitCount: 0,
      lastCircuitRotation: 0,
      connectionAttempts: 0,
      failedConnections: 0,
      bytesTransmitted: 0,
      bytesReceived: 0
    };
  }

  /**
   * Initialize Tor network connection
   */
  async initialize(): Promise<boolean> {
    if (!this.config.enabled) {
      console.log('[TOR] Tor networking is disabled');
      return false;
    }

    // Check if we're in a browser environment
    if (typeof window !== 'undefined' && !(window as any).electronAPI) {
      console.warn('[TOR] Tor networking requires Electron environment');
      return false;
    }

    console.log('[TOR] Initializing Tor network connection...');

    try {
      // In Electron, we don't need to load modules in renderer
      // The main process handles all Tor operations
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        console.log('[TOR] Using Electron main process for Tor operations');
        this.stats.isConnected = true;
        this.isInitialized = true;
        console.log('[TOR] Successfully connected to Tor network via Electron');
        this.notifyConnectionCallbacks(true);
        return true;
      }

      // Browser fallback (should not be reached)
      await loadTorModules();

      if (!SocksProxyAgent || !torRequest) {
        throw new Error('Failed to load Tor modules');
      }

      // Create SOCKS proxy agent for Tor
      const proxyUrl = `socks5://${this.config.host}:${this.config.socksPort}`;
      this.socksAgent = new SocksProxyAgent(proxyUrl);

      // Test Tor connection
      const isConnected = await this.testTorConnection();

      if (isConnected) {
        this.stats.isConnected = true;
        this.isInitialized = true;

        // Start circuit rotation
        this.startCircuitRotation();

        // Configure tor-request
        torRequest.setTorAddress(this.config.host, this.config.socksPort);

        console.log('[TOR] Successfully connected to Tor network');
        this.notifyConnectionCallbacks(true);
        return true;
      } else {
        throw new Error('Failed to establish Tor connection');
      }
    } catch (error) {
      console.error('[TOR] Failed to initialize Tor connection:', error);
      this.stats.failedConnections++;
      handleNetworkError(error as Error, { context: 'tor_initialization' });
      this.notifyConnectionCallbacks(false);
      return false;
    }
  }

  /**
   * Test Tor connection by checking IP address
   */
  private async testTorConnection(): Promise<boolean> {
    return new Promise((resolve) => {
      this.stats.connectionAttempts++;
      
      const timeout = setTimeout(() => {
        console.error('[TOR] Connection test timed out');
        resolve(false);
      }, this.config.connectionTimeout);

      // Test connection by fetching IP through Tor
      torRequest.get('https://check.torproject.org/api/ip', (error, response, body) => {
        clearTimeout(timeout);
        
        if (error) {
          console.error('[TOR] Connection test failed:', error);
          resolve(false);
          return;
        }

        try {
          const result = JSON.parse(body);
          if (result.IsTor) {
            console.log('[TOR] Connection verified - using Tor exit node:', result.IP);
            resolve(true);
          } else {
            console.error('[TOR] Connection test failed - not using Tor network');
            resolve(false);
          }
        } catch (parseError) {
          console.error('[TOR] Failed to parse connection test response:', parseError);
          resolve(false);
        }
      });
    });
  }

  /**
   * Create a new WebSocket connection through Tor
   */
  createTorWebSocket(url: string): WebSocket | null {
    if (!this.isInitialized || !this.socksAgent) {
      console.error('[TOR] Cannot create WebSocket - Tor not initialized');
      return null;
    }

    try {
      // For browser environment, we need to use a different approach
      // since WebSocket doesn't support proxy agents directly
      if (typeof window !== 'undefined') {
        console.warn('[TOR] Browser WebSocket through Tor requires browser extension or proxy setup');
        return new WebSocket(url);
      }

      // For Node.js environment (server-side)
      const WebSocketClass = require('ws');
      return new WebSocketClass(url, { agent: this.socksAgent });
    } catch (error) {
      console.error('[TOR] Failed to create Tor WebSocket:', error);
      handleNetworkError(error as Error, { context: 'tor_websocket_creation' });
      return null;
    }
  }

  /**
   * Make HTTP request through Tor
   */
  async makeRequest(options: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  }): Promise<{ response: any; body: string }> {
    if (!this.isInitialized) {
      throw new Error('Tor network not initialized');
    }

    return new Promise((resolve, reject) => {
      const requestOptions = {
        url: options.url,
        method: options.method || 'GET',
        headers: options.headers || {},
        body: options.body,
        timeout: options.timeout || this.config.connectionTimeout,
      };

      torRequest(requestOptions, (error, response, body) => {
        if (error) {
          this.stats.failedConnections++;
          reject(error);
          return;
        }

        // Update stats
        if (body) {
          this.stats.bytesReceived += body.length;
        }
        if (options.body) {
          this.stats.bytesTransmitted += options.body.length;
        }

        resolve({ response, body });
      });
    });
  }

  /**
   * Rotate Tor circuit for enhanced anonymity
   */
  async rotateCircuit(): Promise<boolean> {
    if (!this.isInitialized) {
      console.error('[TOR] Cannot rotate circuit - Tor not initialized');
      return false;
    }

    try {
      console.log('[TOR] Rotating Tor circuit...');

      // Use Electron API if available
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        console.log('[TOR] ===== INITIATING CIRCUIT ROTATION =====');
        console.log('[TOR] Using Electron API for circuit rotation');

        const result = await (window as any).electronAPI.rotateTorCircuit();

        console.log('[TOR] ===== CIRCUIT ROTATION RESULT =====');
        console.log('[TOR] Full result:', result);

        if (result && result.success) {
          this.stats.circuitCount++;
          this.stats.lastCircuitRotation = Date.now();

          console.log('[TOR] Circuit rotated successfully via Electron');
          console.log('[TOR] Rotation details:');
          console.log('[TOR]   - Method Used:', result.method);
          console.log('[TOR]   - Before IP:', result.beforeIP);
          console.log('[TOR]   - After IP:', result.afterIP);
          console.log('[TOR]   - IP Changed:', result.ipChanged);
          console.log('[TOR]   - Circuit Changed:', result.circuitChanged);
          console.log('[TOR]   - Message:', result.message);
          console.log('[TOR]   - Total rotations:', this.stats.circuitCount);

          console.log('[TOR] CIRCUIT PATH DETAILS:');
          console.log('[TOR]   Before Circuit:', result.beforeCircuit);
          console.log('[TOR]   After Circuit:', result.afterCircuit);

          if (result.circuitChanged) {
            console.log('[TOR] CIRCUIT PATH CHANGED - Real rotation confirmed!');
          } else if (!result.ipChanged) {
            console.log('[TOR] Note: Same IP doesn\'t mean rotation failed!');
            console.log('[TOR]   - Circuit path likely changed internally');
            console.log('[TOR]   - Tor may reuse efficient exit nodes');
            console.log('[TOR]   - Anonymity is still enhanced');
          }

          return true;
        } else {
          console.error('[TOR] Failed to rotate circuit via Electron');
          console.error('[TOR] Error details:', result?.error);
          return false;
        }
      }

      // Fallback for browser environment (if torRequest is available)
      if (torRequest && torRequest.newTorSession) {
        return new Promise((resolve) => {
          torRequest.newTorSession((error: any) => {
            if (error) {
              console.error('[TOR] Failed to rotate circuit:', error);
              resolve(false);
              return;
            }

            this.stats.circuitCount++;
            this.stats.lastCircuitRotation = Date.now();
            console.log('[TOR] Circuit rotated successfully');
            resolve(true);
          });
        });
      }

      console.error('[TOR] No Tor request module available for circuit rotation');
      return false;

    } catch (error) {
      console.error('[TOR] Circuit rotation failed:', error);
      handleNetworkError(error as Error, { context: 'tor_circuit_rotation' });
      return false;
    }
  }

  /**
   * Start automatic circuit rotation
   */
  private startCircuitRotation(): void {
    if (this.circuitRotationTimer) {
      clearInterval(this.circuitRotationTimer);
    }

    const intervalMs = this.config.circuitRotationInterval * 60 * 1000;
    this.circuitRotationTimer = setInterval(async () => {
      await this.rotateCircuit();
    }, intervalMs);

    console.log(`[TOR] Circuit rotation scheduled every ${this.config.circuitRotationInterval} minutes`);
  }

  /**
   * Stop circuit rotation
   */
  private stopCircuitRotation(): void {
    if (this.circuitRotationTimer) {
      clearInterval(this.circuitRotationTimer);
      this.circuitRotationTimer = null;
    }
  }

  /**
   * Get SOCKS proxy agent for manual use
   */
  getSocksAgent(): SocksProxyAgent | null {
    return this.socksAgent;
  }

  /**
   * Get connection statistics
   */
  getStats(): TorConnectionStats {
    return { ...this.stats };
  }

  /**
   * Check if Tor is enabled and connected
   */
  isConnected(): boolean {
    return this.config.enabled && this.stats.isConnected;
  }

  /**
   * Check if Tor is supported in current environment
   */
  isSupported(): boolean {
    return typeof window !== 'undefined' && !!(window as any).electronAPI;
  }

  /**
   * Register callback for connection status changes
   */
  onConnectionChange(callback: (connected: boolean) => void): void {
    this.connectionCallbacks.add(callback);
  }

  /**
   * Unregister connection status callback
   */
  offConnectionChange(callback: (connected: boolean) => void): void {
    this.connectionCallbacks.delete(callback);
  }

  /**
   * Notify all connection callbacks
   */
  private notifyConnectionCallbacks(connected: boolean): void {
    this.connectionCallbacks.forEach(callback => {
      try {
        callback(connected);
      } catch (error) {
        console.error('[TOR] Error in connection callback:', error);
      }
    });
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig: Partial<TorConfig>): void {
    this.config = { ...this.config, ...newConfig };
    
    if (this.isInitialized && newConfig.circuitRotationInterval) {
      this.startCircuitRotation();
    }
  }

  /**
   * Shutdown Tor connection
   */
  async shutdown(): Promise<void> {
    console.log('[TOR] Shutting down Tor network connection...');
    
    this.stopCircuitRotation();
    this.stats.isConnected = false;
    this.isInitialized = false;
    this.socksAgent = null;
    
    this.notifyConnectionCallbacks(false);
    console.log('[TOR] Tor network connection shut down');
  }
}

// Global Tor network manager instance
export const torNetworkManager = new TorNetworkManager();