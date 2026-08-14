// Tor setup
export interface TorSetupStatus {
  isConfigured: boolean;
  isRunning: boolean;
  isBootstrapped?: boolean;
  bootstrapProgress?: number;
  version?: string;
  socksPort?: number;
  controlPort?: number;
  error?: string;
  setupProgress: number;
  currentStep: string;
}

export interface TorSetupOptions {
  autoStart: boolean;
  enableBridges: boolean;
  bridges?: string[];
  transport?: 'obfs4' | 'snowflake';
  onProgress?: (status: TorSetupStatus) => void;
}

// Tor network
export type TorCircuitHealth = 'good' | 'degraded' | 'poor' | 'unknown';

export interface TorConfig {
  enabled: boolean;
  socksPort: number;
  controlPort: number;
  host: string;
  circuitRotationInterval: number;
  maxRetries: number;
  connectionTimeout: number;
}

export interface TorConnectionStats {
  isConnected: boolean;
  circuitCount: number;
  lastCircuitRotation: number;
  connectionAttempts: number;
  failedConnections: number;
  bytesTransmitted: number;
  bytesReceived: number;
  averageLatency: number;
  lastHealthCheck: number;
  circuitHealth: TorCircuitHealth;
  isBootstrapped?: boolean;
  bootstrapProgress?: number;
}
