// Tor setup
export interface TorSetupStatus {
  isInstalled: boolean;
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

export interface TorInstallOptions {
  autoStart: boolean;
  enableBridges: boolean;
  allowBridgeFallback?: boolean;
  bridges?: string[];
  transport?: 'obfs4' | 'snowflake';
  obfs4ProxyPath?: string;
  customConfig?: Record<string, string | number | boolean>;
  onProgress?: (status: TorSetupStatus) => void;
}

// Tor network
export type TorCircuitHealth = 'good' | 'degraded' | 'poor' | 'unknown';

export type TorCircuitRotationResult = {
  success: boolean;
  method?: string;
  beforeIP?: string;
  afterIP?: string;
  ipChanged?: boolean;
  circuitChanged?: boolean;
  message?: string;
  error?: string;
  beforeCircuit?: string;
  afterCircuit?: string;
};

export type TorInitializationResult = { success: boolean; error?: string; socksPort?: number; controlPort?: number; bootstrapped?: boolean };
export type TorTestConnectionResult = { success: boolean; error?: string };
export type TorRequestResult = { response: unknown; body: string };

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
