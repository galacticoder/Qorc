// Tor setup
export interface ElectronTorSetupAPI {
  checkTorInstallation: () => Promise<{ isInstalled: boolean; version?: string; bundled?: boolean }>;
  downloadTor: () => Promise<{ success: boolean; error?: string }>;
  installTor: () => Promise<{ success: boolean; error?: string }>;
  configureTor: (config: { config: string }) => Promise<{ success: boolean; pending?: boolean; error?: string }>;
  startTor: () => Promise<{ success: boolean; error?: string }>;
  stopTor: () => Promise<{ success: boolean; error?: string }>;
  uninstallTor: () => Promise<{ success: boolean; error?: string }>;
  verifyTorConnection: () => Promise<{ success: boolean; isTor?: boolean; error?: string }>;
  getTorStatus: () => Promise<{ isRunning: boolean }>;
  getTorInfo: () => Promise<{ version?: string; systemTorVersion?: string; socksPort?: number; controlPort?: number }>;
  onTorConfigureComplete?: (callback: (event: unknown, data: unknown) => void) => () => void;
  platform?: string;
}

export interface TorSetupStatus {
  isInstalled: boolean;
  isConfigured: boolean;
  isRunning: boolean;
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

export interface TorElectronNetworkAPI {
  initializeTor(config: TorConfig): Promise<TorInitializationResult>;
  testTorConnection(): Promise<TorTestConnectionResult>;
  rotateTorCircuit(): Promise<TorCircuitRotationResult>;
  makeTorRequest(options: {
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: string;
    timeout: number;
  }): Promise<TorRequestResult>;
  getTorWebSocketUrl(url: string): Promise<string | { success?: boolean; url?: string; error?: string }>;
}

export const REQUIRED_ELECTRON_METHODS: Array<keyof TorElectronNetworkAPI> = [
  'initializeTor',
  'testTorConnection',
  'rotateTorCircuit',
  'makeTorRequest',
  'getTorWebSocketUrl'
];

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
}
