/**
 * Tor setup and management
 */

import { TorSetupStatus, TorSetupOptions } from '../types/tor-types';
import {
  DEFAULT_BRIDGE_TRANSPORT_PATH,
  DEFAULT_SNOWFLAKE_BRIDGE,
  isValidBridgeLine
} from '../utils/tor-utils';
import { tor } from '../tauri-bindings';

// Tor setup
export class TorAutoSetup {
  private status: TorSetupStatus = {
    isConfigured: false,
    isRunning: false,
    isBootstrapped: false,
    bootstrapProgress: 0,
    socksPort: 9150,
    controlPort: 9151,
    setupProgress: 0,
    currentStep: 'Initializing'
  };

  private readonly progressCallbacks = new Set<(status: TorSetupStatus) => void>();
  private setupPromise: Promise<boolean> | null = null;

  // Automatically setup Tor
  async autoSetup(options: TorSetupOptions = { autoStart: true, enableBridges: false }): Promise<boolean> {
    if (options.onProgress) {
      this.progressCallbacks.add(options.onProgress);
      options.onProgress({ ...this.status });
    }

    if (!this.setupPromise) {
      this.setupPromise = this.runAutoSetup(options).finally(() => {
        this.setupPromise = null;
      });
    }

    try {
      return await this.setupPromise;
    } finally {
      if (options.onProgress) {
        this.progressCallbacks.delete(options.onProgress);
      }
    }
  }

  private async runAutoSetup(options: TorSetupOptions): Promise<boolean> {
    try {
      this.updateStatus(5, 'Checking system requirements...');

      if (this.isKnownOffline()) {
        this.updateStatus(0, 'Offline', 'No internet connection detected. Reconnect and retry Tor setup.');
        return false;
      }

      this.updateStatus(40, 'Using embedded Tor...');

      this.updateStatus(60, 'Configuring Tor...');
      const configSuccess = await this.configureTor(options);

      if (!configSuccess) {
        this.updateStatus(0, 'Configuration failed', 'Unable to configure Tor.');
        return false;
      }

      if (options.autoStart) {
        this.updateStatus(80, 'Starting Tor service...');
        const startResult = await this.startTor();

        if (!startResult.success) {
          this.updateStatus(0, 'Startup failed', startResult.error || 'Unable to start Tor service.');
          return false;
        }

        this.updateStatus(90, 'Waiting for Tor network...');
        const verifySuccess = await this.verifyTorConnection();
        if (!verifySuccess) {
          this.updateStatus(0, 'Verification failed', 'Tor could not bootstrap. Check your internet connection or try bridges.');
          return false;
        }
      }

      this.updateStatus(100, 'Tor setup complete');
      return true;

    } catch (_error) {
      console.error('[TOR-SETUP] Auto setup failed:', _error);
      this.updateStatus(0, 'Setup failed', this.humanizeError(_error, 'Unknown setup error'));
      throw _error;
    }
  }

  // Configure Tor
  private async configureTor(options: TorSetupOptions): Promise<boolean> {
    try {
      const config = this.generateTorConfig(options);

      const result = await tor.configure(config);
      this.status.isConfigured = result;
      return result;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to configure Tor:', _error);
      throw _error;
    }
  }

  // Start Tor
  private async startTor(): Promise<{ success: boolean; error?: string }> {
    try {
      const result = await tor.start();
      this.status.isRunning = result.success;
      return result;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to start Tor:', _error);
      const errorMessage = _error instanceof Error ? _error.message : 'Unknown error';
      return { success: false, error: errorMessage };
    }
  }

  // Verify Tor connection
  private async verifyTorConnection(): Promise<boolean> {
    try {
      const maxAttempts = 90;
      const waitMs = 2000;
      let localVerifyAttempts = 0;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const status = await tor.status();
        const progress = status.bootstrap_progress;
        const bootstrapped = status.bootstrapped;

        this.status.isRunning = status.is_running;
        this.status.isBootstrapped = bootstrapped;
        this.status.bootstrapProgress = progress;
        this.status.socksPort = status.socks_port;
        this.status.controlPort = status.control_port;

        this.updateStatus(
          Math.max(90, Math.min(99, 90 + Math.floor(progress / 10))),
          bootstrapped ? 'Verifying Tor connection...' : 'Bootstrapping Tor'
        );

        if (bootstrapped) {
          localVerifyAttempts += 1;
          const result = await tor.verifyConnection();
          if (result && result.success) {
            return true;
          }
          if (localVerifyAttempts >= 5) {
            return false;
          }
        }
        await new Promise((res) => setTimeout(res, waitMs));
      }
      return false;
    } catch {
      return false;
    }
  }

  private humanizeError(error: unknown, defaultMessage: string): string {
    const raw = error instanceof Error ? error.message : (typeof error === 'string' ? error : '');
    const text = raw.toLowerCase();

    if (
      text.includes('offline') ||
      text.includes('network') ||
      text.includes('dns') ||
      text.includes('timed out') ||
      text.includes('timeout') ||
      text.includes('failed to reach') ||
      text.includes('connection refused') ||
      text.includes('connection reset') ||
      text.includes('could not resolve') ||
      text.includes('temporary failure') ||
      text.includes('eai_again') ||
      text.includes('enotfound')
    ) {
      return 'Network unavailable. Check your internet connection and retry.';
    }

    return raw || defaultMessage;
  }

  private isKnownOffline(): boolean {
    return navigator.onLine === false;
  }

  // Generate Tor configuration
  private generateTorConfig(options: TorSetupOptions): string {
    const config = [
      '# Auto-generated Tor configuration',
      'CookieAuthentication 1',
      'SocksPolicy accept 127.0.0.1',
      'SocksPolicy reject *',
      '',
      '# Performance / reliability',
      'NewCircuitPeriod 30',
      'MaxCircuitDirtiness 600',
      'CircuitBuildTimeout 20',
      'LearnCircuitBuildTimeout 1',
      '',
      '# Privacy',
      'ExitPolicy reject *:*',
      'ClientOnly 1',
      'SafeLogging 1',
      'Log notice stdout',
    ];

    if (options.enableBridges) {
      const hasBridges = Array.isArray(options.bridges) && options.bridges.length > 0;
      const transport = hasBridges ? (options.transport || 'obfs4') : 'snowflake';
      config.push('', '# Bridge configuration', 'UseBridges 1', 'ConfluxEnabled 0');

      config.push(`ClientTransportPlugin meek_lite,obfs4,snowflake,webtunnel exec ${DEFAULT_BRIDGE_TRANSPORT_PATH}`);

      if (transport === 'snowflake' && !hasBridges) {
        config.push(`Bridge ${DEFAULT_SNOWFLAKE_BRIDGE}`);
      }

      if (hasBridges) {
        const validBridges: string[] = [];
        for (const line of options.bridges!) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          if (!isValidBridgeLine(trimmed)) {
            throw new Error('Invalid bridge line provided.');
          }

          const bridgeLine = trimmed.startsWith('Bridge ') ? trimmed : `Bridge ${trimmed}`;
          validBridges.push(bridgeLine);
          config.push(bridgeLine);
        }

        // Require at least one valid bridge when user provides bridge lines
        if (validBridges.length === 0) {
          throw new Error('Invalid bridge lines provided.');
        }
      }
    }

    return config.join('\n');
  }

  // Update setup status
  private updateStatus(progress: number, step: string, error?: string): void {
    this.status.setupProgress = progress;
    this.status.currentStep = step;
    if (error) {
      this.status.error = error;
    }

    const snapshot = { ...this.status };
    this.progressCallbacks.forEach((callback) => callback(snapshot));
  }

  // Get current setup status
  getStatus(): TorSetupStatus {
    return { ...this.status };
  }

  // Refresh current setup status
  async refreshStatus(): Promise<TorSetupStatus> {
    const torStatus = await tor.status();

    this.status.isRunning = torStatus.is_running;
    this.status.isBootstrapped = torStatus.bootstrapped;
    this.status.bootstrapProgress = torStatus.bootstrap_progress;
    this.status.socksPort = torStatus.socks_port;
    this.status.controlPort = torStatus.control_port;

    if (this.status.isRunning) {
      this.status.isConfigured = true;
      this.status.setupProgress = 100;
      this.status.currentStep = 'Tor setup complete';
    }

    return { ...this.status };
  }

  // Stop Tor
  async stopTor(): Promise<boolean> {
    try {
      const result = await tor.stop();
      if (result) {
        this.status.isRunning = false;
        this.status.error = undefined;
        this.status.setupProgress = 0;
        this.status.currentStep = 'Ready to setup';
      }
      return result;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to stop Tor:', _error);
      return false;
    }
  }

}

let torAutoSetupInstance: TorAutoSetup | null = null;

export function getTorAutoSetup(): TorAutoSetup {
  if (!torAutoSetupInstance) {
    torAutoSetupInstance = new TorAutoSetup();
  }
  return torAutoSetupInstance;
}
