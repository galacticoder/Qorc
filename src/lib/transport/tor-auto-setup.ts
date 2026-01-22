/**
 * Tor setup and management
 */

import { TorSetupStatus, TorInstallOptions } from '../types/tor-types';
import { sanitizeBinaryPath, isValidBridgeLine } from '../utils/tor-utils';
import { tor, isTauri } from '../tauri-bindings';

// Tor setup
export class TorAutoSetup {
  private status: TorSetupStatus = {
    isInstalled: false,
    isConfigured: false,
    isRunning: false,
    isBootstrapped: false,
    bootstrapProgress: 0,
    setupProgress: 0,
    currentStep: 'Initializing'
  };

  private progressCallback?: (status: TorSetupStatus) => void;
  private bridgeFallbackAllowed = false;

  // Automatically setup Tor
  async autoSetup(options: TorInstallOptions = { autoStart: true, enableBridges: false }): Promise<boolean> {
    this.progressCallback = options.onProgress;
    this.bridgeFallbackAllowed = Boolean(options.allowBridgeFallback);

    try {
      this.updateStatus(5, 'Checking system requirements...');

      if (!isTauri()) {
        this.updateStatus(0, 'Desktop application required', 'Tor setup requires the Tauri desktop application.');
        return false;
      }

      this.updateStatus(10, 'Checking for bundled Tor...');

      const bundledTorCheck = await this.checkBundledTor();
      if (bundledTorCheck.isInstalled) {
        this.updateStatus(40, 'Using existing bundled Tor...');
        this.status.isInstalled = true;
        if (bundledTorCheck.version) {
          this.status.version = bundledTorCheck.version;
        }
      } else {
        this.updateStatus(20, 'Downloading Tor Expert Bundle...');
        const downloadSuccess = await this.downloadTor();

        if (!downloadSuccess) {
          return false;
        }

        this.updateStatus(40, 'Installing Tor Expert Bundle...');
        const installSuccess = await this.installTor();

        if (!installSuccess) {
          this.updateStatus(0, 'Installation failed', 'Unable to complete Tor installation.');
          return false;
        }
      }

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
          this.updateStatus(0, 'Startup failed', 'Unable to start Tor service.');
          return false;
        }

        this.updateStatus(90, 'Verifying Tor connection...');
        let verifySuccess = await this.verifyTorConnection();

        if (!verifySuccess && this.bridgeFallbackAllowed) {
          try {
            this.updateStatus(85, 'Enabling bridge transport...');
            const fallbackOptions: TorInstallOptions = {
              ...options,
              enableBridges: true,
              transport: 'snowflake',
              bridges: []
            };

            const reconfigOk = await this.configureTor(fallbackOptions);
            if (reconfigOk) {
              const restart = await this.startTor();
              if (restart.success) {
                this.updateStatus(90, 'Verifying Tor connection...');
                verifySuccess = await this.verifyTorConnection();
              }
            }
          } catch (_e) {
            console.error('[TOR-SETUP] Bridge fallback failed:', _e);
          }

          if (!verifySuccess) {
            this.updateStatus(0, 'Connection failed', 'Unable to establish Tor connection.');
            return false;
          }
        } else if (!verifySuccess) {
          this.updateStatus(0, 'Verification failed', 'Unable to verify Tor connection.');
          return false;
        }
      }

      this.updateStatus(100, 'Tor setup complete');
      return true;

    } catch (_error) {
      console.error('[TOR-SETUP] Auto setup failed:', _error);
      this.updateStatus(0, 'Setup failed', _error instanceof Error ? _error.message : 'Unknown error');
      throw _error;
    }
  }

  // Check if bundled Tor is available
  private async checkBundledTor(): Promise<{ isInstalled: boolean; version?: string; bundled?: boolean }> {
    try {
      if (!isTauri()) {
        return { isInstalled: false };
      }

      const result = await tor.checkInstallation();
      return {
        isInstalled: result.is_installed || false,
        version: result.version || undefined,
        bundled: true
      };
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to check bundled Tor:', _error);
      return { isInstalled: false };
    }
  }

  // Download Tor Expert Bundle
  private async downloadTor(): Promise<boolean> {
    try {
      if (!isTauri()) {
        console.error('[TOR-SETUP] Tauri API not available for download');
        this.updateStatus(0, 'Download failed', 'Tauri API not available');
        return false;
      }

      const result = await tor.download();
      if (!result.success) {
        const msg = result.error ? String(result.error) : 'Unable to download Tor.';
        console.error('[TOR-SETUP] Download error:', msg);
        this.updateStatus(0, 'Download failed', msg);
        return false;
      }
      return true;
    } catch (_error) {
      let msg = 'Unknown download error';
      if (_error instanceof Error) {
        msg = _error.message;
      } else if (typeof _error === 'string') {
        msg = _error;
      }
      console.error('[TOR-SETUP] Failed to download Tor:', msg, _error);
      this.updateStatus(0, 'Download failed', `${msg} ${JSON.stringify(_error)}`);
      return false;
    }
  }

  // Install Tor
  private async installTor(): Promise<boolean> {
    try {
      if (!isTauri()) {
        console.error('[TOR-SETUP] Tauri API not available for install');
        return false;
      }

      const result = await tor.install();
      this.status.isInstalled = result.success;

      if (!result.success && result.error) {
        console.error('[TOR-SETUP] Install error:', result.error);
      }

      return result.success;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to install Tor:', _error);
      return false;
    }
  }

  // Configure Tor
  private async configureTor(options: TorInstallOptions): Promise<boolean> {
    try {
      const config = this.generateTorConfig(options);

      if (!isTauri()) {
        console.error('[TOR-SETUP] Tauri API not available');
        return false;
      }

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
      if (!isTauri()) {
        console.error('[TOR-SETUP] Tauri API not available');
        return { success: false, error: 'Tauri API not available' };
      }

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
      if (!isTauri()) {
        return false;
      }

      const maxAttempts = 30;
      const waitMs = 2000;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const result = await tor.verifyConnection();
        if (result && result.success) {
          return true;
        }
        await new Promise((res) => setTimeout(res, waitMs));
      }
      return false;
    } catch {
      return false;
    }
  }

  // Generate Tor configuration
  private generateTorConfig(options: TorInstallOptions): string {
    const socksPort = options.customConfig?.socksPort || 9150;
    const controlPort = options.customConfig?.controlPort || 9151;

    const config = [
      '# Auto-generated Tor configuration',
      `SocksPort ${socksPort}`,
      `ControlPort ${controlPort}`,
      'CookieAuthentication 1',
      'SocksPolicy accept 127.0.0.1',
      'SocksPolicy reject *',
      '',
      '# Performance',
      'NewCircuitPeriod 30',
      'MaxCircuitDirtiness 600',
      'CircuitBuildTimeout 60',
      'LearnCircuitBuildTimeout 0',
      '',
      '# Privacy',
      'ExitPolicy reject *:*',
      'ClientOnly 1',
      'Log notice stdout',
    ];

    if (options.enableBridges) {
      const hasBridges = Array.isArray(options.bridges) && options.bridges.length > 0;
      const transport = hasBridges ? (options.transport || 'obfs4') : 'snowflake';
      config.push('', '# Bridge configuration', 'UseBridges 1');

      if (transport === 'obfs4') {
        const obfs4Path = sanitizeBinaryPath(options.obfs4ProxyPath?.trim() || './pluggable_transports/lyrebird');
        config.push(`ClientTransportPlugin obfs4 exec ${obfs4Path}`);
      } else if (transport === 'snowflake') {
        config.push('ClientTransportPlugin snowflake exec snowflake-client');
        config.push('Bridge snowflake');
      }

      if (hasBridges) {
        const validBridges: string[] = [];
        for (const line of options.bridges!) {
          const trimmed = (line || '').trim();
          if (!trimmed) continue;

          if (!isValidBridgeLine(trimmed)) {
            console.warn('[TOR-SETUP] Invalid bridge line skipped:', trimmed);
            continue;
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

    if (options.customConfig) {
      config.push('', '# Custom configuration');
      for (const [key, value] of Object.entries(options.customConfig)) {
        if (typeof key !== 'string' || !key.trim()) {
          continue;
        }
        if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(key)) {
          continue;
        }
        if (typeof value === 'string') {
          if (value.includes('\n') || value.includes('\r')) {
            continue;
          }
          config.push(`${key} ${value}`);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          config.push(`${key} ${String(value)}`);
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

    if (this.progressCallback) {
      this.progressCallback({ ...this.status });
    }
  }

  // Get current setup status
  getStatus(): TorSetupStatus {
    return { ...this.status };
  }

  // Refresh current setup status
  async refreshStatus(): Promise<TorSetupStatus> {
    try {
      if (!isTauri()) {
        return { ...this.status };
      }

      const torStatus = await tor.status();
      const torInfo = await tor.info();

      this.status.isRunning = torStatus.is_running || false;
      this.status.isBootstrapped = torStatus.bootstrapped || torInfo.bootstrapped || false;
      this.status.bootstrapProgress = torStatus.bootstrap_progress || torInfo.bootstrap_progress || 0;

      let newVersion = torInfo.version;
      if (!newVersion || newVersion === 'unknown') {
        newVersion = this.status.version;
      }

      if ((!newVersion || newVersion === 'unknown') && this.status.isRunning) {
        try {
          const check = await this.checkBundledTor();
          if (check.version && check.version !== 'unknown') {
            newVersion = check.version;
          }
        } catch (e) {
          console.warn('[TOR-SETUP] Failed to fallback check version:', e);
        }
      }

      this.status.version = newVersion;
      this.status.socksPort = torInfo.socks_port;
      this.status.controlPort = torInfo.control_port;

      if (this.status.isRunning && this.status.version && this.status.version !== 'unknown') {
        this.status.isInstalled = true;
        this.status.isConfigured = true;
        this.status.setupProgress = 100;
        this.status.currentStep = 'Tor setup complete';
      }
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to refresh status:', _error);
    }

    return { ...this.status };
  }

  // Stop Tor
  async stopTor(): Promise<boolean> {
    try {
      if (!isTauri()) {
        return false;
      }

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

  // Uninstall Tor
  async uninstallTor(): Promise<boolean> {
    try {
      if (!isTauri()) {
        return false;
      }

      const result = await tor.uninstall();
      if (result) {
        this.status.isInstalled = false;
        this.status.isConfigured = false;
        this.status.isRunning = false;
        this.status.error = undefined;
        this.status.setupProgress = 0;
        this.status.currentStep = 'Ready to setup';
      }
      return result;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to uninstall Tor:', _error);
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
