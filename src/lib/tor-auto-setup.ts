/**
 * Tor setup and management with automated installation and configuration
 */

import { handleCriticalError } from './secure-error-handler';

interface ElectronTorSetupAPI {
  checkTorInstallation: () => Promise<{ isInstalled: boolean; version?: string; bundled?: boolean }>;
  downloadTor: () => Promise<{ success: boolean; error?: string }>;
  installTor: () => Promise<{ success: boolean; error?: string }>;
  configureTor: (config: { config: string }) => Promise<{ success: boolean; error?: string }>;
  startTor: () => Promise<{ success: boolean; error?: string }>;
  stopTor: () => Promise<{ success: boolean; error?: string }>;
  uninstallTor: () => Promise<{ success: boolean; error?: string }>;
  verifyTorConnection: () => Promise<{ success: boolean; isTor?: boolean; error?: string }>;
  getTorStatus: () => Promise<{ isRunning: boolean }>;
  getTorInfo: () => Promise<{ version?: string; systemTorVersion?: string; socksPort?: number; controlPort?: number }>;
  platform?: string;
}

declare global {
  interface Window {
    electronAPI?: any;
  }
}

export interface TorSetupStatus {
  isInstalled: boolean;
  isConfigured: boolean;
  isRunning: boolean;
  version?: string;
  socksPort?: number;
  controlPort?: number;
  error?: string;
  setupProgress: number; // 0-100
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

export class TorAutoSetup {
  private status: TorSetupStatus = {
    isInstalled: false,
    isConfigured: false,
    isRunning: false,
    setupProgress: 0,
    currentStep: 'Initializing'
  };

  private progressCallback?: (status: TorSetupStatus) => void;
  private bridgeFallbackAllowed = false;

  /**
   * Automatically setup Tor
   */
  async autoSetup(options: TorInstallOptions = { autoStart: true, enableBridges: false }): Promise<boolean> {
    this.progressCallback = options.onProgress;
    this.bridgeFallbackAllowed = Boolean(options.allowBridgeFallback);
    
    try {
      this.updateStatus(5, 'Checking system requirements...');
      
      if (!this.isElectronEnvironment()) {
        this.updateStatus(0, 'Desktop application required', 'Tor auto-setup requires the desktop application.');
        return false;
      }

      this.updateStatus(10, 'Checking for bundled Tor...');
      
      const bundledTorCheck = await this.checkBundledTor();
      if (bundledTorCheck.isInstalled) {
        this.updateStatus(40, 'Using existing bundled Tor...');
        this.status.isInstalled = true;
      } else {
        this.updateStatus(15, 'Preparing Tor Expert Bundle download...');
        this.updateStatus(20, 'Downloading Tor Expert Bundle...', 'Downloading ~15MB from torproject.org');
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
      handleCriticalError(_error as Error, { context: 'tor_auto_setup' });
      return false;
    }
  }


  private async checkBundledTor(): Promise<{ isInstalled: boolean; version?: string; bundled?: boolean }> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        return { isInstalled: false };
      }
      
      const result = await api.checkTorInstallation();
      return { 
        isInstalled: result.isInstalled || false, 
        version: result.version, 
        bundled: result.bundled || false
      };
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to check bundled Tor:', _error);
      return { isInstalled: false };
    }
  }

  private async downloadTor(): Promise<boolean> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        console.error('[TOR-SETUP] Electron API not available for download');
        this.updateStatus(0, 'Download failed', 'Electron API not available');
        return false;
      }

      const result = await api.downloadTor();
      if (!result.success) {
        const msg = (result && result.error) ? String(result.error) : 'Unable to download Tor.';
        console.error('[TOR-SETUP] Download error:', msg);
        this.updateStatus(0, 'Download failed', msg);
        return false;
      }
      return true;
    } catch (_error) {
      const msg = _error instanceof Error ? _error.message : 'Unknown download error';
      console.error('[TOR-SETUP] Failed to download Tor:', msg);
      this.updateStatus(0, 'Download failed', msg);
      return false;
    }
  }

  private async installTor(): Promise<boolean> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        console.error('[TOR-SETUP] Electron API not available for install');
        return false;
      }

      const result = await api.installTor();
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

  private async configureTor(options: TorInstallOptions): Promise<boolean> {
    try {
      const config = this.generateTorConfig(options);

      const api = this.getElectronAPI();
      if (!api) {
        console.error('[TOR-SETUP] Electron API not available');
        return false;
      }

      const result = await new Promise<{ success: boolean; error?: string }>((resolve) => {
        let done = false;
        const finish = (data: any) => {
          if (done) return; done = true; resolve(data);
        };

        const listener = (_event: any, data: any) => finish(data);
        
        // Subscribe to completion event
        const unsubscribe = window.electronAPI?.onTorConfigureComplete
          ? window.electronAPI.onTorConfigureComplete(listener)
          : null;
        
        // Fire configure request
        api.configureTor({ config }).then((initialResult) => {
          if (!initialResult.pending) {
            finish(initialResult);
          }
        }).catch((error) => {
          console.error('[TOR-SETUP] Configuration failed:', error);
          finish({ success: false, error: error.message });
        });
        
        setTimeout(() => {
          if (!done) {
            try { if (typeof unsubscribe === 'function') unsubscribe(); } catch {}
            finish({ success: false, error: 'Tor configuration timeout' });
          }
        }, 20000);
      });
      
      this.status.isConfigured = result.success;
      return result.success;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to configure Tor:', _error);
      return false;
    }
  }

  private async startTor(): Promise<{ success: boolean; error?: string }> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        console.error('[TOR-SETUP] Electron API not available');
        return { success: false, error: 'Electron API not available' };
      }

      const result = await api.startTor();
      this.status.isRunning = result.success;
      return result;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to start Tor:', _error);
      const errorMessage = _error instanceof Error ? _error.message : 'Unknown error';
      return { success: false, error: errorMessage };
    }
  }

  private async verifyTorConnection(): Promise<boolean> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        return false;
      }

      const maxAttempts = 20;
      const waitMs = 1000;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const result = await api.verifyTorConnection();
        if (result && result.success && result.isTor) {
          return true;
        }
        await new Promise((res) => setTimeout(res, waitMs));
      }
      return false;
    } catch (_error) {
      return false;
    }
  }

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
      'CircuitBuildTimeout 30',
      'LearnCircuitBuildTimeout 0',
      '',
      '# Privacy',
      'ExitPolicy reject *:*',
      'ClientOnly 1',
      'SafeLogging 1',
      'Log notice stdout',
      'Log warn stdout',
      '',
      '# Data directory',
      'DataDirectory ./tor-data',
      '',
      '# Network resilience',
      'FetchDirInfoEarly 1',
      'FetchDirInfoExtraEarly 1',
      'FetchUselessDescriptors 1',
    ];

    if (options.enableBridges) {
      const hasBridges = Array.isArray(options.bridges) && options.bridges.length > 0;
      const transport = hasBridges ? (options.transport || 'obfs4') : 'snowflake';
      config.push('', '# Bridge configuration', 'UseBridges 1');

      if (transport === 'obfs4') {
        const obfs4Path = this.sanitizeBinaryPath(options.obfs4ProxyPath?.trim() || 'obfs4proxy');
        config.push(`ClientTransportPlugin obfs4 exec ${obfs4Path}`);
      } else if (transport === 'snowflake') {
        config.push('ClientTransportPlugin snowflake exec snowflake-client');
        config.push('Bridge snowflake');
      }

      if (hasBridges) {
        for (const line of options.bridges!) {
          const trimmed = (line || '').trim();
          if (!trimmed) continue;
          
          if (!this.isValidBridgeLine(trimmed)) {
            continue;
          }
          
          config.push(trimmed.startsWith('Bridge ') ? trimmed : `Bridge ${trimmed}`);
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

  private sanitizeBinaryPath(path: string): string {
    const sanitized = path.replace(/[^a-zA-Z0-9_\-./]/g, '');
    return sanitized || 'obfs4proxy';
  }

  private isValidBridgeLine(line: string): boolean {
    const bridgePattern = /^(Bridge\s+)?(obfs4|snowflake|vanilla)\s+[\w\d.:]+(\s+\w+)?(\s+.+)?$/i;
    const startsWithBridge = line.startsWith('Bridge ') ? line : `Bridge ${line}`;
    return bridgePattern.test(startsWithBridge);
  }

  private getElectronAPI(): ElectronTorSetupAPI | null {
    if (typeof window === 'undefined' || !window.electronAPI) {
      return null;
    }
    return window.electronAPI as ElectronTorSetupAPI;
  }

  private isElectronEnvironment(): boolean {
    return typeof window !== 'undefined' && Boolean(window.electronAPI);
  }

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

  getStatus(): TorSetupStatus {
    return { ...this.status };
  }

  async refreshStatus(): Promise<TorSetupStatus> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        return { ...this.status };
      }

      const torStatus = await api.getTorStatus();
      const torInfo = await api.getTorInfo();
      
      this.status.isRunning = torStatus.isRunning || false;
      this.status.version = torInfo.systemTorVersion || torInfo.version || undefined;
      this.status.socksPort = torInfo.socksPort;
      this.status.controlPort = torInfo.controlPort;
      
      if (this.status.isRunning && this.status.version) {
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

  async stopTor(): Promise<boolean> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        return false;
      }

      const result = await api.stopTor();
      if (result.success) {
        this.status.isRunning = false;
        this.status.error = undefined;
        this.status.setupProgress = 0;
        this.status.currentStep = 'Ready to setup';
      }
      return result.success;
    } catch (_error) {
      console.error('[TOR-SETUP] Failed to stop Tor:', _error);
      return false;
    }
  }

  async uninstallTor(): Promise<boolean> {
    try {
      const api = this.getElectronAPI();
      if (!api) {
        return false;
      }

      const result = await api.uninstallTor();
      if (result.success) {
        this.status.isInstalled = false;
        this.status.isConfigured = false;
        this.status.isRunning = false;
        this.status.error = undefined;
        this.status.setupProgress = 0;
        this.status.currentStep = 'Ready to setup';
      }
      return result.success;
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
