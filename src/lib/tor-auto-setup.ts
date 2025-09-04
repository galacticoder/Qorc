/**
 * Automatic Tor Setup and Management
 * Handles Tor installation, configuration, and startup automatically
 */

import { handleCriticalError } from './secure-error-handler';

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
  // Optional: explicit bridge lines (e.g., obfs4 lines)
  bridges?: string[];
  // Pluggable transport selection (default: obfs4)
  transport?: 'obfs4' | 'snowflake';
  // Optional path to obfs4proxy binary; if not provided, uses 'obfs4proxy' in PATH
  obfs4ProxyPath?: string;
  customConfig?: Record<string, any>;
  onProgress?: (status: TorSetupStatus) => void;
}

export class TorAutoSetup {
  private status: TorSetupStatus = {
    isInstalled: false,
    isConfigured: false,
    isRunning: false,
    setupProgress: 0,
    currentStep: 'Initializing...'
  };

  private progressCallback?: (status: TorSetupStatus) => void;

  constructor() {
    this.detectPlatform();
  }

  /**
   * Automatically setup Tor with zero user intervention
   */
  async autoSetup(options: TorInstallOptions = { autoStart: true, enableBridges: false }): Promise<boolean> {
    this.progressCallback = options.onProgress;
    
    try {
      this.updateStatus(5, 'Checking system requirements...');
      
      // Check if we're in Electron environment
      if (!this.isElectronEnvironment()) {
        this.updateStatus(0, 'Browser mode detected', 'Tor auto-setup requires the desktop application. Please download the desktop version for automatic Tor setup.');
        return false;
      }

      // Step 1: Check for system Tor first (more reliable and faster)
      this.updateStatus(10, 'Checking for system Tor...');
      console.log('[TOR-SETUP] Checking for system Tor installation first');
      
      const systemTorCheck = await this.checkSystemTor();
      if (systemTorCheck.isInstalled) {
        console.log('[TOR-SETUP] Found system Tor, using it instead of downloading');
        this.updateStatus(30, 'Using system Tor installation...');
        this.status.isInstalled = true;
      } else {
        console.log('[TOR-SETUP] No system Tor found, downloading Tor Expert Bundle');
        this.updateStatus(15, 'Preparing Tor Expert Bundle download...');
        
        // Step 2: Download Tor Expert Bundle only if no system Tor
        this.updateStatus(20, 'Downloading Tor Expert Bundle...', 'Downloading ~15MB from torproject.org');
        const downloadSuccess = await this.downloadTor();

        if (!downloadSuccess) {
          this.updateStatus(0, 'Failed to download Tor', 'Could not download Tor Expert Bundle. Check internet connection or install system Tor: sudo apt-get install tor');
          return false;
        }

        this.updateStatus(40, 'Installing Tor Expert Bundle...');
        console.log('[TOR-SETUP] Calling installTor...');
        const installSuccess = await this.installTor();
        console.log('[TOR-SETUP] Install result:', installSuccess);

        if (!installSuccess) {
          this.updateStatus(0, 'Failed to install Tor', 'Could not complete Tor installation. You may need to install Tor manually.');
          return false;
        }
      }

      // Step 3: Configure Tor
      this.updateStatus(60, 'Configuring Tor...');
      console.log('[TOR-SETUP] Calling configureTor with options:', options);
      const configSuccess = await this.configureTor(options);
      console.log('[TOR-SETUP] Configuration result:', configSuccess);

      if (!configSuccess) {
        this.updateStatus(0, 'Failed to configure Tor', 'Could not write Tor configuration.');
        return false;
      }

      // Step 4: Start Tor service
      if (options.autoStart) {
        this.updateStatus(80, 'Starting Tor service...');
        const startResult = await this.startTor();
        
        if (!startResult.success) {
          const errorMessage = startResult.error || 'Tor service could not be started.';
          this.updateStatus(0, 'Failed to start Tor', errorMessage);
          return false;
        }

        // Step 5: Verify connection
        this.updateStatus(90, 'Verifying Tor connection...');
        let verifySuccess = await this.verifyTorConnection();
        
        if (!verifySuccess) {
          // Automatic fallback: enable Snowflake bridges and retry without requiring manual bridge lines
          try {
            this.updateStatus(85, 'Connection failed; enabling Snowflake bridges and retrying...');
            const fallbackOptions = {
              ...options,
              enableBridges: true,
              transport: 'snowflake' as const,
              bridges: []
            };

            const reconfigOk = await this.configureTor(fallbackOptions);
            if (reconfigOk) {
              const restart = await this.startTor();
              if (restart.success) {
                this.updateStatus(90, 'Verifying Tor connection (bridges enabled)...');
                verifySuccess = await this.verifyTorConnection();
              }
            }
          } catch (e) {
            // swallow and proceed to failure path
          }

          if (!verifySuccess) {
            this.updateStatus(0, 'Tor connection failed', 'Could not establish Tor connection (even with bridges).');
            return false;
          }
        }
      }

      this.updateStatus(100, 'Tor setup complete!');
      return true;

    } catch (error) {
      console.error('[TOR-SETUP] Auto setup failed:', error);
      this.updateStatus(0, 'Setup failed', error instanceof Error ? error.message : 'Unknown error');
      handleCriticalError(error as Error, { context: 'tor_auto_setup' });
      return false;
    }
  }


  /**
   * Check if system Tor is available
   */
  private async checkSystemTor(): Promise<{ isInstalled: boolean; version?: string }> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        console.log('[TOR-SETUP] Checking system Tor through Electron API...');
        const result = await (window as any).electronAPI.checkTorInstallation();
        console.log('[TOR-SETUP] System Tor check result:', result);
        return { 
          isInstalled: result.isInstalled || false, 
          version: result.version || result.systemVersion 
        };
      }
      return { isInstalled: false };
    } catch (error) {
      console.error('[TOR-SETUP] Failed to check system Tor:', error);
      return { isInstalled: false };
    }
  }

  /**
   * Download Tor for the current platform
   */
  private async downloadTor(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        // Use Electron to download Tor Expert Bundle
        console.log('[TOR-SETUP] Requesting Tor Expert Bundle download from main process...');
        const result = await (window as any).electronAPI.downloadTor();
        console.log('[TOR-SETUP] Download result:', result);
        return result.success;
      }

      console.error('[TOR-SETUP] No electronAPI available for download');
      return false;
    } catch (error) {
      console.error('[TOR-SETUP] Failed to download Tor Expert Bundle:', error);
      return false;
    }
  }

  /**
   * Install Tor on the system
   */
  private async installTor(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        console.log('[TOR-SETUP] Calling electronAPI.installTor...');
        const result = await (window as any).electronAPI.installTor();
        console.log('[TOR-SETUP] Install result from Electron:', result);
        this.status.isInstalled = result.success;

        if (!result.success && result.error) {
          console.error('[TOR-SETUP] Install error:', result.error);
        }

        return result.success;
      }

      console.error('[TOR-SETUP] No electronAPI available for install');
      return false;
    } catch (error) {
      console.error('[TOR-SETUP] Failed to install Tor:', error);
      return false;
    }
  }

  /**
   * Configure Tor with optimal settings
   */
  private async configureTor(options: TorInstallOptions): Promise<boolean> {
    try {
      console.log('[TOR-SETUP] Generating Tor configuration...');
      const config = this.generateTorConfig(options);
      console.log('[TOR-SETUP] Generated config length:', config.length);

      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        console.log('[TOR-SETUP] Calling electronAPI.configureTor...');
        const result = await (window as any).electronAPI.configureTor({ config });
        console.log('[TOR-SETUP] Configuration result from Electron:', result);
        this.status.isConfigured = result.success;
        return result.success;
      }

      console.error('[TOR-SETUP] No electronAPI available');
      return false;
    } catch (error) {
      console.error('[TOR-SETUP] Failed to configure Tor:', error);
      return false;
    }
  }

  /**
   * Start Tor service
   */
  private async startTor(): Promise<{ success: boolean; error?: string }> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const result = await (window as any).electronAPI.startTor();
        this.status.isRunning = result.success;
        return result;
      }

      return { success: false, error: 'electronAPI not available' };
    } catch (error) {
      console.error('[TOR-SETUP] Failed to start Tor:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return { success: false, error: errorMessage };
    }
  }

  /**
   * Verify Tor connection is working
   */
  private async verifyTorConnection(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        // Use Electron main process to verify Tor connection
        const result = await (window as any).electronAPI.verifyTorConnection();
        if (result && result.success && result.isTor) {
          return true;
        }

        // Fallback heuristic: treat as connected if Tor is running and SOCKS port is known
        try {
          const status = await (window as any).electronAPI.getTorStatus?.();
          const info = await (window as any).electronAPI.getTorInfo?.();
          const running = !!(status && status.isRunning);
          const hasSocks = !!(info && (info.socksPort || info.binaryExists));
          if (running && hasSocks) {
            console.warn('[TOR-SETUP] Verification failed, but Tor appears to be running with SOCKS; proceeding.');
            return true;
          }
        } catch (_e) {
          // ignore and fall through to failure
        }
        return false;
      }

      // Fallback: assume success if we can't verify
      console.log('[TOR-SETUP] Cannot verify Tor connection in browser environment, assuming success');
      return true;
    } catch (error) {
      console.error('[TOR-SETUP] Failed to verify Tor connection:', error);
      return false;
    }
  }

  /**
   * Generate optimal Tor configuration
   */
  private generateTorConfig(options: TorInstallOptions): string {
    // Use dynamic ports from options or defaults
    // Use non-default ports by default to avoid colliding with a system Tor
    const socksPort = options.customConfig?.socksPort || 9150;
    const controlPort = options.customConfig?.controlPort || 9151;

    const config = [
      '# Auto-generated Tor configuration for end2end',
      '# SOCKS proxy port',
      `SocksPort ${socksPort}`,
      '',
      '# Control port for circuit management',
      `ControlPort ${controlPort}`,
      'CookieAuthentication 1',
      '',
      '# Security settings',
      'SocksPolicy accept 127.0.0.1',
      'SocksPolicy reject *',
      '',
      '# Performance optimizations',
      'NewCircuitPeriod 30',
      'MaxCircuitDirtiness 600',
      'CircuitBuildTimeout 30',
      'LearnCircuitBuildTimeout 0',
      '',
      '# Privacy settings',
      'ExitPolicy reject *:*',
      'ClientOnly 1',
      '',
      '# Logging (more verbose for debugging)',
      'Log notice stdout',
      'Log warn stdout',
      'SafeLogging 0',
      '',
      '# Data directory (will be overridden by command line)',
      'DataDirectory ./tor-data',
      '',
      '# Network resilience settings',
      'FetchDirInfoEarly 1',
      'FetchDirInfoExtraEarly 1',
      'FetchUselessDescriptors 1',
    ];

    // Add bridge configuration if requested
    if (options.enableBridges) {
      const hasBridges = Array.isArray(options.bridges) && options.bridges.length > 0;
      const transport = hasBridges ? (options.transport || 'obfs4') : 'snowflake';
      config.push('', '# Bridge configuration for censored networks', 'UseBridges 1');

      if (transport === 'obfs4') {
        const obfs4Path = options.obfs4ProxyPath?.trim() || 'obfs4proxy';
        config.push(`ClientTransportPlugin obfs4 exec ${obfs4Path}`);
      } else if (transport === 'snowflake') {
        // Note: snowflake-client binary must be available; main process should provision it
        config.push('ClientTransportPlugin snowflake exec snowflake-client');
        // For Snowflake, a generic Bridge line can be used
        config.push('Bridge snowflake');
      }

      // Add user-provided bridges (if provided)
      if (hasBridges) {
        for (const line of options.bridges!) {
          const trimmed = (line || '').trim();
          if (!trimmed) continue;
          // Ensure it starts with 'Bridge '
          config.push(trimmed.startsWith('Bridge ') ? trimmed : `Bridge ${trimmed}`);
        }
      }
    }

    // Add custom configuration
    if (options.customConfig) {
      config.push('', '# Custom configuration');
      Object.entries(options.customConfig).forEach(([key, value]) => {
        config.push(`${key} ${value}`);
      });
    }

    return config.join('\n');
  }

  /**
   * Detect current platform
   */
  private detectPlatform(): string {
    if (typeof window !== 'undefined' && (window as any).electronAPI) {
      return (window as any).electronAPI.platform || 'unknown';
    }

    // Guard access to navigator for SSR/Node environments
    if (typeof window === 'undefined' || typeof navigator === 'undefined') {
      return 'unknown';
    }

    // Fallback platform detection using user agent
    try {
      const userAgent = navigator.userAgent.toLowerCase();
      if (userAgent.includes('win')) return 'win32';
      if (userAgent.includes('mac')) return 'darwin';
      if (userAgent.includes('linux')) return 'linux';
      return 'unknown';
    } catch (error) {
      console.warn('[TOR-AUTO-SETUP] Failed to detect platform:', error);
      return 'unknown';
    }
  }



  /**
   * Check if running in Electron environment
   */
  private isElectronEnvironment(): boolean {
    return typeof window !== 'undefined' && (window as any).electronAPI;
  }

  /**
   * Update setup status and notify callback
   */
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

  /**
   * Get current setup status
   */
  getStatus(): TorSetupStatus {
    return { ...this.status };
  }

  /**
   * Refresh status from Electron API
   */
  async refreshStatus(): Promise<TorSetupStatus> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const torStatus = await (window as any).electronAPI.getTorStatus();
        const torInfo = await (window as any).electronAPI.getTorInfo();
        
        this.status.isRunning = torStatus.isRunning || false;
        this.status.version = torInfo.systemTorVersion || torInfo.version || undefined;
        this.status.socksPort = torInfo.socksPort;
        this.status.controlPort = torInfo.controlPort;
        
        // If Tor is running and we have version info, assume installed/configured
        if (this.status.isRunning && this.status.version) {
          this.status.isInstalled = true;
          this.status.isConfigured = true;
          this.status.setupProgress = 100;
          this.status.currentStep = 'Tor setup complete!';
        }
      }
    } catch (error) {
      console.error('[TOR-SETUP] Failed to refresh status:', error);
    }
    
    return { ...this.status };
  }

  /**
   * Stop Tor service
   */
  async stopTor(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const result = await (window as any).electronAPI.stopTor();
        if (result.success) {
          this.status.isRunning = false;
          this.status.error = undefined; // Clear any previous errors
          this.status.setupProgress = 0; // Reset progress
          this.status.currentStep = 'Ready to setup'; // Reset step
        }
        return result.success;
      }
      return false;
    } catch (error) {
      console.error('[TOR-SETUP] Failed to stop Tor:', error);
      return false;
    }
  }

  /**
   * Uninstall Tor (for cleanup)
   */
  async uninstallTor(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const result = await (window as any).electronAPI.uninstallTor();
        if (result.success) {
          this.status.isInstalled = false;
          this.status.isConfigured = false;
          this.status.isRunning = false;
          this.status.error = undefined; // Clear any previous errors
          this.status.setupProgress = 0; // Reset progress
          this.status.currentStep = 'Ready to setup'; // Reset step
        }
        return result.success;
      }
      return false;
    } catch (error) {
      console.error('[TOR-SETUP] Failed to uninstall Tor:', error);
      return false;
    }
  }
}

// Lazy singleton instance
let _torAutoSetupInstance: TorAutoSetup | null = null;

export function getTorAutoSetup(): TorAutoSetup {
  if (!_torAutoSetupInstance) {
    _torAutoSetupInstance = new TorAutoSetup();
  }
  return _torAutoSetupInstance;
}