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
  error?: string;
  setupProgress: number; // 0-100
  currentStep: string;
}

export interface TorInstallOptions {
  autoStart: boolean;
  enableBridges: boolean;
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

      // Step 1: Always download fresh Tor Expert Bundle for consistency
      this.updateStatus(10, 'Preparing Tor Expert Bundle download...');
      console.log('[TOR-SETUP] Will download Tor Expert Bundle for maximum compatibility');

      // Step 2: Download Tor Expert Bundle (always, for consistency)
      this.updateStatus(20, 'Downloading Tor Expert Bundle...', 'Downloading ~15MB from torproject.org');
      const downloadSuccess = await this.downloadTor();

      if (!downloadSuccess) {
        this.updateStatus(0, 'Failed to download Tor', 'Could not download Tor Expert Bundle. Check internet connection.');
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
        const verifySuccess = await this.verifyTorConnection();
        
        if (!verifySuccess) {
          this.updateStatus(0, 'Tor connection failed', 'Could not establish Tor connection.');
          return false;
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
        return result.success && result.isTor;
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
    const config = [
      '# Auto-generated Tor configuration for SecureChat',
      '# SOCKS proxy port',
      'SocksPort 9050',
      '',
      '# Control port for circuit management',
      'ControlPort 9051',
      'CookieAuthentication 1',
      '',
      '# Security settings',
      'SocksPolicy accept 127.0.0.1',
      'SocksPolicy reject *',
      '',
      '# Performance optimizations',
      'NewCircuitPeriod 30',
      'MaxCircuitDirtiness 600',
      'CircuitBuildTimeout 10',
      'LearnCircuitBuildTimeout 1',
      '',
      '# Privacy settings',
      'ExitPolicy reject *:*',
      'ClientOnly 1',
      '',
      '# Logging (minimal for privacy)',
      'Log notice stdout',
      'SafeLogging 1',
    ];

    // Add bridge configuration if requested
    if (options.enableBridges) {
      config.push(
        '',
        '# Bridge configuration for censored networks',
        'UseBridges 1',
        'ClientTransportPlugin obfs4 exec obfs4proxy',
        '# Bridges will be automatically fetched'
      );
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

    // Fallback platform detection
    const userAgent = navigator.userAgent.toLowerCase();
    if (userAgent.includes('win')) return 'win32';
    if (userAgent.includes('mac')) return 'darwin';
    if (userAgent.includes('linux')) return 'linux';
    return 'unknown';
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
   * Stop Tor service
   */
  async stopTor(): Promise<boolean> {
    try {
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        const result = await (window as any).electronAPI.stopTor();
        this.status.isRunning = !result.success;
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

// Global instance
export const torAutoSetup = new TorAutoSetup();
