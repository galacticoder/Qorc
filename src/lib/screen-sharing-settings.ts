/**
 * Screen Sharing Settings Manager
 * Handles persistence and management of user screen sharing preferences
 */

import {
  ScreenSharingSettings,
  ScreenSharingResolution,
  SCREEN_SHARING_RESOLUTIONS,
  SCREEN_SHARING_FRAMERATES
} from './webrtc-calling';

const STORAGE_KEY = 'screen_sharing_settings_v1';

export class ScreenSharingSettingsManager {
  private static instance: ScreenSharingSettingsManager | null = null;
  private settings: ScreenSharingSettings | null = null;
  private listeners: Set<(settings: ScreenSharingSettings) => void> = new Set();

  private constructor() {
    // Don't load settings immediately to avoid circular dependency
    // Settings will be loaded lazily when first accessed
  }

  public static getInstance(): ScreenSharingSettingsManager {
    if (!ScreenSharingSettingsManager.instance) {
      ScreenSharingSettingsManager.instance = new ScreenSharingSettingsManager();
    }
    return ScreenSharingSettingsManager.instance;
  }

  /**
   * Load settings from localStorage with validation
   */
  private loadSettings(): ScreenSharingSettings {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) {
        // Find the 1080p resolution from the current presets as default
        const defaultResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === '1080p') || SCREEN_SHARING_RESOLUTIONS[0];
        return {
          resolution: defaultResolution,
          frameRate: 30,
          quality: 'medium'
        };
      }

      const parsed = JSON.parse(stored);
      
      // Validate the loaded settings
      if (!this.isValidSettings(parsed)) {
        console.warn('[ScreenSharingSettings] Invalid stored settings, using defaults');
        // Find the 1080p resolution from the current presets as fallback
        const defaultResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === '1080p') || SCREEN_SHARING_RESOLUTIONS[0];
        return {
          resolution: defaultResolution,
          frameRate: 30,
          quality: 'medium'
        };
      }

      // Ensure resolution exists in current presets
      const resolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === parsed.resolution?.id);
      if (!resolution) {
        console.warn('[ScreenSharingSettings] Stored resolution not found, using default');
        // Find the 1080p resolution from the current presets
        const defaultResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === '1080p') || SCREEN_SHARING_RESOLUTIONS[0];
        return {
          resolution: defaultResolution,
          frameRate: 30,
          quality: 'medium'
        };
      }

      return {
        resolution,
        frameRate: parsed.frameRate,
        quality: parsed.quality
      };
    } catch (error) {
      console.error('[ScreenSharingSettings] Failed to load settings:', error);
      // Find the 1080p resolution from the current presets as fallback
      const defaultResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === '1080p') || SCREEN_SHARING_RESOLUTIONS[0];
      return {
        resolution: defaultResolution,
        frameRate: 30,
        quality: 'medium'
      };
    }
  }

  /**
   * Validate settings object structure
   */
  private isValidSettings(settings: any): boolean {
    if (!settings || typeof settings !== 'object') return false;
    
    if (!settings.resolution || typeof settings.resolution !== 'object') return false;
    if (typeof settings.resolution.id !== 'string') return false;
    
    if (typeof settings.frameRate !== 'number') return false;
    if (!SCREEN_SHARING_FRAMERATES.includes(settings.frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) return false;
    
    if (!['low', 'medium', 'high'].includes(settings.quality)) return false;
    
    return true;
  }

  /**
   * Save settings to localStorage
   */
  private saveSettings(): void {
    if (this.settings === null) return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.settings));
    } catch (error) {
      console.error('[ScreenSharingSettings] Failed to save settings:', error);
    }
  }

  /**
   * Ensure settings are loaded (lazy loading to avoid circular dependency)
   */
  private ensureSettingsLoaded(): void {
    if (this.settings === null) {
      this.settings = this.loadSettings();
    }
  }

  /**
   * Get current settings
   */
  public getSettings(): ScreenSharingSettings {
    this.ensureSettingsLoaded();
    return { ...this.settings! };
  }

  /**
   * Update resolution setting
   */
  public setResolution(resolution: ScreenSharingResolution): void {
    this.ensureSettingsLoaded();

    // Validate resolution against known presets
    const validResolution = SCREEN_SHARING_RESOLUTIONS.find(r =>
      r.id === resolution.id || r.name === resolution.name
    );

    if (!validResolution) {
      throw new Error(`Invalid resolution: ${resolution.id || resolution.name}. Must be one of: ${SCREEN_SHARING_RESOLUTIONS.map(r => r.id).join(', ')}.`);
    }

    console.log('[ScreenSharingSettings] Resolution changed to:', validResolution.name);
    this.settings!.resolution = validResolution; // Use canonical preset
    this.saveSettings();
    this.notifyListeners();
  }

  /**
   * Update framerate setting
   */
  public setFrameRate(frameRate: number): void {
    if (!SCREEN_SHARING_FRAMERATES.includes(frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
      throw new Error(`Invalid framerate: ${frameRate}. Must be one of: ${SCREEN_SHARING_FRAMERATES.join(', ')}.`);
    }
    this.ensureSettingsLoaded();
    console.log('[ScreenSharingSettings] Frame rate changed to:', frameRate, 'FPS');
    this.settings!.frameRate = frameRate;
    this.saveSettings();
    this.notifyListeners();
  }

  /**
   * Update quality setting
   */
  public setQuality(quality: 'low' | 'medium' | 'high'): void {
    this.ensureSettingsLoaded();
    console.log('[ScreenSharingSettings] Quality changed to:', quality);
    this.settings!.quality = quality;
    this.saveSettings();
    this.notifyListeners();
  }

  /**
   * Update all settings at once
   */
  public updateSettings(newSettings: Partial<ScreenSharingSettings>): void {
    this.ensureSettingsLoaded();

    if (newSettings.resolution) {
      // Validate resolution against known presets
      const validResolution = SCREEN_SHARING_RESOLUTIONS.find(r =>
        r.id === newSettings.resolution!.id || r.name === newSettings.resolution!.name
      );

      if (!validResolution) {
        throw new Error(`Invalid resolution: ${newSettings.resolution.id || newSettings.resolution.name}. Must be one of: ${SCREEN_SHARING_RESOLUTIONS.map(r => r.id).join(', ')}.`);
      }

      this.settings!.resolution = validResolution; // Use canonical preset
    }

    if (newSettings.frameRate !== undefined) {
      if (!SCREEN_SHARING_FRAMERATES.includes(newSettings.frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
        throw new Error(`Invalid framerate: ${newSettings.frameRate}. Must be one of: ${SCREEN_SHARING_FRAMERATES.join(', ')}.`);
      }
      this.settings!.frameRate = newSettings.frameRate;
    }

    if (newSettings.quality) {
      if (!['low', 'medium', 'high'].includes(newSettings.quality)) {
        throw new Error(`Invalid quality: ${newSettings.quality}. Must be one of: low, medium, high.`);
      }
      this.settings!.quality = newSettings.quality;
    }

    this.saveSettings();
    this.notifyListeners();
  }

  /**
   * Reset to default settings
   */
  public resetToDefaults(): void {
    // Find the 1080p resolution from the current presets as default
    const defaultResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === '1080p') || SCREEN_SHARING_RESOLUTIONS[0];
    this.settings = {
      resolution: defaultResolution,
      frameRate: 30,
      quality: 'medium'
    };
    this.saveSettings();
    this.notifyListeners();
  }

  /**
   * Subscribe to settings changes
   */
  public subscribe(listener: (settings: ScreenSharingSettings) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Notify all listeners of settings changes
   */
  private notifyListeners(): void {
    this.listeners.forEach(listener => {
      try {
        listener(this.getSettings());
      } catch (error) {
        console.error('[ScreenSharingSettings] Error in settings listener:', error);
      }
    });
  }

  /**
   * Get video constraints based on current settings
   */
  public getVideoConstraints(): MediaTrackConstraints {
    this.ensureSettingsLoaded();
    const { resolution, frameRate, quality } = this.settings!;

    // Base constraints with frame rate
    const constraints: MediaTrackConstraints = {
      frameRate: { ideal: frameRate, max: frameRate, min: Math.max(1, frameRate - 5) }
    };

    // Apply resolution constraints
    if (resolution.isNative) {
      // For native resolution, let the browser choose the best available
      constraints.width = { ideal: 1920 };
      constraints.height = { ideal: 1080 };
    } else {
      constraints.width = { ideal: resolution.width, max: resolution.width, min: Math.max(640, resolution.width - 100) };
      constraints.height = { ideal: resolution.height, max: resolution.height, min: Math.max(480, resolution.height - 100) };
    }

    // Apply quality settings through bitrate constraints
    const qualitySettings = this.getQualityConstraints(quality);
    Object.assign(constraints, qualitySettings);

    console.log('[ScreenSharingSettings] Generated video constraints:', constraints);
    return constraints;
  }

  /**
   * Get quality-specific constraints
   */
  private getQualityConstraints(quality: 'low' | 'medium' | 'high'): Partial<MediaTrackConstraints> {
    switch (quality) {
      case 'low':
        return {
          // Lower quality settings
          advanced: [{ width: { max: 1280 }, height: { max: 720 } }] as any
        };
      case 'medium':
        return {
          // Medium quality settings
          advanced: [{ width: { max: 1920 }, height: { max: 1080 } }] as any
        };
      case 'high':
        return {
          // High quality settings - no additional restrictions
          advanced: [{ width: { max: 3840 }, height: { max: 2160 } }] as any
        };
      default:
        return {};
    }
  }

  /**
   * Get Electron-specific video constraints
   */
  public getElectronVideoConstraints(): any {
    this.ensureSettingsLoaded();
    const { resolution, frameRate, quality } = this.settings!;

    console.log('[ScreenSharingSettings] Generating Electron constraints for:', { resolution: resolution.name, frameRate, quality });

    if (resolution.isNative) {
      // For native resolution, use flexible constraints
      return {
        mandatory: {
          chromeMediaSource: 'desktop',
          minWidth: 1280,
          maxWidth: 3840,
          minHeight: 720,
          maxHeight: 2160,
          minFrameRate: Math.max(1, frameRate - 2),
          maxFrameRate: frameRate
        }
      };
    } else {
      return {
        mandatory: {
          chromeMediaSource: 'desktop',
          minWidth: resolution.width,
          maxWidth: resolution.width,
          minHeight: resolution.height,
          maxHeight: resolution.height,
          minFrameRate: Math.max(1, frameRate - 2),
          maxFrameRate: frameRate
        }
      };
    }
  }
}

// Export singleton instance
export const screenSharingSettings = ScreenSharingSettingsManager.getInstance();
