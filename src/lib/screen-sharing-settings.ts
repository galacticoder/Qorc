/** Manages persisted screen sharing preferences. */

import {
  ScreenSharingSettings,
  ScreenSharingResolution,
  SCREEN_SHARING_RESOLUTIONS,
  SCREEN_SHARING_FRAMERATES
} from './screen-sharing-consts';
import { CryptoUtils } from './utils/crypto-utils';
import { encryptedStorage } from './database/encrypted-storage';
import { PostQuantumRandom } from './cryptography/random';
import { SecureMemory } from './cryptography/secure-memory';
import { DEFAULT_QUALITY, QUALITY_OPTIONS } from './constants';
import { STORAGE_KEYS } from './database/storage-keys';

const STORAGE_KEY = STORAGE_KEYS.SCREEN_SHARING_SETTINGS;
const DEVICE_KEY_STORAGE = STORAGE_KEYS.SCREEN_SHARING_DEVICE_KEY;
const AUDIT_CHANNEL = 'screen-sharing';
const RATE_LIMIT_WINDOW_MS = 100;
const MAX_REQUESTS_PER_WINDOW = 5;
const SETTINGS_TTL_MS = 24 * 60 * 60 * 1000;

interface PersistedEnvelope {
  version: number;
  ciphertext: string;
  tag: string;
  nonce: string;
  mac: string;
  expiresAt: number;
}

interface InternalSettings extends ScreenSharingSettings {
  updatedAt: number;
}

const HKDF_SALT = new TextEncoder().encode('screen-sharing-settings-salt');
const HKDF_INFO_ENC = new TextEncoder().encode('screen-sharing-settings:enc');
const HKDF_INFO_MAC = new TextEncoder().encode('screen-sharing-settings:mac');
const AAD_CONTEXT = new TextEncoder().encode('screen-sharing-settings:v1');

function isTorMode(): boolean {
  try {
    return typeof window !== 'undefined' && !!(window as any).__TOR_ENABLED__;
  } catch {
    return false;
  }
}

function buildDefaultResolution(): ScreenSharingResolution {
  const viable = SCREEN_SHARING_RESOLUTIONS.filter(r => !r.isNative);
  const pool = viable.length > 0 ? viable : SCREEN_SHARING_RESOLUTIONS;
  const idx = PostQuantumRandom.randomBytes(2).reduce((acc, byte) => (acc + byte) % pool.length, 0);
  return pool[idx];
}

function deepValidateSettings(settings: any): settings is InternalSettings {
  if (!settings || typeof settings !== 'object') {
    return false;
  }
  if (typeof settings.updatedAt !== 'number' || !Number.isFinite(settings.updatedAt)) {
    return false;
  }
  const { resolution, frameRate, quality } = settings;
  if (!resolution || typeof resolution !== 'object') {
    return false;
  }
  const { id, name, width, height, isNative } = resolution;
  if (typeof id !== 'string' || typeof name !== 'string') {
    return false;
  }
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 0 || height < 0) {
    return false;
  }
  if (typeof isNative !== 'boolean' && typeof isNative !== 'undefined') {
    return false;
  }
  if (typeof frameRate !== 'number' || !SCREEN_SHARING_FRAMERATES.includes(frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
    return false;
  }
  if (!QUALITY_OPTIONS.includes(quality as any)) {
    return false;
  }
  return true;
}

export class ScreenSharingSettingsManager {
  private static instance: ScreenSharingSettingsManager | null = null;
  private settings: InternalSettings | null = null;
  private listeners: Set<(settings: ScreenSharingSettings) => void> = new Set();
  private readonly rateBucket = new Map<string, { count: number; resetAt: number }>();
  private readonly isTransient = isTorMode();
  private deviceKey: Uint8Array | null = null;

  private constructor() { }

  public static getInstance(): ScreenSharingSettingsManager {
    if (!ScreenSharingSettingsManager.instance) {
      ScreenSharingSettingsManager.instance = new ScreenSharingSettingsManager();
    }
    return ScreenSharingSettingsManager.instance;
  }

  private async getKeyMaterial(): Promise<Uint8Array> {
    if (this.isTransient) {
      return PostQuantumRandom.randomBytes(32);
    }
    if (this.deviceKey) {
      return this.deviceKey;
    }
    try {
      const stored = await encryptedStorage.getItem(DEVICE_KEY_STORAGE);
      if (stored && typeof stored === 'string') {
        this.deviceKey = CryptoUtils.Base64.base64ToUint8Array(stored);
        return this.deviceKey;
      }
    } catch (_error) {
      console.warn('[screen-sharing] device-key-load-failed', (_error as Error).message);
    }
    const generated = PostQuantumRandom.randomBytes(32);
    try {
      await encryptedStorage.setItem(DEVICE_KEY_STORAGE, CryptoUtils.Base64.arrayBufferToBase64(generated));
      this.deviceKey = generated;
      return this.deviceKey;
    } catch (_error) {
      console.error('[screen-sharing] device-key-store-failed', (_error as Error).message);
      return generated;
    }
  }

  private async deriveKeys(): Promise<{ encKey: Uint8Array; macKey: Uint8Array }> {
    const material = await this.getKeyMaterial();
    const encKey = await CryptoUtils.KDF.blake3Hkdf(material, HKDF_SALT, HKDF_INFO_ENC, 32);
    const macKey = await CryptoUtils.KDF.blake3Hkdf(material, HKDF_SALT, HKDF_INFO_MAC, 32);
    return { encKey, macKey };
  }

  private async encryptSettings(settings: InternalSettings): Promise<PersistedEnvelope> {
    const { encKey, macKey } = await this.deriveKeys();
    const plaintext = new TextEncoder().encode(JSON.stringify(settings));
    const nonce = PostQuantumRandom.randomBytes(36);
    const { ciphertext, tag } = CryptoUtils.PostQuantumAEAD.encrypt(plaintext, encKey, AAD_CONTEXT, nonce);
    const macInput = new Uint8Array(nonce.length + ciphertext.length + tag.length);
    macInput.set(nonce, 0);
    macInput.set(ciphertext, nonce.length);
    macInput.set(tag, nonce.length + ciphertext.length);
    const mac = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
    SecureMemory.zeroBuffer(encKey);
    SecureMemory.zeroBuffer(macKey);
    SecureMemory.zeroBuffer(macInput);
    return {
      version: 1,
      ciphertext: CryptoUtils.Base64.arrayBufferToBase64(ciphertext),
      tag: CryptoUtils.Base64.arrayBufferToBase64(tag),
      nonce: CryptoUtils.Base64.arrayBufferToBase64(nonce),
      mac: CryptoUtils.Base64.arrayBufferToBase64(mac),
      expiresAt: Date.now() + SETTINGS_TTL_MS
    };
  }

  private async decryptSettings(envelope: PersistedEnvelope): Promise<InternalSettings | null> {
    if (!envelope || envelope.version !== 1) {
      return null;
    }
    if (typeof envelope.expiresAt !== 'number' || envelope.expiresAt < Date.now()) {
      return null;
    }
    try {
      const { encKey, macKey } = await this.deriveKeys();
      const ciphertext = CryptoUtils.Base64.base64ToUint8Array(envelope.ciphertext);
      const tag = CryptoUtils.Base64.base64ToUint8Array(envelope.tag);
      const nonce = CryptoUtils.Base64.base64ToUint8Array(envelope.nonce);
      const storedMac = CryptoUtils.Base64.base64ToUint8Array(envelope.mac);
      const macInput = new Uint8Array(nonce.length + ciphertext.length + tag.length);
      macInput.set(nonce, 0);
      macInput.set(ciphertext, nonce.length);
      macInput.set(tag, nonce.length + ciphertext.length);
      const computedMac = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
      const macValid = SecureMemory.constantTimeCompare(computedMac, storedMac);
      SecureMemory.zeroBuffer(computedMac);
      SecureMemory.zeroBuffer(macInput);
      if (!macValid) {
        SecureMemory.zeroBuffer(encKey);
        SecureMemory.zeroBuffer(macKey);
        return null;
      }
      const decrypted = CryptoUtils.PostQuantumAEAD.decrypt(ciphertext, nonce, tag, encKey, AAD_CONTEXT);
      SecureMemory.zeroBuffer(encKey);
      SecureMemory.zeroBuffer(macKey);
      const parsed = JSON.parse(new TextDecoder().decode(decrypted));
      if (!deepValidateSettings(parsed)) {
        return null;
      }
      return parsed;
    } catch (_error) {
      console.error('[screen-sharing] decrypt-failed', (_error as Error).message);
      return null;
    }
  }

  private async loadSettings(): Promise<InternalSettings> {
    if (this.isTransient) {
      return {
        resolution: buildDefaultResolution(),
        frameRate: 30,
        quality: DEFAULT_QUALITY,
        updatedAt: Date.now()
      };
    }
    try {
      const stored = await encryptedStorage.getItem(STORAGE_KEY);
      if (!stored || typeof stored !== 'string') {
        return {
          resolution: buildDefaultResolution(),
          frameRate: 30,
          quality: DEFAULT_QUALITY,
          updatedAt: Date.now()
        };
      }
      const envelope = JSON.parse(stored) as PersistedEnvelope;
      const decrypted = await this.decryptSettings(envelope);
      if (decrypted) {
        return decrypted;
      }
    } catch { }
    return {
      resolution: buildDefaultResolution(),
      frameRate: 30,
      quality: DEFAULT_QUALITY,
      updatedAt: Date.now()
    };
  }

  private async saveSettings(): Promise<void> {
    if (this.settings === null || this.isTransient) {
      return;
    }
    try {
      const envelope = await this.encryptSettings(this.settings);
      await encryptedStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
    } catch (_error) {
      console.error('[screen-sharing] save-failed', (_error as Error).message);
    }
  }

  private async ensureSettingsLoaded(): Promise<void> {
    if (this.settings === null) {
      this.settings = await this.loadSettings();
    }
  }

  private enforceRateLimit(method: string): void {
    const now = Date.now();
    const bucket = this.rateBucket.get(method) ?? { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
    }
    bucket.count += 1;
    if (bucket.count > MAX_REQUESTS_PER_WINDOW) {
      console.warn('[screen-sharing] rate-limited', method);
      throw new Error('Screen sharing settings rate limit exceeded');
    }
    this.rateBucket.set(method, bucket);
  }

  public async getSettings(): Promise<ScreenSharingSettings> {
    await this.ensureSettingsLoaded();
    const { resolution, frameRate, quality } = this.settings!;
    return { resolution, frameRate, quality };
  }

  public async setResolution(resolution: ScreenSharingResolution): Promise<void> {
    this.enforceRateLimit('setResolution');
    await this.ensureSettingsLoaded();
    const validResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === resolution.id);
    if (!validResolution) {
      throw new Error('Invalid resolution preset');
    }
    this.settings!.resolution = validResolution;
    this.settings!.updatedAt = Date.now();
    await this.saveSettings();
    this.notifyListeners();
  }

  public async setFrameRate(frameRate: number): Promise<void> {
    this.enforceRateLimit('setFrameRate');
    if (!SCREEN_SHARING_FRAMERATES.includes(frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
      throw new Error('Invalid frame rate preset');
    }
    await this.ensureSettingsLoaded();
    this.settings!.frameRate = frameRate;
    this.settings!.updatedAt = Date.now();
    await this.saveSettings();
    this.notifyListeners();
  }

  public async setQuality(quality: string): Promise<void> {
    this.enforceRateLimit('setQuality');
    if (!QUALITY_OPTIONS.includes(quality as any)) {
      throw new Error('Invalid quality preset');
    }
    await this.ensureSettingsLoaded();
    this.settings!.quality = quality as any;
    this.settings!.updatedAt = Date.now();
    await this.saveSettings();
    this.notifyListeners();
  }

  public async updateSettings(newSettings: Partial<ScreenSharingSettings>): Promise<void> {
    this.enforceRateLimit('updateSettings');
    await this.ensureSettingsLoaded();
    if (newSettings.resolution) {
      const validResolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === newSettings.resolution!.id);
      if (!validResolution) {
        throw new Error('Invalid resolution preset');
      }
      this.settings!.resolution = validResolution;
    }
    if (newSettings.frameRate !== undefined) {
      if (!SCREEN_SHARING_FRAMERATES.includes(newSettings.frameRate as typeof SCREEN_SHARING_FRAMERATES[number])) {
        throw new Error('Invalid frame rate preset');
      }
      this.settings!.frameRate = newSettings.frameRate;
    }
    if (newSettings.quality) {
      if (!QUALITY_OPTIONS.includes(newSettings.quality as any)) {
        throw new Error('Invalid quality preset');
      }
      this.settings!.quality = newSettings.quality;
    }
    this.settings!.updatedAt = Date.now();
    await this.saveSettings();
    this.notifyListeners();
  }

  public async resetToDefaults(): Promise<void> {
    this.enforceRateLimit('resetToDefaults');
    this.settings = {
      resolution: buildDefaultResolution(),
      frameRate: 30,
      quality: DEFAULT_QUALITY,
      updatedAt: Date.now()
    };
    await this.saveSettings();
    this.notifyListeners();
  }

  public subscribe(listener: (settings: ScreenSharingSettings) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notifyListeners(): void {
    const snapshot = this.settings ? { resolution: this.settings.resolution, frameRate: this.settings.frameRate, quality: this.settings.quality } : undefined;
    this.listeners.forEach(listener => {
      try {
        if (snapshot) {
          listener(snapshot);
        }
      } catch (error) {
        console.error('[screen-sharing] listener-error', (error as Error).message);
      }
    });
  }

  public async getVideoConstraints(): Promise<MediaTrackConstraints> {
    await this.ensureSettingsLoaded();
    const { resolution, frameRate } = this.settings!;
    const constraints: MediaTrackConstraints = {
      frameRate: { ideal: frameRate, max: frameRate }
    };
    if (!resolution.isNative) {
      constraints.width = { ideal: resolution.width, max: resolution.width };
      constraints.height = { ideal: resolution.height, max: resolution.height };
    }
    return constraints;
  }

  public async getElectronVideoConstraints(): Promise<any> {
    await this.ensureSettingsLoaded();
    const { resolution, frameRate } = this.settings!;
    if (resolution.isNative) {
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
    }
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

  public dispose(): void {
    this.listeners.clear();
    this.settings = null;
    this.rateBucket.clear();
    if (this.deviceKey) {
      SecureMemory.zeroBuffer(this.deviceKey);
      this.deviceKey = null;
    }
  }
}

export const screenSharingSettings = ScreenSharingSettingsManager.getInstance();