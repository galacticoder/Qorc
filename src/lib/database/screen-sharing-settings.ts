/**
 * Manages screen sharing preferences
 */

import {
  ScreenSharingSettings,
  cloneScreenSharingSettings
} from '../types/screen-sharing-types';
import { CryptoUtils } from '../utils/crypto-utils';
import { encryptedStorage } from './encrypted-storage';
import { SecureMemory } from '../cryptography/secure-memory';
import { PostQuantumRandom } from '../cryptography/random';
import {
  DEFAULT_QUALITY,
  QUALITY_OPTIONS,
  SCREEN_SHARING_RATE_LIMIT_WINDOW_MS,
  SCREEN_SHARING_MAX_REQUESTS_PER_WINDOW,
  SCREEN_SHARING_SETTINGS_TTL_MS,
  PQ_AEAD_CIPHERTEXT_OVERHEAD,
  PQ_AEAD_MAC_SIZE,
  PQ_AEAD_NONCE_SIZE,
  QualityOption
} from '../constants';
import { STORAGE_KEYS } from './storage-keys';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

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

const HKDF_SALT = new TextEncoder().encode(PROTOCOL_KEYS.SCREEN_SHARING_SALT);
const HKDF_INFO_ENC = new TextEncoder().encode(PROTOCOL_KEYS.SCREEN_SHARING_ENCRYPTION);
const HKDF_INFO_MAC = new TextEncoder().encode(PROTOCOL_KEYS.SCREEN_SHARING_MAC);
const AAD_CONTEXT = new TextEncoder().encode(PROTOCOL_KEYS.SCREEN_SHARING_AAD);
const DEVICE_KEY_BYTES = 32;
const SETTINGS_MAC_BYTES = 32;
const MAX_SETTINGS_PLAINTEXT_BYTES = 2048;
const MAX_SETTINGS_CIPHERTEXT_BYTES = MAX_SETTINGS_PLAINTEXT_BYTES + PQ_AEAD_CIPHERTEXT_OVERHEAD;
const MAX_SETTINGS_ENVELOPE_BYTES = 8192;

// Check if in Tor mode
function isTorMode(): boolean {
  try {
    return typeof window !== 'undefined' && !!(window as any).__TOR_ENABLED__;
  } catch {
    return false;
  }
}

// Deep validate settings
function deepValidateSettings(settings: any): settings is InternalSettings {
  if (
    !settings ||
    typeof settings !== 'object' ||
    Array.isArray(settings) ||
    Object.keys(settings).length !== 2 ||
    !['quality', 'updatedAt'].every(key =>
      Object.prototype.hasOwnProperty.call(settings, key)
    )
  ) {
    return false;
  }

  if (!Number.isSafeInteger(settings.updatedAt) || settings.updatedAt < 0) {
    return false;
  }
  
  const { quality } = settings;
  if (!QUALITY_OPTIONS.includes(quality as any)) {
    return false;
  }
  return true;
}

function hasValidEnvelopeShape(envelope: unknown): envelope is PersistedEnvelope {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) return false;
  const candidate = envelope as Record<string, unknown>;
  const keys = ['version', 'ciphertext', 'tag', 'nonce', 'mac', 'expiresAt'];
  if (
    Object.keys(candidate).length !== keys.length ||
    !keys.every(key => Object.prototype.hasOwnProperty.call(candidate, key)) ||
    candidate.version !== 1 ||
    typeof candidate.ciphertext !== 'string' ||
    candidate.ciphertext.length === 0 ||
    candidate.ciphertext.length > MAX_SETTINGS_ENVELOPE_BYTES ||
    typeof candidate.tag !== 'string' ||
    candidate.tag.length > 128 ||
    typeof candidate.nonce !== 'string' ||
    candidate.nonce.length > 128 ||
    typeof candidate.mac !== 'string' ||
    candidate.mac.length > 128 ||
    !Number.isSafeInteger(candidate.expiresAt)
  ) {
    return false;
  }
  const now = Date.now();
  return (candidate.expiresAt as number) >= now &&
    (candidate.expiresAt as number) <= now + SCREEN_SHARING_SETTINGS_TTL_MS;
}

// Screen sharing settings manager
export class ScreenSharingSettingsManager {
  private static instance: ScreenSharingSettingsManager | null = null;
  private settings: InternalSettings | null = null;
  private listeners: Set<(settings: ScreenSharingSettings) => void> = new Set();
  private requestBucket: Map<string, { count: number; resetAt: number }> = new Map();
  private readonly isTransient = isTorMode();
  private deviceKey: Uint8Array | null = null;
  private deviceKeyPromise: Promise<Uint8Array> | null = null;
  private settingsLoadPromise: Promise<void> | null = null;
  private mutationChain: Promise<void> = Promise.resolve();
  private accountGeneration = 0;

  private constructor() {
    encryptedStorage.subscribeBinding(() => {
      this.resetAccountState();
    });
  }

  // Get singleton instance
  public static getInstance(): ScreenSharingSettingsManager {
    if (!ScreenSharingSettingsManager.instance) {
      ScreenSharingSettingsManager.instance = new ScreenSharingSettingsManager();
    }
    return ScreenSharingSettingsManager.instance;
  }

  private resetAccountState(): void {
    this.accountGeneration += 1;
    this.settings = null;
    this.settingsLoadPromise = null;
    this.deviceKeyPromise = null;
    this.mutationChain = Promise.resolve();
    this.requestBucket.clear();
    if (this.deviceKey) {
      SecureMemory.zeroBuffer(this.deviceKey);
      this.deviceKey = null;
    }
    if (encryptedStorage.isInitialized() && this.listeners.size > 0) {
      const generation = this.accountGeneration;
      void this.ensureSettingsLoaded().then(() => {
        if (generation === this.accountGeneration) this.notifyListeners();
      }).catch(() => { });
    }
  }

  private async loadOrCreateDeviceKey(generation: number): Promise<Uint8Array> {
    const stored = await encryptedStorage.getItem(STORAGE_KEYS.SCREEN_SHARING_DEVICE_KEY);
    if (generation !== this.accountGeneration) {
      throw new Error('Screen sharing settings account changed during key load');
    }

    if (stored !== null) {
      if (typeof stored !== 'string' || stored.length > 128) {
        throw new Error('Stored screen sharing device key is invalid');
      }
      const decoded = CryptoUtils.Base64.base64ToUint8Array(stored);
      if (
        decoded.length !== DEVICE_KEY_BYTES ||
        CryptoUtils.Base64.arrayBufferToBase64(decoded) !== stored
      ) {
        SecureMemory.zeroBuffer(decoded);
        throw new Error('Stored screen sharing device key is invalid');
      }
      if (generation !== this.accountGeneration) {
        SecureMemory.zeroBuffer(decoded);
        throw new Error('Screen sharing settings account changed during key load');
      }
      this.deviceKey = decoded;
      return decoded;
    }

    const generated = PostQuantumRandom.randomBytes(DEVICE_KEY_BYTES);
    try {
      await encryptedStorage.setItem(
        STORAGE_KEYS.SCREEN_SHARING_DEVICE_KEY,
        CryptoUtils.Base64.arrayBufferToBase64(generated)
      );
      if (generation !== this.accountGeneration) {
        throw new Error('Screen sharing settings account changed during key creation');
      }
      this.deviceKey = generated;
      return generated;
    } catch (error) {
      SecureMemory.zeroBuffer(generated);
      throw error;
    }
  }

  // Get key material for encryption
  private async getKeyMaterial(): Promise<Uint8Array> {
    if (this.isTransient) {
      return PostQuantumRandom.randomBytes(DEVICE_KEY_BYTES);
    }
    if (this.deviceKey) {
      return this.deviceKey;
    }
    if (!this.deviceKeyPromise) {
      const generation = this.accountGeneration;
      let pending: Promise<Uint8Array>;
      pending = this.loadOrCreateDeviceKey(generation).finally(() => {
        if (this.deviceKeyPromise === pending) this.deviceKeyPromise = null;
      });
      this.deviceKeyPromise = pending;
    }
    return await this.deviceKeyPromise;
  }

  // Derive encryption and MAC keys
  private async deriveKeys(): Promise<{ encKey: Uint8Array; macKey: Uint8Array }> {
    const material = await this.getKeyMaterial();
    let encKey: Uint8Array | null = null;
    let macKey: Uint8Array | null = null;
    try {
      encKey = await CryptoUtils.KDF.blake3Hkdf(material, HKDF_SALT, HKDF_INFO_ENC, 32);
      macKey = await CryptoUtils.KDF.blake3Hkdf(material, HKDF_SALT, HKDF_INFO_MAC, 32);
      return { encKey, macKey };
    } catch (error) {
      if (encKey) SecureMemory.zeroBuffer(encKey);
      if (macKey) SecureMemory.zeroBuffer(macKey);
      throw error;
    } finally {
      if (this.isTransient) SecureMemory.zeroBuffer(material);
    }
  }

  // Encrypt settings
  private async encryptSettings(settings: InternalSettings): Promise<PersistedEnvelope> {
    if (!deepValidateSettings(settings)) throw new Error('Invalid screen sharing settings');
    let encKey: Uint8Array | null = null;
    let macKey: Uint8Array | null = null;
    let plaintext: Uint8Array | null = null;
    let nonceSeed: Uint8Array | null = null;
    let ciphertext: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let tag: Uint8Array | null = null;
    let macInput: Uint8Array | null = null;
    let mac: Uint8Array | null = null;
    try {
      ({ encKey, macKey } = await this.deriveKeys());
      plaintext = new TextEncoder().encode(JSON.stringify(settings));
      if (plaintext.length === 0 || plaintext.length > MAX_SETTINGS_PLAINTEXT_BYTES) {
        throw new Error('Screen sharing settings payload exceeds limit');
      }
      nonceSeed = PostQuantumRandom.randomBytes(PQ_AEAD_NONCE_SIZE);
      const encrypted = CryptoUtils.PostQuantumAEAD.encrypt(
        plaintext,
        encKey,
        AAD_CONTEXT,
        nonceSeed
      );
      ciphertext = encrypted.ciphertext;
      nonce = encrypted.nonce;
      tag = encrypted.tag;

      macInput = new Uint8Array(nonce.length + ciphertext.length + tag.length);
      macInput.set(nonce, 0);
      macInput.set(ciphertext, nonce.length);
      macInput.set(tag, nonce.length + ciphertext.length);
      mac = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
      if (mac.length !== SETTINGS_MAC_BYTES) throw new Error('Invalid settings MAC length');

      return {
        version: 1,
        ciphertext: CryptoUtils.Base64.arrayBufferToBase64(ciphertext),
        tag: CryptoUtils.Base64.arrayBufferToBase64(tag),
        nonce: CryptoUtils.Base64.arrayBufferToBase64(nonce),
        mac: CryptoUtils.Base64.arrayBufferToBase64(mac),
        expiresAt: Date.now() + SCREEN_SHARING_SETTINGS_TTL_MS
      };
    } finally {
      if (encKey) SecureMemory.zeroBuffer(encKey);
      if (macKey) SecureMemory.zeroBuffer(macKey);
      if (plaintext) SecureMemory.zeroBuffer(plaintext);
      if (nonceSeed) SecureMemory.zeroBuffer(nonceSeed);
      if (ciphertext) SecureMemory.zeroBuffer(ciphertext);
      if (nonce) SecureMemory.zeroBuffer(nonce);
      if (tag) SecureMemory.zeroBuffer(tag);
      if (macInput) SecureMemory.zeroBuffer(macInput);
      if (mac) SecureMemory.zeroBuffer(mac);
    }
  }

  // Decrypt settings
  private async decryptSettings(envelope: unknown): Promise<InternalSettings | null> {
    if (!hasValidEnvelopeShape(envelope)) return null;
    let encKey: Uint8Array | null = null;
    let macKey: Uint8Array | null = null;
    let ciphertext: Uint8Array | null = null;
    let tag: Uint8Array | null = null;
    let nonce: Uint8Array | null = null;
    let storedMac: Uint8Array | null = null;
    let macInput: Uint8Array | null = null;
    let computedMac: Uint8Array | null = null;
    let decrypted: Uint8Array | null = null;
    try {
      ciphertext = CryptoUtils.Base64.base64ToUint8Array(envelope.ciphertext);
      tag = CryptoUtils.Base64.base64ToUint8Array(envelope.tag);
      nonce = CryptoUtils.Base64.base64ToUint8Array(envelope.nonce);
      storedMac = CryptoUtils.Base64.base64ToUint8Array(envelope.mac);
      if (
        ciphertext.length <= PQ_AEAD_CIPHERTEXT_OVERHEAD ||
        ciphertext.length > MAX_SETTINGS_CIPHERTEXT_BYTES ||
        tag.length !== PQ_AEAD_MAC_SIZE ||
        nonce.length !== PQ_AEAD_NONCE_SIZE ||
        storedMac.length !== SETTINGS_MAC_BYTES ||
        CryptoUtils.Base64.arrayBufferToBase64(ciphertext) !== envelope.ciphertext ||
        CryptoUtils.Base64.arrayBufferToBase64(tag) !== envelope.tag ||
        CryptoUtils.Base64.arrayBufferToBase64(nonce) !== envelope.nonce ||
        CryptoUtils.Base64.arrayBufferToBase64(storedMac) !== envelope.mac
      ) {
        return null;
      }

      ({ encKey, macKey } = await this.deriveKeys());
      macInput = new Uint8Array(nonce.length + ciphertext.length + tag.length);
      macInput.set(nonce, 0);
      macInput.set(ciphertext, nonce.length);
      macInput.set(tag, nonce.length + ciphertext.length);

      computedMac = await CryptoUtils.Hash.generateBlake3Mac(macInput, macKey);
      const macValid = SecureMemory.constantTimeCompare(computedMac, storedMac);
      if (!macValid) return null;
      
      decrypted = CryptoUtils.PostQuantumAEAD.decrypt(ciphertext, nonce, tag, encKey, AAD_CONTEXT);
      if (decrypted.length === 0 || decrypted.length > MAX_SETTINGS_PLAINTEXT_BYTES) return null;
      const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decrypted));
      if (!deepValidateSettings(parsed)) return null;
      return {
        quality: parsed.quality,
        updatedAt: parsed.updatedAt
      };
    } catch {
      return null;
    } finally {
      if (encKey) SecureMemory.zeroBuffer(encKey);
      if (macKey) SecureMemory.zeroBuffer(macKey);
      if (ciphertext) SecureMemory.zeroBuffer(ciphertext);
      if (tag) SecureMemory.zeroBuffer(tag);
      if (nonce) SecureMemory.zeroBuffer(nonce);
      if (storedMac) SecureMemory.zeroBuffer(storedMac);
      if (macInput) SecureMemory.zeroBuffer(macInput);
      if (computedMac) SecureMemory.zeroBuffer(computedMac);
      if (decrypted) SecureMemory.zeroBuffer(decrypted);
    }
  }

  // Load settings from storage or return default
  private createDefaultSettings(): InternalSettings {
    return {
      quality: DEFAULT_QUALITY,
      updatedAt: Date.now()
    };
  }

  private async loadSettings(): Promise<InternalSettings> {
    if (this.isTransient) return this.createDefaultSettings();

    const stored = await encryptedStorage.getItem(STORAGE_KEYS.SCREEN_SHARING_SETTINGS);
    if (stored === null) return this.createDefaultSettings();
    if (
      typeof stored !== 'string' ||
      stored.length === 0 ||
      stored.length > MAX_SETTINGS_ENVELOPE_BYTES
    ) {
      return this.createDefaultSettings();
    }

    let envelope: unknown;
    try {
      envelope = JSON.parse(stored);
    } catch {
      return this.createDefaultSettings();
    }
    return await this.decryptSettings(envelope) ?? this.createDefaultSettings();
  }

  // Save settings to storage
  private async saveSettings(settings: InternalSettings, generation: number): Promise<void> {
    if (generation !== this.accountGeneration) {
      throw new Error('Screen sharing settings account changed before save');
    }
    if (this.isTransient) return;

    const envelope = await this.encryptSettings(settings);
    if (generation !== this.accountGeneration) {
      throw new Error('Screen sharing settings account changed during encryption');
    }
    const serialized = JSON.stringify(envelope);
    if (serialized.length > MAX_SETTINGS_ENVELOPE_BYTES) {
      throw new Error('Screen sharing settings envelope exceeds limit');
    }
    await encryptedStorage.setItem(STORAGE_KEYS.SCREEN_SHARING_SETTINGS, serialized);
    if (generation !== this.accountGeneration) {
      throw new Error('Screen sharing settings account changed during save');
    }
  }

  // Ensure settings are loaded
  private async ensureSettingsLoaded(): Promise<void> {
    if (this.settings) return;
    if (!this.settingsLoadPromise) {
      const generation = this.accountGeneration;
      let pending: Promise<void>;
      pending = (async () => {
        const loaded = await this.loadSettings();
        if (generation !== this.accountGeneration) {
          throw new Error('Screen sharing settings account changed during load');
        }
        this.settings = loaded;
      })().finally(() => {
        if (this.settingsLoadPromise === pending) this.settingsLoadPromise = null;
      });
      this.settingsLoadPromise = pending;
    }
    await this.settingsLoadPromise;
  }

  private async mutateSettings(
    generation: number,
    mutation: (settings: InternalSettings) => InternalSettings
  ): Promise<void> {
    let queued: Promise<void>;
    queued = this.mutationChain.catch(() => undefined).then(async () => {
      if (generation !== this.accountGeneration) {
        throw new Error('Screen sharing settings account changed before update');
      }
      await this.ensureSettingsLoaded();
      if (generation !== this.accountGeneration || !this.settings) {
        throw new Error('Screen sharing settings account changed during update');
      }
      const current: InternalSettings = {
        quality: this.settings.quality,
        updatedAt: this.settings.updatedAt
      };
      const next = mutation(current);
      if (!deepValidateSettings(next)) throw new Error('Invalid screen sharing settings update');
      await this.saveSettings(next, generation);
      if (generation !== this.accountGeneration) {
        throw new Error('Screen sharing settings account changed while committing update');
      }
      this.settings = next;
      this.notifyListeners();
    });
    this.mutationChain = queued;
    await queued;
  }

  // Enforce rate limit
  private enforceRateLimit(method: string): void {
    const now = Date.now();
    const bucket = this.requestBucket.get(method) ?? { count: 0, resetAt: now + SCREEN_SHARING_RATE_LIMIT_WINDOW_MS };
    if (now > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = now + SCREEN_SHARING_RATE_LIMIT_WINDOW_MS;
    }

    bucket.count += 1;
    if (bucket.count > SCREEN_SHARING_MAX_REQUESTS_PER_WINDOW) {
      console.warn('[screen-sharing] rate-limited', method);
      throw new Error('Screen sharing settings rate limit exceeded');
    }
    this.requestBucket.set(method, bucket);
  }

  // Get current settings
  public async getSettings(): Promise<ScreenSharingSettings> {
    await this.ensureSettingsLoaded();
    return cloneScreenSharingSettings(this.settings!);
  }

  // Set quality
  public async setQuality(quality: string): Promise<void> {
    this.enforceRateLimit('setQuality');
    if (!QUALITY_OPTIONS.includes(quality as any)) {
      throw new Error('Invalid quality preset');
    }

    await this.mutateSettings(this.accountGeneration, settings => ({
      ...settings,
      quality: quality as QualityOption,
      updatedAt: Date.now()
    }));
  }

  // Update settings
  public async updateSettings(newSettings: Partial<ScreenSharingSettings>): Promise<void> {
    this.enforceRateLimit('updateSettings');
    if (!newSettings || typeof newSettings !== 'object' || Array.isArray(newSettings)) {
      throw new Error('Invalid settings update');
    }
    const keys = Object.keys(newSettings);
    if (
      keys.length === 0 ||
      keys.some(key => key !== 'quality')
    ) {
      throw new Error('Invalid settings update');
    }

    const quality = newSettings.quality;
    if (quality !== undefined && !QUALITY_OPTIONS.includes(quality as QualityOption)) {
      throw new Error('Invalid quality preset');
    }

    await this.mutateSettings(this.accountGeneration, settings => ({
      quality: quality ?? settings.quality,
      updatedAt: Date.now()
    }));
  }

  // Reset to defaults
  public async resetToDefaults(): Promise<void> {
    this.enforceRateLimit('resetToDefaults');
    const defaults = this.createDefaultSettings();
    await this.mutateSettings(this.accountGeneration, () => defaults);
  }

  // Subscribe to settings changes
  public subscribe(listener: (settings: ScreenSharingSettings) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  // Notify all listeners
  private notifyListeners(): void {
    if (!this.settings) return;
    const snapshot = cloneScreenSharingSettings(this.settings);
    this.listeners.forEach(listener => {
      try {
        listener(cloneScreenSharingSettings(snapshot));
      } catch (error) {
        console.error('[screen-sharing] listener-error', (error as Error).message);
      }
    });
  }

  // Dispose of the settings manager
  public dispose(): void {
    this.listeners.clear();
    this.resetAccountState();
  }
}

export const screenSharingSettings = ScreenSharingSettingsManager.getInstance();
