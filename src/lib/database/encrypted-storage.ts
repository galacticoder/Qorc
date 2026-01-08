import { SecureDB } from './secureDB';
import { hasPrototypePollutionKeys } from '../sanitizers';
import { STORAGE_MAX_QUEUE_SIZE, STORAGE_RATE_LIMIT_WINDOW_MS, STORAGE_RATE_LIMIT_MAX_OPS } from '../constants';

const validateKey = (key: string): void => {
  if (typeof key !== 'string' || key.length === 0 || key.length > 256) {
    throw new Error('Invalid storage key');
  }
  if (/[\x00-\x1F\x7F]/.test(key)) {
    throw new Error('Storage key contains invalid control characters');
  }
  if (['__proto__', 'constructor', 'prototype'].includes(key)) {
    throw new Error('Storage key is a reserved identifier');
  }
};

class EncryptedStorageManager {
  private secureDB: SecureDB | null = null;
  private preInitQueue: Array<{ operation: 'set' | 'remove', key: string, value?: any }> = [];
  private initialized = false;
  private initializationPromise: Promise<void>;
  private resolveInitialization: () => void = () => { };
  private rateLimitWindowStart = 0;
  private rateLimitCount = 0;

  constructor() {
    this.initializationPromise = new Promise((resolve) => {
      this.resolveInitialization = resolve;
    });
  }

  // Initialize storage manager with SecureDB instance
  async initialize(secureDB: SecureDB): Promise<void> {
    this.secureDB = secureDB;
    this.initialized = true;
    this.resolveInitialization();

    // Process queued operations
    const queue = this.preInitQueue.slice(0, STORAGE_MAX_QUEUE_SIZE);
    this.preInitQueue = [];

    for (const op of queue) {
      try {
        if (op.operation === 'set') {
          await this.setItem(op.key, op.value);
        } else if (op.operation === 'remove') {
          await this.removeItem(op.key);
        }
      } catch (_error) {
        console.error('[EncryptedStorage] Failed to process queued operation:', _error);
      }
    }
  }

  // Check if storage manager is initialized
  isInitialized(): boolean {
    return this.initialized && this.secureDB !== null;
  }

  // Set an item in storage
  async setItem(key: string, value: any): Promise<void> {
    this.enforceRateLimit();
    validateKey(key);

    if (value != null && typeof value === 'object') {
      if (hasPrototypePollutionKeys(value)) {
        throw new Error('Value contains prototype pollution keys');
      }
    }

    if (!this.isInitialized()) {
      if (this.preInitQueue.length >= STORAGE_MAX_QUEUE_SIZE) {
        throw new Error('Pre-initialization queue is full');
      }
      this.preInitQueue.push({ operation: 'set', key, value });
      return;
    }

    try {
      await this.secureDB!.store('encrypted_storage', key, value);
    } catch (_error) {
      console.error('[EncryptedStorage] Failed to store item:', _error);
      throw _error;
    }
  }

  // Retrieve an item from storage
  async getItem(key: string): Promise<any | null> {
    this.enforceRateLimit();
    validateKey(key);

    if (!this.isInitialized()) {
      return null;
    }

    try {
      const value = await this.secureDB!.retrieve('encrypted_storage', key);

      if (value != null && typeof value === 'object') {
        if (hasPrototypePollutionKeys(value)) {
          console.error('[EncryptedStorage] Retrieved value contains prototype pollution keys');
          return null;
        }
      }

      return value;
    } catch (_error) {
      console.error('[EncryptedStorage] Failed to retrieve item:', _error);
      return null;
    }
  }

  // Remove an item from storage
  async removeItem(key: string): Promise<void> {
    this.enforceRateLimit();
    validateKey(key);

    if (!this.isInitialized()) {
      if (this.preInitQueue.length >= STORAGE_MAX_QUEUE_SIZE) {
        throw new Error('Pre-initialization queue is full');
      }
      this.preInitQueue.push({ operation: 'remove', key });
      return;
    }

    try {
      await this.secureDB!.delete('encrypted_storage', key);
    } catch (_error) {
      console.error('[EncryptedStorage] Failed to remove item:', _error);
      throw _error;
    }
  }

  // Clear all items from storage
  async clear(): Promise<void> {
    if (!this.isInitialized()) {
      this.preInitQueue = [];
      return;
    }

    try {
      await this.secureDB!.store('encrypted_storage', '_cleared_at', Date.now());
    } catch (_error) {
      console.error('[EncryptedStorage] Failed to clear storage:', _error);
      throw _error;
    }
  }

  // Reset the storage manager
  reset(): void {
    this.secureDB = null;
    this.initialized = false;
    this.initializationPromise = new Promise((resolve) => {
      this.resolveInitialization = resolve;
    });
    this.preInitQueue = [];
    this.rateLimitWindowStart = 0;
    this.rateLimitCount = 0;
  }
  
  // Wait for storage manager to be initialized
  async waitForInitialization(): Promise<void> {
    if (this.initialized) return;
    return this.initializationPromise;
  }

  private enforceRateLimit(): void {
    const now = Date.now();
    if (now - this.rateLimitWindowStart > STORAGE_RATE_LIMIT_WINDOW_MS) {
      this.rateLimitWindowStart = now;
      this.rateLimitCount = 0;
    }

    this.rateLimitCount += 1;
    if (this.rateLimitCount > STORAGE_RATE_LIMIT_MAX_OPS) {
      throw new Error('Storage operation rate limit exceeded');
    }
  }

}

export const encryptedStorage = new EncryptedStorageManager();

// Sync adapter for SvelteKit's storage API
class SyncEncryptedStorageAdapter {
  private memoryCache = new Map<string, any>();
  private pendingGets = new Map<string, Promise<any>>();
  private selfInitialized = false;
  private selfInitializationPromise: Promise<void>;
  private resolveSelfInitialization: () => void = () => { };

  constructor() {
    this.selfInitializationPromise = new Promise((resolve) => {
      this.resolveSelfInitialization = resolve;
    });
  }

  // Initialize the sync adapter
  async initialize(): Promise<void> {
    if (!encryptedStorage.isInitialized()) {
      return;
    }

    const syncAccessKeys = [
      'last_authenticated_username',
      'qorchat_server_pin_v2',
      'call_history_v1',
      'app_settings_v1',
      'offlineQueueDeviceId',
      'tor_enabled'
    ];

    for (const key of syncAccessKeys) {
      try {
        const value = await encryptedStorage.getItem(key);
        if (value !== null) {
          this.memoryCache.set(key, value);
        }
      } catch (_error) {
        console.error('[SyncEncryptedStorage] Failed to pre-load key:', _error);
      }
    }

    this.selfInitialized = true;
    this.resolveSelfInitialization();
  }

  // Get an item from the sync adapter
  getItem(key: string): string | null {
    if (this.memoryCache.has(key)) {
      const value = this.memoryCache.get(key);
      return typeof value === 'string' ? value : JSON.stringify(value);
    }

    if (encryptedStorage.isInitialized()) {
      if (!this.pendingGets.has(key)) {
        const promise = encryptedStorage.getItem(key).then(value => {
          if (value !== null) {
            this.memoryCache.set(key, value);
          }
          this.pendingGets.delete(key);
          return value;
        }).catch(error => {
          console.error('[SyncEncryptedStorage] Failed to load key:', error);
          this.pendingGets.delete(key);
          return null;
        });
        this.pendingGets.set(key, promise);
      }
    }

    return null;
  }

  // Set an item in the sync adapter
  setItem(key: string, value: string): void {
    this.memoryCache.set(key, value);

    encryptedStorage.setItem(key, value).catch(error => {
      console.error('[SyncEncryptedStorage] Failed to store key:', error);
    });
  }

  // Remove an item from the sync adapter
  removeItem(key: string): void {
    this.memoryCache.delete(key);
    encryptedStorage.removeItem(key).catch(error => {
      console.error('[SyncEncryptedStorage] Failed to remove key:', error);
    });
  }

  // Reset the sync adapter
  reset(): void {
    this.memoryCache.clear();
    this.pendingGets.clear();
    this.selfInitialized = false;
    this.selfInitializationPromise = new Promise((resolve) => {
      this.resolveSelfInitialization = resolve;
    });
  }

  // Wait for the sync adapter to be initialized
  async waitForInitialization(): Promise<void> {
    await encryptedStorage.waitForInitialization();
    if (this.selfInitialized) return;
    return this.selfInitializationPromise;
  }
}

export const syncEncryptedStorage = new SyncEncryptedStorageAdapter();
