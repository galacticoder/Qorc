import { SecureDB } from './secureDB';
import { hasPrototypePollutionKeys } from '../sanitizers';
import { STORAGE_RATE_LIMIT_WINDOW_MS, STORAGE_RATE_LIMIT_MAX_OPS } from '../constants';
import { STORAGE_KEYS, STORAGE_STORES } from './storage-keys';

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
  private initialized = false;
  private initializationPromise: Promise<void>;
  private resolveInitialization: () => void = () => { };
  private rateLimitWindowStart = 0;
  private rateLimitCount = 0;
  private generation = 0;
  private mutationChain: Promise<void> = Promise.resolve();
  private bindingListeners = new Set<() => void>();

  constructor() {
    this.initializationPromise = new Promise((resolve) => {
      this.resolveInitialization = resolve;
    });
  }

  // Initialize storage manager with SecureDB instance
  async initialize(secureDB: SecureDB): Promise<void> {
    if (!secureDB?.isInitialized()) {
      throw new Error('Cannot bind uninitialized encrypted storage');
    }
    this.generation += 1;
    this.secureDB = secureDB;
    this.initialized = true;
    this.mutationChain = Promise.resolve();
    this.rateLimitWindowStart = 0;
    this.rateLimitCount = 0;
    this.resolveInitialization();
    this.notifyBindingChange();
  }

  subscribeBinding(listener: () => void): () => void {
    this.bindingListeners.add(listener);
    return () => { this.bindingListeners.delete(listener); };
  }

  private notifyBindingChange(): void {
    for (const listener of this.bindingListeners) {
      try { listener(); } catch (error) {
        console.error('[EncryptedStorage] Binding listener failed', error);
      }
    }
  }

  // Check if storage manager is initialized
  isInitialized(): boolean {
    return this.initialized && this.secureDB !== null;
  }

  private captureBinding(): { secureDB: SecureDB; generation: number } {
    if (!this.isInitialized() || !this.secureDB) {
      throw new Error('Encrypted storage is not initialized');
    }
    return { secureDB: this.secureDB, generation: this.generation };
  }

  private isCurrentBinding(secureDB: SecureDB, generation: number): boolean {
    return this.initialized && this.secureDB === secureDB && this.generation === generation;
  }

  private async enqueueMutation(operation: () => Promise<void>): Promise<void> {
    const queued = this.mutationChain.catch(() => undefined).then(operation);
    this.mutationChain = queued;
    await queued;
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

    const { secureDB, generation } = this.captureBinding();
    await this.enqueueMutation(async () => {
      if (!this.isCurrentBinding(secureDB, generation)) {
        throw new Error('Encrypted storage account changed before write');
      }
      await secureDB.store(STORAGE_STORES.ENCRYPTED_STORAGE, key, value);
      if (!this.isCurrentBinding(secureDB, generation)) {
        throw new Error('Encrypted storage account changed during write');
      }
    });
  }

  // Retrieve an item from storage
  async getItem(key: string): Promise<any | null> {
    this.enforceRateLimit();
    validateKey(key);

    const { secureDB, generation } = this.captureBinding();
    const value = await secureDB.retrieve(STORAGE_STORES.ENCRYPTED_STORAGE, key);
    if (!this.isCurrentBinding(secureDB, generation)) {
      throw new Error('Encrypted storage account changed during read');
    }

    if (value != null && typeof value === 'object' && hasPrototypePollutionKeys(value)) {
      throw new Error('Encrypted storage value failed structural validation');
    }

    return value;
  }

  // Remove an item from storage
  async removeItem(key: string): Promise<void> {
    this.enforceRateLimit();
    validateKey(key);

    const { secureDB, generation } = this.captureBinding();
    await this.enqueueMutation(async () => {
      if (!this.isCurrentBinding(secureDB, generation)) {
        throw new Error('Encrypted storage account changed before remove');
      }
      await secureDB.delete(STORAGE_STORES.ENCRYPTED_STORAGE, key);
      if (!this.isCurrentBinding(secureDB, generation)) {
        throw new Error('Encrypted storage account changed during remove');
      }
    });
  }

  // Reset the storage manager
  reset(): void {
    this.generation += 1;
    this.secureDB = null;
    this.initialized = false;
    this.mutationChain = Promise.resolve();
    this.resolveInitialization();
    this.initializationPromise = new Promise((resolve) => {
      this.resolveInitialization = resolve;
    });
    this.rateLimitWindowStart = 0;
    this.rateLimitCount = 0;
    this.notifyBindingChange();
  }
  
  // Wait for storage manager to be initialized
  async waitForInitialization(): Promise<void> {
    while (!this.isInitialized()) {
      const pending = this.initializationPromise;
      await pending;
    }
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

class SyncEncryptedStorageAdapter {
  private memoryCache = new Map<string, any>();
  private pendingGets = new Map<string, Promise<any>>();
  private mutationVersions = new Map<string, number>();
  private selfInitialized = false;
  private selfInitializationPromise: Promise<void>;
  private resolveSelfInitialization: () => void = () => { };
  private changeListeners = new Set<() => void>();
  private generation = 0;

  constructor() {
    this.selfInitializationPromise = new Promise((resolve) => {
      this.resolveSelfInitialization = resolve;
    });
  }

  subscribe(listener: () => void): () => void {
    this.changeListeners.add(listener);
    return () => { this.changeListeners.delete(listener); };
  }

  private notifyChange(): void {
    for (const listener of this.changeListeners) {
      try { listener(); } catch (e) { console.error('[SyncEncryptedStorage] listener failed', e); }
    }
  }

  // Initialize the sync adapter
  async initialize(): Promise<void> {
    if (!encryptedStorage.isInitialized()) {
      throw new Error('Encrypted storage is not initialized');
    }

    const generation = ++this.generation;
    this.selfInitialized = false;
    this.resolveSelfInitialization();
    this.selfInitializationPromise = new Promise((resolve) => {
      this.resolveSelfInitialization = resolve;
    });
    
    this.memoryCache.clear();
    this.pendingGets.clear();
    this.mutationVersions.clear();

    const syncAccessKeys = [
      STORAGE_KEYS.CALL_HISTORY,
      STORAGE_KEYS.APP_SETTINGS
    ];
    const loaded = new Map<string, any>();

    for (const key of syncAccessKeys) {
      const value = await encryptedStorage.getItem(key);
      if (generation !== this.generation) {
        throw new Error('Encrypted storage account changed during cache initialization');
      }
      if (value !== null) {
        loaded.set(key, value);
      }
    }

    if (generation !== this.generation || !encryptedStorage.isInitialized()) {
      throw new Error('Encrypted storage account changed during cache initialization');
    }
    this.memoryCache = loaded;
    this.selfInitialized = true;
    this.resolveSelfInitialization();
    this.notifyChange();
  }

  // Get an item from the sync adapter
  getItem(key: string): string | null {
    validateKey(key);
    if (this.memoryCache.has(key)) {
      const value = this.memoryCache.get(key);
      return typeof value === 'string' ? value : JSON.stringify(value);
    }

    if (this.selfInitialized && encryptedStorage.isInitialized()) {
      if (!this.pendingGets.has(key)) {
        const generation = this.generation;
        const mutationVersion = this.mutationVersions.get(key) || 0;
        let promise: Promise<any>;
        promise = encryptedStorage.getItem(key)
          .then(value => {
            if (
              generation !== this.generation ||
              !this.selfInitialized ||
              (this.mutationVersions.get(key) || 0) !== mutationVersion
            ) return null;
            if (value !== null) this.memoryCache.set(key, value);
            return value;
          })
          .catch(error => {
            if (generation === this.generation) {
              console.error('[SyncEncryptedStorage] Failed to load key:', error);
            }
            return null;
          })
          .finally(() => {
            if (this.pendingGets.get(key) === promise) this.pendingGets.delete(key);
          });
        this.pendingGets.set(key, promise);
      }
    }

    return null;
  }

  // Set an item in the sync adapter
  setItem(key: string, value: string): void {
    validateKey(key);
    if (!this.selfInitialized || !encryptedStorage.isInitialized()) {
      throw new Error('Encrypted storage is not initialized');
    }
    const generation = this.generation;
    const version = (this.mutationVersions.get(key) || 0) + 1;
    this.mutationVersions.set(key, version);
    const hadPrevious = this.memoryCache.has(key);
    const previous = this.memoryCache.get(key);
    this.memoryCache.set(key, value);

    encryptedStorage.setItem(key, value).catch(error => {
      if (generation !== this.generation || this.mutationVersions.get(key) !== version) return;
      if (hadPrevious) this.memoryCache.set(key, previous);
      else this.memoryCache.delete(key);
      console.error('[SyncEncryptedStorage] Failed to store key:', error);
      this.notifyChange();
    });
  }

  // Remove an item from the sync adapter
  removeItem(key: string): void {
    validateKey(key);
    if (!this.selfInitialized || !encryptedStorage.isInitialized()) {
      throw new Error('Encrypted storage is not initialized');
    }
    const generation = this.generation;
    const version = (this.mutationVersions.get(key) || 0) + 1;
    this.mutationVersions.set(key, version);
    const hadPrevious = this.memoryCache.has(key);
    const previous = this.memoryCache.get(key);
    this.memoryCache.delete(key);
    encryptedStorage.removeItem(key).catch(error => {
      if (generation !== this.generation || this.mutationVersions.get(key) !== version) return;
      if (hadPrevious) this.memoryCache.set(key, previous);
      console.error('[SyncEncryptedStorage] Failed to remove key:', error);
      this.notifyChange();
    });
  }

  // Reset the sync adapter
  reset(): void {
    this.generation += 1;
    encryptedStorage.reset();
    this.memoryCache.clear();
    this.pendingGets.clear();
    this.mutationVersions.clear();
    this.selfInitialized = false;
    this.resolveSelfInitialization();
    this.selfInitializationPromise = new Promise((resolve) => {
      this.resolveSelfInitialization = resolve;
    });
    this.notifyChange();
  }

  // Wait for the sync adapter to be initialized
  async waitForInitialization(): Promise<void> {
    while (!this.selfInitialized) {
      await encryptedStorage.waitForInitialization();
      if (this.selfInitialized) return;
      const pending = this.selfInitializationPromise;
      await pending;
    }
  }
}

export const syncEncryptedStorage = new SyncEncryptedStorageAdapter();
