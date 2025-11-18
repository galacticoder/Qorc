import { SecureDB } from './secureDB';

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

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

const MAX_QUEUE_SIZE = 100;
const RATE_LIMIT_WINDOW_MS = 1_000;
const RATE_LIMIT_MAX_OPS = 100;

class EncryptedStorageManager {
  private secureDB: SecureDB | null = null;
  private preInitQueue: Array<{ operation: 'set' | 'remove', key: string, value?: any }> = [];
  private initialized = false;
  private rateLimitWindowStart = 0;
  private rateLimitCount = 0;

  async initialize(secureDB: SecureDB): Promise<void> {
    this.secureDB = secureDB;
    this.initialized = true;
    
    // Process queued operations
    const queue = this.preInitQueue.slice(0, MAX_QUEUE_SIZE);
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

  isInitialized(): boolean {
    return this.initialized && this.secureDB !== null;
  }

  async setItem(key: string, value: any): Promise<void> {
    this.enforceRateLimit();
    validateKey(key);
    
    if (value != null && typeof value === 'object') {
      if (hasPrototypePollutionKeys(value)) {
        throw new Error('Value contains prototype pollution keys');
      }
    }
    
    if (!this.isInitialized()) {
      if (this.preInitQueue.length >= MAX_QUEUE_SIZE) {
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

  async removeItem(key: string): Promise<void> {
    this.enforceRateLimit();
    validateKey(key);
    
    if (!this.isInitialized()) {
      if (this.preInitQueue.length >= MAX_QUEUE_SIZE) {
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

  reset(): void {
    this.secureDB = null;
    this.initialized = false;
    this.preInitQueue = [];
    this.rateLimitWindowStart = 0;
    this.rateLimitCount = 0;
  }

  private enforceRateLimit(): void {
    const now = Date.now();
    if (now - this.rateLimitWindowStart > RATE_LIMIT_WINDOW_MS) {
      this.rateLimitWindowStart = now;
      this.rateLimitCount = 0;
    }
    
    this.rateLimitCount += 1;
    if (this.rateLimitCount > RATE_LIMIT_MAX_OPS) {
      throw new Error('Storage operation rate limit exceeded');
    }
  }
}

export const encryptedStorage = new EncryptedStorageManager();

class SyncEncryptedStorageAdapter {
  private memoryCache = new Map<string, any>();
  private pendingGets = new Map<string, Promise<any>>();

  async initialize(): Promise<void> {
    if (!encryptedStorage.isInitialized()) {
      return;
    }

    const syncAccessKeys = [
      'last_authenticated_username',
      'securechat_server_pin_v2'
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
  }

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

  setItem(key: string, value: string): void {
    this.memoryCache.set(key, value);
    
    encryptedStorage.setItem(key, value).catch(error => {
      console.error('[SyncEncryptedStorage] Failed to store key:', error);
    });
  }

  removeItem(key: string): void {
    this.memoryCache.delete(key);
    encryptedStorage.removeItem(key).catch(error => {
      console.error('[SyncEncryptedStorage] Failed to remove key:', error);
    });
  }

  reset(): void {
    this.memoryCache.clear();
    this.pendingGets.clear();
  }
}

export const syncEncryptedStorage = new SyncEncryptedStorageAdapter();
