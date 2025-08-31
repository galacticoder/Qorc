import { CryptoUtils } from "./unified-crypto";

interface EphemeralConfig {
  enabled: boolean;
  defaultTTL: number; // Time to live in milliseconds
  maxTTL: number; // Maximum TTL allowed
  cleanupInterval: number; // Cleanup interval in milliseconds
}

interface EphemeralData {
  data: any;
  createdAt: number;
  expiresAt: number;
  ttl: number;
  autoDelete: boolean;
}

export class SecureDB {
  private dbName: string;
  private username: string;
  private encryptionKey: CryptoKey | null = null;
  // In-memory fallback when IndexedDB isn't available (e.g., dev sandbox issues)
  private memoryMode: boolean = false;
  private memoryStore = new Map<string, Uint8Array>();
  private readonly MAX_MEMORY_ENTRIES = 1000; // SECURITY: Limit memory usage
  private ephemeralConfig: EphemeralConfig;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(username: string, ephemeralConfig?: Partial<EphemeralConfig>) {
    this.username = username;
    this.dbName = `securechat_${username}_db`;
    this.ephemeralConfig = {
      enabled: true,
      defaultTTL: 24 * 60 * 60 * 1000, // 24 hours
      maxTTL: 7 * 24 * 60 * 60 * 1000, // 7 days
      cleanupInterval: 60 * 60 * 1000, // 1 hour
      ...ephemeralConfig
    };
  }

  async initializeWithKey(key: CryptoKey): Promise<void> {
    this.encryptionKey = key;

    // Start ephemeral cleanup if enabled
    if (this.ephemeralConfig.enabled) {
      this.startEphemeralCleanup();
    }

    console.log("[SecureDB] SecureDB initialized with ephemeral support");
  }

  private async encryptData(data: any): Promise<Uint8Array> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");

    // Export the AES key to raw bytes for ChaCha20
    const keyBytes = await crypto.subtle.exportKey('raw', this.encryptionKey);
    const key = new Uint8Array(keyBytes);

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));

    // Use XChaCha20-Poly1305 for better security and nonce reuse resistance
    const { nonce, ciphertext } = CryptoUtils.XChaCha20Poly1305.encryptWithNonce(key, dataBuffer);

    // Combine nonce and ciphertext
    const combined = new Uint8Array(nonce.length + ciphertext.length);
    combined.set(nonce);
    combined.set(ciphertext, nonce.length);
    return combined;
  }

  private async decryptData(encryptedData: Uint8Array): Promise<any> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");

    // Export the AES key to raw bytes for ChaCha20
    const keyBytes = await crypto.subtle.exportKey('raw', this.encryptionKey);
    const key = new Uint8Array(keyBytes);

    // XChaCha20-Poly1305 uses 24-byte nonces
    const nonceLength = 24;
    const nonce = encryptedData.slice(0, nonceLength);
    const ciphertext = encryptedData.slice(nonceLength);

    // Decrypt using XChaCha20-Poly1305
    const decrypted = CryptoUtils.XChaCha20Poly1305.decryptWithNonce(key, nonce, ciphertext);

    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  private openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("data")) {
          db.createObjectStore("data");
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async saveMessages(messages: any[]): Promise<void> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");
    const encrypted = await this.encryptData(messages);
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        store.put(encrypted, "messages");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      // Fallback to memory mode
      console.warn('[SecureDB] IndexedDB unavailable; using in-memory storage for messages');
      this.memoryMode = true;
      this.memoryStore.set('messages', encrypted);
    }
  }

  async loadMessages(): Promise<any[]> {
    if (this.memoryMode) {
      const buf = this.memoryStore.get('messages');
      if (!buf) return [];
      return await this.decryptData(buf);
    }
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("data", "readonly");
      const store = tx.objectStore("data");
      const request = store.get("messages");

      request.onsuccess = async () => {
        if (!request.result) return resolve([]);
        try {
          const data = await this.decryptData(request.result);
          resolve(data);
        } catch (err) {
          reject(err);
        }
      };

      request.onerror = () => reject(request.error);
    });
  }

  async saveUsers(users: any[]): Promise<void> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");
    const encrypted = await this.encryptData(users);
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        store.put(encrypted, "users");
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      console.warn('[SecureDB] IndexedDB unavailable; using in-memory storage for users');
      this.memoryMode = true;
      this.memoryStore.set('users', encrypted);
    }
  }

  async loadUsers(): Promise<any[]> {
    if (this.memoryMode) {
      const buf = this.memoryStore.get('users');
      if (!buf) return [];
      return await this.decryptData(buf);
    }
    const db = await this.openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("data", "readonly");
      const store = tx.objectStore("data");
      const request = store.get("users");

      request.onsuccess = async () => {
        if (!request.result) return resolve([]);
        try {
          const data = await this.decryptData(request.result);
          resolve(data);
        } catch (err) {
          reject(err);
        }
      };

      request.onerror = () => reject(request.error);
    });
  }

  /**
   * Store ephemeral data with automatic expiration
   */
  async storeEphemeral(
    storeName: string,
    key: string,
    data: any,
    ttl?: number,
    autoDelete: boolean = true
  ): Promise<void> {
    if (!this.ephemeralConfig.enabled) {
      return this.store(storeName, key, data);
    }

    const actualTTL = Math.min(ttl || this.ephemeralConfig.defaultTTL, this.ephemeralConfig.maxTTL);
    const now = Date.now();

    const ephemeralData: EphemeralData = {
      data,
      createdAt: now,
      expiresAt: now + actualTTL,
      ttl: actualTTL,
      autoDelete
    };

    await this.store(storeName, key, ephemeralData);
    console.log(`[SecureDB] Stored ephemeral data: ${key} (expires in ${actualTTL}ms)`);
  }

  /**
   * Retrieve ephemeral data, checking expiration
   */
  async retrieveEphemeral(storeName: string, key: string): Promise<any | null> {
    if (!this.ephemeralConfig.enabled) {
      return this.retrieve(storeName, key);
    }

    const ephemeralData = await this.retrieve(storeName, key) as EphemeralData | null;
    if (!ephemeralData) {
      return null;
    }

    // Check if this is ephemeral data or legacy data
    if (!ephemeralData.expiresAt) {
      return ephemeralData; // Legacy data, return as-is
    }

    // Check expiration
    if (Date.now() > ephemeralData.expiresAt) {
      console.log(`[SecureDB] Ephemeral data expired: ${key}`);
      if (ephemeralData.autoDelete) {
        await this.delete(storeName, key);
      }
      return null;
    }

    return ephemeralData.data;
  }

  /**
   * Start ephemeral cleanup process
   */
  private startEphemeralCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    this.cleanupInterval = setInterval(async () => {
      await this.cleanupExpiredData();
    }, this.ephemeralConfig.cleanupInterval);

    console.log(`[SecureDB] Started ephemeral cleanup (interval: ${this.ephemeralConfig.cleanupInterval}ms)`);
  }

  /**
   * Clean up expired ephemeral data
   */
  private async cleanupExpiredData(): Promise<void> {
    try {
      const now = Date.now();
      let cleanedCount = 0;

      if (this.memoryMode) {
        // Clean up memory store
        for (const [key, encryptedData] of this.memoryStore.entries()) {
          try {
            const decryptedData = await this.decryptData(encryptedData) as EphemeralData;
            if (decryptedData.expiresAt && now > decryptedData.expiresAt && decryptedData.autoDelete) {
              this.memoryStore.delete(key);
              cleanedCount++;
            }
          } catch (error) {
            // Skip invalid data
          }
        }
      }

      if (cleanedCount > 0) {
        console.log(`[SecureDB] Cleaned up ${cleanedCount} expired ephemeral items`);
      }
    } catch (error) {
      console.error('[SecureDB] Error during ephemeral cleanup:', error);
    }
  }

  async clearDatabase(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(this.dbName);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
}
