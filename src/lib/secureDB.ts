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
  private readonly EPHEMERAL_PREFIX = 'ephemeral:';
  private ephemeralConfig: EphemeralConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  /**
   * Create a safe composite key that avoids delimiter collisions
   */
  private createCompositeKey(storeName: string, key: string): string {
    // Use JSON encoding to safely handle any characters in storeName or key
    return JSON.stringify([storeName, key]);
  }

  /**
   * Parse a composite key back to its components
   */
  private parseCompositeKey(compositeKey: string): [string, string] {
    try {
      const parsed = JSON.parse(compositeKey);
      if (Array.isArray(parsed) && parsed.length === 2) {
        return [parsed[0], parsed[1]];
      }
    } catch (error) {
      // Handle legacy keys that might not be JSON encoded
      const colonIndex = compositeKey.indexOf(':');
      if (colonIndex !== -1) {
        return [compositeKey.substring(0, colonIndex), compositeKey.substring(colonIndex + 1)];
      }
    }
    throw new Error('Invalid composite key format: [REDACTED]');
  }

  /**
   * Smart memory eviction policy that prioritizes keeping non-ephemeral data
   */
  private async smartMemoryEviction(): Promise<void> {
    const now = Date.now();
    let removedCount = 0;
    const targetRemoval = Math.floor(this.MAX_MEMORY_ENTRIES * 0.1); // Remove 10%
    
    // Phase 1: Remove expired ephemeral items
    const expiredKeys: string[] = [];
    const ephemeralKeys: string[] = [];
    const nonEphemeralKeys: string[] = [];
    
    for (const [key, encryptedData] of this.memoryStore.entries()) {
      try {
        const [storeName] = this.parseCompositeKey(key);
        if (storeName.startsWith(this.EPHEMERAL_PREFIX)) {
          // This is ephemeral data
          ephemeralKeys.push(key);
          try {
            const decryptedData = await this.decryptData(encryptedData) as EphemeralData;
            if (decryptedData.expiresAt && now > decryptedData.expiresAt && decryptedData.autoDelete) {
              expiredKeys.push(key);
            }
          } catch (error) {
            // If we can't decrypt, treat as candidate for removal
            expiredKeys.push(key);
          }
        } else {
          nonEphemeralKeys.push(key);
        }
      } catch (error) {
        // Handle legacy keys - assume non-ephemeral for safety
        if (key.startsWith(this.EPHEMERAL_PREFIX)) {
          ephemeralKeys.push(key);
        } else {
          nonEphemeralKeys.push(key);
        }
      }
    }
    
    // Remove expired ephemeral items first
    for (const key of expiredKeys) {
      if (removedCount >= targetRemoval) break;
      this.memoryStore.delete(key);
      removedCount++;
    }
    
    // Phase 2: If still need space, remove oldest non-expired ephemeral items
    if (removedCount < targetRemoval) {
      const nonExpiredEphemeral = ephemeralKeys.filter(k => !expiredKeys.includes(k));
      for (const key of nonExpiredEphemeral) {
        if (removedCount >= targetRemoval) break;
        this.memoryStore.delete(key);
        removedCount++;
      }
    }
    
    // Phase 3: Last resort - remove oldest non-ephemeral items
    if (removedCount < targetRemoval) {
      for (const key of nonEphemeralKeys) {
        if (removedCount >= targetRemoval) break;
        this.memoryStore.delete(key);
        removedCount++;
      }
    }
    
    console.warn(`[SecureDB] Memory cap reached, smart eviction removed ${removedCount} entries (${expiredKeys.length} expired, ${removedCount - expiredKeys.length} others)`);
  }

  constructor(username: string, ephemeralConfig?: Partial<EphemeralConfig>) {
    this.username = username;
    // Use a stable per-user database name to ensure consistent loading across sessions
    this.dbName = SecureDB.getStableDbNameForUsername(username);
    console.log(`[SecureDB] Using database (stable): ${this.dbName}`);
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

    // Attempt one-time migration from legacy session-based DB names
    await this.migrateFromLegacyDatabases();

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

  private static getStableDbNameForUsername(username: string): string {
    const sanitized = SecureDB.sanitizeIdentifier(username);
    return `securechat_${sanitized}_db`;
  }

  private static sanitizeIdentifier(value: string): string {
    // Replace anything other than alphanumerics, dash, underscore with underscore
    return (value || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  private openSpecificDB(name: string): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
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

  /**
   * Migrate from legacy session-based DB names to a stable per-username DB.
   * Legacy format: securechat_${username}_${randomSession}_db
   */
  private async migrateFromLegacyDatabases(): Promise<void> {
    try {
      const idbAny: any = indexedDB as any;
      if (!idbAny || typeof idbAny.databases !== 'function') {
        return; // No listing API available; skip best-effort migration
      }

      const databases: Array<{ name?: string | null; version?: number }>|undefined = await idbAny.databases();
      if (!databases || databases.length === 0) return;

      const stableName = this.dbName;
      const sanitizedUsername = SecureDB.sanitizeIdentifier(this.username);
      const prefix = `securechat_${sanitizedUsername}_`;

      // Identify legacy DBs for this username (exclude the stable target name)
      const legacy = databases
        .map(d => d.name)
        .filter((n): n is string => !!n)
        .filter(n => n.startsWith(prefix) && n.endsWith('_db') && n !== stableName);

      if (legacy.length === 0) return;

      console.log('[SecureDB] Found legacy databases to migrate:', legacy);

      let aggregatedMessages: any[] = [];
      let aggregatedUsers: any[] = [];

      for (const legacyName of legacy) {
        try {
          const legacyDb = await this.openSpecificDB(legacyName);

          // Helper to read raw encrypted value by key
          const readRaw = (key: string) => new Promise<Uint8Array | null>((resolve, reject) => {
            const tx = legacyDb.transaction('data', 'readonly');
            const store = tx.objectStore('data');
            const req = store.get(key);
            req.onsuccess = () => resolve((req.result as Uint8Array) || null);
            req.onerror = () => reject(req.error);
          });

          const rawMessages = await readRaw('messages').catch(() => null);
          if (rawMessages) {
            try {
              const msgs = await this.decryptData(rawMessages);
              if (Array.isArray(msgs)) {
                aggregatedMessages = [...aggregatedMessages, ...msgs];
              }
            } catch {}
          }

          const rawUsers = await readRaw('users').catch(() => null);
          if (rawUsers) {
            try {
              const usrs = await this.decryptData(rawUsers);
              if (Array.isArray(usrs)) {
                aggregatedUsers = [...aggregatedUsers, ...usrs];
              }
            } catch {}
          }

          try { legacyDb.close?.(); } catch {}
        } catch (err) {
          console.warn('[SecureDB] Failed to read legacy DB during migration:', err);
        }
      }

      // Merge into the stable DB if we have anything
      if (aggregatedMessages.length > 0) {
        try {
          const existing = await this.loadMessages().catch(() => []);
          const merged = this.deduplicateMessages([...existing, ...aggregatedMessages]);
          await this.saveMessages(merged);
          console.log(`[SecureDB] Migrated ${aggregatedMessages.length} messages into stable DB`);
        } catch (err) {
          console.warn('[SecureDB] Failed to migrate messages into stable DB:', err);
        }
      }

      if (aggregatedUsers.length > 0) {
        try {
          const existingUsers = await this.loadUsers().catch(() => []);
          // Users array is small; simple merge by username if available
          const seen = new Set<string>();
          const mergedUsers = [...existingUsers, ...aggregatedUsers].filter((u: any) => {
            const key = typeof u === 'object' && u && (u.username || u.id || JSON.stringify(u));
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          });
          await this.saveUsers(mergedUsers);
          console.log(`[SecureDB] Migrated ${aggregatedUsers.length} users into stable DB`);
        } catch (err) {
          console.warn('[SecureDB] Failed to migrate users into stable DB:', err);
        }
      }

      // Cleanup legacy DBs now that migration is complete
      for (const legacyName of legacy) {
        try {
          await new Promise<void>((resolve, reject) => {
            const del = indexedDB.deleteDatabase(legacyName);
            del.onsuccess = () => resolve();
            del.onerror = () => reject(del.error);
            del.onblocked = () => {
              console.warn('[SecureDB] Deletion of legacy DB is blocked (will be removed on next run):', legacyName);
              resolve();
            };
          });
          console.log('[SecureDB] Deleted legacy DB:', legacyName);
        } catch (err) {
          console.warn('[SecureDB] Failed to delete legacy DB:', legacyName, err);
        }
      }
    } catch (error) {
      // Best-effort migration; never block initialization
      console.warn('[SecureDB] Legacy DB migration skipped or failed:', error);
    }
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
    
    // Deduplicate messages before saving
    const deduplicatedMessages = this.deduplicateMessages(messages);
    
    const encrypted = await this.encryptData(deduplicatedMessages);
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
      if (!buf) {
        console.log('[SecureDB] No messages found in memory storage');
        return [];
      }
      try {
        const messages = await this.decryptData(buf);
        console.log(`[SecureDB] Loaded ${messages.length} messages from memory storage`);
        return messages;
      } catch (error) {
        console.error('[SecureDB] Failed to decrypt messages from memory storage:', error);
        return [];
      }
    }
    
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readonly");
        const store = tx.objectStore("data");
        const request = store.get("messages");

        request.onsuccess = async () => {
          if (!request.result) {
            console.log('[SecureDB] No messages found in IndexedDB');
            return resolve([]);
          }
          try {
            const data = await this.decryptData(request.result);
            console.log(`[SecureDB] Loaded ${data.length} messages from IndexedDB`);
            resolve(data);
          } catch (err) {
            console.error('[SecureDB] Failed to decrypt messages from IndexedDB:', err);
            reject(err);
          }
        };

        request.onerror = () => {
          console.error('[SecureDB] Error loading messages from IndexedDB:', request.error);
          reject(request.error);
        };
        
        tx.onerror = () => {
          console.error('[SecureDB] Transaction failed while loading messages:', tx.error);
          reject(tx.error);
        };
      });
    } catch (error) {
      console.error('[SecureDB] Error opening database for message load:', error);
      // Try memory fallback
      console.log('[SecureDB] Attempting memory fallback for message load');
      this.memoryMode = true;
      return this.loadMessages(); // Recursively call with memory mode
    }
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

    // Validate and clamp TTL to avoid negative/NaN expirations
    let validatedTTL = ttl || this.ephemeralConfig.defaultTTL;
    if (typeof validatedTTL !== 'number' || isNaN(validatedTTL) || validatedTTL <= 0) {
      console.warn(`[SecureDB] Invalid TTL ${validatedTTL}, using default: ${this.ephemeralConfig.defaultTTL}`);
      validatedTTL = this.ephemeralConfig.defaultTTL;
    }
    
    const actualTTL = Math.min(validatedTTL, this.ephemeralConfig.maxTTL);
    const now = Date.now();

    // Ensure expiration time is valid
    const expiresAt = now + actualTTL;
    if (expiresAt <= now || !Number.isFinite(expiresAt)) {
      throw new Error('[SecureDB] Invalid expiration time calculated: [REDACTED]');
    }

    const ephemeralData: EphemeralData = {
      data,
      createdAt: now,
      expiresAt,
      ttl: actualTTL,
      autoDelete
    };

    // Use ephemeral prefix for efficient cleanup scanning
    await this.storeWithPrefix(this.EPHEMERAL_PREFIX + storeName, key, ephemeralData);
    console.log(`[SecureDB] Stored ephemeral data: ${key} (expires in ${actualTTL}ms)`);
  }

  /**
   * Retrieve ephemeral data, checking expiration
   */
  async retrieveEphemeral(storeName: string, key: string): Promise<any | null> {
    if (!this.ephemeralConfig.enabled) {
      return this.retrieve(storeName, key);
    }

    const ephemeralData = await this.retrieveWithPrefix(this.EPHEMERAL_PREFIX + storeName, key) as EphemeralData | null;
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
        await this.deleteWithPrefix(this.EPHEMERAL_PREFIX + storeName, key);
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
        // Clean up memory store - collect ephemeral keys first
        const ephemeralEntries: Array<{key: string, encryptedData: Uint8Array}> = [];
        
        for (const [key, encryptedData] of this.memoryStore.entries()) {
          try {
            const [storeName] = this.parseCompositeKey(key);
            if (storeName.startsWith(this.EPHEMERAL_PREFIX)) {
              ephemeralEntries.push({key, encryptedData});
            }
          } catch (error) {
            // Handle legacy keys
            if (key.startsWith(this.EPHEMERAL_PREFIX)) {
              ephemeralEntries.push({key, encryptedData});
            }
          }
        }
        
        // Process ephemeral entries for expiration
        for (const {key, encryptedData} of ephemeralEntries) {
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
      } else {
        // Clean up IndexedDB store - only scan ephemeral prefixed keys
        const db = await this.openDB();
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        
        // Use cursor with key range to only iterate through ephemeral keys
        // With JSON encoding, ephemeral keys have structure ["ephemeral:storeName", "key"]
        // Use proper composite bounds to ensure all ephemeral keys are included
        const ephemeralStart = JSON.stringify([this.EPHEMERAL_PREFIX, '']);
        const ephemeralEnd = JSON.stringify([this.EPHEMERAL_PREFIX + '\uFFFF', '']);
        const ephemeralRange = IDBKeyRange.bound(
          ephemeralStart,
          ephemeralEnd,
          false,
          true
        );
        const cursorRequest = store.openCursor(ephemeralRange);
        
        // Collect encrypted data synchronously to avoid transaction inactivation
        const candidateItems: Array<{key: string, encryptedData: Uint8Array}> = [];
        
        await new Promise<void>((resolve, reject) => {
          cursorRequest.onsuccess = (event) => {
            const cursor = (event.target as IDBRequest).result;
            if (cursor) {
              // Collect data synchronously - no async operations here
              candidateItems.push({
                key: cursor.key as string,
                encryptedData: cursor.value as Uint8Array
              });
              cursor.continue();
            } else {
              // Cursor iteration complete
              resolve();
            }
          };
          
          cursorRequest.onerror = () => {
            reject(cursorRequest.error);
          };
        });
        
        // Now decrypt and check expiration outside the cursor (async safe)
        const keysToDelete: string[] = [];
        for (const {key, encryptedData} of candidateItems) {
          try {
            const decryptedData = await this.decryptData(encryptedData) as EphemeralData;
            if (decryptedData.expiresAt && now > decryptedData.expiresAt && decryptedData.autoDelete) {
              keysToDelete.push(key);
            }
          } catch (error) {
            // Skip invalid data
          }
        }
        
        // Delete expired items using the correct keys in a single transaction
        if (keysToDelete.length > 0) {
          const deleteTx = db.transaction("data", "readwrite");
          const deleteStore = deleteTx.objectStore("data");
          
          for (const key of keysToDelete) {
            // Safely parse composite key and delete directly
            try {
              // For cleanup, we can delete the key directly since it's already the composite key
              deleteStore.delete(key);
            } catch (error) {
              console.warn('[SecureDB] Failed to delete key during cleanup: [REDACTED]', error);
            }
          }
          
          await new Promise<void>((resolve, reject) => {
            deleteTx.oncomplete = () => {
              cleanedCount += keysToDelete.length;
              resolve();
            };
            deleteTx.onerror = () => reject(deleteTx.error);
          });
        }
      }

      if (cleanedCount > 0) {
        console.log(`[SecureDB] Cleaned up ${cleanedCount} expired ephemeral entries`);
      }
    } catch (error) {
      console.error('[SecureDB] Error during ephemeral cleanup:', error);
    }
  }

  // Deduplicate messages by ID or serialized content to prevent duplicates
  private deduplicateMessages(messages: any[]): any[] {
    const seen = new Set<string>();
    return messages.filter(msg => {
      if (!msg) return false;
      
      // Use message ID if available, otherwise use serialized content as identifier
      const identifier = msg.id || JSON.stringify(msg);
      
      if (seen.has(identifier)) {
        console.log(`[SecureDB] Skipping duplicate message: ${msg.id || 'content-based'}`);
        return false;
      }
      seen.add(identifier);
      return true;
    });
  }

  // Merge new messages with existing ones, avoiding duplicates
  async appendMessages(newMessages: any[]): Promise<void> {
    try {
      const existingMessages = await this.loadMessages();
      // Merge and sort chronologically before saving (deduplication happens in saveMessages)
      const allMessages = [...existingMessages, ...newMessages].sort((a, b) => {
        const timeA = a.timestamp || 0;
        const timeB = b.timestamp || 0;
        return timeA - timeB;
      });
      await this.saveMessages(allMessages); // deduplication happens in saveMessages
    } catch (error) {
      console.error('[SecureDB] Failed to append messages:', error);
      throw error;
    }
  }

  // Clear all stored data (useful for logout)
  async clearAllData(): Promise<void> {
    if (this.memoryMode) {
      this.memoryStore.clear();
      console.log('[SecureDB] Cleared all data from memory storage');
      return;
    }

    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        const clearRequest = store.clear();

        clearRequest.onsuccess = () => {
          console.log('[SecureDB] Cleared all data from IndexedDB');
          resolve();
        };
        clearRequest.onerror = () => {
          console.error('[SecureDB] Failed to clear IndexedDB:', clearRequest.error);
          reject(clearRequest.error);
        };
      });
    } catch (error) {
      console.error('[SecureDB] Error clearing database:', error);
      throw error;
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

  /**
   * Generic store method for saving data to a specific store
   */
  async store(storeName: string, key: string, data: any): Promise<void> {
    return this.storeWithPrefix(storeName, key, data);
  }

  /**
   * Store method with prefix support for efficient indexing
   */
  private async storeWithPrefix(storeName: string, key: string, data: any): Promise<void> {
    if (!this.encryptionKey) throw new Error("Encryption key not initialized");
    
    const encrypted = await this.encryptData(data);
    const storeKey = this.createCompositeKey(storeName, key);
    
    if (this.memoryMode) {
      // Enforce memory cap in memory mode with smart eviction policy
      if (this.memoryStore.size >= this.MAX_MEMORY_ENTRIES) {
        await this.smartMemoryEviction();
      }
      this.memoryStore.set(storeKey, encrypted);
      return;
    }

    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        store.put(encrypted, storeKey);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      console.warn('[SecureDB] IndexedDB unavailable; using in-memory storage for [REDACTED]');
      this.memoryMode = true;
      this.memoryStore.set(storeKey, encrypted);
    }
  }

  /**
   * Generic retrieve method for loading data from a specific store
   */
  async retrieve(storeName: string, key: string): Promise<any | null> {
    return this.retrieveWithPrefix(storeName, key);
  }

  /**
   * Retrieve method with prefix support
   */
  private async retrieveWithPrefix(storeName: string, key: string): Promise<any | null> {
    const storeKey = this.createCompositeKey(storeName, key);
    
    if (this.memoryMode) {
      const buf = this.memoryStore.get(storeKey);
      if (!buf) return null;
      try {
        return await this.decryptData(buf);
      } catch (error) {
        console.error('[SecureDB] Failed to decrypt data from memory storage: [REDACTED]', error);
        return null;
      }
    }

    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readonly");
        const store = tx.objectStore("data");
        const request = store.get(storeKey);

        request.onsuccess = async () => {
          if (!request.result) {
            return resolve(null);
          }
          try {
            const data = await this.decryptData(request.result);
            resolve(data);
          } catch (err) {
            console.error('[SecureDB] Failed to decrypt data from IndexedDB: [REDACTED]', err);
            reject(err);
          }
        };

        request.onerror = () => {
          console.error('[SecureDB] Error retrieving data from IndexedDB: [REDACTED]', request.error);
          reject(request.error);
        };
      });
    } catch (error) {
      console.error('[SecureDB] Error opening database for retrieval: [REDACTED]', error);
      return null;
    }
  }

  /**
   * Generic delete method for removing data from a specific store
   */
  async delete(storeName: string, key: string): Promise<void> {
    return this.deleteWithPrefix(storeName, key);
  }

  /**
   * Delete method with prefix support
   */
  private async deleteWithPrefix(storeName: string, key: string): Promise<void> {
    const storeKey = this.createCompositeKey(storeName, key);
    
    if (this.memoryMode) {
      this.memoryStore.delete(storeKey);
      return;
    }

    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("data", "readwrite");
        const store = tx.objectStore("data");
        const request = store.delete(storeKey);
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch (error) {
      console.error('[SecureDB] Error deleting data: [REDACTED]', error);
      throw error;
    }
  }
}