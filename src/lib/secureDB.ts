import { SecureAuditLogger } from './secure-error-handler';
import { SQLiteKV } from './sqlite-kv';

interface EphemeralConfig {
  enabled: boolean;
  defaultTTL: number; // ms
  maxTTL: number; // ms
  cleanupInterval: number; // ms
}

interface EphemeralData {
  data: any;
  createdAt: number;
  expiresAt: number;
  ttl: number;
  autoDelete: boolean;
}

interface StoredMessage {
  id?: string;
  timestamp?: number;
  [key: string]: unknown;
}

interface StoredUser {
  id?: string;
  username?: string;
  [key: string]: unknown;
}

type PostQuantumAEADLike = {
  encrypt(plaintext: Uint8Array, key: Uint8Array, aad?: Uint8Array, nonce?: Uint8Array): {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    tag: Uint8Array;
  };
  decrypt(ciphertext: Uint8Array, nonce: Uint8Array, tag: Uint8Array, key: Uint8Array, aad?: Uint8Array): Uint8Array;
};

export class SecureDB {
  private static readonly MAX_VALUE_SIZE = 10 * 1024 * 1024; // 10 MB
  private static readonly encoder = new TextEncoder();
  private static readonly decoder = new TextDecoder();

  private username: string;
  private encryptionKey: CryptoKey | null = null;
  private readonly EPHEMERAL_PREFIX = 'ephemeral:';
  private ephemeralConfig: EphemeralConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private postQuantumAEAD: PostQuantumAEADLike | null = null;
  private lastCleanup = 0;
  private readonly MIN_CLEANUP_INTERVAL = 60_000;
  private readonly MAX_EPHEMERAL_BATCH = 1000;

  constructor(username: string, ephemeralConfig?: Partial<EphemeralConfig>) {
    if (!username || username.length > 255) {
      throw new Error('Invalid username');
    }
    this.username = username;
    this.ephemeralConfig = {
      enabled: true,
      defaultTTL: 24 * 60 * 60 * 1000,
      maxTTL: 7 * 24 * 60 * 60 * 1000,
      cleanupInterval: 60 * 60 * 1000,
      ...ephemeralConfig
    };
  }

  private async kv() { return SQLiteKV.forUser(this.username); }

  async initializeWithKey(key: CryptoKey): Promise<void> {
    try {
      const alg = key.algorithm as Partial<AesKeyAlgorithm> | undefined;
      const name = alg?.name;
      const length = alg && 'length' in alg ? (alg.length as number | undefined) : undefined;
      if (name !== 'AES-GCM' && name !== 'AES-CBC') throw new Error('Invalid key algorithm - must be AES');
      if (length !== 256) throw new Error('Invalid key length - must be 256 bits');
      this.encryptionKey = key;
      if (this.ephemeralConfig.enabled) this.startEphemeralCleanup();
    } catch (_error) {
      if (this.cleanupInterval) { clearInterval(this.cleanupInterval); this.cleanupInterval = null; }
      throw _error;
    }
  }

  isInitialized(): boolean {
    return this.encryptionKey !== null;
  }

  private async encryptData(data: unknown): Promise<Uint8Array> {
    if (!this.encryptionKey) throw new Error('Encryption key not initialized');
    const keyBytes = await crypto.subtle.exportKey('raw', this.encryptionKey);
    const key = new Uint8Array(keyBytes);
    const dataBuffer = SecureDB.encoder.encode(JSON.stringify(data));
    if (dataBuffer.length > SecureDB.MAX_VALUE_SIZE) throw new Error(`Data too large: ${dataBuffer.length} bytes`);
    const PostQuantumAEAD = await this.getPostQuantumAEAD();
    const aad = SecureDB.encoder.encode(`securedb-aead-v2-${this.username}`);
    let encResult;
    try {
      encResult = PostQuantumAEAD.encrypt(dataBuffer, key, aad);
      if (!encResult || !encResult.nonce || !encResult.ciphertext || !encResult.tag) throw new Error('Invalid encryption result');
    } catch (encryptError) {
      SecureAuditLogger.error('securedb', 'encryption', 'encrypt-failed', { error: (encryptError as Error).message });
      throw new Error('Failed to encrypt data');
    }
    const aadLengthBytes = new Uint8Array(2);
    new DataView(aadLengthBytes.buffer).setUint16(0, Math.min(aad.length, 0xffff), false);
    const combined = new Uint8Array(aadLengthBytes.length + aad.length + encResult.nonce.length + encResult.ciphertext.length + encResult.tag.length);
    let offset = 0;
    combined.set(aadLengthBytes, offset); offset += aadLengthBytes.length;
    combined.set(aad, offset); offset += aad.length;
    combined.set(encResult.nonce, offset); offset += encResult.nonce.length;
    combined.set(encResult.ciphertext, offset); offset += encResult.ciphertext.length;
    combined.set(encResult.tag, offset);
    key.fill(0);
    return combined;
  }

  private async decryptData(encryptedData: Uint8Array): Promise<unknown> {
    if (!this.encryptionKey) throw new Error('Encryption key not initialized');
    const keyBytes = await crypto.subtle.exportKey('raw', this.encryptionKey);
    const key = new Uint8Array(keyBytes);
    const nonceLength = 36; const tagLength = 32; const minLength = nonceLength + tagLength + 1;
    if (encryptedData.length < minLength) throw new Error('Encrypted data too short');
    let offset = 0; let aad: Uint8Array | undefined;
    if (encryptedData.length >= 2) {
      const possibleAadLength = new DataView(encryptedData.buffer, encryptedData.byteOffset).getUint16(0, false);
      const expectedLength = 2 + possibleAadLength + nonceLength + tagLength + 1;
      if (possibleAadLength > 0 && possibleAadLength < 4096 && encryptedData.length >= expectedLength) {
        offset = 2; aad = encryptedData.slice(offset, offset + possibleAadLength); offset += possibleAadLength;
      }
    }
    const remainingLength = encryptedData.length - offset;
    if (remainingLength < minLength) throw new Error('Encrypted data malformed');
    const nonce = encryptedData.slice(offset, offset + nonceLength); offset += nonceLength;
    const ciphertext = encryptedData.slice(offset, encryptedData.length - tagLength);
    const tag = encryptedData.slice(encryptedData.length - tagLength);
    const PostQuantumAEAD = await this.getPostQuantumAEAD();
    try {
      const decrypted = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, key, aad);
      key.fill(0);
      return JSON.parse(SecureDB.decoder.decode(decrypted));
    } catch (decryptError: any) {
      const errorMessage = decryptError?.message || String(decryptError);
      if (errorMessage.includes('MAC verification failed') || errorMessage.includes('BLAKE3')) {
        SecureAuditLogger.warn('securedb', 'decryption', 'mac-verification-failed', {});
      }
      SecureAuditLogger.error('securedb', 'decryption', 'decrypt-failed', { error: (decryptError as Error).message });
      throw new Error('Failed to decrypt data');
    }
  }

  private async getPostQuantumAEAD(): Promise<PostQuantumAEADLike> {
    if (!this.postQuantumAEAD) {
      try {
        const module = await import('./post-quantum-crypto');
        const aead = module.PostQuantumAEAD;
        if (!aead) throw new Error('PostQuantumAEAD not found in module');
        this.postQuantumAEAD = aead;
      } catch (error) {
        SecureAuditLogger.error('securedb', 'initialization', 'module-load-failed', { error: (error as Error).message });
        throw new Error('Encryption module unavailable');
      }
    }
    return this.postQuantumAEAD;
  }

  private async decryptDataWithYield(encryptedData: Uint8Array): Promise<any> {
    await new Promise(r => setTimeout(r, 0));
    const decrypted = await this.decryptData(encryptedData);
    await new Promise(r => setTimeout(r, 0));
    return decrypted;
  }

  private static sanitizeIdentifier(value: string): string {
    return (value || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
  }

  async storeMessage(message: StoredMessage): Promise<void> {
    const existingMessages = await this.loadMessages();
    await this.saveMessages([...existingMessages, message]);
  }

  async saveMessages(messages: StoredMessage[], activeConversationPeer?: string): Promise<void> {
    if (!this.encryptionKey) throw new Error('Encryption key not initialized');

    const uniqueMap = new Map<string, StoredMessage>();
    for (const msg of messages) {
      if (msg && msg.id) {
        uniqueMap.set(msg.id, msg);
      }
    }

    const conversationMap = new Map<string, StoredMessage[]>();
    const currentUser = this.username;

    for (const msg of uniqueMap.values()) {
      if (!(msg as any)?.sender || !(msg as any)?.recipient) continue;
      const peer = (msg as any).sender === currentUser ? (msg as any).recipient : (msg as any).sender;

      let list = conversationMap.get(peer);
      if (!list) {
        list = [];
        conversationMap.set(peer, list);
      }
      list.push(msg);
    }

    const capped: StoredMessage[] = [];
    // Process each conversation to enforce limits
    for (const [peer, msgs] of conversationMap.entries()) {
      // Sort by timestamp (oldest to newest)
      msgs.sort((a, b) => new Date(a.timestamp as any).getTime() - new Date(b.timestamp as any).getTime());

      const limit = peer === activeConversationPeer ? 1000 : 500;

      if (msgs.length > limit) {
        // Keep only the most recent 'limit' messages
        const start = msgs.length - limit;
        for (let i = start; i < msgs.length; i++) {
          capped.push(msgs[i]);
        }
      } else {
        for (const m of msgs) {
          capped.push(m);
        }
      }
    }

    const encrypted = await this.encryptData(capped);
    await (await this.kv()).setBinary('data', 'messages', encrypted);
  }

  async loadMessages(): Promise<StoredMessage[]> {
    return this.loadEncryptedArray<StoredMessage>('messages', 'load-messages');
  }

  private async loadEncryptedArray<T>(key: string, logContext: string): Promise<T[]> {
    const encrypted = await (await this.kv()).getBinary('data', key);
    if (!encrypted) return [];
    try {
      const data = await this.decryptData(encrypted);
      return Array.isArray(data) ? (data as T[]) : [];
    } catch (err: any) {
      const msg = err?.message || String(err);
      if (/(decrypt|MAC|BLAKE3)/i.test(msg)) {
        SecureAuditLogger.warn('securedb', logContext, 'decryption-failed', {});
        return [];
      }
      throw err;
    }
  }

  async loadMessagesPaginated(limit = 50, offset = 0): Promise<StoredMessage[]> {
    const all = await this.loadMessages();
    const sorted = all.sort((a, b) => new Date(b.timestamp as any).getTime() - new Date(a.timestamp as any).getTime());
    return sorted.slice(offset, offset + limit);
  }

  async loadConversationMessages(peerUsername: string, currentUsername: string, limit = 50, offset = 0): Promise<StoredMessage[]> {
    const all = await this.loadMessages();
    const filtered = all.filter(m => ((m as any).sender === peerUsername && (m as any).recipient === currentUsername) || ((m as any).sender === currentUsername && (m as any).recipient === peerUsername));
    const sorted = filtered.sort((a, b) => new Date(b.timestamp as any).getTime() - new Date(a.timestamp as any).getTime());
    return sorted.slice(offset, offset + limit);
  }

  async getConversationMessageCount(peerUsername: string, currentUsername: string): Promise<number> {
    const all = await this.loadMessages();
    return all.filter(m => ((m as any).sender === peerUsername && (m as any).recipient === currentUsername) || ((m as any).sender === currentUsername && (m as any).recipient === peerUsername)).length;
  }

  async loadRecentMessagesByConversation(messagesPerConversation = 50, currentUsername?: string): Promise<StoredMessage[]> {
    const encrypted = await (await this.kv()).getBinary('data', 'messages');
    if (!encrypted) return [];
    const allMessages = await this.decryptDataWithYield(encrypted);
    if (!Array.isArray(allMessages)) return [];
    const map = new Map<string, StoredMessage[]>();
    const CHUNK = 100;
    for (let i = 0; i < allMessages.length; i += CHUNK) {
      const chunk = allMessages.slice(i, i + CHUNK);
      for (const msg of chunk) {
        if (!(msg as any)?.sender || !(msg as any)?.recipient) continue;
        const peer = currentUsername ? ((msg as any).sender === currentUsername ? (msg as any).recipient : (msg as any).sender) : (msg as any).sender;
        if (!map.has(peer)) map.set(peer, []);
        map.get(peer)!.push(msg);
      }
      if (i + CHUNK < allMessages.length) await new Promise(r => setTimeout(r, 0));
    }
    const result: StoredMessage[] = [];
    const entries = Array.from(map.entries());
    for (let i = 0; i < entries.length; i++) {
      const [, messages] = entries[i];
      const sorted = messages.sort((a, b) => new Date(b.timestamp as any).getTime() - new Date(a.timestamp as any).getTime());
      result.push(...sorted.slice(0, messagesPerConversation));
      if (i > 0 && i % 5 === 0 && i < entries.length - 1) await new Promise(r => setTimeout(r, 0));
    }
    return result;
  }

  async saveUsers(users: StoredUser[]): Promise<void> {
    if (!this.encryptionKey) throw new Error('Encryption key not initialized');
    const encrypted = await this.encryptData(users);
    await (await this.kv()).setBinary('data', 'users', encrypted);
  }

  async deleteConversationMessages(peerUsername: string, currentUsername: string): Promise<number> {
    if (!peerUsername || !currentUsername) return 0;
    const all = await this.loadMessages().catch(() => [] as StoredMessage[]);
    if (!Array.isArray(all) || all.length === 0) return 0;
    const before = all.length;
    const remaining = all.filter((msg) => {
      const s = (msg as any).sender; const r = (msg as any).recipient; if (!s || !r) return true;
      return !((s === peerUsername && r === currentUsername) || (s === currentUsername && r === peerUsername));
    });
    if (remaining.length === before) return 0;
    const encrypted = await this.encryptData(remaining);
    await (await this.kv()).setBinary('data', 'messages', encrypted);
    return before - remaining.length;
  }

  async loadUsers(): Promise<StoredUser[]> {
    return this.loadEncryptedArray<StoredUser>('users', 'load-users');
  }

  async storeEphemeral(storeName: string, keyOrData: any, maybeData?: unknown, ttl?: number, autoDelete?: boolean): Promise<void>;
  async storeEphemeral(storeName: string, key: string, data: unknown, ttl?: number, autoDelete?: boolean): Promise<void>;
  async storeEphemeral(storeName: string, a: any, b?: any, ttl?: number, autoDelete = true): Promise<void> {
    if (!this.ephemeralConfig.enabled) {
      if (typeof a === 'string') return this.store(storeName, a, b);
      return this.store(storeName, '__singleton__', a);
    }
    let key: string; let data: unknown;
    if (typeof a === 'string') { key = a; data = b; } else { key = '__singleton__'; data = a; }
    let validatedTTL = ttl || this.ephemeralConfig.defaultTTL;
    if (typeof validatedTTL !== 'number' || isNaN(validatedTTL) || validatedTTL <= 0) {
      SecureAuditLogger.warn('securedb', 'ephemeral', 'invalid-ttl', {});
      validatedTTL = this.ephemeralConfig.defaultTTL;
    }
    const now = Date.now(); const expiresAt = now + Math.min(validatedTTL, this.ephemeralConfig.maxTTL);
    if (expiresAt <= now || !Number.isFinite(expiresAt)) throw new Error('Invalid expiration time calculated');
    const payload: EphemeralData = { data, createdAt: now, expiresAt, ttl: expiresAt - now, autoDelete };
    await this.storeWithPrefix(`${this.EPHEMERAL_PREFIX}${storeName}`, key, payload);
  }

  async retrieveEphemeral(storeName: string, keyOrUndefined?: string): Promise<unknown | null> {
    const key = keyOrUndefined ?? '__singleton__';
    if (!this.ephemeralConfig.enabled) return this.retrieve(storeName, key);
    const ephe = await this.retrieveWithPrefix(`${this.EPHEMERAL_PREFIX}${storeName}`, key) as EphemeralData | null;
    if (!ephe) return null;
    if (!ephe.expiresAt) return null;
    if (Date.now() > ephe.expiresAt) {
      if (ephe.autoDelete) await this.deleteWithPrefix(`${this.EPHEMERAL_PREFIX}${storeName}`, key);
      return null;
    }
    return ephe.data;
  }

  async appendEphemeralList(storeName: string, listKey: string, entry: number | string, maxCount = 500, ttl?: number): Promise<(number | string)[]> {
    const existing = await this.retrieveEphemeral(storeName, listKey);
    const list = Array.isArray(existing) ? existing.slice(0, maxCount) : [];
    const normalized = (typeof entry === 'number' || typeof entry === 'string') ? entry : String(entry);
    const deduped = list.filter((v) => v !== normalized);
    deduped.push(normalized);
    const trimmed = deduped.length > maxCount ? deduped.slice(deduped.length - maxCount) : deduped;
    await this.storeEphemeral(storeName, listKey, trimmed, ttl, true);
    return trimmed;
  }

  private startEphemeralCleanup(): void {
    if (this.cleanupInterval) clearInterval(this.cleanupInterval);
    this.cleanupInterval = setInterval(async () => { await this.cleanupExpiredData(); }, this.ephemeralConfig.cleanupInterval);
  }

  private async cleanupExpiredData(): Promise<void> {
    try {
      const now = Date.now(); if (now - this.lastCleanup < this.MIN_CLEANUP_INTERVAL) return; this.lastCleanup = now;
      const kv = await this.kv();
      const candidates = await kv.scanByStorePrefix(this.EPHEMERAL_PREFIX);
      const toDeleteByStore = new Map<string, string[]>();
      for (const { store, key, value } of candidates) {
        try {
          const data = await this.decryptData(value) as EphemeralData;
          if (data?.expiresAt && now > data.expiresAt && data.autoDelete) {
            const arr = toDeleteByStore.get(store) || []; arr.push(key); toDeleteByStore.set(store, arr);
            if (arr.length >= this.MAX_EPHEMERAL_BATCH) { await kv.deleteMany(store, arr.splice(0, arr.length)); }
          }
        } catch { }
      }
      for (const [store, keys] of toDeleteByStore.entries()) if (keys.length) await kv.deleteMany(store, keys);
    } catch (error) {
      SecureAuditLogger.error('securedb', 'cleanup', 'cleanup-failed', { error: (error as Error).message });
    }
  }

  private async storeWithPrefix(storeName: string, key: string, data: unknown): Promise<void> {
    if (!this.encryptionKey) throw new Error('Encryption key not initialized');
    const encrypted = await this.encryptData(data);
    await (await this.kv()).setBinary(storeName, key, encrypted);
  }

  async store(storeName: string, key: string, data: unknown): Promise<void> {
    return this.storeWithPrefix(storeName, key, data);
  }

  private async retrieveWithPrefix(storeName: string, key: string): Promise<unknown | null> {
    const encrypted = await (await this.kv()).getBinary(storeName, key);
    if (!encrypted) return null;
    try { return await this.decryptData(encrypted); } catch (err) {
      SecureAuditLogger.error('securedb', 'retrieval', 'decrypt-failed', { error: (err as Error).message });
      throw err;
    }
  }

  async retrieve(storeName: string, key: string): Promise<unknown | null> {
    return this.retrieveWithPrefix(storeName, key);
  }

  private async deleteWithPrefix(storeName: string, key: string): Promise<void> {
    await (await this.kv()).delete(storeName, key);
  }

  async delete(storeName: string, key: string): Promise<void> { return this.deleteWithPrefix(storeName, key); }

  async cacheUsernameHash(originalUsername: string, hashedUsername: string): Promise<void> {
    await this.store('username_hashes', originalUsername, hashedUsername);
  }

  async getCachedUsernameHash(originalUsername: string): Promise<string | null> {
    const result = await this.retrieve('username_hashes', originalUsername);
    return typeof result === 'string' ? result : null;
  }

  async hasUsernameHash(originalUsername: string): Promise<boolean> {
    return (await this.getCachedUsernameHash(originalUsername)) !== null;
  }

  async storeUsernameMapping(hashedUsername: string, originalUsername: string): Promise<void> {
    if (!hashedUsername || !originalUsername) { SecureAuditLogger.error('securedb', 'username-mapping', 'invalid-parameters', {}); return; }
    await this.store('username_mappings', hashedUsername, originalUsername);
  }

  async getOriginalUsername(hashedUsername: string): Promise<string | null> {
    if (!hashedUsername || typeof hashedUsername !== 'string') return null;
    const result = await this.retrieve('username_mappings', hashedUsername);
    return typeof result === 'string' ? result : null;
  }

  async getAllUsernameMappings(): Promise<Array<{ hashed: string; original: string }>> {
    try {
      const entries = await (await this.kv()).entriesForStore('username_mappings');
      const out: Array<{ hashed: string; original: string }> = [];
      for (const { key, value } of entries) {
        try { const original = await this.decryptData(value); if (typeof original === 'string') out.push({ hashed: key, original }); } catch { }
      }
      return out;
    } catch (error) {
      SecureAuditLogger.error('securedb', 'get-mappings', 'failed', { error: (error as Error).message });
      return [];
    }
  }

  private deduplicateMessages(messages: StoredMessage[]): StoredMessage[] {
    const seen = new Set<string>();
    return messages.filter((msg) => {
      if (!msg) return false;
      const identifier = (msg.id && msg.id.trim().length > 0) ? msg.id : JSON.stringify(msg);
      if (!identifier || seen.has(identifier)) return false; seen.add(identifier); return true;
    });
  }

  async appendMessages(newMessages: StoredMessage[]): Promise<void> {
    const existing = await this.loadMessages();
    const all = [...existing, ...newMessages].sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0));
    await this.saveMessages(all);
  }

  async clearAllData(): Promise<void> { await (await this.kv()).clearAll(); }

  async clearAllDataExceptMappings(): Promise<void> {
    await (await this.kv()).clearAllExcept(new Set(['username_mappings', 'username_hashes']));
  }

  async clearDatabase(): Promise<void> {
    if (this.cleanupInterval) { clearInterval(this.cleanupInterval); this.cleanupInterval = null; }
    await SQLiteKV.purgeUserDb(this.username);
  }

  async destroy(): Promise<void> {
    if (this.cleanupInterval) { clearInterval(this.cleanupInterval); this.cleanupInterval = null; }
    this.encryptionKey = null; this.postQuantumAEAD = null;
  }

  async clearStore(storeName: string): Promise<number> { return (await this.kv()).clearStore(storeName); }

  private static readonly MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
  private static readonly BLOCKED_MIME_TYPES = [
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-sh',
    'application/x-bat',
    'application/x-executable',
    'application/vnd.microsoft.portable-executable',
  ];

  private validateFileData(data: ArrayBuffer | Blob, fileId: string): void {
    const size = data instanceof Blob ? data.size : data.byteLength;

    if (size > SecureDB.MAX_FILE_SIZE) {
      throw new Error(`File too large: ${size} bytes (max: ${SecureDB.MAX_FILE_SIZE})`);
    }

    if (size === 0) {
      throw new Error('File is empty');
    }

    if (!fileId || typeof fileId !== 'string' || fileId.length === 0 || fileId.length > 255) {
      throw new Error('Invalid file ID');
    }

    // Check MIME type if it's a Blob
    if (data instanceof Blob && data.type) {
      const mimeType = data.type.toLowerCase();
      if (SecureDB.BLOCKED_MIME_TYPES.some(blocked => mimeType.includes(blocked))) {
        throw new Error(`Blocked file type: ${data.type}`);
      }
    }
  }

  async saveFile(fileId: string, data: ArrayBuffer | Blob): Promise<void> {
    if (!this.encryptionKey) throw new Error('Encryption key not initialized');

    this.validateFileData(data, fileId);

    const arrayBuffer = data instanceof Blob ? await data.arrayBuffer() : data;
    const uint8Array = new Uint8Array(arrayBuffer);

    // Encrypt the file data
    const encrypted = await this.encryptData(uint8Array);

    // Store in the 'files' store using fileId as key
    await (await this.kv()).setBinary('files', fileId, encrypted);
  }

  async getFile(fileId: string): Promise<Blob | null> {
    if (!fileId || typeof fileId !== 'string') {
      return null;
    }

    const encrypted = await (await this.kv()).getBinary('files', fileId);
    if (!encrypted) return null;

    try {
      const decrypted = await this.decryptData(encrypted);

      // The decrypted data should be a Uint8Array (stored from saveFile)
      if (decrypted instanceof Uint8Array) {
        const regularBuffer = new ArrayBuffer(decrypted.byteLength);
        const regularArray = new Uint8Array(regularBuffer);
        regularArray.set(decrypted);
        return new Blob([regularArray]);
      }

      // Fallback: if it's an array-like object convert it
      if (Array.isArray(decrypted) || (decrypted && typeof decrypted === 'object' && 'length' in decrypted)) {
        const arr = new Uint8Array(decrypted as any);
        const regularBuffer = new ArrayBuffer(arr.byteLength);
        const regularArray = new Uint8Array(regularBuffer);
        regularArray.set(arr);
        return new Blob([regularArray]);
      }

      return null;
    } catch (err) {
      SecureAuditLogger.error('securedb', 'file-retrieval', 'decrypt-failed', { error: (err as Error).message });
      return null;
    }
  }
}

