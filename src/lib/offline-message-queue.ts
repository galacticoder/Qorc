/**
 * Offline message queue for handling messages to offline users
 * Stores messages locally and retries delivery when users come online
 */

import { PostQuantumRandom } from './cryptography/random';
import { STORAGE_KEYS } from './database/storage-keys';
import { SecureDB } from './database/secureDB';
import { encryptLongTerm, decryptLongTerm, LongTermEnvelope } from './cryptography/long-term-encryption';
import { SignalType } from './types/signal-types';
import { EventType } from './types/event-types';

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value == null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
};

interface EncryptedPayload {
  content: string;
  nonce: string;
  tag: string;
  mac: string;
  aad?: string;
  kemCiphertext?: string;
  envelopeVersion?: string;
  sessionId?: string;
  type?: string;
}

interface QueuedMessage {
  id: string;
  to: string;
  encryptedPayload: EncryptedPayload;
  timestamp: number;
  retryCount: number;
  maxRetries: number;
  expiresAt: number;
  nextAttempt: number;
  sizeBytes: number;
}

interface OfflineMessage {
  encryptedPayload?: EncryptedPayload;
  longTermEnvelope?: LongTermEnvelope;
  version?: string;
  messageId?: string;
  to?: string;
  from?: string;
  expiresAt?: number;
  maxRetries?: number;
}

interface UserStatus {
  username: string;
  isOnline: boolean;
  lastSeen: number;
}

interface QueueStats {
  totalQueuedMessages: number;
  usersWithQueuedMessages: number;
  onlineUsers: number;
  totalUsers: number;
}

interface QueueMetrics {
  messagesQueued: number;
  messagesDelivered: number;
  messagesFailed: number;
  messagesExpired: number;
}

type SendCallback = (payload: EncryptedPayload) => Promise<boolean>;
type IncomingOfflineEncryptedMessageCallback = (message: any) => void | Promise<void>;
type OfflineMessagesEvent = CustomEvent<{ messages: OfflineMessage[] }>;

const STORAGE_KEY = STORAGE_KEYS.OFFLINE_MESSAGE_QUEUE;
const AUDIT_CHANNEL = 'offlineQueue';
const DEVICE_ID_KEY = STORAGE_KEYS.OFFLINE_QUEUE_DEVICE_ID;
import { syncEncryptedStorage } from './database/encrypted-storage';
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MESSAGE_EXPIRY = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_RETRY_INTERVAL = 30_000;
const MAX_MESSAGE_SIZE = 100 * 1024;
const MAX_QUEUE_LENGTH_PER_USER = 100;
const PROCESSED_IDS_MAX_SIZE = 1_000;
const MAX_STORAGE_BYTES = 4.5 * 1024 * 1024;
const MAX_RATE_LIMIT = 200;
const SANITIZE_REGEX = /(javascript:|<script[^>]*>.*?<\/script>)/gi;
const ENVELOPE_VERSION = 'pq-offline-v2';

class SimpleRateLimiter {
  private limit: number;
  private window: number;
  private tokens: Map<string, { count: number; resetAt: number }> = new Map();

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.window = windowMs;
  }

  checkLimit(key: string = 'default'): boolean {
    const now = Date.now();
    const entry = this.tokens.get(key);

    if (!entry || now > entry.resetAt) {
      this.tokens.set(key, { count: 1, resetAt: now + this.window });
      return true;
    }

    if (entry.count >= this.limit) {
      return false;
    }

    entry.count++;
    return true;
  }
}

const rateLimiter = new SimpleRateLimiter(MAX_RATE_LIMIT, 60_000);

function sanitizeString(input: string | undefined | null): string | undefined {
  if (typeof input !== 'string') {
    return undefined;
  }
  const sanitized = input.replace(SANITIZE_REGEX, '').trim();
  if (!sanitized) {
    return undefined;
  }
  return sanitized;
}

function sanitizePayload(payload: EncryptedPayload): EncryptedPayload {
  return {
    ...payload,
    content: sanitizeString(payload.content) ?? '',
    aad: sanitizeString(payload.aad),
    kemCiphertext: sanitizeString(payload.kemCiphertext),
    envelopeVersion: sanitizeString(payload.envelopeVersion) ?? ENVELOPE_VERSION,
    sessionId: sanitizeString(payload.sessionId),
    type: sanitizeString(payload.type)
  };
}

function _getDeviceId(): string {
  try {
    const existing = syncEncryptedStorage.getItem(DEVICE_ID_KEY);
    if (existing && typeof existing === 'string') {
      return existing;
    }
  } catch { }
  const deviceId = PostQuantumRandom.randomUUID();
  try { syncEncryptedStorage.setItem(DEVICE_ID_KEY, deviceId); } catch { }
  return deviceId;
}

let globalSecureDB: SecureDB | null = null;

export function initializeOfflineMessageQueue(secureDB: SecureDB): void {
  globalSecureDB = secureDB;
}

async function securePersist<T>(key: string, payload: T): Promise<void> {
  if (!globalSecureDB) return;
  try {
    await globalSecureDB.store('offline_queue', key, { version: ENVELOPE_VERSION, payload });
  } catch { }
}

async function secureLoad<T>(key: string): Promise<T | null> {
  if (!globalSecureDB) return null;
  try {
    const stored = await globalSecureDB.retrieve('offline_queue', key);
    if (!stored || typeof stored !== 'object' || !isPlainObject(stored) || hasPrototypePollutionKeys(stored)) {
      return null;
    }

    const envelope = stored as { version?: string; payload?: T };
    if (envelope.version !== ENVELOPE_VERSION || typeof envelope.payload === 'undefined') {
      return null;
    }
    return envelope.payload;
  } catch {
    return null;
  }
}

class MessageValidator {
  static validate(message: QueuedMessage): void {
    if (!message.to || typeof message.to !== 'string') {
      throw new Error('Invalid recipient username');
    }

    if (!message.id || typeof message.id !== 'string') {
      throw new Error('Invalid message identifier');
    }

    if (message.expiresAt <= Date.now()) {
      throw new Error(`Message ${message.id} already expired`);
    }

    if (message.sizeBytes > MAX_MESSAGE_SIZE) {
      throw new Error(`Message ${message.id} size ${message.sizeBytes} exceeds ${MAX_MESSAGE_SIZE}`);
    }

    if (!message.encryptedPayload?.mac || !message.encryptedPayload?.tag) {
      throw new Error(`Message ${message.id} missing integrity data`);
    }
  }

  static canQueue(username: string, queue: Map<string, QueuedMessage[]>): boolean {
    const userQueue = queue.get(username) ?? [];
    return userQueue.length < MAX_QUEUE_LENGTH_PER_USER;
  }
}

class RetryStrategy {
  private static readonly BASE_DELAY = 5_000;
  private static readonly MAX_DELAY = 5 * 60 * 1_000;
  private static readonly JITTER_FACTOR = 0.1;

  private static cryptoRandomFraction(): number {
    // Derive a fraction in [0,1) from 32 bits of PQ-secure randomness
    const bytes = PostQuantumRandom.randomBytes(4);
    const value =
      (bytes[0]! << 24) >>> 0 ^
      (bytes[1]! << 16) ^
      (bytes[2]! << 8) ^
      bytes[3]!;
    return value / 0xffffffff;
  }

  static calculateDelay(retryCount: number): number {
    const exponential = Math.min(
      RetryStrategy.BASE_DELAY * Math.pow(2, retryCount),
      RetryStrategy.MAX_DELAY
    );

    const jitter = exponential * RetryStrategy.JITTER_FACTOR * RetryStrategy.cryptoRandomFraction();
    return Math.floor(exponential + jitter);
  }
}

class QueueMonitor {
  private metrics: QueueMetrics = {
    messagesQueued: 0,
    messagesDelivered: 0,
    messagesFailed: 0,
    messagesExpired: 0
  };

  recordQueued(): void {
    this.metrics.messagesQueued += 1;
  }

  recordDelivered(): void {
    this.metrics.messagesDelivered += 1;
  }

  recordFailed(): void {
    this.metrics.messagesFailed += 1;
  }

  recordExpired(): void {
    this.metrics.messagesExpired += 1;
  }

  getMetrics(): QueueMetrics {
    return { ...this.metrics };
  }
}

export class OfflineMessageQueue {
  private queue: Map<string, QueuedMessage[]> = new Map();
  private userStatuses: Map<string, UserStatus> = new Map();
  private processingUsers: Set<string> = new Set();
  private processedMessageIds: Set<string> = new Set();
  private processedMessageOrder: string[] = [];
  private sendCallback?: SendCallback;
  private incomingOfflineEncryptedMessageCallback?: IncomingOfflineEncryptedMessageCallback;
  private pendingServerOfflineMessages: OfflineMessage[] | null = null;
  private processingPendingServerOfflineMessages = false;
  private lastRetrieveAttemptAt = 0;
  private pendingRetrieveAfterAuth = false;
  private retryTimer?: number;
  private readonly monitor = new QueueMonitor();
  private readonly abortController = new AbortController();

  private readonly maxRetries = DEFAULT_MAX_RETRIES;
  private readonly messageExpiry = DEFAULT_MESSAGE_EXPIRY;
  private readonly fallbackRetryInterval = DEFAULT_RETRY_INTERVAL;
  private ownKyberSecretKey: Uint8Array | null = null;

  /**
   * Set the user's Kyber secret key for decrypting long-term encrypted messages.
   */
  setDecryptionKey(kyberSecretKey: Uint8Array): void {
    this.ownKyberSecretKey = kyberSecretKey;
    void this.tryProcessPendingServerOfflineMessages();
  }

  clearDecryptionKey(): void {
    this.ownKyberSecretKey = null;
  }

  constructor(sendCallback?: SendCallback) {
    this.sendCallback = sendCallback;
    void this.loadFromStorage();
    this.setupEventListeners();
    this.scheduleNextProcessing(this.fallbackRetryInterval);
  }

  setSendCallback(callback: SendCallback): void {
    this.sendCallback = callback;
  }

  setIncomingOfflineEncryptedMessageCallback(callback: IncomingOfflineEncryptedMessageCallback): void {
    this.incomingOfflineEncryptedMessageCallback = callback;
    void this.tryProcessPendingServerOfflineMessages();
  }

  private async tryProcessPendingServerOfflineMessages(): Promise<void> {
    if (this.processingPendingServerOfflineMessages) return;
    if (!this.pendingServerOfflineMessages || this.pendingServerOfflineMessages.length === 0) return;
    if (!this.incomingOfflineEncryptedMessageCallback) return;

    this.processingPendingServerOfflineMessages = true;
    const pending = this.pendingServerOfflineMessages;
    this.pendingServerOfflineMessages = null;
    try {
      await this.processOfflineMessagesChunked(pending);
    } finally {
      this.processingPendingServerOfflineMessages = false;
    }
  }

  private setupEventListeners(): void {
    window.addEventListener(
      'offline-messages-response',
      this.handleOfflineMessagesResponse as EventListener,
      { signal: this.abortController.signal }
    );

    window.addEventListener(
      'secure-chat:auth-success',
      () => {
        this.pendingRetrieveAfterAuth = true;
        setTimeout(() => {
          this._retrieveOfflineMessagesFromServer(true);
        }, 500);
      },
      { signal: this.abortController.signal }
    );

    window.addEventListener(
      'pq-session-established',
      () => {
        if (!this.pendingRetrieveAfterAuth) {
          return;
        }
        setTimeout(() => {
          this._retrieveOfflineMessagesFromServer(true);
        }, 250);
      },
      { signal: this.abortController.signal }
    );

    window.addEventListener(
      EventType.WS_RECONNECTED,
      () => {
        if (!this.pendingRetrieveAfterAuth) {
          return;
        }
        setTimeout(() => {
          this._retrieveOfflineMessagesFromServer(true);
        }, 250);
      },
      { signal: this.abortController.signal }
    );
  }

  updateUserStatus(username: string, isOnline: boolean): void {
    this.userStatuses.set(username, {
      username,
      isOnline,
      lastSeen: Date.now()
    });

    if (isOnline) {
      void this.processQueueForUser(username);
    }
  }

  queueMessage(to: string, encryptedPayload: EncryptedPayload, options?: {
    skipServerStore?: boolean;
    messageId?: string;
    expiresAt?: number;
    maxRetries?: number;
    recipientKyberPublicKey?: string;
  }): string {
    if (!rateLimiter.checkLimit(to)) {
      throw new Error('Rate limit exceeded');
    }
    const messageId = options?.messageId ?? (crypto?.randomUUID?.() ?? PostQuantumRandom.randomUUID());

    if (this.processedMessageIds.has(messageId)) {
      return messageId;
    }

    if (!MessageValidator.canQueue(to, this.queue)) {
      throw new Error('Offline queue limit reached');
    }

    const now = Date.now();
    const expiresAt = options?.expiresAt ?? (now + this.messageExpiry);
    const sanitizedPayload = sanitizePayload(encryptedPayload);
    const serializedPayload = JSON.stringify(sanitizedPayload);
    const sizeBytes = new Blob([serializedPayload]).size;

    if (sizeBytes > MAX_MESSAGE_SIZE) {
      throw new Error(`Message ${messageId} size ${sizeBytes} exceeds ${MAX_MESSAGE_SIZE}`);
    }

    const queuedMessage: QueuedMessage = {
      id: messageId,
      to,
      encryptedPayload: sanitizedPayload,
      timestamp: now,
      retryCount: 0,
      maxRetries: options?.maxRetries ?? this.maxRetries,
      expiresAt,
      nextAttempt: Date.now(),
      sizeBytes
    };

    MessageValidator.validate(queuedMessage);
    this.trackProcessedMessageId(messageId);

    if (!this.queue.has(to)) {
      this.queue.set(to, []);
    }

    this.queue.get(to)!.push(queuedMessage);
    this.monitor.recordQueued();

    if (!options?.skipServerStore) {
      this.storeMessageOnServer(messageId, to, encryptedPayload, options?.recipientKyberPublicKey);
    }

    void this.saveToStorage();
    this.scheduleNextProcessing(0);

    return messageId;
  }

  /**
   * Store message on server using long-term encryption.
   */
  private storeMessageOnServer(
    messageId: string,
    to: string,
    encryptedPayload: EncryptedPayload,
    recipientKyberPublicKey?: string
  ): void {
    if (!recipientKyberPublicKey) {
      return;
    }

    void import('./websocket/websocket')
      .then(async ({ default: websocketClient }) => {
        if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
          return;
        }

        try {
          const messageData = JSON.stringify({
            messageId,
            encryptedPayload,
            timestamp: Date.now()
          });

          const longTermEnvelope = await encryptLongTerm(
            messageData,
            recipientKyberPublicKey
          );

          await websocketClient.sendSecureControlMessage({
            type: 'store-offline-message',
            messageId,
            to,
            longTermEnvelope,
            version: 'lt-v1'
          });
        } catch { }
      })
      .catch(() => { });
  }

  public retrieveOfflineMessagesFromServer(): void {
    this._retrieveOfflineMessagesFromServer();
  }

  private _retrieveOfflineMessagesFromServer(fromAuthSuccess = false): void {
    const now = Date.now();
    if (now - this.lastRetrieveAttemptAt < 1500) {
      return;
    }
    this.lastRetrieveAttemptAt = now;

    void import('./websocket/websocket')
      .then(async ({ default: websocketClient }) => {
        const isConnected = websocketClient?.isConnectedToServer();
        const isPQReady = websocketClient?.isPQSessionEstablished();

        if (!fromAuthSuccess && (!isConnected || !isPQReady)) {
          return;
        }

        if (isConnected && isPQReady) {
          try {
            await websocketClient.sendSecureControlMessage({ type: 'retrieve-offline-messages' });
            if (fromAuthSuccess) {
              this.pendingRetrieveAfterAuth = false;
            }
          } catch { }
        }
      })
      .catch(() => { });
  }

  handleOfflineMessagesFromServer(messages: OfflineMessage[]): void {
    if (!Array.isArray(messages) || messages.length === 0) {
      return;
    }

    const ltOnly = messages.filter((m) => (m as any)?.version === 'lt-v1' && !!(m as any)?.longTermEnvelope);

    if (ltOnly.length === 0) {
      return;
    }

    if (!this.incomingOfflineEncryptedMessageCallback) {
      const existing = this.pendingServerOfflineMessages ?? [];
      const combined = existing.concat(ltOnly);
      this.pendingServerOfflineMessages = combined.length > 200 ? combined.slice(combined.length - 200) : combined;
      void this.tryProcessPendingServerOfflineMessages();
      return;
    }

    if (!this.ownKyberSecretKey) {
      const existing = this.pendingServerOfflineMessages ?? [];
      const combined = existing.concat(ltOnly);
      this.pendingServerOfflineMessages = combined.length > 200 ? combined.slice(combined.length - 200) : combined;
      void this.tryProcessPendingServerOfflineMessages();
      return;
    }

    this.processOfflineMessagesChunked(ltOnly).catch(error => {
      console.error('[offline-queue] chunked-processing-failed', (error as Error)?.message);
    });
  }

  private async processOfflineMessagesChunked(messages: OfflineMessage[]): Promise<void> {
    const CHUNK_SIZE = 10;

    for (let i = 0; i < messages.length; i += CHUNK_SIZE) {
      const chunk = messages.slice(i, i + CHUNK_SIZE);

      for (const message of chunk) {
        try {
          if (message.version !== 'lt-v1' || !message.longTermEnvelope) {
            continue;
          }

          if (!this.ownKyberSecretKey) {
            console.warn('[offline-queue] no-decryption-key');
            continue;
          }

          const decrypted = await decryptLongTerm(message.longTermEnvelope, this.ownKyberSecretKey);
          if (!decrypted.json || typeof decrypted.json !== 'object') {
            continue;
          }

          const parsed = decrypted.json as { messageId?: string; encryptedPayload?: EncryptedPayload };
          const encryptedPayload = parsed.encryptedPayload;
          const to = sanitizeString(message.to) ?? '';

          if (!encryptedPayload || !to) {
            continue;
          }

          const messageId = sanitizeString(message.messageId ?? parsed.messageId) ?? PostQuantumRandom.randomUUID();
          const expiresAt = Math.min(
            message.expiresAt ?? (Date.now() + this.messageExpiry),
            Date.now() + this.messageExpiry
          );
          const maxRetries = message.maxRetries ?? this.maxRetries;

          const from = sanitizeString(message.from) ?? '';
          const incoming = {
            type: SignalType.ENCRYPTED_MESSAGE,
            from,
            to,
            encryptedPayload,
            offline: true,
            messageId,
            expiresAt,
            maxRetries
          };

          if (this.incomingOfflineEncryptedMessageCallback) {
            await this.incomingOfflineEncryptedMessageCallback(incoming);
          }
        } catch (error) {
          console.error('[offline-queue] queue-server-message-failed', (error as Error)?.message);
        }
      }

      if (i + CHUNK_SIZE < messages.length) {
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }

    await this.saveToStorage();
  }

  isUserOnline(username: string): boolean {
    return this.userStatuses.get(username)?.isOnline ?? false;
  }

  private async processQueueForUser(username: string): Promise<void> {
    if (this.processingUsers.has(username)) {
      return;
    }

    const userQueue = this.queue.get(username);
    if (!userQueue || userQueue.length === 0) {
      this.queue.delete(username);
      return;
    }

    this.processingUsers.add(username);

    try {
      const now = Date.now();
      const remaining: QueuedMessage[] = [];
      const ready: QueuedMessage[] = [];

      for (const message of userQueue) {
        if (message.expiresAt <= now) {
          this.monitor.recordExpired();
          continue;
        }

        if (message.retryCount >= message.maxRetries) {
          this.monitor.recordFailed();
          continue;
        }

        if (message.nextAttempt > now) {
          remaining.push(message);
          continue;
        }

        ready.push(message);
      }

      const retriable = await this.processBatch(ready);

      const updatedQueue = [...remaining, ...retriable]
        .filter((msg) => msg.retryCount < msg.maxRetries && msg.expiresAt > Date.now())
        .sort((a, b) => a.nextAttempt - b.nextAttempt);

      if (updatedQueue.length === 0) {
        this.queue.delete(username);
      } else {
        this.queue.set(username, updatedQueue);
      }

      void this.saveToStorage();
    } finally {
      this.processingUsers.delete(username);
    }
  }

  private async processBatch(batch: QueuedMessage[]): Promise<QueuedMessage[]> {
    const retriable: QueuedMessage[] = [];

    if (!batch.length || !this.sendCallback) {
      if (!this.sendCallback) {
        const now = Date.now();
        for (const message of batch) {
          message.nextAttempt = now + RetryStrategy.calculateDelay(message.retryCount);
          retriable.push(message);
        }
      }
      return retriable;
    }

    for (const message of batch) {
      try {
        const success = await this.sendCallback(message.encryptedPayload);
        if (success) {
          this.monitor.recordDelivered();
        } else {
          message.retryCount += 1;
          message.nextAttempt = Date.now() + RetryStrategy.calculateDelay(message.retryCount);
          this.monitor.recordFailed();
          retriable.push(message);
        }
      } catch (error) {
        const isNetworkError = error instanceof TypeError || (error as { code?: string })?.code === 'ECONNREFUSED' || (error as { code?: string })?.code === 'ETIMEDOUT';
        if (isNetworkError && message.retryCount < message.maxRetries) {
          message.retryCount += 1;
          message.nextAttempt = Date.now() + RetryStrategy.calculateDelay(message.retryCount);
          retriable.push(message);
        } else {
          this.monitor.recordFailed();
        }
      }
    }

    return retriable;
  }

  private async processAllQueues(): Promise<void> {
    const now = Date.now();
    const upcomingAttempts: number[] = [];

    for (const [username, messages] of this.queue.entries()) {
      if (messages.length === 0) {
        this.queue.delete(username);
        continue;
      }

      const earliestAttempt = Math.min(...messages.map((msg) => msg.nextAttempt ?? now));
      if (earliestAttempt > now) {
        upcomingAttempts.push(earliestAttempt - now);
      }

      if (this.isUserOnline(username)) {
        await this.processQueueForUser(username);
      }
    }

    this.cleanupExpiredMessages();

    const nextDelay = upcomingAttempts.length > 0
      ? Math.max(0, Math.min(...upcomingAttempts))
      : this.fallbackRetryInterval;

    this.scheduleNextProcessing(nextDelay);
  }

  private cleanupExpiredMessages(): void {
    const now = Date.now();
    let removed = 0;

    for (const [username, messages] of this.queue.entries()) {
      const valid = messages.filter((msg) => msg.expiresAt > now && msg.retryCount < msg.maxRetries);
      removed += messages.length - valid.length;

      if (valid.length === 0) {
        this.queue.delete(username);
      } else {
        this.queue.set(username, valid);
      }
    }

    if (removed > 0) {
      for (let i = 0; i < removed; i++) {
        this.monitor.recordExpired();
      }
      void this.saveToStorage();
    }
  }

  getStats(): QueueStats {
    const totalQueuedMessages = Array.from(this.queue.values()).reduce((sum, messages) => sum + messages.length, 0);
    const onlineUsers = Array.from(this.userStatuses.values()).filter((status) => status.isOnline).length;
    const totalUsers = this.userStatuses.size;

    return {
      totalQueuedMessages,
      usersWithQueuedMessages: this.queue.size,
      onlineUsers,
      totalUsers
    };
  }

  getMetrics(): QueueMetrics {
    return this.monitor.getMetrics();
  }

  stop(): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = undefined;
    }
    this.abortController.abort();
  }

  clearQueue(): void {
    this.queue.clear();
    void this.saveToStorage();
  }

  private scheduleNextProcessing(delay: number): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
    }

    const safeDelay = Number.isFinite(delay) ? Math.max(0, delay) : this.fallbackRetryInterval;
    this.retryTimer = window.setTimeout(() => {
      this.retryTimer = undefined;
      void this.processAllQueues();
    }, safeDelay);
  }

  private handleOfflineMessagesResponse = (event: Event): void => {
    try {
      const customEvent = event as OfflineMessagesEvent;
      const detail = customEvent.detail;

      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) {
        return;
      }

      const { messages } = detail ?? {};

      if (Array.isArray(messages)) {
        this.handleOfflineMessagesFromServer(messages);
      }
    } catch { }
  };

  private trackProcessedMessageId(messageId: string): void {
    if (!this.processedMessageIds.has(messageId)) {
      this.processedMessageIds.add(messageId);
      this.processedMessageOrder.push(messageId);

      if (this.processedMessageOrder.length > PROCESSED_IDS_MAX_SIZE) {
        const oldest = this.processedMessageOrder.shift();
        if (oldest) {
          this.processedMessageIds.delete(oldest);
        }
      }
    }
  }

  private async saveToStorage(): Promise<void> {
    try {
      const queueData = {
        queue: Array.from(this.queue.entries()),
        userStatuses: Array.from(this.userStatuses.entries()),
        timestamp: Date.now()
      };

      const serializedData = JSON.stringify(queueData);
      const sizeBytes = new Blob([serializedData]).size;

      if (sizeBytes > MAX_STORAGE_BYTES) {
        console.warn('[offline-queue] storage-limit-exceeded', sizeBytes);
        for (const [username, messages] of this.queue.entries()) {
          if (messages.length > 10) {
            this.queue.set(username, messages.slice(-10));
          }
        }
      }

      await securePersist(STORAGE_KEY, queueData);
    } catch (error) {
      console.error('[offline-queue] save-storage-failed', (error as Error)?.message);
    }
  }

  private async loadFromStorage(): Promise<void> {
    try {
      const stored = await secureLoad<{ queue: [string, QueuedMessage[]][]; userStatuses: [string, UserStatus][] }>(STORAGE_KEY);
      if (!stored) {
        return;
      }

      this.queue = new Map(
        (stored.queue ?? []).map(([username, messages]) => [
          username,
          (messages ?? []).map((message) => ({
            ...message,
            encryptedPayload: sanitizePayload(message.encryptedPayload),
            nextAttempt: message.nextAttempt ?? Date.now()
          }))
        ])
      );

      for (const [username, status] of stored.userStatuses ?? []) {
        this.userStatuses.set(username, { ...status, isOnline: false });
      }

    } catch (error) {
      console.error('[offline-queue] load-storage-failed', (error as Error)?.message);
    }
  }
}

export const offlineMessageQueue = new OfflineMessageQueue();

export function retrieveOfflineMessages(): void {
  offlineMessageQueue.retrieveOfflineMessagesFromServer();
}
