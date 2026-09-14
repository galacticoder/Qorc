import { isCanonicalAuthUsername, sanitizeMessageId } from '../sanitizers';
import { receiptBatcher } from '../../hooks/message-handling/receipt-batcher';
import { EventType } from '../types/event-types';

type DeliveryReceiptEntry = {
  peerUsername: string;
  messageId: string;
  createdAt: number;
  sentAt?: number;
};

type DeliveryReceiptPersistence = {
  load: () => Promise<unknown>;
  save: (entries: DeliveryReceiptEntry[]) => Promise<void>;
};

const MAX_OUTBOX_ENTRIES = 500;
const MAX_OUTBOX_ENTRIES_PER_PEER = 64;
const DURABLE_RECEIPT_OUTBOX_TTL_MS = 12 * 60 * 60 * 1000;
const SENT_RECEIPT_RETENTION_MS = 30 * 60 * 1000;
const RETRY_INTERVAL_MS = 30 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function entryKey(peerUsername: string, messageId: string): string {
  return `${peerUsername.length}:${peerUsername}${messageId}`;
}

function isValidEntry(value: unknown, now = Date.now()): value is DeliveryReceiptEntry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Partial<DeliveryReceiptEntry>;
  const keys = Object.keys(candidate).sort().join(',');
  if (keys !== 'createdAt,messageId,peerUsername' && keys !== 'createdAt,messageId,peerUsername,sentAt') {
    return false;
  }
  if (
    !isCanonicalAuthUsername(candidate.peerUsername) ||
    sanitizeMessageId(candidate.messageId) !== candidate.messageId ||
    !Number.isSafeInteger(candidate.createdAt) ||
    candidate.createdAt! <= 0 ||
    candidate.createdAt! > now + CLOCK_SKEW_MS
  ) return false;
  if (candidate.sentAt !== undefined && (
    !Number.isSafeInteger(candidate.sentAt) ||
    candidate.sentAt < candidate.createdAt! ||
    candidate.sentAt > now + CLOCK_SKEW_MS
  )) return false;
  return true;
}

class DeliveryReceiptOutbox {
  private entries = new Map<string, DeliveryReceiptEntry>();
  private activeAccount: string | null = null;
  private persistenceOwner: string | null = null;
  private persistence: DeliveryReceiptPersistence | null = null;
  private restoreState: 'disabled' | 'loading' | 'ready' | 'failed' = 'disabled';
  private restorePromise: Promise<void> = Promise.resolve();
  private persistenceTail: Promise<void> = Promise.resolve();
  private generation = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryTimerDueAt: number | null = null;
  private restoreRetryTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    receiptBatcher.addFlushListener((account, peer, deliveredIds) => {
      void this.markSent(account, peer, deliveredIds);
    });
  }

  setActiveAccount(account: string | null): void {
    const canonical = account && isCanonicalAuthUsername(account) ? account : null;
    if (this.activeAccount === canonical) return;
    this.generation += 1;
    this.activeAccount = canonical;
    this.entries.clear();
    this.restoreState = 'disabled';
    this.restorePromise = Promise.resolve();
    this.persistenceTail = Promise.resolve();
    this.clearRetryTimer();
    this.clearRestoreRetryTimer();
    receiptBatcher.setActiveAccount(null);

    if (this.persistenceOwner !== canonical) {
      this.persistenceOwner = null;
      this.persistence = null;
    }
    if (canonical && this.persistence) this.startRestore();
  }

  setPersistence(account: string | null, persistence: DeliveryReceiptPersistence | null): void {
    if (!account || !isCanonicalAuthUsername(account) || !persistence) {
      this.generation += 1;
      this.persistenceOwner = null;
      this.persistence = null;
      this.entries.clear();
      this.restoreState = 'disabled';
      this.restorePromise = Promise.resolve();
      this.persistenceTail = Promise.resolve();
      this.clearRetryTimer();
      this.clearRestoreRetryTimer();
      receiptBatcher.setActiveAccount(null);
      return;
    }
    this.generation += 1;
    this.persistenceOwner = account;
    this.persistence = persistence;
    this.entries.clear();
    this.persistenceTail = Promise.resolve();
    this.clearRestoreRetryTimer();
    receiptBatcher.setActiveAccount(null);
    if (this.activeAccount === account) this.startRestore();
    else this.restoreState = 'disabled';
  }

  private startRestore(): void {
    const persistence = this.persistence;
    const account = this.activeAccount;
    const generation = this.generation;
    if (!persistence || !account || this.persistenceOwner !== account) return;
    this.clearRestoreRetryTimer();
    this.restoreState = 'loading';
    this.restorePromise = (async () => {
      const raw = await persistence.load();
      if (!this.isCurrent(account, generation, persistence)) return;

      const candidates = Array.isArray(raw) ? raw : null;
      let valid = candidates !== null && candidates.length <= MAX_OUTBOX_ENTRIES;
      const restored = new Map<string, DeliveryReceiptEntry>();
      if (valid && candidates) {
        for (const candidate of candidates) {
          if (!isValidEntry(candidate)) {
            valid = false;
            break;
          }
          const entry = candidate as DeliveryReceiptEntry;
          const key = entryKey(entry.peerUsername, entry.messageId);
          if (restored.has(key)) {
            valid = false;
            break;
          }
          restored.set(key, { ...entry });
        }
      }

      if (!valid) {
        throw new Error('Delivery receipt outbox is invalid');
      }

      this.entries = restored;
      const pruned = this.pruneExpired();
      this.restoreState = 'ready';
      if (pruned) await this.persistSnapshot();
      if (!this.isCurrent(account, generation, persistence)) return;
      receiptBatcher.setActiveAccount(account);
      this.queuePendingEntries();
    })().catch(() => {
      if (this.isCurrent(account, generation, persistence)) {
        this.restoreState = 'failed';
        this.scheduleRestoreRetry(account, generation, persistence);
      }
    });
  }

  private scheduleRestoreRetry(
    account: string,
    generation: number,
    persistence: DeliveryReceiptPersistence
  ): void {
    this.clearRestoreRetryTimer();
    this.restoreRetryTimer = setTimeout(() => {
      this.restoreRetryTimer = null;
      if (this.restoreState === 'failed' && this.isCurrent(account, generation, persistence)) {
        this.startRestore();
      }
    }, RETRY_INTERVAL_MS);
  }

  private isCurrent(
    account: string,
    generation: number,
    persistence: DeliveryReceiptPersistence
  ): boolean {
    return this.activeAccount === account &&
      this.persistenceOwner === account &&
      this.persistence === persistence &&
      this.generation === generation;
  }

  private pruneExpired(now = Date.now()): boolean {
    let changed = false;
    for (const [key, entry] of this.entries) {
      const expired = entry.sentAt !== undefined
        ? now - entry.sentAt >= SENT_RECEIPT_RETENTION_MS
        : now - entry.createdAt >= DURABLE_RECEIPT_OUTBOX_TTL_MS;
      if (expired) {
        this.entries.delete(key);
        changed = true;
      }
    }
    return changed;
  }

  private evictSentHistory(peerUsername?: string): boolean {
    for (const [key, entry] of this.entries) {
      if (entry.sentAt === undefined || (peerUsername && entry.peerUsername !== peerUsername)) continue;
      this.entries.delete(key);
      return true;
    }
    return false;
  }

  private hasCapacity(peerUsername: string, key: string): boolean {
    if (this.entries.has(key)) return true;
    let peerCount = 0;
    for (const entry of this.entries.values()) {
      if (entry.peerUsername === peerUsername) peerCount += 1;
    }
    while (peerCount >= MAX_OUTBOX_ENTRIES_PER_PEER && this.evictSentHistory(peerUsername)) {
      peerCount -= 1;
    }
    while (this.entries.size >= MAX_OUTBOX_ENTRIES && this.evictSentHistory()) {
    }
    return peerCount < MAX_OUTBOX_ENTRIES_PER_PEER && this.entries.size < MAX_OUTBOX_ENTRIES;
  }

  private persistSnapshot(): Promise<void> {
    const persistence = this.persistence;
    const account = this.activeAccount;
    const generation = this.generation;
    if (!persistence || !account || this.persistenceOwner !== account || this.restoreState === 'failed') {
      return Promise.reject(new Error('Delivery receipt persistence is unavailable'));
    }
    const write = this.persistenceTail.then(async () => {
      if (!this.isCurrent(account, generation, persistence)) {
        throw new Error('Delivery receipt account changed');
      }
      await persistence.save(Array.from(this.entries.values(), (entry) => ({ ...entry })));
      if (!this.isCurrent(account, generation, persistence)) {
        throw new Error('Delivery receipt account changed');
      }
    });
    this.persistenceTail = write.catch(() => { });
    return write;
  }

  private async checkReady(account: string): Promise<void> {
    if (!isCanonicalAuthUsername(account) || account !== this.activeAccount || account !== this.persistenceOwner) {
      throw new Error('Delivery receipt account is not current');
    }
    await this.restorePromise;
    if (account !== this.activeAccount || this.restoreState !== 'ready') {
      throw new Error('Delivery receipt outbox is unavailable');
    }
  }

  async queueDelivery(account: string, peerUsername: string, messageId: string): Promise<boolean> {
    if (!isCanonicalAuthUsername(peerUsername) || sanitizeMessageId(messageId) !== messageId) return false;
    await this.checkReady(account);
    this.pruneExpired();
    const key = entryKey(peerUsername, messageId);
    if (!this.hasCapacity(peerUsername, key)) return false;
    const existing = this.entries.get(key);
    this.entries.delete(key);
    this.entries.set(key, {
      peerUsername,
      messageId,
      createdAt: existing?.createdAt ?? Date.now()
    });
    await this.persistSnapshot();
    if (account !== this.activeAccount) return false;
    receiptBatcher.queueDelivery(account, peerUsername, messageId);
    this.scheduleRetry();
    return true;
  }

  async requeueKnownDelivery(account: string, peerUsername: string, messageId: string): Promise<boolean> {
    if (!isCanonicalAuthUsername(peerUsername) || sanitizeMessageId(messageId) !== messageId) return false;
    await this.checkReady(account);
    this.pruneExpired();
    const key = entryKey(peerUsername, messageId);
    const existing = this.entries.get(key);
    if (!existing) return false;
    const { sentAt: _sentAt, ...pendingEntry } = existing;
    this.entries.delete(key);
    this.entries.set(key, pendingEntry);
    await this.persistSnapshot();
    if (account !== this.activeAccount) return false;
    receiptBatcher.queueDelivery(account, peerUsername, messageId);
    this.scheduleRetry();
    return true;
  }

  private async markSent(account: string, peerUsername: string, messageIds: string[]): Promise<void> {
    if (account !== this.activeAccount || !isCanonicalAuthUsername(peerUsername)) return;
    await this.restorePromise;
    if (account !== this.activeAccount || this.restoreState !== 'ready') return;
    const now = Date.now();
    let changed = false;
    for (const messageId of messageIds) {
      const key = entryKey(peerUsername, messageId);
      const entry = this.entries.get(key);
      if (!entry) continue;
      this.entries.delete(key);
      this.entries.set(key, { ...entry, sentAt: now });
      changed = true;
    }
    if (changed) await this.persistSnapshot().catch(() => { });
    this.scheduleRetry();
  }

  private queuePendingEntries(): void {
    const account = this.activeAccount;
    if (!account || this.restoreState !== 'ready') return;
    for (const entry of this.entries.values()) {
      if (entry.sentAt === undefined) {
        receiptBatcher.queueDelivery(account, entry.peerUsername, entry.messageId);
      }
    }
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (!this.activeAccount || this.restoreState !== 'ready') return;
    if (this.entries.size === 0) {
      this.clearRetryTimer();
      return;
    }
    const account = this.activeAccount;
    const generation = this.generation;
    const now = Date.now();
    let hasPending = false;
    let earliestSentExpiry = Number.POSITIVE_INFINITY;
    for (const entry of this.entries.values()) {
      if (entry.sentAt === undefined) {
        hasPending = true;
        break;
      }
      earliestSentExpiry = Math.min(earliestSentExpiry, entry.sentAt + SENT_RECEIPT_RETENTION_MS);
    }
    const delay = hasPending
      ? RETRY_INTERVAL_MS
      : Math.max(1_000, earliestSentExpiry - now);
    const dueAt = now + delay;
    if (this.retryTimer && this.retryTimerDueAt !== null && this.retryTimerDueAt <= dueAt) return;
    this.clearRetryTimer();
    this.retryTimerDueAt = dueAt;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      this.retryTimerDueAt = null;
      if (account !== this.activeAccount || generation !== this.generation) return;
      if (this.pruneExpired()) void this.persistSnapshot().catch(() => { });
      this.queuePendingEntries();
    }, delay);
  }

  private clearRetryTimer(): void {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    this.retryTimerDueAt = null;
  }

  private clearRestoreRetryTimer(): void {
    if (this.restoreRetryTimer) clearTimeout(this.restoreRetryTimer);
    this.restoreRetryTimer = null;
  }
}

export const deliveryReceiptOutbox = new DeliveryReceiptOutbox();

window.addEventListener(EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT, () => {
  deliveryReceiptOutbox.setActiveAccount(null);
});
