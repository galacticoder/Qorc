import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { AUTH_USERNAME_REGEX, RECEIPT_BATCH_WINDOW_MS, MAX_RECEIPT_BATCH_IDS } from '../../lib/constants';
import { sanitizeMessageId } from '../../lib/sanitizers';
import { EventType } from '../../lib/types/event-types';

type PeerBatch = {
  delivered: Set<string>;
  read: Set<string>;
  timer: ReturnType<typeof setTimeout> | null;
  attempts: Map<string, number>;
  flushing: boolean;
};

const MAX_FLUSH_ATTEMPTS = 5;
const MAX_BATCHED_PEERS = 256;

type FlushListener = (account: string, peer: string, deliveredIds: string[], readIds: string[]) => void;

export class ReceiptBatcher {
  private peers = new Map<string, PeerBatch>();
  private lastFlushAt = new Map<string, number>();
  private flushListeners = new Set<FlushListener>();
  private generation = 0;
  private activeAccount: string | null = null;

  addFlushListener(cb: FlushListener): () => void {
    this.flushListeners.add(cb);
    return () => { this.flushListeners.delete(cb); };
  }

  queueDelivery(account: string, peer: string, messageId: string): boolean {
    return this.enqueue(account, peer, 'delivered', messageId);
  }

  queueRead(account: string, peer: string, messageId: string): boolean {
    return this.enqueue(account, peer, 'read', messageId);
  }

  hasPendingRead(account: string, peer: string, messageId: string): boolean {
    return account === this.activeAccount && this.peers.get(peer)?.read.has(messageId) === true;
  }

  purgePeer(peer: string): void {
    const batch = this.peers.get(peer);
    if (batch?.timer) clearTimeout(batch.timer);
    if (batch) {
      batch.timer = null;
      batch.delivered.clear();
      batch.read.clear();
      batch.attempts.clear();
    }
    this.peers.delete(peer);
    this.lastFlushAt.delete(peer);
  }

  private getBatch(peer: string): PeerBatch | null {
    let batch = this.peers.get(peer);
    if (!batch) {
      if (this.peers.size >= MAX_BATCHED_PEERS) return null;
      batch = { delivered: new Set(), read: new Set(), timer: null, attempts: new Map(), flushing: false };
      this.peers.set(peer, batch);
    }
    return batch;
  }

  private enqueue(account: string, peer: string, kind: 'delivered' | 'read', messageId: string): boolean {
    if (
      account !== this.activeAccount ||
      account !== account.trim().toLowerCase() ||
      peer !== peer.trim().toLowerCase() ||
      !AUTH_USERNAME_REGEX.test(account) ||
      !AUTH_USERNAME_REGEX.test(peer) ||
      sanitizeMessageId(messageId) !== messageId
    ) return false;
    const batch = this.getBatch(peer);
    if (!batch) return false;
    if (kind === 'read') {
      batch.delivered.delete(messageId);
    } else if (batch.read.has(messageId)) {
      return true;
    }
    if (!batch[kind].has(messageId) && batch.delivered.size + batch.read.size >= MAX_RECEIPT_BATCH_IDS) {
      return false;
    }
    batch[kind].add(messageId);
    
    if (batch.delivered.size + batch.read.size >= MAX_RECEIPT_BATCH_IDS) {
      if (batch.timer) { clearTimeout(batch.timer); batch.timer = null; }
      void this.flush(peer);
      return true;
    }
    this.scheduleFlush(peer, batch);
    return true;
  }

  private scheduleFlush(peer: string, batch: PeerBatch): void {
    if (batch.timer || batch.flushing) return;
    const now = Date.now();
    const sinceLast = now - (this.lastFlushAt.get(peer) || 0);
    if (sinceLast >= RECEIPT_BATCH_WINDOW_MS) {
      void this.flush(peer);
    } else {
      batch.timer = setTimeout(() => { void this.flush(peer); }, RECEIPT_BATCH_WINDOW_MS - sinceLast);
    }
  }

  private async flush(peer: string): Promise<void> {
    const batch = this.peers.get(peer);
    if (!batch || batch.flushing) return;
    const generation = this.generation;
    const account = this.activeAccount;
    if (!account) return;
    batch.timer = null;

    const deliveredIds = Array.from(batch.delivered);
    const readIds = Array.from(batch.read);
    if (deliveredIds.length === 0 && readIds.length === 0) {
      if (!batch.timer) { this.peers.delete(peer); this.lastFlushAt.delete(peer); }
      return;
    }
    batch.flushing = true;
    this.lastFlushAt.set(peer, Date.now());

    try {
      const result = await unifiedSignalTransport.send(
        peer,
        { deliveredIds, readIds },
        SignalType.RECEIPT_BATCH
      );
      if (generation !== this.generation || account !== this.activeAccount || this.peers.get(peer) !== batch) return;
      if (!result?.success) throw new Error(result?.error || 'receipt batch send failed');

      for (const id of deliveredIds) {
        batch.delivered.delete(id);
        batch.attempts.delete(`d:${id}`);
      }
      for (const id of readIds) {
        batch.read.delete(id);
        batch.attempts.delete(`r:${id}`);
      }
      for (const cb of Array.from(this.flushListeners)) {
        try { cb(account, peer, deliveredIds, readIds); } catch { }
      }
    } catch {
      if (generation !== this.generation || account !== this.activeAccount || this.peers.get(peer) !== batch) return;
      
      for (const id of deliveredIds) {
        const k = `d:${id}`;
        if (!batch.delivered.has(id)) {
          batch.attempts.delete(k);
          continue;
        }
        const n = (batch.attempts.get(k) || 0) + 1;
        if (n < MAX_FLUSH_ATTEMPTS) batch.attempts.set(k, n);
        else {
          batch.attempts.delete(k);
          batch.delivered.delete(id);
        }
      }
      for (const id of readIds) {
        const k = `r:${id}`;
        if (!batch.read.has(id)) {
          batch.attempts.delete(k);
          continue;
        }
        const n = (batch.attempts.get(k) || 0) + 1;
        if (n < MAX_FLUSH_ATTEMPTS) batch.attempts.set(k, n);
        else {
          batch.attempts.delete(k);
          batch.read.delete(id);
        }
      }
    } finally {
      batch.flushing = false;
      if (generation !== this.generation || account !== this.activeAccount || this.peers.get(peer) !== batch) return;
      const b = this.peers.get(peer);
      if (b && (b.delivered.size > 0 || b.read.size > 0)) {
        this.scheduleFlush(peer, b);
      } else if (b && !b.timer) {
        this.peers.delete(peer);
        this.lastFlushAt.delete(peer);
      }
    }
  }

  setActiveAccount(account: string | null): void {
    if (this.activeAccount === account) return;
    this.generation += 1;
    this.activeAccount = account;
    for (const batch of this.peers.values()) {
      if (batch.timer) clearTimeout(batch.timer);
      batch.delivered.clear();
      batch.read.clear();
      batch.attempts.clear();
      batch.flushing = false;
    }
    this.peers.clear();
    this.lastFlushAt.clear();
  }
}

export const receiptBatcher = new ReceiptBatcher();

window.addEventListener(EventType.KEY_TRANSPARENCY_SECURITY_INCIDENT, () => {
  receiptBatcher.setActiveAccount(null);
});
