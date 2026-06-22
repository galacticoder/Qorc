import { SignalType } from '../../lib/types/signal-types';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { RECEIPT_BATCH_WINDOW_MS } from '../../lib/constants';

// Coalesces delivery/read receipts per peer into 1 fully signed message that carries lists of message IDs

type PeerBatch = {
  delivered: Set<string>;
  read: Set<string>;
  timer: ReturnType<typeof setTimeout> | null;
  retriedOnce: Set<string>;
};

class ReceiptBatcher {
  private peers = new Map<string, PeerBatch>();
  private lastFlushAt = new Map<string, number>();

  queueDelivery(peer: string, messageId: string): void {
    this.enqueue(peer, 'delivered', messageId);
  }

  queueRead(peer: string, messageId: string): void {
    this.enqueue(peer, 'read', messageId);
  }

  private getBatch(peer: string): PeerBatch {
    let batch = this.peers.get(peer);
    if (!batch) {
      batch = { delivered: new Set(), read: new Set(), timer: null, retriedOnce: new Set() };
      this.peers.set(peer, batch);
    }
    return batch;
  }

  private enqueue(peer: string, kind: 'delivered' | 'read', messageId: string): void {
    if (!peer || typeof messageId !== 'string' || !messageId) return;
    const batch = this.getBatch(peer);
    batch[kind].add(messageId);
    this.scheduleFlush(peer, batch);
  }

  private scheduleFlush(peer: string, batch: PeerBatch): void {
    if (batch.timer) return;
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
    if (!batch) return;
    batch.timer = null;
    
    this.lastFlushAt.set(peer, Date.now());

    const deliveredIds = Array.from(batch.delivered);
    const readIds = Array.from(batch.read);
    batch.delivered.clear();
    batch.read.clear();

    if (deliveredIds.length === 0 && readIds.length === 0) {
      if (!batch.timer) { this.peers.delete(peer); this.lastFlushAt.delete(peer); }
      return;
    }

    try {
      const result = await unifiedSignalTransport.send(
        peer,
        { type: SignalType.RECEIPT_BATCH, deliveredIds, readIds, timestamp: Date.now() },
        SignalType.RECEIPT_BATCH
      );
      if (!result?.success) throw new Error(result?.error || 'receipt batch send failed');

      // Delivered — clear retry tracking for everything we just sent.
      for (const id of deliveredIds) batch.retriedOnce.delete(`d:${id}`);
      for (const id of readIds) batch.retriedOnce.delete(`r:${id}`);
    } catch {
      for (const id of deliveredIds) {
        const k = `d:${id}`;
        if (!batch.retriedOnce.has(k)) { batch.retriedOnce.add(k); batch.delivered.add(id); }
      }
      for (const id of readIds) {
        const k = `r:${id}`;
        if (!batch.retriedOnce.has(k)) { batch.retriedOnce.add(k); batch.read.add(id); }
      }
      if (batch.delivered.size > 0 || batch.read.size > 0) {
        this.scheduleFlush(peer, batch);
      }
    } finally {
      const b = this.peers.get(peer);
      if (b && b.delivered.size === 0 && b.read.size === 0 && !b.timer) {
        this.peers.delete(peer);
        this.lastFlushAt.delete(peer);
      }
    }
  }
}

export const receiptBatcher = new ReceiptBatcher();
