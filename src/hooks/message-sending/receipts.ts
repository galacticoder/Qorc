import React from 'react';
import { Message } from '../../components/chat/messaging/types';
import { RECEIPT_RETENTION_MS } from '../../lib/constants';
import type { ReceiptEventDetail, ReceiptUpdater, DbQueuedReceipt } from '../../lib/types/message-sending-types';
import { setMessagesWithResult } from '../../lib/utils/set-messages-result';
import {
  hasPrototypePollutionKeys,
  isCanonicalAuthUsername,
  isPlainObject,
  sanitizeMessageId,
} from '../../lib/sanitizers';

export const MAX_PENDING_RECEIPTS = 512;
export const IN_MEMORY_PENDING_RECEIPT_TTL_MS = 10 * 60 * 1000;
export const MAX_SENT_RECEIPT_HISTORY = 4096;

export const receiptScopeKey = (peer: string, messageId: string): string => (
  `${peer.length}:${peer}${messageId}`
);

// Type guard for receipt event detail
export const isReceiptEventDetail = (value: unknown): value is ReceiptEventDetail => {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) return false;
  if (Object.keys(value).sort().join(',') !== 'account,from,messageId') return false;
  return isCanonicalAuthUsername(value.account) &&
    isCanonicalAuthUsername(value.from) &&
    value.account !== value.from &&
    sanitizeMessageId(value.messageId) === value.messageId;
};

// Build smart status map showing only the latest read/delivered per peer
export const buildSmartStatusMap = (messages: Message[], currentUsername: string) => {
  const map = new Map<string, Message['receipt']>();

  // Track latest read and delivered per peer
  const latestReadPerPeer = new Map<string, { id: string; timestamp: number; receipt: Message['receipt'] }>();
  const latestDeliveredPerPeer = new Map<string, { id: string; timestamp: number; receipt: Message['receipt'] }>();

  for (const msg of messages) {
    if (msg.sender !== currentUsername || !msg.receipt) continue;
    const peer = msg.recipient || '';
    if (!peer) continue;

    const timestamp = msg.timestamp instanceof Date ? msg.timestamp.getTime() : new Date(msg.timestamp).getTime();
    if (isNaN(timestamp)) continue;

    // Track latest read message per peer
    if (msg.receipt.read) {
      const existing = latestReadPerPeer.get(peer);
      if (!existing || timestamp > existing.timestamp) {
        latestReadPerPeer.set(peer, { id: msg.id, timestamp, receipt: msg.receipt });
      }
    }

    // Track latest delivered message per peer
    if (msg.receipt.delivered && !msg.receipt.read) {
      const existing = latestDeliveredPerPeer.get(peer);
      if (!existing || timestamp > existing.timestamp) {
        latestDeliveredPerPeer.set(peer, { id: msg.id, timestamp, receipt: msg.receipt });
      }
    }
  }

  for (const [, readInfo] of latestReadPerPeer) {
    map.set(readInfo.id, { ...readInfo.receipt, read: true });
  }

  for (const [peer, deliveredInfo] of latestDeliveredPerPeer) {
    const readInfo = latestReadPerPeer.get(peer);
    if (!readInfo || deliveredInfo.timestamp > readInfo.timestamp) {
      map.set(deliveredInfo.id, { ...deliveredInfo.receipt, delivered: true });
    }
  }

  return map;
};

// Mark receipt as sent
export const markReceiptSent = (store: Map<string, number>, peer: string, messageId: string) => {
  const key = receiptScopeKey(peer, messageId);
  if (!store.has(key)) {
    while (store.size >= MAX_SENT_RECEIPT_HISTORY) {
      const oldest = store.keys().next().value;
      if (typeof oldest !== 'string') break;
      store.delete(oldest);
    }
  } else {
    store.delete(key);
  }
  store.set(key, Date.now());
};

// Check if receipt was recently sent
export const hasRecentReceipt = (store: Map<string, number>, peer: string, messageId: string) => {
  const key = receiptScopeKey(peer, messageId);
  const timestamp = store.get(key);
  if (!timestamp) return false;
  if (Date.now() - timestamp > RECEIPT_RETENTION_MS) {
    store.delete(key);
    return false;
  }
  return true;
};

// Prune old receipts from store
export const pruneOldReceipts = (store: Map<string, number>) => {
  const cutoff = Date.now() - RECEIPT_RETENTION_MS;
  for (const [messageId, timestamp] of store.entries()) {
    if (timestamp < cutoff) {
      store.delete(messageId);
    }
  }
};

// Update message receipt in state and optionally queue for DB flush
export const receiptOwnershipOk = (
  target: { sender?: string; recipient?: string },
  from?: string,
  selfUsername?: string,
): boolean => {
  if (!from || !selfUsername) return true; // no identity to check against
  return target.sender === selfUsername && target.recipient === from;
};

export const updateMessageReceipt = async (
  messageIndexRef: React.RefObject<Map<string, number>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  messageId: string,
  updater: ReceiptUpdater,
  dbReceiptQueueRef: React.RefObject<Map<string, DbQueuedReceipt>>,
  dbFlushTimeoutRef: React.RefObject<ReturnType<typeof setTimeout> | null>,
  flushDBReceiptsRef: React.RefObject<(() => Promise<void>) | null>,
  from?: string,
  selfUsername?: string,
  queueKind?: 'delivered' | 'read',
): Promise<{
  message: Message | null;
  status: 'updated' | 'unchanged' | 'missing' | 'rejected';
}> => {
  const stateResult = await setMessagesWithResult<{
    message: Message | null;
    status: 'updated' | 'unchanged' | 'missing' | 'rejected';
  }>(setMessages, (prev) => {
    let index = messageIndexRef.current.get(messageId);
    const indexedTarget = index === undefined ? undefined : prev[index];
    if (
      !indexedTarget ||
      indexedTarget.id !== messageId ||
      !receiptOwnershipOk(indexedTarget, from, selfUsername)
    ) {
      const liveIndex = prev.findIndex((message) => (
        message.id === messageId && receiptOwnershipOk(message, from, selfUsername)
      ));
      index = liveIndex === -1 ? undefined : liveIndex;
    }
    if (index === undefined) {
      const hasCollidingId = prev.some((message) => message.id === messageId);
      return {
        next: prev,
        result: { message: null, status: hasCollidingId ? 'rejected' : 'missing' },
      };
    }

    const target = prev[index];
    if (!receiptOwnershipOk(target, from, selfUsername)) {
      return { next: prev, result: { message: null, status: 'rejected' } };
    }
    const nextReceipt = updater(target.receipt);
    if (nextReceipt === target.receipt) {
      return { next: prev, result: { message: null, status: 'unchanged' } };
    }

    const updatedMessage = { ...target, receipt: nextReceipt };
    const next = [...prev];
    next[index] = updatedMessage;
    return { next, result: { message: updatedMessage, status: 'updated' } };
  });
  if (stateResult.status !== 'missing') return stateResult;

  {
    if (
      queueKind && from && selfUsername
    ) {
      const queueKey = receiptScopeKey(from || '', messageId);
      if (!dbReceiptQueueRef.current.has(queueKey) &&
        dbReceiptQueueRef.current.size >= MAX_PENDING_RECEIPTS) {
        return { message: null, status: 'missing' };
      }
      const existing = dbReceiptQueueRef.current.get(queueKey);
      dbReceiptQueueRef.current.set(queueKey, {
        messageId,
        kind: existing?.kind === 'read' || queueKind === 'read' ? 'read' : 'delivered',
        from,
        addedAt: existing?.addedAt || Date.now(),
        attempts: existing?.attempts || 0,
      });
      
      if (!dbFlushTimeoutRef.current) {
        dbFlushTimeoutRef.current = setTimeout(() => {
          dbFlushTimeoutRef.current = null;
          const flushFn = flushDBReceiptsRef.current;
          if (flushFn) void flushFn();
        }, 500);
      }
    }
  }

  return stateResult;
};
