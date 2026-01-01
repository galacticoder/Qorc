import React from 'react';
import { Message } from '../../components/chat/messaging/types';
import { RECEIPT_RETENTION_MS } from '../../lib/constants';
import type { ReceiptEventDetail, ReceiptUpdater } from '../../lib/types/message-sending-types';

// Type guard for receipt event detail
export const isReceiptEventDetail = (value: unknown): value is ReceiptEventDetail => {
  if (!value || typeof value !== 'object') return false;
  const detail = value as Record<string, unknown>;
  return typeof detail.messageId === 'string' && typeof detail.from === 'string';
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
export const markReceiptSent = (store: Map<string, number>, messageId: string) => {
  store.set(messageId, Date.now());
};

// Check if receipt was recently sent
export const hasRecentReceipt = (store: Map<string, number>, messageId: string) => {
  const timestamp = store.get(messageId);
  if (!timestamp) return false;
  if (Date.now() - timestamp > RECEIPT_RETENTION_MS) {
    store.delete(messageId);
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
export const updateMessageReceipt = async (
  messageIndexRef: React.RefObject<Map<string, number>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  messageId: string,
  updater: ReceiptUpdater,
  messagesRef: React.RefObject<Message[]>,
  dbReceiptQueueRef?: React.RefObject<Map<string, ReceiptUpdater>>,
  dbFlushTimeoutRef?: React.RefObject<ReturnType<typeof setTimeout> | null>,
  flushDBReceiptsRef?: React.RefObject<(() => Promise<void>) | null>,
): Promise<Message | null> => {
  const index = messageIndexRef.current.get(messageId);
  let updatedMessage: Message | null = null;

  if (index !== undefined) {
    const currentMessages = messagesRef.current;
    if (index >= 0 && index < currentMessages.length) {
      const target = currentMessages[index];
      const nextReceipt = updater(target.receipt);
      if (nextReceipt !== target.receipt) {
        updatedMessage = { ...target, receipt: nextReceipt };
      }
    }

    if (updatedMessage) {
      const msgToSet = updatedMessage;
      setMessages((prev) => {
        if (index < 0 || index >= prev.length) {
          return prev;
        }
        const next = [...prev];
        next[index] = msgToSet;
        return next;
      });
    }
  } else {
    if (dbReceiptQueueRef && dbFlushTimeoutRef && flushDBReceiptsRef) {
      dbReceiptQueueRef.current.set(messageId, updater);

      if (dbFlushTimeoutRef.current) {
        clearTimeout(dbFlushTimeoutRef.current);
      }
      dbFlushTimeoutRef.current = setTimeout(() => {
        const flushFn = flushDBReceiptsRef.current;
        if (flushFn) void flushFn();
      }, 500);
    }
  }

  return updatedMessage;
};
