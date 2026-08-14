import React, { useEffect, useCallback, useMemo, useRef } from 'react';
import { Message } from '../../components/chat/messaging/types';
import { EventType } from '../../lib/types/event-types';
import { isCanonicalAuthUsername, sanitizeMessageId } from '../../lib/sanitizers';
import { RECEIPT_RETENTION_MS, RATE_LIMIT_MAX_RECEIPTS, RATE_LIMIT_WINDOW_MS } from '../../lib/constants';
import type { RateLimitBucket, PendingReceiptInfo, DbQueuedReceipt } from '../../lib/types/message-sending-types';
import {
  isReceiptEventDetail,
  buildSmartStatusMap,
  markReceiptSent,
  hasRecentReceipt,
  pruneOldReceipts,
  receiptOwnershipOk,
  updateMessageReceipt,
  receiptScopeKey,
  MAX_PENDING_RECEIPTS,
  IN_MEMORY_PENDING_RECEIPT_TTL_MS
} from './receipts';
import { receiptBatcher } from '../message-handling/receipt-batcher';

const MAX_DB_RECEIPT_ATTEMPTS = 8;
const READ_RECEIPT_RETRY_INTERVAL_MS = 1000;
const READ_RECEIPT_BACKOFF_BASE_MS = 1000;
const READ_RECEIPT_BACKOFF_MAX_MS = 60_000;

const readReceiptRetryDelayMs = (attempts: number): number => Math.min(
  READ_RECEIPT_BACKOFF_MAX_MS,
  READ_RECEIPT_BACKOFF_BASE_MS * 2 ** Math.min(attempts, 16),
);

type PendingOutgoingReadReceipt = {
  peer: string;
  messageId: string;
  addedAt: number;
  attempts: number;
  nextAttemptAt: number;
};

const applyQueuedReceipt = (target: Message, entry: DbQueuedReceipt): Message => {
  const receipt = target.receipt;
  const now = new Date();
  if (entry.kind === 'read') {
    if (receipt?.read && receipt.delivered) return target;
    return {
      ...target,
      receipt: {
        ...receipt,
        delivered: true,
        deliveredAt: receipt?.deliveredAt || now,
        read: true,
        readAt: receipt?.readAt || now,
      },
    };
  }
  if (receipt?.delivered) return target;
  return { ...target, receipt: { ...receipt, delivered: true, deliveredAt: now } };
};

export function useMessageReceipts(
  messages: Message[],
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  currentUsername: string,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  secureDBRef?: React.RefObject<any>,
) {
  const sentReceiptsRef = useRef<Map<string, number>>(new Map());
  const messageIndexRef = useRef<Map<string, number>>(new Map());
  const rateLimitRef = useRef<RateLimitBucket>({ windowStart: Date.now(), count: 0 });
  const pendingReceiptsRef = useRef<Map<string, PendingReceiptInfo>>(new Map());
  const pendingOutgoingReadsRef = useRef<Map<string, PendingOutgoingReadReceipt>>(new Map());
  const dbReceiptQueueRef = useRef<Map<string, DbQueuedReceipt>>(new Map());
  const dbFlushTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushDBReceiptsRef = useRef<(() => Promise<void>) | null>(null);
  const dbFlushOwnerRef = useRef<object | null>(null);
  const activeAccountRef = useRef<string | null>(null);
  const accountGenerationRef = useRef(0);

  useEffect(() => {
    const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
    if (activeAccountRef.current === account) return;
    activeAccountRef.current = account;
    accountGenerationRef.current += 1;
    sentReceiptsRef.current.clear();
    messageIndexRef.current.clear();
    rateLimitRef.current = { windowStart: Date.now(), count: 0 };
    pendingReceiptsRef.current.clear();
    pendingOutgoingReadsRef.current.clear();
    dbReceiptQueueRef.current.clear();
    dbFlushOwnerRef.current = null;
    if (dbFlushTimeoutRef.current) clearTimeout(dbFlushTimeoutRef.current);
    dbFlushTimeoutRef.current = null;
  }, [currentUsername]);

  // Mark read receipts as sent only after their batch is confirmed delivered
  useEffect(() => {
    const unsubscribe = receiptBatcher.addFlushListener((account, peer, _deliveredIds, readIds) => {
      if (account !== activeAccountRef.current) return;
      for (const id of readIds) {
        try {
          markReceiptSent(sentReceiptsRef.current, peer, id);
          pendingOutgoingReadsRef.current.delete(receiptScopeKey(peer, id));
        } catch { }
      }
    });
    return unsubscribe;
  }, []);

  useEffect(() => {
    const flushDBReceipts = async () => {
      if (!secureDBRef?.current || dbReceiptQueueRef.current.size === 0) return;
      if (dbFlushOwnerRef.current) return;
      const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
      const generation = accountGenerationRef.current;
      const db = secureDBRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account &&
        secureDBRef.current === db
      );
      if (!isCurrent()) return;
      const flushOwner = {};
      dbFlushOwnerRef.current = flushOwner;

      const queue = new Map(dbReceiptQueueRef.current);
      dbReceiptQueueRef.current.clear();

      const requeue = (queueKey: string, entry: DbQueuedReceipt): void => {
        const attempts = entry.attempts + 1;
        if (
          attempts >= MAX_DB_RECEIPT_ATTEMPTS ||
          Date.now() - entry.addedAt > IN_MEMORY_PENDING_RECEIPT_TTL_MS
        ) return;
        const current = dbReceiptQueueRef.current.get(queueKey);
        if (!current && dbReceiptQueueRef.current.size >= MAX_PENDING_RECEIPTS) return;
        dbReceiptQueueRef.current.set(queueKey, {
          messageId: entry.messageId,
          kind: current?.kind === 'read' || entry.kind === 'read' ? 'read' : 'delivered',
          from: current?.from || entry.from,
          addedAt: Math.min(current?.addedAt ?? entry.addedAt, entry.addedAt),
          attempts: Math.max(current?.attempts ?? 0, attempts),
        });
      };

      const scheduleRetry = (): void => {
        if (!isCurrent() || dbReceiptQueueRef.current.size === 0 || dbFlushTimeoutRef.current) return;
        const attempts = Math.min(...Array.from(dbReceiptQueueRef.current.values(), entry => entry.attempts));
        const delay = Math.min(1000 * (2 ** Math.min(attempts, 5)), 30_000);
        dbFlushTimeoutRef.current = setTimeout(() => {
          dbFlushTimeoutRef.current = null;
          void flushDBReceiptsRef.current?.();
        }, delay);
      };

      try {
        const byPeer = new Map<string, Array<[string, DbQueuedReceipt]>>();
        for (const item of queue) {
          const [, entry] = item;
          if (Date.now() - entry.addedAt > IN_MEMORY_PENDING_RECEIPT_TTL_MS) continue;
          const entries = byPeer.get(entry.from) || [];
          entries.push(item);
          byPeer.set(entry.from, entries);
        }

        for (const [peer, entries] of byPeer) {
          if (!isCurrent()) return;
          const mutations = new Map<string, (target: Message) => Message>();
          for (const [, entry] of entries) {
            mutations.set(entry.messageId, (target) => {
              if (!receiptOwnershipOk(target, peer, account)) return target;
              return applyQueuedReceipt(target, entry);
            });
          }
          const found: Set<string> = await db.updateConversationMessages(peer, mutations);
          if (!isCurrent()) return;
          for (const [queueKey, entry] of entries) {
            if (!found.has(entry.messageId)) requeue(queueKey, entry);
          }
        }

      } catch (err) {
        if (isCurrent()) {
          for (const [queueKey, entry] of queue) {
            requeue(queueKey, entry);
          }
          console.error('[Receipts] Failed to flush DB receipt queue', { queueSize: queue.size, error: err });
        }
      } finally {
        if (dbFlushOwnerRef.current === flushOwner) dbFlushOwnerRef.current = null;
        scheduleRetry();
      }
    };

    flushDBReceiptsRef.current = flushDBReceipts;
  }, [secureDBRef, currentUsername]);

  useEffect(() => {
    const indexMap = new Map<string, number>();
    messages.forEach((msg, idx) => {
      indexMap.set(msg.id, idx);
    });
    messageIndexRef.current = indexMap;

    if (pendingReceiptsRef.current.size > 0) {
      const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account
      );
      const now = Date.now();
      const entries = Array.from(pendingReceiptsRef.current.entries());
      for (const [pendingKey, meta] of entries) {
        const safeId = sanitizeMessageId(meta.messageId);
        if (!safeId || now - meta.addedAt > IN_MEMORY_PENDING_RECEIPT_TTL_MS) {
          pendingReceiptsRef.current.delete(pendingKey);
          continue;
        }
        const apply = async () => {
          if (!isCurrent()) return;
          const result = await updateMessageReceipt(
            messageIndexRef,
            setMessages,
            safeId,
            (receipt) => {
              if (meta.kind === 'delivered') {
                if (receipt?.delivered) return receipt;
                return { ...receipt, delivered: true, deliveredAt: new Date() };
              }
              if (receipt?.read) return receipt;
              return {
                ...receipt,
                delivered: true,
                deliveredAt: receipt?.deliveredAt || new Date(),
                read: true,
                readAt: new Date(),
              };
            },
            dbReceiptQueueRef,
            dbFlushTimeoutRef,
            flushDBReceiptsRef,
            meta.from,
            account || undefined,
            meta.kind,
          );
          if (!isCurrent()) return;
          if (result.message) {
            try {
              await saveMessageToLocalDB(result.message);
              if (isCurrent()) pendingReceiptsRef.current.delete(pendingKey);
            } catch { }
          } else if (result.status === 'missing') {
            const next = { ...meta, attempts: (meta.attempts || 0) + 1 };
            if (next.attempts >= 5) {
              pendingReceiptsRef.current.delete(pendingKey);
            } else {
              pendingReceiptsRef.current.set(pendingKey, next);
            }
          } else {
            pendingReceiptsRef.current.delete(pendingKey);
          }
        };
        void apply();
      }
    }
  }, [messages, secureDBRef, saveMessageToLocalDB, currentUsername]);

  useEffect(() => {
    const interval = setInterval(() => pruneOldReceipts(sentReceiptsRef.current), RECEIPT_RETENTION_MS);
    return () => {
      try {
        clearInterval(interval);
      } catch {
      }
    };
  }, []);

  const smartStatusMap = useMemo(() => buildSmartStatusMap(messages, currentUsername), [messages, currentUsername]);

  const getSmartReceiptStatus = useCallback(
    (message: Message) => smartStatusMap.get(message.id),
    [smartStatusMap],
  );

  const flushPendingOutgoingReads = useCallback(() => {
    const account = activeAccountRef.current;
    if (!account) return;
    const now = Date.now();
    const bucket = rateLimitRef.current;
    if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
      bucket.windowStart = now;
      bucket.count = 0;
    }

    for (const [key, entry] of pendingOutgoingReadsRef.current) {
      if (now - entry.addedAt > IN_MEMORY_PENDING_RECEIPT_TTL_MS) {
        pendingOutgoingReadsRef.current.delete(key);
        continue;
      }
      if (hasRecentReceipt(sentReceiptsRef.current, entry.peer, entry.messageId)) {
        pendingOutgoingReadsRef.current.delete(key);
        continue;
      }
      if (receiptBatcher.hasPendingRead(account, entry.peer, entry.messageId)) continue;
      
      if (now < entry.nextAttemptAt) continue;
      if (bucket.count >= RATE_LIMIT_MAX_RECEIPTS) break;
      if (receiptBatcher.queueRead(account, entry.peer, entry.messageId)) {
        bucket.count += 1;
        const attempts = entry.attempts + 1;
        pendingOutgoingReadsRef.current.set(key, {
          ...entry,
          attempts,
          nextAttemptAt: now + readReceiptRetryDelayMs(attempts),
        });
      }
    }
  }, []);

  useEffect(() => {
    const interval = setInterval(flushPendingOutgoingReads, READ_RECEIPT_RETRY_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [flushPendingOutgoingReads]);

  const sendReadReceipt = useCallback(
    async (messageId: string, sender: string) => {
      const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account
      );
      if (!isCurrent()) return;
      const safeMessageId = sanitizeMessageId(messageId);
      const safeSender = isCanonicalAuthUsername(sender) ? sender : null;
      if (!safeMessageId || !safeSender) {
        return;
      }
      if (safeSender === account) {
        return;
      }
      if (hasRecentReceipt(sentReceiptsRef.current, safeSender, safeMessageId)) {
        return;
      }

      const pendingKey = receiptScopeKey(safeSender, safeMessageId);
      if (!pendingOutgoingReadsRef.current.has(pendingKey)) {
        const now = Date.now();
        for (const [key, entry] of pendingOutgoingReadsRef.current) {
          if (now - entry.addedAt > IN_MEMORY_PENDING_RECEIPT_TTL_MS) {
            pendingOutgoingReadsRef.current.delete(key);
          }
        }
        if (pendingOutgoingReadsRef.current.size >= MAX_PENDING_RECEIPTS) return;
        pendingOutgoingReadsRef.current.set(pendingKey, {
          peer: safeSender,
          messageId: safeMessageId,
          addedAt: now,
          attempts: 0,
          nextAttemptAt: now,
        });
      }
      flushPendingOutgoingReads();
    },
    [currentUsername, flushPendingOutgoingReads],
  );

  const markMessageAsRead = useCallback(
    async (messageId: string) => {
      const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account
      );
      if (!isCurrent()) return;
      const safeMessageId = sanitizeMessageId(messageId);
      if (!safeMessageId) return;

      const result = await updateMessageReceipt(
        messageIndexRef,
        setMessages,
        safeMessageId,
        (receipt) => {
          if (receipt?.read) {
            return receipt;
          }
          return {
            ...receipt,
            delivered: true,
            deliveredAt: receipt?.deliveredAt || new Date(),
            read: true,
            readAt: new Date(),
          };
        },
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
        undefined,
        undefined,
        'read',
      );
      if (!isCurrent()) return;

      if (result.message) {
        try {
          await saveMessageToLocalDB(result.message);
        } catch { }
      }
    },
    [setMessages, saveMessageToLocalDB, currentUsername],
  );

  useEffect(() => {
    const handler = async (event: Event) => {
      const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account
      );
      if (!isCurrent()) return;
      const customEvent = event as CustomEvent;
      if (!isReceiptEventDetail(customEvent.detail)) {
        return;
      }
      const detail = customEvent.detail;
      if (detail.account !== account) return;
      const from = detail.from;
      const safeMessageId = sanitizeMessageId(detail.messageId);

      if (!safeMessageId || !from) {
        return;
      }

      const result = await updateMessageReceipt(
        messageIndexRef,
        setMessages,
        safeMessageId,
        (receipt) => {
          if (receipt?.delivered) {
            return receipt;
          }
          return {
            ...receipt,
            delivered: true,
            deliveredAt: new Date(),
          };
        },
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
        from,
        account,
        'delivered',
      );
      if (!isCurrent()) return;

      if (result.message) {
        try {
          await saveMessageToLocalDB(result.message);
        } catch { }
      } else if (result.status === 'missing') {
        const pendingKey = receiptScopeKey(from, safeMessageId);
        const existing = pendingReceiptsRef.current.get(pendingKey);
        if (existing || pendingReceiptsRef.current.size < MAX_PENDING_RECEIPTS) {
          pendingReceiptsRef.current.set(pendingKey, {
            messageId: safeMessageId,
            kind: existing?.kind === 'read' ? 'read' : 'delivered',
            addedAt: existing?.addedAt || Date.now(),
            attempts: existing?.attempts || 1,
            from,
          });
        }
      }
    };

    window.addEventListener(EventType.MESSAGE_DELIVERED, handler as EventListener);
    return () => window.removeEventListener(EventType.MESSAGE_DELIVERED, handler as EventListener);
  }, [setMessages, saveMessageToLocalDB, currentUsername]);

  useEffect(() => {
    const handler = async (event: Event) => {
      const account = isCanonicalAuthUsername(currentUsername) ? currentUsername : null;
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account
      );
      if (!isCurrent()) return;
      const customEvent = event as CustomEvent;

      if (!isReceiptEventDetail(customEvent.detail)) {
        return;
      }

      const detail = customEvent.detail;
      if (detail.account !== account) return;
      const from = detail.from;
      const safeMessageId = sanitizeMessageId(detail.messageId);

      if (!safeMessageId || !from) {
        return;
      }

      const result = await updateMessageReceipt(
        messageIndexRef,
        setMessages,
        safeMessageId,
        (receipt) => {
          if (receipt?.read) {
            return receipt;
          }
          return {
            ...receipt,
            delivered: true,
            deliveredAt: receipt?.deliveredAt || new Date(),
            read: true,
            readAt: new Date(),
          };
        },
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
        from,
        account,
        'read',
      );
      if (!isCurrent()) return;

      if (result.message) {
        try {
          await saveMessageToLocalDB(result.message);
        } catch { }
      } else if (result.status === 'missing') {
        const pendingKey = receiptScopeKey(from, safeMessageId);
        const existing = pendingReceiptsRef.current.get(pendingKey);
        if (existing || pendingReceiptsRef.current.size < MAX_PENDING_RECEIPTS) {
          pendingReceiptsRef.current.set(pendingKey, {
            messageId: safeMessageId,
            kind: 'read',
            addedAt: existing?.addedAt || Date.now(),
            attempts: existing?.attempts || 1,
            from,
          });
        }
      }
    };

    window.addEventListener(EventType.MESSAGE_READ, handler as EventListener);
    return () => window.removeEventListener(EventType.MESSAGE_READ, handler as EventListener);
  }, [setMessages, saveMessageToLocalDB, currentUsername]);

  useEffect(() => {
    pruneOldReceipts(sentReceiptsRef.current);
  }, [messages]);

  return {
    sendReadReceipt,
    markMessageAsRead,
    getSmartReceiptStatus,
  };
}
