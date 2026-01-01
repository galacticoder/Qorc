import React, { useEffect, useCallback, useMemo, useRef } from 'react';
import { Message } from '../../components/chat/messaging/types';
import type { User } from '../../components/chat/messaging/UserList';
import { SignalType } from '../../lib/signal-types';
import { EventType } from '../../lib/event-types';
import { sanitizeMessageId, sanitizeUsername } from '../../lib/sanitizers';
import { RECEIPT_RETENTION_MS, RATE_LIMIT_MAX_RECEIPTS, RATE_LIMIT_WINDOW_MS, READ_RECEIPT_PREFIX, DELIVERY_RECEIPT_PREFIX } from '../../lib/constants';
import type { RateLimitBucket, PendingReceiptInfo, ReceiptUpdater } from '../../lib/types/message-sending-types';
import {
  isReceiptEventDetail,
  buildSmartStatusMap,
  markReceiptSent,
  hasRecentReceipt,
  pruneOldReceipts,
  updateMessageReceipt
} from './receipts';
import { validateHybridKeys } from './validation';

export function useMessageReceipts(
  messages: Message[],
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  currentUsername: string,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  websocketClient: { send: (payload: string) => void; sendSecureControlMessage?: (msg: any) => Promise<void> },
  users: User[],
  getKeysOnDemand?: () => Promise<{
    x25519: { private: Uint8Array; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>,
  secureDBRef?: React.RefObject<any>,
) {
  const sentReceiptsRef = useRef<Map<string, number>>(new Map());
  const messageIndexRef = useRef<Map<string, number>>(new Map());
  const messagesRef = useRef<Message[]>(messages);
  const rateLimitRef = useRef<RateLimitBucket>({ windowStart: Date.now(), count: 0 });
  const pendingReceiptsRef = useRef<Map<string, PendingReceiptInfo>>(new Map());
  const dbReceiptQueueRef = useRef<Map<string, ReceiptUpdater>>(new Map());
  const dbFlushTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushDBReceiptsRef = useRef<(() => Promise<void>) | null>(null);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    const flushDBReceipts = async () => {
      if (!secureDBRef?.current || dbReceiptQueueRef.current.size === 0) return;

      const queue = new Map(dbReceiptQueueRef.current);
      dbReceiptQueueRef.current.clear();

      try {
        const allMessages = await secureDBRef.current.loadMessages().catch(() => []);
        let hasChanges = false;

        const unappliedUpdates = new Map<string, ReceiptUpdater>();

        for (const [messageId, updater] of queue.entries()) {
          const msgIndex = allMessages.findIndex((m: Message) => m.id === messageId);
          if (msgIndex !== -1) {
            const target = allMessages[msgIndex];
            const nextReceipt = updater(target.receipt);
            if (nextReceipt !== target.receipt) {
              allMessages[msgIndex] = { ...target, receipt: nextReceipt };
              hasChanges = true;
            }
          } else {
            unappliedUpdates.set(messageId, updater);
          }
        }

        if (unappliedUpdates.size > 0) {
          for (const [id, updater] of unappliedUpdates.entries()) {
            dbReceiptQueueRef.current.set(id, updater);
          }
        }

        if (hasChanges) {
          await secureDBRef.current.saveMessages(allMessages).catch(() => { });
        }
      } catch (err) {
        console.error('[Receipts] Failed to flush DB receipt queue', { queueSize: queue.size, error: err });
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
      const entries = Array.from(pendingReceiptsRef.current.entries());
      for (const [rawId, meta] of entries) {
        const safeId = sanitizeMessageId(rawId);
        if (!safeId) { pendingReceiptsRef.current.delete(rawId); continue; }
        const apply = async () => {
          const updated = await updateMessageReceipt(
            messageIndexRef,
            setMessages,
            safeId,
            (receipt) => {
              if (meta.kind === 'delivered') {
                if (receipt?.delivered) return receipt;
                return { ...receipt, delivered: true, deliveredAt: new Date() };
              }
              if (receipt?.read) return receipt;
              return { ...receipt, read: true, readAt: new Date() };
            },
            messagesRef,
            dbReceiptQueueRef,
            dbFlushTimeoutRef,
            flushDBReceiptsRef,
          );
          if (updated) {
            try { await saveMessageToLocalDB(updated); } catch { }
            pendingReceiptsRef.current.delete(rawId);
          } else {
            const next = { ...meta, attempts: (meta.attempts || 0) + 1 };
            if (next.attempts >= 5) {
              pendingReceiptsRef.current.delete(rawId);
            } else {
              pendingReceiptsRef.current.set(rawId, next);
            }
          }
        };
        void apply();
      }
    }
  }, [messages, secureDBRef, saveMessageToLocalDB]);

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

  const sendReadReceipt = useCallback(
    async (messageId: string, sender: string) => {
      const safeMessageId = sanitizeMessageId(messageId);
      const safeSender = sanitizeUsername(sender);
      if (!safeMessageId || !safeSender) {
        return;
      }
      if (safeSender === currentUsername) {
        return;
      }
      if (hasRecentReceipt(sentReceiptsRef.current, safeMessageId)) {
        return;
      }
      if (!getKeysOnDemand) {
        return;
      }

      const now = Date.now();
      const bucket = rateLimitRef.current;
      if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
        bucket.windowStart = now;
        bucket.count = 0;
      }
      bucket.count += 1;
      if (bucket.count > RATE_LIMIT_MAX_RECEIPTS) {
        return;
      }

      try {
        const user = users.find(u => u.username === safeSender);
        if (!user?.hybridPublicKeys || !validateHybridKeys(user.hybridPublicKeys)) {
          return;
        }

        const hybridKeys = user.hybridPublicKeys;

        const sessionCheck = await (window as any).edgeApi?.hasSession?.({
          selfUsername: currentUsername,
          peerUsername: safeSender,
          deviceId: 1,
        });

        if (!sessionCheck?.hasSession) {
          try {
            await websocketClient.sendSecureControlMessage?.({
              type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
              username: safeSender,
              from: currentUsername,
              timestamp: now,
            });
          } catch { }
          try {
            await new Promise<void>((resolve, reject) => {
              const timeout = setTimeout(() => { cleanup(); reject(new Error('bundle-timeout')); }, 6000);
              const onReady = (evt: Event) => {
                const d = (evt as CustomEvent).detail;
                if (d?.peer === safeSender) { cleanup(); resolve(); }
              };
              const cleanup = () => {
                clearTimeout(timeout);
                window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, onReady as EventListener);
              };
              window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, onReady as EventListener);
            });
          } catch { }
        }

        const readReceiptData = {
          messageId: `${READ_RECEIPT_PREFIX}${safeMessageId}`,
          from: currentUsername,
          to: safeSender,
          type: SignalType.READ_RECEIPT,
          timestamp: Date.now(),
        };

        const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
          fromUsername: currentUsername,
          toUsername: safeSender,
          plaintext: JSON.stringify(readReceiptData),
          recipientKyberPublicKey: hybridKeys.kyberPublicBase64,
          recipientHybridKeys: hybridKeys
        });

        if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
          return;
        }

        const readReceiptPayload = {
          type: SignalType.ENCRYPTED_MESSAGE,
          to: safeSender,
          encryptedPayload: encryptedMessage.encryptedPayload,
        };

        websocketClient.send(JSON.stringify(readReceiptPayload));

        markReceiptSent(sentReceiptsRef.current, safeMessageId);
      } catch { }
    },
    [currentUsername, websocketClient, users, getKeysOnDemand],
  );

  const markMessageAsRead = useCallback(
    async (messageId: string) => {
      const safeMessageId = sanitizeMessageId(messageId);
      if (!safeMessageId) return;

      const updated = await updateMessageReceipt(
        messageIndexRef,
        setMessages,
        safeMessageId,
        (receipt) => {
          if (receipt?.read) {
            return receipt;
          }
          return {
            ...receipt,
            read: true,
            readAt: new Date(),
          };
        },
        messagesRef,
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
      );

      if (updated) {
        try {
          await saveMessageToLocalDB(updated);
        } catch { }
      }
    },
    [setMessages, saveMessageToLocalDB],
  );

  useEffect(() => {
    const handler = async (event: Event) => {
      const customEvent = event as CustomEvent;
      if (!isReceiptEventDetail(customEvent.detail)) {
        return;
      }
      const detail = customEvent.detail;
      const rawId = detail.messageId || '';
      const safeMessageId = sanitizeMessageId(
        rawId.startsWith(DELIVERY_RECEIPT_PREFIX) ? rawId.replace(DELIVERY_RECEIPT_PREFIX, '') : rawId
      );
      if (!safeMessageId) {
        return;
      }

      const updated = await updateMessageReceipt(
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
        messagesRef,
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
      );

      if (updated) {
        try {
          await saveMessageToLocalDB(updated);
        } catch { }
      } else {
        pendingReceiptsRef.current.set(safeMessageId, { kind: 'delivered', addedAt: Date.now(), attempts: 1 });
      }
    };

    window.addEventListener(EventType.MESSAGE_DELIVERED, handler as EventListener);
    return () => window.removeEventListener(EventType.MESSAGE_DELIVERED, handler as EventListener);
  }, [setMessages, saveMessageToLocalDB]);

  useEffect(() => {
    const handler = async (event: Event) => {
      const customEvent = event as CustomEvent;
      if (!isReceiptEventDetail(customEvent.detail)) {
        return;
      }
      const detail = customEvent.detail;
      const rawId = detail.messageId || '';
      const safeMessageId = sanitizeMessageId(
        rawId.startsWith(READ_RECEIPT_PREFIX) ? rawId.replace(READ_RECEIPT_PREFIX, '') : rawId
      );
      if (!safeMessageId) {
        return;
      }

      const updated = await updateMessageReceipt(
        messageIndexRef,
        setMessages,
        safeMessageId,
        (receipt) => {
          if (receipt?.read) {
            return receipt;
          }
          return {
            ...receipt,
            read: true,
            readAt: new Date(),
          };
        },
        messagesRef,
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
      );

      if (updated) {
        try {
          await saveMessageToLocalDB(updated);
        } catch { }
      } else {
        pendingReceiptsRef.current.set(safeMessageId, { kind: 'read', addedAt: Date.now(), attempts: 1 });
      }
    };

    window.addEventListener(EventType.MESSAGE_READ, handler as EventListener);
    return () => window.removeEventListener(EventType.MESSAGE_READ, handler as EventListener);
  }, [setMessages, saveMessageToLocalDB]);

  useEffect(() => {
    pruneOldReceipts(sentReceiptsRef.current);
  }, [messages]);

  return {
    sendReadReceipt,
    markMessageAsRead,
    getSmartReceiptStatus,
  };
}
