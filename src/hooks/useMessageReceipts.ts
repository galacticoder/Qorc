import { useEffect, useCallback, useMemo, useRef } from 'react';
import { Message, User } from '@/components/chat/types';
import { SignalType } from '@/lib/signal-types';
import { sanitizeTextInput } from '@/lib/sanitizers';

const READ_RECEIPT_PREFIX = 'read-receipt-';
const DELIVERY_RECEIPT_PREFIX = 'delivery-receipt-';
const RECEIPT_RETENTION_MS = 24 * 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_RECEIPTS = 100;

const sanitizeUsername = (value: string | undefined) => {
  if (typeof value !== 'string') return undefined;
  const sanitized = sanitizeTextInput(value, { maxLength: 96, allowNewlines: false });
  return sanitized.length ? sanitized : undefined;
};

interface ReceiptEventDetail {
  messageId: string;
  from: string;
}

const isReceiptEventDetail = (value: unknown): value is ReceiptEventDetail => {
  if (!value || typeof value !== 'object') return false;
  const detail = value as Record<string, unknown>;
  return typeof detail.messageId === 'string' && typeof detail.from === 'string';
};

const sanitizeMessageId = (id: string | undefined) => {
  if (!id || typeof id !== 'string') return undefined;
  const trimmed = sanitizeTextInput(id, { maxLength: 256, allowNewlines: false });
  return trimmed.length ? trimmed : undefined;
};

const validateHybridKeys = (keys: any): boolean => {
  if (!keys || typeof keys !== 'object') return false;
  return (
    typeof keys.kyberPublicBase64 === 'string' &&
    keys.kyberPublicBase64.length > 0 &&
    typeof keys.dilithiumPublicBase64 === 'string' &&
    keys.dilithiumPublicBase64.length > 0
  );
};

const buildSmartStatusMap = (messages: Message[], currentUsername: string) => {
  const map = new Map<string, Message['receipt']>();
  
  // Group messages by conversation (recipient/peer)
  const conversationGroups = new Map<string, Array<{id: string; timestamp: number; receipt: Message['receipt']; recipient: string}>>();
  
  for (const msg of messages) {
    if (msg.sender !== currentUsername || !msg.receipt) continue;
    const peer = msg.recipient || '';
    if (!peer) continue;
    
    if (!conversationGroups.has(peer)) {
      conversationGroups.set(peer, []);
    }
    conversationGroups.get(peer)!.push({
      id: msg.id,
      timestamp: new Date(msg.timestamp).getTime(),
      receipt: msg.receipt,
      recipient: peer,
    });
  }
  
  // For each conversation, find latest read and latest delivered
  for (const [peer, msgs] of conversationGroups.entries()) {
    // Sort by timestamp (newest first)
    const sorted = msgs.sort((a, b) => b.timestamp - a.timestamp);
    
    // Find latest read message for this conversation
    const latestRead = sorted.find((item) => item.receipt.read);
    const latestReadTimestamp = latestRead ? latestRead.timestamp : 0;
    
    // Find latest delivered (newer than latest read) for this conversation
    const latestDelivered = sorted.find(
      (item) => item.receipt.delivered && !item.receipt.read && item.timestamp > latestReadTimestamp,
    );
    
    if (latestRead) {
      map.set(latestRead.id, { ...latestRead.receipt, read: true });
    }
    if (latestDelivered) {
      map.set(latestDelivered.id, { ...latestDelivered.receipt, delivered: true });
    }
  }
  
  return map;
};

const markReceiptSent = (store: Map<string, number>, messageId: string) => {
  store.set(messageId, Date.now());
};

const hasRecentReceipt = (store: Map<string, number>, messageId: string) => {
  const timestamp = store.get(messageId);
  if (!timestamp) return false;
  if (Date.now() - timestamp > RECEIPT_RETENTION_MS) {
    store.delete(messageId);
    return false;
  }
  return true;
};

const pruneOldReceipts = (store: Map<string, number>) => {
  const cutoff = Date.now() - RECEIPT_RETENTION_MS;
  for (const [messageId, timestamp] of store.entries()) {
    if (timestamp < cutoff) {
      store.delete(messageId);
    }
  }
};

const updateMessageReceipt = async (
  messageIndexRef: React.MutableRefObject<Map<string, number>>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  messageId: string,
  updater: (receipt: Message['receipt'] | undefined) => Message['receipt'] | undefined,
  dbReceiptQueueRef?: React.MutableRefObject<Map<string, (receipt: Message['receipt'] | undefined) => Message['receipt'] | undefined>>,
  dbFlushTimeoutRef?: React.MutableRefObject<ReturnType<typeof setTimeout> | null>,
  flushDBReceiptsRef?: React.MutableRefObject<(() => Promise<void>) | null>,
): Promise<Message | null> => {
  // First, update in-memory state if message is in current view
  const index = messageIndexRef.current.get(messageId);
  let updatedMessage: Message | null = null;
  
  if (index !== undefined) {
    setMessages((prev) => {
      if (index < 0 || index >= prev.length) {
        return prev;
      }
      const target = prev[index];
      const nextReceipt = updater(target.receipt);
      if (nextReceipt === target.receipt) {
        return prev;
      }
      updatedMessage = { ...target, receipt: nextReceipt };
      const next = [...prev];
      next[index] = updatedMessage;
      return next;
    });
  } else {
    // Message not in current view - queue for batched DB update
    if (dbReceiptQueueRef && dbFlushTimeoutRef && flushDBReceiptsRef) {
      dbReceiptQueueRef.current.set(messageId, updater);
      
      // Debounce DB flush - batch multiple receipts within 500ms window
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

export function useMessageReceipts(
  messages: Message[],
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  currentUsername: string,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  websocketClient: { send: (payload: string) => void },
  users: User[],
  getKeysOnDemand?: () => Promise<{
    x25519: { private: Uint8Array; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>,
  secureDBRef?: React.MutableRefObject<any>,
) {
  const sentReceiptsRef = useRef<Map<string, number>>(new Map());
  const messageIndexRef = useRef<Map<string, number>>(new Map());
  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });
  const pendingReceiptsRef = useRef<Map<string, { kind: 'delivered' | 'read'; addedAt: number; attempts: number }>>(new Map());
  const dbReceiptQueueRef = useRef<Map<string, (receipt: Message['receipt'] | undefined) => Message['receipt'] | undefined>>(new Map());
  const dbFlushTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushDBReceiptsRef = useRef<(() => Promise<void>) | null>(null);

  // Batched DB receipt flusher - only loads messages once and applies all queued receipts
  useEffect(() => {
    const flushDBReceipts = async () => {
      if (!secureDBRef?.current || dbReceiptQueueRef.current.size === 0) return;
      
      const queue = new Map(dbReceiptQueueRef.current);
      dbReceiptQueueRef.current.clear();
      
      try {
        const allMessages = await secureDBRef.current.loadMessages().catch(() => []);
        let hasChanges = false;
        
        // Apply all queued receipt updates in one pass
        for (const [messageId, updater] of queue.entries()) {
          const msgIndex = allMessages.findIndex((m: Message) => m.id === messageId);
          if (msgIndex !== -1) {
            const target = allMessages[msgIndex];
            const nextReceipt = updater(target.receipt);
            if (nextReceipt !== target.receipt) {
              allMessages[msgIndex] = { ...target, receipt: nextReceipt };
              hasChanges = true;
            }
          }
        }
        
        // Smart receipt cleanup: Only keep latest read and latest delivered per conversation
        if (hasChanges) {
          // Group messages by conversation (peer)
          const conversationGroups = new Map<string, Message[]>();
          for (const msg of allMessages) {
            if (msg.sender !== currentUsername) continue;
            const peer = msg.recipient || '';
            if (!peer) continue;
            if (!conversationGroups.has(peer)) {
              conversationGroups.set(peer, []);
            }
            conversationGroups.get(peer)!.push(msg);
          }
          
          // For each conversation, find latest read and latest delivered
          for (const [peer, msgs] of conversationGroups.entries()) {
            // Sort by timestamp (newest first)
            const sorted = msgs.sort((a, b) => 
              new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
            );
            
            let latestRead: Message | null = null;
            let latestDelivered: Message | null = null;
            
            // Find latest read message
            for (const msg of sorted) {
              if (msg.receipt?.read) {
                latestRead = msg;
                break;
              }
            }
            
            const latestReadTime = latestRead ? new Date(latestRead.timestamp).getTime() : 0;
            for (const msg of sorted) {
              const msgTime = new Date(msg.timestamp).getTime();
              if (msg.receipt?.delivered && !msg.receipt?.read && msgTime > latestReadTime) {
                latestDelivered = msg;
                break;
              }
            }
            
            // Clear receipts from all messages except the latest read and latest delivered
            for (const msg of msgs) {
              const isLatestRead = latestRead && msg.id === latestRead.id;
              const isLatestDelivered = latestDelivered && msg.id === latestDelivered.id;
              
              if (!isLatestRead && !isLatestDelivered && msg.receipt) {
                // Clear receipt to save storage
                const msgIndex = allMessages.findIndex((m: Message) => m.id === msg.id);
                if (msgIndex !== -1) {
                  allMessages[msgIndex] = { ...msg, receipt: undefined };
                  hasChanges = true;
                }
              }
            }
          }
          
          await secureDBRef.current.saveMessages(allMessages).catch(() => {});
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
  
    // Attempt to flush any pending receipts once messages index is refreshed
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
            dbReceiptQueueRef,
            dbFlushTimeoutRef,
            flushDBReceiptsRef,
          );
          if (updated) {
            try { await saveMessageToLocalDB(updated); } catch {}
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
          // Request bundle and wait briefly for session establishment, then proceed
          try {
            await websocketClient.sendSecureControlMessage({ 
              type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, 
              username: safeSender,
              from: currentUsername,
              timestamp: now,
            });
          } catch {}
          try {
            await new Promise<void>((resolve, reject) => {
              const timeout = setTimeout(() => { cleanup(); reject(new Error('bundle-timeout')); }, 6000);
              const onReady = (evt: Event) => {
                const d = (evt as CustomEvent).detail;
                if (d?.peer === safeSender) { cleanup(); resolve(); }
              };
              const cleanup = () => {
                clearTimeout(timeout);
                window.removeEventListener('libsignal-session-ready', onReady as EventListener);
              };
              window.addEventListener('libsignal-session-ready', onReady as EventListener);
            });
          } catch {}
        }

        const readReceiptData = {
          messageId: `${READ_RECEIPT_PREFIX}${safeMessageId}`,
          from: currentUsername,
          to: safeSender,
          type: 'read-receipt',
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
      } catch (error) {
      }
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
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
      );

      if (updated) {
        try {
          await saveMessageToLocalDB(updated);
        } catch (error) {
        }
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

      const index = messageIndexRef.current.get(safeMessageId);
      
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
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
      );

      if (updated) {
        try {
          await saveMessageToLocalDB(updated);
        } catch (error) {
        }
      } else {
        pendingReceiptsRef.current.set(safeMessageId, { kind: 'delivered', addedAt: Date.now(), attempts: 1 });
      }
    };

    window.addEventListener('message-delivered', handler as EventListener);
    return () => window.removeEventListener('message-delivered', handler as EventListener);
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

      const index = messageIndexRef.current.get(safeMessageId);
      
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
        dbReceiptQueueRef,
        dbFlushTimeoutRef,
        flushDBReceiptsRef,
      );

      if (updated) {
        try {
          await saveMessageToLocalDB(updated);
        } catch (error) {
        }
      } else {
        pendingReceiptsRef.current.set(safeMessageId, { kind: 'read', addedAt: Date.now(), attempts: 1 });
      }
    };

    window.addEventListener('message-read', handler as EventListener);
    return () => window.removeEventListener('message-read', handler as EventListener);
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