import { useEffect, useCallback, useRef } from 'react';
import { Message } from '@/components/chat/types';
import { SignalType } from '@/lib/signal-types';
import websocketClient from '@/lib/websocket';
import { sanitizeTextInput } from '@/lib/sanitizers';

const MAX_HISTORY_LIMIT = 500;
const DEFAULT_HISTORY_LIMIT = 50;
const HISTORY_RATE_WINDOW_MS = 5_000;
const HISTORY_RATE_MAX_REQUESTS = 10;
const MAX_BATCH_SIZE = 1000;
const MAX_PERSIST_CONCURRENCY = 10;

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const sanitizeHistoryRequest = (limit: number, since?: number) => {
  const safeLimit = Math.min(Math.max(1, Math.floor(limit)), MAX_HISTORY_LIMIT);
  const safeSince = typeof since === 'number' && Number.isFinite(since) && since > 0 ? since : undefined;
  return { limit: safeLimit, since: safeSince };
};

const validateEncryptedFormat = (content: string): boolean => {
  if (content.length < 10) return false;
  try {
    const parsed = JSON.parse(content);
    if (!isPlainObject(parsed)) return false;
    return (
      typeof parsed.version === 'string' &&
      (typeof parsed.encryptedMessage === 'string' || typeof parsed.ciphertext === 'string')
    );
  } catch {
    return false;
  }
};

const sanitizeHistoryPayload = (payload: unknown) => {
  if (!isPlainObject(payload)) {
    return null;
  }
  const sanitized: Record<string, unknown> = {};
  if (typeof payload.messageId === 'string') {
    sanitized.messageId = sanitizeTextInput(payload.messageId, { maxLength: 128, allowNewlines: false });
  }
  if (typeof payload.timestamp === 'number' || typeof payload.timestamp === 'string') {
    sanitized.timestamp = payload.timestamp;
  }
  if (typeof payload.encryptedContent === 'string') {
    if (!validateEncryptedFormat(payload.encryptedContent)) {
      console.error('[MessageHistory] Invalid encrypted content format - rejecting message');
      return null;
    }
    sanitized.encryptedContent = payload.encryptedContent;
  } else {
    console.error('[MessageHistory] Missing encrypted content - rejecting plaintext or unencrypted message');
    return null;
  }
  if (typeof payload.fromUsername === 'string') {
    sanitized.fromUsername = sanitizeTextInput(payload.fromUsername, { maxLength: 96, allowNewlines: false });
  } else {
    return null;
  }
  if (typeof payload.toUsername === 'string') {
    sanitized.toUsername = sanitizeTextInput(payload.toUsername, { maxLength: 96, allowNewlines: false });
  }
  if (typeof payload.messageType === 'string') {
    sanitized.messageType = sanitizeTextInput(payload.messageType, { maxLength: 32, allowNewlines: false });
  } else {
    return null;
  }
  if (typeof payload.version === 'string') {
    sanitized.version = sanitizeTextInput(payload.version, { maxLength: 16, allowNewlines: false });
  } else {
    return null;
  }
  if (payload.receipt && isPlainObject(payload.receipt)) {
    const receipt = payload.receipt;
    sanitized.receipt = {
      delivered: Boolean(receipt.delivered),
      read: Boolean(receipt.read),
      deliveredAt: receipt.deliveredAt,
      readAt: receipt.readAt,
    };
  }
  if (payload.replyTo && isPlainObject(payload.replyTo)) {
    const reply = payload.replyTo;
    sanitized.replyTo = {
      id: typeof reply.id === 'string' ? sanitizeTextInput(reply.id, { maxLength: 128, allowNewlines: false }) : undefined,
      content: typeof reply.content === 'string' ? reply.content : undefined,
      sender: typeof reply.sender === 'string' ? sanitizeTextInput(reply.sender, { maxLength: 96, allowNewlines: false }) : undefined,
    };
  }
  return sanitized;
};

const transformServerMessage = (serverMsg: any, currentUsername: string): Message | null => {
  if (!isPlainObject(serverMsg)) {
    return null;
  }

  let payload = serverMsg.payload;
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload);
    } catch {
      return null;
    }
  }

  const sanitizedPayload = sanitizeHistoryPayload(payload);
  if (!sanitizedPayload) {
    return null;
  }

  const id = typeof serverMsg.messageId === 'string'
    ? sanitizeTextInput(serverMsg.messageId, { maxLength: 128, allowNewlines: false })
    : typeof sanitizedPayload.messageId === 'string'
      ? sanitizedPayload.messageId
      : undefined;
  if (!id) {
    return null;
  }

  const timestampValue = typeof serverMsg.timestamp !== 'undefined' ? serverMsg.timestamp : sanitizedPayload.timestamp;
  const timestampDate = new Date(timestampValue as any);
  if (!timestampValue || Number.isNaN(timestampDate.getTime())) {
    console.error('[MessageHistory] Invalid timestamp - rejecting message');
    return null;
  }
  
  const now = Date.now();
  const fiveMinutesFromNow = now + 5 * 60 * 1000;
  const tenYearsAgo = now - 10 * 365 * 24 * 60 * 60 * 1000;
  const msgTime = timestampDate.getTime();
  if (msgTime > fiveMinutesFromNow || msgTime < tenYearsAgo) {
    console.error('[MessageHistory] Timestamp out of acceptable range - rejecting message');
    return null;
  }

  const senderUsername = typeof serverMsg.fromUsername === 'string'
    ? sanitizeTextInput(serverMsg.fromUsername, { maxLength: 96, allowNewlines: false })
    : typeof sanitizedPayload.fromUsername === 'string'
      ? sanitizedPayload.fromUsername
      : undefined;
  const recipientUsername = typeof serverMsg.toUsername === 'string'
    ? sanitizeTextInput(serverMsg.toUsername, { maxLength: 96, allowNewlines: false })
    : typeof sanitizedPayload.toUsername === 'string'
      ? sanitizedPayload.toUsername
      : undefined;

  const content = typeof sanitizedPayload.encryptedContent === 'string'
    ? sanitizedPayload.encryptedContent
    : undefined;
  if (!content) {
    console.error('[MessageHistory] Message rejected - no encrypted content');
    return null;
  }

  const messageType = typeof sanitizedPayload.messageType === 'string' ? sanitizedPayload.messageType : undefined;
  if (!messageType) {
    console.error('[MessageHistory] Message rejected - no message type');
    return null;
  }

  const version = typeof sanitizedPayload.version === 'string' ? sanitizedPayload.version : undefined;
  if (!version) {
    console.error('[MessageHistory] Message rejected - no version');
    return null;
  }

  return {
    id,
    content,
    sender: senderUsername ?? 'unknown',
    recipient: recipientUsername,
    timestamp: timestampDate,
    type: messageType,
    isCurrentUser: senderUsername === currentUsername,
    encrypted: true,
    transport: 'websocket',
    p2p: false,
    version,
    receipt: sanitizedPayload.receipt ? {
      delivered: Boolean((sanitizedPayload.receipt as any).delivered),
      read: Boolean((sanitizedPayload.receipt as any).read),
      deliveredAt: (sanitizedPayload.receipt as any).deliveredAt ? new Date((sanitizedPayload.receipt as any).deliveredAt as any) : undefined,
      readAt: (sanitizedPayload.receipt as any).readAt ? new Date((sanitizedPayload.receipt as any).readAt as any) : undefined,
    } : undefined,
    replyTo: sanitizedPayload.replyTo && typeof sanitizedPayload.replyTo === 'object' ? {
      id: typeof (sanitizedPayload.replyTo as any).id === 'string' ? (sanitizedPayload.replyTo as any).id : undefined,
      content: typeof (sanitizedPayload.replyTo as any).content === 'string' ? (sanitizedPayload.replyTo as any).content : undefined,
      sender: typeof (sanitizedPayload.replyTo as any).sender === 'string' ? (sanitizedPayload.replyTo as any).sender : undefined,
    } : undefined,
  };
};

const mergeMessages = (currentMessages: Message[], incoming: Message[]): Message[] => {
  if (incoming.length === 0) {
    return currentMessages;
  }
  const existing = new Map(currentMessages.map((msg) => [msg.id, msg]));
  let dirty = false;
  for (const msg of incoming) {
    if (!existing.has(msg.id)) {
      existing.set(msg.id, msg);
      dirty = true;
    }
  }
  if (!dirty) {
    return currentMessages;
  }
  const merged = Array.from(existing.values());
  merged.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  return merged;
};

const persistMessages = async (messages: Message[], saveFn: (msg: Message) => Promise<void>) => {
  if (messages.length === 0) return;
  
  // Batch large sets to avoid overwhelming the database with too many concurrent operations
  const batches: Message[][] = [];
  for (let i = 0; i < messages.length; i += MAX_PERSIST_CONCURRENCY) {
    batches.push(messages.slice(i, i + MAX_PERSIST_CONCURRENCY));
  }
  
  let totalFailed = 0;
  for (const batch of batches) {
    const results = await Promise.allSettled(batch.map(msg => saveFn(msg)));
    totalFailed += results.filter(r => r.status === 'rejected').length;
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  
  if (totalFailed > 0) {
    console.error(`[MessageHistory] Failed to persist ${totalFailed}/${messages.length} messages`);
  }
};

export function useMessageHistory(
  currentUsername: string,
  isLoggedIn: boolean,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  isFullyAuthenticated?: boolean
) {
  const hasRequestedHistory = useRef(false);
  const isProcessingHistory = useRef(false);
  const lastHistoryRequestRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });

  // Request message history from server after successful authentication
  const requestMessageHistory = useCallback(async (limit: number = DEFAULT_HISTORY_LIMIT, since?: number) => {
    if (!isLoggedIn || !currentUsername || !isFullyAuthenticated) {
      return;
    }

    const now = Date.now();
    const bucket = lastHistoryRequestRef.current;
    if (now - bucket.windowStart > HISTORY_RATE_WINDOW_MS) {
      bucket.windowStart = now;
      bucket.count = 0;
    }
    bucket.count += 1;
    if (bucket.count > HISTORY_RATE_MAX_REQUESTS) {
      return;
    }

    if (hasRequestedHistory.current && !since) {
      return;
    }

    try {
      const { limit: safeLimit, since: safeSince } = sanitizeHistoryRequest(limit, since);
      const request = {
        type: SignalType.REQUEST_MESSAGE_HISTORY,
        limit: safeLimit,
        ...(safeSince ? { since: safeSince } : {})
      };

      await websocketClient.sendSecureControlMessage(request);
      if (!safeSince) {
        hasRequestedHistory.current = true;
      }
    } catch (_error) {
      console.error('[MessageHistory] Failed to request message history');
    }
  }, [isLoggedIn, currentUsername, isFullyAuthenticated]);

  // Handle message history response from server
  const handleMessageHistory = useCallback(async (data: any) => {
    if (!isFullyAuthenticated || !isPlainObject(data)) {
      return;
    }

    if (isProcessingHistory.current) {
      return;
    }

    const { messages: serverMessages, hasMore, timestamp } = data as Record<string, unknown>;
    if (!Array.isArray(serverMessages)) {
      console.error('[MessageHistory] Invalid history response - messages not an array');
      return;
    }

    if (serverMessages.length > MAX_BATCH_SIZE) {
      console.error(`[MessageHistory] Batch size ${serverMessages.length} exceeds maximum ${MAX_BATCH_SIZE} - rejecting`);
      return;
    }

    isProcessingHistory.current = true;

    try {
      const transformed: Message[] = [];
      const seenIds = new Set<string>();
      const CHUNK_SIZE = 50;
      
      for (let i = 0; i < serverMessages.length; i += CHUNK_SIZE) {
        const chunk = serverMessages.slice(i, i + CHUNK_SIZE);
        for (const serverMsg of chunk) {
          const msg = transformServerMessage(serverMsg, currentUsername);
          if (msg) {
            if (seenIds.has(msg.id)) {
              continue;
            }
            seenIds.add(msg.id);
            transformed.push(msg);
          }
        }
        // Yield to UI thread after each chunk
        if (i + CHUNK_SIZE < serverMessages.length) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }

      if (transformed.length > 0) {
        setMessages((currentMessages) => mergeMessages(currentMessages, transformed));
        await persistMessages(transformed, saveMessageToLocalDB);
      }

      if (hasMore === true && typeof timestamp === 'number' && Number.isFinite(timestamp)) {
        requestMessageHistory(DEFAULT_HISTORY_LIMIT, timestamp);
      }
    } finally {
      isProcessingHistory.current = false;
    }
  }, [currentUsername, setMessages, saveMessageToLocalDB, isFullyAuthenticated, requestMessageHistory]);

  // Auto-request message history on login
  useEffect(() => {
    if (isLoggedIn && currentUsername && isFullyAuthenticated && !hasRequestedHistory.current) {
      const timer = setTimeout(() => {
        requestMessageHistory(DEFAULT_HISTORY_LIMIT);
      }, 1000);

      return () => {
        try { clearTimeout(timer); } catch {}
      };
    }
  }, [isLoggedIn, currentUsername, isFullyAuthenticated, requestMessageHistory]);

  // Reset flag when user logs out
  useEffect(() => {
    if (!isLoggedIn) {
      hasRequestedHistory.current = false;
      isProcessingHistory.current = false;
      lastHistoryRequestRef.current = { windowStart: 0, count: 0 };
    }
  }, [isLoggedIn]);

  return {
    requestMessageHistory,
    handleMessageHistory
  };
}