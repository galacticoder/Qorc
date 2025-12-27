import { useCallback, useEffect, useRef } from 'react';
import { Message } from '@/components/chat/messaging/types';
import { EventType } from '@/lib/event-types';

const MAX_TRACKED_ORIGINS = 5000;
const MAX_REPLIES_PER_ORIGIN = 250;
const RATE_LIMIT_WINDOW_MS = 10_000;
const RATE_LIMIT_MAX_EVENTS = 100;

const sanitizeMessageId = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 160) return null;
  return trimmed;
};

const sanitizeContent = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFC').replace(/[\u0000-\u001F\u007F]/g, '').slice(0, 10000);
  return normalized.length ? normalized : null;
};

const createReplyUpdateError = (code: string) => {
  const error = new Error(code);
  error.name = 'ReplyUpdatesError';
  (error as Error & { code?: string }).code = code;
  return error;
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: Record<string, unknown>): boolean => {
  return ['__proto__', 'prototype', 'constructor'].some(key => Object.prototype.hasOwnProperty.call(obj, key));
};

const validateEventDetail = (detail: unknown): detail is { messageId: string; newContent?: string } => {
  if (!isPlainObject(detail)) return false;
  if (hasPrototypePollutionKeys(detail)) return false;
  return typeof detail.messageId === 'string';
};

const trimOriginMap = (map: Map<string, Set<string>>): void => {
  if (map.size <= MAX_TRACKED_ORIGINS) return;
  const iterator = map.keys();
  while (map.size > MAX_TRACKED_ORIGINS) {
    const next = iterator.next();
    if (next.done) break;
    map.delete(next.value);
  }
};

/**
 * Hook for managing reply field updates when messages are edited
 */
export const useReplyUpdates = (
  messages: readonly Message[],
  onMessagesUpdate: React.Dispatch<React.SetStateAction<Message[]>>,
  persistMessage?: (msg: Message) => Promise<void>
) => {
  // Reverse mapping: original message ID -> set of message IDs that reply to it
  const replyMappingRef = useRef<Map<string, Set<string>>>(new Map());

  // Index of messages by ID for fast lookup
  const messageIndexRef = useRef<Map<string, number>>(new Map());

  // Rate limiting state
  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  // Build and maintain the reply mapping whenever messages change
  useEffect(() => {
    const replyMapping = new Map<string, Set<string>>();
    const messageIndex = new Map<string, number>();

    messages.forEach((message, index) => {
      // Build message index for fast lookup
      messageIndex.set(message.id, index);

      // Build reply mapping
      if (message.replyTo?.id) {
        const replyToId = message.replyTo.id;
        if (!replyMapping.has(replyToId)) {
          replyMapping.set(replyToId, new Set());
        }
        const replyingSet = replyMapping.get(replyToId)!;
        if (replyingSet.size < MAX_REPLIES_PER_ORIGIN) {
          replyingSet.add(message.id);
        }
      }
    });

    replyMappingRef.current = replyMapping;
    messageIndexRef.current = messageIndex;
    trimOriginMap(replyMappingRef.current);
  }, [messages]);

  // Function to update reply fields when a message is edited
  const updateReplyFields = useCallback((editedMessageId: string, newContent: string) => {
    const replyingMessageIds = replyMappingRef.current.get(editedMessageId);

    if (!replyingMessageIds || replyingMessageIds.size === 0) {
      return;
    }

    const toPersist: Message[] = [];

    onMessagesUpdate((currentMessages) => {
      const editedIndex = messageIndexRef.current.get(editedMessageId);
      const editedMessage = editedIndex !== undefined ? currentMessages[editedIndex] : undefined;
      if (!editedMessage) {
        return currentMessages;
      }

      let hasUpdates = false;
      const updatedMessages = currentMessages.map((msg) => {
        if (replyingMessageIds.has(msg.id) && msg.replyTo?.id === editedMessageId) {
          hasUpdates = true;
          const updated = {
            ...msg,
            replyTo: {
              ...msg.replyTo,
              content: newContent,
              sender: editedMessage.sender
            }
          } as Message;
          toPersist.push(updated);
          return updated;
        }
        return msg;
      });

      return hasUpdates ? updatedMessages : currentMessages;
    });

    if (persistMessage && toPersist.length > 0) {
      (async () => {
        try {
          await Promise.allSettled(toPersist.map(m => persistMessage(m)));
        } catch { }
      })();
    }
  }, [onMessagesUpdate, persistMessage]);

  const handleMessageDeleted = useCallback((deletedMessageId: string) => {
    const replyingMessageIds = replyMappingRef.current.get(deletedMessageId);

    if (!replyingMessageIds || replyingMessageIds.size === 0) {
      return;
    }

    const toPersist: Message[] = [];

    onMessagesUpdate(currentMessages => {
      let hasUpdates = false;
      const updatedMessages = currentMessages.map(msg => {
        if (replyingMessageIds.has(msg.id) && msg.replyTo?.id === deletedMessageId) {
          hasUpdates = true;
          const updated = {
            ...msg,
            replyTo: {
              ...msg.replyTo,
              content: '[Message deleted]',
              sender: msg.replyTo.sender || '[Unknown]'
            }
          } as Message;
          toPersist.push(updated);
          return updated;
        }
        return msg;
      });

      return hasUpdates ? updatedMessages : currentMessages;
    });

    if (persistMessage && toPersist.length > 0) {
      (async () => {
        try {
          await Promise.allSettled(toPersist.map(m => persistMessage(m)));
        } catch { }
      })();
    }
  }, [onMessagesUpdate, persistMessage]);

  // Set up event listeners for message edits and deletions
  useEffect(() => {
    const handleMessageEdit = (event: CustomEvent) => {
      try {
        // Rate limiting
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > RATE_LIMIT_MAX_EVENTS) {
          return;
        }

        if (!validateEventDetail(event.detail)) {
          throw createReplyUpdateError('INVALID_EVENT_DETAIL');
        }
        const messageId = sanitizeMessageId(event.detail.messageId);
        const newContent = sanitizeContent(event.detail.newContent);
        if (!messageId || newContent === null) {
          return;
        }
        updateReplyFields(messageId, newContent);
      } catch (_error) {
        console.error('[ReplyUpdates] Error handling message edit event:', _error);
      }
    };

    const handleMessageDelete = (event: CustomEvent) => {
      try {
        // Rate limiting
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > RATE_LIMIT_MAX_EVENTS) {
          return;
        }

        if (!validateEventDetail(event.detail)) {
          throw createReplyUpdateError('INVALID_EVENT_DETAIL');
        }
        const messageId = sanitizeMessageId(event.detail.messageId);
        if (!messageId) {
          return;
        }
        handleMessageDeleted(messageId);
      } catch (_error) {
        console.error('[ReplyUpdates] Error handling message delete event:', _error);
      }
    };

    window.addEventListener(EventType.LOCAL_MESSAGE_EDIT, handleMessageEdit as EventListener);
    window.addEventListener(EventType.LOCAL_MESSAGE_DELETE, handleMessageDelete as EventListener);
    window.addEventListener(EventType.REMOTE_MESSAGE_EDIT, handleMessageEdit as EventListener);
    window.addEventListener(EventType.REMOTE_MESSAGE_DELETE, handleMessageDelete as EventListener);

    return () => {
      window.removeEventListener(EventType.LOCAL_MESSAGE_EDIT, handleMessageEdit as EventListener);
      window.removeEventListener(EventType.LOCAL_MESSAGE_DELETE, handleMessageDelete as EventListener);
      window.removeEventListener(EventType.REMOTE_MESSAGE_EDIT, handleMessageEdit as EventListener);
      window.removeEventListener(EventType.REMOTE_MESSAGE_DELETE, handleMessageDelete as EventListener);
    };
  }, [updateReplyFields, handleMessageDeleted]);

  return {
    updateReplyFields,
    handleMessageDeleted
  };
};
