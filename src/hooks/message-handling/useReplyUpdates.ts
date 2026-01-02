import { useCallback, useEffect, useRef } from 'react';
import { Message } from '@/components/chat/messaging/types';
import { EventType } from '@/lib/event-types';
import { REPLY_MAX_TRACKED_ORIGINS, REPLY_MAX_REPLIES_PER_ORIGIN, REPLY_RATE_LIMIT_WINDOW_MS, REPLY_RATE_LIMIT_MAX_EVENTS } from '@/lib/constants';
import { sanitizeContent, sanitizeMessageId } from '@/lib/sanitizers';
import { validateEventDetail } from '../../lib/utils/shared-utils';

const createReplyUpdateError = (code: string) => {
  const error = new Error(code);
  error.name = 'ReplyUpdatesError';
  (error as Error & { code?: string }).code = code;
  return error;
};

const trimOriginMap = (map: Map<string, Set<string>>): void => {
  if (map.size <= REPLY_MAX_TRACKED_ORIGINS) return;
  const iterator = map.keys();
  while (map.size > REPLY_MAX_TRACKED_ORIGINS) {
    const next = iterator.next();
    if (next.done) break;
    map.delete(next.value);
  }
};

// Hook for managing reply field updates when messages are edited
export const useReplyUpdates = (
  messages: readonly Message[],
  onMessagesUpdate: React.Dispatch<React.SetStateAction<Message[]>>,
  persistMessage?: (msg: Message) => Promise<void>
) => {
  const replyMappingRef = useRef<Map<string, Set<string>>>(new Map());
  const messageIndexRef = useRef<Map<string, number>>(new Map());
  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  // Build and maintain the reply mapping whenever messages change
  useEffect(() => {
    const replyMapping = new Map<string, Set<string>>();
    const messageIndex = new Map<string, number>();

    messages.forEach((message, index) => {
      messageIndex.set(message.id, index);
      if (message.replyTo?.id) {
        const replyToId = message.replyTo.id;
        if (!replyMapping.has(replyToId)) {
          replyMapping.set(replyToId, new Set());
        }
        const replyingSet = replyMapping.get(replyToId)!;
        if (replyingSet.size < REPLY_MAX_REPLIES_PER_ORIGIN) {
          replyingSet.add(message.id);
        }
      }
    });

    replyMappingRef.current = replyMapping;
    messageIndexRef.current = messageIndex;
    trimOriginMap(replyMappingRef.current);
  }, [messages]);

  // Update reply fields when a message is edited
  const updateReplyFields = useCallback((editedMessageId: string, newContent: string) => {
    const replyingMessageIds = replyMappingRef.current.get(editedMessageId);

    if (!replyingMessageIds || replyingMessageIds.size === 0) { return; }

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

  // Update reply fields when a message is deleted
  const handleMessageDeleted = useCallback((deletedMessageId: string) => {
    const replyingMessageIds = replyMappingRef.current.get(deletedMessageId);

    if (!replyingMessageIds || replyingMessageIds.size === 0) { return; }

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
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart > REPLY_RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > REPLY_RATE_LIMIT_MAX_EVENTS) {
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
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart >  REPLY_RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > REPLY_RATE_LIMIT_MAX_EVENTS) {
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
