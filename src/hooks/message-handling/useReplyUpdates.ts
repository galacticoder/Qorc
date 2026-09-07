import { useCallback, useEffect, useRef } from 'react';
import { Message } from '@/components/chat/messaging/types';
import { EventType } from '@/lib/types/event-types';
import { REPLY_MAX_TRACKED_ORIGINS, REPLY_MAX_REPLIES_PER_ORIGIN, REPLY_RATE_LIMIT_WINDOW_MS, REPLY_RATE_LIMIT_MAX_EVENTS } from '@/lib/constants';
import { exactEventDetail, sanitizeMessageId } from '@/lib/sanitizers';
import { isPlausibleControlOperationId } from '@/lib/messages/message-controls';
import { setMessagesWithResult } from '../../lib/utils/set-messages-result';
import { nativeMessageContent } from '../../lib/tauri-bindings';

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
  persistMessage: (msg: Message) => Promise<void>,
  currentUsername: string
) => {
  const replyMappingRef = useRef<Map<string, Set<string>>>(new Map());
  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });
  const activeAccountRef = useRef(currentUsername);
  const accountGenerationRef = useRef(0);

  useEffect(() => {
    if (activeAccountRef.current === currentUsername) return;
    activeAccountRef.current = currentUsername;
    accountGenerationRef.current += 1;
    replyMappingRef.current.clear();
    rateLimitRef.current = { windowStart: Date.now(), count: 0 };
  }, [currentUsername]);

  // Build and maintain the reply mapping whenever messages change
  useEffect(() => {
    const replyMapping = new Map<string, Set<string>>();

    messages.forEach((message) => {
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
    trimOriginMap(replyMappingRef.current);
  }, [messages]);

  // Update reply fields when a message is edited
  const updateReplyFields = useCallback((editedMessageId: string, contentVaultId: string, operationId: string) => {
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    const isCurrent = () => !!account &&
      activeAccountRef.current === account &&
      generation === accountGenerationRef.current;
    if (!isCurrent()) return;
    const replyingMessageIds = replyMappingRef.current.get(editedMessageId);

    if (!replyingMessageIds || replyingMessageIds.size === 0) { return; }

    void (async () => {
      if (!await nativeMessageContent.has(contentVaultId) || !isCurrent()) return;
      const updates = await setMessagesWithResult<Message[]>(onMessagesUpdate, (currentMessages) => {
        if (!isCurrent()) return { next: currentMessages, result: [] };
        const editedMessage = currentMessages.find(m => (
          m.id === editedMessageId || m.wireMessageId === editedMessageId
        ));
        if (!editedMessage) return { next: currentMessages, result: [] };

        const persistedUpdates: Message[] = [];
        let hasUpdates = false;
        const updatedMessages = currentMessages.map((msg) => {
          if (replyingMessageIds.has(msg.id) && msg.replyTo?.id === editedMessageId) {
            hasUpdates = true;
            const projected = {
              ...msg,
              replyTo: {
                ...msg.replyTo,
                content: '',
                secureContentId: contentVaultId,
                contentVersion: operationId,
                isDeleted: undefined,
                sender: editedMessage.sender
              }
            } as Message;
            persistedUpdates.push(projected);
            return projected;
          }
          return msg;
        });
        return { next: hasUpdates ? updatedMessages : currentMessages, result: persistedUpdates };
      });
      if (!isCurrent() || updates.length === 0) return;
      await Promise.all(updates.map((message) => persistMessage(message)));
    })().catch((error) => {
      console.error('Failed to persist reply edits:', error);
    });
  }, [onMessagesUpdate, persistMessage, currentUsername]);

  // Update reply fields when a message is deleted
  const handleMessageDeleted = useCallback((deletedMessageId: string, operationId: string) => {
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    const isCurrent = () => !!account &&
      activeAccountRef.current === account &&
      generation === accountGenerationRef.current;
    if (!isCurrent()) return;
    const replyingMessageIds = replyMappingRef.current.get(deletedMessageId);

    if (!replyingMessageIds || replyingMessageIds.size === 0) { return; }

    void setMessagesWithResult<Message[]>(onMessagesUpdate, (currentMessages) => {
      if (!isCurrent()) return { next: currentMessages, result: [] };
      const updates: Message[] = [];
      let hasUpdates = false;
      const updatedMessages = currentMessages.map(msg => {
        if (replyingMessageIds.has(msg.id) && msg.replyTo?.id === deletedMessageId) {
          hasUpdates = true;
          const updated = {
            ...msg,
            replyTo: {
              ...msg.replyTo,
              content: '',
              secureContentId: undefined,
              contentVersion: operationId,
              isDeleted: true,
              sender: msg.replyTo.sender
            }
          } as Message;
          updates.push(updated);
          return updated;
        }
        return msg;
      });

      return { next: hasUpdates ? updatedMessages : currentMessages, result: updates };
    }).then((updates) => {
      if (!isCurrent() || updates.length === 0) return;
      void Promise.all(updates.map((message) => persistMessage(message))).catch((error) => {
        console.error('Failed to persist reply deletions:', error);
      });
    });
  }, [onMessagesUpdate, persistMessage, currentUsername]);

  // Set up event listeners for message edits and deletions
  useEffect(() => {
    const handleMessageEdit = (event: CustomEvent) => {
      try {
        const detail = exactEventDetail(event, ['account', 'contentVaultId', 'messageId', 'operationId']);
        if (!detail || detail.account !== currentUsername) return;
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

        const messageId = sanitizeMessageId(detail.messageId);
        const contentVaultId = sanitizeMessageId(detail.contentVaultId);
        const operationId = isPlausibleControlOperationId(detail.operationId)
          ? detail.operationId
          : null;
        if (!messageId || !contentVaultId || !operationId) {
          return;
        }
        updateReplyFields(messageId, contentVaultId, operationId);
      } catch (_error) {
        console.error('[ReplyUpdates] Error handling message edit event:', _error);
      }
    };

    const handleMessageDelete = (event: CustomEvent) => {
      try {
        const detail = exactEventDetail(event, ['account', 'messageId', 'operationId']);
        if (!detail || detail.account !== currentUsername) return;
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

        const messageId = sanitizeMessageId(detail.messageId);
        const operationId = isPlausibleControlOperationId(detail.operationId)
          ? detail.operationId
          : null;
        if (!messageId || !operationId) {
          return;
        }
        handleMessageDeleted(messageId, operationId);
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
