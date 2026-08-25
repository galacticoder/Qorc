import React, { useEffect, useLayoutEffect, useCallback, useRef } from 'react';
import { Message } from '../../components/chat/messaging/types';
import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import { exactEventDetail, isPlainObject, hasPrototypePollutionKeys, sanitizeNonEmptyText, sanitizeFilename, sanitizeMessageId } from '../../lib/sanitizers';
import { nativeMessageContent } from '../../lib/tauri-bindings';
import { setMessagesWithResult } from '../../lib/utils/set-messages-result';
import { 
  MAX_LOCAL_MESSAGE_ID_LENGTH,
  MAX_LOCAL_USERNAME_LENGTH,
  MAX_LOCAL_MIMETYPE_LENGTH,
  MAX_LOCAL_EMOJI_LENGTH,
  MAX_LOCAL_FILE_SIZE_BYTES,
  AUTH_USERNAME_REGEX,
} from '../../lib/constants';
import {
  applyDeleteControl,
  applyEditControl,
  applyReactionControl,
  hasWireMessageId,
  isPlausibleControlOperationId,
  type MessageControlOutcome,
} from '../../lib/messages/message-controls';

interface UseLocalMessageHandlersProps {
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  saveMessageWithContext: (message: Message) => Promise<any> | void;
  allowEvent: (eventType: string) => boolean;
  currentUsername: string;
}

export function useLocalMessageHandlers({
  setMessages,
  saveMessageWithContext,
  allowEvent,
  currentUsername,
}: UseLocalMessageHandlersProps) {
  const saveMessageRef = useRef(saveMessageWithContext);
  const activeAccountRef = useRef(currentUsername);
  const accountGenerationRef = useRef(0);
  useLayoutEffect(() => { saveMessageRef.current = saveMessageWithContext; }, [saveMessageWithContext]);
  useLayoutEffect(() => {
    if (activeAccountRef.current === currentUsername) return;
    activeAccountRef.current = currentUsername;
    accountGenerationRef.current += 1;
  }, [currentUsername]);

  const captureAccountOperation = useCallback(() => {
    const account = currentUsername;
    const generation = accountGenerationRef.current;
    return () => !!account &&
      activeAccountRef.current === account &&
      generation === accountGenerationRef.current;
  }, [currentUsername]);

  const handleLocalMessageDelete = useCallback((event: CustomEvent) => {
    try {
      const isCurrent = captureAccountOperation();
      if (!isCurrent()) return;
      const detail = exactEventDetail(event, ['account', 'messageId', 'operationId']);
      if (!detail || detail.account !== currentUsername) return;
      const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      const operationId = isPlausibleControlOperationId(detail.operationId)
        ? detail.operationId
        : null;
      if (!messageId || !operationId) return;
      if (!allowEvent(EventType.LOCAL_MESSAGE_DELETE)) return;

      void setMessagesWithResult<MessageControlOutcome | null>(setMessages, (prev) => {
        if (!isCurrent()) return { next: prev, result: null };
        let matched: MessageControlOutcome | null = null;
        const next = prev.map(msg => {
          if (hasWireMessageId(msg, messageId) && msg.sender === currentUsername && msg.isCurrentUser === true) {
            matched = applyDeleteControl(msg, currentUsername, operationId);
            return matched?.message ?? msg;
          }
          return msg;
        });
        return { next: matched?.changed ? next : prev, result: matched };
      }).then((outcome) => {
        if (!outcome?.changed || !isCurrent()) return;
        void nativeMessageContent.delete(outcome.message.secureContentId || messageId).catch(() => false);
        void Promise.resolve(saveMessageRef.current(outcome.message)).catch(() => { });
      }).catch(() => { });
    } catch { }
  }, [setMessages, allowEvent, captureAccountOperation, currentUsername]);

  const handleLocalMessageEdit = useCallback((event: CustomEvent) => {
    try {
      const isCurrent = captureAccountOperation();
      if (!isCurrent()) return;
      const detail = exactEventDetail(event, ['account', 'contentVaultId', 'messageId', 'operationId']);
      if (!detail || detail.account !== currentUsername) return;
      const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      const contentVaultId = sanitizeMessageId(detail.contentVaultId);
      const operationId = isPlausibleControlOperationId(detail.operationId)
        ? detail.operationId
        : null;
      if (!messageId || !contentVaultId || !operationId) return;
      if (!allowEvent(EventType.LOCAL_MESSAGE_EDIT)) return;

      void (async () => {
        if (!await nativeMessageContent.has(contentVaultId) || !isCurrent()) return;
        const outcome = await setMessagesWithResult<MessageControlOutcome | null>(setMessages, (prev) => {
          if (!isCurrent()) return { next: prev, result: null };
          let matched: MessageControlOutcome | null = null;
          const next = prev.map(msg => {
            if (hasWireMessageId(msg, messageId) && msg.sender === currentUsername && msg.isCurrentUser === true) {
              const applied = applyEditControl(msg, currentUsername, operationId);
              matched = applied?.changed
                ? { ...applied, message: { ...applied.message, content: '', secureContentId: contentVaultId } }
                : applied;
              return matched?.message ?? msg;
            }
            return msg;
          });
          return { next: matched?.changed ? next : prev, result: matched };
        });
        if (!outcome?.changed || !isCurrent()) return;
        await Promise.resolve(saveMessageRef.current({ ...outcome.message, content: '' }));
      })().catch(() => { });
    } catch { }
  }, [setMessages, allowEvent, captureAccountOperation, currentUsername]);

  const handleLocalFileMessage = useCallback(async (event: CustomEvent) => {
    try {
      const isCurrent = captureAccountOperation();
      if (!isCurrent()) return;
      const detail = exactEventDetail(event, [
        'account', 'content', 'fileSize', 'filename', 'id', 'isCurrentUser',
        'mimeType', 'receipt', 'recipient', 'sender', 'timestamp', 'type'
      ]);
      if (!detail || detail.account !== currentUsername) return;

      const fileId = sanitizeNonEmptyText(detail.id, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      if (!fileId) return;

      const filenameRaw = typeof detail.filename === 'string' ? detail.filename : 'file';
      const filename = sanitizeFilename(filenameRaw, 128);
      const mimeType = sanitizeNonEmptyText(detail.mimeType, MAX_LOCAL_MIMETYPE_LENGTH, false) || 'application/octet-stream';
      const sender = sanitizeNonEmptyText(detail.sender, MAX_LOCAL_USERNAME_LENGTH, false) || '';
      const recipient = sanitizeNonEmptyText(detail.recipient, MAX_LOCAL_USERNAME_LENGTH, false) || '';
      if (
        sender !== currentUsername ||
        sender !== sender.trim().toLowerCase() ||
        recipient !== recipient.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(sender) ||
        !AUTH_USERNAME_REGEX.test(recipient) ||
        recipient === sender ||
        detail.type !== SignalType.FILE ||
        detail.isCurrentUser !== true ||
        detail.content !== ''
      ) return;

      const sizeCandidate = typeof detail.fileSize === 'number' ? detail.fileSize : undefined;
      const fileSize = typeof sizeCandidate === 'number' && Number.isFinite(sizeCandidate) && sizeCandidate > 0 && sizeCandidate <= MAX_LOCAL_FILE_SIZE_BYTES
        ? sizeCandidate : undefined;

      if (!fileSize) return;

      if (!Number.isSafeInteger(detail.timestamp) || (detail.timestamp as number) <= 0) return;
      const timestamp = new Date(detail.timestamp as number);
      if (!Number.isFinite(timestamp.getTime())) return;

      const receiptDetail = detail.receipt;
      if (
        !isPlainObject(receiptDetail) ||
        hasPrototypePollutionKeys(receiptDetail) ||
        Object.keys(receiptDetail).sort().join(',') !== 'delivered,read' ||
        receiptDetail.delivered !== false ||
        receiptDetail.read !== false
      ) return;
      if (!allowEvent(EventType.LOCAL_FILE_MESSAGE)) return;

      const newMessage: Message = {
        id: fileId,
        content: '',
        sender,
        recipient,
        timestamp,
        isCurrentUser: true,
        type: 'file',
        filename,
        fileSize,
        mimeType,
        receipt: { delivered: false, read: false },
      } as Message;

      const added = await setMessagesWithResult<boolean>(setMessages, (prev) => (
        !isCurrent() || prev.find(msg => msg.id === fileId)
          ? { next: prev, result: false }
          : { next: [...prev, newMessage], result: true }
      ));
      if (!isCurrent()) return;

      void added;
    } catch { }
  }, [setMessages, allowEvent, captureAccountOperation, currentUsername]);

  const handleLocalFileSendCanceled = useCallback((event: CustomEvent) => {
    try {
      const isCurrent = captureAccountOperation();
      if (!isCurrent()) return;
      const detail = exactEventDetail(event, ['account', 'fileId']);
      if (!detail || detail.account !== currentUsername) return;
      const fileId = sanitizeMessageId(detail.fileId);
      if (!fileId || !allowEvent(EventType.LOCAL_FILE_SEND_CANCELED)) return;
      setMessages((previous) => !isCurrent() ? previous : previous.map((message) => (
        message.id === fileId &&
        message.sender === currentUsername &&
        message.isCurrentUser === true
          ? { ...message, content: 'This message was deleted', isDeleted: true }
          : message
      )));
    } catch { }
  }, [allowEvent, captureAccountOperation, currentUsername, setMessages]);

  const handleLocalReactionUpdate = useCallback((event: CustomEvent) => {
    try {
      const isCurrent = captureAccountOperation();
      if (!isCurrent()) return;
      const detail = exactEventDetail(event, ['account', 'emoji', 'isAdd', 'messageId', 'operationId', 'username']);
      if (!detail || detail.account !== currentUsername) return;
      const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      const emoji = sanitizeNonEmptyText(detail.emoji, MAX_LOCAL_EMOJI_LENGTH, false);
      const username = sanitizeNonEmptyText(detail.username, MAX_LOCAL_USERNAME_LENGTH, false);
      const isAdd = typeof detail.isAdd === 'boolean' ? detail.isAdd : null;
      const operationId = isPlausibleControlOperationId(detail.operationId)
        ? detail.operationId
        : null;
      if (!messageId || !emoji || !username || username !== currentUsername || isAdd === null || !operationId) return;
      if (!allowEvent(EventType.LOCAL_REACTION_UPDATE)) return;

      void setMessagesWithResult<MessageControlOutcome | null>(setMessages, (prev) => {
        if (!isCurrent()) return { next: prev, result: null };
        let outcome: MessageControlOutcome | null = null;
        const next = prev.map(msg => {
          if (!hasWireMessageId(msg, messageId)) return msg;
          outcome = applyReactionControl(msg, username, operationId, emoji, isAdd);
          return outcome?.message ?? msg;
        });
        return { next: outcome?.changed ? next : prev, result: outcome };
      }).then((outcome) => {
        if (outcome?.changed && isCurrent()) {
          void Promise.resolve(saveMessageRef.current(outcome.message)).catch(() => { });
        }
      }).catch(() => { });
    } catch { }
  }, [setMessages, allowEvent, captureAccountOperation, currentUsername]);

  useEffect(() => {
    window.addEventListener(EventType.LOCAL_MESSAGE_DELETE, handleLocalMessageDelete as EventListener);
    window.addEventListener(EventType.LOCAL_MESSAGE_EDIT, handleLocalMessageEdit as EventListener);
    window.addEventListener(EventType.LOCAL_FILE_MESSAGE, handleLocalFileMessage as EventListener);
    window.addEventListener(EventType.LOCAL_FILE_SEND_CANCELED, handleLocalFileSendCanceled as EventListener);
    window.addEventListener(EventType.LOCAL_REACTION_UPDATE, handleLocalReactionUpdate as EventListener);

    return () => {
      window.removeEventListener(EventType.LOCAL_MESSAGE_DELETE, handleLocalMessageDelete as EventListener);
      window.removeEventListener(EventType.LOCAL_MESSAGE_EDIT, handleLocalMessageEdit as EventListener);
      window.removeEventListener(EventType.LOCAL_FILE_MESSAGE, handleLocalFileMessage as EventListener);
      window.removeEventListener(EventType.LOCAL_FILE_SEND_CANCELED, handleLocalFileSendCanceled as EventListener);
      window.removeEventListener(EventType.LOCAL_REACTION_UPDATE, handleLocalReactionUpdate as EventListener);
    };
  }, [handleLocalMessageDelete, handleLocalMessageEdit, handleLocalFileMessage, handleLocalFileSendCanceled, handleLocalReactionUpdate]);
}
