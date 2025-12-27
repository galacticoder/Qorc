import { useEffect, useCallback, useRef } from 'react';
import { Message } from '../components/chat/messaging/types';
import { EventType } from '../lib/event-types';
import { isPlainObject, hasPrototypePollutionKeys, isUnsafeObjectKey, sanitizeNonEmptyText, sanitizeFilename } from '../lib/sanitizers';
import { toast } from 'sonner';

const MAX_LOCAL_MESSAGE_ID_LENGTH = 160;
const MAX_LOCAL_MESSAGE_LENGTH = 10_000;
const MAX_LOCAL_USERNAME_LENGTH = 256;
const MAX_LOCAL_MIMETYPE_LENGTH = 128;
const MAX_LOCAL_EMOJI_LENGTH = 32;
const MAX_LOCAL_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_INLINE_BASE64_BYTES = 10 * 1024 * 1024;

interface UseLocalMessageHandlersProps {
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>;
  saveMessageWithContext: (message: Message) => Promise<any> | void;
  secureDBRef: React.RefObject<any>;
  allowEvent: (eventType: string) => boolean;
}

export function useLocalMessageHandlers({
  setMessages,
  saveMessageWithContext,
  secureDBRef,
  allowEvent,
}: UseLocalMessageHandlersProps) {
  const saveMessageRef = useRef(saveMessageWithContext);
  useEffect(() => { saveMessageRef.current = saveMessageWithContext; }, [saveMessageWithContext]);

  const handleLocalMessageDelete = useCallback((event: CustomEvent) => {
    try {
      if (!allowEvent(EventType.LOCAL_MESSAGE_DELETE)) return;
      const detail = (event as any).detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
      const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      if (!messageId) return;

      let messageToPersist: Message | null = null;
      setMessages(prev => prev.map(msg => {
        if (msg.id === messageId) {
          const updated = { ...msg, isDeleted: true, content: 'This message was deleted' } as Message;
          messageToPersist = updated;
          return updated;
        }
        return msg;
      }));

      if (messageToPersist) {
        try { void saveMessageRef.current(messageToPersist); } catch { }
      }
    } catch { }
  }, [setMessages, allowEvent]);

  const handleLocalMessageEdit = useCallback((event: CustomEvent) => {
    try {
      if (!allowEvent(EventType.LOCAL_MESSAGE_EDIT)) return;
      const detail = (event as any).detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
      const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      const newContent = sanitizeNonEmptyText(detail.newContent, MAX_LOCAL_MESSAGE_LENGTH, true);
      if (!messageId || !newContent) return;

      let messageToPersist: Message | null = null;
      setMessages(prev => prev.map(msg => {
        if (msg.id === messageId) {
          const updated = { ...msg, content: newContent, isEdited: true } as Message;
          messageToPersist = updated;
          return updated;
        }
        return msg;
      }));

      if (messageToPersist) {
        try { void saveMessageRef.current(messageToPersist); } catch { }
      }
    } catch { }
  }, [setMessages, allowEvent]);

  const handleLocalFileMessage = useCallback(async (event: CustomEvent) => {
    try {
      if (!allowEvent('local-file-message')) return;
      const detail = (event as any).detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

      const fileId = sanitizeNonEmptyText(detail.id, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      if (!fileId) return;

      const filenameRaw = typeof detail.filename === 'string' ? detail.filename : 'file';
      const filename = sanitizeFilename(filenameRaw, 128);
      const mimeType = sanitizeNonEmptyText(detail.mimeType, MAX_LOCAL_MIMETYPE_LENGTH, false) || 'application/octet-stream';
      const sender = sanitizeNonEmptyText(detail.sender, MAX_LOCAL_USERNAME_LENGTH, false) || '';
      const recipient = sanitizeNonEmptyText(detail.recipient, MAX_LOCAL_USERNAME_LENGTH, false) || '';

      const sizeCandidate = typeof detail.fileSize === 'number' ? detail.fileSize : typeof detail.size === 'number' ? detail.size : undefined;
      const fileSize = typeof sizeCandidate === 'number' && Number.isFinite(sizeCandidate) && sizeCandidate >= 0 && sizeCandidate <= MAX_LOCAL_FILE_SIZE_BYTES
        ? sizeCandidate : undefined;

      const content = sanitizeNonEmptyText(detail.content, 2048, false) || '';
      const blobUrl = content.startsWith('blob:') ? content : '';

      let secureDbSaveSucceeded = false;
      try {
        if (secureDBRef.current && blobUrl) {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15_000);
          try {
            const resp = await fetch(blobUrl, { signal: controller.signal });
            if (resp.ok) {
              const fetchedBlob = await resp.blob();
              if (fetchedBlob.size > 0 && fetchedBlob.size <= MAX_LOCAL_FILE_SIZE_BYTES) {
                const saveResult = await secureDBRef.current.saveFile(fileId, fetchedBlob);
                secureDbSaveSucceeded = Boolean(saveResult?.success);
                if (!saveResult.success && saveResult.quotaExceeded) {
                  toast.warning('Storage limit reached. This file will not persist after restart.', { duration: 5000 });
                }
              }
            }
          } finally {
            clearTimeout(timeout);
          }
        }
      } catch { }

      let timestamp: Date;
      try {
        if (typeof detail.timestamp === 'number' && Number.isFinite(detail.timestamp)) {
          timestamp = new Date(detail.timestamp);
        } else if (typeof detail.timestamp === 'string') {
          timestamp = new Date(detail.timestamp);
        } else if (detail.timestamp instanceof Date) {
          timestamp = detail.timestamp;
        } else {
          timestamp = new Date();
        }
        if (isNaN(timestamp.getTime())) timestamp = new Date();
      } catch {
        timestamp = new Date();
      }

      const receiptDetail = detail.receipt;
      const receipt = isPlainObject(receiptDetail) && !hasPrototypePollutionKeys(receiptDetail)
        ? { delivered: typeof receiptDetail.delivered === 'boolean' ? receiptDetail.delivered : false, read: typeof receiptDetail.read === 'boolean' ? receiptDetail.read : false }
        : { delivered: false, read: false };

      let safeOriginalBase64Data: string | undefined;
      if (!secureDbSaveSucceeded && typeof detail.originalBase64Data === 'string') {
        const raw = detail.originalBase64Data;
        const maxChars = Math.ceil((MAX_INLINE_BASE64_BYTES * 4) / 3) + 128;
        if (raw.length > 0 && raw.length <= maxChars) {
          let normalized = raw.trim();
          const commaIndex = normalized.indexOf(',');
          if (commaIndex > 0 && commaIndex < 128) normalized = normalized.slice(commaIndex + 1);
          normalized = normalized.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
          if (/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
            const pad = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
            const estimatedBytes = Math.floor((normalized.length * 3) / 4) - pad;
            if (estimatedBytes > 0 && estimatedBytes <= MAX_INLINE_BASE64_BYTES) {
              safeOriginalBase64Data = normalized;
            }
          }
        }
      }

      const newMessage: Message = {
        id: fileId,
        content: blobUrl,
        sender,
        recipient,
        timestamp,
        isCurrentUser: true,
        type: 'file',
        filename,
        fileSize,
        mimeType,
        receipt,
        ...(safeOriginalBase64Data ? { originalBase64Data: safeOriginalBase64Data } : {}),
        version: typeof detail.version === 'string' && detail.version.length > 0 ? detail.version : '1'
      } as Message;

      let messageToPersist: Message | null = null;
      setMessages(prev => {
        if (prev.find(msg => msg.id === fileId)) return prev;
        messageToPersist = newMessage;
        return [...prev, newMessage];
      });

      if (messageToPersist) {
        try { void saveMessageRef.current(messageToPersist); } catch { }
      }
    } catch { }
  }, [setMessages, allowEvent, secureDBRef]);

  const handleLocalReactionUpdate = useCallback((event: CustomEvent) => {
    try {
      if (!allowEvent(EventType.LOCAL_REACTION_UPDATE)) return;
      const detail = (event as any).detail;
      if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
      const messageId = sanitizeNonEmptyText(detail.messageId, MAX_LOCAL_MESSAGE_ID_LENGTH, false);
      const emoji = sanitizeNonEmptyText(detail.emoji, MAX_LOCAL_EMOJI_LENGTH, false);
      const username = sanitizeNonEmptyText(detail.username, MAX_LOCAL_USERNAME_LENGTH, false);
      const isAdd = typeof detail.isAdd === 'boolean' ? detail.isAdd : null;
      if (!messageId || !emoji || !username || isAdd === null) return;
      if (isUnsafeObjectKey(emoji)) return;

      let updatedMessage: Message | null = null;

      setMessages(prev => prev.map(msg => {
        if (msg.id !== messageId) return msg;

        const currentReactions: Record<string, string[]> = Object.create(null);
        if (msg.reactions && typeof msg.reactions === 'object') {
          for (const [reactionKey, rawUsers] of Object.entries(msg.reactions as Record<string, unknown>)) {
            if (typeof reactionKey !== 'string' || isUnsafeObjectKey(reactionKey)) continue;
            if (!Array.isArray(rawUsers)) continue;
            const safeUsers: string[] = [];
            const seen = new Set<string>();
            for (const candidate of rawUsers as unknown[]) {
              if (safeUsers.length >= 250) break;
              const cleaned = sanitizeNonEmptyText(candidate, MAX_LOCAL_USERNAME_LENGTH, false);
              if (!cleaned || seen.has(cleaned)) continue;
              seen.add(cleaned);
              safeUsers.push(cleaned);
            }
            if (safeUsers.length > 0) currentReactions[reactionKey] = safeUsers;
          }
        }

        const users = currentReactions[emoji] ? [...currentReactions[emoji]] : [];
        if (isAdd) {
          if (!users.includes(username) && users.length < 250) users.push(username);
        } else {
          const idx = users.indexOf(username);
          if (idx !== -1) users.splice(idx, 1);
        }

        if (users.length > 0) {
          currentReactions[emoji] = users;
        } else {
          delete currentReactions[emoji];
        }

        const updated = { ...msg, reactions: currentReactions };
        updatedMessage = updated;
        return updated;
      }));

      if (updatedMessage) {
        try { void saveMessageRef.current(updatedMessage); } catch { }
      }
    } catch { }
  }, [setMessages, allowEvent]);

  useEffect(() => {
    window.addEventListener(EventType.LOCAL_MESSAGE_DELETE, handleLocalMessageDelete as EventListener);
    window.addEventListener(EventType.LOCAL_MESSAGE_EDIT, handleLocalMessageEdit as EventListener);
    window.addEventListener(EventType.LOCAL_FILE_MESSAGE, handleLocalFileMessage as EventListener);
    window.addEventListener(EventType.LOCAL_REACTION_UPDATE, handleLocalReactionUpdate as EventListener);

    return () => {
      window.removeEventListener(EventType.LOCAL_MESSAGE_DELETE, handleLocalMessageDelete as EventListener);
      window.removeEventListener(EventType.LOCAL_MESSAGE_EDIT, handleLocalMessageEdit as EventListener);
      window.removeEventListener(EventType.LOCAL_FILE_MESSAGE, handleLocalFileMessage as EventListener);
      window.removeEventListener(EventType.LOCAL_REACTION_UPDATE, handleLocalReactionUpdate as EventListener);
    };
  }, [handleLocalMessageDelete, handleLocalMessageEdit, handleLocalFileMessage, handleLocalReactionUpdate]);
}
