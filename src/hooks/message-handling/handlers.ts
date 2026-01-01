import { EventType } from '../../lib/event-types';
import { SignalType } from '../../lib/signal-types';
import { CryptoUtils } from '../../lib/unified-crypto';
import { safeJsonParse, safeJsonParseForMessages } from '../../lib/message-handler-utils';
import { sanitizeContent, sanitizeTextInput } from '../../lib/sanitizers';
import type { Message } from '../../components/chat/messaging/types';

// Dispatch read receipt event
export const dispatchReadReceiptEvent = (messageId: string, from: string): void => {
  const event = new CustomEvent(EventType.MESSAGE_READ, {
    detail: { messageId, from }
  });
  window.dispatchEvent(event);
};

// Dispatch delivery receipt event
export const dispatchDeliveryReceiptEvent = (messageId: string, from: string): void => {
  const event = new CustomEvent(EventType.MESSAGE_DELIVERED, {
    detail: { messageId, from }
  });
  window.dispatchEvent(event);
};

// Dispatch typing indicator event
export const dispatchTypingIndicatorEvent = async (
  payload: { from: string; type: string; content?: string }
): Promise<void> => {
  let indicatorType = payload.type;
  if (payload.type === SignalType.TYPING_INDICATOR && payload.content) {
    const contentData = safeJsonParse(payload.content);
    if (contentData && contentData.type) {
      indicatorType = contentData.type;
    } else {
      indicatorType = SignalType.TYPING_START;
    }
  }

  try {
    const username = String(payload.from || '');
    const action = indicatorType === SignalType.TYPING_STOP ? 'stop' : 'start';
    const timestamp = Date.now();
    const nonceBytes = crypto.getRandomValues(new Uint8Array(24));
    const nonce = btoa(String.fromCharCode(...nonceBytes));
    const encoder = new TextEncoder();
    const macKey = await CryptoUtils.Hash.generateBlake3Mac(encoder.encode(nonce), encoder.encode(String(timestamp)));
    const typedPayload = { username, action };
    const payloadBytes = encoder.encode(JSON.stringify(typedPayload));
    const macBytes = await CryptoUtils.Hash.generateBlake3Mac(payloadBytes, macKey);
    const signature = CryptoUtils.Base64.arrayBufferToBase64(macBytes);
    const secureEvent = new CustomEvent(EventType.TYPING_INDICATOR, {
      detail: { signature, timestamp, nonce, payload: typedPayload }
    });
    window.dispatchEvent(secureEvent);
  } catch (_e) {
    console.error('[EncryptedMessageHandler] Failed to dispatch secure typing indicator:', _e);
  }
};

// Clear typing indicator for a sender
export const clearTypingIndicator = (from: string): void => {
  try {
    const typingClearEvent = new CustomEvent(EventType.TYPING_INDICATOR, {
      detail: { from, indicatorType: SignalType.TYPING_STOP }
    });
    window.dispatchEvent(typingClearEvent);
  } catch { }
};

// Handle message deletion
export const handleMessageDeletion = async (
  payload: { deleteMessageId?: string; messageId?: string; content?: string },
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
): Promise<void> => {
  const messageIdToDelete = payload.deleteMessageId || payload.messageId || payload.content;
  if (!messageIdToDelete) return;

  let messageToPersist: Message | null = null;
  setMessages(prev => {
    const updatedMessages = prev.map(msg => {
      if (msg.id === messageIdToDelete) {
        const updated = { ...msg, isDeleted: true, content: 'This message was deleted' } as Message;
        messageToPersist = updated;
        return updated;
      }
      return msg;
    });
    return updatedMessages;
  });

  if (messageToPersist) {
    try { await saveMessageToLocalDB(messageToPersist); } catch { }
  }

  try {
    const deleteEvent = new CustomEvent(EventType.REMOTE_MESSAGE_DELETE, {
      detail: { messageId: messageIdToDelete }
    });
    window.dispatchEvent(deleteEvent);
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Failed to dispatch remote delete event:', _error);
  }
};

// Handle message editing
export const handleMessageEdit = async (
  payload: { messageId?: string; content?: string; from?: string },
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>
): Promise<void> => {
  const messageIdToEdit = payload.messageId;
  const newContent = payload.content;
  if (!messageIdToEdit || !newContent) return;

  let messageToPersist: Message | null = null;
  setMessages(prev => {
    const updatedMessages = prev.map(msg => {
      if (msg.id === messageIdToEdit) {
        const updated = { ...msg, content: newContent, isEdited: true } as Message;
        messageToPersist = updated;
        return updated;
      }
      return msg;
    });
    return updatedMessages;
  });

  if (messageToPersist) {
    try { await saveMessageToLocalDB(messageToPersist); } catch { }
  }

  try {
    const editEvent = new CustomEvent(EventType.REMOTE_MESSAGE_EDIT, {
      detail: { messageId: messageIdToEdit, newContent }
    });
    window.dispatchEvent(editEvent);
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Failed to dispatch remote edit event:', _error);
  }

  try {
    const typingStopEvent = new CustomEvent(EventType.TYPING_INDICATOR, {
      detail: { from: payload.from, indicatorType: SignalType.TYPING_STOP }
    });
    window.dispatchEvent(typingStopEvent);
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Failed to dispatch typing stop for edit:', _error);
  }
};

// Handle reactions
export const handleReaction = (
  payload: { type: string; reactTo?: string; emoji?: string; from: string },
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>
): void => {
  const reactTo = payload.reactTo;
  const emoji = payload.emoji;
  if (!reactTo || typeof emoji !== 'string' || emoji.length === 0) return;

  setMessages(prev => prev.map(msg => {
    if (msg.id !== reactTo) return msg;
    const reactions = { ...(msg.reactions || {}) } as Record<string, string[]>;
    const arr = Array.isArray(reactions[emoji]) ? [...reactions[emoji]] : [];
    const actor = payload.from;
    const has = arr.includes(actor);
    const isAdd = (payload.type === SignalType.REACTION_ADD);

    for (const key of Object.keys(reactions)) {
      if (key !== emoji) {
        reactions[key] = (reactions[key] || []).filter(u => u !== actor);
        if (reactions[key].length === 0) delete reactions[key];
      }
    }
    if (isAdd && !has) arr.push(actor);
    if (!isAdd && has) reactions[emoji] = arr.filter(u => u !== actor);
    else reactions[emoji] = arr;
    if (reactions[emoji].length === 0) delete reactions[emoji];
    return { ...msg, reactions };
  }));
};

// Show notification when window is unfocused
export const showNotification = (
  payload: { from: string; type?: string; content?: string; fileName?: string },
  loginUsername: string,
  isCallSignal: boolean,
  isFileMessage: boolean
): void => {
  if (payload.from === loginUsername) return;

  try {
    const isFocused = document.hasFocus();
    if (!isFocused && (window as any).electronAPI?.showNotification) {
      const senderName = payload.from || 'Someone';
      const title = isCallSignal ? 'Incoming Call' : (isFileMessage ? 'New File' : 'New Message');
      const preview = sanitizeTextInput(payload.content || '', { maxLength: 50, allowNewlines: false });
      const body = isCallSignal
        ? `${senderName} is calling you`
        : isFileMessage
          ? `${senderName} sent a file: ${payload.fileName}`
          : `${senderName}: ${preview}`;

      (window as any).electronAPI.showNotification({
        title,
        body,
        silent: false,
        data: { from: payload.from, type: isCallSignal ? 'call' : SignalType.MESSAGE }
      }).catch((e: Error) => console.error('[EncryptedMessageHandler] Notification failed:', e));
    }
  } catch (e) {
    console.error('[EncryptedMessageHandler] Notification error:', e);
  }
};

// Store username mapping from decrypted payload
export const storeUsernameMapping = (payload: { fromOriginal?: string; from?: string }): void => {
  try {
    const originalFrom = payload.fromOriginal;
    const hashedFrom = payload.from;
    if (typeof originalFrom === 'string' && typeof hashedFrom === 'string') {
      window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_RECEIVED, {
        detail: { hashed: hashedFrom, original: originalFrom }
      }));
    }
  } catch { }
};
