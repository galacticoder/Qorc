import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import { sanitizeNonEmptyText, isUnsafeObjectKey, sanitizeMessageId } from '../../lib/sanitizers';
import { MAX_LOCAL_EMOJI_LENGTH } from '../../lib/constants';
import type { Message } from '../../components/chat/messaging/types';
import { nativeMessageContent, notifications, tray } from '../../lib/tauri-bindings';
import {
  applyDeleteControl,
  applyEditControl,
  applyReactionControl,
  hasWireMessageId,
  type MessageControlOutcome,
} from '../../lib/messages/message-controls';

type PersistedMessageMutator = (
  peerUsername: string,
  messageId: string,
  mutator: (message: Message) => Message | null
) => Promise<Message | null>;

// Dispatch read receipt event
export const dispatchReadReceiptEvent = (messageId: string, from: string, account: string): void => {
  const event = new CustomEvent(EventType.MESSAGE_READ, {
    detail: { account, messageId, from }
  });
  window.dispatchEvent(event);
};

// Dispatch delivery receipt event
export const dispatchDeliveryReceiptEvent = (messageId: string, from: string, account: string): void => {
  const event = new CustomEvent(EventType.MESSAGE_DELIVERED, {
    detail: { account, messageId, from }
  });
  window.dispatchEvent(event);
};

// Dispatch typing indicator event
export const dispatchTypingIndicatorEvent = (
  payload: { from: string; type: string }
): void => {
  try {
    const event = new CustomEvent(EventType.TYPING_INDICATOR, {
      detail: {
        username: String(payload.from || ''),
        action: payload.type === SignalType.TYPING_STOP ? 'stop' : 'start'
      }
    });
    window.dispatchEvent(event);
  } catch (_e) {
    console.error('[EncryptedMessageHandler] Failed to dispatch typing indicator:', _e);
  }
};

// Clear typing indicator for a sender
export const clearTypingIndicator = (from: string): void => {
  try {
    const typingClearEvent = new CustomEvent(EventType.TYPING_INDICATOR, {
      detail: { username: from, action: 'stop' }
    });
    window.dispatchEvent(typingClearEvent);
  } catch { }
};

export const handleMessageDeletion = async (
  payload: { deleteMessageId?: string; from?: string; messageId?: string },
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  isCurrentAccount: () => boolean,
  account: string,
  mutatePersistedMessage?: PersistedMessageMutator,
): Promise<boolean> => {
  if (!isCurrentAccount()) return false;
  const messageIdToDelete = sanitizeMessageId(payload.deleteMessageId);
  if (!messageIdToDelete) return false;
  const from = payload.from;
  const operationId = sanitizeMessageId(payload.messageId);
  if (!from || !operationId || !mutatePersistedMessage) return false;

  let outcome: MessageControlOutcome | null = null;
  const persisted = await mutatePersistedMessage(from, messageIdToDelete, (message) => {
    outcome = applyDeleteControl(message, from, operationId);
    return outcome?.message ?? null;
  });
  if (!persisted || !outcome || !isCurrentAccount()) return false;
  if (!outcome.changed) return true;

  setMessages((prev) => !isCurrentAccount() ? prev : prev.map((message) => (
    hasWireMessageId(message, messageIdToDelete) && message.sender === from
      ? {
          ...message,
          isDeleted: true,
          content: 'This message was deleted',
          controlState: persisted.controlState,
        }
      : message
  )));
  await nativeMessageContent.delete(persisted.secureContentId || messageIdToDelete).catch(() => false);

  try {
    const deleteEvent = new CustomEvent(EventType.REMOTE_MESSAGE_DELETE, {
      detail: { account, messageId: messageIdToDelete }
    });
    window.dispatchEvent(deleteEvent);
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Failed to dispatch remote delete event:', _error);
  }
  return true;
};

// Handle message editing
export const handleMessageEdit = async (
  payload: { editMessageId?: string; content?: string; nativeContentRef?: string; from?: string; messageId?: string },
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  isCurrentAccount: () => boolean,
  account: string,
  mutatePersistedMessage?: PersistedMessageMutator,
): Promise<boolean> => {
  if (!isCurrentAccount()) return false;
  const messageIdToEdit = sanitizeMessageId(payload.editMessageId);
  const nativeContentRef = sanitizeMessageId(payload.nativeContentRef);
  const from = payload.from;
  const operationId = sanitizeMessageId(payload.messageId);
  if (
    !messageIdToEdit || !nativeContentRef || payload.content !== '' ||
    !from || !operationId || !mutatePersistedMessage
  ) return false;

  let outcome: MessageControlOutcome | null = null;
  const persisted = await mutatePersistedMessage(from, messageIdToEdit, (message) => {
    outcome = applyEditControl(message, from, operationId);
    return outcome?.changed
      ? {
          ...outcome.message,
          content: '',
          secureContentId: message.secureContentId || messageIdToEdit,
        }
      : outcome?.message ?? null;
  });
  if (!persisted || !outcome || !isCurrentAccount()) return false;
  
  if (persisted.isDeleted) return true;
  const editApplied = outcome.changed;
  const secureContentId = persisted.secureContentId || messageIdToEdit;
  const isExactRetry = persisted.controlState?.editOperationId === operationId;
  if (!editApplied && !isExactRetry) return true;
  const contentCommit = await nativeMessageContent.commitPending(
    account,
    nativeContentRef,
    messageIdToEdit,
    secureContentId,
    true,
  );
  if (!contentCommit.stored && !contentCommit.duplicate) return false;
  if (!isCurrentAccount()) return false;
  setMessages((prev) => !isCurrentAccount() ? prev : prev.map((message) => (
    hasWireMessageId(message, messageIdToEdit) && message.sender === from
      ? {
          ...message,
          content: '',
          secureContentId,
          isEdited: persisted.isEdited === true,
          controlState: persisted.controlState,
        }
      : message
  )));

  if (!editApplied) return true;

  try {
    const editEvent = new CustomEvent(EventType.REMOTE_MESSAGE_EDIT, {
      detail: { account, messageId: messageIdToEdit, contentVaultId: secureContentId }
    });
    window.dispatchEvent(editEvent);
  } catch (_error) {
    console.error('[EncryptedMessageHandler] Failed to dispatch remote edit event:', _error);
  }

  if (payload.from) clearTypingIndicator(payload.from);
  return true;
};

export const handleReaction = async (
  payload: { type: string; reactTo?: string; emoji?: string; from: string; messageId?: string },
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  isCurrentAccount: () => boolean,
  mutatePersistedMessage?: PersistedMessageMutator,
): Promise<boolean> => {
  if (!isCurrentAccount()) return false;
  const reactTo = sanitizeMessageId(payload.reactTo);
  const actor = payload.from;
  
  const emoji = sanitizeNonEmptyText(payload.emoji, MAX_LOCAL_EMOJI_LENGTH, false);
  const operationId = sanitizeMessageId(payload.messageId);
  if (!reactTo || !emoji || !actor || !operationId || isUnsafeObjectKey(emoji) || !mutatePersistedMessage) return false;
  const isAdd = (payload.type === SignalType.REACTION_ADD);

  let outcome: MessageControlOutcome | null = null;
  const persisted = await mutatePersistedMessage(actor, reactTo, (message) => {
    outcome = applyReactionControl(message, actor, operationId, emoji, isAdd);
    return outcome?.message ?? null;
  });
  if (!persisted || !outcome || !isCurrentAccount()) return false;
  if (!outcome.changed) return true;

  setMessages((prev) => !isCurrentAccount() ? prev : prev.map((message) => (
    hasWireMessageId(message, reactTo) && (actor === message.sender || actor === message.recipient)
      ? { ...message, reactions: persisted.reactions, controlState: persisted.controlState }
      : message
  )));
  return true;
};

// Show notification when window is unfocused or hidden
export const showNotification = (
  payload: { from: string },
  loginUsername: string
): void => {
  if (payload.from === loginUsername) return;

  try {
    // Check if window is hidden or unfocused
    const isHidden = document.hidden;
    const isFocused = document.hasFocus();
    const shouldNotify = isHidden || !isFocused;

    if (shouldNotify) {
      notifications.show()
        .catch((e: Error) => console.error('[EncryptedMessageHandler] Notification failed:', e));

      tray.incrementUnread().catch(() => { });
    } else {
    }
  } catch (e) {
    console.error('[EncryptedMessageHandler] Notification error:', e);
  }
};
