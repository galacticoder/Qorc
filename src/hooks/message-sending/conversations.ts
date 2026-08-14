import { Message } from '../../components/chat/messaging/types';
import { Conversation } from '../../components/chat/messaging/ConversationList';
import { SignalType } from '../../lib/types/signal-types';
import { sanitizeEventPayload, sanitizeTextInput } from '../../lib/sanitizers';
import { MAX_PREVIEW_LENGTH, CONVERSATION_MIN_USERNAME_LENGTH, CONVERSATION_MAX_USERNAME_LENGTH, CONVERSATION_USERNAME_PATTERN, HEX_PATTERN, IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, AUDIO_EXTENSIONS } from '../../lib/constants';
import { hasExtension } from '../../lib/utils/file-utils';

// Dispatch sanitized events only
export const dispatchSafeEvent = (name: string, detail: Record<string, unknown>, allowedKeys?: string[]): void => {
  try {
    const sanitized = sanitizeEventPayload(detail, allowedKeys);
    window.dispatchEvent(new CustomEvent(name, { detail: sanitized }));
  } catch (_error) {
    console.error(`[useConversations] Failed to dispatch event ${name}:`, _error);
  }
};

export const sanitizePreviewText = (input: string | undefined | null): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  return sanitizeTextInput(input, { maxLength: MAX_PREVIEW_LENGTH, allowNewlines: false });
};

// Generate safe preview text from message
export const getConversationPreview = (message: Message, currentUsername: string): string => {
  if (message.type === 'system' || message.isSystemMessage) {
    try {
      const parsed = JSON.parse(message.content);
      if (parsed?.label && typeof parsed.label === 'string') {
        return sanitizePreviewText(parsed.label);
      }
    } catch { }
    return 'System message';
  }

  const filename = sanitizePreviewText(message.filename);
  const isMe = message.sender === currentUsername;
  const prefix = isMe ? 'You' : message.sender;

  const isReactionMessage = message.content?.includes(SignalType.REACTION_ADD) || message.content?.includes(SignalType.REACTION_REMOVE);

  if (isReactionMessage) {
    if (isMe) {
      return 'You reacted to a message';
    } else {
      return `${message.sender} reacted to your message`;
    }
  }

  if (message.type === SignalType.FILE || message.type === SignalType.FILE_MESSAGE || filename) {
    const normalizedFilename = filename?.toLowerCase() || '';
    if (filename && normalizedFilename.includes('voice-note')) {
      return `${prefix} sent a voice message`;
    }
    if (filename && hasExtension(filename, IMAGE_EXTENSIONS)) {
      return `${prefix} sent an image`;
    }
    if (filename && hasExtension(filename, VIDEO_EXTENSIONS)) {
      return `${prefix} sent a video`;
    }
    if (filename && hasExtension(filename, AUDIO_EXTENSIONS)) {
      return `${prefix} sent a voice message`;
    }
    return `${prefix} sent a file`;
  }

  if (message.secureContentId) {
    return '';
  }

  return 'Message';
};

// Validate username format
export const isValidConversationUsername = (username: string): boolean => {
  if (!username || typeof username !== 'string') return false;
  if (username.length < CONVERSATION_MIN_USERNAME_LENGTH || username.length > CONVERSATION_MAX_USERNAME_LENGTH) return false;
  return CONVERSATION_USERNAME_PATTERN.test(username);
};

// Check if string looks like a pseudonym hash
export const isPseudonymHash = (value: string): boolean => {
  return HEX_PATTERN.test(value);
};

// Create a new conversation object
export const createConversation = (username: string): Conversation => ({
  id: crypto.randomUUID(),
  username,
  lastMessage: undefined,
  lastMessageTime: undefined,
  unreadCount: 0
});
