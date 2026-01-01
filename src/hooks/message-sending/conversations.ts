import { Message } from '../../components/chat/messaging/types';
import { Conversation } from '../../components/chat/messaging/ConversationList';
import { SignalType } from '../../lib/signal-types';
import { sanitizeEventPayload, sanitizeTextInput } from '../../lib/sanitizers';
import { MAX_PREVIEW_LENGTH, CONVERSATION_MIN_USERNAME_LENGTH, CONVERSATION_MAX_USERNAME_LENGTH, CONVERSATION_USERNAME_PATTERN, HEX_PATTERN, IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, AUDIO_EXTENSIONS } from '../../lib/constants';

// Dispatch sanitized events only
export const dispatchSafeEvent = (name: string, detail: Record<string, unknown>, allowedKeys?: string[]): void => {
  try {
    const sanitized = sanitizeEventPayload(detail, allowedKeys);
    window.dispatchEvent(new CustomEvent(name, { detail: sanitized }));
  } catch (_error) {
    console.error(`[useConversations] Failed to dispatch event ${name}:`, _error);
  }
};

// Sanitize preview text for display
export const sanitizePreviewText = (input: string | undefined | null): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  const clean = sanitizeTextInput(input, { maxLength: MAX_PREVIEW_LENGTH, allowNewlines: false });
  return clean.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
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
    const hasExtension = (extensions: readonly string[]) =>
      extensions.some(ext => normalizedFilename.endsWith(`.${ext}`));

    if (filename && hasExtension(IMAGE_EXTENSIONS)) {
      return `${prefix} sent an image`;
    }
    if (filename && hasExtension(VIDEO_EXTENSIONS)) {
      return `${prefix} sent a video`;
    }
    if (filename && (normalizedFilename.includes('voice-note') || hasExtension(AUDIO_EXTENSIONS))) {
      return `${prefix} sent a voice message`;
    }
    return `${prefix} sent a file`;
  }

  return sanitizePreviewText(message.content);
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
export const createConversation = (username: string, isOnline: boolean): Conversation => ({
  id: crypto.randomUUID(),
  username,
  isOnline,
  lastMessage: undefined,
  lastMessageTime: undefined,
  unreadCount: 0
});
