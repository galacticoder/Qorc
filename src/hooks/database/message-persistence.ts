import type { Message } from '../../components/chat/messaging/types';
import type { SecureDB } from '../../lib/database/secureDB';
import {
  CONVERSATION_WARM_MESSAGE_COUNT,
  DB_MAX_PENDING_MESSAGES,
} from '../../lib/constants';
import { mergeReceipts } from '../../lib/utils/database-utils';

const isVaultedTextMessage = (msg: Message): boolean => (
  !msg.isSystemMessage &&
  !msg.isDeleted &&
  msg.type !== 'file' &&
  msg.type !== 'file-message' &&
  !msg.filename &&
  !msg.fileInfo
);

export const projectMessageForUi = (msg: Message): Message => {
  const shouldVaultContent = isVaultedTextMessage(msg);
  const replyTo = msg.replyTo
    ? {
        ...msg.replyTo,
        content: '',
      }
    : undefined;

  return {
    ...msg,
    ...(shouldVaultContent
      ? { content: '', secureContentId: msg.secureContentId || msg.id }
      : {}),
    ...(replyTo ? { replyTo } : {}),
  };
};

// Process message from DB format to UI format
export const processMessageFromDB = (msg: any, currentUser: string): Message => projectMessageForUi({
  ...msg,
  timestamp: new Date(msg.timestamp),
  isCurrentUser: msg.sender === currentUser,
  receipt: msg.receipt ? {
    ...msg.receipt,
    deliveredAt: msg.receipt.deliveredAt ? new Date(msg.receipt.deliveredAt) : undefined,
    readAt: msg.receipt.readAt ? new Date(msg.receipt.readAt) : undefined,
  } : undefined,
});

// Merge messages with existing state
export const mergeMessages = (
  existingMessages: Message[],
  newMessages: Message[],
  currentUser: string
): Message[] => {
  const existingMap = new Map(existingMessages.map(msg => [msg.id, msg]));

  for (const dbMsg of newMessages) {
    const processed = processMessageFromDB(dbMsg, currentUser);
    const existing = existingMap.get(processed.id);
    if (existing) {
      existingMap.set(processed.id, {
        ...existing,
        receipt: mergeReceipts(existing.receipt, processed.receipt)
      });
    } else {
      existingMap.set(processed.id, processed);
    }
  }

  const merged = Array.from(existingMap.values());
  merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  return merged;
};

export const loadConversationWarmPages = async (
  secureDB: SecureDB,
  currentUser: string,
  limit = CONVERSATION_WARM_MESSAGE_COUNT,
): Promise<Array<{ peerUsername: string; messages: Message[] }>> => {
  const pages = await secureDB.loadConversationWarmPages(limit);
  return pages.map((page) => ({
    peerUsername: page.peerUsername,
    messages: page.messages.map((message) => processMessageFromDB(message, currentUser)),
  }));
};

// Load conversation messages with pagination
export const loadConversationMessages = async (
  secureDB: SecureDB,
  peerUsername: string,
  currentUser: string,
  limit: number = 50,
  offset: number = 0
): Promise<Message[]> => {
  const messages = await secureDB.loadConversationMessages(peerUsername, limit, offset);
  if (!messages || messages.length === 0) return [];

  const processed = messages.map((msg: any) => processMessageFromDB(msg, currentUser));
  processed.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  return processed;
};

// Flush pending messages to database
export const flushPendingMessages = async (
  secureDB: SecureDB,
  pendingMessages: Message[]
): Promise<void> => {
  if (pendingMessages.length === 0) return;

  const storedMessages = pendingMessages.map(message => ({
    ...message,
    timestamp: message.timestamp instanceof Date ? message.timestamp.getTime() : message.timestamp,
  }));
  await secureDB.upsertMessages(storedMessages as any);
};

// Save message
export const saveMessageBatch = async (
  secureDB: SecureDB,
  pendingMessages: Map<string, Message>,
  activeConversationPeer?: string
): Promise<void> => {
  if (pendingMessages.size === 0) return;

  await secureDB.upsertMessages(
    Array.from(pendingMessages.values()) as any,
    activeConversationPeer
  );
};

// Add message to pending queue
export const addToPendingQueue = (
  pendingMessages: Message[],
  message: Message
): Message[] => {
  const idx = pendingMessages.findIndex(m => m.id === message.id);
  if (idx !== -1) {
    pendingMessages[idx] = message;
  } else {
    pendingMessages.push(message);
    if (pendingMessages.length > DB_MAX_PENDING_MESSAGES) {
      return pendingMessages.slice(-DB_MAX_PENDING_MESSAGES);
    }
  }
  return pendingMessages;
};
