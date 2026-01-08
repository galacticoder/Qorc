import type { Message } from '../../components/chat/messaging/types';
import type { SecureDB } from '../../lib/database/secureDB';
import { DB_MAX_PENDING_MESSAGES, DB_MAX_MESSAGES } from '../../lib/constants';

// Process message from DB format to UI format
export const processMessageFromDB = (msg: any, currentUser: string): Message => ({
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
      const mergedReceipt = {
        delivered: existing.receipt?.delivered || processed.receipt?.delivered || false,
        read: existing.receipt?.read || processed.receipt?.read || false,
        deliveredAt: existing.receipt?.deliveredAt || processed.receipt?.deliveredAt,
        readAt: existing.receipt?.readAt || processed.receipt?.readAt,
      };
      existingMap.set(processed.id, { ...existing, receipt: mergedReceipt });
    } else {
      existingMap.set(processed.id, processed);
    }
  }

  const merged = Array.from(existingMap.values());
  merged.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  return merged;
};

// Load recent messages by conversation
export const loadRecentMessages = async (
  secureDB: SecureDB,
  currentUser: string,
  limit: number = 50
): Promise<Message[]> => {
  const savedMessages = await secureDB.loadRecentMessagesByConversation(limit, currentUser);
  if (!savedMessages || savedMessages.length === 0) return [];
  return savedMessages.map((msg: any) => processMessageFromDB(msg, currentUser));
};

// Load all messages in background
export const loadAllMessages = async (
  secureDB: SecureDB,
  currentUser: string
): Promise<Message[]> => {
  const allMessages = await secureDB.loadMessages();
  if (!allMessages || allMessages.length === 0) return [];
  return allMessages.map((msg: any) => processMessageFromDB(msg, currentUser));
};

// Load conversation messages with pagination
export const loadConversationMessages = async (
  secureDB: SecureDB,
  peerUsername: string,
  currentUser: string,
  limit: number = 50,
  offset: number = 0
): Promise<Message[]> => {
  const messages = await secureDB.loadConversationMessages(peerUsername, currentUser, limit, offset);
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

  const currentMessages = (await secureDB.loadMessages()) || [];
  const mergedMap = new Map<string, Message>();
  
  [...currentMessages, ...pendingMessages].forEach((msg: Message) => {
    mergedMap.set(msg.id!, msg);
  });
  
  const limited = Array.from(mergedMap.values()).slice(-DB_MAX_MESSAGES);
  const storedMessages = limited.map(m => ({
    ...m,
    timestamp: m.timestamp instanceof Date ? m.timestamp.getTime() : m.timestamp,
  }));
  
  await secureDB.saveMessages(storedMessages as any);
};

// Save message
export const saveMessageBatch = async (
  secureDB: SecureDB,
  pendingMessages: Map<string, Message>,
  activeConversationPeer?: string
): Promise<void> => {
  if (pendingMessages.size === 0) return;

  const msgs = (await secureDB.loadMessages().catch(() => [])) || [];

  for (const [msgId, pendingMsg] of pendingMessages.entries()) {
    const idx = msgs.findIndex((m: Message) => m.id === msgId);
    if (idx !== -1) {
      msgs[idx] = pendingMsg;
    } else {
      msgs.push(pendingMsg);
    }
  }

  await secureDB.saveMessages(msgs, activeConversationPeer);
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
