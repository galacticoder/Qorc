import { SignalType } from '../types/signal-types';
import { Message } from '../../components/chat/messaging/types';
import { sanitizeMessageId, sanitizeUsername } from '../sanitizers';
import { AUTH_USERNAME_REGEX, MAX_ID_CACHE_SIZE, ID_CACHE_TTL_MS } from '../constants';
import type { IdCache, SessionApi } from '../types/message-sending-types';
import { nativeMessageContent, signal } from '../tauri-bindings';
import { setBoundedMapEntry } from './message-state-limits';
import { CryptoUtils } from './crypto-utils';

const MAX_SESSION_REQUEST_PEERS = 256;

// Signal type mapping for message types
export const SIGNAL_TYPE_MAP: Record<string, string> = {
  [SignalType.MESSAGE]: SignalType.MESSAGE,
  [SignalType.DELETE_MESSAGE]: SignalType.DELETE_MESSAGE,
  [SignalType.EDIT_MESSAGE]: SignalType.EDIT_MESSAGE,
  [SignalType.REACTION_ADD]: SignalType.REACTION_ADD,
  [SignalType.REACTION_REMOVE]: SignalType.REACTION_REMOVE,
};

// Get session API wrapper for Tauri signal bindings
export const getSessionApi = (): SessionApi => {
  return {
    async hasSession(args: { selfUsername: string; peerUsername: string }) {
      try {
        const result = await signal.hasSession(args.selfUsername, args.peerUsername);
        return { hasSession: result };
      } catch {
        return { hasSession: false };
      }
    },
  };
};

// Sanitize reply data
export const sanitizeReply = (reply: string | { id: string; sender?: string; content?: string } | undefined) => {
  if (!reply) return undefined;
  if (typeof reply === 'string') {
    const id = sanitizeMessageId(reply);
    return id ? { id } : undefined;
  }
  const id = sanitizeMessageId(reply.id);
  if (!id) return undefined;
  const senderCandidate = sanitizeUsername(reply.sender);
  const sender = senderCandidate &&
    senderCandidate === senderCandidate.trim().toLowerCase() &&
    AUTH_USERNAME_REGEX.test(senderCandidate)
      ? senderCandidate
      : null;
  return {
    id,
    ...(sender ? { sender } : {}),
  };
};

// Log error with code prefix
export const logError = (code: string, error?: unknown) => {
  if (error) {
    console.error(`[MessageSender][${code}]`, error);
  } else {
    console.error(`[MessageSender][${code}]`);
  }
};

export const recordSessionRequest = (
  requests: Map<string, number>,
  peer: string,
  timestamp: number,
): void => {
  setBoundedMapEntry(requests, peer, timestamp, MAX_SESSION_REQUEST_PEERS);
};

// Create ID cache for message deduplication
export const getIdCache = (): IdCache => {
  const entries = new Map<string, number>();
  const order: string[] = [];
  return {
    add(id: string) {
      entries.set(id, Date.now());
      order.push(id);
      if (order.length > MAX_ID_CACHE_SIZE) {
        const oldest = order.shift();
        if (oldest) {
          entries.delete(oldest);
        }
      }
    },
    isStale(id: string) {
      const timestamp = entries.get(id);
      if (!timestamp) return true;
      const stale = Date.now() - timestamp > ID_CACHE_TTL_MS;
      if (stale) {
        entries.delete(id);
      }
      return stale;
    },
  };
};

// Map message signal type to wire type
export const mapSignalType = (baseType: string, messageSignalType?: string): string => {
  const candidate = messageSignalType || baseType;
  const mapped = SIGNAL_TYPE_MAP[candidate];
  if (!mapped) throw new Error('Unsupported message operation');
  return mapped;
};

// Create local message for optimistic UI update
export const createLocalMessage = async (
  messageId: string,
  sender: string,
  recipient: string,
  content: string,
  timestamp: number,
  replyToData: { id: string; sender?: string; content?: string } | undefined,
): Promise<Message> => {
  const isVaultable = content && content.trim().length > 0;

  if (isVaultable) {
    const committed = await nativeMessageContent.storeOutgoing(
      messageId,
      content,
      recipient,
      SignalType.MESSAGE,
      messageId,
      false,
    );
    if (!committed.stored && !committed.duplicate) {
      throw new Error('Native message content identifier collision');
    }
  }

  const message: Message = {
    id: messageId,
    content: isVaultable ? '' : content,
    secureContentId: isVaultable ? messageId : undefined,
    sender,
    recipient,
    timestamp: new Date(timestamp),
    type: SignalType.TEXT,
    isCurrentUser: true,
    isDeliberateUserAction: true,
    encrypted: true,
    receipt: { delivered: false, read: false },
  };

  if (replyToData) {
    message.replyTo = {
      ...replyToData,
      content: '',
    };
  }

  return message;
};

// Create cover padding
export const createCoverPadding = () => {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('Secure random number generator is unavailable');
  }
  const lengthBias = globalThis.crypto.getRandomValues(new Uint8Array(1))[0] % 32;
  const length = 32 + lengthBias;
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(length));
  return CryptoUtils.Base64.arrayBufferToBase64(bytes);
};
