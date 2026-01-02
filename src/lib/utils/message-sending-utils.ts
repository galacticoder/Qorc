import { SignalType } from '../types/signal-types';
import { Message } from '../../components/chat/messaging/types';
import { sanitizeContent, sanitizeUsername } from '../sanitizers';
import { MAX_FILEDATA_LENGTH, BASE64_SAFE_REGEX, MAX_ID_CACHE_SIZE, ID_CACHE_TTL_MS } from '../constants';
import type { IdCache, SessionApi } from '../types/message-sending-types';
import { CryptoUtils } from '../utils/crypto-utils';

export const TEXT_ENCODER = new TextEncoder();

// Signal type mapping for message types
export const SIGNAL_TYPE_MAP: Record<string, string> = {
  [SignalType.TYPING_START]: SignalType.TYPING_INDICATOR,
  [SignalType.TYPING_STOP]: SignalType.TYPING_INDICATOR,
  [SignalType.DELETE_MESSAGE]: SignalType.DELETE_MESSAGE,
  [SignalType.EDIT_MESSAGE]: SignalType.EDIT_MESSAGE,
  [SignalType.REACTION_ADD]: SignalType.REACTION_ADD,
  [SignalType.REACTION_REMOVE]: SignalType.REACTION_REMOVE,
};

// Get session API wrapper for edgeApi
export const getSessionApi = (): SessionApi => {
  const edgeApi = (globalThis as any)?.edgeApi ?? null;
  return {
    async hasSession(args: { selfUsername: string; peerUsername: string; deviceId: number }) {
      if (typeof edgeApi?.hasSession !== 'function') {
        return { hasSession: false };
      }
      try {
        return await edgeApi.hasSession(args);
      } catch {
        return { hasSession: false };
      }
    },
  };
};

// Validate file data for sending
export const validateFileData = (value: string | undefined): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  const inlinePrefixIndex = trimmed.indexOf(',');
  const base64Payload = inlinePrefixIndex > 0 ? trimmed.slice(inlinePrefixIndex + 1) : trimmed;

  if (base64Payload.length > MAX_FILEDATA_LENGTH * 1.4) {
    return undefined;
  }
  if (!BASE64_SAFE_REGEX.test(base64Payload.replace(/=+$/, ''))) {
    return undefined;
  }

  const estimatedBytes = Math.floor((base64Payload.length * 3) / 4) - (base64Payload.endsWith('==') ? 2 : base64Payload.endsWith('=') ? 1 : 0);
  if (estimatedBytes <= 0 || estimatedBytes > MAX_FILEDATA_LENGTH) {
    return undefined;
  }

  return trimmed;
};

// Sanitize reply data
export const sanitizeReply = (reply: string | { id: string; sender?: string; content?: string } | undefined) => {
  if (!reply) return undefined;
  if (typeof reply === 'string') {
    const id = reply.trim();
    return id ? { id } : undefined;
  }
  const id = typeof reply.id === 'string' ? reply.id.trim() : '';
  if (!id) return undefined;
  return {
    id,
    sender: sanitizeUsername(reply.sender),
    content: sanitizeContent(reply.content),
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
export const mapSignalType = (baseType: string, messageSignalType?: string, fileData?: string): string => {
  if (!messageSignalType) {
    return fileData ? SignalType.FILE_MESSAGE : baseType;
  }
  return SIGNAL_TYPE_MAP[messageSignalType] ?? (fileData ? SignalType.FILE_MESSAGE : baseType);
};

// Create local message for optimistic UI update
export const createLocalMessage = (
  messageId: string,
  sender: string,
  recipient: string,
  content: string,
  timestamp: number,
  replyToData?: { id: string; sender?: string; content?: string },
  fileData?: string,
): Message => {
  const message: Message = {
    id: messageId,
    content,
    sender,
    recipient,
    timestamp: new Date(timestamp),
    type: fileData ? SignalType.FILE : SignalType.TEXT,
    isCurrentUser: true,
    receipt: { delivered: false, read: false },
    version: '1',
    ...(replyToData && { replyTo: replyToData }),
  };

  if (fileData) {
    message.fileInfo = {
      name: 'attachment',
      type: 'application/octet-stream',
      size: 0,
      data: new ArrayBuffer(0),
    };
  }

  return message;
};

// Create cover padding for traffic analysis resistance
export const createCoverPadding = () => {
  if (!globalThis.crypto?.getRandomValues) {
    return undefined;
  }
  const lengthBias = globalThis.crypto.getRandomValues(new Uint8Array(1))[0] % 32;
  const length = 32 + lengthBias;
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(length));
  return CryptoUtils.Base64.arrayBufferToBase64(bytes);
};
