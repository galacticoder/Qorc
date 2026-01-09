/**
 * Message type handler functions for processing different message types
 */

import { v4 as uuidv4 } from 'uuid';
import websocketClient from '../websocket/websocket';
import { SignalType } from './signal-types';
import { EventType } from './event-types';
import { Message } from '../../components/chat/messaging/types';
import {
  safeJsonParseForMessages,
  safeJsonParseForFileMessages,
  safeJsonParseForCallSignals,
  createBlobUrlFromBase64,
  createBlobCache
} from '../utils/message-handler-utils';

export interface DeliveryReceiptContext {
  currentUser: string;
  senderUsername: string;
  messageId: string;
  payloadFrom: string;
  kyber: string | null;
  hybrid: {
    kyberPublicBase64?: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
  } | null;
}

export interface FileMessageContext {
  payload: {
    content: string;
    messageId?: string;
    fileName?: string;
    fileType?: string;
    fileSize?: number;
    from: string;
    to?: string;
    timestamp?: number;
    version?: string;
  };
  loginUsername: string;
  blobCache: ReturnType<typeof createBlobCache>;
}

export interface TextMessageContext {
  payload: {
    content: string;
    messageId?: string;
    from: string;
    to?: string;
    timestamp?: number;
    version?: string;
    p2p?: boolean;
    replyTo?: { id: string; sender?: string; content?: string };
  };
  loginUsername: string;
  existingMessages: Message[];
}

export interface CallSignalContext {
  payload: {
    content: string;
    from: string;
    fromOriginal?: string;
  };
}

// Wait for a Signal Protocol session to be ready with the peer
export async function waitForSessionReady(
  senderUsername: string,
  timeoutMs: number = 10000
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve(false);
      }
    }, timeoutMs);

    const handleSessionReady = (event: Event) => {
      const customEvent = event as CustomEvent;
      if (customEvent.detail?.peer === senderUsername) {
        if (!settled) {
          settled = true;
          cleanup();
          resolve(true);
        }
      }
    };

    const handleBundleFailed = (event: Event) => {
      const customEvent = event as CustomEvent;
      if (customEvent.detail?.peer === senderUsername) {
        if (!settled) {
          settled = true;
          cleanup();
          resolve(false);
        }
      }
    };

    const cleanup = () => {
      clearTimeout(timeout);
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady);
      window.removeEventListener(EventType.LIBSIGNAL_BUNDLE_FAILED, handleBundleFailed);
    };

    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady);
    window.addEventListener(EventType.LIBSIGNAL_BUNDLE_FAILED, handleBundleFailed);
  });
}

// Request a bundle and optionally wait for session to be ready
export async function requestBundleAndWait(
  senderUsername: string,
  waitForSession: boolean = true,
  timeoutMs: number = 10000
): Promise<boolean> {
  try {
    const sessionReadyPromise = waitForSession
      ? waitForSessionReady(senderUsername, timeoutMs)
      : Promise.resolve(true);

    await websocketClient.sendSecureControlMessage({
      type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
      username: senderUsername
    });

    return await sessionReadyPromise;
  } catch {
    return false;
  }
}

// Create a delivery receipt payload
export function createDeliveryReceiptPayload(
  messageId: string,
  fromUsername: string,
  toUsername: string
): Record<string, unknown> {
  return {
    messageId: `delivery-receipt-${messageId}`,
    from: fromUsername,
    to: toUsername,
    content: SignalType.DELIVERY_RECEIPT,
    timestamp: Date.now(),
    messageType: SignalType.SIGNAL_PROTOCOL,
    signalType: SignalType.SIGNAL_PROTOCOL,
    protocolType: SignalType.SIGNAL,
    type: SignalType.DELIVERY_RECEIPT
  };
}

// Send an encrypted delivery receipt
export async function sendEncryptedDeliveryReceipt(
  ctx: DeliveryReceiptContext
): Promise<boolean> {
  const { currentUser, senderUsername, messageId, payloadFrom, kyber, hybrid } = ctx;

  if (!hybrid || !hybrid.dilithiumPublicBase64) {
    return false;
  }

  try {
    const deliveryReceiptData = createDeliveryReceiptPayload(messageId, currentUser, payloadFrom);

    let encryptedMessage = await (window as any).edgeApi?.encrypt?.({
      fromUsername: currentUser,
      toUsername: payloadFrom,
      plaintext: JSON.stringify(deliveryReceiptData),
      recipientKyberPublicKey: kyber,
      recipientHybridKeys: hybrid || undefined
    });

    // Retry once if session error
    if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
      const errMsg = String(encryptedMessage?.error || '');
      if (/session|no valid sessions|no session|invalid whisper message|decryption failed/i.test(errMsg)) {
        const sessionReady = await requestBundleAndWait(senderUsername, true, 1500);
        if (sessionReady) {
          encryptedMessage = await (window as any).edgeApi?.encrypt?.({
            fromUsername: currentUser,
            toUsername: payloadFrom,
            plaintext: JSON.stringify(deliveryReceiptData),
            recipientKyberPublicKey: kyber,
            recipientHybridKeys: hybrid || undefined
          });
        }
      }
    }

    if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
      return false;
    }

    const deliveryReceiptPayload = {
      type: SignalType.ENCRYPTED_MESSAGE,
      to: payloadFrom,
      encryptedPayload: encryptedMessage.encryptedPayload
    };

    websocketClient.send(JSON.stringify(deliveryReceiptPayload));
    return true;
  } catch {
    return false;
  }
}

// Parse file message payload
export function parseFileMessagePayload(ctx: FileMessageContext): {
  messageId: string;
  fileName: string;
  fileType: string;
  fileSize: number;
  dataBase64: string | null;
  contentValue: string;
} {
  const { payload, blobCache } = ctx;

  let messageId = payload.messageId || uuidv4();
  let fileName = payload.fileName || 'File';
  let fileType = payload.fileType || 'application/octet-stream';
  let fileSize = payload.fileSize || 0;
  let dataBase64: string | null = null;

  const fileContentData = safeJsonParseForFileMessages(payload.content);
  if (fileContentData) {
    messageId = fileContentData.messageId || messageId;
    fileName = fileContentData.fileName || fileContentData.fileData || payload.fileName || 'File';
    fileType = fileContentData.fileType || fileType;
    fileSize = fileContentData.fileSize || fileSize;
    dataBase64 = fileContentData.dataBase64 || null;
  }

  let contentValue: string = payload.content;
  if (dataBase64 && typeof dataBase64 === 'string') {
    const blobUrl = createBlobUrlFromBase64(dataBase64, fileType, blobCache);
    if (blobUrl) {
      contentValue = blobUrl;
    }
  }

  return { messageId, fileName, fileType, fileSize, dataBase64, contentValue };
}

// Create a file message object
export function createFileMessage(
  messageId: string,
  fileContent: string,
  sender: string,
  recipient: string,
  timestamp: Date,
  fileName: string,
  fileType: string,
  fileSize: number,
  dataBase64: string | null,
  version: string = '1.0'
): Message {
  return {
    id: messageId,
    content: fileContent,
    sender,
    recipient,
    timestamp,
    type: SignalType.FILE,
    isCurrentUser: false,
    filename: fileName,
    mimeType: fileType,
    fileSize,
    originalBase64Data: dataBase64,
    version,
    fileInfo: {
      name: fileName || 'File',
      type: fileType,
      size: fileSize,
      data: new ArrayBuffer(0)
    }
  };
}

// Parse text message payload
export function parseTextMessagePayload(ctx: TextMessageContext): {
  messageId: string;
  messageContent: string;
  replyTo?: { id: string; sender: string; content: string };
} | null {
  const { payload, existingMessages } = ctx;
  const trimmedContent = payload.content.trim();

  // Skip typing indicators
  if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
    const typingCheckData = safeJsonParseForMessages(payload.content);
    if (typingCheckData && (typingCheckData.type === SignalType.TYPING_START || typingCheckData.type === SignalType.TYPING_STOP)) {
      return null;
    }
  }

  let messageId = payload.messageId || uuidv4();
  let messageContent = payload.content;

  // Parse content if it looks like JSON
  if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
    const contentData = safeJsonParseForMessages(payload.content);
    if (contentData && contentData.messageId) {
      messageId = contentData.messageId;
      messageContent = contentData.content || contentData.message || payload.content;
      if (contentData.replyTo) {
        payload.replyTo = contentData.replyTo;
      }
    }
  }

  let replyTo: { id: string; sender: string; content: string } | undefined;
  if (payload.replyTo && typeof payload.replyTo === 'object' && payload.replyTo.id) {
    let replyContent = payload.replyTo.content || '';
    const ref = existingMessages.find(m => m.id === payload.replyTo!.id);
    if (!replyContent) {
      if (ref?.isDeleted) {
        replyContent = 'Message deleted';
      } else if (ref?.content) {
        replyContent = ref.content;
      }
    }
    if (!replyContent || replyContent.trim().length === 0) {
      replyContent = "Message doesn't exist";
    }
    replyTo = {
      id: payload.replyTo.id,
      sender: payload.replyTo.sender || (ref?.sender ?? payload.from),
      content: replyContent
    };
  }

  return { messageId, messageContent, replyTo };
}

// Create a text message object
export function createTextMessage(
  messageId: string,
  content: string,
  sender: string,
  recipient: string,
  timestamp: Date,
  p2p: boolean,
  version: string = '1.0',
  replyTo?: { id: string; sender: string; content: string }
): Message {
  return {
    id: messageId,
    content,
    sender,
    recipient,
    timestamp,
    type: SignalType.TEXT,
    isCurrentUser: false,
    p2p,
    encrypted: true,
    version,
    ...(replyTo && { replyTo })
  };
}

// Handle call signal payload
export function handleCallSignal(ctx: CallSignalContext): boolean {
  const callSignalData = safeJsonParseForCallSignals(ctx.payload.content);
  if (!callSignalData) {
    return false;
  }

  try {
    const originalFrom = ctx.payload.fromOriginal;
    if (typeof originalFrom === 'string') {
      window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_RECEIVED, {
        detail: { hashed: ctx.payload.from, original: originalFrom }
      }));
      (callSignalData as any).fromOriginal = originalFrom;
    }
  } catch { }

  window.dispatchEvent(new CustomEvent(EventType.CALL_SIGNAL, {
    detail: callSignalData
  }));

  return true;
}
