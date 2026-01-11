import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import websocketClient from '../../lib/websocket/websocket';
import { secureMessageQueue } from '../../lib/database/secure-message-queue';
import { MAX_PAYLOAD_CACHE_SIZE } from '../../lib/constants';
import type { HybridPublicKeys } from '../../lib/types/message-sending-types';
import { ensureSession } from './session';
import {
  TEXT_ENCODER,
  logError,
  createCoverPadding
} from '../../lib/utils/message-sending-utils';

// Global caches
export const globalEncryptedPayloadCache = new Map<string, { encryptedPayload: any; to: string; messageId: string }>();
export const globalLongTermStoreAttempted = new Set<string>();

// Build message payload
export const buildMessagePayload = (
  wireMessageId: string,
  currentUser: string,
  recipientUsername: string,
  sanitizedContent: string | undefined,
  timestamp: number,
  messageType: string,
  messageSignalType: string | undefined,
  localKeys: { kyber: { publicKeyBase64: string }; dilithium: { publicKeyBase64: string; secretKey: Uint8Array } },
  originalUsernameRef: React.RefObject<string>,
  replyToData?: { id: string; sender?: string; content?: string },
  fileData?: string,
  originalMessageId?: string,
  editMessageId?: string,
  senderSignalBundle?: any
): Record<string, unknown> => {
  const payload: Record<string, unknown> = {
    messageId: wireMessageId,
    from: currentUser,
    to: recipientUsername,
    content: sanitizedContent,
    timestamp,
    type: messageType,
    signalType: messageSignalType,
    senderKyberPublicBase64: localKeys.kyber.publicKeyBase64,
    ...(senderSignalBundle ? { senderSignalBundle } : {}),
    ...(editMessageId ? { editMessageId } : {}),
  };

  if (originalUsernameRef.current && originalUsernameRef.current !== currentUser) {
    payload.fromOriginal = originalUsernameRef.current;
  }

  if (replyToData) {
    payload.replyTo = replyToData;
  }
  if (fileData) {
    payload.fileData = fileData;
  }
  if (messageSignalType === SignalType.DELETE_MESSAGE && originalMessageId) {
    payload.deleteMessageId = originalMessageId;
  }
  if (
    (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) &&
    originalMessageId
  ) {
    payload.reactTo = originalMessageId;
    payload.emoji = sanitizedContent;
  }

  const coverPadding = createCoverPadding();
  if (coverPadding) {
    payload.coverPadding = coverPadding;
  }

  if (editMessageId) {
    payload.editMessageId = editMessageId;
  }

  return payload;
};

// Encrypt and send message
export const encryptAndSend = async (
  payload: Record<string, unknown>,
  currentUser: string,
  recipientUsername: string,
  recipientKyberKey: string,
  recipientHybridKeys: HybridPublicKeys,
  localKeys: { dilithium: { publicKeyBase64: string; secretKey: Uint8Array } },
  sessionLocksRef: React.RefObject<WeakMap<object, Map<string, Promise<boolean>>>>,
  lockContext: object
): Promise<{ success: boolean; encryptedPayload?: any; error?: string }> => {
  let encrypted = await (window as any).edgeApi.encrypt({
    fromUsername: currentUser,
    toUsername: recipientUsername,
    plaintext: JSON.stringify(payload),
    recipientKyberPublicKey: recipientKyberKey,
    recipientHybridKeys: {
      ...recipientHybridKeys,
      kyberPublicBase64: recipientKyberKey,
    }
  });

  if (!encrypted?.success && encrypted?.error?.includes('session') && encrypted?.error?.includes('not found')) {
    const retrySession = await ensureSession(
      sessionLocksRef.current,
      lockContext,
      currentUser,
      recipientUsername,
      { secretKey: localKeys.dilithium.secretKey, publicKeyBase64: localKeys.dilithium.publicKeyBase64 },
    );

    if (retrySession) {
      encrypted = await (window as any).edgeApi.encrypt({
        fromUsername: currentUser,
        toUsername: recipientUsername,
        plaintext: JSON.stringify(payload),
        recipientKyberPublicKey: recipientKyberKey,
        recipientHybridKeys: {
          ...recipientHybridKeys,
          kyberPublicBase64: recipientKyberKey,
        }
      });
    }
  }

  return encrypted;
};

// Cache encrypted payload
export const cacheEncryptedPayload = (recipientUsername: string, wireMessageId: string, encryptedPayload: any) => {
  try {
    const cacheKey = `${recipientUsername}|${wireMessageId}`;
    globalEncryptedPayloadCache.set(cacheKey, {
      encryptedPayload,
      to: recipientUsername,
      messageId: wireMessageId
    });
    
    if (globalEncryptedPayloadCache.size > MAX_PAYLOAD_CACHE_SIZE) {
      const firstKey = globalEncryptedPayloadCache.keys().next().value;
      if (firstKey) {
        globalEncryptedPayloadCache.delete(firstKey);
      }
    }
  } catch { }
};

// Dispatch local events after send
export const dispatchLocalEvents = (
  messageType: string,
  messageSignalType: string | undefined,
  originalMessageId: string | undefined,
  editMessageId: string | undefined,
  wireMessageId: string,
  sanitizedContent: string | undefined,
  currentUser: string
): boolean => {
  if (messageType === SignalType.DELETE_MESSAGE && originalMessageId) {
    window.dispatchEvent(
      new CustomEvent(EventType.LOCAL_MESSAGE_DELETE, { detail: { messageId: originalMessageId } }),
    );
    return true;
  }

  if (messageType === SignalType.EDIT_MESSAGE) {
    const targetId = editMessageId || wireMessageId;
    window.dispatchEvent(
      new CustomEvent(EventType.LOCAL_MESSAGE_EDIT, { detail: { messageId: targetId, newContent: sanitizedContent } }),
    );
    return true;
  }

  if (
    (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) &&
    originalMessageId
  ) {
    window.dispatchEvent(new CustomEvent(EventType.LOCAL_REACTION_UPDATE, {
      detail: {
        messageId: originalMessageId,
        emoji: sanitizedContent,
        isAdd: messageSignalType === SignalType.REACTION_ADD,
        username: currentUser
      }
    }));
    return true;
  }

  if (messageType === SignalType.TYPING_INDICATOR) {
    return true;
  }

  return false;
};

// Store unacknowledged message for retry on session reset
export const storeUnacknowledgedMessage = async (
  secureDBRef: React.RefObject<any> | undefined,
  recipientUsername: string,
  timestamp: number,
  messageData: any
) => {
  if (!secureDBRef?.current) return;

  try {
    await secureDBRef.current.storeEphemeral(
      'unacknowledged-messages',
      `${recipientUsername}:${timestamp}`,
      messageData,
      30000,
      true
    );

    const messageListKey = `${recipientUsername}:message-list`;
    await secureDBRef.current.appendEphemeralList(
      'unacknowledged-messages',
      messageListKey,
      timestamp,
      500,
      30000
    );
  } catch (_error) {
    logError('unack-msg-store-failed', _error);
  }
};

// Queue message when keys are unavailable
export const queueMessageForLater = async (
  recipientUsername: string,
  sanitizedContent: string,
  messageId: string,
  replyToData: { id: string; sender?: string; content?: string } | undefined,
  fileDataToSend: string | undefined,
  messageSignalType: string | undefined,
  editMessageId: string | undefined
) => {
  await secureMessageQueue.queueMessage(recipientUsername, sanitizedContent ?? '', {
    messageId,
    replyTo: replyToData,
    fileData: fileDataToSend,
    messageSignalType,
    originalMessageId: messageId,
    editMessageId,
  });
};

// Request bundle for retry
export const requestBundleForRetry = async (
  recipientUsername: string,
  currentUser: string,
  getKeysOnDemand: () => Promise<any>,
  lastSessionBundleReqTsRef: React.RefObject<Map<string, number>>
) => {
  try {
    const now = Date.now();
    const last = lastSessionBundleReqTsRef.current.get(recipientUsername) || 0;
    if (now - last >= 3000) {
      lastSessionBundleReqTsRef.current.set(recipientUsername, now);
      const keys = await getKeysOnDemand();
      if (keys?.dilithium?.secretKey && keys.dilithium.publicKeyBase64) {
        const req = {
          type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
          username: recipientUsername,
          from: currentUser,
          timestamp: now,
          challenge: CryptoUtils.Base64.arrayBufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
          senderDilithium: keys.dilithium.publicKeyBase64,
          reason: 'retry-after-session-error',
        } as const;
        const canonical = TEXT_ENCODER.encode(JSON.stringify(req));
        const sigRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
        const signature = CryptoUtils.Base64.arrayBufferToBase64(sigRaw);
        await websocketClient.sendSecureControlMessage({ ...req, signature });
      }
    }
  } catch { }
};
