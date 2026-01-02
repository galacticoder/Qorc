import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import websocketClient from '../../lib/websocket';
import { safeJsonParseForMessages } from '../../lib/utils/message-handler-utils';
import type { DecryptResult, EncryptedEnvelope } from '../../lib/types/message-handling-types';

// Validate P2P message structure
export const validateP2PMessage = (msg: any, loginUsername: string): boolean => {
  if (!msg.from || !msg.to || !msg.id ||
    typeof msg.from !== 'string' ||
    typeof msg.to !== 'string' ||
    typeof msg.id !== 'string') {
    console.error('[EncryptedMessageHandler] Invalid P2P message structure');
    return false;
  }

  const usernameRegex = /^[a-zA-Z0-9_-]{1,32}$/;
  if (!usernameRegex.test(msg.from) || !usernameRegex.test(msg.to)) {
    console.error('[EncryptedMessageHandler] Invalid username format in P2P message');
    return false;
  }

  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(msg.id)) {
    console.error('[EncryptedMessageHandler] Invalid message ID format');
    return false;
  }

  if (msg.to !== loginUsername) {
    console.error('[EncryptedMessageHandler] P2P message not intended for current user');
    return false;
  }

  if (typeof msg.content !== 'string' || msg.content.length === 0 || msg.content.length > 10000) {
    console.error('[EncryptedMessageHandler] Invalid P2P message content length');
    return false;
  }

  const dangerousPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi, /vbscript:/gi, /data:text\/html/gi,
    /on\w+\s*=/gi, /<iframe\b/gi, /<object\b/gi,
    /<embed\b/gi, /<link\b/gi, /<meta\b/gi
  ];
  if (dangerousPatterns.some(p => p.test(msg.content))) {
    console.error('[EncryptedMessageHandler] Potentially dangerous content detected');
    return false;
  }

  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(msg.content)) {
    console.error('[EncryptedMessageHandler] Invalid control characters in P2P message');
    return false;
  }

  const now = Date.now();
  const messageTime = new Date(msg.timestamp).getTime();
  const maxAge = 24 * 60 * 60 * 1000;
  const maxFuture = 5 * 60 * 1000;
  if (isNaN(messageTime) || messageTime < (now - maxAge) || messageTime > (now + maxFuture)) {
    console.error('[EncryptedMessageHandler] Invalid P2P message timestamp');
    return false;
  }

  return true;
};

// Create P2P payload from validated message
export const createP2PPayload = (msg: any): any => ({
  id: msg.id,
  content: msg.content,
  timestamp: msg.timestamp,
  from: msg.from,
  to: msg.to,
  type: SignalType.MESSAGE,
  p2p: true
});

// Decrypt Signal Protocol message
export const decryptSignalMessage = async (
  encryptedMessage: any,
  currentUser: string,
  processedPreKeyMessagesRef: React.RefObject<Map<string, number>>
): Promise<{ payload: any; attachedChunkData: any } | null> => {
  const envelope = encryptedMessage.encryptedPayload as EncryptedEnvelope;

  if (!envelope || typeof envelope !== 'object' || !('kemCiphertext' in envelope) || !('ciphertext' in envelope)) {
    console.error('[EncryptedMessageHandler] Unsupported envelope format');
    return null;
  }

  const kemCiphertext = envelope?.kemCiphertext;
  if (typeof kemCiphertext === 'string' && kemCiphertext.length > 0) {
    const dedupKey = `${encryptedMessage.from || 'unknown'}:${kemCiphertext}`;
    const retryCount = (encryptedMessage as any)?.__retryCount || 0;
    if (retryCount <= 0 && processedPreKeyMessagesRef.current.has(dedupKey)) {
      return null;
    }
    processedPreKeyMessagesRef.current.set(dedupKey, Date.now());

    const now = Date.now();
    for (const [key, timestamp] of processedPreKeyMessagesRef.current.entries()) {
      if (now - timestamp > 60000) {
        processedPreKeyMessagesRef.current.delete(key);
      }
    }
  }

  const attachedChunkData = envelope?.chunkData;
  const cleanedEnvelope: any = { ...envelope };
  if ('chunkData' in cleanedEnvelope) {
    try { delete cleanedEnvelope.chunkData; } catch { }
  }

  const senderForDecrypt = encryptedMessage.from || '';

  const decrypted: DecryptResult = await (window as any).edgeApi?.decrypt?.({
    fromUsername: senderForDecrypt,
    toUsername: currentUser,
    encryptedData: cleanedEnvelope
  });

  return { payload: decrypted, attachedChunkData };
};

// Process bundle delivery message
export const processBundleDelivery = async (
  encryptedMessage: any,
  currentUser: string
): Promise<boolean> => {
  try {
    const bundle = encryptedMessage.bundle;
    const peerUsername = encryptedMessage.username;

    const bundleResult = await (window as any).edgeApi.processPreKeyBundle({
      selfUsername: currentUser,
      peerUsername,
      bundle
    });

    if (bundleResult?.success) {
      const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername, deviceId: 1 });
      try { window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: peerUsername } })); } catch { }

      try {
        if (has?.hasSession) await websocketClient.sendSecureControlMessage({
          type: SignalType.SESSION_ESTABLISHED,
          from: currentUser,
          username: peerUsername,
          deviceId: 1,
          timestamp: Date.now()
        });
      } catch { }
      return true;
    }
  } catch (_error) {
    try { window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_BUNDLE_FAILED, { detail: { peer: encryptedMessage?.username, error: _error instanceof Error ? _error.message : String(_error) } })); } catch { }
  }
  return false;
};

// Process sender's signal bundle from payload
export const processSenderBundle = async (
  payload: any,
  currentUser: string
): Promise<void> => {
  try {
    const senderUsername = payload?.from;
    if (!currentUser || !senderUsername) return;

    const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername: senderUsername, deviceId: 1 });
    if (!has?.hasSession && payload?.senderSignalBundle) {
      try {
        const bundleResult = await (window as any).edgeApi?.processPreKeyBundle?.({ selfUsername: currentUser, peerUsername: senderUsername, bundle: payload.senderSignalBundle });
        if (bundleResult?.success) {
          const hasNow = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername: senderUsername, deviceId: 1 });
          try { window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: senderUsername } })); } catch { }

          try {
            if (hasNow?.hasSession) await websocketClient.sendSecureControlMessage({
              type: SignalType.SESSION_ESTABLISHED,
              from: currentUser,
              username: senderUsername,
              deviceId: 1,
              timestamp: Date.now()
            });
          } catch { }
        }
      } catch { }
    }
  } catch { }
};

// Trust peer identity on untrusted identity error
export const trustPeerIdentity = async (currentUser: string, peerUsername: string): Promise<void> => {
  try {
    await (window as any).edgeApi?.trustPeerIdentity?.({ selfUsername: currentUser, peerUsername, deviceId: 1 });
  } catch { }
};

// Parse decrypted plaintext to payload
export const parseDecryptedPayload = (plaintext: string, from?: string): any => {
  const payload = safeJsonParseForMessages(plaintext) || { content: plaintext, type: SignalType.MESSAGE };
  if (from && payload && !payload.from) {
    payload.from = from;
  }
  payload.encrypted = true;
  return payload;
};
