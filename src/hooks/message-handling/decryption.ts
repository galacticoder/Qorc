import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { safeJsonParse, safeJsonParseForMessages } from '../../lib/utils/message-handler-utils';
import { MAX_SIGNAL_PAYLOAD_JSON_BYTES } from '../../lib/constants';
import type { EncryptedMessage } from '../../lib/types/message-handling-types';
import { signal } from '../../lib/tauri-bindings';
import { validateSignalBundleForPeerIdentity, type PeerIdentityLike } from '../../lib/utils/signal-bundle-utils';

// Decrypt Signal Protocol message
export const decryptSignalMessage = async (
  encryptedMessage: any,
  currentUser: string,
  processedPreKeyMessagesRef: React.RefObject<Map<string, number>>
): Promise<{ payload: any; attachedChunkData: any } | null> => {
  const envelope = encryptedMessage.encryptedPayload as EncryptedMessage;

  if (!envelope || typeof envelope !== 'object' || !('ciphertext' in envelope)) {
    console.error('[EncryptedMessageHandler] Unsupported envelope format', { keys: envelope ? Object.keys(envelope) : [] });
    return null;
  }

  const kemCiphertext = envelope.pqEnvelope?.kemCiphertext;
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
  const decrypted = await signal.decrypt(senderForDecrypt, currentUser, cleanedEnvelope as any);

  return { payload: decrypted, attachedChunkData };
};

// Process bundle delivery message
export const processBundleDelivery = async (
  encryptedMessage: any,
  currentUser: string,
  users?: PeerIdentityLike[] | null,
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<boolean> => {
  try {
    const bundle = encryptedMessage.bundle;
    const peerUsername = encryptedMessage.username;
    if (!peerUsername) {
      throw new Error('BUNDLE_DELIVERY_MISSING_PEER');
    }
    const validation = await validateSignalBundleForPeerIdentity(peerUsername, bundle, users, findUser);
    if (!validation.valid) {
      throw new Error(validation.reason || 'BUNDLE_IDENTITY_VALIDATION_FAILED');
    }

    const bundleResult = await signal.processPreKeyBundle(currentUser, peerUsername, bundle);

    if (bundleResult) {
      const has = await signal.hasSession(currentUser, peerUsername, 1);
      try { window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: peerUsername } })); } catch { }

      return true;
    }
  } catch (_error) {
    try { window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_BUNDLE_FAILED, { detail: { peer: encryptedMessage?.username, error: _error instanceof Error ? _error.message : String(_error) } })); } catch { }
  }
  return false;
};

// Process sender signal bundle from payload
export const processSenderBundle = async (
  payload: any,
  currentUser: string,
  users?: PeerIdentityLike[] | null,
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<void> => {
  try {
    const senderUsername = payload?.from;
    if (!currentUser || !senderUsername) return;

    const has = await signal.hasSession(currentUser, senderUsername, 1);
    if (!has && payload?.senderSignalBundle) {
      try {
        const validation = await validateSignalBundleForPeerIdentity(
          senderUsername,
          payload.senderSignalBundle,
          users,
          findUser
        );
        if (!validation.valid) {
          throw new Error(validation.reason || 'SENDER_BUNDLE_IDENTITY_VALIDATION_FAILED');
        }
        const bundleResult = await signal.processPreKeyBundle(currentUser, senderUsername, payload.senderSignalBundle);
        if (bundleResult) {
          const hasNow = await signal.hasSession(currentUser, senderUsername, 1);
          try { window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: senderUsername } })); } catch { }

        }
      } catch (error) {
        console.warn('[EncryptedMessageHandler] Rejected senderSignalBundle', {
          peer: senderUsername,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
  } catch { }
};

// Trust peer identity on untrusted identity error
export const trustPeerIdentity = async (currentUser: string, peerUsername: string): Promise<void> => {
  try {
    await signal.trustPeerIdentity(currentUser, peerUsername, 1);
  } catch { }
};

// Parse decrypted plaintext to payload
export const parseDecryptedPayload = (plaintext: string, from?: string): any => {
  let payload = safeJsonParseForMessages(plaintext);

  if (!payload && typeof plaintext === 'string') {
    const trimmed = plaintext.trim();
    const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');
    const looksLikeSignalPayload = trimmed.includes('"signal-payload"') || trimmed.includes('"file-message-chunk"');
    if (looksJson && looksLikeSignalPayload) {
      payload = safeJsonParse(plaintext, MAX_SIGNAL_PAYLOAD_JSON_BYTES);
    }
  }

  if (!payload) {
    payload = { content: plaintext, type: SignalType.MESSAGE };
  }
  if (from && payload && !payload.from) {
    payload.from = from;
  }
  payload.encrypted = true;
  return payload;
};
