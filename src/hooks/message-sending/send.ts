import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { secureMessageQueue } from '../../lib/database/secure-message-queue';
import {
  logError,
  createCoverPadding
} from '../../lib/utils/message-sending-utils';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { validateSignalBundleForPeerIdentity } from '../../lib/utils/signal-bundle-utils';

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
    messageType,
    signalType: messageSignalType,
    senderKyberPublicBase64: localKeys.kyber.publicKeyBase64,
    ...(senderSignalBundle ? { senderSignalBundle } : {}),
    ...(editMessageId ? { editMessageId } : {}),
  };

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

// Request bundle for retry using discovery
export const requestBundleForRetry = async (
  recipientUsername: string,
  currentUser: string,
  _getKeysOnDemand: () => Promise<any>,
  lastSessionBundleReqTsRef: React.RefObject<Map<string, number>>,
  _inboxId?: string,
  users?: Array<{ username: string; hybridPublicKeys?: any; peerCertificateFingerprint?: string; identityRootFingerprint?: string }>,
  findUser?: (handle: string) => Promise<any>
) => {
  try {
    const now = Date.now();
    const last = lastSessionBundleReqTsRef.current.get(recipientUsername) || 0;
    if (now - last >= 3000) {
      lastSessionBundleReqTsRef.current.set(recipientUsername, now);

      if (!findUser) {
        console.warn('[Send] findUser not available for bundle retry');
        return;
      }

      if (!shouldAttemptDiscovery(recipientUsername)) {
        return;
      }

      const material = await findUser(recipientUsername);
      if (material && material.fullBundle) {
        const validation = await validateSignalBundleForPeerIdentity(
          recipientUsername,
          material.fullBundle,
          users as any,
          findUser as any
        );
        if (!validation.valid) {
          return;
        }
        await signal.processPreKeyBundle(currentUser, recipientUsername, material.fullBundle);
        window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: recipientUsername } }));
      }
    }
  } catch (_err) {
    console.error('[Send] Bundle retry via Discovery failed:', _err);
  }
};
