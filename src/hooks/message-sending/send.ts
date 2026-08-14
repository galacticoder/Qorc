import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import {
  logError,
  createCoverPadding,
  recordSessionRequest
} from '../../lib/utils/message-sending-utils';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { validateSignalBundleForPeerIdentity } from '../../lib/utils/signal-bundle-utils';
import { OUTBOUND_RETRY_MAX_AGE_MS } from '../../lib/constants';
import { sanitizeMessageId } from '../../lib/sanitizers';

// Build message payload
export const buildMessagePayload = (
  wireMessageId: string,
  sanitizedContent: string | undefined,
  messageSignalType: string | undefined,
  replyToData?: { id: string; sender?: string; content?: string },
  originalMessageId?: string,
  editMessageId?: string,
): Record<string, unknown> => {
  const isNativePrivateText = messageSignalType === SignalType.MESSAGE ||
    messageSignalType === SignalType.EDIT_MESSAGE;
  const payload: Record<string, unknown> = {
    messageId: wireMessageId,
    content: isNativePrivateText ? '' : sanitizedContent,
    ...(isNativePrivateText ? { nativeContentRef: wireMessageId } : {}),
  };

  if (replyToData) {
    payload.replyTo = replyToData;
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
  sanitizedContent: string | undefined,
  contentVaultId: string | undefined,
  currentUser: string,
  operationId: string,
): boolean => {
  if (messageType === SignalType.DELETE_MESSAGE && originalMessageId) {
    window.dispatchEvent(
      new CustomEvent(EventType.LOCAL_MESSAGE_DELETE, {
        detail: { account: currentUser, messageId: originalMessageId, operationId }
      }),
    );
    return true;
  }

  if (messageType === SignalType.EDIT_MESSAGE) {
    if (!editMessageId || !contentVaultId) return false;
    const targetId = editMessageId;
    window.dispatchEvent(
      new CustomEvent(EventType.LOCAL_MESSAGE_EDIT, {
        detail: { account: currentUser, messageId: targetId, contentVaultId, operationId }
      }),
    );
    return true;
  }

  if (
    (messageSignalType === SignalType.REACTION_ADD || messageSignalType === SignalType.REACTION_REMOVE) &&
    originalMessageId
  ) {
    window.dispatchEvent(new CustomEvent(EventType.LOCAL_REACTION_UPDATE, {
      detail: {
        account: currentUser,
        messageId: originalMessageId,
        emoji: sanitizedContent,
        isAdd: messageSignalType === SignalType.REACTION_ADD,
        username: currentUser,
        operationId,
      }
    }));
    return true;
  }
  return false;
};

// Store unacknowledged message for retry on session reset
export const storeUnacknowledgedMessage = async (
  secureDBRef: React.RefObject<any> | undefined,
  recipientUsername: string,
  messageData: any,
  isCurrent: () => boolean
) => {
  const db = secureDBRef?.current;
  if (!db || !isCurrent()) throw new Error('Secure database account is not current');
  const operationId = sanitizeMessageId(messageData?.retryId || messageData?.originalMessageId);
  if (!operationId) throw new Error('Unacknowledged message operation ID is invalid');

  try {
    await db.storeEphemeral(
      'unacknowledged-messages',
      `${recipientUsername}:${operationId}`,
      messageData,
      OUTBOUND_RETRY_MAX_AGE_MS,
      true
    );
    if (!isCurrent()) throw new Error('Account changed while recording unacknowledged message');
  } catch (_error) {
    logError('unack-msg-store-failed', _error);
    throw _error;
  }
};

// Request bundle for retry using discovery
export const requestBundleForRetry = async (
  recipientUsername: string,
  currentUser: string,
  lastSessionBundleReqTsRef: React.RefObject<Map<string, number>>,
  users: Array<{ username: string; hybridPublicKeys?: any; peerCertificateFingerprint?: string; identityRootFingerprint?: string }> | undefined,
  findUser: ((handle: string) => Promise<any>) | undefined,
  isCurrent: () => boolean
) => {
  try {
    if (!isCurrent()) return;
    const now = Date.now();
    const last = lastSessionBundleReqTsRef.current.get(recipientUsername) || 0;
    if (now - last >= 3000) {
      recordSessionRequest(lastSessionBundleReqTsRef.current, recipientUsername, now);

      if (!findUser) {
        console.warn('[Send] findUser not available for bundle retry');
        return;
      }

      if (!shouldAttemptDiscovery(recipientUsername)) {
        return;
      }

      const material = await findUser(recipientUsername);
      if (!isCurrent()) return;
      if (material && material.fullBundle) {
        const validation = await validateSignalBundleForPeerIdentity(
          currentUser,
          recipientUsername,
          material.fullBundle,
          users as any,
          findUser as any
        );
        if (!isCurrent()) return;
        if (!validation.valid) {
          return;
        }
        await signal.processVerifiedPreKeyBundle(currentUser, recipientUsername, material.fullBundle);
        if (!isCurrent()) return;
        window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
          detail: { peer: recipientUsername, account: currentUser }
        }));
      }
    }
  } catch { }
};
