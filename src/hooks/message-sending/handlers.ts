import type { UserWithKeys, PendingRetryMessage } from '../../lib/types/message-sending-types';
import type { SecureDB } from '../../lib/database/secureDB';
import { logError } from '../../lib/utils/message-sending-utils';
import { AUTH_USERNAME_REGEX } from '../../lib/constants';
import { hasPrototypePollutionKeys, isPlainObject, sanitizeMessageId } from '../../lib/sanitizers';
import { EventType } from '../../lib/types/event-types';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import {
  enqueueRetry,
  isPendingRetryExpired,
  pinRetryEntry,
  persistRetryQueue,
  releaseRetryEntries,
  recoverUnacknowledgedRetryEntry,
} from './retry-queue';

// Setup session ready handler for retrying pending messages
export const createSessionReadyHandler = (
  pendingRetryMessagesRef: React.RefObject<Map<string, PendingRetryMessage[]>>,
  secureDBRef: React.RefObject<SecureDB | null> | undefined,
  handleSendMessage: (
    user: UserWithKeys,
    content: string,
    replyTo?: string | { id: string; sender?: string; content?: string },
    messageSignalType?: string,
    originalMessageId?: string,
    editMessageId?: string,
    retryId?: string,
  ) => Promise<void>,
  drainingPeersRef: React.RefObject<Set<string>>,
  activeAccountRef: React.RefObject<string | null>,
  accountGenerationRef: React.RefObject<number>
) => {
  return async (event: Event) => {
    let drainingId: string | null = null;
    let isCurrent = () => false;
    try {
      const detail = (event as CustomEvent).detail;
      if (
        !isPlainObject(detail) ||
        hasPrototypePollutionKeys(detail) ||
        Object.keys(detail).sort().join(',') !== 'account,peer'
      ) return;
      const { peer, account } = detail as { peer?: unknown; account?: unknown };
      const generation = accountGenerationRef.current;
      isCurrent = () => (
        typeof account === 'string' &&
        accountGenerationRef.current === generation &&
        activeAccountRef.current === account
      );
      if (
        !isCurrent() ||
        typeof peer !== 'string' ||
        peer !== peer.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(peer)
      ) return;
      const id = peer;

      if (drainingPeersRef?.current.has(id)) return;

      let pending = pendingRetryMessagesRef.current.get(id);
      if (!pending || pending.length === 0) return;
      if (pending.some((entry) => isPendingRetryExpired(entry))) {
        await persistRetryQueue(
          secureDBRef,
          pendingRetryMessagesRef.current,
          isCurrent,
        );
        pending = pendingRetryMessagesRef.current.get(id);
        if (!pending || pending.length === 0) return;
      }

      drainingId = id;
      drainingPeersRef?.current.add(id);

      for (const entry of [...pending]) {
        if (!isCurrent()) return;
        try {
          await handleSendMessage(
            entry.user,
            entry.content,
            entry.replyTo,
            entry.messageSignalType,
            entry.originalMessageId,
            entry.editMessageId,
            entry.retryId,
          );
          if (!isCurrent()) return;
        } catch (error) {
          if (isCurrent()) console.error('[MessageSender] Retry after session establishment failed:', error);
        }
      }
    } catch (_error) {
      if (isCurrent()) console.error('[MessageSender] Error handling session-ready event:', _error);
    } finally {
      if (drainingId && isCurrent()) drainingPeersRef.current.delete(drainingId);
    }
  };
};

// Handle session reset for unacknowledged messages
export const createSessionResetRetryHandler = (
  pendingRetryMessagesRef: React.RefObject<Map<string, PendingRetryMessage[]>>,
  secureDBRef: React.RefObject<any> | undefined,
  activeAccountRef: React.RefObject<string | null>,
  accountGenerationRef: React.RefObject<number>
) => {
  return async (event: Event) => {
    let isCurrent = () => false;
    try {
      const detail = (event as CustomEvent).detail;
      if (
        !isPlainObject(detail) ||
        hasPrototypePollutionKeys(detail) ||
        Object.keys(detail).sort().join(',') !== 'account,failedMessageId,peerUsername'
      ) return;
      const { peerUsername, account, failedMessageId } = detail;
      const generation = accountGenerationRef.current;
      isCurrent = () => (
        typeof account === 'string' &&
        accountGenerationRef.current === generation &&
        activeAccountRef.current === account
      );
      if (
        !isCurrent() ||
        typeof account !== 'string' ||
        account !== account.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(account) ||
        typeof peerUsername !== 'string' ||
        peerUsername !== peerUsername.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(peerUsername) ||
        peerUsername === account ||
        typeof failedMessageId !== 'string' ||
        sanitizeMessageId(failedMessageId) !== failedMessageId ||
        !secureDBRef?.current
      ) return;
      if (!blockingSystem.isEnforcementReady() || blockingSystem.isBlockedSync(peerUsername)) return;

      const db = secureDBRef.current;
      const messageData = await db.retrieveEphemeral(
        'unacknowledged-messages',
        `${peerUsername}:${failedMessageId}`
      );
      if (!isCurrent()) return;
      if (!blockingSystem.isEnforcementReady() || blockingSystem.isBlockedSync(peerUsername)) return;
      const entry = recoverUnacknowledgedRetryEntry(messageData, peerUsername, failedMessageId);
      if (!entry) return;

      const replacementEntry: PendingRetryMessage = {
        user: entry.user,
        content: entry.content,
        replyTo: entry.replyTo,
        messageSignalType: entry.messageSignalType,
        retryId: entry.retryId,
        originalMessageId: entry.originalMessageId,
        editMessageId: entry.editMessageId,
        retryCount: 0,
        queuedAt: entry.queuedAt,
      };
      
      const retryMap = pendingRetryMessagesRef.current;
      const inserted = enqueueRetry(retryMap, peerUsername, replacementEntry);
      if (inserted) pinRetryEntry(replacementEntry);
      try {
        await persistRetryQueue(secureDBRef, retryMap, isCurrent);
      } catch (error) {
        if (inserted && isCurrent()) {
          const queue = retryMap.get(peerUsername);
          const index = queue?.indexOf(replacementEntry) ?? -1;
          if (queue && index >= 0) {
            queue.splice(index, 1);
            if (queue.length === 0) retryMap.delete(peerUsername);
            releaseRetryEntries([replacementEntry]);
          }
        }
        throw error;
      }
      if (!isCurrent()) return;
      window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
        detail: { peer: peerUsername, account }
      }));
    } catch (_error) {
      if (isCurrent()) logError('session-reset-handler-error', _error);
    }
  };
};
