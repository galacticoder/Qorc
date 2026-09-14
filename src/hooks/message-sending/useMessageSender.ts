import React, { useCallback, useRef, useEffect } from 'react';
import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { Message } from '../../components/chat/messaging/types';
import type { SecureDB } from '../../lib/database/secureDB';
import type { StoredMessage } from '../../lib/types/database-types';
import { canonicalAuthUsernameOrNull, sanitizeContent, sanitizeMessageId } from '../../lib/sanitizers';
import type { UserWithKeys, PendingRetryMessage } from '../../lib/types/message-sending-types';
import {
  sanitizeReply,
  logError,
  getIdCache,
  mapSignalType,
  createLocalMessage,
  getSessionApi,
  recordSessionRequest,
} from '../../lib/utils/message-sending-utils';
import { createSessionReadyHandler, createSessionResetRetryHandler } from './handlers';
import { buildMessagePayload, dispatchLocalEvents, storeUnacknowledgedMessage, requestBundleForRetry } from './send';
import {
  enqueueRetry,
  isPendingRetryExpired,
  loadRetryQueue,
  persistRetryQueue,
  pinRetryEntry,
  releaseRetryEntries,
  releaseRetryMap,
} from './retry-queue';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { nativeMessageContent, signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { validateSignalBundleForPeerIdentity } from '../../lib/utils/signal-bundle-utils';
import { isReceiptEventDetail } from './receipts';
import {
  applyDeleteControl,
  applyEditControl,
  applyReactionControl,
  createControlOperationId,
  isControlOperationId,
} from '../../lib/messages/message-controls';
import { blockingSystem } from '../../lib/blocking/blocking-system';

const MAX_DURABLE_SEND_RETRY_ATTEMPTS = 2;
const MAX_CONCURRENT_SESSION_PREFETCHES = 16;
const MAX_DELIVERED_OPERATION_TOMBSTONES = 1000;
const RETRY_REHYDRATE_DELAY_MS = 5000;

const retryOperationKey = (peer: string, operationId: string): string => (
  `${peer.length}:${peer}${operationId}`
);

export function useMessageSender(
  users: UserWithKeys[],
  loginUsernameRef: React.RefObject<string>,
  currentUsername: string,
  onNewMessage: (message: Message) => void,
  isLoggedIn: boolean,
  secureDBRef: React.RefObject<SecureDB | null>,
  findUser: (handle: string) => Promise<any>
) {
  const activeAccountRef = useRef<string | null>(null);
  const accountGenerationRef = useRef(0);

  const idCacheRef = useRef(getIdCache());
  const sessionPrefetchMap = useRef<Map<string, Promise<void>>>(new Map());
  const lastSessionBundleReqTsRef = useRef<Map<string, number>>(new Map());
  const pendingRetryMessagesRef = useRef<Map<string, PendingRetryMessage[]>>(new Map());
  const retryRehydratedRef = useRef(false);
  const drainingPeersRef = useRef<Set<string>>(new Set());
  const inFlightOperationsRef = useRef<Map<string, { done: Promise<void>; resolve: () => void }>>(new Map());
  const deliveredOperationsRef = useRef<Map<string, number>>(new Map());
  const retryPersistenceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryRehydrateTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retryRehydrateOwnerRef = useRef<object | null>(null);
  useEffect(() => {
    const account = isLoggedIn
      ? canonicalAuthUsernameOrNull(currentUsername || loginUsernameRef.current)
      : null;
    if (activeAccountRef.current === account) return;

    accountGenerationRef.current += 1;
    activeAccountRef.current = account;
    sessionPrefetchMap.current.clear();
    lastSessionBundleReqTsRef.current.clear();
    releaseRetryMap(pendingRetryMessagesRef.current);
    pendingRetryMessagesRef.current.clear();
    drainingPeersRef.current.clear();
    deliveredOperationsRef.current.clear();
    if (retryPersistenceTimerRef.current) clearTimeout(retryPersistenceTimerRef.current);
    retryPersistenceTimerRef.current = null;
    if (retryRehydrateTimerRef.current) clearTimeout(retryRehydrateTimerRef.current);
    retryRehydrateTimerRef.current = null;
    retryRehydrateOwnerRef.current = null;
    for (const operation of inFlightOperationsRef.current.values()) operation.resolve();
    inFlightOperationsRef.current.clear();
    retryRehydratedRef.current = false;
  }, [isLoggedIn, currentUsername, loginUsernameRef]);

  const scheduleRetryPersistence = useCallback((account: string, generation: number): void => {
    const isCurrent = () => (
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      canonicalAuthUsernameOrNull(loginUsernameRef.current) === account
    );
    const schedule = () => {
      if (!isCurrent() || retryPersistenceTimerRef.current) return;
      retryPersistenceTimerRef.current = setTimeout(() => {
        retryPersistenceTimerRef.current = null;
        if (!isCurrent()) return;
        void persistRetryQueue(secureDBRef, pendingRetryMessagesRef.current, isCurrent)
          .catch(() => { if (isCurrent()) schedule(); });
      }, 5000);
    };
    schedule();
  }, [loginUsernameRef, secureDBRef]);

  useEffect(() => {
    const interval = setInterval(() => {
      const account = canonicalAuthUsernameOrNull(currentUsername || loginUsernameRef.current);
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account &&
        canonicalAuthUsernameOrNull(loginUsernameRef.current) === account
      );
      if (!isCurrent()) return;
      const hasExpired = Array.from(pendingRetryMessagesRef.current.values())
        .some((entries) => entries.some((entry) => isPendingRetryExpired(entry)));
      if (!hasExpired) return;
      void persistRetryQueue(secureDBRef, pendingRetryMessagesRef.current, isCurrent)
        .catch(() => {
          if (isCurrent()) scheduleRetryPersistence(account!, generation);
        });
    }, 10_000);
    return () => clearInterval(interval);
  }, [currentUsername, loginUsernameRef, scheduleRetryPersistence, secureDBRef]);

  const clearPendingRetriesForPeer = useCallback(async (
    peer: string,
    account: string,
    generation: number,
  ): Promise<void> => {
    const isCurrent = () => (
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      canonicalAuthUsernameOrNull(loginUsernameRef.current) === account
    );
    if (!isCurrent()) return;

    const entries = pendingRetryMessagesRef.current.get(peer) || [];
    pendingRetryMessagesRef.current.delete(peer);
    drainingPeersRef.current.delete(peer);
    releaseRetryEntries(entries);

    const operationIds: string[] = [];
    for (const entry of entries) {
      const operationId = entry.retryId;
      operationIds.push(operationId);
      if (entry.messageSignalType === SignalType.MESSAGE) {
        await nativeMessageContent.revokeSend(operationId).catch(() => false);
      } else if (entry.messageSignalType === SignalType.EDIT_MESSAGE) {
        await nativeMessageContent.delete(operationId).catch(() => false);
      }
    }

    const db = secureDBRef.current;
    if (db && operationIds.length > 0) {
      await db.clearUnacknowledgedMessages(peer, operationIds);
      if (!isCurrent()) return;
    }
    await persistRetryQueue(secureDBRef, pendingRetryMessagesRef.current, isCurrent);
  }, [loginUsernameRef, secureDBRef]);

  const handleSendMessage = useCallback(
    async (user: UserWithKeys, content: string, replyTo?: string | { id: string; sender?: string; content?: string }, messageSignalType?: string, originalMessageId?: string, editMessageId?: string, retryId?: string) => {
      if (!isLoggedIn) { logError('AUTH'); return; }

      const currentUser = canonicalAuthUsernameOrNull(currentUsername || loginUsernameRef.current);
      if (!currentUser) { logError('AUTH-CURRENT'); return; }
      const accountGeneration = accountGenerationRef.current;
      const isCurrent = () => (
        accountGeneration === accountGenerationRef.current &&
        activeAccountRef.current === currentUser &&
        canonicalAuthUsernameOrNull(loginUsernameRef.current) === currentUser
      );
      const assertCurrent = () => {
        if (!isCurrent()) throw new Error('Account changed during message send');
      };
      if (!isCurrent()) return;
      const recipientUsername = canonicalAuthUsernameOrNull(user.username);
      if (!recipientUsername || recipientUsername === currentUser) { logError('RECIPIENT'); return; }

      const recipientBlocked = await blockingSystem.isUserBlocked(recipientUsername);
      assertCurrent();
      if (recipientBlocked) throw new Error('recipient-blocked');

      const sanitizedContent = sanitizeContent(content);
      const messageType = mapSignalType(SignalType.MESSAGE, messageSignalType);
      const replyToData = messageType === SignalType.MESSAGE
        ? sanitizeReply(replyTo)
        : undefined;
      const isEditMessage = messageType === SignalType.EDIT_MESSAGE;
      const isPrivateText = messageType === SignalType.MESSAGE || isEditMessage;
      const isReaction = messageType === SignalType.REACTION_ADD || messageType === SignalType.REACTION_REMOVE;
      const isMutation = isEditMessage || messageType === SignalType.DELETE_MESSAGE || isReaction;

      if (isReaction && !sanitizedContent) return;

      const targetMessageId = originalMessageId === undefined
        ? undefined
        : sanitizeMessageId(originalMessageId);
      const suppliedRetryId = retryId === undefined ? undefined : sanitizeMessageId(retryId);
      const suppliedEditId = editMessageId === undefined ? undefined : sanitizeMessageId(editMessageId);
      if (
        (originalMessageId !== undefined && !targetMessageId) ||
        (retryId !== undefined && !suppliedRetryId) ||
        (editMessageId !== undefined && !suppliedEditId) ||
        (isMutation && !targetMessageId) ||
        (isMutation && suppliedRetryId === targetMessageId) ||
        (isMutation && suppliedRetryId !== undefined && !isControlOperationId(suppliedRetryId))
      ) return;
      if (!sanitizedContent && isPrivateText) {
        if (!suppliedRetryId || !await nativeMessageContent.has(suppliedRetryId)) return;
        assertCurrent();
      }

      const timestamp = Date.now();
      const messageId = targetMessageId || (() => {
        let id: string;
        do { id = crypto.randomUUID().replace(/-/g, ''); } while (!idCacheRef.current.isStale(id));
        idCacheRef.current.add(id);
        return id;
      })();
      const operationId = suppliedRetryId || (isMutation
        ? createControlOperationId(timestamp)
        : messageId);
      const editTargetId = isEditMessage ? (suppliedEditId || targetMessageId) : suppliedEditId;
      const operationKey = retryOperationKey(recipientUsername, operationId);
      const existingFlight = inFlightOperationsRef.current.get(operationKey);
      if (existingFlight) {
        await existingFlight.done;
        if (!isCurrent()) return;
        const stillQueued = pendingRetryMessagesRef.current.get(recipientUsername)
          ?.some((entry) => entry.retryId === operationId);
        if (stillQueued) {
          setTimeout(() => {
            if (isCurrent()) {
              window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
                detail: { peer: recipientUsername, account: currentUser }
              }));
            }
          }, 0);
        }
        return;
      }

      let resolveFlight!: () => void;
      const done = new Promise<void>((resolve) => { resolveFlight = resolve; });
      const flight = { done, resolve: resolveFlight };
      inFlightOperationsRef.current.set(operationKey, flight);
      const retryUser: UserWithKeys = { username: recipientUsername };
      let writeAheadStarted = false;
      let localMessage: Message | null = null;
      let storedLocalMessage: StoredMessage | undefined;
      let localMessageCommitted = false;
      let localMessagePublished = false;
      const publishLocalMessage = () => {
        if (!localMessage || localMessagePublished) return;
        localMessagePublished = true;
        onNewMessage(localMessage);
      };

      try {
        unifiedSignalTransport.preparePeer(recipientUsername);
        if (messageType === SignalType.MESSAGE && !targetMessageId) {
          localMessage = await createLocalMessage(
            messageId,
            currentUser,
            recipientUsername,
            sanitizedContent!,
            timestamp,
            replyToData,
          );
          assertCurrent();
          if (!secureDBRef.current) {
            await nativeMessageContent.delete(messageId).catch(() => false);
            throw new Error('Secure database is not ready');
          }
          storedLocalMessage = {
            ...localMessage,
            content: '',
            ...(localMessage.replyTo
              ? { replyTo: { ...localMessage.replyTo, content: '' } }
              : {}),
            timestamp: localMessage.timestamp.getTime(),
          };
        }

        if (isEditMessage && sanitizedContent) {
          const staged = await nativeMessageContent.storeOutgoing(
            operationId,
            sanitizedContent,
            recipientUsername,
            SignalType.EDIT_MESSAGE,
            operationId,
            true,
          );
          if (!staged.stored && !staged.duplicate) {
            throw new Error('Native edit content staging failed');
          }
          assertCurrent();
        }

        const prior = pendingRetryMessagesRef.current.get(recipientUsername)
          ?.find((entry) => entry.retryId === operationId);
        const retryEntry: PendingRetryMessage = {
          user: retryUser,
          content: isPrivateText ? '' : (sanitizedContent ?? ''),
          replyTo: replyToData,
          messageSignalType: messageType,
          retryId: operationId,
          originalMessageId: messageId,
          editMessageId: editTargetId,
          retryCount: prior?.retryCount || 0,
          queuedAt: prior?.queuedAt || Date.now(),
        };
        if (enqueueRetry(pendingRetryMessagesRef.current, recipientUsername, retryEntry)) {
          pinRetryEntry(retryEntry);
        }
        writeAheadStarted = true;
        await persistRetryQueue(
          secureDBRef,
          pendingRetryMessagesRef.current,
          isCurrent,
          storedLocalMessage,
        );
        localMessageCommitted = !!storedLocalMessage;
        assertCurrent();
        publishLocalMessage();

        await storeUnacknowledgedMessage(secureDBRef, recipientUsername, {
          user: retryUser,
          content: isPrivateText ? '' : (sanitizedContent ?? ''),
          replyTo: replyToData,
          messageSignalType: messageType,
          retryId: operationId,
          originalMessageId: messageId,
          editMessageId: editTargetId,
          timestamp,
        }, isCurrent);
        assertCurrent();

        if (isMutation) {
          const db = secureDBRef.current;
          if (!db || !targetMessageId) throw new Error('Secure database is not ready for message control');
          let acceptedControl = false;
          const persisted = await db.updateConversationMessage(
            recipientUsername,
            targetMessageId,
            (stored) => {
              const message = stored as unknown as Message;
              const outcome = messageType === SignalType.DELETE_MESSAGE
                ? applyDeleteControl(message, currentUser, operationId)
                : messageType === SignalType.EDIT_MESSAGE
                  ? applyEditControl(message, currentUser, operationId)
                  : applyReactionControl(
                      message,
                      currentUser,
                      operationId,
                      sanitizedContent!,
                      messageType === SignalType.REACTION_ADD,
                    );
              if (!outcome) return null;
              acceptedControl = true;
              return (
                messageType === SignalType.EDIT_MESSAGE && outcome.changed
                  ? { ...outcome.message, content: '' }
                  : outcome.message
              ) as unknown as StoredMessage;
            },
            {
              grantIncomingCallPermission: isReaction && suppliedRetryId === undefined,
            },
          );
          assertCurrent();
          if (secureDBRef.current !== db || !persisted || !acceptedControl) {
            throw new Error('Message control target is unavailable or unauthorized');
          }

          let contentVaultId: string | undefined;
          if (messageType === SignalType.EDIT_MESSAGE && sanitizedContent) {
            contentVaultId = sanitizeMessageId(persisted.secureContentId) || targetMessageId;
            const committed = await nativeMessageContent.cloneForDisplay(operationId, contentVaultId, true);
            if (!committed.stored && !committed.duplicate) {
              throw new Error('Native edited message content commit failed');
            }
            assertCurrent();
          }

          dispatchLocalEvents(
            messageType,
            messageType,
            targetMessageId,
            editTargetId,
            sanitizedContent,
            contentVaultId,
            currentUser,
            operationId,
          );
        }

        const payload = buildMessagePayload(
          operationId,
          sanitizedContent,
          messageType,
          replyToData,
          targetMessageId,
          editTargetId,
        );
        const sendResult = await unifiedSignalTransport.send(recipientUsername, payload, messageType as SignalType);
        assertCurrent();

        if (!sendResult.success) {
          throw new Error(sendResult.error || 'Transport failed');
        }

        const queue = pendingRetryMessagesRef.current.get(recipientUsername) || [];
        const removed = queue.filter(
          (entry) => entry.retryId === operationId
        );
        const remaining = queue.filter(
          (entry) => entry.retryId !== operationId
        );
        if (remaining.length) pendingRetryMessagesRef.current.set(recipientUsername, remaining);
        else pendingRetryMessagesRef.current.delete(recipientUsername);
        releaseRetryEntries(removed);
        try {
          await persistRetryQueue(secureDBRef, pendingRetryMessagesRef.current, isCurrent);
        } catch (error) {
          if (isCurrent()) logError('RETRY-CLEAR-PERSIST', error);
          scheduleRetryPersistence(currentUser, accountGeneration);
        }
        if (messageType === SignalType.MESSAGE) {
          await nativeMessageContent.revokeSend(operationId).catch(() => false);
        } else if (isEditMessage) {
          await nativeMessageContent.delete(operationId).catch(() => false);
        }
      } catch (_error) {
        if (!isCurrent()) {
          if (messageType === SignalType.MESSAGE) throw _error;
          return;
        }
        if (!writeAheadStarted) {
          logError('SEND-PRECOMMIT', _error);
          throw _error;
        }

        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        const lowerError = errorMessage.toLowerCase();
        const isSessionErr = lowerError.includes('session') || lowerError.includes('encryption failed');
        const blockedDuringSend = lowerError.includes('recipient-blocked') ||
          lowerError.includes('recipient-policy-changed') ||
          (blockingSystem.isEnforcementReady() && blockingSystem.isBlockedSync(recipientUsername));
        if (blockedDuringSend) {
          try {
            await clearPendingRetriesForPeer(recipientUsername, currentUser, accountGeneration);
          } catch (error) {
            if (isCurrent()) {
              logError('BLOCKED-RETRY-CLEAR', error);
              scheduleRetryPersistence(currentUser, accountGeneration);
            }
          }
          if (messageType === SignalType.MESSAGE) throw new Error('recipient-blocked');
          return;
        }
        if (deliveredOperationsRef.current.has(operationKey)) {
          if (messageType === SignalType.MESSAGE) {
            await nativeMessageContent.revokeSend(operationId).catch(() => false);
          } else if (isEditMessage) {
            await nativeMessageContent.delete(operationId).catch(() => false);
          }
          scheduleRetryPersistence(currentUser, accountGeneration);
          return;
        }
        const prior = pendingRetryMessagesRef.current.get(recipientUsername)
          ?.find((entry) => entry.retryId === operationId);
        const retryCount = Math.min((prior?.retryCount || 0) + 1, MAX_DURABLE_SEND_RETRY_ATTEMPTS);
        const retryEntry: PendingRetryMessage = {
          user: retryUser,
          content: isPrivateText ? '' : (sanitizedContent ?? ''),
          replyTo: replyToData,
          messageSignalType: messageType,
          retryId: operationId,
          originalMessageId: messageId,
          editMessageId: editTargetId,
          retryCount,
          queuedAt: prior?.queuedAt || Date.now(),
        };
        if (enqueueRetry(pendingRetryMessagesRef.current, recipientUsername, retryEntry)) {
          pinRetryEntry(retryEntry);
        }
        await persistRetryQueue(
          secureDBRef,
          pendingRetryMessagesRef.current,
          isCurrent,
          localMessageCommitted ? undefined : storedLocalMessage,
        );
        if (storedLocalMessage) localMessageCommitted = true;
        assertCurrent();
        publishLocalMessage();

        if (isSessionErr) {
          await requestBundleForRetry(
            recipientUsername,
            currentUser,
            lastSessionBundleReqTsRef,
            users as any,
            findUser,
            isCurrent,
          );
        }
        logError('SEND', _error);
        if (messageType === SignalType.MESSAGE) throw _error;
      } finally {
        if (inFlightOperationsRef.current.get(operationKey) === flight) {
          inFlightOperationsRef.current.delete(operationKey);
        }
        resolveFlight();
      }
    },
    [
      isLoggedIn, loginUsernameRef, onNewMessage, users, findUser, currentUsername,
      secureDBRef, scheduleRetryPersistence, clearPendingRetriesForPeer
    ],
  );

  const prefetchSessionForPeer = useCallback(async (peer: string) => {
    if (!isLoggedIn) return;
    const currentUser = canonicalAuthUsernameOrNull(loginUsernameRef.current);
    const canonicalPeer = canonicalAuthUsernameOrNull(peer);
    if (!currentUser || !canonicalPeer || canonicalPeer === currentUser) return;
    peer = canonicalPeer;
    const generation = accountGenerationRef.current;
    const isCurrent = () => (
      generation === accountGenerationRef.current &&
      activeAccountRef.current === currentUser &&
      canonicalAuthUsernameOrNull(loginUsernameRef.current) === currentUser
    );
    if (!isCurrent()) return;
    const blocked = await blockingSystem.isUserBlocked(peer);
    if (!isCurrent() || blocked) return;
    const has = await getSessionApi().hasSession({ selfUsername: currentUser, peerUsername: peer });
    if (!isCurrent()) return;
    if (has?.hasSession) return;
    const now = Date.now();
    if (now - (lastSessionBundleReqTsRef.current.get(peer) || 0) < 3000) return;
    recordSessionRequest(lastSessionBundleReqTsRef.current, peer, now);

    if (sessionPrefetchMap.current.has(peer)) {
      await sessionPrefetchMap.current.get(peer)!;
      return;
    }
    if (sessionPrefetchMap.current.size >= MAX_CONCURRENT_SESSION_PREFETCHES) return;
    const operation = async () => {
      if (!shouldAttemptDiscovery(peer)) {
        return;
      }
      const material = await findUser(peer);
      if (!isCurrent()) return;
      if (material && material.fullBundle) {
        const validation = await validateSignalBundleForPeerIdentity(
          currentUser,
          peer,
          material.fullBundle,
          users as any,
          findUser as any,
          material,
        );
        if (!isCurrent() || !validation.valid) return;
        const processed = await signal.processVerifiedPreKeyBundle(currentUser, peer, material.fullBundle);
        if (processed && isCurrent()) {
          window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
            detail: { peer, account: currentUser }
          }));
        }
      }
    };
    let p!: Promise<void>;
    p = operation().finally(() => {
      if (sessionPrefetchMap.current.get(peer) === p) sessionPrefetchMap.current.delete(peer);
    });
    sessionPrefetchMap.current.set(peer, p);
    await p;
  }, [findUser, isLoggedIn, loginUsernameRef, users]);

  // Rehydrate durable send retry queue on login
  useEffect(() => {
    if (!isLoggedIn) { retryRehydratedRef.current = false; return; }
    if (retryRehydratedRef.current || retryRehydrateOwnerRef.current) return;
    const account = canonicalAuthUsernameOrNull(loginUsernameRef.current);
    const generation = accountGenerationRef.current;
    if (!account) return;
    let cancelled = false;
    const owner = {};
    retryRehydrateOwnerRef.current = owner;
    const isCurrent = () => (
      !cancelled &&
      retryRehydrateOwnerRef.current === owner &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      canonicalAuthUsernameOrNull(loginUsernameRef.current) === account
    );

    const scheduleRetry = (): void => {
      if (!isCurrent() || retryRehydrateTimerRef.current) return;
      retryRehydrateTimerRef.current = setTimeout(() => {
        retryRehydrateTimerRef.current = null;
        void restore();
      }, RETRY_REHYDRATE_DELAY_MS);
    };

    const restore = async (): Promise<void> => {
      if (!isCurrent()) return;
      try {
        const restored = await loadRetryQueue(secureDBRef, isCurrent);
        if (!isCurrent()) return;
        let removedBlockedEntries = false;
        for (const [peer, entries] of restored) {
          const blocked = await blockingSystem.isUserBlocked(peer);
          if (!isCurrent()) return;
          if (blocked) {
            removedBlockedEntries = true;
            restored.delete(peer);
            const operationIds: string[] = [];
            for (const entry of entries) {
              const operationId = entry.retryId;
              operationIds.push(operationId);
              if (entry.messageSignalType === SignalType.MESSAGE) {
                await nativeMessageContent.revokeSend(operationId).catch(() => false);
              } else if (entry.messageSignalType === SignalType.EDIT_MESSAGE) {
                await nativeMessageContent.delete(operationId).catch(() => false);
              }
            }
            if (operationIds.length > 0 && secureDBRef.current) {
              await secureDBRef.current.clearUnacknowledgedMessages(peer, operationIds);
              if (!isCurrent()) return;
            }
            continue;
          }
          for (const entry of entries) {
            if (!isCurrent()) return;
            const key = entry.retryId;
            const alreadyQueued = pendingRetryMessagesRef.current.get(peer)
              ?.some((candidate) => candidate.retryId === key);
            if (alreadyQueued) continue;
            if (enqueueRetry(pendingRetryMessagesRef.current, peer, entry)) pinRetryEntry(entry);
          }
        }
        if (removedBlockedEntries) {
          await persistRetryQueue(secureDBRef, pendingRetryMessagesRef.current, isCurrent);
          if (!isCurrent()) return;
        }
        retryRehydratedRef.current = true;

        for (const peer of restored.keys()) {
          void (async () => {
            try {
              if (!isCurrent() || !peer) return;
              const has = await getSessionApi().hasSession({ selfUsername: account, peerUsername: peer });
              if (!isCurrent()) return;
              if (has?.hasSession) {
                window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
                  detail: { peer, account }
                }));
                return;
              }
              await prefetchSessionForPeer(peer);
            } catch { }
          })();
        }
      } catch {
        scheduleRetry();
      }
    };

    void restore();
    return () => {
      cancelled = true;
      if (retryRehydrateOwnerRef.current === owner) retryRehydrateOwnerRef.current = null;
      if (retryRehydrateTimerRef.current) clearTimeout(retryRehydrateTimerRef.current);
      retryRehydrateTimerRef.current = null;
    };
  }, [isLoggedIn, secureDBRef, prefetchSessionForPeer]);

  useEffect(() => {
    return blockingSystem.registerBlockCleanupHandler(async (peer) => {
      const account = canonicalAuthUsernameOrNull(currentUsername || loginUsernameRef.current);
      const generation = accountGenerationRef.current;
      if (!account || activeAccountRef.current !== account) {
        throw new Error('Message retry cleanup account is unavailable');
      }
      try {
        await clearPendingRetriesForPeer(peer, account, generation);
      } catch (error) {
        if (
          generation === accountGenerationRef.current &&
          activeAccountRef.current === account
        ) scheduleRetryPersistence(account, generation);
        throw error;
      }
    });
  }, [
    clearPendingRetriesForPeer, currentUsername, loginUsernameRef,
    scheduleRetryPersistence
  ]);

  useEffect(() => {
    const handleConfirmedReceipt = (event: Event) => {
      if (!(event instanceof CustomEvent) || !isReceiptEventDetail(event.detail)) return;
      const detail = event.detail;
      const account = canonicalAuthUsernameOrNull(currentUsername || loginUsernameRef.current);
      const generation = accountGenerationRef.current;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account &&
        canonicalAuthUsernameOrNull(loginUsernameRef.current) === account
      );
      if (!isCurrent() || detail.account !== account) return;

      const peer = detail.from;
      const operationId = detail.messageId;
      const operationKey = retryOperationKey(peer, operationId);
      const queue = pendingRetryMessagesRef.current.get(peer);
      const removed = queue?.filter(
        (entry) => entry.retryId === operationId
      ) || [];
      if (removed.length === 0 && !inFlightOperationsRef.current.has(operationKey)) return;

      deliveredOperationsRef.current.delete(operationKey);
      while (deliveredOperationsRef.current.size >= MAX_DELIVERED_OPERATION_TOMBSTONES) {
        const oldest = deliveredOperationsRef.current.keys().next().value;
        if (typeof oldest !== 'string') break;
        deliveredOperationsRef.current.delete(oldest);
      }
      deliveredOperationsRef.current.set(operationKey, Date.now());

      if (queue && removed.length > 0) {
        const remaining = queue.filter(
          (entry) => entry.retryId !== operationId
        );
        if (remaining.length > 0) pendingRetryMessagesRef.current.set(peer, remaining);
        else pendingRetryMessagesRef.current.delete(peer);
      }
      releaseRetryEntries(removed);
      for (const entry of removed) {
        if (entry.messageSignalType === SignalType.MESSAGE) {
          void nativeMessageContent.revokeSend(operationId).catch(() => false);
        } else if (entry.messageSignalType === SignalType.EDIT_MESSAGE) {
          void nativeMessageContent.delete(operationId).catch(() => false);
        }
      }

      void persistRetryQueue(secureDBRef, pendingRetryMessagesRef.current, isCurrent)
        .catch(() => {
          if (isCurrent()) scheduleRetryPersistence(account!, generation);
        });
    };

    window.addEventListener(EventType.MESSAGE_DELIVERED, handleConfirmedReceipt as EventListener);
    window.addEventListener(EventType.MESSAGE_READ, handleConfirmedReceipt as EventListener);
    return () => {
      window.removeEventListener(EventType.MESSAGE_DELIVERED, handleConfirmedReceipt as EventListener);
      window.removeEventListener(EventType.MESSAGE_READ, handleConfirmedReceipt as EventListener);
    };
  }, [currentUsername, loginUsernameRef, secureDBRef, scheduleRetryPersistence]);

  useEffect(() => {
    const drainAfterServerEntry = () => {
      const account = canonicalAuthUsernameOrNull(currentUsername || loginUsernameRef.current);
      if (!account || activeAccountRef.current !== account) return;
      for (const [peer, entries] of pendingRetryMessagesRef.current) {
        if (entries.length === 0) continue;
        window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
          detail: { account, peer }
        }));
      }
    };
    window.addEventListener(EventType.SERVER_ENTRY_GRANTED, drainAfterServerEntry);
    return () => window.removeEventListener(EventType.SERVER_ENTRY_GRANTED, drainAfterServerEntry);
  }, [currentUsername, loginUsernameRef]);

  useEffect(() => {
    const handleSessionReady = createSessionReadyHandler(
      pendingRetryMessagesRef,
      secureDBRef,
      handleSendMessage,
      drainingPeersRef,
      activeAccountRef,
      accountGenerationRef
    );
    const handleSessionReset = createSessionResetRetryHandler(
      pendingRetryMessagesRef,
      secureDBRef,
      activeAccountRef,
      accountGenerationRef
    );

    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    window.addEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    return () => {
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
      window.removeEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    };
  }, [handleSendMessage, secureDBRef]);

  return { handleSendMessage, prefetchSessionForPeer };
}
