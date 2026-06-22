import React, { useCallback, useMemo, useRef, useEffect } from 'react';
import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { Message } from '../../components/chat/messaging/types';
import websocketClient from '../../lib/websocket/websocket';
import { isValidKyberPublicKeyBase64 } from '../../lib/utils/messaging-validators';
import type { SecureDB } from '../../lib/database/secureDB';
import { sanitizeContent, sanitizeUsername } from '../../lib/sanitizers';
import type { HybridPublicKeys, UserWithKeys, PendingRetryMessage } from '../../lib/types/message-sending-types';
import { validateFileData, sanitizeReply, logError, getIdCache, mapSignalType, createLocalMessage, getSessionApi } from '../../lib/utils/message-sending-utils';
import { recipientKeyValidator } from './validation';
import { createDefaultResolvePeerHybridKeys } from './keys';
import { createSessionResetHandler, createSessionEstablishedHandler, createSessionReadyHandler, createSessionResetRetryHandler } from './handlers';
import { buildMessagePayload, dispatchLocalEvents, storeUnacknowledgedMessage, queueMessageForLater, requestBundleForRetry } from './send';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';
import { messageVault } from '../../lib/security/message-vault';
import { signal } from '../../lib/tauri-bindings';
import { shouldAttemptDiscovery } from '../../lib/utils/discovery-utils';
import { validateAndDecodeBase64 } from '../../lib/utils/file-utils';
import { validateSignalBundleForPeerIdentity } from '../../lib/utils/signal-bundle-utils';

export function useMessageSender(
  users: UserWithKeys[],
  loginUsernameRef: React.RefObject<string>,
  currentUsername: string,
  originalUsernameRef: React.RefObject<string>,
  onNewMessage: (message: Message) => void,
  _serverHybridPublic: { x25519PublicBase64: string; kyberPublicBase64: string; dilithiumPublicBase64: string } | null,
  getKeysOnDemand: () => Promise<{
    x25519: { private: Uint8Array; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>,
  _aesKeyRef: React.RefObject<CryptoKey | null>,
  _keyManagerRef?: React.RefObject<any>,
  _passphraseRef?: React.RefObject<string>,
  isLoggedIn?: boolean,
  hasUsernameMapping?: (hashedUsername: string) => Promise<boolean>,
  secureDBRef?: React.RefObject<SecureDB | null>,
  resolvePeerHybridKeys?: (peerUsername: string) => Promise<HybridPublicKeys | null>,
  findUser?: (handle: string) => Promise<any>
) {
  const recipientDirectory = useMemo(() => {
    const map = new Map<string, UserWithKeys>();
    users.forEach((user) => { if (user.username) map.set(user.username, user); });
    return map;
  }, [users]);

  const defaultResolvePeerHybridKeys = useCallback(
    createDefaultResolvePeerHybridKeys(recipientDirectory, getKeysOnDemand, loginUsernameRef, currentUsername, findUser),
    [recipientDirectory, getKeysOnDemand, loginUsernameRef, currentUsername, findUser]
  );

  const resolvePeerHybridKeysToUse = resolvePeerHybridKeys || defaultResolvePeerHybridKeys;

  const idCacheRef = useRef(getIdCache());
  const validatorRef = useRef(recipientKeyValidator());
  const lockContext = useMemo(() => ({}), []);
  const sessionPrefetchMap = useRef<Map<string, Promise<void>>>(new Map());
  const lastSessionBundleReqTsRef = useRef<Map<string, number>>(new Map());
  const pendingRetryMessagesRef = useRef<Map<string, PendingRetryMessage>>(new Map());
  const recentSessionResetsRef = useRef<Map<string, number>>(new Map());
  const peerCanDecryptRef = useRef<Map<string, boolean>>(new Map());
  const preKeyFailureCountRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    const handleSessionReset = createSessionResetHandler(recentSessionResetsRef, peerCanDecryptRef, preKeyFailureCountRef);
    const handleSessionEstablished = createSessionEstablishedHandler(peerCanDecryptRef);

    window.addEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablished as EventListener);
    return () => {
      window.removeEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablished as EventListener);
    };
  }, []);

  const handleSendMessage = useCallback(
    async (user: UserWithKeys, content: string, replyTo?: string | { id: string; sender?: string; content?: string }, fileData?: string, messageSignalType?: string, originalMessageId?: string, editMessageId?: string) => {
      if (!isLoggedIn) { logError('AUTH'); return; }

      const fileDataToSend = fileData ? validateFileData(fileData) : undefined;
      if (fileData && !fileDataToSend) { logError('FILEDATA-INVALID'); return; }

      const currentUser = sanitizeUsername(currentUsername || loginUsernameRef.current);
      if (!currentUser) { logError('AUTH-CURRENT'); return; }

      const recipientUsername = sanitizeUsername(user.username);
      if (!recipientUsername) { logError('RECIPIENT'); return; }

      const sanitizedContent = sanitizeContent(content);
      const replyToData = sanitizeReply(replyTo);
      const messageType = mapSignalType(SignalType.MESSAGE, messageSignalType, fileDataToSend);
      const isTypingSignal = messageSignalType === SignalType.TYPING_START || messageSignalType === SignalType.TYPING_STOP || messageType === SignalType.TYPING_INDICATOR;

      if (isTypingSignal) {
        const sessionCheck = await getSessionApi().hasSession({
          selfUsername: currentUser,
          peerUsername: recipientUsername,
          deviceId: 1,
        });
        if (!sessionCheck?.hasSession) {
          return;
        }
      }

      let recipient = recipientDirectory.get(recipientUsername);
      if (!recipient?.hybridPublicKeys) {
        const fetchedKeys = await resolvePeerHybridKeysToUse(recipientUsername);
        if (!fetchedKeys) { if (originalMessageId) { logError('KEYS-UNAVAILABLE-RETRY'); return; } throw new Error('Recipient keys unavailable'); }
        recipient = { username: recipientUsername, hybridPublicKeys: fetchedKeys };
      }
      if (!validatorRef.current(recipient.hybridPublicKeys)) { logError('RECIPIENT-KEYS-INVALID'); return; }

      if (!recipient?.hybridPublicKeys?.kyberPublicBase64 || !isValidKyberPublicKeyBase64(recipient.hybridPublicKeys.kyberPublicBase64)) {
        if (originalMessageId) { logError('INVALID-KEYS-RETRY'); return; }
        const timestamp = Date.now();
        let messageId: string;
        do { messageId = crypto.randomUUID().replace(/-/g, ''); } while (!idCacheRef.current.isStale(messageId));
        idCacheRef.current.add(messageId);

        if (messageSignalType !== SignalType.TYPING_START && messageSignalType !== SignalType.TYPING_STOP) {
          const localMessage = await createLocalMessage(messageId, currentUser, recipientUsername, sanitizedContent ?? '', timestamp, replyToData, fileDataToSend);
          (localMessage as any).pending = true;
          onNewMessage(localMessage);
          if (secureDBRef?.current) { 
            try { await secureDBRef.current.storeMessage({ ...localMessage, timestamp: localMessage.timestamp.getTime() }); } catch { }
            if (fileDataToSend) {
              const decoded = validateAndDecodeBase64(fileDataToSend);
              if (decoded) {
                try {
                  const buffer = new ArrayBuffer(decoded.length);
                  const copy = new Uint8Array(buffer);
                  copy.set(decoded);
                  await secureDBRef.current.saveFile(messageId, buffer);
                } catch { }
              }
            }
          }
        }
        await queueMessageForLater(recipientUsername, sanitizedContent ?? '', messageId, replyToData, fileDataToSend, messageSignalType, editMessageId);
        resolvePeerHybridKeysToUse(recipientUsername).catch(() => { });
        return;
      }

      if (messageType === SignalType.MESSAGE && !sanitizedContent) return;
      if ((messageType === SignalType.REACTION_ADD || messageType === SignalType.REACTION_REMOVE) && !sanitizedContent) return;

      const timestamp = Date.now();
      let messageId = originalMessageId || (() => { let id; do { id = crypto.randomUUID().replace(/-/g, ''); } while (!idCacheRef.current.isStale(id)); idCacheRef.current.add(id); return id; })();

      const isControlMessage = messageType === SignalType.TYPING_INDICATOR || messageType === SignalType.DELIVERY_RECEIPT || messageType === SignalType.READ_RECEIPT;

      // show local message before key resolution and encryption
      if (!isControlMessage && !originalMessageId && !editMessageId) {
        const localMessage = await createLocalMessage(messageId, currentUser, recipientUsername, sanitizedContent ?? '', timestamp, replyToData, fileDataToSend);
        onNewMessage(localMessage);
        if (secureDBRef?.current) {
          try { await secureDBRef.current.storeMessage({ ...localMessage, timestamp: localMessage.timestamp.getTime() }); } catch { }
          if (fileDataToSend) {
            const decoded = validateAndDecodeBase64(fileDataToSend);
            if (decoded) {
              try {
                const buffer = new ArrayBuffer(decoded.length);
                const copy = new Uint8Array(buffer);
                copy.set(decoded);
                await secureDBRef.current.saveFile(messageId, buffer);
              } catch { }
            }
          }
        }
      }

      const localKeys = await getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey) { logError('LOCAL-KEYS'); return; }

      try {
        const wireMessageId = (messageType === SignalType.EDIT_MESSAGE && editMessageId) ? editMessageId : messageId;

        if (!isControlMessage && (originalMessageId || editMessageId)) {
          dispatchLocalEvents(messageType, messageSignalType, originalMessageId, editMessageId, wireMessageId, sanitizedContent, currentUser);
        }

        const payload = buildMessagePayload(wireMessageId, currentUser, recipientUsername, sanitizedContent, timestamp, messageType, messageSignalType, localKeys, originalUsernameRef, replyToData, fileData, originalMessageId, editMessageId);
        const recipientInboxId = recipient?.inboxId || recipient?.hybridPublicKeys?.inboxId;
        const destinationRouteId = (recipient as any)?.routeId || (recipient?.hybridPublicKeys as any)?.routeId;
        const destinationMailboxLookupId = (recipient as any)?.mailboxLookupId || (recipient?.hybridPublicKeys as any)?.mailboxLookupId;
        const sendResult = await unifiedSignalTransport.send(recipientUsername, payload, messageType as SignalType, {
          recipientInboxId,
          destinationRouteId,
          destinationMailboxLookupId
        });

        if (!sendResult.success) {
          throw new Error(sendResult.error || 'Transport failed');
        }

        if (!isControlMessage) {
          await storeUnacknowledgedMessage(secureDBRef, recipientUsername, timestamp, { user, content, replyTo, fileData, messageSignalType, originalMessageId: messageId, editMessageId, timestamp });
        }
      } catch (_error) {
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        if (errorMessage.toLowerCase().includes('prekey') && recipientUsername) preKeyFailureCountRef.current.set(recipientUsername, (preKeyFailureCountRef.current.get(recipientUsername) || 0) + 1);
        if ((errorMessage.includes('session') || errorMessage.includes('Encryption failed')) && recipientUsername) {
          const retryCount = (pendingRetryMessagesRef.current.get(recipientUsername)?.retryCount || 0) + 1;
          if (retryCount <= 2) {
            if (content) { await messageVault.store(messageId, content); }
            pendingRetryMessagesRef.current.set(recipientUsername, {
              user,
              content: '',
              replyTo,
              fileData,
              messageSignalType,
              originalMessageId: messageId,
              editMessageId,
              retryCount
            });
          }
          const recipientInboxId = recipient?.inboxId || recipient?.hybridPublicKeys?.inboxId;
          await requestBundleForRetry(
            recipientUsername,
            currentUser,
            getKeysOnDemand,
            lastSessionBundleReqTsRef,
            recipientInboxId,
            users as any,
            findUser
          );
        }
        logError('SEND', _error);
      }
    },
    [isLoggedIn, loginUsernameRef, recipientDirectory, getKeysOnDemand, onNewMessage, lockContext, hasUsernameMapping, users, findUser],
  );

  const prefetchSessionForPeer = useCallback(async (peer: string) => {
    if (!isLoggedIn) return;
    const currentUser = sanitizeUsername(loginUsernameRef.current);
    if (!currentUser || !peer) return;
    const has = await getSessionApi().hasSession({ selfUsername: currentUser, peerUsername: peer, deviceId: 1 });
    if (has?.hasSession) return;
    const now = Date.now();
    if (now - (lastSessionBundleReqTsRef.current.get(peer) || 0) < 3000) return;
    lastSessionBundleReqTsRef.current.set(peer, now);

    if (sessionPrefetchMap.current.has(peer)) { await sessionPrefetchMap.current.get(peer)!.catch(() => { }); return; }
    const p = (async () => {
      try {
        if (!findUser) {
          console.warn('[MessageSender] findUser not available for session prefetch');
          return;
        }
        if (!shouldAttemptDiscovery(peer, users.map(u => u.username).filter(Boolean))) {
          return;
        }
        const material = await findUser(peer);
        if (material && material.fullBundle) {
          const validation = await validateSignalBundleForPeerIdentity(peer, material.fullBundle, users as any, findUser as any);
          if (!validation.valid) {
            return;
          }
          await signal.processPreKeyBundle(loginUsernameRef.current, peer, material.fullBundle);
        }
      } finally { sessionPrefetchMap.current.delete(peer); }
    })();
    sessionPrefetchMap.current.set(peer, p);
    await p.catch(() => { });
  }, [findUser, isLoggedIn, loginUsernameRef, users]);

  useEffect(() => {
    const handleSessionReady = createSessionReadyHandler(pendingRetryMessagesRef, handleSendMessage);
    const handleSessionEstablishedReceived = createSessionReadyHandler(pendingRetryMessagesRef, handleSendMessage);
    const handleSessionReset = createSessionResetRetryHandler(pendingRetryMessagesRef, secureDBRef);

    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablishedReceived as EventListener);
    window.addEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    return () => {
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablishedReceived as EventListener);
      window.removeEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    };
  }, [handleSendMessage]);

  return { handleSendMessage, prefetchSessionForPeer };
}
