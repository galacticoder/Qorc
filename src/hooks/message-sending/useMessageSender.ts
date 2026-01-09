import React, { useCallback, useMemo, useRef, useEffect } from 'react';
import { SignalType } from '../../lib/types/signal-types';
import { EventType } from '../../lib/types/event-types';
import { Message } from '../../components/chat/messaging/types';
import websocketClient from '../../lib/websocket/websocket';
import { isValidKyberPublicKeyBase64 } from '../../lib/utils/messaging-validators';
import type { SecureDB } from '../../lib/database/secureDB';
import { encryptLongTerm } from '../../lib/cryptography/long-term-encryption';
import { sanitizeContent, sanitizeUsername } from '../../lib/sanitizers';
import type { HybridPublicKeys, UserWithKeys, PendingRetryMessage } from '../../lib/types/message-sending-types';
import { validateFileData, sanitizeReply, logError, getIdCache, mapSignalType, createLocalMessage, getSessionApi, TEXT_ENCODER } from '../../lib/utils/message-sending-utils';
import { ensureSession } from './session';
import { recipientKeyValidator } from './validation';
import { createDefaultResolvePeerHybridKeys } from './keys';
import { createSessionResetHandler, createSessionEstablishedHandler, createSessionReadyHandler, createSessionResetRetryHandler } from './handlers';
import { globalEncryptedPayloadCache, globalLongTermStoreAttempted, buildMessagePayload, encryptAndSend, cacheEncryptedPayload, dispatchLocalEvents, storeUnacknowledgedMessage, queueMessageForLater, requestBundleForRetry } from './send';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import type { SecureP2PService } from '../../lib/transport/secure-p2p-service';
import { unifiedSignalTransport } from '../../lib/transport/unified-signal-transport';

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
  p2pServiceRef?: React.RefObject<SecureP2PService | null>
) {
  const recipientDirectory = useMemo(() => {
    const map = new Map<string, UserWithKeys>();
    users.forEach((user) => { if (user.username) map.set(user.username, user); });
    return map;
  }, [users]);

  const defaultResolvePeerHybridKeys = useCallback(
    createDefaultResolvePeerHybridKeys(recipientDirectory, getKeysOnDemand, loginUsernameRef, currentUsername),
    [recipientDirectory, getKeysOnDemand, loginUsernameRef, currentUsername]
  );

  const resolvePeerHybridKeysToUse = resolvePeerHybridKeys || defaultResolvePeerHybridKeys;

  useEffect(() => {
    const handler = async (event: Event) => {
      const detail = (event as CustomEvent).detail || {};
      const to = typeof detail.to === 'string' ? detail.to : '';
      const messageId = typeof detail.messageId === 'string' ? detail.messageId : '';
      if (!to || !messageId) return;

      const attemptKey = `${to}|${messageId}`;
      if (globalLongTermStoreAttempted.has(attemptKey)) return;
      globalLongTermStoreAttempted.add(attemptKey);

      const cached = globalEncryptedPayloadCache.get(attemptKey);
      if (!cached?.encryptedPayload) return;

      let recipientKyberKey: string | null = recipientDirectory.get(to)?.hybridPublicKeys?.kyberPublicBase64 ?? null;
      if (!recipientKyberKey) {
        try { const resolved = await resolvePeerHybridKeysToUse(to); recipientKyberKey = resolved?.kyberPublicBase64 ?? null; } catch { }
      }
      if (!recipientKyberKey || !isValidKyberPublicKeyBase64(recipientKyberKey)) return;

      try {
        const messageData = JSON.stringify({ messageId, encryptedPayload: cached.encryptedPayload, timestamp: Date.now() });
        const longTermEnvelope = await encryptLongTerm(messageData, recipientKyberKey);
        await websocketClient.sendSecureControlMessage({ type: SignalType.STORE_OFFLINE_MESSAGE, messageId, to, longTermEnvelope, version: 'lt-v1' });
      } catch { }
    };

    window.addEventListener(EventType.OFFLINE_LONGTERM_REQUIRED, handler as EventListener);
    return () => window.removeEventListener(EventType.OFFLINE_LONGTERM_REQUIRED, handler as EventListener);
  }, [recipientDirectory, resolvePeerHybridKeysToUse]);

  const sessionLocksRef = useRef(new WeakMap<object, Map<string, Promise<boolean>>>());
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
          const localMessage = createLocalMessage(messageId, currentUser, recipientUsername, sanitizedContent ?? '', timestamp, replyToData, fileDataToSend);
          (localMessage as any).pending = true;
          onNewMessage(localMessage);
          if (secureDBRef?.current) { try { await secureDBRef.current.storeMessage({ ...localMessage, timestamp: localMessage.timestamp.getTime() }); } catch { } }
        }
        await queueMessageForLater(recipientUsername, sanitizedContent ?? '', messageId, replyToData, fileDataToSend, messageSignalType, editMessageId);
        resolvePeerHybridKeysToUse(recipientUsername).catch(() => { });
        return;
      }

      const recipientKyberKey = recipient.hybridPublicKeys.kyberPublicBase64;
      if (messageType === SignalType.MESSAGE && !sanitizedContent) return;
      if ((messageType === SignalType.REACTION_ADD || messageType === SignalType.REACTION_REMOVE) && !sanitizedContent) return;

      const localKeys = await getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey) { logError('LOCAL-KEYS'); return; }

      const timestamp = Date.now();
      let messageId = originalMessageId || (() => { let id; do { id = crypto.randomUUID().replace(/-/g, ''); } while (!idCacheRef.current.isStale(id)); idCacheRef.current.add(id); return id; })();

      try {
        const sessionReady = await ensureSession(sessionLocksRef.current, lockContext, currentUser, recipientUsername, { secretKey: localKeys.dilithium.secretKey, publicKeyBase64: localKeys.dilithium.publicKeyBase64 });
        if (!sessionReady) throw new Error('Failed to establish session');

        let senderSignalBundle: any;
        if (!peerCanDecryptRef.current.get(recipientUsername) && (preKeyFailureCountRef.current.get(recipientUsername) || 0) < 3) {
          try { senderSignalBundle = await (window as any).edgeApi?.getPreKeyBundle?.({ selfUsername: currentUser, deviceId: 1 }); } catch { }
        }

        const wireMessageId = (messageType === SignalType.EDIT_MESSAGE && editMessageId) ? editMessageId : messageId;
        const payload = buildMessagePayload(wireMessageId, currentUser, recipientUsername, sanitizedContent, timestamp, messageType, messageSignalType, localKeys, originalUsernameRef, replyToData, fileData, originalMessageId, editMessageId, senderSignalBundle);

        const encrypted = await encryptAndSend(payload, currentUser, recipientUsername, recipientKyberKey, recipient.hybridPublicKeys, localKeys, sessionLocksRef, lockContext);
        if (!encrypted?.success || !encrypted?.encryptedPayload) { logError('encryption-failed', new Error(encrypted?.error || 'Unknown')); throw new Error(`Encryption failed: ${encrypted?.error}`); }

        cacheEncryptedPayload(recipientUsername, wireMessageId, encrypted.encryptedPayload);
        await unifiedSignalTransport.send(recipientUsername, { messageId: wireMessageId, encryptedPayload: encrypted.encryptedPayload }, messageType as SignalType);

        if (messageType !== SignalType.TYPING_INDICATOR && messageType !== SignalType.DELIVERY_RECEIPT && messageType !== SignalType.READ_RECEIPT) {
          await storeUnacknowledgedMessage(secureDBRef, recipientUsername, timestamp, { user, content, replyTo, fileData, messageSignalType, originalMessageId: messageId, editMessageId, timestamp });
        }

        if (dispatchLocalEvents(messageType, messageSignalType, originalMessageId, editMessageId, wireMessageId, sanitizedContent, currentUser)) return;

        if (!originalMessageId) {
          const localMessage = createLocalMessage(messageId, currentUser, recipientUsername, sanitizedContent ?? '', timestamp, replyToData, fileData);
          onNewMessage(localMessage);
          if (secureDBRef?.current) { try { await secureDBRef.current.storeMessage({ ...localMessage, timestamp: localMessage.timestamp.getTime() }); } catch { } }
        }
      } catch (_error) {
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        if (errorMessage.toLowerCase().includes('prekey') && recipientUsername) preKeyFailureCountRef.current.set(recipientUsername, (preKeyFailureCountRef.current.get(recipientUsername) || 0) + 1);
        if ((errorMessage.includes('session') || errorMessage.includes('Encryption failed')) && recipientUsername) {
          const retryCount = (pendingRetryMessagesRef.current.get(recipientUsername)?.retryCount || 0) + 1;
          if (retryCount <= 2) pendingRetryMessagesRef.current.set(recipientUsername, { user, content, replyTo, fileData, messageSignalType, originalMessageId: messageId, editMessageId, retryCount });
          await requestBundleForRetry(recipientUsername, currentUser, getKeysOnDemand, lastSessionBundleReqTsRef);
        }
        logError('SEND', _error);
      }
    },
    [isLoggedIn, loginUsernameRef, recipientDirectory, getKeysOnDemand, onNewMessage, lockContext, hasUsernameMapping],
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
        const keys = await getKeysOnDemand();
        if (!keys?.dilithium?.secretKey) return;
        const req = { type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, username: peer, from: currentUser, timestamp: now, challenge: CryptoUtils.Base64.arrayBufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))), senderDilithium: keys.dilithium.publicKeyBase64, reason: 'prefetch-session' } as const;
        const canonical = TEXT_ENCODER.encode(JSON.stringify(req));
        const sigRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
        await websocketClient.sendSecureControlMessage({ ...req, signature: CryptoUtils.Base64.arrayBufferToBase64(sigRaw) });
      } finally { sessionPrefetchMap.current.delete(peer); }
    })();
    sessionPrefetchMap.current.set(peer, p);
    await p.catch(() => { });
  }, [getKeysOnDemand, isLoggedIn, loginUsernameRef]);

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
