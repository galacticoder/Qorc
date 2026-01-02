import React, { useCallback, useEffect, useRef } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import { Message } from "../../components/chat/messaging/types";
import type { User } from "../../components/chat/messaging/UserList";
import websocketClient from "../../lib/websocket";
import { blockingSystem } from "../../lib/blocking/blocking-system";
import { handleCallSignal } from "../../lib/types/message-handler-types";
import { resolveSenderHybridKeys, requestBundleOnce } from "./keys";
import { sendEncryptedDeliveryReceipt, retryFailedDeliveryReceipts } from "./receipts";
import { processTextMessage, processFileMessage, checkBlockingFilter, getMessageType } from "./message-processing";
import type { PendingRetryEntry, FailedDeliveryReceipt, AttemptsLedgerEntry, ResetCounterEntry } from "../../lib/types/message-handling-types";
import { handleSessionResetAndRetry, retryPendingMessages, replenishPqKyberPrekey } from "./session";
import {
  createBlobCache,
  sanitizeRateLimitConfig,
  type RateLimitConfig,
} from "../../lib/utils/message-handler-utils";
import { BLOB_URL_TTL_MS,
  KEY_REQUEST_CACHE_DURATION,
  PENDING_QUEUE_TTL_MS,
  PENDING_QUEUE_MAX_PER_PEER,
  MAX_GLOBAL_PENDING_MESSAGES,
  PQ_KEY_REPLENISH_COOLDOWN_MS,
  MAX_RESETS_PER_PEER,
  RESET_WINDOW_MS 
} from "../../lib/constants";
import {
  dispatchReadReceiptEvent,
  dispatchDeliveryReceiptEvent,
  dispatchTypingIndicatorEvent,
  clearTypingIndicator,
  handleMessageDeletion,
  handleMessageEdit,
  handleReaction,
  showNotification,
  storeUsernameMapping
} from "./handlers";
import {
  validateP2PMessage,
  createP2PPayload,
  decryptSignalMessage,
  processBundleDelivery,
  processSenderBundle,
  trustPeerIdentity,
  parseDecryptedPayload
} from "./decryption";

export function useEncryptedMessageHandler(
  loginUsernameRef: React.RefObject<string>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  isAuthenticated?: boolean,
  getKeysOnDemand?: () => Promise<{ x25519: { private: Uint8Array; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array }; dilithium?: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  usersRef?: React.RefObject<User[]>,
  options?: { rateLimit?: Partial<RateLimitConfig> },
  handleFileMessageChunk?: (data: any, meta: any) => Promise<void>,
  secureDBRef?: React.RefObject<any | null>
) {
  const blobCacheRef = useRef(createBlobCache());
  const rateStateRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });
  const rateConfigRef = useRef<RateLimitConfig>(sanitizeRateLimitConfig(options?.rateLimit));
  const keyRequestCacheRef = useRef<Map<string, number>>(new Map());
  const inFlightBundleRequestsRef = useRef<Map<string, Promise<void>>>(new Map());
  const pendingRetryMessagesRef = useRef<Map<string, PendingRetryEntry[]>>(new Map());
  const pendingRetryIdsRef = useRef<Map<string, Set<string>>>(new Map());
  const failedDeliveryReceiptsRef = useRef<Map<string, FailedDeliveryReceipt>>(new Map());
  const attemptsLedgerRef = useRef<Map<string, AttemptsLedgerEntry>>(new Map());
  const lastKyberFpRef = useRef<Map<string, string>>(new Map());
  const bundleRequestCooldownRef = useRef<Map<string, number>>(new Map());
  const resetCounterRef = useRef<Map<string, ResetCounterEntry>>(new Map());
  const callbackRef = useRef<((msg: any) => Promise<void>) | null>(null);
  const lastPqKeyReplenishRef = useRef<number>(0);
  const replenishmentInProgressRef = useRef<boolean>(false);
  const processedPreKeyMessagesRef = useRef<Map<string, number>>(new Map());
  const resetCooldownRef = useRef<Map<string, number>>(new Map());

  const requestBundleOnceCallback = useCallback(async (peerUsername: string, reason?: string) => {
    await requestBundleOnce(peerUsername, keyRequestCacheRef, inFlightBundleRequestsRef, getKeysOnDemand, loginUsernameRef, reason);
  }, [getKeysOnDemand, loginUsernameRef]);

  const replenishCallback = useCallback(async (opts?: { force?: boolean }) => {
    await replenishPqKyberPrekey(isAuthenticated, loginUsernameRef, lastPqKeyReplenishRef, replenishmentInProgressRef, PQ_KEY_REPLENISH_COOLDOWN_MS, opts);
  }, [isAuthenticated, loginUsernameRef]);

  // Cleanup intervals
  useEffect(() => {
    const interval = setInterval(() => blobCacheRef.current.flush(), BLOB_URL_TTL_MS / 2);
    const cacheCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [username, timestamp] of keyRequestCacheRef.current.entries()) {
        if (now - timestamp > KEY_REQUEST_CACHE_DURATION) keyRequestCacheRef.current.delete(username);
      }

      const pendingMessages = pendingRetryMessagesRef.current;
      let total = 0;
      const allEntries: Array<{ user: string; idx: number; ts: number }> = [];
      
      for (const [username, messages] of pendingMessages.entries()) {
        const filtered = messages.filter(m => now - m.timestamp < PENDING_QUEUE_TTL_MS);
        const kept = filtered.length > PENDING_QUEUE_MAX_PER_PEER ? filtered.slice(filtered.length - PENDING_QUEUE_MAX_PER_PEER) : filtered;

        if (kept.length === 0) {
          pendingMessages.delete(username);
          pendingRetryIdsRef.current.delete(username);
        } else {
          pendingMessages.set(username, kept);
          const idSet = new Set<string>();
          for (const item of kept) {
            const env = item?.message?.encryptedPayload;
            const msgKey: string = typeof env?.kemCiphertext === 'string' ? env.kemCiphertext : (item?.message?.messageId || '');
            if (msgKey) idSet.add(msgKey);
          }
          pendingRetryIdsRef.current.set(username, idSet);
          total += kept.length;
          kept.forEach((m, i) => allEntries.push({ user: username, idx: i, ts: m.timestamp }));
        }
      }
      if (total > MAX_GLOBAL_PENDING_MESSAGES) {
        const toDrop = total - MAX_GLOBAL_PENDING_MESSAGES;
        allEntries.sort((a, b) => a.ts - b.ts);

        for (let k = 0; k < toDrop && k < allEntries.length; k++) {
          const e = allEntries[k];
          const arr = pendingMessages.get(e.user);
          if (!arr) continue;
          arr.splice(0, 1);
          if (arr.length === 0) { pendingMessages.delete(e.user); pendingRetryIdsRef.current.delete(e.user); }
        }
      }
    }, 10000);

    const handleSessionReady = (event: Event) => {
      const detail = (event as CustomEvent).detail || {};
      const peer = typeof detail.peer === 'string' ? detail.peer : (typeof detail.peerUsername === 'string' ? detail.peerUsername : undefined);
      if (typeof peer === 'string') retryPendingMessages(peer, pendingRetryMessagesRef, pendingRetryIdsRef, callbackRef);
    };

    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);

    return () => {
      clearInterval(interval);
      clearInterval(cacheCleanupInterval);
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
      blobCacheRef.current.clearAll();
      keyRequestCacheRef.current.clear();
      pendingRetryMessagesRef.current.clear();
    };
  }, []);

  // P2P peer reconnection handler
  useEffect(() => {
    const handlePeerReconnection = async (event: Event) => {
      try {
        const { peer } = (event as CustomEvent).detail || {};
        if (typeof peer !== 'string' || !loginUsernameRef.current) return;

        try { await (window as any).edgeApi?.deleteSession?.({ selfUsername: loginUsernameRef.current, peerUsername: peer, deviceId: 1 }); } catch { }
        pendingRetryMessagesRef.current.delete(peer);
        pendingRetryIdsRef.current.delete(peer);
        attemptsLedgerRef.current.forEach((_, key) => { if (key.startsWith(`${peer}|`)) attemptsLedgerRef.current.delete(key); });
        resetCooldownRef.current.delete(peer);
        keyRequestCacheRef.current.delete(peer);
        try { await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: peer }); } catch { }
      } catch { }
    };

    window.addEventListener(EventType.P2P_PEER_RECONNECTED, handlePeerReconnection as EventListener);
    return () => window.removeEventListener(EventType.P2P_PEER_RECONNECTED, handlePeerReconnection as EventListener);
  }, [loginUsernameRef]);

  // Session established handler retry failed receipts
  useEffect(() => {
    const handleSessionEstablished = async (event: Event) => {
      try {
        const { peer, fromPeer } = (event as CustomEvent).detail || {};
        const peerUsername = peer || fromPeer;
        if (typeof peerUsername !== 'string') return;
        await retryFailedDeliveryReceipts(peerUsername, failedDeliveryReceiptsRef, getKeysOnDemand, usersRef as any, loginUsernameRef);
      } catch (_error) {
        console.error('[EncryptedMessageHandler] Error handling session-established event:', _error);
      }
    };

    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablished as EventListener);
    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionEstablished as EventListener);
    return () => {
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablished as EventListener);
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionEstablished as EventListener);
    };
  }, [getKeysOnDemand, usersRef, loginUsernameRef]);

  // File transfer complete handler
  useEffect(() => {
    const handler = async (event: Event) => {
      try {
        const detail = (event as CustomEvent).detail || {};
        const senderUsername: string | undefined = typeof detail.from === 'string' ? detail.from : undefined;
        const messageId: string | undefined = typeof detail.messageId === 'string' ? detail.messageId : undefined;
        if (!senderUsername || !messageId) return;

        const { kyber, hybrid } = await resolveSenderHybridKeys(senderUsername, usersRef as any, keyRequestCacheRef, getKeysOnDemand, loginUsernameRef, KEY_REQUEST_CACHE_DURATION);
        if (!kyber || !hybrid) {
          const key = `${senderUsername}|${messageId}`;
          failedDeliveryReceiptsRef.current.set(key, { messageId, peerUsername: senderUsername, timestamp: Date.now(), attempts: 0 });
          return;
        }

        await sendEncryptedDeliveryReceipt(loginUsernameRef.current || '', senderUsername, messageId, kyber, hybrid, failedDeliveryReceiptsRef);
      } catch { }
    };
    window.addEventListener(EventType.FILE_TRANSFER_COMPLETE, handler as EventListener);
    return () => window.removeEventListener(EventType.FILE_TRANSFER_COMPLETE, handler as EventListener);
  }, [getKeysOnDemand, usersRef, loginUsernameRef]);

  // P2P session reset control
  useEffect(() => {
    const onP2PSessionResetReq = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const from = d?.from;
        if (!from || !loginUsernameRef.current) return;

        try { await (window as any).edgeApi?.deleteSession?.({ selfUsername: loginUsernameRef.current, peerUsername: from, deviceId: 1 }); } catch { }
        
        try { window.dispatchEvent(new CustomEvent(EventType.SESSION_RESET_RECEIVED, { detail: { peerUsername: from, reason: d?.reason || 'p2p-control' } })); } catch { }
        
        try { await requestBundleOnceCallback(from, EventType.P2P_SESSION_RESET); } catch { }
      } catch { }
    };

    window.addEventListener(EventType.P2P_SESSION_RESET_REQUEST, onP2PSessionResetReq as EventListener);
    return () => window.removeEventListener(EventType.P2P_SESSION_RESET_REQUEST, onP2PSessionResetReq as EventListener);
  }, [loginUsernameRef, requestBundleOnceCallback]);

  const handleEncryptedMessageCallback = useCallback(
    async (encryptedMessage: any) => {
      const now = Date.now();
      const rateState = rateStateRef.current;
      const config = rateConfigRef.current;
      if (now - rateState.windowStart > config.windowMs) { rateState.windowStart = now; rateState.count = 0; }
      rateState.count += 1;
      if (rateState.count > config.max) return;

      const isP2PMessage = encryptedMessage?.p2p === true && encryptedMessage?.encrypted === true;
      const isOfflineMessage = encryptedMessage?.offline === true;
      const isSignalProtocolMessage = encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE;
      const isBundleMessage = encryptedMessage?.type === SignalType.LIBSIGNAL_DELIVER_BUNDLE;
      const isBackgroundMessage = encryptedMessage?._decryptedInBackground === true;

      if (!isAuthenticated && !isP2PMessage && !isOfflineMessage && !isSignalProtocolMessage && !isBundleMessage && !isBackgroundMessage) return;

      try {
        if (typeof encryptedMessage !== "object" || encryptedMessage === null || Array.isArray(encryptedMessage)) {
          console.error('[EncryptedMessageHandler] Invalid message type');
          return;
        }
        if (encryptedMessage.hasOwnProperty('__proto__') || encryptedMessage.hasOwnProperty('constructor') || encryptedMessage.hasOwnProperty('prototype')) {
          console.error('[EncryptedMessageHandler] Prototype pollution attempt detected');
          return;
        }

        let payload: any;
        const currentUser = loginUsernameRef.current || '';

        // Pre-decrypted background messages
        if (isBackgroundMessage) {
          const { _decryptedInBackground, _originalFrom, ...rest } = encryptedMessage;
          payload = rest;
          if (!payload.from && _originalFrom) payload.from = _originalFrom;
        }
        // P2P messages
        else if (isP2PMessage) {
          if (!validateP2PMessage(encryptedMessage, currentUser)) return;
          payload = createP2PPayload(encryptedMessage);
        }
        // Signal Protocol messages
        else if (isSignalProtocolMessage && encryptedMessage?.encryptedPayload && getKeysOnDemand) {
          const result = await decryptSignalMessage(encryptedMessage, currentUser, processedPreKeyMessagesRef);
          if (!result) return;

          const { payload: decrypted, attachedChunkData } = result;
          if (!decrypted?.success || typeof decrypted?.plaintext !== 'string') {
            const errMsg = String(decrypted?.error || '').toLowerCase();
            const senderUsername = encryptedMessage.from || '';

            // Handle untrusted identity errors
            if (errMsg.includes('untrusted identity') && senderUsername) {
              await trustPeerIdentity(currentUser, senderUsername);
            }

            // Handle session errors with retry
            const isSessionError = /session|no valid sessions|no session|invalid whisper message|decryption failed|bad mac|message keys/i.test(errMsg);
            if (isSessionError && senderUsername) {
              await handleSessionResetAndRetry(
                senderUsername,
                encryptedMessage,
                currentUser,
                pendingRetryMessagesRef,
                pendingRetryIdsRef,
                attemptsLedgerRef,
                lastKyberFpRef,
                bundleRequestCooldownRef,
                resetCooldownRef,
                resetCounterRef,
                requestBundleOnceCallback,
                MAX_RESETS_PER_PEER,
                RESET_WINDOW_MS
              );
            }
            return;
          }

          payload = parseDecryptedPayload(decrypted.plaintext, encryptedMessage.from);
          await processSenderBundle(payload, currentUser);
          replenishCallback().catch(() => { });

          if (payload.type === SignalType.FILE_MESSAGE_CHUNK && attachedChunkData) {
            payload.chunkData = attachedChunkData;
          }
        }
        // Bundle delivery
        else if (isBundleMessage) {
          await processBundleDelivery(encryptedMessage, currentUser);
          return;
        }
        else {
          return;
        }

        storeUsernameMapping(payload);

        // Request sender keys if needed
        if (payload.from && payload.from !== currentUser) {
          const userExists = usersRef?.current?.find?.((u: any) => u.username === payload.from);
          const needsKeys = !userExists || !userExists.hybridPublicKeys || !userExists.hybridPublicKeys.kyberPublicBase64;
          if (needsKeys) {
            const lastReq = keyRequestCacheRef.current.get(payload.from);
            if (!lastReq || (now - lastReq) > KEY_REQUEST_CACHE_DURATION) {
              keyRequestCacheRef.current.set(payload.from, now);
              await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: payload.from });
              try { await requestBundleOnceCallback(payload.from); } catch { }
            }
          }
        }

        // Check blocking filter
        if (!await checkBlockingFilter(payload, currentUser, blockingSystem)) return;

        // Handle receipts
        if (payload.type === SignalType.READ_RECEIPT && payload.messageId) { dispatchReadReceiptEvent(payload.messageId, payload.from); return; }
        if (payload.type === SignalType.DELIVERY_RECEIPT && payload.messageId) { dispatchDeliveryReceiptEvent(payload.messageId, payload.from); return; }

        // Handle file chunks
        if (payload.type === SignalType.FILE_MESSAGE_CHUNK) {
          if (handleFileMessageChunk) {
            try { await handleFileMessageChunk(payload, { from: payload.from }); } catch (_error) { console.error('[EncryptedMessageHandler] Failed to handle file chunk:', _error); }
          }
          return;
        }

        // Handle typing indicators
        if (payload.type === SignalType.TYPING_START || payload.type === SignalType.TYPING_STOP || payload.type === SignalType.TYPING_INDICATOR) {
          await dispatchTypingIndicatorEvent(payload);
          return;
        }

        const { isTextMessage, isFileMessage, isCallSignal } = getMessageType(payload);
        if (isTextMessage || isFileMessage) clearTypingIndicator(payload.from);
        if ((isTextMessage || isFileMessage || isCallSignal) && payload.from !== currentUser) {
          showNotification(payload, currentUser, isCallSignal, isFileMessage);
        }

        // Handle deletion
        if (payload.type === SignalType.DELETE_MESSAGE) {
          await handleMessageDeletion(payload, setMessages, saveMessageToLocalDB);
          return;
        }

        // Handle edit
        if (payload.type === SignalType.EDIT_MESSAGE) {
          await handleMessageEdit(payload, setMessages, saveMessageToLocalDB);
          return;
        }

        // Handle reactions
        if (payload.type === SignalType.REACTION_ADD || payload.type === SignalType.REACTION_REMOVE) {
          handleReaction(payload, setMessages);
          return;
        }

        // Handle text messages
        if (isTextMessage && payload.type !== SignalType.FILE_MESSAGE) {
          const { messageId, messageAdded } = await processTextMessage(payload, currentUser, setMessages, saveMessageToLocalDB);
          if (messageAdded && messageId) {
            const { kyber, hybrid } = await resolveSenderHybridKeys(payload.from, usersRef as any, keyRequestCacheRef, getKeysOnDemand, loginUsernameRef, KEY_REQUEST_CACHE_DURATION);
            if (kyber && hybrid) {
              await sendEncryptedDeliveryReceipt(currentUser, payload.from, messageId, kyber, hybrid, failedDeliveryReceiptsRef);
            }
          }
        }

        // Handle file messages
        if (payload.type === SignalType.FILE_MESSAGE) {
          const { messageId, messageAdded } = await processFileMessage(payload, currentUser, setMessages, saveMessageToLocalDB, blobCacheRef.current, secureDBRef);
          if (messageAdded && messageId) {
            const { kyber, hybrid } = await resolveSenderHybridKeys(payload.from, usersRef as any, keyRequestCacheRef, getKeysOnDemand, loginUsernameRef, KEY_REQUEST_CACHE_DURATION);
            if (kyber && hybrid) {
              await sendEncryptedDeliveryReceipt(currentUser, payload.from, messageId, kyber, hybrid, failedDeliveryReceiptsRef);
            }
          }
        }

        // Handle call signals
        if (payload.type === EventType.CALL_SIGNAL) {
          handleCallSignal({ payload: { content: payload.content, from: payload.from, fromOriginal: payload?.fromOriginal } });
        }
      } catch (_error) {
        console.error('[EncryptedMessageHandler] Error processing encrypted message:', _error);
      }
    },
    [setMessages, saveMessageToLocalDB, isAuthenticated, getKeysOnDemand, usersRef, handleFileMessageChunk, replenishCallback, requestBundleOnceCallback, loginUsernameRef, secureDBRef]
  );

  useEffect(() => { callbackRef.current = handleEncryptedMessageCallback; }, [handleEncryptedMessageCallback]);

  return handleEncryptedMessageCallback;
}
