import React, { useCallback, useEffect, useRef } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { invalidateDiscoveryCache } from "../discovery/useDiscovery";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { EventType } from "../../lib/types/event-types";
import { Message } from "../../components/chat/messaging/types";
import type { User } from "../../components/chat/messaging/UserList";
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
import {
  BLOB_URL_TTL_MS,
  KEY_REQUEST_CACHE_DURATION,
  PENDING_QUEUE_TTL_MS,
  PENDING_QUEUE_MAX_PER_PEER,
  MAX_GLOBAL_PENDING_MESSAGES,
  PQ_KEY_REPLENISH_COOLDOWN_MS,
  MAX_RESETS_PER_PEER,
  RESET_WINDOW_MS,
  COVER_TRAFFIC_PAYLOAD_TYPE
} from "../../lib/constants";
import {
  dispatchReadReceiptEvent,
  dispatchDeliveryReceiptEvent,
  dispatchTypingIndicatorEvent,
  clearTypingIndicator,
  handleMessageDeletion,
  handleMessageEdit,
  handleReaction,
  showNotification
} from "./handlers";
import {
  processBundleDelivery,
  processSenderBundle,
  trustPeerIdentity,
  parseDecryptedPayload,
  decryptSignalMessage
} from "./decryption";
import { signal } from "../../lib/tauri-bindings";
import { getBlindRoutingClient } from "../../lib/transport/blind-routing-client";
import { profilePictureSystem } from "../../lib/avatar/profile-picture-system";
import { shouldAttemptDiscovery } from "../../lib/utils/discovery-utils";

const ENVELOPE_DEDUP_TTL_MS = 5 * 60 * 1000;

export function useEncryptedMessageHandler(
  loginUsernameRef: React.RefObject<string>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  isAuthenticated?: boolean,
  getKeysOnDemand?: () => Promise<{ x25519: { private: Uint8Array; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array }; dilithium?: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  usersRef?: React.RefObject<User[]>,
  options?: { rateLimit?: Partial<RateLimitConfig> },
  handleFileMessageChunk?: (data: any, meta: any) => Promise<void>,
  secureDBRef?: React.RefObject<any | null>,
  findUser?: (handle: string) => Promise<any>
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
  const processedEnvelopeIdsRef = useRef<Map<string, number>>(new Map());
  const processedSignalCiphertextsRef = useRef<Map<string, number>>(new Map());
  const resetCooldownRef = useRef<Map<string, number>>(new Map());

  const requestBundleOnceCallback = useCallback(async (peerUsername: string, _reason?: string) => {
    await requestBundleOnce(peerUsername, keyRequestCacheRef, inFlightBundleRequestsRef, loginUsernameRef, findUser);
  }, [getKeysOnDemand, loginUsernameRef, usersRef, findUser]);

  const replenishCallback = useCallback(async (opts?: { force?: boolean }) => {
    await replenishPqKyberPrekey(isAuthenticated, loginUsernameRef, lastPqKeyReplenishRef, replenishmentInProgressRef, PQ_KEY_REPLENISH_COOLDOWN_MS, opts);
  }, [isAuthenticated, loginUsernameRef]);

  const getSignalCiphertextKey = useCallback((payload: any): string | null => {
    if (!payload || typeof payload !== 'object') return null;
    const kem = payload.kem_ciphertext || payload.kemCiphertext ||
      payload?.pqEnvelope?.kemCiphertext || payload?.pq_envelope?.kem_ciphertext;
    if (typeof kem === 'string' && kem.length > 0) {
      return `kem:${kem}`;
    }
    const cipher = payload.ciphertext || payload.signal_message;
    if (typeof cipher === 'string' && cipher.length > 0) {
      return `ct:${cipher}`;
    }
    return null;
  }, []);

  const resolvePeerInboxId = useCallback(async (peer: string): Promise<string | null> => {
    if (!peer) return null;
    const users = usersRef?.current || [];
    const existing = users.find((u: any) => u.username === peer);
    const cachedInbox = existing?.inboxId || existing?.hybridPublicKeys?.inboxId;
    if (cachedInbox) return cachedInbox;

    if (!findUser) return null;
    try {
      const known = usersRef?.current?.map?.((u: any) => u.username).filter(Boolean) ?? [];
      if (!shouldAttemptDiscovery(peer, known)) {
        return null;
      }
      const material = await findUser(peer);
      if (material?.inboxId) {
        window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
          detail: {
            username: peer,
            hybridKeys: material.publicKeys,
            inboxId: material.inboxId
          }
        }));
        return material.inboxId;
      }
    } catch { }
    return null;
  }, [usersRef, findUser]);

  // Cleanup intervals
  useEffect(() => {
    const interval = setInterval(() => blobCacheRef.current.flush(), BLOB_URL_TTL_MS / 2);
    const cacheCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [username, timestamp] of keyRequestCacheRef.current.entries()) {
        if (now - timestamp > KEY_REQUEST_CACHE_DURATION) keyRequestCacheRef.current.delete(username);
      }
      for (const [messageId, timestamp] of processedEnvelopeIdsRef.current.entries()) {
        if (now - timestamp > ENVELOPE_DEDUP_TTL_MS) {
          processedEnvelopeIdsRef.current.delete(messageId);
        }
      }
      for (const [cipherKey, timestamp] of processedSignalCiphertextsRef.current.entries()) {
        if (now - timestamp > ENVELOPE_DEDUP_TTL_MS) {
          processedSignalCiphertextsRef.current.delete(cipherKey);
        }
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
      processedEnvelopeIdsRef.current.clear();
      processedSignalCiphertextsRef.current.clear();
    };
  }, []);

  // Handler for when a session with a peer becomes ready
  useEffect(() => {
    const handleReady = async (event: Event) => {
      try {
        const { peer, fromPeer } = (event as CustomEvent).detail || {};
        const peerUsername = peer || fromPeer;
        if (typeof peerUsername !== 'string' || !loginUsernameRef.current) return;

        // Retry pending messages
        retryPendingMessages(peerUsername, pendingRetryMessagesRef, pendingRetryIdsRef, callbackRef);

        // Clear reset cooldowns and ledger to allow fresh attempts if needed later
        attemptsLedgerRef.current.forEach((_, key) => { if (key.startsWith(`${peerUsername}|`)) attemptsLedgerRef.current.delete(key); });
        resetCooldownRef.current.delete(peerUsername);
        keyRequestCacheRef.current.delete(peerUsername);

        // Trigger retries for failed delivery receipts
        await retryFailedDeliveryReceipts(peerUsername, failedDeliveryReceiptsRef, usersRef as any, loginUsernameRef, resolvePeerInboxId);
      } catch (_error) {
        console.error('[EncryptedMessageHandler] Error handling ready event:', _error);
      }
    };

    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleReady as EventListener);
    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleReady as EventListener);
    window.addEventListener(EventType.P2P_PEER_CONNECTED, handleReady as EventListener);

    return () => {
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleReady as EventListener);
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleReady as EventListener);
      window.removeEventListener(EventType.P2P_PEER_CONNECTED, handleReady as EventListener);
    };
  }, [getKeysOnDemand, usersRef, loginUsernameRef, resolvePeerInboxId]);

  // File transfer complete handler
  useEffect(() => {
    const handler = async (event: Event) => {
      try {
        const detail = (event as CustomEvent).detail || {};
        const senderUsername: string | undefined = typeof detail.from === 'string' ? detail.from : undefined;
        const messageId: string | undefined = typeof detail.messageId === 'string' ? detail.messageId : undefined;
        if (!senderUsername || !messageId) return;

        const { kyber, hybrid } = await resolveSenderHybridKeys(senderUsername, usersRef as any, keyRequestCacheRef, loginUsernameRef, KEY_REQUEST_CACHE_DURATION, findUser);
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

        try { await signal.deleteSession(loginUsernameRef.current!, from, 1); } catch { }

        try { window.dispatchEvent(new CustomEvent(EventType.SESSION_RESET_RECEIVED, { detail: { peerUsername: from, reason: d?.reason || 'p2p-control' } })); } catch { }

        try { await requestBundleOnceCallback(from, EventType.P2P_SESSION_RESET); } catch { }
      } catch { }
    };

    window.addEventListener(EventType.P2P_SESSION_RESET_REQUEST, onP2PSessionResetReq as EventListener);
    return () => window.removeEventListener(EventType.P2P_SESSION_RESET_REQUEST, onP2PSessionResetReq as EventListener);
  }, [loginUsernameRef, requestBundleOnceCallback]);

  const handleEncryptedMessageCallback = useCallback(
    async (encryptedMessage: any, options: { isRecursive?: boolean } = {}) => {
      const now = Date.now();
      const rateState = rateStateRef.current;
      const config = rateConfigRef.current;
      if (now - rateState.windowStart > config.windowMs) { rateState.windowStart = now; rateState.count = 0; }
      rateState.count += 1;
      if (rateState.count > config.max) return;

      const isSealedEnvelope = encryptedMessage?.type === SignalType.SEALED_ENVELOPE;
      const isBundleMessage = encryptedMessage?.type === SignalType.LIBSIGNAL_DELIVER_BUNDLE;
      const isBackgroundMessage = encryptedMessage?._decryptedInBackground === true;
      const isRecursive = !!options.isRecursive || !!encryptedMessage?.__isRecursive;
      const isP2PTransport = (encryptedMessage as any)?.__transport === 'p2p';

      if (!isAuthenticated && !isBundleMessage && !isBackgroundMessage && !isSealedEnvelope && !isRecursive) return;

      if (!isSealedEnvelope && !isRecursive && !isBackgroundMessage && !isBundleMessage) return;

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
        const envelopeMessageId = isSealedEnvelope && typeof encryptedMessage?.messageId === 'string'
          ? encryptedMessage.messageId
          : null;
        if (envelopeMessageId) {
          const seenAt = processedEnvelopeIdsRef.current.get(envelopeMessageId);
          if (seenAt && (now - seenAt) < ENVELOPE_DEDUP_TTL_MS) {
            return;
          }
        }

        // Pre-decrypted background messages
        if (isBackgroundMessage) {
          const { _decryptedInBackground, _originalFrom, ...rest } = encryptedMessage;
          payload = rest;
          if (!payload.from && _originalFrom) payload.from = _originalFrom;
        }
        // Bundle delivery
        else if (isBundleMessage) {
          await processBundleDelivery(encryptedMessage, currentUser);
          return;
        }
        // Signal Protocol messages
        else if (encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE && encryptedMessage?.encryptedPayload) {
          if (!isRecursive && !isBackgroundMessage) return;

          // LibSignal decryption
          const senderUsername = encryptedMessage.from || '';
          const legacyMessageType = (encryptedMessage.encryptedPayload as any)?.messageType ?? (encryptedMessage.encryptedPayload as any)?.message_type;
          const isLegacyPreKey = legacyMessageType === 3;
          const directCipherKey = getSignalCiphertextKey(encryptedMessage.encryptedPayload);
          if (directCipherKey) {
            const seenAt = processedSignalCiphertextsRef.current.get(directCipherKey);
            if (seenAt && (now - seenAt) < ENVELOPE_DEDUP_TTL_MS) {
              return;
            }
            processedSignalCiphertextsRef.current.set(directCipherKey, now);
          }
          const decrypted = await signal.decrypt(
            senderUsername,
            currentUser,
            encryptedMessage.encryptedPayload
          );

          if (!decrypted?.success || typeof decrypted?.plaintext !== 'string') {
            const errMsg = String(decrypted?.error || '').toLowerCase();

            if (errMsg.includes('untrusted identity') && senderUsername) {
              await trustPeerIdentity(currentUser, senderUsername);
            }

            const isSessionError = /session|no valid sessions|no session|invalid whisper message|invalid prekey identifier|decryption failed|bad mac|message keys|counter/i.test(errMsg);
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
                RESET_WINDOW_MS,
                { resolvePeerInboxId }
              );
            }
            return;
          }

          if (isLegacyPreKey && senderUsername) {
            try {
              window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: senderUsername } }));
            } catch { }
          }

          payload = parseDecryptedPayload(decrypted.plaintext, senderUsername);

          // Unwrap signal-payload messages
          if (payload.type === 'signal-payload') {
            if (payload.content && typeof payload.content === 'string') {
              try {
                const inner = JSON.parse(payload.content);
                payload = { ...payload, ...inner };
              } catch { }
            }
            if (payload.kind) {
              payload.type = payload.kind;
            }
          }

          await processSenderBundle(payload, currentUser);
          replenishCallback().catch(() => { });
        }
        // Sealed envelope
        else if (isSealedEnvelope) {
          try {
            if (!currentUser || currentUser === 'unknown') {
              console.warn('[EncryptedMessageHandler] Cannot decrypt - current user not ready');
              return;
            }

            const sealedEnvelope = encryptedMessage.envelope || encryptedMessage.payload;
            if (!sealedEnvelope) return;

            const localKeys = await getKeysOnDemand?.();
            let hybridEnvelope: any = sealedEnvelope;
            let senderInboxId: string | null = null;
            let senderUsernameFromBlind: string | undefined;

            if (sealedEnvelope?.version === 'ss-v1') {
              try {
                if (localKeys?.kyber?.secretKey && localKeys?.kyber?.publicKeyBase64) {
                  const blindClient = getBlindRoutingClient();
                  blindClient.setKyberKeys({
                    publicKey: CryptoUtils.Base64.base64ToUint8Array(localKeys.kyber.publicKeyBase64),
                    secretKey: localKeys.kyber.secretKey
                  });

                  const opened = await blindClient.openSealedEnvelope(sealedEnvelope);
                  if (!opened) {
                    console.warn('[EncryptedMessageHandler] Failed to open blind-route envelope');
                    return;
                  }

                  senderUsernameFromBlind = opened.from;
                  senderInboxId = opened.fromInbox || null;
                  const innerPayload = opened.payload;
                  if (innerPayload?.type === COVER_TRAFFIC_PAYLOAD_TYPE) {
                    return;
                  }
                  hybridEnvelope = innerPayload?.envelope ?? innerPayload?.hybridEnvelope ?? innerPayload;
                }
              } catch (err) {
                console.warn('[EncryptedMessageHandler] Blind-route envelope open failed:', err);
                return;
              }
            }

            const senderDilithiumPublicKey = hybridEnvelope?.routing?.from;

            if (!localKeys?.kyber?.secretKey || !senderDilithiumPublicKey) {
              console.warn('[EncryptedMessageHandler] Missing keys for sealed-envelope decryption');
              return;
            }

            // Decrypt Hybrid envelope
            const decrypted = await CryptoUtils.Hybrid.decryptIncoming(
              hybridEnvelope,
              {
                kyberSecretKey: localKeys.kyber.secretKey,
                x25519SecretKey: localKeys.x25519.private,
                senderDilithiumPublicKey: senderDilithiumPublicKey
              },
              { expectJsonPayload: true }
            );

            if (!(decrypted?.payloadJson as any)?.signalCiphertext) {
              console.warn('[EncryptedMessageHandler] No signalCiphertext in decrypted envelope');
              return;
            }

            // Decrypt LibSignal message
            const signalPayload = (decrypted.payloadJson as any).signalCiphertext;
            const senderUsername = (decrypted.payloadJson as any).from ||
              senderUsernameFromBlind ||
              (encryptedMessage as any)?.from ||
              (usersRef?.current as any)?.find((u: any) =>
                u.hybridPublicKeys?.dilithiumPublicBase64 === senderDilithiumPublicKey
              )?.username;
            if (!senderInboxId && typeof (decrypted.payloadJson as any).fromInbox === 'string') {
              senderInboxId = (decrypted.payloadJson as any).fromInbox;
            }

            const messageType = (signalPayload as any)?.messageType ?? (signalPayload as any)?.message_type;
            const kemCiphertext = (signalPayload as any)?.pqEnvelope?.kemCiphertext ||
              (signalPayload as any)?.pq_envelope?.kem_ciphertext;
            const isPreKey = messageType === 3 && typeof kemCiphertext === 'string' && kemCiphertext.length > 0;
            let preKeyDedupKey: string | null = null;

            if (isPreKey && senderUsername) {
              preKeyDedupKey = `${senderUsername}:${kemCiphertext}`;
              if (processedPreKeyMessagesRef.current.has(preKeyDedupKey)) return;
            }

            const signalCipherKey = getSignalCiphertextKey(signalPayload);
            if (signalCipherKey) {
              const seenAt = processedSignalCiphertextsRef.current.get(signalCipherKey);
              if (seenAt && (now - seenAt) < ENVELOPE_DEDUP_TTL_MS) {
                return;
              }
              processedSignalCiphertextsRef.current.set(signalCipherKey, now);
            }

            const decryptedSignal = await signal.decrypt(
              senderUsername || 'unknown',
              currentUser,
              signalPayload
            );

            if (!decryptedSignal?.success || typeof decryptedSignal.plaintext !== 'string') {
              const errMsg = String(decryptedSignal?.error || '').toLowerCase();

              // Check for duplicate messages
              const isDuplicate = errMsg.includes('old counter') || errMsg.includes('duplicate');
              if (isDuplicate) return;

              if (errMsg.includes('untrusted identity') && senderUsername) {
                await trustPeerIdentity(currentUser, senderUsername);
              }

              const isSessionError = decryptedSignal?.requires_key_refresh ||
                /session|no valid sessions|no session|invalid whisper message|invalid prekey identifier|decryption failed|bad mac|message keys/i.test(errMsg);

              if (isSessionError && senderUsername && !isPreKey) {
                const retryMessage = (encryptedMessage && (encryptedMessage as any).encryptedPayload)
                  ? encryptedMessage
                  : { ...encryptedMessage, encryptedPayload: signalPayload };

                await handleSessionResetAndRetry(
                  senderUsername,
                  retryMessage,
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
                  RESET_WINDOW_MS,
                  { resolvePeerInboxId, senderInboxId }
                );
              }

              const messageId = typeof (signalPayload as any)?.messageId === 'string'
                ? (signalPayload as any).messageId
                : envelopeMessageId;
              console.warn('[EncryptedMessageHandler] LibSignal decryption failed', {
                from: senderUsername || senderUsernameFromBlind,
                messageId,
                messageType,
                isPreKey,
                kemCiphertextPrefix: typeof kemCiphertext === 'string' ? kemCiphertext.slice(0, 16) : null,
                error: decryptedSignal?.error || 'unknown'
              });
              return;
            }

            if (isPreKey && preKeyDedupKey) {
              processedPreKeyMessagesRef.current.set(preKeyDedupKey, Date.now());
              const nowTs = Date.now();
              for (const [key, timestamp] of processedPreKeyMessagesRef.current.entries()) {
                if (nowTs - timestamp > 60000) {
                  processedPreKeyMessagesRef.current.delete(key);
                }
              }
            }

            if (isPreKey && senderUsername) {
              try {
                window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: senderUsername } }));
              } catch { }
            }

            // Parse and process inner payload
            payload = parseDecryptedPayload(decryptedSignal.plaintext, senderUsername);

            // Unwrap signal-payload wrapper
            if (payload.type === 'signal-payload') {
              if (payload.content && typeof payload.content === 'string') {
                try {
                  const inner = JSON.parse(payload.content);
                  payload = { ...payload, ...inner };
                } catch { }
              }
              if (payload.kind) payload.type = payload.kind;
            }

            if (envelopeMessageId) {
              processedEnvelopeIdsRef.current.set(envelopeMessageId, Date.now());
            }

            if (isP2PTransport) {
              payload.p2p = true;
              payload.transport = 'p2p';
            }

            await processSenderBundle(payload, currentUser);
            replenishCallback().catch(() => { });
          } catch (err) {
            console.error('[EncryptedMessageHandler] Failed to decrypt sealed envelope:', err);
            return;
          }
        }
        else {
          return;
        }

        // Request sender keys if needed
        if (payload.from && payload.from !== currentUser) {
          const userExists = usersRef?.current?.find?.((u: any) => u.username === payload.from);
          const needsKeys = !userExists || !userExists.hybridPublicKeys || !userExists.hybridPublicKeys.kyberPublicBase64;
          if (needsKeys) {
            const lastReq = keyRequestCacheRef.current.get(payload.from);
            if (!lastReq || (now - lastReq) > KEY_REQUEST_CACHE_DURATION) {
              keyRequestCacheRef.current.set(payload.from, now);
              try { await requestBundleOnceCallback(payload.from, 'passive-discovery'); } catch { }
            }
          }
        }

        // Check blocking filter
        if (!await checkBlockingFilter(payload, currentUser, blockingSystem)) return;

        // Handle profile picture request/response messages
        if (
          payload?.type === 'profile-picture-request' ||
          payload?.type === 'profile-picture-response'
        ) {
          const fromUsername = payload?.from;
          if (typeof fromUsername === 'string' && fromUsername.length > 0) {
            try {
              await profilePictureSystem.handleIncomingMessage(payload, fromUsername);
            } catch (err) {
              console.warn('[EncryptedMessageHandler] Profile picture message handling failed', err);
            }
          }
          return;
        }

        // Handle receipts
        if (payload.type === SignalType.READ_RECEIPT && payload.messageId) {
          dispatchReadReceiptEvent(payload.messageId, payload.from);
          return;
        }
        if ((payload.type === SignalType.DELIVERY_RECEIPT || payload.type === SignalType.DELIVERY_ACK) && payload.messageId) {
          dispatchDeliveryReceiptEvent(payload.messageId, payload.from);
          return;
        }

        // Handle profile updates
        if (payload.type === SignalType.PROFILE_UPDATE && payload.from) {
          invalidateDiscoveryCache(payload.from);
          if (findUser) {
            const known = usersRef?.current?.map?.((u: any) => u.username).filter(Boolean) ?? [];
            if (shouldAttemptDiscovery(payload.from, known)) {
              findUser(payload.from).catch(err => console.warn('[EncryptedMessageHandler] Refetch failed after profile update', err));
            }
          }
          return;
        }

        // Handle P2P session reset requests
        if (payload.type === SignalType.SESSION_RESET_REQUEST) {
          try {
            window.dispatchEvent(new CustomEvent(EventType.P2P_SESSION_RESET_REQUEST, {
              detail: { from: payload.from, reason: payload.reason }
            }));
          } catch { }
          return;
        }

        // Handle file chunks
        if (payload.type === SignalType.FILE_MESSAGE_CHUNK) {
          let chunkPayload = payload;
          if (payload?.encryptedPayload && !payload?.chunkData) {
            try {
              const inner = await decryptSignalMessage(
                { encryptedPayload: payload.encryptedPayload, from: payload.from },
                currentUser,
                processedPreKeyMessagesRef
              );
              if (inner?.payload?.success && typeof inner.payload.plaintext === 'string') {
                const meta = parseDecryptedPayload(inner.payload.plaintext, payload.from);
                if (inner.attachedChunkData && !meta.chunkData) {
                  meta.chunkData = inner.attachedChunkData;
                }
                chunkPayload = meta;
              }
            } catch (err) {
              console.warn('[EncryptedMessageHandler] Failed to unwrap file chunk metadata', err);
            }
          }

          if (handleFileMessageChunk) {
            try {
              await handleFileMessageChunk(chunkPayload, { from: chunkPayload.from ?? payload.from, to: chunkPayload.to });
            } catch (_error) {
              console.error('[EncryptedMessageHandler] Failed to handle file chunk:', _error);
            }
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

          window.dispatchEvent(new CustomEvent('peer-interaction', { detail: { peer: payload.from } }));
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
            const { kyber, hybrid } = await resolveSenderHybridKeys(payload.from, usersRef as any, keyRequestCacheRef, loginUsernameRef, KEY_REQUEST_CACHE_DURATION, findUser);
            if (kyber && hybrid) {
              await sendEncryptedDeliveryReceipt(currentUser, payload.from, messageId, kyber, hybrid, failedDeliveryReceiptsRef);
            } else {
              // Queue for retry when keys become available
              const receiptKey = `${payload.from}:${messageId}`;
              failedDeliveryReceiptsRef.current.set(receiptKey, {
                messageId,
                peerUsername: payload.from,
                timestamp: Date.now(),
                attempts: 0
              });
            }
          }
        }

        // Handle file messages
        if (payload.type === SignalType.FILE_MESSAGE) {
          const { messageId, messageAdded } = await processFileMessage(payload, currentUser, setMessages, saveMessageToLocalDB, blobCacheRef.current, secureDBRef);
          if (messageAdded && messageId) {
            const { kyber, hybrid } = await resolveSenderHybridKeys(payload.from, usersRef as any, keyRequestCacheRef, loginUsernameRef, KEY_REQUEST_CACHE_DURATION, findUser);
            if (kyber && hybrid) {
              await sendEncryptedDeliveryReceipt(currentUser, payload.from, messageId, kyber, hybrid, failedDeliveryReceiptsRef);
            } else {
              // Queue for retry when keys become available
              const receiptKey = `${payload.from}:${messageId}`;
              failedDeliveryReceiptsRef.current.set(receiptKey, {
                messageId,
                peerUsername: payload.from,
                timestamp: Date.now(),
                attempts: 0
              });
            }
          }
        }

        // Handle call signals
        if (payload.type === EventType.CALL_SIGNAL) {
          handleCallSignal({ payload: { content: payload.content, from: payload.from } });
        }
      } catch (_error) {
        console.error('[EncryptedMessageHandler] Error processing encrypted message:', _error);
      }
    },
    [setMessages, saveMessageToLocalDB, isAuthenticated, getKeysOnDemand, usersRef, handleFileMessageChunk, replenishCallback, requestBundleOnceCallback, loginUsernameRef, secureDBRef, findUser, getSignalCiphertextKey]
  );

  useEffect(() => { callbackRef.current = handleEncryptedMessageCallback; }, [handleEncryptedMessageCallback]);

  return handleEncryptedMessageCallback;
}
