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
  COVER_TRAFFIC_PAYLOAD_TYPE,
  MAX_INBOUND_PROCESSING_QUEUE
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
import { unifiedSignalTransport } from "../../lib/transport/unified-signal-transport";
import { profilePictureSystem } from "../../lib/avatar/profile-picture-system";
import { shouldAttemptDiscovery } from "../../lib/utils/discovery-utils";

const ENVELOPE_DEDUP_TTL_MS = 5 * 60 * 1000;
const PROFILE_META_REFRESH_DISCOVERY_COOLDOWN_MS = 30 * 1000;

// Per-frame receive logging is extremely hot: the global-spool snapshot re-delivers
// hundreds–thousands of sealed envelopes per epoch, and serializing an object to the
// WebKitGTK console per frame is itself a major source of UI stutter. Flip to true only
// when actively tracing the receive path.
const VERBOSE_RECV = false;

// Cap for the "already trial-decapsulated, not ours" memo. Sized above the server spool
// message cap (plus byte-budget trimming) so the retained spool window is covered and any given
// sealed envelope is ML-KEM-decapsulated at most once.
const SEALED_DECAP_NEG_CACHE_MAX = 20000;

// Fast, non-cryptographic 53-bit string hash (cyrb53). Used only to build a compact dedup
// key over a sealed envelope's unique fields — a collision could at worst cause one
// redundant decap, and since we only ever cache NEGATIVE (not-ours) outcomes it can never
// drop or misroute a real message.
function cyrb53(str: string): string {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

// Cheap content key for a sealed envelope, computed WITHOUT any decryption. ephemeralKey
// is the per-message ML-KEM ciphertext (unique per envelope); combined with the nonce it
// uniquely identifies the exact bytes we would otherwise re-decapsulate.
function cheapEnvelopeKey(env: any): string | null {
  const eph = typeof env?.ephemeralKey === 'string' ? env.ephemeralKey : '';
  if (!eph) return null;
  const nonce = typeof env?.nonce === 'string' ? env.nonce : '';
  return cyrb53(`${eph}|${nonce}`);
}

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
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
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

  const sealedDecapNegCacheRef = useRef<Map<string, number>>(new Map());
  const kyberKeysSetRef = useRef<string | null>(null);
  const resetCooldownRef = useRef<Map<string, number>>(new Map());
  const profileMetaSeenRef = useRef<Map<string, { profileVersion: number; avatarHash: string | null }>>(new Map());
  const profileRefreshCooldownRef = useRef<Map<string, number>>(new Map());

  const requestBundleOnceCallback = useCallback(async (
    peerUsername: string,
    _reason?: string,
    options?: { force?: boolean; forceRefreshDiscovery?: boolean }
  ) => {
    await requestBundleOnce(
      peerUsername,
      keyRequestCacheRef,
      inFlightBundleRequestsRef,
      loginUsernameRef,
      findUser,
      options
    );
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
    const cachedInbox = existing?.peerCertificateFingerprint && existing?.identityRootFingerprint
      ? existing?.inboxId || existing?.hybridPublicKeys?.inboxId
      : null;
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
            hybridKeys: {
              ...material.publicKeys,
              inboxId: material.inboxId,
              routeId: material.routeId,
              mailboxLookupId: material.mailboxLookupId,
              bundleLookupId: material.bundleLookupId
            },
            inboxId: material.inboxId,
            routeId: material.routeId,
            mailboxLookupId: material.mailboxLookupId,
            bundleLookupId: material.bundleLookupId,
            peerCertificateFingerprint: material.peerCertificateFingerprint,
            identityRootFingerprint: material.identityRootFingerprint,
            identityBundleFingerprint: material.identityBundleFingerprint
          }
        }));
        return material.inboxId;
      }
    } catch { }
    return null;
  }, [usersRef, findUser]);

  const maybeRefreshPeerProfileFromMessage = useCallback((payload: any) => {
    if (!findUser || !payload) return;
    const sender = typeof payload.from === 'string' ? payload.from : '';
    if (!sender) return;

    const meta = payload.senderProfileMeta;
    if (!meta || typeof meta !== 'object') return;

    const incomingVersion = Number.isFinite(meta.profileVersion) ? Math.trunc(meta.profileVersion) : 0;
    const incomingAvatarHash = typeof meta.avatarHash === 'string' && meta.avatarHash.length > 0
      ? meta.avatarHash
      : null;

    const peerKey = sender.trim().toLowerCase();
    if (!peerKey) return;

    const previous = profileMetaSeenRef.current.get(peerKey);
    const previousVersion = previous?.profileVersion || 0;
    const previousHash = previous?.avatarHash ?? null;
    const versionAdvanced = incomingVersion > previousVersion;
    const hashChanged = incomingAvatarHash !== previousHash;

    profileMetaSeenRef.current.set(peerKey, {
      profileVersion: Math.max(previousVersion, incomingVersion),
      avatarHash: incomingAvatarHash
    });

    if (!versionAdvanced && !hashChanged) return;

    const localHash = profilePictureSystem.getPeerAvatarHash(sender);
    const avatarMismatch = incomingAvatarHash !== localHash;
    if (!versionAdvanced && !avatarMismatch) return;

    const now = Date.now();
    const cooldownUntil = profileRefreshCooldownRef.current.get(peerKey) || 0;
    if (now < cooldownUntil) return;
    profileRefreshCooldownRef.current.set(peerKey, now + PROFILE_META_REFRESH_DISCOVERY_COOLDOWN_MS);

    const known = usersRef?.current?.map?.((u: any) => u.username).filter(Boolean) ?? [];
    if (!shouldAttemptDiscovery(sender, known)) return;

    void findUser(sender, { forceRefresh: true }).catch(() => {
      console.warn('[EncryptedMessageHandler] Profile metadata-triggered discovery refresh failed');
    });
  }, [findUser, usersRef]);

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

        try { invalidateDiscoveryCache(from); } catch { }
        try { await requestBundleOnceCallback(from, EventType.P2P_SESSION_RESET, { force: true, forceRefreshDiscovery: true }); } catch { }
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
      if (rateState.count > config.max) {
        console.warn('[MSG-RECV] EncryptedMessageHandler DROP: rate limited', { count: rateState.count });
        return;
      }

      const isSealedEnvelope = encryptedMessage?.type === SignalType.SEALED_ENVELOPE;
      const isBundleMessage = encryptedMessage?.type === SignalType.LIBSIGNAL_DELIVER_BUNDLE;
      const isBackgroundMessage = encryptedMessage?._decryptedInBackground === true;
      const isRecursive = !!options.isRecursive || !!encryptedMessage?.__isRecursive;
      const isP2PTransport = (encryptedMessage as any)?.__transport === 'p2p';

      if (VERBOSE_RECV) console.log('[MSG-RECV] EncryptedMessageHandler enter', {
        type: encryptedMessage?.type, isSealedEnvelope, isBundleMessage, isBackgroundMessage,
        isRecursive, isP2PTransport, isAuthenticated,
        from: String(encryptedMessage?.from || '').slice(0, 24)
      });

      if (!isAuthenticated && !isBundleMessage && !isBackgroundMessage && !isSealedEnvelope && !isRecursive) {
        console.warn('[MSG-RECV] DROP: not authenticated and not an allowed type');
        return;
      }

      if (!isSealedEnvelope && !isRecursive && !isBackgroundMessage && !isBundleMessage) {
        console.warn('[MSG-RECV] DROP: unhandled message type', { type: encryptedMessage?.type });
        return;
      }

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
        const recoverUntrustedIdentity = async (peerUsername: string): Promise<boolean> => {
          if (!currentUser || !peerUsername) return false;
          await trustPeerIdentity(currentUser, peerUsername).catch(() => { });
          return true;
        };
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
          await processBundleDelivery(encryptedMessage, currentUser, usersRef?.current, findUser);
          return;
        }
        // Signal Protocol messages
        else if (encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE && encryptedMessage?.encryptedPayload) {
          if (!isRecursive && !isBackgroundMessage) return;

          // LibSignal decryption
          const senderUsername = encryptedMessage.from || '';
          const directCipherKey = getSignalCiphertextKey(encryptedMessage.encryptedPayload);
          if (directCipherKey) {
            const seenAt = processedSignalCiphertextsRef.current.get(directCipherKey);
            if (seenAt && (now - seenAt) < ENVELOPE_DEDUP_TTL_MS) {
              return;
            }
          }
          let decrypted = await signal.decrypt(
            senderUsername,
            currentUser,
            encryptedMessage.encryptedPayload
          );

          if (!decrypted?.success || typeof decrypted?.plaintext !== 'string') {
            let errMsg = String(decrypted?.error || '').toLowerCase();

            if (errMsg.includes('untrusted identity') && senderUsername) {
              const recovered = await recoverUntrustedIdentity(senderUsername);
              if (recovered) {
                decrypted = await signal.decrypt(
                  senderUsername,
                  currentUser,
                  encryptedMessage.encryptedPayload
                );
                errMsg = String(decrypted?.error || '').toLowerCase();
              }
            }

            if (!decrypted?.success || typeof decrypted?.plaintext !== 'string') {
              const isReplay = /old counter|duplicate/i.test(errMsg);
              if (isReplay) {
                return;
              }

              const isSessionError = decrypted?.requires_key_refresh ||
                /no.?session|no valid sessions|invalid prekey|invalid whisper message|mac verification|bad mac|ratchet|decryption failed/i.test(errMsg);
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
                  { 
                    resolvePeerInboxId,
                    forceRefreshDiscovery: true,
                    invalidateCache: invalidateDiscoveryCache
                  }
                );
              }
              return;
            }
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

          await processSenderBundle(payload, currentUser, usersRef?.current, findUser);
          if (directCipherKey) {
            processedSignalCiphertextsRef.current.set(directCipherKey, Date.now());
          }
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
            if (!sealedEnvelope) {
              console.warn('[MSG-RECV] DROP: sealed branch but no envelope/payload', { keys: Object.keys(encryptedMessage || {}).slice(0, 10) });
              return;
            }

            const localKeys = await getKeysOnDemand?.();
            let hybridEnvelope: any = sealedEnvelope;
            let senderInboxId: string | null = null;
            let senderUsernameFromBlind: string | undefined;

            // Install Kyber decryption keys once per key and reset trial decap memo if the key actually rotates
            const curKyberPub = typeof localKeys?.kyber?.publicKeyBase64 === 'string' ? localKeys.kyber.publicKeyBase64 : null;
            if (curKyberPub && localKeys?.kyber?.secretKey) {
              const bc = getBlindRoutingClient();
              if (kyberKeysSetRef.current !== curKyberPub || !bc.getLocalKyberPublicKey()) {
                bc.setKyberKeys({
                  publicKey: CryptoUtils.Base64.base64ToUint8Array(curKyberPub),
                  secretKey: localKeys.kyber.secretKey
                });
                
                if (kyberKeysSetRef.current !== curKyberPub) {
                  sealedDecapNegCacheRef.current.clear();
                }
                kyberKeysSetRef.current = curKyberPub;
              }
            }

            const sealedNegKey = sealedEnvelope?.version === 'ss-v1' ? cheapEnvelopeKey(sealedEnvelope) : null;
            if (sealedNegKey && sealedDecapNegCacheRef.current.has(sealedNegKey)) {
              return;
            }

            if (VERBOSE_RECV) console.log('[MSG-RECV] sealed branch', {
              version: sealedEnvelope?.version,
              hasKyberSecret: !!localKeys?.kyber?.secretKey,
              hasKyberPub: !!localKeys?.kyber?.publicKeyBase64,
              localKyberFp: typeof localKeys?.kyber?.publicKeyBase64 === 'string' ? localKeys.kyber.publicKeyBase64.slice(0, 18) : undefined,
              recipientHint: typeof sealedEnvelope?.recipientInboxId === 'string' ? sealedEnvelope.recipientInboxId.slice(0, 16) : undefined
            });

            if (sealedEnvelope?.version === 'ss-v1') {
              try {
                if (localKeys?.kyber?.secretKey && localKeys?.kyber?.publicKeyBase64) {
                  const blindClient = getBlindRoutingClient();

                  const opened = await blindClient.openSealedEnvelope(sealedEnvelope);
                  if (!opened) {
                    if (VERBOSE_RECV) console.warn('[MSG-RECV] openSealedEnvelope -> null (not ours / cover / wrong key)');
                    if (sealedNegKey) {
                      const negCache = sealedDecapNegCacheRef.current;
                      negCache.set(sealedNegKey, now);
                      if (negCache.size > SEALED_DECAP_NEG_CACHE_MAX) {
                        const oldest = negCache.keys().next().value;
                        if (oldest !== undefined) negCache.delete(oldest);
                      }
                    }
                    return;
                  }

                  senderUsernameFromBlind = opened.from;
                  senderInboxId = opened.fromInbox || null;
                  const innerPayload = opened.payload;
                  if (VERBOSE_RECV) console.log('[MSG-RECV] sealed OPENED', {
                    from: String(opened.from || '').slice(0, 24),
                    innerType: innerPayload?.type,
                    isCover: innerPayload?.type === COVER_TRAFFIC_PAYLOAD_TYPE
                  });
                  if (innerPayload?.type === COVER_TRAFFIC_PAYLOAD_TYPE) {
                    if (sealedNegKey) {
                      const negCache = sealedDecapNegCacheRef.current;
                      negCache.set(sealedNegKey, now);
                      if (negCache.size > SEALED_DECAP_NEG_CACHE_MAX) {
                        const oldest = negCache.keys().next().value;
                        if (oldest !== undefined) negCache.delete(oldest);
                      }
                    }
                    return;
                  }
                  hybridEnvelope = innerPayload?.envelope ?? innerPayload?.hybridEnvelope ?? innerPayload;
                } else {
                  console.warn('[MSG-RECV] DROP: ss-v1 but local kyber keys not available');
                }
              } catch (err) {
                console.warn('[MSG-RECV] Blind-route envelope open FAILED', { error: (err as Error)?.message || String(err) });
                return;
              }
            }

            const senderDilithiumPublicKey = hybridEnvelope?.routing?.from;

            const verifiedP2PSender = isP2PTransport
              ? (encryptedMessage as any)?.__p2pVerifiedSender
              : null;
            const hasVerifiedP2PSender = !!verifiedP2PSender &&
              typeof verifiedP2PSender.username === 'string' &&
              typeof verifiedP2PSender.dilithiumBase64 === 'string';

            const senderUsernameHint = senderUsernameFromBlind ||
              (hasVerifiedP2PSender ? verifiedP2PSender.username : undefined) ||
              (typeof (encryptedMessage as any)?.from === 'string' ? (encryptedMessage as any).from : undefined);

            if (!localKeys?.kyber?.secretKey || !senderDilithiumPublicKey) {
              console.warn('[EncryptedMessageHandler] Missing keys for sealed-envelope decryption');
              return;
            }

            let senderIdentity: { usernameHint?: string; expectedDilithium?: string | null };
            if (hasVerifiedP2PSender) {
              // pinned from the PQ-Noise handshake
              senderIdentity = {
                usernameHint: verifiedP2PSender.username as string,
                expectedDilithium: verifiedP2PSender.dilithiumBase64 as string
              };
              console.log('[MSG-RECV] P2P sender pinned from handshake identity', {
                from: String(verifiedP2PSender.username).slice(0, 24),
                envelopeMatchesHandshake: senderIdentity.expectedDilithium === senderDilithiumPublicKey
              });
            } else {
              // Fast lookup for an already-pinned contact
              const locallyPinned = (usersRef?.current || []).find((u: any) =>
                u?.username === senderUsernameHint &&
                u?.peerCertificateFingerprint &&
                u?.identityRootFingerprint &&
                u?.hybridPublicKeys?.dilithiumPublicBase64
              );
              if (locallyPinned?.hybridPublicKeys?.dilithiumPublicBase64) {
                senderIdentity = {
                  usernameHint: senderUsernameHint,
                  expectedDilithium: locallyPinned.hybridPublicKeys.dilithiumPublicBase64
                };
              } else if (senderUsernameHint && senderDilithiumPublicKey) {
                // First contact tofu
                senderIdentity = { usernameHint: senderUsernameHint, expectedDilithium: senderDilithiumPublicKey };
                console.log('[MSG-RECV] TOFU sender pin (first contact)', { from: String(senderUsernameHint).slice(0, 24) });
              } else {
                senderIdentity = { usernameHint: undefined, expectedDilithium: null };
              }
            }

            if (!senderIdentity.usernameHint || !senderIdentity.expectedDilithium) {
              console.warn('[EncryptedMessageHandler] Rejecting sealed envelope without pinned sender identity');
              return;
            }

            if (senderIdentity.expectedDilithium !== senderDilithiumPublicKey) {
              console.warn('[EncryptedMessageHandler] Rejecting sealed envelope due to sender key mismatch');
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
            const senderUsername = senderIdentity.usernameHint;
            const outerSenderHint = (decrypted.payloadJson as any).from ||
              senderUsernameFromBlind ||
              (encryptedMessage as any)?.from;
            if (
              outerSenderHint &&
              senderUsername &&
              outerSenderHint !== senderUsername
            ) {
              console.warn('[EncryptedMessageHandler] Rejecting sealed envelope due to outer sender hint mismatch');
              return;
            }
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
            }

            let decryptedSignal = await signal.decrypt(
              senderUsername,
              currentUser,
              signalPayload
            );

            if (!decryptedSignal?.success || typeof decryptedSignal.plaintext !== 'string') {
              let errMsg = String(decryptedSignal?.error || '').toLowerCase();

              // Check for duplicate messages
              const isDuplicate = errMsg.includes('old counter') || errMsg.includes('duplicate');
              if (isDuplicate) return;

              if (errMsg.includes('untrusted identity') && senderUsername) {
                const recovered = await recoverUntrustedIdentity(senderUsername);
                if (recovered) {
                  decryptedSignal = await signal.decrypt(
                    senderUsername,
                    currentUser,
                    signalPayload
                  );
                  errMsg = String(decryptedSignal?.error || '').toLowerCase();
                }
              }

              if (!decryptedSignal?.success || typeof decryptedSignal.plaintext !== 'string') {
                const isReplay = /old counter|duplicate/i.test(errMsg);
                if (isReplay) {
                  return;
                }

                const isSessionError = decryptedSignal?.requires_key_refresh ||
                  /no.?session|no valid sessions|invalid prekey|invalid whisper message|mac verification|bad mac|ratchet|decryption failed/i.test(errMsg);

                if (isSessionError && senderUsername) {
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
                    { 
                      resolvePeerInboxId, 
                      senderInboxId,
                      forceRefreshDiscovery: true,
                      invalidateCache: invalidateDiscoveryCache
                    }
                  );
                }

                const messageId = typeof (signalPayload as any)?.messageId === 'string'
                  ? (signalPayload as any).messageId
                  : envelopeMessageId;
                console.warn('[EncryptedMessageHandler] LibSignal decryption failed', {
                  hasMessageId: !!messageId,
                  messageType,
                  isPreKey,
                  hasKemCiphertext: typeof kemCiphertext === 'string',
                  hasError: !!decryptedSignal?.error
                });
                return;
              }
            }

            console.log('[MSG-RECV] libsignal decrypt OK (sealed)', {
              from: String(senderUsername).slice(0, 24), isPreKey,
              plaintextLen: decryptedSignal.plaintext.length
            });

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
            console.log('[MSG-RECV] payload parsed', {
              type: payload?.type, from: String(payload?.from || senderUsername).slice(0, 24),
              hasContent: payload?.content != null
            });
            if (payload?.from && payload.from !== senderUsername) {
              console.warn('[EncryptedMessageHandler] Rejecting decrypted Signal payload due to sender mismatch');
              return;
            }

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

            await processSenderBundle(payload, currentUser, usersRef?.current, findUser);
            if (signalCipherKey) {
              processedSignalCiphertextsRef.current.set(signalCipherKey, Date.now());
            }
            replenishCallback().catch(() => { });
          } catch {
        console.error('[EncryptedMessageHandler] Failed to decrypt sealed envelope');
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
        maybeRefreshPeerProfileFromMessage(payload);

        // Handle profile picture request/response messages
        if (
          payload?.type === 'profile-picture-request' ||
          payload?.type === 'profile-picture-response'
        ) {
          const fromUsername = payload?.from;
          if (typeof fromUsername === 'string' && fromUsername.length > 0) {
            try {
              await profilePictureSystem.handleIncomingMessage(payload, fromUsername);
            } catch {
              console.warn('[EncryptedMessageHandler] Profile picture message handling failed');
            }
          }
          return;
        }

        // Handle receipts
        // Batched receipts
        if (payload.type === SignalType.RECEIPT_BATCH || payload.kind === SignalType.RECEIPT_BATCH) {
          const deliveredIds = Array.isArray(payload.deliveredIds) ? payload.deliveredIds : [];
          const readIds = Array.isArray(payload.readIds) ? payload.readIds : [];
          for (const id of deliveredIds) {
            if (typeof id === 'string' && id) { unifiedSignalTransport.markDelivered(id); dispatchDeliveryReceiptEvent(id, payload.from); }
          }
          for (const id of readIds) {
            if (typeof id === 'string' && id) { unifiedSignalTransport.markDelivered(id); dispatchReadReceiptEvent(id, payload.from); }
          }
          return;
        }
        if (payload.type === SignalType.READ_RECEIPT && payload.messageId) {
          unifiedSignalTransport.markDelivered(payload.messageId);
          dispatchReadReceiptEvent(payload.messageId, payload.from);
          return;
        }
        if ((payload.type === SignalType.DELIVERY_RECEIPT || payload.type === SignalType.DELIVERY_ACK) && payload.messageId) {
          unifiedSignalTransport.markDelivered(payload.messageId);
          dispatchDeliveryReceiptEvent(payload.messageId, payload.from);
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
            } catch {
              console.warn('[EncryptedMessageHandler] Failed to unwrap file chunk metadata');
            }
          }

          if (handleFileMessageChunk) {
            try {
              await handleFileMessageChunk(chunkPayload, { from: chunkPayload.from ?? payload.from, to: chunkPayload.to });
            } catch {
              console.error('[EncryptedMessageHandler] Failed to handle file chunk');
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
          console.log('[MSG-RECV] processTextMessage (-> UI)', {
            from: String(payload.from).slice(0, 24), type: payload.type
          });
          const { messageId, messageAdded } = await processTextMessage(payload, currentUser, setMessages, saveMessageToLocalDB);
          console.log('[MSG-RECV] processTextMessage result', { messageId, messageAdded });
          if (messageAdded && messageId) {
            // The receipt batcher resolves routing/session material itself
            void sendEncryptedDeliveryReceipt(currentUser, payload.from, messageId, null, null, failedDeliveryReceiptsRef).catch(() => { });
          }
        }

        // Handle file messages
        if (payload.type === SignalType.FILE_MESSAGE) {
          const { messageId, messageAdded } = await processFileMessage(payload, currentUser, setMessages, saveMessageToLocalDB, blobCacheRef.current, secureDBRef);
          if (messageAdded && messageId) {
            void sendEncryptedDeliveryReceipt(currentUser, payload.from, messageId, null, null, failedDeliveryReceiptsRef).catch(() => { });
          }
        }
        if (payload.type === EventType.CALL_SIGNAL || payload.kind === EventType.CALL_SIGNAL) {
          handleCallSignal({ payload: { content: payload.content, from: payload.from } });
        }
      } catch {
        console.error('[EncryptedMessageHandler] Error processing encrypted message');
      }
    },
    [setMessages, saveMessageToLocalDB, isAuthenticated, getKeysOnDemand, usersRef, handleFileMessageChunk, replenishCallback, requestBundleOnceCallback, loginUsernameRef, secureDBRef, findUser, getSignalCiphertextKey]
  );

  // FIFO serialization of incoming messages
  const processingChainRef = useRef<Promise<void>>(Promise.resolve());
  const processingDepthRef = useRef(0);
  const serializedEncryptedMessageHandler = useCallback(
    (encryptedMessage: any, options: { isRecursive?: boolean } = {}): Promise<void> => {
      const bypassQueue =
        !!options.isRecursive ||
        !!encryptedMessage?.__isRecursive ||
        encryptedMessage?._decryptedInBackground === true;
      if (bypassQueue) {
        return handleEncryptedMessageCallback(encryptedMessage, options);
      }
      // Backpressure: the FIFO chain pins each queued payload in memory until it is
      // drained. Bound the backlog so a flood that slips past the upstream P2P rate
      // limiter (a modified peer) or arrives over the server/WS path can't grow the
      // chain without limit and OOM the receiver. Dropped messages are recoverable:
      // P2P ones are spooled to the server by the sender, server ones stay in the
      // spool for the next catch-up poll.
      if (processingDepthRef.current >= MAX_INBOUND_PROCESSING_QUEUE) {
        console.warn('[EncryptedMessageHandler] inbound processing queue saturated, dropping message', {
          depth: processingDepthRef.current
        });
        return Promise.resolve();
      }
      processingDepthRef.current++;
      const run = processingChainRef.current
        .catch(() => { })
        .then(() => handleEncryptedMessageCallback(encryptedMessage, options));
      processingChainRef.current = run.catch(() => { });
      void run.finally(() => { processingDepthRef.current--; }).catch(() => { });
      return run;
    },
    [handleEncryptedMessageCallback]
  );

  useEffect(() => { callbackRef.current = handleEncryptedMessageCallback; }, [handleEncryptedMessageCallback]);

  return serializedEncryptedMessageHandler;
}
