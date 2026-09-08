import React, { useCallback, useEffect, useRef } from "react";
import { SignalType } from "../../lib/types/signal-types";
import websocketClient from "../../lib/websocket/websocket";
import { invalidateDiscoveryCache } from "../discovery/useDiscovery";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { EventType } from "../../lib/types/event-types";
import { Message } from "../../components/chat/messaging/types";
import type { User } from "../../components/chat/messaging/UserList";
import { blockingSystem } from "../../lib/blocking/blocking-system";
import {
  dispatchAuthenticatedCallSignal,
  parseAuthenticatedCallSignal,
} from "../../lib/types/message-handler-types";
import { requestBundleOnce } from "./keys";
import { hasExactKeys, hasPrototypePollutionKeys, isPlainObject, sanitizeMessageId } from "../../lib/sanitizers";
import { processTextMessage, checkBlockingFilter, getMessageType } from "./message-processing";
import type { ResetCounterEntry } from "../../lib/types/message-handling-types";
import {
  KEY_REQUEST_CACHE_DURATION,
  MAX_RESETS_PER_PEER,
  RESET_WINDOW_MS,
  MAX_INBOUND_PROCESSING_QUEUE,
  MAX_RECEIPT_BATCH_IDS,
  MAX_RETRANSMIT_CHUNKS_PER_REQUEST,
  AUTH_USERNAME_REGEX,
  MESSAGE_RATE_LIMIT_WINDOW_MS,
  MESSAGE_RATE_LIMIT_MAX,
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
  parseDecryptedPayload
} from "./decryption";
import { createBoundedMapSetter } from "../../lib/utils/message-state-limits";
import { signal } from "../../lib/tauri-bindings";
import {
  clearPersistedPeerEndpoint,
  savePersistedPeerEndpoint,
} from "../../lib/p2p/persisted-peer-cert";
import { PROTOCOL_KEYS } from '../../lib/config/protocol-keys';
import { getBlindRoutingClient } from "../../lib/transport/blind-routing-client";
import {
  isAckTrackedSignalType,
  unifiedSignalTransport,
} from "../../lib/transport/unified-signal-transport";
import { p2pTransport } from "../../lib/transport/p2p-transport";
import { normalizeP2PEndpointUrl } from "../../lib/utils/p2p-endpoint";
import { identityChangeStore } from "../../lib/security/identity-change-store";
import { blake3 } from '@noble/hashes/blake3.js';
import { isPostQuantumWorkerInfrastructureError } from '../../lib/cryptography/worker-bridge';
import { deliveryReceiptOutbox } from '../../lib/signals/delivery-receipt-outbox';
import { isPlausibleControlOperationId } from '../../lib/messages/message-controls';
import { keyTransparencyClient } from '../../lib/key-transparency/client';
import {
  captureKeyTransparencyPeerAuthorization,
  isKeyTransparencyPeerAuthorizationCurrent,
  isKeyTransparencyPeerRevoked,
  type KeyTransparencyPeerAuthorization,
} from '../../lib/key-transparency/verified-material';
import { awaitPeerIdentityRevocation } from '../../lib/key-transparency/revocation';
import { resolveTrustedPeerHybridPublicKeys } from '../../lib/utils/signal-bundle-utils';
import { detectionTagForProbe } from '../../lib/spool/detection-key';
import { loadConsumedSpoolProbeCache } from '../../lib/spool/consumed-probe-cache';

const P2P_SESSION_RESET_COOLDOWN_MS = 10 * 1000;
const SEALED_DECAP_NEG_CACHE_MAX = 20000;
const MESSAGE_DEDUP_CACHE_MAX = 20000;
const PENDING_CONTROL_MAX_ENTRIES = 64;
const PENDING_CONTROL_MAX_ATTEMPTS = 3;
const PENDING_CONTROL_MAX_AGE_MS = 2 * 60 * 1000;
const PENDING_CONTROL_ATTEMPT_INTERVAL_MS = 30 * 1000;
const PENDING_CONTROL_TERMINAL_MAX_ENTRIES = 512;
const FIRST_CONTACT_VERIFY_MAX_ENTRIES = 64;
const FIRST_CONTACT_VERIFY_MAX_ATTEMPTS = 3;
const FIRST_CONTACT_VERIFY_MAX_AGE_MS = 2 * 60 * 1000;
const FIRST_CONTACT_DISCOVERY_BUDGET_MAX = 4;
const FIRST_CONTACT_DISCOVERY_BUDGET_WINDOW_MS = 60 * 1000;
const SENDER_VERIFY_INLINE_WAIT_MS = 5 * 1000;
const SENDER_VERIFY_PARK_MAX_SENDERS = 16;
const SENDER_VERIFY_PARK_MAX_PER_SENDER = 32;
const SENDER_VERIFY_PARK_MAX_KEYS = 512;
const SENDER_VERIFY_PARK_MAX_BYTES = 8 * 1024 * 1024;
const SENDER_VERIFY_PARK_MAX_PARKS = 3;
const SENDER_VERIFY_PARK_RETRY_DELAY_MS = 20 * 1000;
const PREKEY_IDENTITY_VERIFY_RETRY_MS = 30 * 1000;
const NATIVE_PENDING_RECOVERY_MIN_RETRY_MS = 3 * 1000;
const NATIVE_PENDING_RECOVERY_MAX_RETRY_MS = 5 * 60 * 1000;
const SIGNAL_TYPE_VALUES: ReadonlySet<string> = new Set(Object.values(SignalType));

type ReplayDeliveryReceipt = Readonly<{
  peerUsername: string;
  messageId: string;
}>;

type ProcessedDedupEntry = Readonly<{
  processedAt: number;
  deliveryReceipt: ReplayDeliveryReceipt | null;
}>;

const setBoundedDedupEntry = createBoundedMapSetter(MESSAGE_DEDUP_CACHE_MAX);
const setBoundedPeerEntry = createBoundedMapSetter(512);

function rememberBoundedKey(cache: Set<string>, key: string, maxEntries: number): void {
  cache.delete(key);
  while (cache.size >= maxEntries) {
    const oldest = cache.values().next().value;
    if (typeof oldest !== 'string') break;
    cache.delete(oldest);
  }
  cache.add(key);
}

function rememberTerminalSealedEnvelope(cache: Set<string>, key: string): void {
  rememberBoundedKey(cache, key, SEALED_DECAP_NEG_CACHE_MAX);
}

function computeSealedEnvelopeCacheKey(env: any): string | null {
  const version = env?.version === PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL ? env.version : '';
  const eph = typeof env?.ephemeralKey === 'string' ? env.ephemeralKey : '';
  const nonce = typeof env?.nonce === 'string' ? env.nonce : '';
  const ciphertext = typeof env?.ciphertext === 'string' ? env.ciphertext : '';
  if (!version || !eph || !nonce || !ciphertext) return null;

  const encoder = new TextEncoder();
  const hasher = blake3.create({ dkLen: 16 });
  hasher.update(encoder.encode(PROTOCOL_KEYS.SEALED_ENVELOPE_CACHE));
  hasher.update(encoder.encode(version));
  hasher.update(new Uint8Array([0]));
  hasher.update(encoder.encode(eph));
  hasher.update(new Uint8Array([0]));
  hasher.update(encoder.encode(nonce));
  hasher.update(new Uint8Array([0]));
  hasher.update(encoder.encode(ciphertext));
  const digest = hasher.digest();
  try {
    let hex = '';
    for (const byte of digest) hex += byte.toString(16).padStart(2, '0');
    return hex;
  } finally {
    digest.fill(0);
  }
}

function compactCiphertextKey(kind: string, value: string): string {
  const digest = blake3(
    new TextEncoder().encode(`${PROTOCOL_KEYS.SIGNAL_DEDUP}\0${kind}\0${value}`),
    { dkLen: 16 }
  );
  try {
    let hex = '';
    for (const byte of digest) hex += byte.toString(16).padStart(2, '0');
    return hex;
  } finally {
    digest.fill(0);
  }
}

export function useEncryptedMessageHandler(
  loginUsernameRef: React.RefObject<string>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  isAuthenticated: boolean,
  getKeysOnDemand: () => Promise<import('../../lib/types/auth-types').HybridKeys | null>,
  usersRef: React.RefObject<User[]>,
  handleFileMessageChunk: (data: any, meta: any) => Promise<boolean | void>,
  cancelIncomingFileTransfer: (from: string, fileId: string) => boolean,
  secureDBRef: React.RefObject<any | null>,
  findUser: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>,
  isDatabaseReady: boolean,
  activeConversationRef: React.RefObject<string | null>,
) {
  const rateStateRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });
  const rateConfigRef = useRef({
    windowMs: MESSAGE_RATE_LIMIT_WINDOW_MS,
    max: MESSAGE_RATE_LIMIT_MAX,
  });
  const keyRequestCacheRef = useRef<Map<string, number>>(new Map());
  const inFlightBundleRequestsRef = useRef<Map<string, Promise<void>>>(new Map());

  const mutatePersistedMessage = useCallback(async (
    peerUsername: string,
    messageId: string,
    mutator: (message: Message) => Message | null
  ): Promise<Message | null> => {
    const db = secureDBRef.current;
    if (!db || !isDatabaseReady) throw new Error('Secure database is not ready');
    const updated = await db.updateConversationMessage(peerUsername, messageId, mutator);
    if (secureDBRef.current !== db) throw new Error('Secure database account changed during mutation');
    return updated as Message | null;
  }, [secureDBRef, isDatabaseReady]);

  const loadPersistedMessage = useCallback(async (
    peerUsername: string,
    messageId: string
  ): Promise<Message | null> => {
    const db = secureDBRef.current;
    if (!db || !isDatabaseReady) throw new Error('Secure database is not ready');
    const stored = await db.loadConversationMessageById(peerUsername, messageId);
    if (secureDBRef.current !== db) throw new Error('Secure database account changed during lookup');
    if (!stored) return null;
    return {
      ...stored,
      timestamp: new Date(stored.timestamp),
    } as Message;
  }, [secureDBRef, isDatabaseReady]);

  const storePersistedMessage = useCallback(async (message: Message): Promise<{
    stored: boolean;
    existing: Message | null;
  }> => {
    const db = secureDBRef.current;
    if (!db || !isDatabaseReady) throw new Error('Secure database is not ready');
    const result = await db.storeMessageIfAbsent({
      ...message,
      timestamp: message.timestamp.getTime(),
    }, activeConversationRef.current || undefined);
    if (secureDBRef.current !== db) throw new Error('Secure database account changed during insert');
    return {
      stored: result.stored === true,
      existing: result.existing
        ? { ...result.existing, timestamp: new Date(result.existing.timestamp) } as Message
        : null,
    };
  }, [secureDBRef, isDatabaseReady, activeConversationRef]);
  const resetCounterRef = useRef<Map<string, ResetCounterEntry>>(new Map());
  
  const p2pResetCooldownRef = useRef<Map<string, number>>(new Map());
  const processedPreKeyMessagesRef = useRef<Map<string, ProcessedDedupEntry>>(new Map());
  const processedEnvelopeIdsRef = useRef<Map<string, ProcessedDedupEntry>>(new Map());
  const processedSignalCiphertextsRef = useRef<Map<string, ProcessedDedupEntry>>(new Map());
  const acknowledgedPendingDecryptsRef = useRef<Set<string>>(new Set());
  const signalDecryptRateRef = useRef<Map<string, { windowStart: number; count: number }>>(new Map());

  const sealedDecapNegCacheRef = useRef<Set<string>>(new Set());
  
  const loggedOwnKyberRef = useRef<boolean>(false);
  const kyberKeysSetRef = useRef<string | null>(null);
  const resetCooldownRef = useRef<Map<string, number>>(new Map());
  const pendingControlAttemptsRef = useRef<Map<string, { attempts: number; firstAt: number; lastAt: number }>>(new Map());
  const terminalPendingControlsRef = useRef<Set<string>>(new Set());
  const firstContactVerifyAttemptsRef = useRef<Map<string, { attempts: number; firstAt: number }>>(new Map());
  const preKeyIdentityVerifyAttemptsRef = useRef<Map<string, number>>(new Map());
  const verifiedPendingIdentityRef = useRef<Map<string, {
    senderIdentityKey: string;
    authorization: KeyTransparencyPeerAuthorization;
  }>>(new Map());
  const firstContactDiscoveryBudgetRef = useRef({ windowStart: 0, count: 0 });
  
  const senderVerifyParkRef = useRef<Map<string, {
    envelopes: Map<string, { envelope: any; bytes: number }>;
    replayScheduled: boolean;
  }>>(new Map());
  const senderVerifyParkBytesRef = useRef(0);
  
  const senderVerifyParkedKeysRef = useRef<Map<string, number>>(new Map());
  
  const replayEnqueueRef = useRef<((message: any) => Promise<boolean>) | null>(null);
  const accountGenerationRef = useRef(0);
  const activeAccountRef = useRef<string | null>(null);
  const processingChainRef = useRef<Promise<void>>(Promise.resolve());
  const processingDepthRef = useRef(0);

  // redrive every envelope held for `sender` now that its verification settled
  const releaseSenderVerificationPark = useCallback((sender: string): void => {
    const parked = senderVerifyParkRef.current.get(sender);
    senderVerifyParkRef.current.delete(sender);
    if (!parked) return;
    for (const held of parked.envelopes.values()) {
      senderVerifyParkBytesRef.current -= held.bytes;
    }
    if (senderVerifyParkBytesRef.current < 0) senderVerifyParkBytesRef.current = 0;
    const enqueue = replayEnqueueRef.current;
    if (!enqueue) return;
    const generation = accountGenerationRef.current;
    const held = [...parked.envelopes.values()];
    void (async () => {
      for (const entry of held) {
        if (generation !== accountGenerationRef.current) return;
        try {
          await enqueue(entry.envelope);
        } catch {}
      }
    })();
  }, []);

  // Hold one envelope until its senders verification settles
  const parkForSenderVerification = useCallback((
    sender: string,
    cacheKey: string | null,
    envelope: any,
    lookup: Promise<unknown> | null,
  ): boolean => {
    if (!cacheKey) return false;
    if ((senderVerifyParkedKeysRef.current.get(cacheKey) ?? 0) >= SENDER_VERIFY_PARK_MAX_PARKS) {
      return false;
    }
    let bytes = 0;
    try { bytes = JSON.stringify(envelope).length; } catch { return false; }
    if (bytes <= 0) return false;
    if (senderVerifyParkBytesRef.current + bytes > SENDER_VERIFY_PARK_MAX_BYTES) return false;
    let entry = senderVerifyParkRef.current.get(sender);
    if (!entry) {
      if (!lookup) return false;
      if (senderVerifyParkRef.current.size >= SENDER_VERIFY_PARK_MAX_SENDERS) return false;
      entry = { envelopes: new Map(), replayScheduled: false };
      senderVerifyParkRef.current.set(sender, entry);
    }
    if (entry.envelopes.size >= SENDER_VERIFY_PARK_MAX_PER_SENDER) return false;
    
    const parks = senderVerifyParkedKeysRef.current.get(cacheKey) ?? 0;
    senderVerifyParkedKeysRef.current.delete(cacheKey);
    while (senderVerifyParkedKeysRef.current.size >= SENDER_VERIFY_PARK_MAX_KEYS) {
      const oldest = senderVerifyParkedKeysRef.current.keys().next().value;
      if (typeof oldest !== 'string') break;
      senderVerifyParkedKeysRef.current.delete(oldest);
    }
    senderVerifyParkedKeysRef.current.set(cacheKey, parks + 1);
    entry.envelopes.set(cacheKey, { envelope, bytes });
    senderVerifyParkBytesRef.current += bytes;
    
    if (lookup && !entry.replayScheduled) {
      entry.replayScheduled = true;
      const generation = accountGenerationRef.current;
      void lookup.catch(() => null).then((settled) => {
        if (generation !== accountGenerationRef.current) return;
        const usable = !!(settled && (settled as { trust?: unknown }).trust);
        if (usable || websocketClient.isConnectedToServer()) {
          releaseSenderVerificationPark(sender);
          return;
        }
        setTimeout(() => {
          if (generation !== accountGenerationRef.current) return;
          releaseSenderVerificationPark(sender);
        }, SENDER_VERIFY_PARK_RETRY_DELAY_MS);
      });
    }
    return true;
  }, [releaseSenderVerificationPark]);

  const requestBundleOnceCallback = useCallback(async (
    peerUsername: string,
    _reason?: string,
    options?: { force?: boolean; forceRefreshDiscovery?: boolean }
  ) => {
    const account = loginUsernameRef.current || '';
    const generation = accountGenerationRef.current;
    const isCurrent = () => (
      !!account &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      loginUsernameRef.current === account
    );
    if (!isCurrent()) return;
    await requestBundleOnce(
      peerUsername,
      keyRequestCacheRef,
      inFlightBundleRequestsRef,
      findUser,
      { ...options, account, isCurrent }
    );
  }, [loginUsernameRef, findUser]);

  const requestAuthenticatedSessionReset = useCallback(async (
    peerUsername: string,
    failedMessageId: string,
    account: string,
    isCurrent: () => boolean,
  ): Promise<'sent' | 'retry' | 'terminal'> => {
    if (
      !isCurrent() ||
      peerUsername === account ||
      !AUTH_USERNAME_REGEX.test(peerUsername) ||
      sanitizeMessageId(failedMessageId) !== failedMessageId
    ) return 'terminal';

    const now = Date.now();
    const lastReset = resetCooldownRef.current.get(peerUsername) || 0;
    if (now - lastReset < 3000) return 'retry';

    const counter = resetCounterRef.current.get(peerUsername);
    if (
      counter &&
      now - counter.windowStart <= RESET_WINDOW_MS &&
      counter.count >= MAX_RESETS_PER_PEER
    ) return 'terminal';

    const nextCounter = !counter || now - counter.windowStart > RESET_WINDOW_MS
      ? { count: 1, windowStart: now }
      : { count: counter.count + 1, windowStart: counter.windowStart };
    setBoundedPeerEntry(resetCounterRef.current, peerUsername, nextCounter);
    setBoundedPeerEntry(resetCooldownRef.current, peerUsername, now);
    invalidateDiscoveryCache(peerUsername);

    try {
      await signal.deleteAllSessions(account, peerUsername);
      if (!isCurrent()) return 'retry';
      const result = await unifiedSignalTransport.send(
        peerUsername,
        { failedMessageId },
        SignalType.SESSION_RESET_REQUEST,
      );
      if (!isCurrent()) return 'retry';
      return result.success ? 'sent' : 'retry';
    } catch {
      return 'retry';
    }
  }, []);

  const getSignalCiphertextKey = useCallback((payload: any): string | null => {
    if (!payload || typeof payload !== 'object') return null;
    const kem = payload?.pqEnvelope?.kemCiphertext;
    if (typeof kem === 'string' && kem.length > 0) {
      return `kem:${compactCiphertextKey('kem', kem)}`;
    }
    const cipher = payload.ciphertext;
    if (typeof cipher === 'string' && cipher.length > 0) {
      return `ct:${compactCiphertextKey('ciphertext', cipher)}`;
    }
    return null;
  }, []);

  useEffect(() => {
    const account = isAuthenticated && loginUsernameRef.current
      ? loginUsernameRef.current
      : null;
    if (activeAccountRef.current === account) return;

    const previousAccount = activeAccountRef.current;
    activeAccountRef.current = account;
    accountGenerationRef.current += 1;
    rateStateRef.current = { windowStart: 0, count: 0 };
    keyRequestCacheRef.current.clear();
    inFlightBundleRequestsRef.current.clear();
    resetCounterRef.current.clear();
    p2pResetCooldownRef.current.clear();
    processedPreKeyMessagesRef.current.clear();
    processedEnvelopeIdsRef.current.clear();
    processedSignalCiphertextsRef.current.clear();
    acknowledgedPendingDecryptsRef.current.clear();
    signalDecryptRateRef.current.clear();
    sealedDecapNegCacheRef.current.clear();
    kyberKeysSetRef.current = null;
    resetCooldownRef.current.clear();
    pendingControlAttemptsRef.current.clear();
    terminalPendingControlsRef.current.clear();
    firstContactVerifyAttemptsRef.current.clear();
    preKeyIdentityVerifyAttemptsRef.current.clear();
    verifiedPendingIdentityRef.current.clear();
    firstContactDiscoveryBudgetRef.current = { windowStart: 0, count: 0 };
    senderVerifyParkRef.current.clear();
    senderVerifyParkBytesRef.current = 0;
    senderVerifyParkedKeysRef.current.clear();
    processingChainRef.current = Promise.resolve();
    processingDepthRef.current = 0;
    deliveryReceiptOutbox.setActiveAccount(account);
    if (previousAccount !== null) {
      identityChangeStore.clear();
    }
  }, [isAuthenticated, loginUsernameRef, loginUsernameRef.current]);

  // Cleanup intervals
  useEffect(() => {
    const cacheCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [username, timestamp] of keyRequestCacheRef.current.entries()) {
        if (now - timestamp > KEY_REQUEST_CACHE_DURATION) keyRequestCacheRef.current.delete(username);
      }
      for (const [peer, timestamp] of resetCooldownRef.current) {
        if (now - timestamp > RESET_WINDOW_MS) resetCooldownRef.current.delete(peer);
      }
      for (const [peer, counter] of resetCounterRef.current) {
        if (now - counter.windowStart > RESET_WINDOW_MS) resetCounterRef.current.delete(peer);
      }
      for (const [peer, timestamp] of p2pResetCooldownRef.current) {
        if (now - timestamp > RESET_WINDOW_MS) p2pResetCooldownRef.current.delete(peer);
      }
      for (const [envelopeKey, attempt] of firstContactVerifyAttemptsRef.current) {
        if (now - attempt.firstAt > FIRST_CONTACT_VERIFY_MAX_AGE_MS) {
          rememberTerminalSealedEnvelope(sealedDecapNegCacheRef.current, envelopeKey);
          firstContactVerifyAttemptsRef.current.delete(envelopeKey);
        }
      }
      for (const [controlKey, attempt] of pendingControlAttemptsRef.current) {
        if (now - attempt.firstAt > PENDING_CONTROL_MAX_AGE_MS) {
          pendingControlAttemptsRef.current.delete(controlKey);
          rememberBoundedKey(
            terminalPendingControlsRef.current,
            controlKey,
            PENDING_CONTROL_TERMINAL_MAX_ENTRIES,
          );
        }
      }
      for (const [candidate, attemptedAt] of preKeyIdentityVerifyAttemptsRef.current) {
        if (now - attemptedAt > PREKEY_IDENTITY_VERIFY_RETRY_MS * 4) {
          preKeyIdentityVerifyAttemptsRef.current.delete(candidate);
        }
      }
    }, 10000);

    return () => {
      clearInterval(cacheCleanupInterval);
      keyRequestCacheRef.current.clear();
      processedEnvelopeIdsRef.current.clear();
      processedSignalCiphertextsRef.current.clear();
    };
  }, []);

  // P2P session reset control
  useEffect(() => {
    const onP2PSessionResetReq = async (evt: Event) => {
      try {
        const detail = (evt as CustomEvent).detail;
        if (
          !isPlainObject(detail) ||
          hasPrototypePollutionKeys(detail) ||
          !hasExactKeys(detail, ['account', 'failedMessageId', 'from'])
        ) return;
        const from = detail.from;
        const failedMessageId = sanitizeMessageId(detail.failedMessageId);
        const account = loginUsernameRef.current || '';
        const generation = accountGenerationRef.current;
        const isCurrent = () => (
          !!account &&
          generation === accountGenerationRef.current &&
          activeAccountRef.current === account &&
          loginUsernameRef.current === account
        );
        if (
          typeof from !== 'string' ||
          detail.account !== account ||
          from !== from.trim().toLowerCase() ||
          !AUTH_USERNAME_REGEX.test(from) ||
          !failedMessageId ||
          !isCurrent()
        ) return;

        const nowTs = Date.now();
        const lastReset = p2pResetCooldownRef.current.get(from) || 0;
        const refreshSession = nowTs - lastReset >= P2P_SESSION_RESET_COOLDOWN_MS;
        if (refreshSession) {
          setBoundedPeerEntry(p2pResetCooldownRef.current, from, nowTs);
          try { await signal.deleteAllSessions(account, from); } catch { }
          if (!isCurrent()) return;
        }

        try {
          window.dispatchEvent(new CustomEvent(EventType.SESSION_RESET_RECEIVED, {
            detail: { peerUsername: from, account, failedMessageId }
          }));
        } catch { }

        if (refreshSession) {
          try { invalidateDiscoveryCache(from); } catch { }
          try {
            await requestBundleOnceCallback(from, EventType.P2P_SESSION_RESET, {
              force: true,
              forceRefreshDiscovery: true
            });
          } catch { }
        }
      } catch { }
    };

    window.addEventListener(EventType.P2P_SESSION_RESET_REQUEST, onP2PSessionResetReq as EventListener);
    return () => window.removeEventListener(EventType.P2P_SESSION_RESET_REQUEST, onP2PSessionResetReq as EventListener);
  }, [loginUsernameRef, requestBundleOnceCallback]);

  const handleEncryptedMessageCallback = useCallback(
    async (
      encryptedMessage: any,
      options: {
        source?: 'external' | 'native-pending';
        __status?: {
          notReady: boolean;
          durablyStaged: boolean;
          authenticated: boolean;
          spoolTerminal: boolean;
        };
      } = {}
    ) => {
      const accountGeneration = accountGenerationRef.current;
      const currentUser = loginUsernameRef.current || '';
      let operationPeerAuthorization: {
        peer: string;
        authorization: KeyTransparencyPeerAuthorization;
      } | null = null;
      const now = Date.now();
      const isCurrentAccount = () => {
        if (
          !currentUser ||
          keyTransparencyClient.isSecurityIncidentActive() ||
          accountGeneration !== accountGenerationRef.current ||
          activeAccountRef.current !== currentUser ||
          loginUsernameRef.current !== currentUser
        ) return false;
        return !operationPeerAuthorization || isKeyTransparencyPeerAuthorizationCurrent(
          currentUser,
          operationPeerAuthorization.peer,
          operationPeerAuthorization.authorization,
        );
      };
      const abortIfStale = (): boolean => {
        if (isCurrentAccount()) return false;
        if (options.__status) options.__status.notReady = true;
        return true;
      };
      const requeueCachedDeliveryReceipt = async (
        receipt: ReplayDeliveryReceipt | null,
        onKnown?: () => void,
      ): Promise<boolean> => {
        if (!receipt) return true;
        try {
          const known = await deliveryReceiptOutbox.requeueKnownDelivery(
            currentUser,
            receipt.peerUsername,
            receipt.messageId,
          );
          if (abortIfStale()) return false;
          if (!known) {
            const queued = await deliveryReceiptOutbox.queueDelivery(
              currentUser,
              receipt.peerUsername,
              receipt.messageId,
            );
            if (!queued || abortIfStale()) {
              if (options.__status) options.__status.notReady = true;
              return false;
            }
          }
          onKnown?.();
          return true;
        } catch {
          if (options.__status) options.__status.notReady = true;
          return false;
        }
      };

      if (abortIfStale()) return;

      const isSealedEnvelope = encryptedMessage?.type === SignalType.SEALED_ENVELOPE;
      const candidateSealedEnvelope = isSealedEnvelope
        ? encryptedMessage?.envelope
        : null;
      if (candidateSealedEnvelope?.version === PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL) {
        const expectedDetectionTag = await detectionTagForProbe(
          currentUser,
          candidateSealedEnvelope.probe,
        );
        if (abortIfStale()) return;
        if (expectedDetectionTag === null) {
          if (options.__status) options.__status.notReady = true;
          return;
        }
        if (expectedDetectionTag !== candidateSealedEnvelope.tag) return;
      }
      const sealedEnvelopeCacheKey = candidateSealedEnvelope?.version === PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL
        ? computeSealedEnvelopeCacheKey(candidateSealedEnvelope)
        : null;

      if (sealedEnvelopeCacheKey && sealedDecapNegCacheRef.current.has(sealedEnvelopeCacheKey)) {
        return;
      }
      
      const envelopeMessageId = isSealedEnvelope
        ? sanitizeMessageId(encryptedMessage?.messageId)
        : null;
      const envelopeDedupKey = sealedEnvelopeCacheKey
        ? `sealed:${sealedEnvelopeCacheKey}`
        : (envelopeMessageId ? `id:${envelopeMessageId}` : null);
      if (envelopeDedupKey) {
        const processed = processedEnvelopeIdsRef.current.get(envelopeDedupKey);
        if (processed) {
          if (
            await requeueCachedDeliveryReceipt(processed.deliveryReceipt) &&
            options.__status
          ) {
            options.__status.authenticated = true;
            options.__status.spoolTerminal = true;
          }
          return;
        }
      }

      const rateState = rateStateRef.current;
      const config = rateConfigRef.current;
      if (now - rateState.windowStart > config.windowMs) { rateState.windowStart = now; rateState.count = 0; }
      rateState.count += 1;
      if (rateState.count > config.max) {
        console.warn('[MSG-RECV] EncryptedMessageHandler DROP: rate limited', { count: rateState.count });
        if (options.__status) options.__status.notReady = true;
        return;
      }

      const isNativePendingReplay = options.source === 'native-pending' &&
        encryptedMessage?.type === PROTOCOL_KEYS.NATIVE_PENDING_DECRYPT;
      const isP2PTransport = (encryptedMessage as any)?.__transport === 'p2p';
      const receiverObservedTransport: NonNullable<Message['transport']> = isP2PTransport
        ? 'p2p'
        : (isNativePendingReplay ? 'relay' : 'websocket');

      if (!isAuthenticated) {
        console.warn('[MSG-RECV] DROP: not authenticated');
        if (options.__status) options.__status.notReady = true;
        return;
      }

      if (!isSealedEnvelope && !isNativePendingReplay) {
        console.warn('[MSG-RECV] DROP: unhandled message type', { type: encryptedMessage?.type });
        return;
      }

      const nativePendingDecryptIds = new Set<string>();
      let nativePendingDecryptOwner: string | null = null;
      try {
        if (!isPlainObject(encryptedMessage) || hasPrototypePollutionKeys(encryptedMessage)) {
          console.error('[EncryptedMessageHandler] Invalid message type');
          return;
        }

        let payload: any;
        let authenticatedSignalCipherKey: string | null = null;
        let authenticatedPreKeyDedupKey: string | null = null;
        let authenticatedEnvelopeId: string | null = null;
        let authenticatedP2PEndpoint: string | null | undefined;
        let authenticatedP2PEndpointAt: number | null = null;
        let authenticatedTransportMessageId: string | null = null;
        let authenticatedApplicationType: SignalType | null = null;
        let authenticatedSenderUsername: string | null = null;
        let authenticatedSenderDilithiumPublicKey: string | null = null;
        let authenticatedReplayReceipt: ReplayDeliveryReceipt | null = null;
        let signalRatchetCommitted = false;
        let transportWrapperMessageId = isP2PTransport ? envelopeMessageId : null;
        const commitAuthenticatedMessage = () => {
          if (abortIfStale()) return;
          if (options.__status) {
            options.__status.authenticated = true;
            options.__status.spoolTerminal = true;
          }
          const entry: ProcessedDedupEntry = {
            processedAt: Date.now(),
            deliveryReceipt: authenticatedReplayReceipt,
          };
          if (authenticatedEnvelopeId) {
            setBoundedDedupEntry(processedEnvelopeIdsRef.current, authenticatedEnvelopeId, entry);
          }
          if (authenticatedSignalCipherKey) {
            setBoundedDedupEntry(processedSignalCiphertextsRef.current, authenticatedSignalCipherKey, entry);
          }
          if (authenticatedPreKeyDedupKey) {
            setBoundedDedupEntry(processedPreKeyMessagesRef.current, authenticatedPreKeyDedupKey, entry);
          }
        };
        const recoverKnownDeliveryReceipt = async (): Promise<boolean> => {
          if (
            !authenticatedTransportMessageId ||
            !authenticatedApplicationType ||
            !authenticatedSenderUsername ||
            !isAckTrackedSignalType(authenticatedApplicationType) ||
            authenticatedApplicationType === SignalType.FILE_MESSAGE_CHUNK
          ) return true;
          try {
            const receipt = {
              peerUsername: authenticatedSenderUsername,
              messageId: authenticatedTransportMessageId,
            };
            return requeueCachedDeliveryReceipt(
              receipt,
              () => { authenticatedReplayReceipt = receipt; },
            );
          } catch {
            if (options.__status) options.__status.notReady = true;
            return false;
          }
        };
        const queueDurableDeliveryReceipt = async (peerUsername: string, messageId: string): Promise<boolean> => {
          try {
            const queued = await deliveryReceiptOutbox.queueDelivery(
              currentUser,
              peerUsername,
              messageId
            );
            if (!queued || abortIfStale()) {
              if (options.__status) options.__status.notReady = true;
              return false;
            }
            authenticatedReplayReceipt = { peerUsername, messageId };
            return true;
          } catch {
            if (options.__status) options.__status.notReady = true;
            return false;
          }
        };
        const pendingControlKey = (): string | null => {
          const from = typeof payload?.from === 'string' ? payload.from : '';
          const id = sanitizeMessageId(payload?.messageId);
          const type = typeof payload?.type === 'string' ? payload.type : '';
          return from && id && type ? `${from}|${type}|${id}` : null;
        };
        const clearPendingControl = () => {
          const key = pendingControlKey();
          if (key) {
            pendingControlAttemptsRef.current.delete(key);
            terminalPendingControlsRef.current.delete(key);
          }
        };
        const deferPendingControl = (): boolean => {
          const key = pendingControlKey();
          if (!key) return false;
          if (terminalPendingControlsRef.current.has(key)) return false;
          const now = Date.now();
          const previous = pendingControlAttemptsRef.current.get(key);
          
          if (previous && now - previous.firstAt >= PENDING_CONTROL_MAX_AGE_MS) {
            pendingControlAttemptsRef.current.delete(key);
            rememberBoundedKey(
              terminalPendingControlsRef.current,
              key,
              PENDING_CONTROL_TERMINAL_MAX_ENTRIES,
            );
            return false;
          }
          const entry = previous
            ? {
                attempts: previous.attempts + (now - previous.lastAt >= PENDING_CONTROL_ATTEMPT_INTERVAL_MS ? 1 : 0),
                firstAt: previous.firstAt,
                lastAt: now - previous.lastAt >= PENDING_CONTROL_ATTEMPT_INTERVAL_MS ? now : previous.lastAt
              }
            : { attempts: 1, firstAt: now, lastAt: now };
          if (
            now - entry.firstAt >= PENDING_CONTROL_MAX_AGE_MS ||
            entry.attempts >= PENDING_CONTROL_MAX_ATTEMPTS
          ) {
            pendingControlAttemptsRef.current.delete(key);
            rememberBoundedKey(
              terminalPendingControlsRef.current,
              key,
              PENDING_CONTROL_TERMINAL_MAX_ENTRIES,
            );
            return false;
          }
          if (!pendingControlAttemptsRef.current.has(key) && pendingControlAttemptsRef.current.size >= PENDING_CONTROL_MAX_ENTRIES) {
            rememberBoundedKey(
              terminalPendingControlsRef.current,
              key,
              PENDING_CONTROL_TERMINAL_MAX_ENTRIES,
            );
            return false;
          }
          pendingControlAttemptsRef.current.set(key, entry);
          if (options.__status) options.__status.notReady = true;
          return true;
        };
        const clearFirstContactVerification = () => {
          if (sealedEnvelopeCacheKey) firstContactVerifyAttemptsRef.current.delete(sealedEnvelopeCacheKey);
        };
        const consumeFirstContactDiscoveryBudget = (): boolean => {
          const now = Date.now();
          const budget = firstContactDiscoveryBudgetRef.current;
          if (now - budget.windowStart >= FIRST_CONTACT_DISCOVERY_BUDGET_WINDOW_MS) {
            budget.windowStart = now;
            budget.count = 0;
          }
          if (budget.count >= FIRST_CONTACT_DISCOVERY_BUDGET_MAX) return false;
          budget.count += 1;
          return true;
        };

        const deferFirstContactVerification = (countsAsAttempt = true): boolean => {
          if (!sealedEnvelopeCacheKey) return false;
          const now = Date.now();
          const previous = firstContactVerifyAttemptsRef.current.get(sealedEnvelopeCacheKey);
          
          if (previous && now - previous.firstAt >= FIRST_CONTACT_VERIFY_MAX_AGE_MS) {
            firstContactVerifyAttemptsRef.current.delete(sealedEnvelopeCacheKey);
            rememberTerminalSealedEnvelope(sealedDecapNegCacheRef.current, sealedEnvelopeCacheKey);
            return false;
          }
          const entry = previous
            ? { attempts: previous.attempts + (countsAsAttempt ? 1 : 0), firstAt: previous.firstAt }
            : { attempts: countsAsAttempt ? 1 : 0, firstAt: now };
          if (
            now - entry.firstAt >= FIRST_CONTACT_VERIFY_MAX_AGE_MS ||
            entry.attempts >= FIRST_CONTACT_VERIFY_MAX_ATTEMPTS
          ) {
            firstContactVerifyAttemptsRef.current.delete(sealedEnvelopeCacheKey);
            rememberTerminalSealedEnvelope(sealedDecapNegCacheRef.current, sealedEnvelopeCacheKey);
            return false;
          }
          if (
            !previous &&
            firstContactVerifyAttemptsRef.current.size >= FIRST_CONTACT_VERIFY_MAX_ENTRIES
          ) {
            rememberTerminalSealedEnvelope(sealedDecapNegCacheRef.current, sealedEnvelopeCacheKey);
            return false;
          }
          firstContactVerifyAttemptsRef.current.set(sealedEnvelopeCacheKey, entry);
          if (options.__status) options.__status.notReady = true;
          return true;
        };

        // Signal decryption advances ratchet state
        if (
          (!secureDBRef.current || !isDatabaseReady) &&
          (isSealedEnvelope || isNativePendingReplay)
        ) {
          if (options.__status) options.__status.notReady = true;
          return;
        }

        const authorizeIncomingPreKeyIdentity = async (
          peerUsername: string,
          encryptedPayload: any,
        ): Promise<'allow' | 'pending' | 'reject'> => {
          if (!peerUsername) return 'pending';
          if (
            isKeyTransparencyPeerRevoked(currentUser, peerUsername) &&
            !await awaitPeerIdentityRevocation(currentUser, peerUsername)
          ) return 'pending';
          let presentedIdentity: string | null = null;
          try {
            presentedIdentity = await signal.peekPreKeyIdentity(
              peerUsername,
              currentUser,
              encryptedPayload,
            );
          } catch {
            return 'pending';
          }
          if (abortIfStale()) return 'pending';
          if (
            typeof presentedIdentity !== 'string' ||
            presentedIdentity.length !== 44 ||
            !/^[A-Za-z0-9+/]{44}$/.test(presentedIdentity)
          ) return 'reject';

          const deferVerification = (): 'pending' => {
            const chunkMarker = ':chunk:';
            const chunkMarkerAt = authenticatedTransportMessageId?.lastIndexOf(chunkMarker) ?? -1;
            const fileTransferId = authenticatedApplicationType === SignalType.FILE_MESSAGE_CHUNK &&
              authenticatedTransportMessageId &&
              chunkMarkerAt > 0
              ? sanitizeMessageId(authenticatedTransportMessageId.slice(0, chunkMarkerAt))
              : null;
            const displayDedupKey = authenticatedApplicationType === SignalType.FILE_MESSAGE_CHUNK
              ? (fileTransferId ? `file:${fileTransferId}` : null)
              : (authenticatedApplicationType &&
                isAckTrackedSignalType(authenticatedApplicationType) &&
                authenticatedTransportMessageId
                ? `${authenticatedApplicationType}:${authenticatedTransportMessageId}`
                : null);
            if (identityChangeStore.add(peerUsername, presentedIdentity!)) {
              identityChangeStore.hold(
                peerUsername,
                encryptedMessage,
                authenticatedTransportMessageId || sealedEnvelopeCacheKey,
                displayDedupKey,
              );
            }
            if (options.__status) options.__status.notReady = true;
            return 'pending';
          };
          const attemptKey = `${peerUsername}\0${presentedIdentity}`;
          const attemptedAt = preKeyIdentityVerifyAttemptsRef.current.get(attemptKey) || 0;
          const now = Date.now();
          if (now - attemptedAt < PREKEY_IDENTITY_VERIFY_RETRY_MS) {
            return deferVerification();
          }
          setBoundedPeerEntry(preKeyIdentityVerifyAttemptsRef.current, attemptKey, now);

          let material: any;
          let trusted: Awaited<ReturnType<typeof resolveTrustedPeerHybridPublicKeys>>;
          try {
            material = await findUser(peerUsername).catch(() => null);
            if (
              material &&
              (typeof material.fullBundle?.identityKeyBase64 !== 'string' ||
              material.fullBundle.identityKeyBase64 !== presentedIdentity
              )
            ) {
              material = await findUser(peerUsername, { forceRefresh: true });
            }
            if (abortIfStale()) return 'pending';
            if (!material) {
              return deferVerification();
            }
            trusted = await resolveTrustedPeerHybridPublicKeys(
              currentUser,
              peerUsername,
              material
            );
          } catch {
            return deferVerification();
          }
          if (abortIfStale()) return 'pending';
          if (!trusted.valid || !trusted.hybridKeys) {
            return deferVerification();
          }

          const expectedIdentity = typeof material?.fullBundle?.identityKeyBase64 === 'string'
            ? material.fullBundle.identityKeyBase64
            : '';
          if (expectedIdentity !== presentedIdentity) {
            preKeyIdentityVerifyAttemptsRef.current.delete(attemptKey);
            identityChangeStore.removeIfMatches(peerUsername, presentedIdentity);
            return 'reject';
          }

          try {
            await signal.installTransparencyVerifiedPeerIdentity(
              currentUser,
              peerUsername,
              presentedIdentity,
            );
          } catch {
            return deferVerification();
          }
          if (abortIfStale()) return 'pending';

          preKeyIdentityVerifyAttemptsRef.current.delete(attemptKey);
          window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
            detail: {
              account: currentUser,
              username: peerUsername,
              hybridKeys: trusted.hybridKeys,
              peerCertificateFingerprint: trusted.peerCertificateFingerprint,
              identityRootFingerprint: trusted.identityRootFingerprint,
              identityBundleFingerprint: trusted.identityBundleFingerprint,
            },
          }));
          if (identityChangeStore.matches(peerUsername, presentedIdentity)) {
            window.dispatchEvent(new CustomEvent(EventType.PEER_IDENTITY_REPLAY, {
              detail: { peer: peerUsername, account: currentUser, verifiedKey: presentedIdentity },
            }));
            identityChangeStore.removeIfMatches(peerUsername, presentedIdentity);
          }
          return 'allow';
        };

        if (isNativePendingReplay) {
          const keys = Object.keys(encryptedMessage);
          if (
            keys.length !== 9 ||
            !keys.every((key) => [
              'type', 'pendingId', 'from', 'senderIdentityKey',
              'identityRootFingerprint', 'identityBundleFingerprint',
              'transportMessageId', 'applicationType', 'plaintext'
            ].includes(key)) ||
            typeof encryptedMessage.pendingId !== 'string' ||
            encryptedMessage.pendingId.length !== 44 ||
            typeof encryptedMessage.from !== 'string' ||
            encryptedMessage.from !== encryptedMessage.from.trim().toLowerCase() ||
            !AUTH_USERNAME_REGEX.test(encryptedMessage.from) ||
            typeof encryptedMessage.senderIdentityKey !== 'string' ||
            encryptedMessage.senderIdentityKey.length !== 44 ||
            !/^[A-Za-z0-9+/]{44}$/.test(encryptedMessage.senderIdentityKey) ||
            typeof encryptedMessage.identityRootFingerprint !== 'string' ||
            !/^[a-f0-9]{64}$/.test(encryptedMessage.identityRootFingerprint) ||
            typeof encryptedMessage.identityBundleFingerprint !== 'string' ||
            !/^[a-f0-9]{64}$/.test(encryptedMessage.identityBundleFingerprint) ||
            sanitizeMessageId(encryptedMessage.transportMessageId) !== encryptedMessage.transportMessageId ||
            typeof encryptedMessage.applicationType !== 'string' ||
            !SIGNAL_TYPE_VALUES.has(encryptedMessage.applicationType) ||
            typeof encryptedMessage.plaintext !== 'string'
          ) {
            return;
          }
          nativePendingDecryptIds.add(encryptedMessage.pendingId);
          nativePendingDecryptOwner = currentUser;
          if (options.__status) options.__status.durablyStaged = true;
          const pendingPeer = encryptedMessage.from as string;
          let verifiedPending = verifiedPendingIdentityRef.current.get(pendingPeer);
          if (
            !verifiedPending ||
            verifiedPending.senderIdentityKey !== encryptedMessage.senderIdentityKey ||
            verifiedPending.authorization.identityRootFingerprint !== encryptedMessage.identityRootFingerprint ||
            verifiedPending.authorization.identityBundleFingerprint !== encryptedMessage.identityBundleFingerprint ||
            !isKeyTransparencyPeerAuthorizationCurrent(
              currentUser,
              pendingPeer,
              verifiedPending.authorization,
            )
          ) {
            verifiedPendingIdentityRef.current.delete(pendingPeer);
            const resolvePendingIdentity = async (forceRefresh: boolean) => {
              const material = await findUser(
                pendingPeer,
                forceRefresh ? { forceRefresh: true } : undefined,
              );
              if (abortIfStale()) return null;
              const trusted = await resolveTrustedPeerHybridPublicKeys(
                currentUser,
                pendingPeer,
                material,
              );
              const currentSignalIdentity = typeof material?.fullBundle?.identityKeyBase64 === 'string'
                ? material.fullBundle.identityKeyBase64
                : '';
              if (
                !trusted.valid ||
                !trusted.hybridKeys ||
                !trusted.peerCertificateFingerprint ||
                !trusted.identityRootFingerprint ||
                !trusted.identityBundleFingerprint ||
                !/^[A-Za-z0-9+/]{44}$/.test(currentSignalIdentity)
              ) {
                return null;
              }
              const authorization = captureKeyTransparencyPeerAuthorization(
                currentUser,
                pendingPeer,
                trusted.hybridKeys.dilithiumPublicBase64,
              );
              if (!authorization) return null;
              return { currentSignalIdentity, trusted, authorization };
            };
            let resolvedPendingIdentity;
            try {
              resolvedPendingIdentity = await resolvePendingIdentity(false);
              if (
                resolvedPendingIdentity && (
                resolvedPendingIdentity.currentSignalIdentity !== encryptedMessage.senderIdentityKey ||
                resolvedPendingIdentity.authorization.identityRootFingerprint !== encryptedMessage.identityRootFingerprint ||
                resolvedPendingIdentity.authorization.identityBundleFingerprint !== encryptedMessage.identityBundleFingerprint
                )
              ) {
                resolvedPendingIdentity = await resolvePendingIdentity(true);
              }
            } catch {
              if (options.__status) options.__status.notReady = true;
              return;
            }
            if (!resolvedPendingIdentity) {
              if (options.__status) options.__status.notReady = true;
              return;
            }
            const { currentSignalIdentity, trusted, authorization } = resolvedPendingIdentity;
            if (
              currentSignalIdentity !== encryptedMessage.senderIdentityKey ||
              authorization.identityRootFingerprint !== encryptedMessage.identityRootFingerprint ||
              authorization.identityBundleFingerprint !== encryptedMessage.identityBundleFingerprint
            ) {
              return;
            }
            try {
              const installed = await signal.installTransparencyVerifiedPeerIdentity(
                currentUser,
                pendingPeer,
                currentSignalIdentity,
              );
              if (!installed || abortIfStale()) {
                if (options.__status) options.__status.notReady = true;
                return;
              }
            } catch {
              if (options.__status) options.__status.notReady = true;
              return;
            }
            verifiedPending = {
              senderIdentityKey: currentSignalIdentity,
              authorization,
            };
            setBoundedPeerEntry(verifiedPendingIdentityRef.current, pendingPeer, verifiedPending);
            window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
              detail: {
                account: currentUser,
                username: pendingPeer,
                hybridKeys: trusted.hybridKeys,
                peerCertificateFingerprint: trusted.peerCertificateFingerprint,
                identityRootFingerprint: trusted.identityRootFingerprint,
                identityBundleFingerprint: trusted.identityBundleFingerprint,
              },
            }));
          }
          operationPeerAuthorization = {
            peer: pendingPeer,
            authorization: verifiedPending.authorization,
          };
          if (abortIfStale()) return;
          authenticatedTransportMessageId = encryptedMessage.transportMessageId;
          authenticatedApplicationType = encryptedMessage.applicationType as SignalType;
          authenticatedSenderUsername = encryptedMessage.from;
          payload = parseDecryptedPayload(encryptedMessage.plaintext, encryptedMessage.from);
          if (!payload || (payload.from && payload.from !== encryptedMessage.from)) return;
          if (
            payload.type !== authenticatedApplicationType ||
            (isAckTrackedSignalType(authenticatedApplicationType) &&
              sanitizeMessageId(payload.messageId) !== authenticatedTransportMessageId)
          ) return;
        }
        // Sealed envelope
        else if (isSealedEnvelope) {
          try {
            if (!currentUser || currentUser === 'unknown') {
              console.warn('[EncryptedMessageHandler] Cannot decrypt - current user not ready');
              return;
            }

            const sealedEnvelope: any = encryptedMessage.envelope;
            if (!sealedEnvelope) {
              console.warn('[MSG-RECV] DROP: sealed branch but no envelope', { keys: Object.keys(encryptedMessage || {}).slice(0, 10) });
              return;
            }

            const localKeys = await getKeysOnDemand();
            if (abortIfStale()) return;
            let hybridEnvelope: any = sealedEnvelope;
            let senderUsernameFromBlind: string | undefined;

            const curKyberPub = typeof localKeys?.kyber?.publicKeyBase64 === 'string' ? localKeys.kyber.publicKeyBase64 : null;
            if (curKyberPub && kyberKeysSetRef.current !== curKyberPub) {
              sealedDecapNegCacheRef.current.clear();
              kyberKeysSetRef.current = curKyberPub;
            }

            const sealedNegKey = sealedEnvelopeCacheKey;
            if (sealedNegKey && sealedDecapNegCacheRef.current.has(sealedNegKey)) {
              return;
            }


            if (sealedEnvelope?.version === PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL) {
              try {
                if (localKeys?.native === true && localKeys?.kyber?.publicKeyBase64) {
                  const blindClient = getBlindRoutingClient();
                  if (!loggedOwnKyberRef.current) {
                    loggedOwnKyberRef.current = true;
                  }

                  const opened = await blindClient.openSealedEnvelope(sealedEnvelope);
                  if (abortIfStale()) return;
                  if (!opened) {
                    if (sealedNegKey) {
                      rememberTerminalSealedEnvelope(sealedDecapNegCacheRef.current, sealedNegKey);
                    }
                    return;
                  }

                  senderUsernameFromBlind = opened.from;
                  const innerPayload = opened.payload;
                  if (
                    !isPlainObject(innerPayload) ||
                    hasPrototypePollutionKeys(innerPayload) ||
                    !hasExactKeys(innerPayload, ['envelope', 'messageId'])
                  ) {
                    return;
                  }
                  transportWrapperMessageId = sanitizeMessageId(innerPayload.messageId) ?? null;
                  if (!transportWrapperMessageId) {
                    return;
                  }
                  hybridEnvelope = innerPayload.envelope;
                } else {
                  console.warn('[MSG-RECV] DROP: sealed envelope arrived before local ML-KEM keys were available');
                  if (options.__status) options.__status.notReady = true;
                  return;
                }
              } catch (err) {
                if (abortIfStale()) return;
                if (isPostQuantumWorkerInfrastructureError(err)) {
                  if (options.__status) options.__status.notReady = true;
                  console.warn('[MSG-RECV] Blind-route crypto worker unavailable, deferring envelope');
                  return;
                }
                if (sealedNegKey) {
                  rememberTerminalSealedEnvelope(sealedDecapNegCacheRef.current, sealedNegKey);
                }
                console.warn('[MSG-RECV] Blind-route envelope open FAILED', { error: (err as Error)?.message || String(err) });
                return;
              }
            } else if (!isP2PTransport || !transportWrapperMessageId) {
              return;
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
            if (
              typeof senderUsernameHint !== 'string' ||
              senderUsernameHint !== senderUsernameHint.trim().toLowerCase() ||
              !AUTH_USERNAME_REGEX.test(senderUsernameHint)
            ) {
              return;
            }
            await keyTransparencyClient.restorePersistedAuthorizations(currentUser);
            if (abortIfStale()) return;
            const senderWasRevoked = isKeyTransparencyPeerRevoked(currentUser, senderUsernameHint);
            if (senderWasRevoked) {
              if (hasVerifiedP2PSender) return;
              if (!await awaitPeerIdentityRevocation(currentUser, senderUsernameHint)) {
                if (options.__status) options.__status.notReady = true;
                return;
              }
              if (abortIfStale()) return;
            }

            if (
              localKeys?.native !== true ||
              !localKeys?.dilithium?.publicKeyBase64 ||
              !senderDilithiumPublicKey
            ) {
              console.warn('[EncryptedMessageHandler] Missing keys for sealed-envelope decryption');
              if (
                (localKeys?.native !== true || !localKeys?.dilithium?.publicKeyBase64) &&
                options.__status
              ) options.__status.notReady = true;
              return;
            }

            let senderIdentity: { usernameHint?: string; expectedDilithium?: string | null };
            if (hasVerifiedP2PSender) {
              // pinned from the PQ-Noise handshake
              senderIdentity = {
                usernameHint: verifiedP2PSender.username as string,
                expectedDilithium: verifiedP2PSender.dilithiumBase64 as string
              };
            } else {
              const cachedAuthorization = senderUsernameHint && senderDilithiumPublicKey
                ? captureKeyTransparencyPeerAuthorization(
                  currentUser,
                  senderUsernameHint,
                  senderDilithiumPublicKey,
                )
                : null;
              const cachedKeyIsAuthorized =
                !senderWasRevoked &&
                !isKeyTransparencyPeerRevoked(currentUser, senderUsernameHint) &&
                cachedAuthorization !== null;
              if (cachedKeyIsAuthorized) {
                senderIdentity = {
                  usernameHint: senderUsernameHint,
                  expectedDilithium: senderDilithiumPublicKey,
                };
              } else if (senderUsernameHint && senderDilithiumPublicKey) {
                let trustedMaterial: Awaited<ReturnType<typeof resolveTrustedPeerHybridPublicKeys>> | null = null;
                if (parkForSenderVerification(
                  senderUsernameHint,
                  sealedEnvelopeCacheKey,
                  encryptedMessage,
                  null,
                )) {
                  if (deferFirstContactVerification(false)) {
                    console.warn(
                      '[EncryptedMessageHandler] Sender verification already in flight, parked',
                    );
                  }
                  return;
                }
                if (!consumeFirstContactDiscoveryBudget()) {
                  if (deferFirstContactVerification()) {
                    console.warn('[EncryptedMessageHandler] Automatic sender verification budget exhausted');
                  }
                  return;
                }
                let verificationStillRunning = false;
                let parkedForVerification = false;
                try {
                  const lookup = (async () => {
                    const cached = await findUser(senderUsernameHint).catch(() => null);
                    if (cached) {
                      const cachedTrust = await resolveTrustedPeerHybridPublicKeys(
                        currentUser,
                        senderUsernameHint,
                        cached
                      );
                      if (
                        cachedTrust?.valid &&
                        cachedTrust.hybridKeys?.dilithiumPublicBase64 === senderDilithiumPublicKey
                      ) {
                        return { trust: cachedTrust, fromCache: true };
                      }
                    } else {
                      return { trust: null, fromCache: false };
                    }

                    const fresh = await findUser(senderUsernameHint, { forceRefresh: true });
                    return {
                      trust: fresh
                        ? await resolveTrustedPeerHybridPublicKeys(
                          currentUser,
                          senderUsernameHint,
                          fresh
                        )
                        : null,
                      fromCache: false,
                    };
                  })();
                  
                  lookup.catch(() => { });

                  const settled = await Promise.race([
                    lookup.catch(() => null),
                    new Promise<'pending'>((resolve) =>
                      setTimeout(() => resolve('pending'), SENDER_VERIFY_INLINE_WAIT_MS)
                    ),
                  ]);
                  if (abortIfStale()) return;
                  if (settled === 'pending') {
                    verificationStillRunning = true;
                    parkedForVerification = parkForSenderVerification(
                      senderUsernameHint,
                      sealedEnvelopeCacheKey,
                      encryptedMessage,
                      lookup,
                    );
                  } else {
                    trustedMaterial = settled?.trust ?? null;
                  }
                } catch { trustedMaterial = null; }
                if (abortIfStale()) return;
                if (verificationStillRunning) {
                  if (deferFirstContactVerification(false)) {
                    console.warn(
                      '[EncryptedMessageHandler] Sender verification in flight, deferring',
                      { parked: parkedForVerification },
                    );
                  }
                  return;
                }
                if (!trustedMaterial?.valid || !trustedMaterial.hybridKeys) {
                  const transportDown = !websocketClient.isConnectedToServer();
                  if (deferFirstContactVerification(!transportDown)) {
                    console.warn(
                      '[EncryptedMessageHandler] Sender identity unavailable, deferring bounded retry',
                      { transportDown },
                    );
                  }
                  return;
                }
                clearFirstContactVerification();
                senderIdentity = {
                  usernameHint: senderUsernameHint,
                  expectedDilithium: trustedMaterial.hybridKeys.dilithiumPublicBase64,
                };
                window.dispatchEvent(new CustomEvent(EventType.USER_KEYS_AVAILABLE, {
                  detail: {
                    account: currentUser,
                    username: senderUsernameHint,
                    hybridKeys: trustedMaterial.hybridKeys,
                    peerCertificateFingerprint: trustedMaterial.peerCertificateFingerprint,
                    identityRootFingerprint: trustedMaterial.identityRootFingerprint,
                    identityBundleFingerprint: trustedMaterial.identityBundleFingerprint,
                  },
                }));
              } else {
                senderIdentity = { usernameHint: undefined, expectedDilithium: null };
              }
            }

            if (!senderIdentity.usernameHint || !senderIdentity.expectedDilithium) {
              console.warn('[EncryptedMessageHandler] Rejecting sealed envelope without transparency-verified sender identity');
              return;
            }

            if (senderIdentity.expectedDilithium !== senderDilithiumPublicKey) {
              console.warn('[EncryptedMessageHandler] Rejecting sealed envelope due to sender key mismatch');
              return;
            }
            if (isKeyTransparencyPeerRevoked(currentUser, senderIdentity.usernameHint)) {
              if (options.__status && !isP2PTransport) options.__status.notReady = true;
              return;
            }
            const envelopeAuthorization = captureKeyTransparencyPeerAuthorization(
              currentUser,
              senderIdentity.usernameHint,
              senderIdentity.expectedDilithium,
            );
            if (!envelopeAuthorization) {
              if (options.__status && !isP2PTransport) options.__status.notReady = true;
              return;
            }
            operationPeerAuthorization = {
              peer: senderIdentity.usernameHint,
              authorization: envelopeAuthorization,
            };
            if (abortIfStale()) return;

            // Decrypt Hybrid envelope
            const decrypted = await CryptoUtils.Hybrid.decryptIncoming(
              hybridEnvelope,
              {
                senderDilithiumPublicKey: senderDilithiumPublicKey
              },
              { expectJsonPayload: true }
            );
            if (abortIfStale()) return;

            const hybridPayload = decrypted?.payloadJson;
            if (!isPlainObject(hybridPayload) || hasPrototypePollutionKeys(hybridPayload)) {
              return;
            }
            const expectedHybridPayloadKeys = [
              'signalCiphertext',
              'from',
              'transportMessageId',
              'applicationType',
              'p2pEndpointUrl'
            ];
            if (!hasExactKeys(hybridPayload, expectedHybridPayloadKeys)) {
              return;
            }
            if (!(hybridPayload as any).signalCiphertext || !isPlainObject((hybridPayload as any).signalCiphertext)) {
              console.warn('[EncryptedMessageHandler] No signalCiphertext in decrypted envelope');
              return;
            }
            const signedTransportMessageId = sanitizeMessageId((hybridPayload as any).transportMessageId);
            const signedApplicationType = (hybridPayload as any).applicationType;
            if (
              !signedTransportMessageId ||
              typeof signedApplicationType !== 'string' ||
              !SIGNAL_TYPE_VALUES.has(signedApplicationType) ||
              transportWrapperMessageId !== signedTransportMessageId
            ) {
              return;
            }

            // Decrypt LibSignal message
            const signalPayload = (hybridPayload as any).signalCiphertext;
            const senderUsername = senderIdentity.usernameHint;
            const outerSenderHint = (hybridPayload as any).from ||
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
            authenticatedTransportMessageId = signedTransportMessageId;
            authenticatedApplicationType = signedApplicationType as SignalType;
            authenticatedSenderUsername = senderUsername;
            authenticatedSenderDilithiumPublicKey = senderDilithiumPublicKey;
            const endpointAnnouncement = (hybridPayload as any).p2pEndpointUrl;
            if (endpointAnnouncement === null) {
              authenticatedP2PEndpoint = null;
            } else {
              const privateEndpoint = normalizeP2PEndpointUrl(endpointAnnouncement);
              if (!privateEndpoint) {
                console.warn(
                  '[EncryptedMessageHandler] Ignoring unusable P2P endpoint announcement, message still delivered',
                  {
                    scheme: String(endpointAnnouncement).split('://', 1)[0]?.slice(0, 16),
                    length: String(endpointAnnouncement).length,
                  },
                );
              } else {
                authenticatedP2PEndpoint = privateEndpoint;
              }
            }
            authenticatedP2PEndpointAt = (hybridEnvelope as any).routing.timestamp;

            const messageType = (signalPayload as any)?.messageType;
            const kemCiphertext = (signalPayload as any)?.pqEnvelope?.kemCiphertext;
            const isPreKey = messageType === 3 && typeof kemCiphertext === 'string' && kemCiphertext.length > 0;
            const signalCipherKey = getSignalCiphertextKey(signalPayload);
            let preKeyDedupKey: string | null = null;

            if (isPreKey && senderUsername) {
              preKeyDedupKey = signalCipherKey ? `${senderUsername}:${signalCipherKey}` : null;
              if (preKeyDedupKey) {
                const processed = processedPreKeyMessagesRef.current.get(preKeyDedupKey);
                if (processed) {
                  if (
                    await requeueCachedDeliveryReceipt(processed.deliveryReceipt) &&
                    options.__status
                  ) {
                    options.__status.authenticated = true;
                    options.__status.spoolTerminal = true;
                  }
                  return;
                }
              }
            }

            if (signalCipherKey) {
              const processed = processedSignalCiphertextsRef.current.get(signalCipherKey);
              if (processed) {
                if (
                  await requeueCachedDeliveryReceipt(processed.deliveryReceipt) &&
                  options.__status
                ) {
                  options.__status.authenticated = true;
                  options.__status.spoolTerminal = true;
                }
                return;
              }
            }

            const decryptRateNow = Date.now();
            const decryptRate = signalDecryptRateRef.current.get(senderUsername) || {
              windowStart: decryptRateNow,
              count: 0
            };
            if (decryptRateNow - decryptRate.windowStart > 10_000) {
              decryptRate.windowStart = decryptRateNow;
              decryptRate.count = 0;
            }
            decryptRate.count += 1;
            signalDecryptRateRef.current.set(senderUsername, decryptRate);
            if (signalDecryptRateRef.current.size > 512) {
              for (const [peer, rate] of signalDecryptRateRef.current) {
                if (decryptRateNow - rate.windowStart > 10_000) signalDecryptRateRef.current.delete(peer);
              }
              while (signalDecryptRateRef.current.size > 512) {
                const oldest = signalDecryptRateRef.current.keys().next().value;
                if (typeof oldest !== 'string') break;
                signalDecryptRateRef.current.delete(oldest);
              }
            }
            if (decryptRate.count > 64) {
              if (options.__status) options.__status.notReady = true;
              return;
            }

            if (isPreKey && senderUsername) {
              const identityAuthorization = await authorizeIncomingPreKeyIdentity(
                senderUsername,
                signalPayload,
              );
              if (abortIfStale()) return;
              if (identityAuthorization === 'pending') {
                if (options.__status) options.__status.notReady = true;
                return;
              }
              if (identityAuthorization === 'reject') {
                authenticatedEnvelopeId = envelopeDedupKey;
                authenticatedSignalCipherKey = signalCipherKey;
                authenticatedPreKeyDedupKey = preKeyDedupKey;
                commitAuthenticatedMessage();
                return;
              }
            }

            let decryptedSignal;
            try {
              if (isKeyTransparencyPeerRevoked(currentUser, senderUsername)) {
                if (options.__status && !isP2PTransport) options.__status.notReady = true;
                return;
              }
              decryptedSignal = await signal.decrypt(
                senderUsername,
                currentUser,
                signalPayload,
                signedTransportMessageId,
                signedApplicationType,
                envelopeAuthorization.identityRootFingerprint,
                envelopeAuthorization.identityBundleFingerprint,
              );
            } catch {
              if (options.__status) options.__status.notReady = true;
              return;
            }
            if (abortIfStale()) return;

            if (!decryptedSignal?.success || typeof decryptedSignal.plaintext !== 'string') {
              const errMsg = String(decryptedSignal?.error || '').toLowerCase();

              // Check for duplicate messages
              const isDuplicate = errMsg.includes('old counter') || errMsg.includes('duplicate');
              if (isDuplicate) {
                authenticatedEnvelopeId = envelopeDedupKey;
                authenticatedSignalCipherKey = signalCipherKey;
                authenticatedPreKeyDedupKey = preKeyDedupKey;
                if (!await recoverKnownDeliveryReceipt()) return;
                commitAuthenticatedMessage();
                return;
              }

              if (errMsg.includes('untrusted identity') && senderUsername) {
                const retryPrefix = `${senderUsername}\0`;
                for (const candidate of preKeyIdentityVerifyAttemptsRef.current.keys()) {
                  if (candidate.startsWith(retryPrefix)) {
                    preKeyIdentityVerifyAttemptsRef.current.delete(candidate);
                  }
                }
                if (options.__status) options.__status.notReady = true;
                return;
              }

              const isSessionError = decryptedSignal?.requires_key_refresh ||
                /no.?session|no valid sessions|invalid prekey|invalid whisper message|mac verification|bad mac|ratchet|decryption failed/i.test(errMsg);

              if (isSessionError && senderUsername && authenticatedTransportMessageId) {
                const resetStatus = await requestAuthenticatedSessionReset(
                  senderUsername,
                  authenticatedTransportMessageId,
                  currentUser,
                  isCurrentAccount,
                );
                if (abortIfStale()) return;
                if (resetStatus === 'retry' && options.__status) {
                  options.__status.notReady = true;
                }
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
              if (!options.__status?.notReady) {
                authenticatedEnvelopeId = envelopeDedupKey;
                authenticatedSignalCipherKey = signalCipherKey;
                authenticatedPreKeyDedupKey = preKeyDedupKey;
                commitAuthenticatedMessage();
              }
              return;
            }

            signalRatchetCommitted = true;

            if (typeof decryptedSignal.pending_id === 'string' && decryptedSignal.pending_id.length === 44) {
              nativePendingDecryptIds.add(decryptedSignal.pending_id);
              nativePendingDecryptOwner = currentUser;
              if (options.__status) options.__status.durablyStaged = true;
            }

            authenticatedEnvelopeId = envelopeDedupKey;
            authenticatedSignalCipherKey = signalCipherKey;
            authenticatedPreKeyDedupKey = preKeyDedupKey;

            if (isPreKey && senderUsername) {
              try {
                window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
                  detail: { peer: senderUsername, account: currentUser }
                }));
              } catch { }
            }

            // Parse and process inner payload
            payload = parseDecryptedPayload(decryptedSignal.plaintext, senderUsername);
            if (!payload) {
              commitAuthenticatedMessage();
              return;
            }
            if (payload?.from && payload.from !== senderUsername) {
              console.warn('[EncryptedMessageHandler] Rejecting decrypted Signal payload due to sender mismatch');
              commitAuthenticatedMessage();
              return;
            }
            if (
              payload.type !== authenticatedApplicationType ||
              (isAckTrackedSignalType(authenticatedApplicationType) &&
                sanitizeMessageId(payload.messageId) !== authenticatedTransportMessageId)
            ) {
              console.warn('[EncryptedMessageHandler] Rejecting mismatched authenticated transport metadata');
              commitAuthenticatedMessage();
              return;
            }
          } catch (error) {
            if (
              options.__status &&
              (signalRatchetCommitted || isPostQuantumWorkerInfrastructureError(error))
            ) {
              options.__status.notReady = true;
            }
            console.error('[EncryptedMessageHandler] Failed to decrypt sealed envelope', {
              stage: error instanceof Error ? error.message : 'unknown receive stage',
            });
            return;
          }
        }
        else {
          return;
        }

        if (abortIfStale()) return;

        payload.p2p = receiverObservedTransport === 'p2p';
        payload.transport = receiverObservedTransport;

        if (payload?.to !== undefined && payload.to !== currentUser) {
          commitAuthenticatedMessage();
          return;
        }

        // Check blocking filter
        const allowedByBlockingFilter = await checkBlockingFilter(payload, currentUser, blockingSystem);
        if (abortIfStale()) return;
        if (!allowedByBlockingFilter) {
          commitAuthenticatedMessage();
          return;
        }

        if (authenticatedP2PEndpoint !== undefined) {
          if (
            !authenticatedSenderUsername ||
            !authenticatedSenderDilithiumPublicKey ||
            authenticatedP2PEndpointAt === null ||
            !p2pTransport.updateAuthenticatedEndpoint(
              authenticatedSenderUsername,
              authenticatedP2PEndpoint,
              authenticatedSenderDilithiumPublicKey,
              authenticatedP2PEndpointAt
            )
          ) {
          } else if (authenticatedSenderUsername && authenticatedSenderDilithiumPublicKey) {
            if (authenticatedP2PEndpoint === null) {
              void clearPersistedPeerEndpoint(currentUser, authenticatedSenderUsername).catch(() => { });
            } else if (authenticatedP2PEndpointAt !== null) {
              void savePersistedPeerEndpoint(currentUser, authenticatedSenderUsername, {
                endpointUrl: authenticatedP2PEndpoint,
                signerPublicKeyBase64: authenticatedSenderDilithiumPublicKey,
                announcedAt: authenticatedP2PEndpointAt,
              }).catch(() => { });
            }
          }
        }
        
        if (payload.keyTransparencyHead !== undefined && payload.keyTransparencyHead !== null) {
          keyTransparencyClient.observeGossipHead(payload.keyTransparencyHead, payload.from);
        }

        // Do not perform discovery work for blocked senders
        if (payload.from && payload.from !== currentUser) {
          const userExists = usersRef.current.find((u: any) => u.username === payload.from);
          const needsKeys = !userExists || !userExists.hybridPublicKeys || !userExists.hybridPublicKeys.kyberPublicBase64;
          if (needsKeys) {
            const lastReq = keyRequestCacheRef.current.get(payload.from);
            if (!lastReq || (now - lastReq) > KEY_REQUEST_CACHE_DURATION) {
              setBoundedPeerEntry(keyRequestCacheRef.current, payload.from, now);
              try { await requestBundleOnceCallback(payload.from, 'passive-discovery'); } catch { }
              if (abortIfStale()) return;
            }
          }
        }


        // Handle receipts
        if (payload.type === SignalType.RECEIPT_BATCH) {
          const deliveredIds = (Array.isArray(payload.deliveredIds) ? payload.deliveredIds : []).slice(0, MAX_RECEIPT_BATCH_IDS);
          const readIds = (Array.isArray(payload.readIds) ? payload.readIds : []).slice(0, MAX_RECEIPT_BATCH_IDS);
          for (const rawId of deliveredIds) {
            const id = sanitizeMessageId(rawId);
            if (id) { unifiedSignalTransport.markDelivered(id, payload.from); dispatchDeliveryReceiptEvent(id, payload.from, currentUser); }
          }
          for (const rawId of readIds) {
            const id = sanitizeMessageId(rawId);
            if (id) { unifiedSignalTransport.markDelivered(id, payload.from); dispatchReadReceiptEvent(id, payload.from, currentUser); }
          }
          commitAuthenticatedMessage();
          return;
        }
        
        if (payload.type === SignalType.FILE_TRANSPORT_ACK) {
          const ackFor = sanitizeMessageId(payload.ackFor);
          if (ackFor && payload.from) {
            unifiedSignalTransport.markDelivered(ackFor, payload.from, SignalType.FILE_MESSAGE_CHUNK);
          }
          commitAuthenticatedMessage();
          return;
        }

        // Handle P2P session reset requests
        if (payload.type === SignalType.SESSION_RESET_REQUEST) {
          const failedMessageId = sanitizeMessageId(payload.failedMessageId);
          if (!failedMessageId || !payload.from || payload.from === currentUser) {
            commitAuthenticatedMessage();
            return;
          }
          try {
            window.dispatchEvent(new CustomEvent(EventType.P2P_SESSION_RESET_REQUEST, {
              detail: { account: currentUser, from: payload.from, failedMessageId }
            }));
          } catch { }
          commitAuthenticatedMessage();
          return;
        }

        // Handle file chunks
        if (payload.type === SignalType.FILE_MESSAGE_CHUNK) {
          const transportMessageId = sanitizeMessageId(
            envelopeMessageId ||
            (typeof encryptedMessage?.messageId === 'string' ? encryptedMessage.messageId : undefined) ||
            (typeof payload?.messageId === 'string' ? payload.messageId : undefined)
          );
          try {
            const filePayload = { ...payload };
            delete filePayload.encrypted;
            delete filePayload.p2p;
            delete filePayload.transport;
            delete filePayload.keyTransparencyHead;
            const accepted = await handleFileMessageChunk(filePayload, {
              from: payload.from,
              to: currentUser,
              transportMessageId,
              transport: receiverObservedTransport,
            });
            if (abortIfStale()) return;
            if (accepted === false) {
              if (options.__status) options.__status.notReady = true;
              return;
            }
          } catch {
            console.error('[EncryptedMessageHandler] Failed to handle file chunk');
            if (options.__status) options.__status.notReady = true;
            return;
          }
          commitAuthenticatedMessage();
          return;
        }

        if (payload.type === SignalType.FILE_CHUNK_NACK) {
          const fileId = sanitizeMessageId(payload.fileId);
          const missingIndices = Array.isArray(payload.missingIndices)
            ? payload.missingIndices.filter((i: any) => Number.isInteger(i) && i >= 0).slice(0, MAX_RETRANSMIT_CHUNKS_PER_REQUEST)
            : [];
          if (fileId && missingIndices.length > 0 && payload.from && payload.from !== currentUser) {
            window.dispatchEvent(new CustomEvent(EventType.FILE_CHUNK_RETRANSMIT, {
              detail: { account: currentUser, from: payload.from, fileId, missingIndices }
            }));
          }
          commitAuthenticatedMessage();
          return;
        }

        if (payload.type === SignalType.FILE_TRANSFER_CANCEL) {
          const fileId = sanitizeMessageId(payload.fileId);
          if (fileId && payload.from && payload.from !== currentUser) {
            cancelIncomingFileTransfer(payload.from, fileId);
          }
          commitAuthenticatedMessage();
          return;
        }

        // Handle typing indicators
        if (payload.type === SignalType.TYPING_START || payload.type === SignalType.TYPING_STOP) {
          await dispatchTypingIndicatorEvent(payload);
          if (abortIfStale()) return;
          commitAuthenticatedMessage();
          return;
        }

        const { isTextMessage, isCallSignal } = getMessageType(payload);
        if (isTextMessage) clearTypingIndicator(payload.from);
        if (isCallSignal) {
          const callSignal = parseAuthenticatedCallSignal({
            localUsername: currentUser,
            payload: { content: payload.content, from: payload.from }
          });
          if (!callSignal) {
            console.error('[CALL-SIGNAL-RECV] authenticated call signal payload rejected');
            commitAuthenticatedMessage();
            return;
          }

          if (callSignal.type === 'offer') {
            const callAuthorizationCurrent =
              operationPeerAuthorization?.peer === callSignal.from &&
              isKeyTransparencyPeerAuthorizationCurrent(
                currentUser,
                callSignal.from,
                operationPeerAuthorization.authorization,
              );
            if (!callAuthorizationCurrent) {
              console.warn('[CALL-SIGNAL-RECV] incoming offer rejected without current key-transparency authorization');

              commitAuthenticatedMessage();
              return;
            }
          }

          dispatchAuthenticatedCallSignal(callSignal);
          commitAuthenticatedMessage();
          return;
        }

        // Acknowledge edits/deletes/reactions the same way as text/file messages
        const ackControlMessage = async (): Promise<boolean> => {
          const ackId = sanitizeMessageId(payload.messageId);
          if (ackId && payload.from && payload.from !== currentUser) {
            return queueDurableDeliveryReceipt(payload.from, ackId);
          }
          return false;
        };

        const isOrderedMessageControl = (
          payload.type === SignalType.DELETE_MESSAGE ||
          payload.type === SignalType.EDIT_MESSAGE ||
          payload.type === SignalType.REACTION_ADD ||
          payload.type === SignalType.REACTION_REMOVE
        );
        if (isOrderedMessageControl && !isPlausibleControlOperationId(payload.messageId)) {
          commitAuthenticatedMessage();
          return;
        }

        // Handle deletion
        if (payload.type === SignalType.DELETE_MESSAGE) {
          try {
            const applied = await handleMessageDeletion(
              payload,
              setMessages,
              isCurrentAccount,
              currentUser,
              mutatePersistedMessage
            );
            if (abortIfStale()) return;
            if (applied) {
              clearPendingControl();
              if (!await ackControlMessage()) return;
              commitAuthenticatedMessage();
            } else if (!deferPendingControl()) {
              commitAuthenticatedMessage();
            }
          } catch {
            if (options.__status) options.__status.notReady = true;
          }
          return;
        }

        // Handle edit
        if (payload.type === SignalType.EDIT_MESSAGE) {
          try {
            const applied = await handleMessageEdit(
              payload,
              setMessages,
              isCurrentAccount,
              currentUser,
              mutatePersistedMessage
            );
            if (abortIfStale()) return;
            if (applied) {
              clearPendingControl();
              if (!await ackControlMessage()) return;
              commitAuthenticatedMessage();
            } else if (!deferPendingControl()) {
              commitAuthenticatedMessage();
            }
          } catch {
            if (options.__status) options.__status.notReady = true;
          }
          return;
        }

        // Handle reactions
        if (payload.type === SignalType.REACTION_ADD || payload.type === SignalType.REACTION_REMOVE) {
          try {
            const applied = await handleReaction(
              payload,
              setMessages,
              isCurrentAccount,
              mutatePersistedMessage
            );
            if (abortIfStale()) return;
            if (applied) {
              clearPendingControl();
              if (!await ackControlMessage()) return;
              commitAuthenticatedMessage();
            } else if (!deferPendingControl()) {
              commitAuthenticatedMessage();
            }
          } catch {
            if (options.__status) options.__status.notReady = true;
          }
          return;
        }

        // Handle text messages
        if (isTextMessage && payload.type !== SignalType.FILE_MESSAGE) {
          let processed;
          try {
            processed = await processTextMessage(
              payload,
              currentUser,
              setMessages,
              saveMessageToLocalDB,
              isCurrentAccount,
              loadPersistedMessage,
              storePersistedMessage,
              receiverObservedTransport,
            );
          } catch {
            if (options.__status) options.__status.notReady = true;
            return;
          }
          if (abortIfStale()) return;
          const { messageId, messageAdded, duplicate } = processed;
          
          if ((messageAdded || duplicate) && messageId) {
            if (!await queueDurableDeliveryReceipt(payload.from, messageId)) return;
            commitAuthenticatedMessage();
          } else {
            commitAuthenticatedMessage();
          }
          if (messageAdded && payload.from !== currentUser) {
            showNotification(payload, currentUser);
          }
        }

        commitAuthenticatedMessage();
      } catch {
        console.error('[EncryptedMessageHandler] Error processing encrypted message');
        if (options.__status) options.__status.notReady = true;
      } finally {
        if (
          nativePendingDecryptIds.size > 0 &&
          nativePendingDecryptOwner &&
          !options.__status?.notReady &&
          isCurrentAccount()
        ) {
          try {
            await signal.ackPendingDecrypts(nativePendingDecryptOwner, Array.from(nativePendingDecryptIds));
            if (abortIfStale()) return;
            for (const pendingId of nativePendingDecryptIds) {
              acknowledgedPendingDecryptsRef.current.add(pendingId);
              if (acknowledgedPendingDecryptsRef.current.size > 4096) {
                const oldest = acknowledgedPendingDecryptsRef.current.values().next().value;
                if (oldest !== undefined) acknowledgedPendingDecryptsRef.current.delete(oldest);
              }
            }
          } catch {
            if (options.__status) options.__status.notReady = true;
          }
        } else if (nativePendingDecryptIds.size > 0 && !isCurrentAccount()) {
          if (options.__status) options.__status.notReady = true;
        }
      }
    },
    [setMessages, saveMessageToLocalDB, isAuthenticated, getKeysOnDemand, usersRef, handleFileMessageChunk, cancelIncomingFileTransfer, requestBundleOnceCallback, requestAuthenticatedSessionReset, loginUsernameRef, secureDBRef, findUser, getSignalCiphertextKey, isDatabaseReady, mutatePersistedMessage, loadPersistedMessage, storePersistedMessage, parkForSenderVerification]
  );

  const enqueueEncryptedMessage = useCallback(
    (
      encryptedMessage: any,
      source: 'external' | 'native-pending',
      deliverySource: 'live' | 'spool-pir' = 'live',
    ): Promise<boolean> => {
      const accountGeneration = accountGenerationRef.current;
      const status = {
        notReady: false,
        durablyStaged: false,
        authenticated: false,
        spoolTerminal: false,
      };
      if (processingDepthRef.current >= MAX_INBOUND_PROCESSING_QUEUE) {
        console.warn('[EncryptedMessageHandler] inbound processing queue saturated, dropping message', {
          depth: processingDepthRef.current
        });
        
        return Promise.resolve(false);
      }
      processingDepthRef.current++;
      const run = processingChainRef.current
        .catch(() => { })
        .then(() => {
          if (accountGeneration !== accountGenerationRef.current) {
            status.notReady = true;
            return;
          }
          return handleEncryptedMessageCallback(encryptedMessage, { source, __status: status });
        });
      processingChainRef.current = run.catch(() => { });
      void run.finally(() => {
        if (accountGeneration === accountGenerationRef.current) processingDepthRef.current--;
      }).catch(() => { });
      
      return run.then(
        async () => {
          const accepted = deliverySource === 'spool-pir'
            ? status.spoolTerminal || status.durablyStaged
            : !status.notReady || status.durablyStaged;
          if (
            source === 'external' &&
            (status.spoolTerminal || status.durablyStaged) &&
            accountGeneration === accountGenerationRef.current
          ) {
            const envelope = encryptedMessage?.type === SignalType.SEALED_ENVELOPE
              ? encryptedMessage?.envelope
              : null;
            if (
              envelope?.version === PROTOCOL_KEYS.SEALED_ENVELOPE_PROTOCOL &&
              typeof envelope.probe === 'string'
            ) {
              try {
                const cache = await loadConsumedSpoolProbeCache(loginUsernameRef.current || '');
                if (accountGeneration === accountGenerationRef.current) {
                  await cache.remember([envelope.probe]);
                }
              } catch { }
            }
          }
          return accepted;
        },
        () => status.durablyStaged,
      );
    },
    [handleEncryptedMessageCallback, loginUsernameRef]
  );

  const serializedEncryptedMessageHandler = useCallback(
    (
      encryptedMessage: any,
      deliverySource: 'live' | 'spool-pir' = 'live',
    ): Promise<boolean> => enqueueEncryptedMessage(encryptedMessage, 'external', deliverySource),
    [enqueueEncryptedMessage]
  );

  useEffect(() => {
    replayEnqueueRef.current = serializedEncryptedMessageHandler;
    return () => { replayEnqueueRef.current = null; };
  }, [serializedEncryptedMessageHandler]);

  useEffect(() => {
    const account = isAuthenticated && isDatabaseReady ? loginUsernameRef.current : '';
    if (!account) return;
    const generation = accountGenerationRef.current;
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let retryAttempts = 0;
    const isCurrent = () => (
      !cancelled &&
      !keyTransparencyClient.isSecurityIncidentActive() &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      account === loginUsernameRef.current
    );

    const scheduleRecoveryRetry = (madeProgress: boolean) => {
      if (!isCurrent()) return;
      if (retryTimer) clearTimeout(retryTimer);
      retryAttempts = madeProgress ? 0 : Math.min(retryAttempts + 1, 16);
      const exponent = Math.min(retryAttempts, 7);
      const ceiling = Math.min(
        NATIVE_PENDING_RECOVERY_MAX_RETRY_MS,
        NATIVE_PENDING_RECOVERY_MIN_RETRY_MS * (2 ** exponent),
      );
      const floor = Math.max(
        NATIVE_PENDING_RECOVERY_MIN_RETRY_MS,
        Math.floor(ceiling * 0.75),
      );
      const random = crypto.getRandomValues(new Uint32Array(1))[0] / 0x1_0000_0000;
      const delay = floor + Math.floor(random * Math.max(1, ceiling - floor + 1));
      retryTimer = setTimeout(() => { retryTimer = null; void recover(); }, delay);
    };

    const recover = async () => {
      if (!isCurrent()) return;
      try {
        const pending = await signal.listPendingDecrypts(account);
        if (!isCurrent()) return;
        for (const entry of pending) {
          if (!isCurrent()) return;
          if (acknowledgedPendingDecryptsRef.current.has(entry.pendingId)) continue;
          const accepted = await enqueueEncryptedMessage({
            type: PROTOCOL_KEYS.NATIVE_PENDING_DECRYPT,
            pendingId: entry.pendingId,
            from: entry.fromUsername,
            senderIdentityKey: entry.senderIdentityKey,
            identityRootFingerprint: entry.identityRootFingerprint,
            identityBundleFingerprint: entry.identityBundleFingerprint,
            transportMessageId: entry.transportMessageId,
            applicationType: entry.applicationType,
            plaintext: entry.plaintext
          }, 'native-pending');
          if (!accepted) break;
        }
        if (!isCurrent()) return;
        const remaining = await signal.listPendingDecrypts(account);
        if (isCurrent() && remaining.length > 0) {
          scheduleRecoveryRetry(remaining.length < pending.length);
        } else if (remaining.length === 0) {
          retryAttempts = 0;
        }
      } catch {
        scheduleRecoveryRetry(false);
      }
    };
    void recover();
    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [isAuthenticated, isDatabaseReady, loginUsernameRef, enqueueEncryptedMessage]);

  // Once automatic transparency verification installs the exact peer identity
  useEffect(() => {
    const onReplay = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      if (
        !isPlainObject(detail) ||
        hasPrototypePollutionKeys(detail) ||
        !hasExactKeys(detail, ['account', 'peer', 'verifiedKey'])
      ) return;
      const peer = detail.peer;
      const verifiedKey = detail.verifiedKey;
      const account = loginUsernameRef.current || '';
      const generation = accountGenerationRef.current;
      if (
        typeof peer !== 'string' ||
        peer !== peer.trim().toLowerCase() ||
        !AUTH_USERNAME_REGEX.test(peer) ||
        typeof verifiedKey !== 'string' ||
        verifiedKey.length === 0 ||
        detail.account !== account
      ) return;
      const isCurrent = () => (
        !!account &&
        generation === accountGenerationRef.current &&
        activeAccountRef.current === account &&
        loginUsernameRef.current === account
      );
      if (!isCurrent()) return;
      if (!identityChangeStore.matches(peer, verifiedKey)) return;
      const held = identityChangeStore.takeHeld(peer);
      if (held.length === 0) return;
      void (async () => {
        for (const h of held) {
          if (!isCurrent()) return;
          try {
            await serializedEncryptedMessageHandler(h.encryptedMessage);
          } catch { }
        }
      })();
    };
    window.addEventListener(EventType.PEER_IDENTITY_REPLAY, onReplay as EventListener);
    return () => window.removeEventListener(EventType.PEER_IDENTITY_REPLAY, onReplay as EventListener);
  }, [loginUsernameRef, serializedEncryptedMessageHandler]);

  // A lone PreKey message must not depend on a later message to trigger the
  // next transparency check. Keep one bounded, account-scoped retry per peer
  // until verification either releases or rejects the held ciphertext.
  useEffect(() => {
    const account = isAuthenticated && isDatabaseReady
      ? (loginUsernameRef.current || '')
      : '';
    if (!account) return;
    const generation = accountGenerationRef.current;
    const timers = new Map<string, ReturnType<typeof setTimeout>>();
    const inFlight = new Set<string>();
    let cancelled = false;

    const isCurrent = () => (
      !cancelled &&
      generation === accountGenerationRef.current &&
      activeAccountRef.current === account &&
      loginUsernameRef.current === account
    );

    const schedule = (): void => {
      if (!isCurrent()) return;
      const pendingEntries = identityChangeStore.list();
      const pendingPeers = new Set(pendingEntries.map(entry => entry.peer));
      for (const [peer, timer] of timers) {
        if (!pendingPeers.has(peer)) {
          clearTimeout(timer);
          timers.delete(peer);
        }
      }
      for (const { peer, newKey } of pendingEntries) {
        if (timers.has(peer) || inFlight.has(peer)) continue;
        const attemptedAt = preKeyIdentityVerifyAttemptsRef.current.get(`${peer}\0${newKey}`) || 0;
        const delay = Math.max(
          250,
          PREKEY_IDENTITY_VERIFY_RETRY_MS - Math.max(0, Date.now() - attemptedAt),
        );
        const timer = setTimeout(() => {
          timers.delete(peer);
          if (!isCurrent() || !identityChangeStore.has(peer)) return;
          const held = identityChangeStore.peekHeld(peer);
          if (!held) return;
          inFlight.add(peer);
          void serializedEncryptedMessageHandler(held.encryptedMessage)
            .catch(() => false)
            .finally(() => {
              inFlight.delete(peer);
              schedule();
            });
        }, delay);
        timers.set(peer, timer);
      }
    };

    const unsubscribe = identityChangeStore.subscribe(schedule);
    schedule();
    return () => {
      cancelled = true;
      unsubscribe();
      for (const timer of timers.values()) clearTimeout(timer);
      timers.clear();
      inFlight.clear();
    };
  }, [isAuthenticated, isDatabaseReady, loginUsernameRef, serializedEncryptedMessageHandler]);

  return serializedEncryptedMessageHandler;
}
