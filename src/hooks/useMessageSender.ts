import React, { useCallback, useMemo, useRef, useEffect } from 'react';
import { SignalType } from '../lib/signal-types';
import { EventType } from '../lib/event-types';
import { Message } from '../components/chat/messaging/types';
import { CryptoUtils } from '../lib/unified-crypto';
import websocketClient from '../lib/websocket';
import { isValidKyberPublicKeyBase64 } from '../lib/validators';
import type { SecureDB } from '../lib/secureDB';
import { secureMessageQueue } from '../lib/secure-message-queue';
import { encryptLongTerm } from '../lib/long-term-encryption';

const MAX_CONTENT_LENGTH = 16 * 1024;
const SESSION_WAIT_MS = 12_000;
const SESSION_POLL_BASE_MS = 200;
const SESSION_POLL_MAX_MS = 1_500;
const ID_CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_ID_CACHE_SIZE = 4_096;
const MAX_FILEDATA_LENGTH = 10 * 1024 * 1024; // 10MB
const BASE64_SAFE_REGEX = /^[A-Za-z0-9+/=_-]+$/;
const KYBER_PUBLIC_KEY_LENGTH = 1_568;
const DILITHIUM_PUBLIC_KEY_LENGTH = 2_592;
const X25519_PUBLIC_KEY_LENGTH = 32;

const SIGNAL_TYPE_MAP: Record<string, string> = {
  [SignalType.TYPING_START]: SignalType.TYPING_INDICATOR,
  [SignalType.TYPING_STOP]: SignalType.TYPING_INDICATOR,
  [SignalType.DELETE_MESSAGE]: SignalType.DELETE_MESSAGE,
  [SignalType.EDIT_MESSAGE]: SignalType.EDIT_MESSAGE,
  [SignalType.REACTION_ADD]: SignalType.REACTION_ADD,
  [SignalType.REACTION_REMOVE]: SignalType.REACTION_REMOVE,
};

const TEXT_ENCODER = new TextEncoder();
const globalEncryptedPayloadCache = new Map<string, { encryptedPayload: any; to: string; messageId: string }>();
const globalLongTermStoreAttempted = new Set<string>();
const MAX_CACHE_SIZE = 2000;

const getSessionApi = () => {
  const edgeApi = (globalThis as any)?.edgeApi ?? null;
  return {
    async hasSession(args: { selfUsername: string; peerUsername: string; deviceId: number }) {
      if (typeof edgeApi?.hasSession !== 'function') {
        return { hasSession: false };
      }
      try {
        return await edgeApi.hasSession(args);
      } catch {
        return { hasSession: false };
      }
    },
  };
};

const sanitizeUsername = (value: string | undefined) => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed.slice(0, 96);
};

const sanitizeContent = (value: string | undefined) => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const normalized = trimmed.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  return normalized.slice(0, MAX_CONTENT_LENGTH);
};

const validateFileData = (value: string | undefined): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;

  const inlinePrefixIndex = trimmed.indexOf(',');
  const base64Payload = inlinePrefixIndex > 0 ? trimmed.slice(inlinePrefixIndex + 1) : trimmed;

  if (base64Payload.length > MAX_FILEDATA_LENGTH * 1.4) {
    return undefined;
  }
  if (!BASE64_SAFE_REGEX.test(base64Payload.replace(/=+$/, ''))) {
    return undefined;
  }

  const estimatedBytes = Math.floor((base64Payload.length * 3) / 4) - (base64Payload.endsWith('==') ? 2 : base64Payload.endsWith('=') ? 1 : 0);
  if (estimatedBytes <= 0 || estimatedBytes > MAX_FILEDATA_LENGTH) {
    return undefined;
  }

  return trimmed;
};

const sanitizeReply = (reply: string | { id: string; sender?: string; content?: string } | undefined) => {
  if (!reply) return undefined;
  if (typeof reply === 'string') {
    const id = reply.trim();
    return id ? { id } : undefined;
  }
  const id = typeof reply.id === 'string' ? reply.id.trim() : '';
  if (!id) return undefined;
  return {
    id,
    sender: sanitizeUsername(reply.sender),
    content: reply.content ? reply.content.slice(0, MAX_CONTENT_LENGTH) : undefined,
  };
};

const logError = (code: string, error?: unknown) => {
  if (error) {
    console.error(`[MessageSender][${code}]`, error);
  } else {
    console.error(`[MessageSender][${code}]`);
  }
};

const getIdCache = () => {
  const entries = new Map<string, number>();
  const order: string[] = [];
  return {
    add(id: string) {
      entries.set(id, Date.now());
      order.push(id);
      if (order.length > MAX_ID_CACHE_SIZE) {
        const oldest = order.shift();
        if (oldest) {
          entries.delete(oldest);
        }
      }
    },
    isStale(id: string) {
      const timestamp = entries.get(id);
      if (!timestamp) return true;
      const stale = Date.now() - timestamp > ID_CACHE_TTL_MS;
      if (stale) {
        entries.delete(id);
      }
      return stale;
    },
  };
};

const mapSignalType = (baseType: string, messageSignalType?: string, fileData?: string): string => {
  if (!messageSignalType) {
    return fileData ? SignalType.FILE_MESSAGE : baseType;
  }
  return SIGNAL_TYPE_MAP[messageSignalType] ?? (fileData ? SignalType.FILE_MESSAGE : baseType);
};

const createLocalMessage = (
  messageId: string,
  sender: string,
  recipient: string,
  content: string,
  timestamp: number,
  replyToData?: { id: string; sender?: string; content?: string },
  fileData?: string,
): Message => {
  const message: Message = {
    id: messageId,
    content,
    sender,
    recipient,
    timestamp: new Date(timestamp),
    type: fileData ? SignalType.FILE : SignalType.TEXT,
    isCurrentUser: true,
    receipt: { delivered: false, read: false },
    version: '1',
    ...(replyToData && { replyTo: replyToData }),
  };

  if (fileData) {
    message.fileInfo = {
      name: 'attachment',
      type: 'application/octet-stream',
      size: 0,
      data: new ArrayBuffer(0),
    };
  }

  return message;
};

// Throttle bundle requests: track last request time per peer to avoid excessive requests
const bundleRequestTracker = new Map<string, number>();
const BUNDLE_REQUEST_COOLDOWN_MS = 5000;

const ensureSession = async (
  sessionLocks: WeakMap<object, Map<string, Promise<boolean>>>,
  lockContext: object,
  currentUser: string,
  peer: string,
  signingKeys: { secretKey: Uint8Array; publicKeyBase64: string },
) => {
  let contextMap = sessionLocks.get(lockContext);
  if (!contextMap) {
    contextMap = new Map();
    sessionLocks.set(lockContext, contextMap);
  }
  const key = `${currentUser}:${peer}`;
  const existing = contextMap.get(key);
  if (existing) {
    return existing;
  }

  const promise = (async () => {
    const sessionApi = getSessionApi();
    try {
      const initial = await sessionApi.hasSession({
        selfUsername: currentUser,
        peerUsername: peer,
        deviceId: 1,
      });
      if (initial?.hasSession) {
        return true;
      }

      const deadline = Date.now() + SESSION_WAIT_MS;
      let delay = SESSION_POLL_BASE_MS;
      const MAX_REPLIES = 1;
      let requestCount = 0;

      let sessionReadyFlag = false;
      const readyHandler = (event: Event) => {
        const customEvent = event as CustomEvent;
        if (customEvent.detail?.peer === peer) {
          sessionReadyFlag = true;
          try { window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener); } catch { }
        }
      };
      window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener);

      try {
        let lastRequestAt = 0;
        // Check if we've recently requested this peer's bundle
        const lastBundleRequest = bundleRequestTracker.get(peer) || 0;
        const nowTs = Date.now();
        const canRequestBundle = (nowTs - lastBundleRequest) >= BUNDLE_REQUEST_COOLDOWN_MS;

        if (canRequestBundle) {
          requestCount++;
          const requestBase = {
            type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
            username: peer,
            from: currentUser,
            timestamp: nowTs,
            challenge: CryptoUtils.Base64.arrayBufferToBase64(
              globalThis.crypto.getRandomValues(new Uint8Array(32)),
            ),
            senderDilithium: signingKeys.publicKeyBase64,
          } as const;
          const canonical = TEXT_ENCODER.encode(JSON.stringify(requestBase));
          const signatureRaw = await CryptoUtils.Dilithium.sign(signingKeys.secretKey, canonical);
          const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureRaw);
          await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
          lastRequestAt = nowTs;
          bundleRequestTracker.set(peer, nowTs);
        }

        while (Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, delay));

          if (sessionReadyFlag) {
            return true;
          }

          const check = await sessionApi.hasSession({
            selfUsername: currentUser,
            peerUsername: peer,
            deviceId: 1,
          });
          if (check?.hasSession) {
            return true;
          }

          if (requestCount <= MAX_REPLIES && Date.now() - lastRequestAt >= 3000) {
            const nowTs = Date.now();
            const lastBundleRequest = bundleRequestTracker.get(peer) || 0;
            const canRetryBundle = (nowTs - lastBundleRequest) >= BUNDLE_REQUEST_COOLDOWN_MS;

            if (canRetryBundle) {
              requestCount++;
              const requestBase = {
                type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                username: peer,
                from: currentUser,
                timestamp: nowTs,
                challenge: CryptoUtils.Base64.arrayBufferToBase64(
                  globalThis.crypto.getRandomValues(new Uint8Array(32)),
                ),
                senderDilithium: signingKeys.publicKeyBase64,
              } as const;
              const canonical = TEXT_ENCODER.encode(JSON.stringify(requestBase));
              const signatureRaw = await CryptoUtils.Dilithium.sign(signingKeys.secretKey, canonical);
              const signature = CryptoUtils.Base64.arrayBufferToBase64(signatureRaw);
              await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
              lastRequestAt = nowTs;
              bundleRequestTracker.set(peer, nowTs);
            }
          }

          const randomSource = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 0xffffffff;
          const poisson = -Math.log(Math.max(1 - randomSource, 1e-6));
          delay = Math.min(delay + poisson * SESSION_POLL_BASE_MS, SESSION_POLL_MAX_MS);
        }
      } finally {
        try { window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, readyHandler as EventListener); } catch { }
      }

      console.error(`[MessageSender] Failed to establish session with ${peer} after ${requestCount} attempts`);
      return false;
    } finally {
      contextMap?.delete(key);
    }
  })();

  contextMap.set(key, promise);
  return promise;
};

const createCoverPadding = () => {
  if (!globalThis.crypto?.getRandomValues) {
    return undefined;
  }
  const lengthBias = globalThis.crypto.getRandomValues(new Uint8Array(1))[0] % 32;
  const length = 32 + lengthBias;
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(length));
  return CryptoUtils.Base64.arrayBufferToBase64(bytes);
};

const recipientKeyValidator = () => {
  const cache = new Map<string, { valid: boolean; expiresAt: number }>();
  return (keys: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string }) => {
    if (!keys) return false;
    const compositeKey = `${keys.kyberPublicBase64}:${keys.dilithiumPublicBase64}:${keys.x25519PublicBase64 ?? ''}`;
    const cached = cache.get(compositeKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.valid;
    }
    let valid = true;
    try {
      const kyber = CryptoUtils.Base64.base64ToUint8Array(keys.kyberPublicBase64);
      const dilithium = CryptoUtils.Base64.base64ToUint8Array(keys.dilithiumPublicBase64);
      if (kyber.length !== KYBER_PUBLIC_KEY_LENGTH || dilithium.length !== DILITHIUM_PUBLIC_KEY_LENGTH) {
        valid = false;
      }
      if (keys.x25519PublicBase64) {
        const x25519 = CryptoUtils.Base64.base64ToUint8Array(keys.x25519PublicBase64);
        if (x25519.length !== X25519_PUBLIC_KEY_LENGTH) {
          valid = false;
        }
      }
    } catch {
      valid = false;
    }
    cache.set(compositeKey, {
      valid,
      expiresAt: Date.now() + 60_000,
    });
    return valid;
  };
};

export function useMessageSender(
  users: { username: string; hybridPublicKeys?: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } }[],
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
  resolvePeerHybridKeys?: (peerUsername: string) => Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null>
) {
  const recipientDirectory = useMemo(() => {
    const map = new Map<string, { username: string; hybridPublicKeys?: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } }>();
    users.forEach((user) => {
      if (user.username) {
        map.set(user.username, user);
      }
    });
    return map;
  }, [users]);

  const defaultResolvePeerHybridKeys = useCallback(async (peerUsername: string): Promise<{ kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } | null> => {
    if (!peerUsername) return null;

    const existing = recipientDirectory.get(peerUsername)?.hybridPublicKeys;
    if (existing && existing.kyberPublicBase64 && existing.dilithiumPublicBase64) {
      return existing;
    }
    try {
      await websocketClient.sendSecureControlMessage({ type: SignalType.CHECK_USER_EXISTS, username: peerUsername });
    } catch { }

    try {
      const keys = await getKeysOnDemand?.();
      if (keys?.dilithium?.publicKeyBase64 && keys?.dilithium?.secretKey) {
        const requestBase = {
          type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
          username: peerUsername,
          from: currentUsername || loginUsernameRef.current,
          timestamp: Date.now(),
          challenge: CryptoUtils.Base64.arrayBufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
          senderDilithium: keys.dilithium.publicKeyBase64,
          reason: 'resolve-keys',
        } as const;
        const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
        const sigRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
        const signature = CryptoUtils.Base64.arrayBufferToBase64(sigRaw);
        await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
      }
    } catch { }

    // Wait up to 2000ms for a user-keys-available event (or a users list update)
    const hybrid = await new Promise<any>((resolve) => {
      let settled = false;
      const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(null); } }, 2000);

      const onKeys = (e: Event) => {
        const d = (e as CustomEvent).detail || {};
        if (d?.username === peerUsername && d?.hybridKeys && d.hybridKeys.kyberPublicBase64 && d.hybridKeys.dilithiumPublicBase64) {
          cleanup();
          resolve(d.hybridKeys);
        }
      };
      const cleanup = () => {
        try { clearTimeout(timeout); } catch { }
        try { window.removeEventListener(EventType.USER_KEYS_AVAILABLE, onKeys as EventListener); } catch { }
      };

      window.addEventListener(EventType.USER_KEYS_AVAILABLE, onKeys as EventListener);
    });

    if (hybrid && hybrid.kyberPublicBase64 && hybrid.dilithiumPublicBase64) return hybrid;
    const refreshed = recipientDirectory.get(peerUsername)?.hybridPublicKeys || null;
    return refreshed || null;
  }, [recipientDirectory, getKeysOnDemand, loginUsernameRef]);

  const resolvePeerHybridKeysToUse = resolvePeerHybridKeys || defaultResolvePeerHybridKeys;

  useEffect(() => {
    const handler = async (event: Event) => {
      const detail = (event as CustomEvent).detail || {};
      const to = typeof detail.to === 'string' ? detail.to : '';
      const messageId = typeof detail.messageId === 'string' ? detail.messageId : '';
      
      if (!to || !messageId) {
        return;
      }

      const attemptKey = `${to}|${messageId}`;
      if (globalLongTermStoreAttempted.has(attemptKey)) {
        return;
      }
      globalLongTermStoreAttempted.add(attemptKey);

      const cached = globalEncryptedPayloadCache.get(attemptKey);
      if (!cached?.encryptedPayload) {
        return;
      }

      let recipientKyberKey: string | null = recipientDirectory.get(to)?.hybridPublicKeys?.kyberPublicBase64 ?? null;
      if (!recipientKyberKey) {
        try {
          const resolved = await resolvePeerHybridKeysToUse(to);
          recipientKyberKey = resolved?.kyberPublicBase64 ?? null;
        } catch { }
      }

      if (!recipientKyberKey || !isValidKyberPublicKeyBase64(recipientKyberKey)) {
        return;
      }

      try {
        const messageData = JSON.stringify({
          messageId,
          encryptedPayload: cached.encryptedPayload,
          timestamp: Date.now()
        });
        const longTermEnvelope = await encryptLongTerm(messageData, recipientKyberKey);
        await websocketClient.sendSecureControlMessage({
          type: SignalType.STORE_OFFLINE_MESSAGE,
          messageId,
          to,
          longTermEnvelope,
          version: 'lt-v1'
        });
      } catch { }
    };

    window.addEventListener(EventType.OFFLINE_LONGTERM_REQUIRED, handler as EventListener);
    return () => window.removeEventListener(EventType.OFFLINE_LONGTERM_REQUIRED, handler as EventListener);
  }, [recipientDirectory, resolvePeerHybridKeysToUse]);

  const sessionLocksRef = useRef(new WeakMap<object, Map<string, Promise<boolean>>>());
  const idCacheRef = useRef(getIdCache());
  const validatorRef = useRef(recipientKeyValidator());
  const lockContext = useMemo(() => ({}), []);

  // Session prefetch deduplication and throttling
  const sessionPrefetchMap = useRef<Map<string, Promise<void>>>(new Map());
  const lastSessionBundleReqTsRef = useRef<Map<string, number>>(new Map());
  const pendingRetryMessagesRef = useRef<Map<string, {
    user: { username: string; hybridPublicKeys?: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } };
    content: string;
    replyTo?: string | { id: string; sender?: string; content?: string };
    fileData?: string;
    messageSignalType?: string;
    originalMessageId?: string;
    editMessageId?: string;
    retryCount: number;
  }>>(new Map());

  const recentSessionResetsRef = useRef<Map<string, number>>(new Map());
  const peerCanDecryptRef = useRef<Map<string, boolean>>(new Map());
  const preKeyFailureCountRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {


    const handleSessionReset = (event: Event) => {
      try {
        const { peerUsername } = (event as CustomEvent).detail || {};
        if (typeof peerUsername === 'string') {
          recentSessionResetsRef.current.set(peerUsername, Date.now());
          peerCanDecryptRef.current.delete(peerUsername);
          preKeyFailureCountRef.current.delete(peerUsername);
        }
      } catch { }
    };

    const handleSessionEstablished = async (event: Event) => {
      try {
        const { peer, fromPeer } = (event as CustomEvent).detail || {};
        const peerUsername = peer || fromPeer;
        if (typeof peerUsername !== 'string') return;

        // Peer has processed our bundle and can now decrypt messages from us
        peerCanDecryptRef.current.set(peerUsername, true);

        // Process any queued messages for this peer
        window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, {
          detail: { peer: peerUsername }
        }));
      } catch (_err) {
        console.error('[MessageSender] Error handling SESSION_ESTABLISHED:', _err);
      }
    };

    window.addEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablished as EventListener);
    return () => {
      window.removeEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablished as EventListener);
    };
  }, []);


  const handleSendMessage = useCallback(
    async (
      user: { username: string; hybridPublicKeys?: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } },
      content: string,
      replyTo?: string | { id: string; sender?: string; content?: string },
      fileData?: string,
      messageSignalType?: string,
      originalMessageId?: string,
      editMessageId?: string,
    ) => {
      if (!isLoggedIn) {
        logError('AUTH');
        return;
      }

      const fileDataToSend = fileData ? validateFileData(fileData) : undefined;
      if (fileData && !fileDataToSend) {
        logError('FILEDATA-INVALID');
        return;
      }

      const currentUser = sanitizeUsername(currentUsername || loginUsernameRef.current);
      if (!currentUser) {
        console.error('[MessageSender] Missing current user', { currentUsername, ref: loginUsernameRef.current });
        alert('Error: Could not identify current user. Please try reloading.');
        logError('AUTH-CURRENT');
        return;
      }

      const recipientUsername = sanitizeUsername(user.username);
      if (!recipientUsername) {
        logError('RECIPIENT');
        return;
      }

      // Pre-compute sanitized content and reply info for potential queuing
      const sanitizedContent = sanitizeContent(content);
      const replyToData = sanitizeReply(replyTo);
      const messageType = mapSignalType(SignalType.MESSAGE, messageSignalType, fileDataToSend);

      let recipient = recipientDirectory.get(recipientUsername);
      if (!recipient?.hybridPublicKeys) {
        const fetchedKeys = await resolvePeerHybridKeysToUse(recipientUsername);
        if (!fetchedKeys) {
          if (originalMessageId) {
            resolvePeerHybridKeysToUse(recipientUsername).catch(() => { });
            logError('KEYS-UNAVAILABLE-RETRY');
            return;
          }
          throw new Error('Recipient keys unavailable');
        }
        recipient = { username: recipientUsername, hybridPublicKeys: fetchedKeys };
      }
      if (!validatorRef.current(recipient.hybridPublicKeys)) {
        logError('RECIPIENT-KEYS-INVALID');
        return;
      }

      if (!recipient?.hybridPublicKeys || !recipient.hybridPublicKeys.kyberPublicBase64 || !isValidKyberPublicKeyBase64(recipient.hybridPublicKeys.kyberPublicBase64)) {
        if (originalMessageId) {
          // Proactively request keys in background for next retry
          resolvePeerHybridKeysToUse(recipientUsername).catch(() => { });
          logError('INVALID-KEYS-RETRY');
          return;
        }

        try {
          const timestamp = Date.now();
          // Generate messageId now so UI and queue share the same id
          let messageId: string;
          do {
            messageId = crypto.randomUUID().replace(/-/g, '');
          } while (!idCacheRef.current.isStale(messageId));
          idCacheRef.current.add(messageId);

          const isTyping = (messageSignalType === SignalType.TYPING_START || messageSignalType === SignalType.TYPING_STOP);

          if (!isTyping) {
            // Create local bubble for real messages only
            const localMessage = createLocalMessage(
              messageId,
              currentUser,
              recipientUsername,
              sanitizedContent ?? '',
              timestamp,
              replyToData,
              fileDataToSend,
            );
            (localMessage as any).pending = true;
            onNewMessage(localMessage);

            // Save to SecureDB immediately so it persists
            if (secureDBRef?.current) {
              try {
                await secureDBRef.current.storeMessage({ ...localMessage, timestamp: localMessage.timestamp.getTime() });
              } catch (_err) {
                console.error('[MessageSender] Failed to save queued message to SecureDB:', _err);
              }
            }
          }

          // Queue for later when keys/session are ready
          await secureMessageQueue.queueMessage(recipientUsername, sanitizedContent ?? '', {
            messageId,
            replyTo: replyToData,
            fileData: fileDataToSend,
            messageSignalType,
            originalMessageId: messageId,
            editMessageId,
          });

          // Request keys/bundle in background
          resolvePeerHybridKeysToUse(recipientUsername).catch(() => { });
          return;
        } catch (_err) {
          logError('QUEUE', _err);
          return;
        }
      }

      let recipientKyberKey = recipient.hybridPublicKeys.kyberPublicBase64;
      if (!isValidKyberPublicKeyBase64(recipientKyberKey)) {
        logError('PQ-KEY-INVALID');
        return;
      }

      if (messageType === SignalType.MESSAGE && !sanitizedContent) {
        return;
      }

      if (
        (messageType === SignalType.REACTION_ADD || messageType === SignalType.REACTION_REMOVE) &&
        !sanitizedContent
      ) {
        return;
      }

      const localKeys = await getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey) {
        logError('LOCAL-KEYS');
        return;
      }

      const timestamp = Date.now();
      const idCache = idCacheRef.current ?? getIdCache();
      idCacheRef.current = idCache;

      let messageId: string;

      // Reuse the original message ID if this is a retry to prevent duplicates in UI
      if (originalMessageId) {
        messageId = originalMessageId;
      } else {
        do {
          messageId = crypto.randomUUID().replace(/-/g, '');
        } while (!idCache.isStale(messageId));
        idCache.add(messageId);
      }

      try {
        const sessionReady = await ensureSession(
          sessionLocksRef.current,
          lockContext,
          currentUser,
          recipientUsername,
          { secretKey: localKeys.dilithium.secretKey, publicKeyBase64: localKeys.dilithium.publicKeyBase64 },
        );
        if (!sessionReady) {
          throw new Error('Failed to establish session - no response to bundle request');
        }

        const includeSenderKyber = true;
        let senderSignalBundle: any = undefined;

        const preKeyFailures = preKeyFailureCountRef.current.get(recipientUsername) || 0;
        if (!peerCanDecryptRef.current.get(recipientUsername) && preKeyFailures < 3) {
          try {
            senderSignalBundle = await (window as any).edgeApi?.getPreKeyBundle?.({ selfUsername: currentUser, deviceId: 1 });
          } catch { }
        }

        const wireMessageId = (messageType === SignalType.EDIT_MESSAGE && editMessageId) ? editMessageId : messageId;

        const payload: Record<string, unknown> = {
          messageId: wireMessageId,
          from: currentUser,
          to: recipientUsername,
          content: sanitizedContent,
          timestamp,
          type: messageType,
          signalType: messageSignalType,
          ...(includeSenderKyber ? { senderKyberPublicBase64: localKeys.kyber.publicKeyBase64 } : {}),
          ...(senderSignalBundle ? { senderSignalBundle } : {}),
        };

        if (originalUsernameRef.current && originalUsernameRef.current !== currentUser) {
          payload.fromOriginal = originalUsernameRef.current;
        }

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

        if (
          messageType === SignalType.REACTION_ADD ||
          messageType === SignalType.REACTION_REMOVE ||
          messageType === SignalType.DELIVERY_RECEIPT ||
          messageType === SignalType.READ_RECEIPT
        ) {
          if (typeof localKeys.kyber.publicKeyBase64 === 'string') {
            payload.senderKyberPublicBase64 = localKeys.kyber.publicKeyBase64;
          }
        }

        const coverPadding = createCoverPadding();
        if (coverPadding) {
          payload.coverPadding = coverPadding;
        }

        let encrypted = await (window as any).edgeApi.encrypt({
          fromUsername: currentUser,
          toUsername: recipientUsername,
          plaintext: JSON.stringify(payload),
          recipientKyberPublicKey: recipientKyberKey,
          recipientHybridKeys: {
            ...recipient.hybridPublicKeys,
            kyberPublicBase64: recipientKyberKey,
          }
        });

        // Retry logic for session not found error
        if (!encrypted?.success && encrypted?.error?.includes('session') && encrypted?.error?.includes('not found')) {

          // Force re-check session
          const retrySession = await ensureSession(
            sessionLocksRef.current,
            lockContext,
            currentUser,
            recipientUsername,
            { secretKey: localKeys.dilithium.secretKey, publicKeyBase64: localKeys.dilithium.publicKeyBase64 },
          );

          if (retrySession) {
            // Try encrypting one more time
            encrypted = await (window as any).edgeApi.encrypt({
              fromUsername: currentUser,
              toUsername: recipientUsername,
              plaintext: JSON.stringify(payload),
              recipientKyberPublicKey: recipientKyberKey,
              recipientHybridKeys: {
                ...recipient.hybridPublicKeys,
                kyberPublicBase64: recipientKyberKey,
              }
            });
          }
        }

        if (!encrypted?.success || !encrypted?.encryptedPayload) {
          logError('encryption-failed', new Error(encrypted?.error || 'Unknown error'));
          throw new Error(`Encryption failed: ${encrypted?.error || 'Unknown error'}`);
        }

        const encryptedPayload = encrypted.encryptedPayload;

        try {
          const cacheKey = `${recipientUsername}|${wireMessageId}`;
          globalEncryptedPayloadCache.set(cacheKey, {
            encryptedPayload,
            to: recipientUsername,
            messageId: wireMessageId
          });
          if (globalEncryptedPayloadCache.size > MAX_CACHE_SIZE) {
            const firstKey = globalEncryptedPayloadCache.keys().next().value;
            if (firstKey) {
              globalEncryptedPayloadCache.delete(firstKey);
            }
          }
        } catch { }

        websocketClient.send(
          JSON.stringify({
            type: SignalType.ENCRYPTED_MESSAGE,
            to: recipientUsername,
            messageId: wireMessageId,
            encryptedPayload
          }),
        );

        if (
          secureDBRef?.current &&
          messageType !== SignalType.TYPING_INDICATOR &&
          messageType !== SignalType.DELIVERY_RECEIPT &&
          messageType !== SignalType.READ_RECEIPT) {
          try {
            const messageData = {
              user: user,
              content,
              replyTo,
              fileData,
              messageSignalType,
              originalMessageId: messageId,
              editMessageId,
              timestamp
            };

            // Store the message data
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
        }

        if (messageType === SignalType.DELETE_MESSAGE && originalMessageId) {
          window.dispatchEvent(
            new CustomEvent(EventType.LOCAL_MESSAGE_DELETE, { detail: { messageId: originalMessageId } }),
          );
          return;
        }

        if (messageType === SignalType.EDIT_MESSAGE) {
          const targetId = editMessageId || wireMessageId;
          window.dispatchEvent(
            new CustomEvent(EventType.LOCAL_MESSAGE_EDIT, { detail: { messageId: targetId, newContent: sanitizedContent } }),
          );
          return;
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
          return;
        }

        if (messageType === SignalType.TYPING_INDICATOR) {
          return;
        }

        if (!originalMessageId) {
          const localMessage = createLocalMessage(
            messageId,
            currentUser,
            recipientUsername,
            sanitizedContent ?? '',
            timestamp,
            replyToData,
            fileData,
          );

          onNewMessage(localMessage);
          if (secureDBRef?.current) {
            try {
              await secureDBRef.current.storeMessage({ ...localMessage, timestamp: localMessage.timestamp.getTime() });
            } catch (_err) {
              console.error('[MessageSender] Failed to save message to SecureDB:', _err);
            }
          }
        }
      } catch (_error) {
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        const isSessionError = errorMessage.includes('session') || errorMessage.includes('Encryption failed');
        const isPreKeyError = errorMessage.toLowerCase().includes('prekey');

        if (isPreKeyError && recipientUsername) {
          const currentCount = preKeyFailureCountRef.current.get(recipientUsername) || 0;
          preKeyFailureCountRef.current.set(recipientUsername, currentCount + 1);
        }

        if (isSessionError && recipientUsername) {
          const existingPending = pendingRetryMessagesRef.current.get(recipientUsername);
          const retryCount = (existingPending?.retryCount || 0) + 1;

          if (retryCount <= 2) {
            pendingRetryMessagesRef.current.set(recipientUsername, {
              user,
              content,
              replyTo,
              fileData,
              messageSignalType,
              originalMessageId: messageId,
              editMessageId,
              retryCount,
            });
          } else {
            console.error('[MessageSender] Message retry limit reached for', recipientUsername);
          }

          try {
            const now = Date.now();
            const last = lastSessionBundleReqTsRef.current.get(recipientUsername) || 0;
            if (now - last >= 3000) {
              lastSessionBundleReqTsRef.current.set(recipientUsername, now);
              const keys = await getKeysOnDemand();
              if (keys?.dilithium?.secretKey && keys.dilithium.publicKeyBase64) {
                const req = {
                  type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                  username: recipientUsername,
                  from: currentUser,
                  timestamp: now,
                  challenge: CryptoUtils.Base64.arrayBufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
                  senderDilithium: keys.dilithium.publicKeyBase64,
                  reason: 'retry-after-session-error',
                } as const;
                const canonical = TEXT_ENCODER.encode(JSON.stringify(req));
                const sigRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
                const signature = CryptoUtils.Base64.arrayBufferToBase64(sigRaw);
                await websocketClient.sendSecureControlMessage({ ...req, signature });
              }
            }
          } catch { }
        }

        logError('SEND', _error);
      }
    },
    [
      isLoggedIn,
      loginUsernameRef,
      recipientDirectory,
      getKeysOnDemand,
      onNewMessage,
      lockContext,
      hasUsernameMapping,
    ],
  );

  const prefetchSessionForPeer = useCallback(async (peer: string) => {
    try {
      if (!isLoggedIn) return;
      const currentUser = sanitizeUsername(loginUsernameRef.current);
      if (!currentUser || !peer) return;
      const has = await getSessionApi().hasSession({ selfUsername: currentUser, peerUsername: peer, deviceId: 1 });
      if (has?.hasSession) return;
      const now = Date.now();
      const last = lastSessionBundleReqTsRef.current.get(peer) || 0;
      if (now - last < 3000) return;
      lastSessionBundleReqTsRef.current.set(peer, now);

      if (sessionPrefetchMap.current.has(peer)) {
        await sessionPrefetchMap.current.get(peer)!.catch(() => { });
        return;
      }
      const p = (async () => {
        try {
          const keys = await getKeysOnDemand();
          if (!keys?.dilithium?.secretKey || !keys?.dilithium?.publicKeyBase64) return;
          const req = {
            type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
            username: peer,
            from: currentUser,
            timestamp: now,
            challenge: CryptoUtils.Base64.arrayBufferToBase64(globalThis.crypto.getRandomValues(new Uint8Array(32))),
            senderDilithium: keys.dilithium.publicKeyBase64,
            reason: 'prefetch-session',
          } as const;
          const canonical = TEXT_ENCODER.encode(JSON.stringify(req));
          const sigRaw = await CryptoUtils.Dilithium.sign(keys.dilithium.secretKey, canonical);
          const signature = CryptoUtils.Base64.arrayBufferToBase64(sigRaw);
          await websocketClient.sendSecureControlMessage({ ...req, signature });
        } catch { }
        finally {
          sessionPrefetchMap.current.delete(peer);
        }
      })();
      sessionPrefetchMap.current.set(peer, p);
      await p.catch(() => { });
    } catch { }
  }, [getKeysOnDemand, isLoggedIn, loginUsernameRef]);

  // Handle session establishment - retry pending messages
  useEffect(() => {
    const handleSessionReady = (event: Event) => {
      try {
        const { peer, peerUsername, fromPeer } = (event as CustomEvent).detail || {};
        const id = (peerUsername || fromPeer || peer) as string | undefined;
        if (!id || typeof id !== 'string') return;

        const pending = pendingRetryMessagesRef.current.get(id);
        pendingRetryMessagesRef.current.delete(id);
        if (!pending) return;

        handleSendMessage(
          pending.user,
          pending.content,
          pending.replyTo,
          pending.fileData,
          pending.messageSignalType,
          pending.originalMessageId,
          pending.editMessageId,
        ).catch((error) => {
          console.error('[MessageSender] Retry after session establishment failed:', error);
        });
      } catch (_error) {
        console.error('[MessageSender] Error handling session-ready event:', _error);
      }
    };

    // Handler for when peer confirms they've established the session
    const handleSessionEstablishedReceived = (event: Event) => {
      try {
        const { fromPeer, peer, peerUsername } = (event as CustomEvent).detail || {};
        const id = (fromPeer || peerUsername || peer) as string | undefined;
        if (!id || typeof id !== 'string') return;

        const pending = pendingRetryMessagesRef.current.get(id);
        pendingRetryMessagesRef.current.delete(id);
        if (!pending) return;

        handleSendMessage(
          pending.user,
          pending.content,
          pending.replyTo,
          pending.fileData,
          pending.messageSignalType,
          pending.originalMessageId,
          pending.editMessageId,
        ).catch((error) => {
          console.error('[MessageSender] Retry after session confirmation failed:', error);
        });
      } catch (_error) {
        console.error('[MessageSender] Error handling session-established-received event:', _error);
      }
    };

    window.addEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
    window.addEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablishedReceived as EventListener);

    // Handle session resets - queue unacknowledged messages for retry
    const handleSessionReset = async (event: Event) => {
      try {
        const { peerUsername } = (event as CustomEvent).detail || {};
        if (!peerUsername || !secureDBRef?.current) return;

        const db = secureDBRef.current;
        const unacknowledged: Array<{
          user: { username: string; hybridPublicKeys: { kyberPublicBase64: string; dilithiumPublicBase64: string; x25519PublicBase64?: string } };
          content: string;
          replyTo?: string | { id: string; sender?: string; content?: string };
          fileData?: string;
          messageSignalType?: string;
          originalMessageId?: string;
          editMessageId?: string;
          timestamp: number;
        }> = [];

        // Retrieve messages from ephemeral storage
        const messageListKey = `${peerUsername}:message-list`;
        const messageList = (await db.retrieveEphemeral('unacknowledged-messages', messageListKey) as number[] | null) || [];

        if (messageList.length === 0) {
          return;
        }

        // Retrieve each message
        for (const timestamp of messageList) {
          const messageKey = `${peerUsername}:${timestamp}`;
          const messageData = await db.retrieveEphemeral('unacknowledged-messages', messageKey);
          if (messageData) {
            unacknowledged.push(messageData as any);
          }
        }

        if (unacknowledged.length === 0) {
          return;
        }

        // Queue the most recent unacknowledged message for retry
        const lastMessage = unacknowledged[unacknowledged.length - 1];
        pendingRetryMessagesRef.current.set(peerUsername, {
          user: lastMessage.user,
          content: lastMessage.content,
          replyTo: lastMessage.replyTo,
          fileData: lastMessage.fileData,
          messageSignalType: lastMessage.messageSignalType,
          originalMessageId: lastMessage.originalMessageId,
          editMessageId: lastMessage.editMessageId,
          retryCount: 0,
        });

        // Clear unacknowledged messages for this peer from secure storage
        for (const timestamp of messageList) {
          try {
            await db.delete('ephemeral:unacknowledged-messages', `${peerUsername}:${timestamp}`);
          } catch { }
        }
        try {
          await db.delete('ephemeral:unacknowledged-messages', messageListKey);
        } catch { }
      } catch (_error) {
        logError('session-reset-handler-error', _error);
      }
    };

    window.addEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);

    return () => {
      window.removeEventListener(EventType.LIBSIGNAL_SESSION_READY, handleSessionReady as EventListener);
      window.removeEventListener(EventType.SESSION_ESTABLISHED_RECEIVED, handleSessionEstablishedReceived as EventListener);
      window.removeEventListener(EventType.SESSION_RESET_RECEIVED, handleSessionReset as EventListener);
    };
  }, [handleSendMessage]);

  return { handleSendMessage, prefetchSessionForPeer };
}