import { v4 as uuidv4 } from 'uuid';
import { useCallback, useEffect, useRef } from "react";
import { toast } from "sonner";
import { SignalType } from "../lib/signal-types";
import { Message } from "../components/chat/types";
import type { User } from "../components/chat/UserList";
import websocketClient from "../lib/websocket";
import { blockingSystem } from "../lib/blocking-system";
import { CryptoUtils } from "../lib/unified-crypto";

const textEncoder = new TextEncoder();

const MAX_MESSAGE_JSON_BYTES = 64 * 1024; // 64 KB
const MAX_FILE_JSON_BYTES = 256 * 1024; // 256 KB
const MAX_CALL_SIGNAL_BYTES = 256 * 1024; // 256 KB
const MAX_INLINE_FILE_BYTES = 5 * 1024 * 1024; // 5 MB inline payloads
const MAX_BLOB_URLS = 32;
const BLOB_URL_TTL_MS = 15 * 60 * 1000; // 15 minutes
const MESSAGE_RATE_LIMIT_WINDOW_MS = 5_000;
const MESSAGE_RATE_LIMIT_MAX = 300;

const BASE64_STANDARD_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64_URLSAFE_REGEX = /^[A-Za-z0-9\-_]*={0,2}$/;

type PlainObject = Record<string, unknown>;

const isPlainObject = (value: unknown): value is PlainObject => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const exceedsBytes = (input: string, limit: number): boolean => {
  const bytes = textEncoder.encode(input).length;
  return bytes > limit;
};

const MAX_CALL_SIGNAL_SIZE = MAX_CALL_SIGNAL_BYTES;
const MAX_MESSAGE_SIZE = MAX_MESSAGE_JSON_BYTES;
const MAX_FILE_MESSAGE_SIZE = MAX_FILE_JSON_BYTES;

type BlobEntry = { url: string; expiresAt: number };

const createBlobCache = () => {
  const entries: BlobEntry[] = [];

  const revoke = (entry: BlobEntry | undefined) => {
    if (!entry) return;
    try { URL.revokeObjectURL(entry.url); } catch { }
  };

  const flush = () => {
    const now = Date.now();
    while (entries.length && entries[0].expiresAt <= now) {
      revoke(entries.shift());
    }
  };

  const enqueue = (url: string) => {
    const expiresAt = Date.now() + BLOB_URL_TTL_MS;
    entries.push({ url, expiresAt });
    flush();
    if (entries.length > MAX_BLOB_URLS) {
      revoke(entries.shift());
    }
  };

  const clearAll = () => {
    while (entries.length) {
      revoke(entries.shift());
    }
  };

  return { enqueue, flush, clearAll };
};

type RateLimitConfig = { windowMs: number; max: number };

const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  windowMs: MESSAGE_RATE_LIMIT_WINDOW_MS,
  max: MESSAGE_RATE_LIMIT_MAX,
};

const sanitizeRateLimitConfig = (input: any): RateLimitConfig => {
  if (!input || typeof input !== 'object') {
    return DEFAULT_RATE_LIMIT;
  }

  const rawWindow = Number((input.windowMs ?? input.window ?? input.windowMsMs));
  const rawMax = Number((input.max ?? input.maxMessages ?? input.limit));

  const windowMs = Number.isFinite(rawWindow)
    ? Math.min(Math.max(500, Math.floor(rawWindow)), 60_000)
    : DEFAULT_RATE_LIMIT.windowMs;
  const max = Number.isFinite(rawMax)
    ? Math.min(Math.max(50, Math.floor(rawMax)), 2000)
    : DEFAULT_RATE_LIMIT.max;

  return { windowMs, max };
};

// Helper function to create blob URL from base64 data
function createBlobUrlFromBase64(
  dataBase64: string,
  fileType: string | undefined,
  blobCache: ReturnType<typeof createBlobCache>
): string | null {
  try {
    let cleanBase64 = dataBase64.trim();

    const inlinePrefixIndex = cleanBase64.indexOf(',');
    if (inlinePrefixIndex > 0 && inlinePrefixIndex < 128) {
      cleanBase64 = cleanBase64.slice(inlinePrefixIndex + 1);
    }

    const isUrlSafe = BASE64_URLSAFE_REGEX.test(cleanBase64.replace(/=*$/, ''));
    const regex = isUrlSafe ? BASE64_URLSAFE_REGEX : BASE64_STANDARD_REGEX;

    if (!regex.test(cleanBase64)) {
      return null;
    }

    const byteLength = Math.floor((cleanBase64.length * 3) / 4) - (cleanBase64.endsWith('==') ? 2 : cleanBase64.endsWith('=') ? 1 : 0);
    if (byteLength > MAX_INLINE_FILE_BYTES) {
      return null;
    }

    const binary = Uint8Array.from(atob(cleanBase64), char => char.charCodeAt(0));

    const blob = new Blob([binary], { type: fileType || 'application/octet-stream' });
    if (blob.size !== byteLength) {
      return null;
    }

    const url = URL.createObjectURL(blob);
    blobCache.enqueue(url);
    return url;
  } catch {
    return null;
  }
}

const safeJsonParse = (jsonString: string, maxBytes: number = MAX_MESSAGE_JSON_BYTES): any => {
  if (!jsonString || typeof jsonString !== 'string') {
    return null;
  }
  if (exceedsBytes(jsonString, maxBytes)) {
    return null;
  }
  const trimmed = jsonString.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return null;
  }
  try {
    const parsed = JSON.parse(jsonString);
    return parsed;
  } catch {
    return null;
  }
};

const safeJsonParseForCallSignals = (jsonString: string): any => safeJsonParse(jsonString, MAX_CALL_SIGNAL_SIZE);
const safeJsonParseForMessages = (jsonString: string): any => safeJsonParse(jsonString, MAX_MESSAGE_SIZE);

const safeJsonParseForFileMessages = (jsonString: string): any => {
  const parsed = safeJsonParse(jsonString, MAX_FILE_MESSAGE_SIZE);
  if (!parsed || !isPlainObject(parsed)) {
    return null;
  }

  const candidateFields = ['dataBase64', 'fileData', 'data', 'content'];
  for (const field of candidateFields) {
    const value = parsed[field];
    if (typeof value !== 'string') {
      continue;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      continue;
    }

    const inlinePrefixIndex = trimmed.indexOf(',');
    const base64Payload = inlinePrefixIndex > 0 ? trimmed.slice(inlinePrefixIndex + 1) : trimmed;
    const isUrlSafe = BASE64_URLSAFE_REGEX.test(base64Payload.replace(/=*$/, ''));
    const regex = isUrlSafe ? BASE64_URLSAFE_REGEX : BASE64_STANDARD_REGEX;
    if (!regex.test(base64Payload)) {
      return null;
    }
    const byteLength = Math.floor((base64Payload.length * 3) / 4) - (base64Payload.endsWith('==') ? 2 : base64Payload.endsWith('=') ? 1 : 0);
    if (byteLength > MAX_INLINE_FILE_BYTES) {
      return null;
    }
  }
  return parsed;
};

export function useEncryptedMessageHandler(
  loginUsernameRef: React.MutableRefObject<string>,
  setMessages: React.Dispatch<React.SetStateAction<Message[]>>,
  saveMessageToLocalDB: (msg: Message) => Promise<void>,
  isAuthenticated?: boolean,
  getKeysOnDemand?: () => Promise<{ x25519: { private: Uint8Array; publicKeyBase64: string }; kyber: { publicKeyBase64: string; secretKey: Uint8Array }; dilithium?: { publicKeyBase64: string; secretKey: Uint8Array } } | null>,
  usersRef?: React.MutableRefObject<User[]>,
  options?: { rateLimit?: Partial<RateLimitConfig> },
  handleFileMessageChunk?: (data: any, meta: any) => Promise<void>,
  secureDBRef?: React.MutableRefObject<any | null>
) {
  const blobCacheRef = useRef(createBlobCache());
  const rateStateRef = useRef<{ windowStart: number; count: number }>({ windowStart: 0, count: 0 });
  const rateConfigRef = useRef<RateLimitConfig>(sanitizeRateLimitConfig(options?.rateLimit));

  // Track recent key requests to prevent duplicates
  // Map: username -> timestamp of last request
  const keyRequestCacheRef = useRef<Map<string, number>>(new Map());
  const KEY_REQUEST_CACHE_DURATION = 5000; // 5 seconds

  // Deduplicate in-flight bundle requests per peer to avoid storms
  const inFlightBundleRequestsRef = useRef<Map<string, Promise<void>>>(new Map());

  // Store messages that failed PQ MAC verification for retry after key refresh
  // Map: username -> array of pending messages with retry count
  const pendingRetryMessagesRef = useRef<Map<string, Array<{ message: any; timestamp: number; retryCount: number }>>>(new Map());
  // Deduplicate queued retries per peer using a lightweight message key (e.g., kemCiphertext or messageId)
  const pendingRetryIdsRef = useRef<Map<string, Set<string>>>(new Map());

  // Queue for failed delivery receipts that should be retried after session reestablishment
  const failedDeliveryReceiptsRef = useRef<Map<string, {
    messageId: string;
    peerUsername: string;
    timestamp: number;
    attempts: number
  }>>(new Map());

  // Attempts ledger to throttle and cap retries per message (peer|dedupId)
  const attemptsLedgerRef = useRef<Map<string, { attempts: number; lastTriedKyberFp: string | null; nextAt: number }>>(new Map());
  // Fingerprint of the last seen PQ Kyber key for each peer to gate retries on actual key changes
  const lastKyberFpRef = useRef<Map<string, string>>(new Map());
  // Cooldown for bundle requests triggered by PQ MAC failures (per peer)
  const bundleRequestCooldownRef = useRef<Map<string, number>>(new Map());

  // Limit retry attempts to prevent resource exhaustion
  const MAX_RETRY_ATTEMPTS = 3;
  const PENDING_QUEUE_TTL_MS = 120_000;
  const PENDING_QUEUE_MAX_PER_PEER = 50;
  const MAX_GLOBAL_PENDING_MESSAGES = 1000;
  const BUNDLE_REQUEST_COOLDOWN_MS = 2_000;

  // Helper: exponential backoff for retries (3s, 15s, 60s)
  const computeBackoffMs = (attempts: number): number => {
    if (attempts <= 0) return 1000;
    if (attempts === 1) return 3000;
    return 8000;
  };

  // Resolve sender's PQ Kyber key
  const resolveSenderHybridKeys = useCallback(async (
    senderUsername: string
  ): Promise<{ kyber: string | null; hybrid: any | null; retried: boolean }> => {
    const user = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
    let kyber = user?.hybridPublicKeys?.kyberPublicBase64 || null;
    let retried = false;

    if (!kyber) {
      const now = Date.now();
      const lastReq = keyRequestCacheRef.current.get(senderUsername);
      if (!lastReq || (now - lastReq) > KEY_REQUEST_CACHE_DURATION) {
        keyRequestCacheRef.current.set(senderUsername, now);
        try {
          await websocketClient.sendSecureControlMessage({
            type: SignalType.CHECK_USER_EXISTS,
            username: senderUsername
          });
        } catch { }
        try {
          const keys = await getKeysOnDemand?.();
          if (keys?.dilithium?.secretKey && keys?.dilithium?.publicKeyBase64) {
            const requestBase = {
              type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
              username: senderUsername,
              from: loginUsernameRef.current,
              timestamp: Date.now(),
              challenge: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))),
              senderDilithium: keys.dilithium.publicKeyBase64,
            } as const;
            const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
            let signature: string | undefined;
            try {
              const sigRaw = await (window as any).CryptoUtils?.Dilithium?.sign(keys.dilithium.secretKey, canonical);
              signature = (window as any).CryptoUtils?.Base64?.arrayBufferToBase64
                ? (window as any).CryptoUtils.Base64.arrayBufferToBase64(sigRaw)
                : btoa(String.fromCharCode(...new Uint8Array(sigRaw)));
            } catch { }
            await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
          }
        } catch { }
        retried = true;

        await new Promise<void>((resolve) => {
          let settled = false;
          const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 2000);
          const handler = (event: Event) => {
            const d = (event as CustomEvent).detail;
            if (d?.username === senderUsername && d?.hybridKeys) {
              window.removeEventListener('user-keys-available', handler as EventListener);
              if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
            }
          };
          window.addEventListener('user-keys-available', handler as EventListener, { once: true });
        });
        const refreshed = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
        kyber = refreshed?.hybridPublicKeys?.kyberPublicBase64 || null;
      }
    }

    // Re-read hybrid keys to include latest non-Kyber parts
    let refreshedUser = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
    let hybrid = refreshedUser?.hybridPublicKeys ? { ...refreshedUser.hybridPublicKeys, kyberPublicBase64: kyber ?? refreshedUser.hybridPublicKeys?.kyberPublicBase64 } : null;
    const hasFullHybrid = (obj: any) => obj && typeof obj.dilithiumPublicBase64 === 'string' && (typeof obj.x25519PublicBase64 === 'string' || obj.x25519PublicBase64 === undefined);
    if (!hasFullHybrid(hybrid)) {
      await new Promise<void>((resolve) => {
        let settled = false;
        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1200);
        const handler = (event: Event) => {
          const d = (event as CustomEvent).detail;
          if (d?.username === senderUsername && d?.hybridKeys) {
            window.removeEventListener('user-keys-available', handler as EventListener);
            if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
          }
        };
        window.addEventListener('user-keys-available', handler as EventListener, { once: true });
      });
      refreshedUser = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
      hybrid = refreshedUser?.hybridPublicKeys ? { ...refreshedUser.hybridPublicKeys, kyberPublicBase64: kyber ?? refreshedUser.hybridPublicKeys?.kyberPublicBase64 } : null;
    }
    return { kyber, hybrid, retried };
  }, [getKeysOnDemand, loginUsernameRef, usersRef]);

  // Ref to store the callback function for retry logic
  const callbackRef = useRef<((msg: any) => Promise<void>) | null>(null);

  // Track last PQ Kyber prekey replenishment to prevent spam
  const lastPqKeyReplenishRef = useRef<number>(0);
  const PQ_KEY_REPLENISH_COOLDOWN_MS = 60_000;

  // Mutex to prevent concurrent replenishment attempts
  const replenishmentInProgressRef = useRef<boolean>(false);

  // Deduplicate PreKeySignalMessage processing to prevent consuming multiple prekeys
  const processedPreKeyMessagesRef = useRef<Map<string, number>>(new Map());
  // Cooldown to avoid session-reset thrash per peer
  const resetCooldownRef = useRef<Map<string, number>>(new Map());
  // Counter to limit total session resets per peer (resets after 1 minute)
  const resetCounterRef = useRef<Map<string, { count: number; windowStart: number }>>(new Map());
  const MAX_RESETS_PER_PEER = 5;
  const RESET_WINDOW_MS = 60_000;

  useEffect(() => {
    const interval = setInterval(() => blobCacheRef.current.flush(), BLOB_URL_TTL_MS / 2);

    // Cleanup old key request cache entries and pending retry messages every 10 seconds
    const cacheCleanupInterval = setInterval(() => {
      const now = Date.now();
      const cache = keyRequestCacheRef.current;
      for (const [username, timestamp] of cache.entries()) {
        if (now - timestamp > KEY_REQUEST_CACHE_DURATION) {
          cache.delete(username);
        }
      }

      // Clean up old pending retry messages and enforce bounds
      const pendingMessages = pendingRetryMessagesRef.current;
      let total = 0;
      const allEntries: Array<{ user: string; idx: number; ts: number }> = [];
      for (const [username, messages] of pendingMessages.entries()) {
        // TTL filter
        const filtered = messages.filter(m => now - m.timestamp < PENDING_QUEUE_TTL_MS);
        // Enforce per-peer size: keep most recent items
        const kept = filtered.length > PENDING_QUEUE_MAX_PER_PEER
          ? filtered.slice(filtered.length - PENDING_QUEUE_MAX_PER_PEER)
          : filtered;
        if (kept.length === 0) {
          pendingMessages.delete(username);
          pendingRetryIdsRef.current.delete(username);
        } else {
          pendingMessages.set(username, kept);
          // Refresh the dedup key set from the kept queue
          const idSet = new Set<string>();
          for (const item of kept) {
            const env = item?.message?.encryptedPayload;
            const msgKey: string = typeof env?.kemCiphertext === 'string'
              ? env.kemCiphertext
              : (item?.message?.messageId || '');
            if (msgKey) idSet.add(msgKey);
          }
          pendingRetryIdsRef.current.set(username, idSet);
          total += kept.length;
          kept.forEach((m, i) => allEntries.push({ user: username, idx: i, ts: m.timestamp }));
        }
      }
      // Enforce global bound by dropping oldest entries across peers
      if (total > MAX_GLOBAL_PENDING_MESSAGES) {
        const toDrop = total - MAX_GLOBAL_PENDING_MESSAGES;
        allEntries.sort((a, b) => a.ts - b.ts); // oldest first
        for (let k = 0; k < toDrop && k < allEntries.length; k++) {
          const e = allEntries[k];
          const arr = pendingMessages.get(e.user);
          if (!arr) continue;
          arr.splice(0, 1); // remove oldest for that peer
          if (arr.length === 0) {
            pendingMessages.delete(e.user);
            pendingRetryIdsRef.current.delete(e.user);
          }
        }
      }
    }, 10000);

    // Listen for session ready events to retry queued messages
    const _retryForPeer = (peer: string) => {
      const pending = pendingRetryMessagesRef.current.get(peer);
      if (pending && pending.length > 0) {
        pendingRetryMessagesRef.current.delete(peer);
        pendingRetryIdsRef.current.delete(peer);
        pending.forEach(({ message }) => {
          setTimeout(() => {
            if (callbackRef.current) {
              callbackRef.current(message).catch(() => {
              });
            }
          }, 150);
        });
      }
    };

    const handleSessionReady = (event: Event) => {
      const detail = (event as CustomEvent).detail || {};
      const peer = typeof detail.peer === 'string'
        ? detail.peer
        : (typeof detail.peerUsername === 'string' ? detail.peerUsername : undefined);
      if (typeof peer !== 'string') return;
      _retryForPeer(peer);
    };

    window.addEventListener('libsignal-session-ready', handleSessionReady as EventListener);

    return () => {
      clearInterval(interval);
      clearInterval(cacheCleanupInterval);
      window.removeEventListener('libsignal-session-ready', handleSessionReady as EventListener);
      blobCacheRef.current.clearAll();
      keyRequestCacheRef.current.clear();
      pendingRetryMessagesRef.current.clear();
    };
  }, []);

  // Listen for P2P peer reconnection events and invalidate stale hybrid encryption sessions
  useEffect(() => {
    const handlePeerReconnection = async (event: Event) => {
      try {
        const { peer } = (event as CustomEvent).detail || {};
        if (typeof peer !== 'string') return;

        const currentUser = loginUsernameRef.current;
        if (!currentUser) return;

        try {
          await (window as any).edgeApi?.deleteSession?.({
            selfUsername: currentUser,
            peerUsername: peer,
            deviceId: 1
          });
        } catch {
        }

        // Clear any pending retry messages for this peer
        pendingRetryMessagesRef.current.delete(peer);
        pendingRetryIdsRef.current.delete(peer);
        attemptsLedgerRef.current.forEach((_, key) => {
          if (key.startsWith(`${peer}|`)) {
            attemptsLedgerRef.current.delete(key);
          }
        });
        resetCooldownRef.current.delete(peer);

        // Clear cached key request to allow immediate bundle fetch
        keyRequestCacheRef.current.delete(peer);

        // Request fresh bundle from reconnected peer
        try {
          await websocketClient.sendSecureControlMessage({
            type: 'check-user-exists',
            username: peer
          });
        } catch { }
      } catch { }
    };

    window.addEventListener('p2p-peer-reconnected', handlePeerReconnection as EventListener);

    return () => {
      window.removeEventListener('p2p-peer-reconnected', handlePeerReconnection as EventListener);
    };
  }, []);

  // Listen for session established events and retry failed delivery receipts
  useEffect(() => {
    const handleSessionEstablished = async (event: Event) => {
      try {
        const { peer, fromPeer } = (event as CustomEvent).detail || {};
        const peerUsername = peer || fromPeer;
        if (typeof peerUsername !== 'string') return;


        // Find all failed receipts for this peer
        const receiptsToRetry: Array<{ key: string; data: any }> = [];
        for (const [key, data] of failedDeliveryReceiptsRef.current.entries()) {
          if (data.peerUsername === peerUsername) {
            receiptsToRetry.push({ key, data });
          }
        }

        if (receiptsToRetry.length === 0) return;


        // Get sender keys
        const keys = await getKeysOnDemand?.();
        if (!keys?.kyber?.publicKeyBase64 || !keys?.dilithium?.secretKey) return;

        // Get recipient's hybrid keys
        const user = usersRef?.current?.find?.((u: any) => u.username === peerUsername);
        if (!user?.hybridPublicKeys) return;

        const hybrid = user.hybridPublicKeys;
        const kyber = hybrid?.kyberPublicBase64;

        // Retry each failed receipt
        for (const { key, data } of receiptsToRetry) {
          try {
            const deliveryReceiptData = {
              messageId: `delivery-receipt-${data.messageId}`,
              from: loginUsernameRef.current,
              to: peerUsername,
              content: 'delivery-receipt',
              timestamp: Date.now(),
              messageType: 'signal-protocol',
              signalType: 'signal-protocol',
              protocolType: 'signal',
              type: 'delivery-receipt'
            };

            const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
              fromUsername: loginUsernameRef.current,
              toUsername: peerUsername,
              plaintext: JSON.stringify(deliveryReceiptData),
              recipientKyberPublicKey: kyber,
              recipientHybridKeys: hybrid
            });

            if (encryptedMessage?.success && encryptedMessage?.encryptedPayload) {
              const deliveryReceiptPayload = {
                type: SignalType.ENCRYPTED_MESSAGE,
                to: peerUsername,
                encryptedPayload: encryptedMessage.encryptedPayload
              };

              websocketClient.send(JSON.stringify(deliveryReceiptPayload));

              // Remove from failed queue on success
              failedDeliveryReceiptsRef.current.delete(key);
            } else {
              // Increment attempts
              data.attempts++;
              if (data.attempts > 3) {
                // Give up after 3 attempts
                failedDeliveryReceiptsRef.current.delete(key);
              } else {
                failedDeliveryReceiptsRef.current.set(key, data);
              }
            }
          } catch (_error) {
            console.error(`[EncryptedMessageHandler] Failed to retry delivery receipt:`, _error);
            // Keep in queue for next attempt
            data.attempts++;
            if (data.attempts > 3) {
              failedDeliveryReceiptsRef.current.delete(key);
            } else {
              failedDeliveryReceiptsRef.current.set(key, data);
            }
          }

          // Small delay between retries to avoid overwhelming the system
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      } catch (_error) {
        console.error('[EncryptedMessageHandler] Error handling session-established event:', _error);
      }
    };

    window.addEventListener('session-established-received', handleSessionEstablished as EventListener);
    window.addEventListener('libsignal-session-ready', handleSessionEstablished as EventListener);

    return () => {
      window.removeEventListener('session-established-received', handleSessionEstablished as EventListener);
      window.removeEventListener('libsignal-session-ready', handleSessionEstablished as EventListener);
    };
  }, [getKeysOnDemand, usersRef, loginUsernameRef]);

  // Send delivery receipts for completed file transfers (receiver -> sender)
  useEffect(() => {
    const handler = async (event: Event) => {
      try {
        const detail = (event as CustomEvent).detail || {};
        const senderUsername: string | undefined = typeof detail.from === 'string' ? detail.from : undefined;
        const messageId: string | undefined = typeof detail.messageId === 'string' ? detail.messageId : undefined;
        if (!senderUsername || !messageId) return;

        // Ensure session exists; if not, request bundle and wait briefly
        try {
          const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: loginUsernameRef.current, peerUsername: senderUsername, deviceId: 1 });
          if (!has?.hasSession) {
            await websocketClient.sendSecureControlMessage({ type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, username: senderUsername, from: loginUsernameRef.current, timestamp: Date.now() });
            await new Promise<void>((resolve) => {
              let settled = false;
              const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 6000);
              const ready = (e: Event) => {
                const d = (e as CustomEvent).detail || {};
                if (d?.peer === senderUsername) {
                  try { window.removeEventListener('libsignal-session-ready', ready as EventListener); } catch { }
                  if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
                }
              };
              window.addEventListener('libsignal-session-ready', ready as EventListener, { once: true });
            });
          }
        } catch { }

        // Resolve recipient keys (Kyber)
        const user = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
        const hybrid = user?.hybridPublicKeys;
        const kyber = hybrid?.kyberPublicBase64;
        if (!kyber || !hybrid) {
          // Queue for retry after session established
          const key = `${senderUsername}|${messageId}`;
          const prev = failedDeliveryReceiptsRef.current.get(key) || { messageId, peerUsername: senderUsername, timestamp: Date.now(), attempts: 0 };
          failedDeliveryReceiptsRef.current.set(key, prev);
          return;
        }

        // Build and send delivery receipt
        const deliveryReceiptData = {
          messageId: `delivery-receipt-${messageId}`,
          from: loginUsernameRef.current,
          to: senderUsername,
          content: 'delivery-receipt',
          timestamp: Date.now(),
          messageType: 'signal-protocol',
          signalType: 'signal-protocol',
          protocolType: 'signal',
          type: 'delivery-receipt'
        };

        const keys = await getKeysOnDemand?.();
        if (!keys?.kyber?.publicKeyBase64) return;

        const encryptedMessage = await (window as any).edgeApi?.encrypt?.({
          fromUsername: loginUsernameRef.current,
          toUsername: senderUsername,
          plaintext: JSON.stringify(deliveryReceiptData),
          recipientKyberPublicKey: kyber,
          recipientHybridKeys: hybrid
        });

        if (encryptedMessage?.success && encryptedMessage?.encryptedPayload) {
          const deliveryReceiptPayload = {
            type: SignalType.ENCRYPTED_MESSAGE,
            to: senderUsername,
            encryptedPayload: encryptedMessage.encryptedPayload
          };
          websocketClient.send(JSON.stringify(deliveryReceiptPayload));
        } else {
          const key = `${senderUsername}|${messageId}`;
          const prev = failedDeliveryReceiptsRef.current.get(key) || { messageId, peerUsername: senderUsername, timestamp: Date.now(), attempts: 0 };
          prev.attempts = (prev.attempts || 0) + 1;
          failedDeliveryReceiptsRef.current.set(key, prev);
        }
      } catch {
        // Non-fatal
      }
    };
    window.addEventListener('file-transfer-complete', handler as EventListener);
    return () => window.removeEventListener('file-transfer-complete', handler as EventListener);
  }, [getKeysOnDemand, usersRef, loginUsernameRef]);

  // Automatic PQ Kyber prekey replenishment
  const replenishPqKyberPrekey = useCallback(async (options?: { force?: boolean }) => {
    const now = Date.now();
    const lastReplenish = lastPqKeyReplenishRef.current;
    const force = options?.force === true;

    if (replenishmentInProgressRef.current) {
      return;
    }

    // Rate limiting - max once per minute
    if (!force && now - lastReplenish < PQ_KEY_REPLENISH_COOLDOWN_MS) {
      return;
    }

    // Only replenish if authenticated
    if (!isAuthenticated || !loginUsernameRef.current) {
      return;
    }

    // Acquire mutex
    replenishmentInProgressRef.current = true;

    try {
      lastPqKeyReplenishRef.current = now;

      // Ensure new prekeys are generated before fetching bundle
      try {
        await (window as any).edgeApi?.generatePreKeys?.({ username: loginUsernameRef.current, count: 50 });
      } catch { }

      // Generate fresh Signal Protocol bundle locally with new one-time prekey
      const bundle = await (window as any).edgeApi?.getPreKeyBundle?.({
        username: loginUsernameRef.current,
        regeneratePrekeys: true
      });

      if (!bundle || bundle.success === false || bundle.error) {
        console.error('[EncryptedMessageHandler] Failed to generate fresh bundle for PQ key replenishment:', bundle?.error);
        return;
      }

      // Validate bundle structure
      if (!bundle.registrationId || !bundle.identityKeyBase64 || !bundle.signedPreKey || !bundle.kyberPreKey) {
        console.error('[EncryptedMessageHandler] Invalid bundle structure during PQ key replenishment');
        return;
      }

      // Publish
      try {
        await websocketClient.sendSecureControlMessage({
          type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE,
          bundle,
          isReplenishment: true
        });
      } catch (sendErr) {
        console.error('[EncryptedMessageHandler] Failed to publish replenishment bundle:', sendErr);
        return;
      }
    } catch (_error) {
      console.error('[EncryptedMessageHandler] Error during PQ key replenishment:', _error);
    } finally {
      replenishmentInProgressRef.current = false;
    }
  }, [isAuthenticated, loginUsernameRef]);

  // Request a peer's Signal bundle once with dedup/throttle
  const requestBundleOnce = useCallback(async (peerUsername: string, reason?: string): Promise<void> => {
    if (!peerUsername) return;
    const now = Date.now();
    const last = keyRequestCacheRef.current.get(peerUsername) || 0;
    // Throttle to at most once per 1200ms per peer
    if (now - last < 1200) return;

    // Coalesce concurrent requests
    const inflight = inFlightBundleRequestsRef.current.get(peerUsername);
    if (inflight) {
      try { await inflight; } catch { }
      return;
    }

    const promise = (async () => {
      try {
        const keys = await getKeysOnDemand?.();
        if (!keys?.dilithium?.secretKey || !keys?.dilithium?.publicKeyBase64) return;
        const requestBase = {
          type: 'libsignal-request-bundle',
          username: peerUsername,
          from: loginUsernameRef.current,
          timestamp: Date.now(),
          challenge: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))),
          senderDilithium: keys.dilithium.publicKeyBase64,
          reason,
        } as const;
        const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
        let signature: string | undefined;
        try {
          const sig = await (window as any).CryptoUtils?.Dilithium?.sign(keys.dilithium.secretKey, canonical);
          signature = btoa(String.fromCharCode(...new Uint8Array(sig)));
        } catch { }
        await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
        keyRequestCacheRef.current.set(peerUsername, now);
        await new Promise<void>((resolve) => {
          let settled = false;
          const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
          const handler = (event: Event) => {
            const d = (event as CustomEvent).detail || {};
            if (d?.username === peerUsername) {
              try { window.removeEventListener('libsignal-session-ready', handler as EventListener); } catch { }
              if (!settled) { settled = true; clearTimeout(timeout); resolve(); }
            }
          };
          window.addEventListener('libsignal-session-ready', handler as EventListener, { once: true });
        });
      } finally {
        inFlightBundleRequestsRef.current.delete(peerUsername);
      }
    })();

    inFlightBundleRequestsRef.current.set(peerUsername, promise);
    await promise;
  }, [getKeysOnDemand, loginUsernameRef]);

  // Handle P2P session reset control
  useEffect(() => {
    const onP2PSessionResetReq = async (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const from = d?.from;
        if (!from || !loginUsernameRef.current) return;
        try {
          await (window as any).edgeApi?.deleteSession?.({ selfUsername: loginUsernameRef.current, peerUsername: from, deviceId: 1 });
        } catch { }
        try {
          window.dispatchEvent(new CustomEvent('session-reset-received', { detail: { peerUsername: from, reason: d?.reason || 'p2p-control' } }));
        } catch { }
        try {
          await requestBundleOnce(from, 'p2p-session-reset');
        } catch { }
      } catch { }
    };
    const onP2PSessionResetAck = async (_evt: Event) => { };
    try {
      window.addEventListener('p2p-session-reset-request', onP2PSessionResetReq as EventListener);
      window.addEventListener('p2p-session-reset-ack', onP2PSessionResetAck as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener('p2p-session-reset-request', onP2PSessionResetReq as EventListener);
        window.removeEventListener('p2p-session-reset-ack', onP2PSessionResetAck as EventListener);
      } catch { }
    };
  }, [loginUsernameRef, requestBundleOnce]);

  const handleEncryptedMessageCallback = useCallback(
    async (encryptedMessage: any) => {
      const now = Date.now();
      const rateState = rateStateRef.current;
      const config = rateConfigRef.current;
      if (now - rateState.windowStart > config.windowMs) {
        rateState.windowStart = now;
        rateState.count = 0;
      }
      rateState.count += 1;
      if (rateState.count > config.max) {
        return;
      }

      const isP2PMessage = encryptedMessage?.p2p === true && encryptedMessage?.encrypted === true;
      const isOfflineMessage = encryptedMessage?.offline === true;
      const isSignalProtocolMessage = encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE;
      const isBundleMessage = encryptedMessage?.type === SignalType.LIBSIGNAL_DELIVER_BUNDLE;
      const isBackgroundMessage = encryptedMessage?._decryptedInBackground === true;

      if (!isAuthenticated && !isP2PMessage && !isOfflineMessage && !isSignalProtocolMessage && !isBundleMessage && !isBackgroundMessage) {
        return;
      }

      try {
        if (typeof encryptedMessage !== "object" ||
          encryptedMessage === null ||
          Array.isArray(encryptedMessage) ||
          encryptedMessage instanceof Date ||
          encryptedMessage instanceof RegExp ||
          typeof encryptedMessage === 'function') {
          console.error('[EncryptedMessageHandler] Invalid message type:', typeof encryptedMessage);
          return;
        }

        if (encryptedMessage.hasOwnProperty('__proto__') ||
          encryptedMessage.hasOwnProperty('constructor') ||
          encryptedMessage.hasOwnProperty('prototype')) {
          console.error('[EncryptedMessageHandler] Prototype pollution attempt detected');
          return;
        }

        let payload: any;

        // Handle pre-decrypted background messages (already decrypted by main process)
        if (encryptedMessage?._decryptedInBackground === true) {
          const { _decryptedInBackground, _originalFrom, _timestamp, ...rest } = encryptedMessage;
          payload = rest;
          if (!payload.from && _originalFrom) {
            payload.from = _originalFrom;
          }
        }
        // Handle P2P encrypted messages
        else if (encryptedMessage?.p2p === true && encryptedMessage?.encrypted === true) {
          try {
            if (!encryptedMessage.from || !encryptedMessage.to || !encryptedMessage.id ||
              typeof encryptedMessage.from !== 'string' ||
              typeof encryptedMessage.to !== 'string' ||
              typeof encryptedMessage.id !== 'string') {
              console.error('[EncryptedMessageHandler] Invalid P2P message structure');
              return;
            }

            const usernameRegex = /^[a-zA-Z0-9_-]{1,32}$/;
            if (!usernameRegex.test(encryptedMessage.from) || !usernameRegex.test(encryptedMessage.to)) {
              console.error('[EncryptedMessageHandler] Invalid username format in P2P message');
              return;
            }

            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(encryptedMessage.id)) {
              console.error('[EncryptedMessageHandler] Invalid message ID format');
              return;
            }

            if (encryptedMessage.to !== loginUsernameRef.current) {
              console.error('[EncryptedMessageHandler] P2P message not intended for current user');
              return;
            }

            if (typeof encryptedMessage.content !== 'string' ||
              encryptedMessage.content.length === 0 ||
              encryptedMessage.content.length > 10000) {
              console.error('[EncryptedMessageHandler] Invalid P2P message content length');
              return;
            }

            const dangerousPatterns = [
              /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
              /javascript:/gi,
              /vbscript:/gi,
              /data:text\/html/gi,
              /on\w+\s*=/gi,
              /<iframe\b/gi,
              /<object\b/gi,
              /<embed\b/gi,
              /<link\b/gi,
              /<meta\b/gi
            ];

            const hasDangerousContent = dangerousPatterns.some(pattern => pattern.test(encryptedMessage.content));
            if (hasDangerousContent) {
              console.error('[EncryptedMessageHandler] Potentially dangerous content detected in P2P message');
              return;
            }

            if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(encryptedMessage.content)) {
              console.error('[EncryptedMessageHandler] Invalid control characters in P2P message content');
              return;
            }

            const now = Date.now();
            const messageTime = new Date(encryptedMessage.timestamp).getTime();
            const maxAge = 24 * 60 * 60 * 1000; // 24 hours
            const maxFuture = 5 * 60 * 1000; // 5 minutes

            if (isNaN(messageTime) || messageTime < (now - maxAge) || messageTime > (now + maxFuture)) {
              console.error('[EncryptedMessageHandler] Invalid P2P message timestamp');
              return;
            }

            payload = {
              id: encryptedMessage.id,
              content: encryptedMessage.content,
              timestamp: encryptedMessage.timestamp,
              from: encryptedMessage.from,
              to: encryptedMessage.to,
              type: 'message',
              p2p: true
            };
          } catch (_error) {
            console.error('[EncryptedMessageHandler] Failed to process P2P message:', _error);
            return;
          }
        }
        // Handle Signal Protocol encrypted messages
        else if (
          encryptedMessage?.type === SignalType.ENCRYPTED_MESSAGE &&
          encryptedMessage?.encryptedPayload &&
          getKeysOnDemand
        ) {
          try {
            const currentUser = loginUsernameRef.current;
            const envelope = encryptedMessage.encryptedPayload;

            if (envelope && typeof envelope === 'object' && 'kemCiphertext' in envelope && 'ciphertext' in envelope) {
              const kemCiphertext = (envelope as any)?.kemCiphertext;
              if (typeof kemCiphertext === 'string' && kemCiphertext.length > 0) {
                const dedupKey = `${encryptedMessage.from || 'unknown'}:${kemCiphertext}`;
                const retryCount = (encryptedMessage as any)?.__retryCount || 0;
                if (retryCount <= 0 && processedPreKeyMessagesRef.current.has(dedupKey)) {
                  return;
                }
                processedPreKeyMessagesRef.current.set(dedupKey, Date.now());
                const now = Date.now();
                for (const [key, timestamp] of processedPreKeyMessagesRef.current.entries()) {
                  if (now - timestamp > 60000) {
                    processedPreKeyMessagesRef.current.delete(key);
                  }
                }
              }

              const attachedChunkData = (envelope as any)?.chunkData;
              const cleanedEnvelope: any = { ...(envelope as any) };
              if ('chunkData' in cleanedEnvelope) {
                try { delete cleanedEnvelope.chunkData; } catch { }
              }

              const senderForDecrypt = encryptedMessage.from || (payload?.from ?? '');

              const decrypted = await (window as any).edgeApi?.decrypt?.({
                fromUsername: senderForDecrypt,
                toUsername: currentUser,
                encryptedData: cleanedEnvelope
              });

              (encryptedMessage as any).__attachedChunkData = attachedChunkData;
              if (!decrypted?.success || typeof decrypted?.plaintext !== 'string') {
                const errMsg = String(decrypted?.error || '');
                const errLower = errMsg.toLowerCase();
                const senderUsername = encryptedMessage.from || encryptedMessage.encryptedPayload?.from || (payload?.from ?? '');

                console.error(`[DECRYPT ERROR] Failed to decrypt from ${senderUsername}:`, {
                  error: errMsg,
                  code: decrypted?.code,
                  requiresKeyRefresh: decrypted?.requiresKeyRefresh,
                  sessionInfo: decrypted?.sessionInfo
                });

                if (errLower.includes('untrusted identity') && senderUsername) {
                  try {
                    await (window as any).edgeApi?.trustPeerIdentity?.({ selfUsername: currentUser, peerUsername: senderUsername, deviceId: 1 });
                  } catch { }
                }

                const requiresKeyRefresh = decrypted?.requiresKeyRefresh === true || decrypted?.code === 'SESSION_KEYS_INVALID';
                const isPqMacFailure = errLower.includes('pq_mac_verification_failed');
                const isPreKeyFailure = errLower.includes('invalid prekey message');

                if (isPreKeyFailure && senderUsername) {
                  const _lastReset = resetCooldownRef.current.get(senderUsername) || 0;
                  const preKeyAttempts = attemptsLedgerRef.current.get(`${senderUsername}|prekey-attempts`);
                  if (preKeyAttempts && preKeyAttempts.attempts >= 5) {
                    return;
                  }
                }

                if (requiresKeyRefresh && senderUsername) {
                  const _lastReset = resetCooldownRef.current.get(senderUsername) || 0;
                  const nowTsCooldown = Date.now();
                  if (nowTsCooldown - _lastReset < 3000) {
                    return;
                  }

                  // Check reset counter to prevent infinite reset loops
                  const counterEntry = resetCounterRef.current.get(senderUsername);
                  if (counterEntry) {
                    // Reset the counter if the window has expired
                    if (nowTsCooldown - counterEntry.windowStart > RESET_WINDOW_MS) {
                      resetCounterRef.current.set(senderUsername, { count: 1, windowStart: nowTsCooldown });
                    } else if (counterEntry.count >= MAX_RESETS_PER_PEER) {
                      // Exceeded max resets for this peer in this window
                      console.warn(`[EncryptedMessageHandler] Max session resets (${MAX_RESETS_PER_PEER}) reached for ${senderUsername}, waiting for window to expire`);
                      return;
                    } else {
                      // Increment the counter
                      counterEntry.count += 1;
                    }
                  } else {
                    // First reset for this peer
                    resetCounterRef.current.set(senderUsername, { count: 1, windowStart: nowTsCooldown });
                  }

                  resetCooldownRef.current.set(senderUsername, nowTsCooldown);
                  try {
                    // Delete the broken session immediately
                    await (window as any).edgeApi?.deleteSession?.({
                      selfUsername: currentUser,
                      peerUsername: senderUsername,
                      deviceId: 1
                    });

                    try {
                      await websocketClient.sendSecureControlMessage({
                        type: 'session-reset-request',
                        from: currentUser,
                        targetUsername: senderUsername,
                        deviceId: 1,
                        timestamp: Date.now(),
                        reason: 'decryption-failure'
                      });
                      // Also request a P2P control reset so peer can react immediately over DC
                      try {
                        window.dispatchEvent(new CustomEvent('p2p-session-reset-send', {
                          detail: { to: senderUsername, reason: 'decryption-failure' }
                        }));
                      } catch { }

                      window.dispatchEvent(new CustomEvent('session-reset-received', {
                        detail: { peerUsername: senderUsername, reason: 'local-initiated-reset' }
                      }));
                    } catch (notifyErr) {
                      console.error('[EncryptedMessageHandler] Failed to send session reset notification:', notifyErr);
                    }
                  } catch {
                    console.error('[EncryptedMessageHandler] Failed to delete stale session');
                  }

                  // Queue message for retry after session recovery
                  const messageRetryCount = (encryptedMessage as any).__retryCount || 0;
                  const env = (encryptedMessage as any)?.encryptedPayload;
                  const dedupId: string = typeof env?.kemCiphertext === 'string' ? env.kemCiphertext : ((encryptedMessage as any)?.messageId || '');
                  const ledgerKey = `${senderUsername}|${dedupId || uuidv4()}`;
                  const nowTs = Date.now();

                  // Attempts ledger with exponential backoff and cap
                  const entry = attemptsLedgerRef.current.get(ledgerKey) || { attempts: 0, lastTriedKyberFp: null as string | null, nextAt: 0 };
                  if (nowTs < entry.nextAt) {
                    return;
                  }
                  if (entry.attempts >= MAX_RETRY_ATTEMPTS) {
                    return;
                  }
                  const currentFp = lastKyberFpRef.current.get(senderUsername) || null;
                  entry.attempts += 1;
                  entry.lastTriedKyberFp = currentFp;
                  entry.nextAt = nowTs + computeBackoffMs(entry.attempts - 1);
                  attemptsLedgerRef.current.set(ledgerKey, entry);

                  // Queue message for retry
                  const pendingQueue = pendingRetryMessagesRef.current.get(senderUsername) || [];
                  const messageWithRetryCount = { ...encryptedMessage, __retryCount: messageRetryCount + 1 };
                  const idSet = pendingRetryIdsRef.current.get(senderUsername) || new Set<string>();
                  if (!dedupId || !idSet.has(dedupId)) {
                    if (pendingQueue.length >= PENDING_QUEUE_MAX_PER_PEER) {
                      pendingQueue.shift();
                    }
                    pendingQueue.push({ message: messageWithRetryCount, timestamp: nowTs, retryCount: messageRetryCount + 1 });
                    pendingRetryMessagesRef.current.set(senderUsername, pendingQueue);
                    if (dedupId) {
                      idSet.add(dedupId);
                      pendingRetryIdsRef.current.set(senderUsername, idSet);
                    }
                  }

                  // Request fresh bundle from sender to establish new session
                  const lastBundle = bundleRequestCooldownRef.current.get(senderUsername) || 0;
                  if (nowTs - lastBundle >= BUNDLE_REQUEST_COOLDOWN_MS) {
                    bundleRequestCooldownRef.current.set(senderUsername, nowTs);
                    try {
                      await requestBundleOnce(senderUsername, 'session-key-refresh');
                    } catch (bundleReqError) {
                      console.error('[EncryptedMessageHandler] Failed to request bundle for session recovery:', bundleReqError);
                    }
                  }

                  return;
                }

                // Handle any other decryption failures (Signal Protocol or PQ layer) not already covered by requiresKeyRefresh
                const shouldRebuildSession = (!requiresKeyRefresh || true) && (
                  isPqMacFailure ||
                  errLower.includes('untrusted identity') ||
                  (errLower.includes('session with') && errLower.includes('not found')) ||
                  errLower.includes('invalid whisper message') ||
                  errLower.includes('decryption failed') ||
                  errLower.includes('no valid sessions') ||
                  errLower.includes('no session') ||
                  errLower.includes('invalid mac')
                ) && !!senderUsername;

                if (shouldRebuildSession) {
                  const _lastReset2 = resetCooldownRef.current.get(senderUsername) || 0;
                  const nowTsCooldown2 = Date.now();
                  if (nowTsCooldown2 - _lastReset2 < 3000) {
                    return;
                  }
                  resetCooldownRef.current.set(senderUsername, nowTsCooldown2);
                  try {
                    // Trust peer identity on first-seen after token unlock to avoid untrusted-identity loops
                    try { await (window as any).edgeApi?.trustPeerIdentity?.({ selfUsername: currentUser, peerUsername: senderUsername, deviceId: 1 }); } catch { }
                    await (window as any).edgeApi?.deleteSession?.({
                      selfUsername: currentUser,
                      peerUsername: senderUsername,
                      deviceId: 1
                    });

                    // Send session reset notification
                    try {
                      await websocketClient.sendSecureControlMessage({
                        type: 'session-reset-request',
                        from: currentUser,
                        targetUsername: senderUsername,
                        deviceId: 1,
                        timestamp: Date.now(),
                        reason: isPqMacFailure ? 'pq-mac-failure' : 'decryption-failure'
                      });
                      // Request P2P control session reset too
                      try {
                        window.dispatchEvent(new CustomEvent('p2p-session-reset-send', {
                          detail: { to: senderUsername, reason: isPqMacFailure ? 'pq-mac-failure' : 'decryption-failure' }
                        }));
                      } catch { }

                      // Emit local session-reset-received event
                      window.dispatchEvent(new CustomEvent('session-reset-received', {
                        detail: { peerUsername: senderUsername, reason: 'decryption-failure' }
                      }));
                    } catch (notifyErr) {
                      console.error('[EncryptedMessageHandler] Failed to send session reset:', notifyErr);
                    }
                  } catch {
                    console.error('[EncryptedMessageHandler] Failed to delete session');
                  }

                  try {
                    const now = Date.now();
                    const lastReq = keyRequestCacheRef.current.get(senderUsername);
                    if (!lastReq || (now - lastReq) > KEY_REQUEST_CACHE_DURATION) {
                      keyRequestCacheRef.current.set(senderUsername, now);
                      const keys = await getKeysOnDemand?.();
                      if (keys?.dilithium?.secretKey && keys.dilithium.publicKeyBase64) {
                        const requestBase = {
                          type: 'libsignal-request-bundle',
                          username: senderUsername,
                          from: currentUser,
                          timestamp: Date.now(),
                          challenge: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))),
                          senderDilithium: keys.dilithium.publicKeyBase64,
                        };
                        const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
                        const signatureRaw = await (window as any).CryptoUtils?.Dilithium?.sign(keys.dilithium.secretKey, canonical);
                        const signature = btoa(String.fromCharCode(...new Uint8Array(signatureRaw)));
                        await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
                        const sessionReadyPromise = new Promise<void>((resolve, reject) => {
                          const timeout = setTimeout(() => {
                            cleanup();
                            reject(new Error('Bundle processing timeout'));
                          }, 10000);
                          const handleReady = (event: Event) => {
                            const d = (event as CustomEvent).detail;
                            if (d?.peer === senderUsername) {
                              cleanup();
                              resolve();
                            }
                          };
                          const handleFailed = (event: Event) => {
                            const d = (event as CustomEvent).detail;
                            if (d?.peer === senderUsername) {
                              cleanup();
                              reject(new Error(d?.error || 'Bundle not available'));
                            }
                          };
                          const cleanup = () => {
                            clearTimeout(timeout);
                            window.removeEventListener('libsignal-session-ready', handleReady as EventListener);
                            window.removeEventListener('libsignal-bundle-failed', handleFailed as EventListener);
                          };
                          window.addEventListener('libsignal-session-ready', handleReady as EventListener);
                          window.addEventListener('libsignal-bundle-failed', handleFailed as EventListener);
                        });
                        try {
                          await sessionReadyPromise;
                          const retried = await (window as any).edgeApi?.decrypt?.({
                            fromUsername: senderUsername,
                            toUsername: currentUser,
                            encryptedData: cleanedEnvelope
                          });
                          if (retried?.success && typeof retried?.plaintext === 'string') {
                            payload = safeJsonParseForMessages(retried.plaintext) || { content: retried.plaintext, type: 'message' };
                            if (encryptedMessage.from && payload && !payload.from) {
                              (payload as any).from = encryptedMessage.from;
                            }
                            replenishPqKyberPrekey().catch(() => { });
                          }
                        } catch { }

                      }
                    }
                  } catch { }
                } else {
                  // Log non-rebuildable errors briefly
                  try {
                    console.error('[EncryptedMessageHandler] Signal+PQ decrypt failed:', {
                      success: decrypted?.success,
                      plaintextType: typeof decrypted?.plaintext,
                      error: decrypted?.error,
                      from: encryptedMessage.from,
                      to: currentUser
                    });
                  } catch { }
                }

                if (!payload) return;
              }

              payload = safeJsonParseForMessages(decrypted.plaintext) || { content: decrypted.plaintext, type: 'message' };
              if (!payload || typeof payload !== 'object') {
                console.error('[EncryptedMessageHandler] Decrypted payload invalid');
                return;
              }
              (payload as any).encrypted = true;

              if (encryptedMessage.from && !payload.from) {
                (payload as any).from = encryptedMessage.from;
              }

              replenishPqKyberPrekey().catch(() => { });

              try {
                const currentUserForSession = loginUsernameRef.current;
                const senderUsername = (payload as any)?.from;
                if (currentUserForSession && senderUsername) {
                  const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUserForSession, peerUsername: senderUsername, deviceId: 1 });
                  if (!has?.hasSession && (payload as any)?.senderSignalBundle) {
                    try {
                      const bundleResult = await (window as any).edgeApi?.processPreKeyBundle?.({ selfUsername: currentUserForSession, peerUsername: senderUsername, bundle: (payload as any).senderSignalBundle });
                      if (bundleResult?.success) {
                        const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUserForSession, peerUsername: senderUsername, deviceId: 1 });
                        if (!has?.hasSession) {
                        }
                        try { window.dispatchEvent(new CustomEvent('libsignal-session-ready', { detail: { peer: senderUsername } })); } catch { }

                        try {
                          if (has?.hasSession) await websocketClient.sendSecureControlMessage({
                            type: 'session-established',
                            from: currentUserForSession,
                            username: senderUsername,
                            deviceId: 1,
                            timestamp: Date.now()
                          });
                        } catch {
                        }
                      }
                    } catch {
                    }
                  }
                }
              } catch { }

              if (payload.type === SignalType.FILE_MESSAGE_CHUNK) {
                const attachedChunkData = (encryptedMessage as any)?.__attachedChunkData;
                if (attachedChunkData && typeof attachedChunkData === 'string') {
                  (payload as any).chunkData = attachedChunkData;
                } else {
                }
              }
            } else {
              console.error('[EncryptedMessageHandler] Unsupported envelope format - expected Signal+PQ');
              return;
            }
          } catch (_err) {
            console.error('[EncryptedMessageHandler] Envelope decryption failed:', _err);
            return;
          }
        } else if (encryptedMessage?.type === SignalType.LIBSIGNAL_DELIVER_BUNDLE) {
          try {
            const currentUser = loginUsernameRef.current;
            const bundle = encryptedMessage.bundle;
            const peerUsername = encryptedMessage.username;

            const bundleResult = await (window as any).edgeApi.processPreKeyBundle({
              selfUsername: currentUser,
              peerUsername,
              bundle
            });

            if (bundleResult?.success) {
              const has = await (window as any).edgeApi?.hasSession?.({ selfUsername: currentUser, peerUsername, deviceId: 1 });
              if (!has?.hasSession) {
              }
              try { window.dispatchEvent(new CustomEvent('libsignal-session-ready', { detail: { peer: peerUsername } })); } catch { }

              try {
                if (has?.hasSession) await websocketClient.sendSecureControlMessage({
                  type: 'session-established',
                  from: currentUser,
                  username: peerUsername,
                  deviceId: 1,
                  timestamp: Date.now()
                });
              } catch {
              }
            }
          } catch (_error) {
            try { window.dispatchEvent(new CustomEvent('libsignal-bundle-failed', { detail: { peer: encryptedMessage?.username, error: _error instanceof Error ? _error.message : String(_error) } })); } catch { }
            return;
          }
          return;
        } else {
          return;
        }

        // If sender's original name was provided inside the encrypted payload, store mapping locally
        try {
          const originalFrom = (payload as any)?.fromOriginal;
          const hashedFrom = (payload as any)?.from;
          if (typeof originalFrom === 'string' && typeof hashedFrom === 'string') {
            // Emit event so whoever holds SecureDB can store mapping
            window.dispatchEvent(new CustomEvent('username-mapping-received', {
              detail: { hashed: hashedFrom, original: originalFrom }
            }));
          }
        } catch { }

        try {
          const senderUsername = payload.from;

          if (senderUsername && senderUsername !== loginUsernameRef.current) {
            const userExists = usersRef?.current?.find?.((u: any) => u.username === senderUsername);
            const needsKeys = !userExists || !userExists.hybridPublicKeys || !userExists.hybridPublicKeys.kyberPublicBase64;

            if (needsKeys) {
              // Check if we recently requested keys for this user to prevent duplicates
              const now = Date.now();
              const lastRequest = keyRequestCacheRef.current.get(senderUsername);

              if (!lastRequest || (now - lastRequest) > KEY_REQUEST_CACHE_DURATION) {
                // Mark this request in cache
                keyRequestCacheRef.current.set(senderUsername, now);

                // First, check if user exists and get their basic hybrid keys (PQ encrypted)
                await websocketClient.sendSecureControlMessage({
                  type: 'check-user-exists',
                  username: senderUsername
                });

                try {
                  const keysOnDemand = await getKeysOnDemand?.();
                  if (keysOnDemand?.dilithium?.secretKey) {
                    const requestBase = {
                      type: 'libsignal-request-bundle',
                      username: senderUsername,
                      from: loginUsernameRef.current,
                      timestamp: Date.now(),
                      challenge: btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))),
                      senderDilithium: keysOnDemand.dilithium.publicKeyBase64,
                    };
                    const canonical = new TextEncoder().encode(JSON.stringify(requestBase));
                    const signatureRaw = await (window as any).CryptoUtils?.Dilithium?.sign(keysOnDemand.dilithium.secretKey, canonical);
                    const signature = btoa(String.fromCharCode(...new Uint8Array(signatureRaw)));
                    await websocketClient.sendSecureControlMessage({ ...requestBase, signature });
                  }
                } catch { }
              }
            }
          }
        } catch {
        }

        // Process the decrypted payload
        if (payload && typeof payload === 'object') {
          // Apply blocking filter for incoming messages (except system messages)
          if (payload.from && payload.from !== loginUsernameRef.current &&
            payload.type !== 'read-receipt' && payload.type !== 'delivery-receipt' &&
            payload.type !== 'typing-start' && payload.type !== 'typing-stop' &&
            payload.type !== 'typing-indicator') {
            try {
              let passphrase = null;

              if (passphrase) {
                const shouldFilter = await blockingSystem.filterIncomingMessage({
                  sender: payload.from,
                  content: payload.content || ''
                }, passphrase);

                if (!shouldFilter) {
                  return;
                }
              }
            } catch (_error) {
              console.error('[EncryptedMessageHandler] Error checking blocking filter:', _error);
            }
          }

          // Handle read receipts
          if (payload.type === 'read-receipt' && payload.messageId) {
            const event = new CustomEvent('message-read', {
              detail: {
                messageId: payload.messageId,
                from: payload.from
              }
            });
            window.dispatchEvent(event);
            return;
          }

          // Handle delivery receipts
          if (payload.type === 'delivery-receipt' && payload.messageId) {
            const event = new CustomEvent('message-delivered', {
              detail: {
                messageId: payload.messageId,
                from: payload.from
              }
            });
            window.dispatchEvent(event);
            return;
          }

          // Handle file chunks
          if (payload.type === SignalType.FILE_MESSAGE_CHUNK) {
            // Forward to file handler if available
            if (handleFileMessageChunk) {
              try {
                await handleFileMessageChunk(payload, { from: payload.from });
              } catch (_error) {
                console.error('[EncryptedMessageHandler] Failed to handle file chunk:', _error);
              }
            }
            return;
          }

          // Handle typing indicators
          if (payload.type === 'typing-start' || payload.type === 'typing-stop' || payload.type === 'typing-indicator') {
            let indicatorType = payload.type;
            if (payload.type === 'typing-indicator' && payload.content) {
              const contentData = safeJsonParse(payload.content);
              if (contentData && contentData.type) {
                indicatorType = contentData.type;
              } else {
                indicatorType = 'typing-start';
              }
            }

            // Dispatch typing-indicator event
            try {
              const username = String(payload.from || '');
              const action = indicatorType === 'typing-stop' ? 'stop' : 'start';
              const timestamp = Date.now();
              const nonceBytes = crypto.getRandomValues(new Uint8Array(24));
              const nonce = btoa(String.fromCharCode(...nonceBytes));
              const encoder = new TextEncoder();
              const macKey = await CryptoUtils.Hash.generateBlake3Mac(encoder.encode(nonce), encoder.encode(String(timestamp)));
              const typedPayload = { username, action };
              const payloadBytes = encoder.encode(JSON.stringify(typedPayload));
              const macBytes = await CryptoUtils.Hash.generateBlake3Mac(payloadBytes, macKey);
              const signature = CryptoUtils.Base64.arrayBufferToBase64(macBytes);
              const secureEvent = new CustomEvent('typing-indicator', {
                detail: {
                  signature,
                  timestamp,
                  nonce,
                  payload: typedPayload
                }
              });
              window.dispatchEvent(secureEvent);
            } catch (_e) {
              console.error('[EncryptedMessageHandler] Failed to dispatch secure typing indicator:', _e);
            }
            return;
          }

          const isTextMessage = (payload.type === 'message' || payload.type === 'text' || !payload.type) &&
            payload.content &&
            typeof payload.content === 'string' &&
            payload.content.trim().length > 0;
          const isFileMessage = payload.type === 'file-message' && payload.fileName;
          const isActualMessage = isTextMessage || isFileMessage;

          const isCallSignal = payload.type?.startsWith?.('call-') ||
            ['call-offer', 'call-answer', 'call-ice', 'call-signal', 'call-end', 'call-reject'].includes(payload.type);

          if (isActualMessage) {
            try {
              const typingClearEvent = new CustomEvent('typing-indicator', {
                detail: { from: payload.from, indicatorType: 'typing-stop' }
              });
              window.dispatchEvent(typingClearEvent);
            } catch { }
          }

          // Show notification when window is unfocused
          if ((isActualMessage || isCallSignal) && payload.from !== loginUsernameRef.current) {
            try {
              const isFocused = document.hasFocus();
              if (!isFocused && (window as any).electronAPI?.showNotification) {
                const senderName = payload.from || 'Someone';
                const title = isCallSignal ? 'Incoming Call' : (isFileMessage ? 'New File' : 'New Message');
                const body = isCallSignal
                  ? `${senderName} is calling you`
                  : isFileMessage
                    ? `${senderName} sent a file: ${payload.fileName}`
                    : `${senderName}: ${(payload.content || '').slice(0, 50)}${(payload.content?.length || 0) > 50 ? '...' : ''}`;

                (window as any).electronAPI.showNotification({
                  title,
                  body,
                  silent: false,
                  data: { from: payload.from, type: isCallSignal ? 'call' : 'message' }
                }).catch((e: Error) => console.error('[EncryptedMessageHandler] Notification failed:', e));
              }
            } catch (e) { console.error('[EncryptedMessageHandler] Notification error:', e); }
          }

          // Handle message deletion first
          if (payload.type === 'delete-message' || payload.type === 'DELETE_MESSAGE') {
            const messageIdToDelete = payload.deleteMessageId || payload.messageId || payload.content;
            if (messageIdToDelete) {
              let messageToPersist: Message | null = null;
              setMessages(prev => {
                const updatedMessages = prev.map(msg => {
                  if (msg.id === messageIdToDelete) {
                    const updated = { ...msg, isDeleted: true, content: 'This message was deleted' } as Message;
                    messageToPersist = updated;
                    return updated;
                  }
                  return msg;
                });
                return updatedMessages;
              });

              // Persist deletion to SecureDB so it survives reloads
              if (messageToPersist) {
                try { await saveMessageToLocalDB(messageToPersist); } catch {
                }
              }

              // Dispatch remote message delete event for reply field updates
              try {
                const deleteEvent = new CustomEvent('remote-message-delete', {
                  detail: { messageId: messageIdToDelete }
                });
                window.dispatchEvent(deleteEvent);
              } catch (_error) {
                console.error('[EncryptedMessageHandler] Failed to dispatch remote delete event:', _error);
              }
            }
            return;
          }

          // Handle message editing
          if (payload.type === 'edit-message' || payload.type === 'EDIT_MESSAGE') {
            const messageIdToEdit = payload.messageId;
            const newContent = payload.content;
            if (messageIdToEdit && newContent) {
              let messageToPersist: Message | null = null;
              setMessages(prev => {
                const updatedMessages = prev.map(msg => {
                  if (msg.id === messageIdToEdit) {
                    const updated = { ...msg, content: newContent, isEdited: true } as Message;
                    messageToPersist = updated;
                    return updated;
                  }
                  return msg;
                });
                return updatedMessages;
              });

              if (messageToPersist) {
                try { await saveMessageToLocalDB(messageToPersist); } catch { }
              }

              // Dispatch remote message edit event for reply field updates
              try {
                const editEvent = new CustomEvent('remote-message-edit', {
                  detail: { messageId: messageIdToEdit, newContent }
                });
                window.dispatchEvent(editEvent);
              } catch (_error) {
                console.error('[EncryptedMessageHandler] Failed to dispatch remote edit event:', _error);
              }
            }

            // Dispatch typing stop event for edit messages (same as normal messages)
            try {
              const typingStopEvent = new CustomEvent('typing-indicator', {
                detail: { from: payload.from, indicatorType: 'typing-stop' }
              });
              window.dispatchEvent(typingStopEvent);
            } catch (_error) {
              console.error('[EncryptedMessageHandler] Failed to dispatch typing stop for edit:', _error);
            }

            return;
          }

          // Handle reactions (add/remove)
          if (payload.type === 'reaction-add' || payload.type === 'REACTION_ADD' || payload.type === 'reaction-remove' || payload.type === 'REACTION_REMOVE') {
            const reactTo = (payload as any).reactTo;
            const emoji = (payload as any).emoji;
            if (reactTo && typeof emoji === 'string' && emoji.length > 0) {
              setMessages(prev => prev.map(msg => {
                if (msg.id !== reactTo) return msg;
                const reactions = { ...(msg.reactions || {}) } as Record<string, string[]>;
                const arr = Array.isArray(reactions[emoji]) ? [...reactions[emoji]] : [];
                const actor = payload.from;
                const has = arr.includes(actor);
                const isAdd = (payload.type === 'reaction-add' || payload.type === 'REACTION_ADD');
                for (const key of Object.keys(reactions)) {
                  if (key !== emoji) {
                    reactions[key] = (reactions[key] || []).filter(u => u !== actor);
                    if (reactions[key].length === 0) delete reactions[key];
                  }
                }
                if (isAdd && !has) arr.push(actor);
                if (!isAdd && has) reactions[emoji] = arr.filter(u => u !== actor);
                else reactions[emoji] = arr;
                if (reactions[emoji].length === 0) delete reactions[emoji];
                return { ...msg, reactions };
              }));
            }
            return;
          }

          // Handle regular messages 
          if ((payload.type === 'message' || payload.type === 'text' || !payload.type) &&
            payload.content && payload.type !== 'file-message') {
            const trimmedContent = payload.content.trim();
            if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
              const typingCheckData = safeJsonParseForMessages(payload.content);
              if (typingCheckData && (typingCheckData.type === 'typing-start' || typingCheckData.type === 'typing-stop')) {
                return;
              }
            }

            // Extract or generate message ID
            let messageId = payload.messageId || uuidv4();
            let messageContent = payload.content;

            // Parse content if it looks like JSON to extract metadata
            if (trimmedContent.startsWith('{') || trimmedContent.startsWith('[')) {
              const contentData = safeJsonParseForMessages(payload.content);
              if (contentData && contentData.messageId) {
                messageId = contentData.messageId;
                messageContent = contentData.content || contentData.message || payload.content;
                // Extract reply data from content
                if (contentData.replyTo) {
                  payload.replyTo = contentData.replyTo;
                }
              }
            }

            const directReplyTo = (payload as any).replyTo;
            if (!payload.replyTo && directReplyTo) {
              payload.replyTo = directReplyTo;
            }

            let messageExists = false;
            let messageAdded = false;
            let replyToForSave: { id: string; sender: string; content: string } | undefined = undefined;

            setMessages(prev => {
              messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                return prev;
              }

              messageAdded = true;
              let replyToFilled: { id: string; sender: string; content: string } | undefined = undefined;
              if (payload.replyTo && typeof payload.replyTo === 'object' && payload.replyTo.id) {
                let replyContent = payload.replyTo.content || '';
                const ref = prev.find(m => m.id === payload.replyTo.id);
                if (!replyContent) {
                  if (ref?.isDeleted) {
                    replyContent = 'Message deleted';
                  } else if (ref?.content) {
                    replyContent = ref.content;
                  }
                }
                // Guard: if still no content after lookup, indicate the message doesn't exist
                if (!replyContent || replyContent.trim().length === 0) {
                  replyContent = "Message doesn't exist";
                }
                replyToFilled = {
                  id: payload.replyTo.id,
                  sender: payload.replyTo.sender || (ref?.sender ?? payload.from),
                  content: replyContent
                };
                // Store for DB persistence outside of state updater
                replyToForSave = replyToFilled;
              }

              const message: Message = {
                id: messageId,
                content: messageContent,
                sender: payload.from,
                recipient: (payload as any)?.to || loginUsernameRef.current,
                timestamp: new Date(payload.timestamp || Date.now()),
                type: 'text',
                isCurrentUser: false,
                p2p: payload.p2p || false,
                encrypted: true,
                version: payload.version || '1.0',
                ...(replyToFilled && { replyTo: replyToFilled })
              };

              return [...prev, message];
            });

            if (!messageExists && messageAdded) {
              try {
                await saveMessageToLocalDB({
                  id: messageId,
                  content: messageContent,
                  sender: payload.from,
                  recipient: (payload as any)?.to || loginUsernameRef.current,
                  p2p: payload.p2p || false,
                  encrypted: true,
                  transport: payload.p2p ? 'p2p' : 'websocket',
                  timestamp: new Date(payload.timestamp || Date.now()),
                  type: 'text',
                  isCurrentUser: false,
                  version: payload.version || '1.0',
                  ...(replyToForSave && { replyTo: replyToForSave })
                });
              } catch (dbError) {
                console.error('[EncryptedMessageHandler] Failed to save message to database:', dbError);
              }
            }

            // Send delivery receipt to the sender as encrypted message - async with bundle request if needed
            (async () => {
              const currentUser = loginUsernameRef.current;
              const senderUsername = payload.from;
              try {
                // Check if we have a session with the sender
                const sessionCheck = await (window as any).edgeApi?.hasSession?.({
                  selfUsername: currentUser,
                  peerUsername: senderUsername,
                  deviceId: 1
                });

                // If no session exists, request bundle and wait for it to be processed
                if (!sessionCheck?.hasSession) {
                  const sessionReadyPromise = new Promise<void>((resolve, reject) => {
                    const timeout = setTimeout(() => {
                      cleanup();
                      reject(new Error('Bundle processing timeout'));
                    }, 10000);

                    const handleSessionReady = (event: Event) => {
                      const customEvent = event as CustomEvent;
                      if (customEvent.detail?.peer === senderUsername) {
                        cleanup();
                        resolve();
                      }
                    };

                    const handleBundleFailed = (event: Event) => {
                      const customEvent = event as CustomEvent;
                      if (customEvent.detail?.peer === senderUsername) {
                        cleanup();
                        reject(new Error(customEvent.detail?.error || 'Bundle not available'));
                      }
                    };

                    const cleanup = () => {
                      clearTimeout(timeout);
                      window.removeEventListener('libsignal-session-ready', handleSessionReady);
                      window.removeEventListener('libsignal-bundle-failed', handleBundleFailed);
                    };

                    window.addEventListener('libsignal-session-ready', handleSessionReady);
                    window.addEventListener('libsignal-bundle-failed', handleBundleFailed);
                  });

                  await websocketClient.sendSecureControlMessage({
                    type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                    username: senderUsername
                  });

                  try {
                    await sessionReadyPromise;
                  } catch {
                    return;
                  }
                }

                const deliveryReceiptData = {
                  messageId: `delivery-receipt-${messageId}`,
                  from: loginUsernameRef.current,
                  to: payload.from,
                  content: 'delivery-receipt',
                  timestamp: Date.now(),
                  messageType: 'signal-protocol',
                  signalType: 'signal-protocol',
                  protocolType: 'signal',
                  type: 'delivery-receipt'
                };

                // Use shared helper to resolve sender's PQ Kyber key
                const { kyber, hybrid } = await resolveSenderHybridKeys(senderUsername);
                if (!hybrid || !hybrid.dilithiumPublicBase64) {
                  return;
                }

                // Use the proper Signal Protocol encryption flow through edgeApi, with one-shot retry on PQ Kyber missing
                let encryptedMessage;
                try {
                  encryptedMessage = await (window as any).edgeApi?.encrypt?.({
                    fromUsername: loginUsernameRef.current,
                    toUsername: payload.from,
                    plaintext: JSON.stringify(deliveryReceiptData),
                    recipientKyberPublicKey: kyber,
                    recipientHybridKeys: hybrid || undefined
                  });
                } catch {
                  return;
                }

                if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
                  const errMsg = String(encryptedMessage?.error || '');
                  if (/session|no valid sessions|no session|invalid whisper message|decryption failed/i.test(errMsg)) {
                    try {
                      const quickWait = new Promise<void>((resolve) => {
                        let settled = false;
                        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
                        const onReady = (evt: Event) => {
                          const d = (evt as CustomEvent).detail;
                          if (d?.peer === senderUsername) {
                            if (!settled) { settled = true; clearTimeout(timeout); }
                            resolve();
                          }
                        };
                        window.addEventListener('libsignal-session-ready', onReady as EventListener, { once: true });
                      });
                      try { await websocketClient.sendSecureControlMessage({ type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, username: senderUsername }); } catch { }
                      await quickWait;
                      try {
                        encryptedMessage = await (window as any).edgeApi?.encrypt?.({
                          fromUsername: loginUsernameRef.current,
                          toUsername: payload.from,
                          plaintext: JSON.stringify(deliveryReceiptData),
                          recipientKyberPublicKey: kyber,
                          recipientHybridKeys: hybrid || undefined
                        });
                      } catch { }
                    } catch { }
                  }

                  if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
                    const receiptKey = `${senderUsername}:${messageId}`;
                    const existing = failedDeliveryReceiptsRef.current.get(receiptKey);
                    const attempts = (existing?.attempts || 0) + 1;

                    if (attempts <= 3) {
                      failedDeliveryReceiptsRef.current.set(receiptKey, {
                        messageId,
                        peerUsername: senderUsername,
                        timestamp: Date.now(),
                        attempts
                      });
                    }
                    return;
                  }
                }

                const deliveryReceiptPayload = {
                  type: SignalType.ENCRYPTED_MESSAGE,
                  to: payload.from,
                  encryptedPayload: encryptedMessage.encryptedPayload
                };

                websocketClient.send(JSON.stringify(deliveryReceiptPayload));

                // Remove from failed queue if it was there
                const receiptKey = `${senderUsername}:${messageId}`;
                failedDeliveryReceiptsRef.current.delete(receiptKey);
              } catch (_error) {
                console.error('[EncryptedMessageHandler] Failed to send delivery receipt:', _error);

                // Queue this receipt for retry
                const receiptKey = `${senderUsername}:${messageId}`;
                const existing = failedDeliveryReceiptsRef.current.get(receiptKey);
                const attempts = (existing?.attempts || 0) + 1;

                if (attempts <= 3) {
                  failedDeliveryReceiptsRef.current.set(receiptKey, {
                    messageId,
                    peerUsername: senderUsername,
                    timestamp: Date.now(),
                    attempts
                  });
                }
              }
            })();
          }

          // Handle file messages
          if (payload.type === 'file-message') {
            let messageId = payload.messageId || uuidv4();
            let fileName = payload.fileName;
            let fileType = payload.fileType || 'application/octet-stream';
            let fileSize = payload.fileSize || 0;
            let dataBase64: string | null = null;

            // Parse content to extract file metadata
            const fileContentData = safeJsonParseForFileMessages(payload.content);
            if (fileContentData) {
              messageId = fileContentData.messageId || messageId;
              fileName = fileContentData.fileName || fileContentData.fileData || payload.fileName;
              fileType = fileContentData.fileType || fileType;
              fileSize = fileContentData.fileSize || fileSize;
              dataBase64 = fileContentData.dataBase64 || null;
            }

            // If inline base64 is present, construct a Blob URL for immediate playback/download
            let contentValue: string = payload.content;
            if (dataBase64 && typeof dataBase64 === 'string') {
              const blobUrl = createBlobUrlFromBase64(dataBase64, fileType, blobCacheRef.current);
              if (blobUrl) {
                contentValue = blobUrl;
              }
            }

            // Check if message already exists to prevent duplicates
            let messageExists = false;
            setMessages(prev => {
              messageExists = prev.some(msg => msg.id === messageId);
              if (messageExists) {
                return prev;
              }

              // Convert base64 data to blob URL for file content if available
              let fileContent = contentValue || fileName || 'File';
              if (dataBase64) {
                const blobUrl = createBlobUrlFromBase64(dataBase64, fileType, blobCacheRef.current);
                if (blobUrl) {
                  fileContent = blobUrl;
                } else {
                  // Fail securely for invalid file data
                  console.error('[EncryptedMessageHandler] Failed to create blob URL, skipping invalid file');
                  messageExists = true;
                }
              }

              const message: Message = {
                id: messageId,
                content: fileContent,
                sender: payload.from,
                recipient: (payload as any)?.to || loginUsernameRef.current,
                timestamp: new Date(payload.timestamp || Date.now()),
                type: 'file',
                isCurrentUser: false,
                filename: fileName,
                mimeType: fileType,
                fileSize: fileSize,
                originalBase64Data: dataBase64,
                version: payload.version || '1.0',
                fileInfo: {
                  name: fileName || 'File',
                  type: fileType,
                  size: fileSize,
                  data: new ArrayBuffer(0)
                }
              };

              return [...prev, message];
            });

            if (!messageExists) {
              // Save to database 
              await saveMessageToLocalDB({
                id: messageId,
                content: contentValue || fileName || 'File',
                sender: payload.from,
                recipient: (payload as any)?.to || loginUsernameRef.current,
                timestamp: new Date(payload.timestamp || Date.now()),
                type: 'file',
                isCurrentUser: false,
                filename: fileName,
                mimeType: fileType,
                fileSize: fileSize,
                originalBase64Data: dataBase64,
                version: payload.version || '1.0',
                fileInfo: {
                  name: fileName || 'File',
                  type: fileType,
                  size: fileSize,
                  data: new ArrayBuffer(0)
                }
              });

              // Save file blob to SecureDB
              if (secureDBRef?.current && dataBase64) {
                try {
                  let cleanBase64 = dataBase64.trim();
                  const inlinePrefixIndex = cleanBase64.indexOf(',');
                  if (inlinePrefixIndex > 0 && inlinePrefixIndex < 128) {
                    cleanBase64 = cleanBase64.slice(inlinePrefixIndex + 1);
                  }
                  const binary = Uint8Array.from(atob(cleanBase64), char => char.charCodeAt(0));
                  const blob = new Blob([binary], { type: fileType || 'application/octet-stream' });
                  const saveResult = await secureDBRef.current.saveFile(messageId, blob);
                  if (!saveResult.success && saveResult.quotaExceeded) {
                    toast.warning('Storage limit reached. This file will not persist after restart.', {
                      duration: 5000
                    });
                  }
                } catch (saveErr) {
                  console.error('[EncryptedMessageHandler] Failed to save file to SecureDB:', saveErr);
                }
              }
            }

            (async () => {
              try {
                const currentUser = loginUsernameRef.current;
                const senderUsername = payload.from;

                // Check if we have a session with the sender
                const sessionCheck = await (window as any).edgeApi?.hasSession?.({
                  selfUsername: currentUser,
                  peerUsername: senderUsername,
                  deviceId: 1
                });

                // If no session exists, request bundle and wait for it to be processed
                if (!sessionCheck?.hasSession) {
                  const sessionReadyPromise = new Promise<void>((resolve, reject) => {
                    const timeout = setTimeout(() => {
                      cleanup();
                      reject(new Error('Bundle processing timeout'));
                    }, 10000);

                    const handleSessionReady = (event: Event) => {
                      const customEvent = event as CustomEvent;
                      if (customEvent.detail?.peer === senderUsername) {
                        cleanup();
                        resolve();
                      }
                    };

                    const handleBundleFailed = (event: Event) => {
                      const customEvent = event as CustomEvent;
                      if (customEvent.detail?.peer === senderUsername) {
                        cleanup();
                        reject(new Error(customEvent.detail?.error || 'Bundle not available'));
                      }
                    };

                    const cleanup = () => {
                      clearTimeout(timeout);
                      window.removeEventListener('libsignal-session-ready', handleSessionReady);
                      window.removeEventListener('libsignal-bundle-failed', handleBundleFailed);
                    };

                    window.addEventListener('libsignal-session-ready', handleSessionReady);
                    window.addEventListener('libsignal-bundle-failed', handleBundleFailed);
                  });

                  await websocketClient.sendSecureControlMessage({
                    type: SignalType.LIBSIGNAL_REQUEST_BUNDLE,
                    username: senderUsername
                  });

                  try {
                    await sessionReadyPromise;
                  } catch {
                    return;
                  }
                }

                const deliveryReceiptData = {
                  messageId: `delivery-receipt-${messageId}`,
                  from: loginUsernameRef.current,
                  to: payload.from,
                  content: 'delivery-receipt',
                  timestamp: Date.now(),
                  messageType: 'signal-protocol',
                  signalType: 'signal-protocol',
                  protocolType: 'signal',
                  type: 'delivery-receipt'
                };

                // Use shared helper to resolve sender's PQ Kyber key
                const { kyber: kyberFile, hybrid: hybridFile } = await resolveSenderHybridKeys(senderUsername);
                if (!hybridFile || !hybridFile.dilithiumPublicBase64) {
                  return;
                }

                // Use the proper Signal Protocol encryption flow through edgeApi
                let encryptedMessage = await (window as any).edgeApi?.encrypt?.({
                  fromUsername: loginUsernameRef.current,
                  toUsername: payload.from,
                  plaintext: JSON.stringify(deliveryReceiptData),
                  recipientKyberPublicKey: kyberFile,
                  recipientHybridKeys: hybridFile || undefined
                });

                if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
                  const errMsg = String(encryptedMessage?.error || '');
                  if (/session|no valid sessions|no session|invalid whisper message|decryption failed/i.test(errMsg)) {
                    try {
                      const quickWait = new Promise<void>((resolve) => {
                        let settled = false;
                        const timeout = setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 1500);
                        const onReady = (evt: Event) => {
                          const d = (evt as CustomEvent).detail;
                          if (d?.peer === senderUsername) {
                            if (!settled) { settled = true; clearTimeout(timeout); }
                            resolve();
                          }
                        };
                        window.addEventListener('libsignal-session-ready', onReady as EventListener, { once: true });
                      });
                      try { await websocketClient.sendSecureControlMessage({ type: SignalType.LIBSIGNAL_REQUEST_BUNDLE, username: senderUsername }); } catch { }
                      await quickWait;
                      encryptedMessage = await (window as any).edgeApi?.encrypt?.({
                        fromUsername: loginUsernameRef.current,
                        toUsername: payload.from,
                        plaintext: JSON.stringify(deliveryReceiptData),
                        recipientKyberPublicKey: kyberFile,
                        recipientHybridKeys: hybridFile || undefined
                      });
                    } catch { }
                  }

                  if (!encryptedMessage?.success || !encryptedMessage?.encryptedPayload) {
                    console.error('[EncryptedMessageHandler] Failed to encrypt delivery receipt for file message');
                    return;
                  }
                }

                const deliveryReceiptPayload = {
                  type: SignalType.ENCRYPTED_MESSAGE,
                  to: payload.from,
                  encryptedPayload: encryptedMessage.encryptedPayload
                };

                websocketClient.send(JSON.stringify(deliveryReceiptPayload));
              } catch (_error) {
                console.error('[EncryptedMessageHandler] Failed to send delivery receipt for file message:', _error);
              }
            })();
          }

          // Handle call signals
          if (payload.type === 'call-signal') {
            const callSignalData = safeJsonParseForCallSignals(payload.content);
            if (callSignalData) {
              try {
                const originalFrom = (payload as any)?.fromOriginal;
                if (typeof originalFrom === 'string') {
                  window.dispatchEvent(new CustomEvent('username-mapping-received', {
                    detail: { hashed: payload.from, original: originalFrom }
                  }));
                  (callSignalData as any).fromOriginal = originalFrom;
                }
              } catch { }
              const callSignalEvent = new CustomEvent('call-signal', {
                detail: callSignalData
              });
              window.dispatchEvent(callSignalEvent);
            } else {
              console.error('[EncryptedMessageHandler] Failed to parse call signal content');
            }
            return;
          }

        }
      } catch (_error) {
        console.error('[EncryptedMessageHandler] Error processing encrypted message:', _error);
      }
    },
    [setMessages, saveMessageToLocalDB, isAuthenticated, getKeysOnDemand, usersRef, handleFileMessageChunk, replenishPqKyberPrekey]
  );

  callbackRef.current = handleEncryptedMessageCallback;

  return handleEncryptedMessageCallback;
}