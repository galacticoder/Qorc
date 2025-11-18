/**
 * P2P Messaging Hook
 * Integrates WebRTC P2P transport with encrypted messaging
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { WebRTCP2PService } from '../lib/webrtc-p2p';
import { CryptoUtils } from '../lib/unified-crypto';
import { SecurityAuditLogger } from '../lib/post-quantum-crypto';

export interface P2PMessage {
  type: 'chat' | 'signal' | 'heartbeat' | 'dummy' | 'typing' | 'reaction' | 'file' | 'delivery-ack' | 'read-receipt';
  from: string;
  to: string;
  timestamp: number;
  payload: any;
  signature?: string;
}

export interface EncryptedMessage {
  id: string;
  from: string;
  to: string;
  content: string;
  timestamp: number;
  encrypted: boolean;
  p2p: boolean;
  transport?: 'p2p';
  routeProof?: string;
  messageType?: 'text' | 'typing' | 'reaction' | 'file' | 'edit' | 'delete';
  metadata?: any;
}

export interface P2PStatus {
  isInitialized: boolean;
  connectedPeers: string[];
  signalingConnected: boolean;
  lastError: string | null;
}

export type P2PSendStatus =
  | 'sent'
  | 'queued_not_connected'
  | 'queued_no_session'
  | 'fatal_validation'
  | 'fatal_keys'
  | 'fatal_transport';

export interface P2PSendResult {
  status: P2PSendStatus;
  messageId?: string;
  errorCode?: string;
  errorMessage?: string;
}

export interface PeerCertificateBundle {
  username: string;
  dilithiumPublicKey: string;
  kyberPublicKey: string;
  x25519PublicKey?: string;
  proof: string;
  issuedAt: number;
  expiresAt: number;
  signature: string;
}

export interface HybridKeys {
  dilithium: {
    secretKey: Uint8Array;
    publicKeyBase64: string;
  };
  kyber?: {
    secretKey: Uint8Array;
  };
  x25519?: {
    private: Uint8Array;
  };
}

export interface RemoteHybridKeys {
  dilithiumPublicBase64: string;
  kyberPublicBase64: string;
  x25519PublicBase64?: string;
}

const MAX_INCOMING_QUEUE = 256;
const MAX_PEER_CACHE = 256;
const PEER_CACHE_TTL_MS = 5 * 60 * 1000;
const ROUTE_PROOF_TTL_MS = 60 * 1000;
const MAX_CERT_CACHE_SIZE = 128;
const MAX_ROUTE_PROOF_CACHE_SIZE = 512;
const MAX_MESSAGE_CONTENT_LENGTH = 64 * 1024;
const MAX_USERNAME_LENGTH = 96;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_MESSAGES = 200;
const CERT_CLOCK_SKEW_MS = 2 * 60 * 1000;

const createP2PError = (code: string) => {
  const error = new Error(code);
  error.name = 'P2PError';
  (error as Error & { code?: string }).code = code;
  return error;
};

const concatUint8Arrays = (...arrays: Uint8Array[]) => {
  const total = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  arrays.forEach((arr) => {
    merged.set(arr, offset);
    offset += arr.length;
  });
  return merged;
};

const getChannelId = (localKey: string, remoteKey: string) =>
  localKey < remoteKey ? `${localKey}|${remoteKey}` : `${remoteKey}|${localKey}`;

const sanitizeErrorMessage = (error: unknown): string => {
  if (!error) return 'UNKNOWN';
  if (typeof error === 'string') return error.slice(0, 80);
  if (error instanceof Error) return error.message.slice(0, 80);
  return 'UNRECOGNIZED_ERROR';
};

const createBoundedQueue = <T,>(maxSize: number) => {
  const queue: T[] = [];
  return {
    push(item: T) {
      queue.push(item);
      if (queue.length > maxSize) {
        queue.shift();
      }
    },
    items() {
      return [...queue];
    },
    clear() {
      queue.length = 0;
    },
  };
};

const buildAuthenticator = () => {
  const cache = new Map<string, { expiresAt: number }>();
  return {
    memoize(key: string) {
      const cached = cache.get(key);
      if (cached && cached.expiresAt > Date.now()) {
        return true;
      }
      return false;
    },
    store(key: string, ttlMs: number) {
      cache.set(key, { expiresAt: Date.now() + ttlMs });
      if (cache.size > MAX_PEER_CACHE) {
        const now = Date.now();
        for (const [entryKey, entry] of cache) {
          if (entry.expiresAt <= now) {
            cache.delete(entryKey);
          }
        }
      }
    },
  };
};

const toUint8 = (base64?: string) => {
  if (!base64) return null;
  try {
    return CryptoUtils.Base64.base64ToUint8Array(base64);
  } catch {
    return null;
  }
};

const getCrypto = () => {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj?.subtle) {
    throw new Error('WebCrypto unavailable');
  }
  return cryptoObj;
};

const generateRandomBase64 = (length = 48) => {
  const cryptoObj = getCrypto();
  const bytes = cryptoObj.getRandomValues(new Uint8Array(length));
  return CryptoUtils.Base64.arrayBufferToBase64(bytes);
};

const generateMessageId = async (channelId: string, sequence: number) => {
  const cryptoObj = getCrypto();
  const randomBytes = cryptoObj.getRandomValues(new Uint8Array(48));
  const sequenceBuffer = new Uint8Array(8);
  new DataView(sequenceBuffer.buffer).setUint32(4, sequence, false);
  const channelBytes = new TextEncoder().encode(channelId);
  const material = concatUint8Arrays(randomBytes, sequenceBuffer, channelBytes);
  const macKey = cryptoObj.getRandomValues(new Uint8Array(32));
  const mac = await CryptoUtils.Hash.generateBlake3Mac(material, macKey);
  return CryptoUtils.Base64.arrayBufferToBase64(mac).replace(/[^a-zA-Z0-9]/g, '').slice(0, 48);
};

const buildRouteProof = async (
  localDilithiumSecret: Uint8Array,
  localDilithiumPublic: string,
  peerDilithiumPublic: string,
  channelId: string,
  sequence: number,
) => {
  const cryptoObj = getCrypto();
  const nonce = cryptoObj.getRandomValues(new Uint8Array(24));
  const expiresAt = Date.now() + ROUTE_PROOF_TTL_MS;
  const payload = {
    kind: 'route-proof-v1',
    nonce: CryptoUtils.Base64.arrayBufferToBase64(nonce),
    at: Date.now(),
    expiresAt,
    from: localDilithiumPublic,
    to: peerDilithiumPublic,
    channelId,
    sequence,
  };
  // Create deterministic canonical form by sorting keys alphabetically
  const canonicalPayload = {
    at: payload.at,
    channelId: payload.channelId,
    expiresAt: payload.expiresAt,
    from: payload.from,
    kind: payload.kind,
    nonce: payload.nonce,
    sequence: payload.sequence,
    to: payload.to,
  };
  const canonical = new TextEncoder().encode(JSON.stringify(canonicalPayload));
  const signature = await CryptoUtils.Dilithium.sign(localDilithiumSecret, canonical);
  return {
    payload,
    signature: CryptoUtils.Base64.arrayBufferToBase64(signature),
  };
};

const verifyRouteProof = async (
  proof: { payload: any; signature: string } | undefined,
  localDilithiumPublic: string,
  peerDilithiumPublic: string,
  channelId: string,
  minSequence: number,
) => {
  if (!proof?.payload || !proof.signature) {
    return false;
  }
  const { kind, nonce, at, from, to, channelId: proofChannel, sequence, expiresAt } = proof.payload;
  if (kind !== 'route-proof-v1') {
    return false;
  }
  if (typeof at !== 'number' || typeof expiresAt !== 'number') {
    return false;
  }
  const now = Date.now();
  // Allow small clock skew when checking route proof time window
  if (at > (now + CERT_CLOCK_SKEW_MS) || expiresAt <= (now - CERT_CLOCK_SKEW_MS) || expiresAt - at > ROUTE_PROOF_TTL_MS) {
    return false;
  }
  if (typeof sequence !== 'number' || sequence < minSequence) {
    return false;
  }
  if (from !== peerDilithiumPublic || to !== localDilithiumPublic) {
    return false;
  }
  if (proofChannel !== channelId) {
    return false;
  }
  const nonceBytes = toUint8(nonce);
  if (!nonceBytes || nonceBytes.length !== 24) {
    return false;
  }
  const signatureBytes = toUint8(proof.signature);
  if (!signatureBytes) {
    return false;
  }
  // Create deterministic canonical form by sorting keys alphabetically
  const canonicalPayload = {
    at: at,
    channelId: proofChannel,
    expiresAt: expiresAt,
    from: from,
    kind: kind,
    nonce: nonce,
    sequence: sequence,
    to: to,
  };
  const canonical = new TextEncoder().encode(JSON.stringify(canonicalPayload));
  const peerKey = toUint8(peerDilithiumPublic);
  if (!peerKey) {
    return false;
  }
  try {
    const result = await CryptoUtils.Dilithium.verify(signatureBytes, canonical, peerKey);
    return result;
  } catch {
    return false;
  }
};

export function useP2PMessaging(
  username: string,
  hybridKeys: HybridKeys | null,
  options?: {
    fetchPeerCertificates?: (peer: string) => Promise<PeerCertificateBundle | null>;
    signalingTokenProvider?: () => Promise<string | null>;
    onServiceReady?: (service: WebRTCP2PService | null) => void;
    trustedIssuerDilithiumPublicKeyBase64?: string;
  },
) {
  const p2pServiceRef = useRef<WebRTCP2PService | null>(null);
  const [p2pStatus, setP2PStatus] = useState<P2PStatus>({
    isInitialized: false,
    connectedPeers: [],
    signalingConnected: false,
    lastError: null,
  });
  const incomingQueueRef = useRef(createBoundedQueue<EncryptedMessage>(MAX_INCOMING_QUEUE));
  const [incomingMessages, setIncomingMessages] = useState<EncryptedMessage[]>([]);
  const messageCallbackRef = useRef<((message: EncryptedMessage) => void) | null>(null);
  const peerAuthCacheRef = useRef(buildAuthenticator());
  const peerWaitersRef = useRef(new Map<string, Set<(ok: boolean) => void>>());
  const peerCertificateCacheRef = useRef(new Map<string, { cert: PeerCertificateBundle; expiresAt: number }>());
  const routeProofCacheRef = useRef(new Map<string, { proof: { payload: any; signature: string }; expiresAt: number }>());
  const channelSequenceRef = useRef(new Map<string, number>());
  const authLockRef = useRef<Promise<void> | null>(null);
  const rateLimitRef = useRef<Map<string, { windowStart: number; count: number }>>(new Map());
  const handleIncomingP2PMessageRef = useRef<((message: P2PMessage) => Promise<void>) | null>(null);
  
  // Deduplicate P2P read-receipts we send (per messageId)
  const sentP2PReceiptsRef = useRef<Map<string, number>>(new Map());
  // Deduplicate incoming read-receipts we process (avoid event storms)
  const processedReadReceiptsRef = useRef<Set<string>>(new Set());
  const RECEIPT_RETENTION_MS = 24 * 60 * 60 * 1000; // 24h

  // Secure outbound P2P queue (stores already-hybrid-encrypted envelopes; memory-only, TTL enforced)
  type QueuedItem = { to: string; envelope: any; type: 'text' | 'typing' | 'reaction' | 'file'; enqueuedAt: number; ttlMs: number };
  const outboundQueueRef = useRef(new Map<string, QueuedItem[]>());
  const flushTimersRef = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  // Use a ref to always call the latest flush function from timers (avoids stale closures)
  const flushPeerQueueRef = useRef<(peer: string) => void>(() => {});

  const appendIncoming = useCallback((message: EncryptedMessage) => {
    incomingQueueRef.current.push(message);
    setIncomingMessages(incomingQueueRef.current.items());
  }, []);

  const setLastError = useCallback((error: unknown) => {
    const sanitized = sanitizeErrorMessage(error);
    setP2PStatus((prev) => ({
      ...prev,
      lastError: sanitized,
    }));
  }, []);

  const clearLastError = useCallback(() => {
    setP2PStatus((prev) => ({
      ...prev,
      lastError: null,
    }));
  }, []);

  const destroyService = useCallback(() => {
    if (p2pServiceRef.current) {
      try {
        p2pServiceRef.current.destroy();
      } catch (_error) {
      }
      options?.onServiceReady?.(null);
      p2pServiceRef.current = null;
    }
    routeProofCacheRef.current.clear();
    peerCertificateCacheRef.current.clear();
    peerAuthCacheRef.current = buildAuthenticator();
    try {
      outboundQueueRef.current.forEach((arr) => arr.forEach(it => { try { it.envelope = null; } catch {} }));
      outboundQueueRef.current.clear();
    } catch {}
    flushTimersRef.current.forEach(t => clearTimeout(t));
    flushTimersRef.current.clear();
    incomingQueueRef.current.clear();
    setIncomingMessages([]);
    setP2PStatus((prev) => ({
      ...prev,
      isInitialized: false,
      connectedPeers: [],
      signalingConnected: false,
    }));
  }, []);

  const deriveConversationKey = useCallback(
    (peer: string) => {
      if (!hybridKeys?.dilithium?.publicKeyBase64) return null;
      return `${hybridKeys.dilithium.publicKeyBase64}:${peer}`;
    },
    [hybridKeys?.dilithium?.publicKeyBase64],
  );

  const invalidatePeerCert = useCallback((peerUsername: string) => {
    if (!peerUsername) return;
    peerCertificateCacheRef.current.delete(peerUsername);
    const keysToDelete: string[] = [];
    for (const [key] of routeProofCacheRef.current) {
      if (key.includes(peerUsername)) {
        keysToDelete.push(key);
      }
    }
    for (const key of keysToDelete) {
      routeProofCacheRef.current.delete(key);
    }
  }, []);

  const getPeerCertificate = useCallback(
    async (peerUsername: string, bypassCache = false) => {
      const now = Date.now();
      const cached = bypassCache ? null : peerCertificateCacheRef.current.get(peerUsername);
      if (cached && cached.expiresAt > now) {
        return cached.cert;
      }
      if (!options?.fetchPeerCertificates) {
        return null;
      }
      try {
        const cert = await options.fetchPeerCertificates(peerUsername);
        if (!cert) {
          return null;
        }
        const dilithiumKey = toUint8(cert.dilithiumPublicKey);
        const signature = toUint8(cert.signature);
        if (!dilithiumKey || !signature) {
          return null;
        }
        const canonical = new TextEncoder().encode(
          JSON.stringify({
            username: cert.username,
            dilithiumPublicKey: cert.dilithiumPublicKey,
            kyberPublicKey: cert.kyberPublicKey,
            x25519PublicKey: cert.x25519PublicKey,
            proof: cert.proof,
            issuedAt: cert.issuedAt,
            expiresAt: cert.expiresAt,
          }),
        );
        const issuerKey = toUint8(cert.proof);
        if (!issuerKey) return null;
        const valid = await CryptoUtils.Dilithium.verify(signature, canonical, issuerKey);
        if (!valid) {
          throw new Error('CERT_INVALID_SIGNATURE');
        }
        if (options?.trustedIssuerDilithiumPublicKeyBase64 && cert.proof !== options.trustedIssuerDilithiumPublicKeyBase64) {
          throw new Error('CERT_UNTRUSTED_ISSUER');
        }
        const notYetValid = cert.issuedAt > (now + CERT_CLOCK_SKEW_MS);
        const alreadyExpired = cert.expiresAt <= (now - CERT_CLOCK_SKEW_MS);
        if (notYetValid || alreadyExpired) {
          throw new Error('CERT_INVALID_WINDOW');
        }
        peerCertificateCacheRef.current.set(peerUsername, {
          cert,
          expiresAt: Math.min(cert.expiresAt, now + PEER_CACHE_TTL_MS),
        });
        if (peerCertificateCacheRef.current.size > MAX_CERT_CACHE_SIZE) {
          const entries = [...peerCertificateCacheRef.current.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
          while (entries.length > MAX_CERT_CACHE_SIZE) {
            const [key] = entries.shift()!;
            peerCertificateCacheRef.current.delete(key);
          }
        }
        return cert;
      } catch {
        return null;
      }
    },
    [options?.fetchPeerCertificates],
  );

  const ensurePeerAuthenticated = useCallback(
    async (peerUsername: string, envelope?: any) => {
      const conversationKey = deriveConversationKey(peerUsername);
      if (!conversationKey) return false;
      if (peerAuthCacheRef.current.memoize(conversationKey)) {
        return true;
      }

      const cert = await getPeerCertificate(peerUsername);
      if (!cert) {
        return false;
      }

      const dilithiumKey = toUint8(cert.dilithiumPublicKey);
      const kyberKey = toUint8(cert.kyberPublicKey);
      if (!dilithiumKey || !kyberKey) {
        return false;
      }

      if (envelope?.metadata?.sender?.dilithiumPublicKey !== cert.dilithiumPublicKey) {
        return false;
      }

      const proofRecord = routeProofCacheRef.current.get(conversationKey);
      if (!proofRecord || proofRecord.expiresAt <= Date.now()) {
        const routeProof = await buildRouteProof(
          hybridKeys.dilithium.secretKey,
          hybridKeys.dilithium.publicKeyBase64,
          cert.dilithiumPublicKey,
          getChannelId(hybridKeys.dilithium.publicKeyBase64, cert.dilithiumPublicKey),
          (channelSequenceRef.current.get(conversationKey) ?? 0) + 1,
        );
        routeProofCacheRef.current.set(conversationKey, {
          proof: routeProof,
          expiresAt: Date.now() + ROUTE_PROOF_TTL_MS,
        });
        if (routeProofCacheRef.current.size > MAX_ROUTE_PROOF_CACHE_SIZE) {
          const entries = [...routeProofCacheRef.current.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
          while (entries.length > MAX_ROUTE_PROOF_CACHE_SIZE) {
            const [key] = entries.shift()!;
            routeProofCacheRef.current.delete(key);
          }
        }
        channelSequenceRef.current.set(conversationKey, (channelSequenceRef.current.get(conversationKey) ?? 0) + 1);
      }

      peerAuthCacheRef.current.store(conversationKey, PEER_CACHE_TTL_MS);
      return true;
    },
    [deriveConversationKey, getPeerCertificate, hybridKeys?.dilithium],
  );

  const initializeP2P = useCallback(
    async (signalingServerUrl: string) => {
      clearLastError();
      try {
        if (p2pServiceRef.current) {
          try {
            p2pServiceRef.current.destroy();
          } catch (_error) {
          }
          options?.onServiceReady?.(null);
          p2pServiceRef.current = null;
        }
        // Clear caches and queues
        routeProofCacheRef.current.clear();
        peerCertificateCacheRef.current.clear();
        peerAuthCacheRef.current = buildAuthenticator();
        outboundQueueRef.current.forEach((arr) => arr.forEach(it => { try { it.envelope = null; } catch {} }));
        outboundQueueRef.current.clear();
        flushTimersRef.current.forEach(t => clearTimeout(t));
        flushTimersRef.current.clear();
        incomingQueueRef.current.clear();
        setIncomingMessages([]);
        
        if (!username || !hybridKeys?.dilithium?.secretKey) {
          throw createP2PError('AUTH_REQUIRED');
        }
        try { SecurityAuditLogger.log('info', 'p2p-initiate', { server: signalingServerUrl, user: username }); } catch {}

        const service = new WebRTCP2PService(username);
        p2pServiceRef.current = service;
        options?.onServiceReady?.(service);
        const dilithiumPublic = toUint8(hybridKeys.dilithium.publicKeyBase64);
        const dilithiumSecret = hybridKeys.dilithium.secretKey;
        if (dilithiumPublic && dilithiumSecret) {
          service.setDilithiumKeys({ publicKey: dilithiumPublic, secretKey: dilithiumSecret });
        }

        service.onMessage((message: P2PMessage) => {
          handleIncomingP2PMessageRef.current?.(message).catch(() => {
          });
        });

        service.onPeerConnected((peerUsername: string) => {
          setP2PStatus((prev) => ({
            ...prev,
            connectedPeers: [...new Set([...prev.connectedPeers, peerUsername])],
          }));
          // Resolve any pending waiters for this peer
          try {
            const set = peerWaitersRef.current.get(peerUsername);
            if (set) {
              set.forEach(fn => { try { fn(true); } catch {} });
              peerWaitersRef.current.delete(peerUsername);
            }
          } catch {}
          try { SecurityAuditLogger.log('info', 'p2p-peer-connected', { peer: peerUsername }); } catch {}
          
          try {
            window.dispatchEvent(new CustomEvent('p2p-peer-reconnected', { detail: { peer: peerUsername } }));
          } catch {}
          
          try { window.dispatchEvent(new CustomEvent('p2p-peer-connected', { detail: { peer: peerUsername } })); } catch {}
          clearLastError();
        });

        service.onPeerDisconnected((peerUsername: string) => {
          setP2PStatus((prev) => ({
            ...prev,
            connectedPeers: prev.connectedPeers.filter((p) => p !== peerUsername),
          }));
          try { SecurityAuditLogger.log('info', 'p2p-peer-disconnected', { peer: peerUsername }); } catch {}
        });

        const token = (await options?.signalingTokenProvider?.()) ?? null;
        const registerPayload = {
          username,
          timestamp: Date.now(),
          nonce: generateRandomBase64(32),
          token,
        };
        const canonical = new TextEncoder().encode(JSON.stringify(registerPayload));
        const registrationSig = await CryptoUtils.Dilithium.sign(hybridKeys.dilithium.secretKey, canonical);

        await service.initialize(signalingServerUrl, {
          registerPayload,
          registrationSignature: CryptoUtils.Base64.arrayBufferToBase64(registrationSig),
          registrationPublicKey: hybridKeys.dilithium.publicKeyBase64,
        });
        try { SecurityAuditLogger.log('info', 'p2p-init-complete', { server: signalingServerUrl }); } catch {}

        setP2PStatus((prev) => ({
          ...prev,
          isInitialized: true,
          signalingConnected: true,
          lastError: null,
        }));
      } catch (_error) {
        setLastError(_error);
        destroyService();
      }
    },
    [clearLastError, destroyService, hybridKeys, options, username],
  );

  const connectToPeer = useCallback(
    async (peerUsername: string) => {
      if (!p2pServiceRef.current) {
        throw createP2PError('SERVICE_UNINITIALIZED');
      }
      try { SecurityAuditLogger.log('info', 'p2p-connect-request', { peer: peerUsername }); } catch {}
      if (!hybridKeys?.dilithium?.secretKey) {
        throw createP2PError('LOCAL_KEYS_MISSING');
      }

      const cert = await getPeerCertificate(peerUsername);
      if (!cert) {
        throw createP2PError('PEER_CERT_MISSING');
      }

      const conversationKey = deriveConversationKey(peerUsername);
      if (!conversationKey) {
        throw createP2PError('CONVERSATION_KEY_MISSING');
      }

      if (!authLockRef.current) {
        authLockRef.current = (async () => {
          const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, cert.dilithiumPublicKey);
          const sequence = (channelSequenceRef.current.get(conversationKey) ?? 0) + 1;
          const routeProof = await buildRouteProof(
            hybridKeys.dilithium.secretKey,
            hybridKeys.dilithium.publicKeyBase64,
            cert.dilithiumPublicKey,
            channelId,
            sequence,
          );
          routeProofCacheRef.current.set(conversationKey, {
            proof: routeProof,
            expiresAt: Date.now() + ROUTE_PROOF_TTL_MS,
          });
          channelSequenceRef.current.set(conversationKey, sequence);
        })();
      }
      await authLockRef.current.finally(() => {
        authLockRef.current = null;
      });

      try {
        // Provide peer's Dilithium public key to transport for signature verification
        try {
          const pk = toUint8(cert.dilithiumPublicKey);
          if (pk) p2pServiceRef.current.addPeerDilithiumKey(peerUsername, pk);
        } catch {}
        await p2pServiceRef.current.connectToPeer(peerUsername, {
          peerCertificate: cert,
          routeProof: routeProofCacheRef.current.get(conversationKey)?.proof,
        });
        try { SecurityAuditLogger.log('info', 'p2p-connect-dispatched', { peer: peerUsername }); } catch {}
      } catch (_error) {
        try { SecurityAuditLogger.log('warn', 'p2p-connect-error', { peer: peerUsername, error: String((_error as any)?.message || _error) }); } catch {}
        setLastError(_error);
        throw _error;
      }
    },
    [deriveConversationKey, getPeerCertificate, hybridKeys?.dilithium, setLastError],
  );

  const isPeerConnected = useCallback(
    (peerUsername: string): boolean => p2pStatus.connectedPeers.includes(peerUsername),
    [p2pStatus.connectedPeers],
  );

  const enqueueOutbound = useCallback((to: string, envelope: any, type: 'text' | 'typing' | 'reaction' | 'file', ttlMs: number) => {
    const now = Date.now();
    const arr = outboundQueueRef.current.get(to) || [];
    const pruned = arr.filter(it => (now - it.enqueuedAt) < it.ttlMs).slice(-MAX_INCOMING_QUEUE);
    pruned.push({ to, envelope, type, enqueuedAt: now, ttlMs });
    outboundQueueRef.current.set(to, pruned);
    const existing = flushTimersRef.current.get(to);
    if (!existing) {
      const t = setTimeout(() => {
        flushTimersRef.current.delete(to);
        try { flushPeerQueueRef.current(to); } catch {}
      }, 300);
      flushTimersRef.current.set(to, t);
    }
  }, []);

  const flushPeerQueue = useCallback((peer: string) => {
    const service = p2pServiceRef.current;
    if (!service) return;
    const connectedPeers = service.getConnectedPeers();
    if (!connectedPeers.includes(peer)) return;
    const arr = outboundQueueRef.current.get(peer) || [];
    if (arr.length === 0) return;
    const now = Date.now();
    const remaining: QueuedItem[] = [];
    for (const item of arr) {
      if (now - item.enqueuedAt >= item.ttlMs) {
        try { item.envelope = null; } catch {}
        continue;
      }
      try {
        service.sendMessage(peer, item.envelope, item.type === 'text' ? 'chat' : item.type);
        try { item.envelope = null; } catch {}
      } catch (_e) {
        remaining.push(item);
      }
    }
    if (remaining.length > 0) {
      outboundQueueRef.current.set(peer, remaining);
      const t = setTimeout(() => {
        flushTimersRef.current.delete(peer);
        flushPeerQueue(peer);
      }, 1000);
      flushTimersRef.current.set(peer, t);
    } else {
      outboundQueueRef.current.delete(peer);
    }
  }, []);

  useEffect(() => {
    flushPeerQueueRef.current = flushPeerQueue;
  }, [flushPeerQueue]);

  const sendP2PMessage = useCallback(
    async (
      to: string,
      content: string,
      remoteHybridKeys?: RemoteHybridKeys,
      options?: {
        messageType?: 'text' | 'typing' | 'reaction' | 'file' | 'edit' | 'delete';
        metadata?: any;
      }
    ): Promise<P2PSendResult> => {
      if (!p2pServiceRef.current) {
        throw createP2PError('SERVICE_UNINITIALIZED');
      }
      if (!hybridKeys?.dilithium?.secretKey || !hybridKeys?.dilithium?.publicKeyBase64) {
        throw createP2PError('LOCAL_KEYS_MISSING');
      }

      if (!to || typeof to !== 'string' || to.length === 0 || to.length > MAX_USERNAME_LENGTH) {
        throw createP2PError('INVALID_RECIPIENT');
      }

      const isTyping = options?.messageType === 'typing';
      const isReaction = options?.messageType === 'reaction';
      const allowEmptyContent = isTyping || isReaction || (options?.metadata?.targetMessageId && typeof options.metadata.targetMessageId === 'string');

      if (!allowEmptyContent && (!content || typeof content !== 'string' || content.length === 0 || content.length > MAX_MESSAGE_CONTENT_LENGTH)) {
        throw createP2PError('INVALID_CONTENT');
      }

      if (typeof content !== 'string') {
        throw createP2PError('INVALID_CONTENT');
      }

      if (content.length > MAX_MESSAGE_CONTENT_LENGTH) {
        throw createP2PError('INVALID_CONTENT');
      }

      let effectiveRemoteKeys: RemoteHybridKeys | null = remoteHybridKeys ?? null;
      if (!effectiveRemoteKeys?.kyberPublicBase64 || !effectiveRemoteKeys?.dilithiumPublicBase64) {
        const peerCert = await getPeerCertificate(to);
        if (peerCert?.kyberPublicKey && peerCert?.dilithiumPublicKey) {
          effectiveRemoteKeys = {
            kyberPublicBase64: peerCert.kyberPublicKey,
            dilithiumPublicBase64: peerCert.dilithiumPublicKey,
            x25519PublicBase64: peerCert.x25519PublicKey,
          };
        }
      }
      if (!effectiveRemoteKeys?.kyberPublicBase64) {
        throw createP2PError('MISSING_REMOTE_KYBER_KEY');
      }
      if (!effectiveRemoteKeys.dilithiumPublicBase64) {
        throw createP2PError('MISSING_REMOTE_DILITHIUM_KEY');
      }

      if (!isTyping) {
        const now = Date.now();
        const bucket = rateLimitRef.current.get(to) ?? { windowStart: now, count: 0 };
        if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        rateLimitRef.current.set(to, bucket);
        if (bucket.count > RATE_LIMIT_MAX_MESSAGES) {
          throw createP2PError('RATE_LIMIT_EXCEEDED');
        }
      }

      const conversationKey = deriveConversationKey(to);
      if (!conversationKey) throw createP2PError('CONVERSATION_KEY_MISSING');

      await ensurePeerAuthenticated(to);

      const peerCert = await getPeerCertificate(to);
      if (!peerCert?.dilithiumPublicKey) {
        throw createP2PError('PEER_CERT_MISSING');
      }

      let routeProofRecord = routeProofCacheRef.current.get(conversationKey);
      if (!routeProofRecord || routeProofRecord.expiresAt <= Date.now()) {
        const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, peerCert.dilithiumPublicKey);
        const sequence = (channelSequenceRef.current.get(conversationKey) ?? 0) + 1;
        const routeProof = await buildRouteProof(
          hybridKeys.dilithium.secretKey,
          hybridKeys.dilithium.publicKeyBase64,
          peerCert.dilithiumPublicKey,
          channelId,
          sequence,
        );
        routeProofRecord = {
          proof: routeProof,
          expiresAt: Date.now() + ROUTE_PROOF_TTL_MS,
        };
        routeProofCacheRef.current.set(conversationKey, routeProofRecord);
        channelSequenceRef.current.set(conversationKey, sequence);
      }

      // Generate messageId outside try block to avoid scoping issues
      const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, peerCert.dilithiumPublicKey);
      const messageId = await generateMessageId(channelId, channelSequenceRef.current.get(conversationKey) ?? 0);

      try {
        const messageObj = {
          id: messageId,
          content,
          timestamp: Date.now(),
          from: hybridKeys.dilithium.publicKeyBase64,
          to,
          routeProof: routeProofRecord.proof,
          messageType: options?.messageType || 'text',
          metadata: options?.metadata,
        };

        const encryptedEnvelope = await CryptoUtils.Hybrid.encryptForClient(messageObj, effectiveRemoteKeys, {
          to: peerCert.dilithiumPublicKey,
          from: hybridKeys.dilithium.publicKeyBase64,
          type: `p2p-${options?.messageType || 'message'}`,
          senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
          senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
          timestamp: Date.now(),
          extras: {
            routeProof: routeProofRecord.proof,
            messageType: options?.messageType || 'text',
          },
        });

        // Determine P2P message type
        let p2pType: 'chat' | 'typing' | 'reaction' | 'file' = 'chat';
        if (options?.messageType === 'typing') p2pType = 'typing';
        else if (options?.messageType === 'reaction') p2pType = 'reaction';
        else if (options?.messageType === 'file') p2pType = 'file';

        try { SecurityAuditLogger.log('info', 'p2p-send-request', { to, type: p2pType }); } catch {}
        const connectedPeers = p2pServiceRef.current?.getConnectedPeers() ?? [];
        const serviceConnected = connectedPeers.includes(to);
        if (!serviceConnected) {
          const ttl = p2pType === 'typing' ? 5000 : p2pType === 'reaction' ? 30000 : p2pType === 'file' ? 180000 : 120000;
          enqueueOutbound(to, encryptedEnvelope, p2pType, ttl);
          try { SecurityAuditLogger.log('info', 'p2p-enqueued-not-connected', { to, type: p2pType }); } catch {}
          connectToPeer(to).catch(() => {
          });
          setLastError(createP2PError('PEER_NOT_CONNECTED'));
          return { status: 'queued_not_connected', messageId };
        }

        await p2pServiceRef.current.sendMessage(to, encryptedEnvelope, p2pType);
        try { SecurityAuditLogger.log('info', 'p2p-send-ok', { to, type: p2pType }); } catch {}
        return { status: 'sent', messageId };
      } catch (_error) {
        try { SecurityAuditLogger.log('warn', 'p2p-send-error', { to, error: String((_error as any)?.message || _error) }); } catch {}
        const errorMsg = String((_error as any)?.message || _error);
        const errorCode = (_error as any)?.code as string | undefined;

        try {
          console.error('[P2P] sendP2PMessage error', {
            to,
            type: options?.messageType || 'text',
            code: errorCode,
            message: errorMsg,
          });
        } catch {}

        if (errorMsg.includes('no PQ session') || errorMsg.includes('without established PQ session')) {
          try {
            const p2pType: 'chat' | 'typing' | 'reaction' | 'file' =
              options?.messageType === 'typing' ? 'typing'
              : options?.messageType === 'reaction' ? 'reaction'
              : options?.messageType === 'file' ? 'file'
              : 'chat';
            const ttl = p2pType === 'typing' ? 5000 : p2pType === 'reaction' ? 30000 : p2pType === 'file' ? 180000 : 120000;
            const messageObj = {
              id: messageId,
              content,
              timestamp: Date.now(),
              from: hybridKeys.dilithium.publicKeyBase64,
              to,
              routeProof: routeProofRecord.proof,
              messageType: options?.messageType || 'text',
              metadata: options?.metadata,
            };
            const encryptedEnvelope = await CryptoUtils.Hybrid.encryptForClient(messageObj, effectiveRemoteKeys, {
              to: peerCert.dilithiumPublicKey,
              from: hybridKeys.dilithium.publicKeyBase64,
              type: `p2p-${options?.messageType || 'message'}`,
              senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
              senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
              timestamp: Date.now(),
              extras: {
                routeProof: routeProofRecord.proof,
                messageType: options?.messageType || 'text',
              },
            });
            enqueueOutbound(to, encryptedEnvelope, p2pType, ttl);
            try { SecurityAuditLogger.log('info', 'p2p-enqueued-no-session', { to, type: p2pType }); } catch {}
          } catch {}
          setLastError(_error);
          return {
            status: 'queued_no_session',
            messageId,
            errorCode,
            errorMessage: errorMsg,
          };
        }

        try {
          const p2pType: 'chat' | 'typing' | 'reaction' | 'file' =
            options?.messageType === 'typing' ? 'typing'
            : options?.messageType === 'reaction' ? 'reaction'
            : options?.messageType === 'file' ? 'file'
            : 'chat';
          const ttl = p2pType === 'typing' ? 5000 : p2pType === 'reaction' ? 30000 : p2pType === 'file' ? 180000 : 120000;
          const messageObj = {
            id: messageId,
            content,
            timestamp: Date.now(),
            from: hybridKeys.dilithium.publicKeyBase64,
            to,
            routeProof: routeProofRecord.proof,
            messageType: options?.messageType || 'text',
            metadata: options?.metadata,
          };
          const encryptedEnvelope = await CryptoUtils.Hybrid.encryptForClient(messageObj, effectiveRemoteKeys, {
            to: peerCert.dilithiumPublicKey,
            from: hybridKeys.dilithium.publicKeyBase64,
            type: `p2p-${options?.messageType || 'message'}`,
            senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
            senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
            timestamp: Date.now(),
            extras: {
              routeProof: routeProofRecord.proof,
              messageType: options?.messageType || 'text',
            },
          });
          enqueueOutbound(to, encryptedEnvelope, p2pType, ttl);
        } catch {}
        setLastError(_error);
        return {
          status: 'fatal_transport',
          messageId,
          errorCode,
          errorMessage: errorMsg,
        };
      }
    },
    [deriveConversationKey, ensurePeerAuthenticated, getPeerCertificate, hybridKeys?.dilithium, setLastError],
  );

  const handleIncomingP2PMessage = useCallback(
    async (message: P2PMessage) => {
      try {
        if (message.type === 'signal') {
          try {
            const service: any = p2pServiceRef.current as any;
            if (!service || typeof service.decryptPayload !== 'function') {
              throw createP2PError('SERVICE_UNAVAILABLE');
            }
            const decryptedRaw = await service.decryptPayload(message.from, message.payload);
            const obj = typeof decryptedRaw === 'string' ? JSON.parse(decryptedRaw) : decryptedRaw;
            if (obj && obj.kind === 'call-signal' && obj.signal) {
              try {
                const callSignal = obj.signal;
                window.dispatchEvent(new CustomEvent('call-signal', { detail: callSignal }));
              } catch {}
              return; 
            }
          } catch (_err) {
          }
        }

        // Handle encrypted delivery acknowledgments
        if (message.type === 'delivery-ack') {
          try {
            if (!hybridKeys?.kyber?.secretKey || !hybridKeys?.x25519?.private) {
              return;
            }
            
          const peerCert = await getPeerCertificate(message.from);
          if (!peerCert) {
            return;
          }
            
            // Decrypt the acknowledgment
            const decryptedAck = await CryptoUtils.Hybrid.decryptIncoming(
              message.payload,
              {
                kyberSecretKey: hybridKeys.kyber.secretKey,
                x25519SecretKey: hybridKeys.x25519.private,
                senderDilithiumPublicKey: peerCert.dilithiumPublicKey,
              },
              { expectJsonPayload: true },
            );
            
            const ackData = decryptedAck.payloadJson as any;
            if (ackData?.messageId) {
              window.dispatchEvent(
                new CustomEvent('message-delivered', {
                  detail: { messageId: ackData.messageId, from: message.from },
                }),
              );
            }
          } catch (_error) {
            console.error('[P2P] Failed to process delivery-ack', { error: _error, message: (_error as Error)?.message, stack: (_error as Error)?.stack });
          }
          return;
        }

        // Handle encrypted read receipts
        if (message.type === 'read-receipt') {
          try {
            if (!hybridKeys?.kyber?.secretKey || !hybridKeys?.x25519?.private) {
              return;
            }
            
            const peerCert = await getPeerCertificate(message.from);
            if (!peerCert) {
              return;
            }
            
            // Decrypt the read receipt
            const decryptedReceipt = await CryptoUtils.Hybrid.decryptIncoming(
              message.payload,
              {
                kyberSecretKey: hybridKeys.kyber.secretKey,
                x25519SecretKey: hybridKeys.x25519.private,
                senderDilithiumPublicKey: peerCert.dilithiumPublicKey,
              },
              { expectJsonPayload: true },
            );
            
            const receiptData = decryptedReceipt.payloadJson as any;
            if (receiptData?.messageId) {
              const id = String(receiptData.messageId);
              if (processedReadReceiptsRef.current.has(id)) {
                return;
              }
              processedReadReceiptsRef.current.add(id);
              window.dispatchEvent(
                new CustomEvent('message-read', {
                  detail: { messageId: id, from: message.from },
                }),
              );
            }
          } catch (_error) {
            console.error('[P2P] Failed to process read-receipt', { error: _error, message: (_error as Error)?.message, stack: (_error as Error)?.stack });
          }
          return;
        }

        // Accept chat, typing, reaction, file, edit, and delete messages
        if (!['chat', 'typing', 'reaction', 'file', 'edit', 'delete'].includes(message.type)) {
          return;
        }
        if (!hybridKeys?.dilithium?.secretKey || !hybridKeys?.dilithium?.publicKeyBase64) {
          throw createP2PError('LOCAL_KEYS_MISSING');
        }
        if (!hybridKeys?.kyber?.secretKey || !hybridKeys?.x25519?.private) {
          throw createP2PError('LOCAL_DECRYPTION_KEYS_MISSING');
        }

        const peerCert = await getPeerCertificate(message.from);
        if (!peerCert) {
          throw createP2PError('PEER_CERT_MISSING');
        }

        const routeProof = message.payload?.routing?.extras?.routeProof || message.payload?.metadata?.extras?.routeProof || message.payload?.metadata?.routeProof;
        const conversationKey = deriveConversationKey(message.from);
        const minSequence = 0;
        let validProof = await verifyRouteProof(
          routeProof,
          hybridKeys.dilithium.publicKeyBase64,
          peerCert.dilithiumPublicKey,
          getChannelId(hybridKeys.dilithium.publicKeyBase64, peerCert.dilithiumPublicKey),
          minSequence,
        );
        
        let freshPeerCert = peerCert;
        if (!validProof) {
          invalidatePeerCert(message.from);
          const newCert = await getPeerCertificate(message.from, true);
          if (newCert) {
            freshPeerCert = newCert;
            validProof = await verifyRouteProof(
              routeProof,
              hybridKeys.dilithium.publicKeyBase64,
              newCert.dilithiumPublicKey,
              getChannelId(hybridKeys.dilithium.publicKeyBase64, newCert.dilithiumPublicKey),
              minSequence,
            );
            if (validProof) {
            }
          }
        }
        
        if (!validProof) {
          try { SecurityAuditLogger.log('warn', 'p2p-route-proof-invalid', { from: message.from }); } catch {}
          throw createP2PError('ROUTE_PROOF_INVALID');
        } else {
          try { SecurityAuditLogger.log('info', 'p2p-route-proof-ok', { from: message.from }); } catch {}
        }

        const authenticated = await ensurePeerAuthenticated(message.from, message.payload);
        if (!authenticated) {
          throw createP2PError('PEER_AUTH_FAILED');
        }

        const decryptedEnvelope = await CryptoUtils.Hybrid.decryptIncoming(
          message.payload,
          {
            kyberSecretKey: hybridKeys.kyber.secretKey,
            x25519SecretKey: hybridKeys.x25519.private,
            senderDilithiumPublicKey: freshPeerCert.dilithiumPublicKey,
          },
          { expectJsonPayload: true },
        );

        const decryptedMessage = decryptedEnvelope.payloadJson as any;
        const routeProofPayload = decryptedMessage?.routeProof ?? routeProof;
        const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, freshPeerCert.dilithiumPublicKey);
        const proofValid = await verifyRouteProof(
          routeProofPayload,
          hybridKeys.dilithium.publicKeyBase64,
          freshPeerCert.dilithiumPublicKey,
          channelId,
          0,
        );
        if (!proofValid) {
          try { SecurityAuditLogger.log('warn', 'p2p-payload-route-proof-invalid', { from: message.from }); } catch {}
          throw createP2PError('PAYLOAD_ROUTE_PROOF_INVALID');
        } else {
          try { SecurityAuditLogger.log('info', 'p2p-payload-route-proof-ok', { from: message.from }); } catch {}
        }
        const currentSequence = channelSequenceRef.current.get(conversationKey) ?? 0;
        const nextSequence = Math.max(currentSequence, routeProofPayload?.payload?.sequence ?? currentSequence) + 1;
        if (conversationKey) {
          channelSequenceRef.current.set(conversationKey, nextSequence);
        }

        const messageSequence = routeProofPayload?.payload?.sequence ?? currentSequence;
        const messageId = await generateMessageId(channelId, messageSequence);
        
        // Determine message type from P2P message type or decrypted message
        let messageType: 'text' | 'typing' | 'reaction' | 'file' | 'edit' | 'delete' = 'text';
        if (message.type === 'typing') messageType = 'typing';
        else if (message.type === 'reaction') messageType = 'reaction';
        else if (message.type === 'file') messageType = 'file';
        else if (message.type === 'edit') messageType = 'edit';
        else if (message.type === 'delete') messageType = 'delete';
        else if (decryptedMessage.messageType) messageType = decryptedMessage.messageType;
        
        const encryptedMessage: EncryptedMessage = {
          id: decryptedMessage.id || messageId,
          from: message.from,
          to: message.to,
          content: decryptedMessage.content,
          timestamp: decryptedMessage.timestamp || message.timestamp,
          encrypted: true,
          p2p: true,
          transport: 'p2p',
          routeProof: routeProofPayload?.signature,
          messageType,
          metadata: decryptedMessage.metadata,
        };

        if (message.type === 'typing') {
          try {
            window.dispatchEvent(
              new CustomEvent('p2p-typing-indicator', {
                detail: {
                  from: message.from,
                  content: decryptedMessage.content,
                  timestamp: decryptedMessage.timestamp || message.timestamp,
                },
              }),
            );
          } catch {}
          return; 
        }

        appendIncoming(encryptedMessage);
        messageCallbackRef.current?.(encryptedMessage);

        if (message.type === 'chat' || message.type === 'file') {
          try {
            const ackPayload = {
              messageId: encryptedMessage.id,
              timestamp: Date.now(),
            };
            
            // Encrypt the delivery acknowledgment
            const encryptedAck = await CryptoUtils.Hybrid.encryptForClient(
              ackPayload,
              {
                kyberPublicBase64: freshPeerCert.kyberPublicKey,
                dilithiumPublicBase64: freshPeerCert.dilithiumPublicKey,
                x25519PublicBase64: freshPeerCert.x25519PublicKey,
              },
              {
                to: peerCert.dilithiumPublicKey,
                from: hybridKeys.dilithium.publicKeyBase64,
                type: 'p2p-delivery-ack',
                senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
                senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
                timestamp: Date.now(),
              },
            );
            
            await p2pServiceRef.current?.sendMessage(message.from, encryptedAck, 'delivery-ack');
            try { SecurityAuditLogger.log('info', 'p2p-delivery-ack-sent', { to: message.from, messageId: encryptedMessage.id }); } catch {}
          } catch (_error) {
          }
        }
      } catch (_error) {
        try {
          console.error('[P2P] handleIncomingP2PMessage failed', {
            type: (message as any)?.type,
            from: (message as any)?.from,
            error: _error instanceof Error ? _error.message : String(_error),
          });
        } catch {}
        try {
          SecurityAuditLogger.log('error', 'p2p-incoming-error', {
            from: (message as any)?.from || null,
            type: (message as any)?.type || null,
            error: _error instanceof Error ? _error.message : String(_error),
          });
        } catch {}
      }
    },
    [appendIncoming, deriveConversationKey, ensurePeerAuthenticated, getPeerCertificate, hybridKeys],
  );

  // Assign handler to ref
  handleIncomingP2PMessageRef.current = handleIncomingP2PMessage;

  const onMessage = useCallback((callback: (message: EncryptedMessage) => void) => {
    messageCallbackRef.current = callback;
  }, []);

  const disconnectPeer = useCallback((peerUsername: string) => {
    p2pServiceRef.current?.disconnectPeer(peerUsername);
  }, []);

  const getP2PStats = useCallback(
    () => ({
      isInitialized: p2pStatus.isInitialized,
      connectedPeers: [...p2pStatus.connectedPeers],
      totalConnections: p2pStatus.connectedPeers.length,
      signalingConnected: p2pStatus.signalingConnected,
      lastError: p2pStatus.lastError,
    }),
    [p2pStatus],
  );

  const flushPeerQueueRefStable = useRef(flushPeerQueue);
  useEffect(() => { flushPeerQueueRefStable.current = flushPeerQueue; }, [flushPeerQueue]);

  useEffect(() => {
    const onPqEstablished = (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const peer = d?.peer;
        if (peer) {
          flushPeerQueueRefStable.current?.(peer);
        }
      } catch {}
    };
    try {
      window.addEventListener('p2p-pq-established', onPqEstablished as EventListener);
    } catch {}
    return () => {
      try {
        window.removeEventListener('p2p-pq-established', onPqEstablished as EventListener);
      } catch {}
    };
  }, []);

  useEffect(() => {
    return () => {
      destroyService();
    };
  }, [destroyService]);

  const waitForPeerConnection = useCallback(
    (peerUsername: string, timeoutMs = 5000): Promise<boolean> => {
      if (!peerUsername) return Promise.resolve(false);
      if (isPeerConnected(peerUsername)) return Promise.resolve(true);
      return new Promise<boolean>((resolve) => {
        let resolved = false;
        const resolver = (ok: boolean) => {
          if (resolved) return;
          resolved = true;
          try { clearTimeout(timer); } catch {}
          resolve(ok);
        };
        const set = peerWaitersRef.current.get(peerUsername) || new Set<(ok: boolean) => void>();
        set.add(resolver);
        peerWaitersRef.current.set(peerUsername, set);
        const timer = setTimeout(() => {
          if (resolved) return;
          resolved = true;
          try {
            const s = peerWaitersRef.current.get(peerUsername);
            if (s) {
              s.delete(resolver);
              if (s.size === 0) peerWaitersRef.current.delete(peerUsername);
            }
          } catch {}
          resolve(false);
        }, Math.max(0, timeoutMs | 0));
      });
    },
    [isPeerConnected],
  );

  const sendP2PReadReceipt = useCallback(
    async (messageId: string, recipient: string): Promise<void> => {
      if (!p2pServiceRef.current) return;
      if (!isPeerConnected(recipient)) return;
      if (!hybridKeys?.dilithium?.secretKey || !hybridKeys?.dilithium?.publicKeyBase64) {
        return;
      }

      // Deduplicate: if we have recently sent a receipt for this messageId, skip
      try {
        const last = sentP2PReceiptsRef.current.get(messageId);
        if (last && (Date.now() - last) < RECEIPT_RETENTION_MS) {
          return;
        }
      } catch {}

      try {
        const peerCert = await getPeerCertificate(recipient);
        if (!peerCert) {
          return;
        }

        const readReceiptPayload = {
          messageId,
          timestamp: Date.now(),
        };
        
        // Encrypt the read receipt
        const encryptedReceipt = await CryptoUtils.Hybrid.encryptForClient(
          readReceiptPayload,
          {
            kyberPublicBase64: peerCert.kyberPublicKey,
            dilithiumPublicBase64: peerCert.dilithiumPublicKey,
            x25519PublicBase64: peerCert.x25519PublicKey,
          },
          {
            to: peerCert.dilithiumPublicKey,
            from: hybridKeys.dilithium.publicKeyBase64,
            type: 'p2p-read-receipt',
            senderDilithiumSecretKey: hybridKeys.dilithium.secretKey,
            senderDilithiumPublicKey: hybridKeys.dilithium.publicKeyBase64,
            timestamp: Date.now(),
          },
        );
        
        await p2pServiceRef.current.sendMessage(recipient, encryptedReceipt, 'read-receipt');
        try { sentP2PReceiptsRef.current.set(messageId, Date.now()); } catch {}
        try { SecurityAuditLogger.log('info', 'p2p-read-receipt-sent', { to: recipient, messageId }); } catch {}
      } catch (_error) {
      }
    },
    [isPeerConnected, hybridKeys?.dilithium, getPeerCertificate],
  );

  useEffect(() => {
    const interval = setInterval(() => {
      try {
        const cutoff = Date.now() - RECEIPT_RETENTION_MS;
        for (const [id, ts] of sentP2PReceiptsRef.current.entries()) {
          if (ts < cutoff) sentP2PReceiptsRef.current.delete(id);
        }
        if (processedReadReceiptsRef.current.size > 5000) {
          processedReadReceiptsRef.current.clear();
        }
      } catch {}
    }, RECEIPT_RETENTION_MS);
    return () => { try { clearInterval(interval); } catch {} };
  }, []);

  // Refresh peer certificate on new connection (keys may have rotated)
  useEffect(() => {
    const onPeerConnected = (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const peer = d?.peer;
        if (peer) {
          invalidatePeerCert(peer);
          getPeerCertificate(peer, true).then(cert => {
            if (cert) {
              const pk = toUint8(cert.dilithiumPublicKey);
              if (pk && p2pServiceRef.current) {
                p2pServiceRef.current.addPeerDilithiumKey(peer, pk);
              }
            }
          }).catch(() => {});
        }
      } catch {}
    };
    try {
      window.addEventListener('p2p-peer-connected', onPeerConnected as EventListener);
    } catch {}
    return () => {
      try {
        window.removeEventListener('p2p-peer-connected', onPeerConnected as EventListener);
      } catch {}
    };
  }, [getPeerCertificate, invalidatePeerCert]);

  // Listen for certificate fetch requests from answerer side
  useEffect(() => {
    const onFetchPeerCert = (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const peer = d?.peer;
        if (peer) {
          getPeerCertificate(peer, true).then(cert => {
            if (cert) {
              const pk = toUint8(cert.dilithiumPublicKey);
              if (pk && p2pServiceRef.current) {
                p2pServiceRef.current.addPeerDilithiumKey(peer, pk);
              }
            }
          }).catch(() => {
          });
        }
      } catch {}
    };
    try {
      window.addEventListener('p2p-fetch-peer-cert', onFetchPeerCert as EventListener);
    } catch {}
    return () => {
      try {
        window.removeEventListener('p2p-fetch-peer-cert', onFetchPeerCert as EventListener);
      } catch {}
    };
  }, [getPeerCertificate]);

  // Listen for hybrid keys update event and clear caches
  useEffect(() => {
    const onKeysUpdated = () => {
      peerCertificateCacheRef.current.clear();
      routeProofCacheRef.current.clear();
      peerAuthCacheRef.current = buildAuthenticator();
    };
    try {
      window.addEventListener('hybrid-keys-updated', onKeysUpdated as EventListener);
    } catch {}
    return () => {
      try {
        window.removeEventListener('hybrid-keys-updated', onKeysUpdated as EventListener);
      } catch {}
    };
  }, []);

  return {
    p2pStatus,
    incomingMessages,
    initializeP2P,
    connectToPeer,
    sendP2PMessage,
    disconnectPeer,
    onMessage,
    isPeerConnected,
    getP2PStats,
    waitForPeerConnection,
    sendP2PReadReceipt,
  };
}