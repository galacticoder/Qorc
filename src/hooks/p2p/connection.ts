import React, { RefObject } from "react";
import { SecureP2PService } from "../../lib/transport/secure-p2p-service";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { SecurityAuditLogger } from "../../lib/cryptography/audit-logger";
import { EventType } from "../../lib/types/event-types";
import type { P2PStatus, HybridKeys, PeerCertificateBundle, EncryptedMessage, P2PMessage, RouteProofRecord, CertCacheEntry } from "../../lib/types/p2p-types";
import {
  createP2PError,
  toUint8,
  buildRouteProof,
  getChannelId,
  generateRandomBase64,
  buildAuthenticator
} from "../../lib/utils/p2p-utils";
import { P2P_ROUTE_PROOF_TTL_MS } from "../../lib/constants";

export interface ConnectionRefs {
  p2pServiceRef: RefObject<SecureP2PService | null>;
  routeProofCacheRef: RefObject<Map<string, RouteProofRecord>>;
  peerCertificateCacheRef: RefObject<Map<string, CertCacheEntry>>;
  peerAuthCacheRef: RefObject<ReturnType<typeof buildAuthenticator>>;
  channelSequenceRef: RefObject<Map<string, number>>;
  authLockRef: RefObject<Promise<void> | null>;
  peerWaitersRef: RefObject<Map<string, Set<(ok: boolean) => void>>>;
  incomingQueueRef: RefObject<{ push: (item: EncryptedMessage) => void; items: () => EncryptedMessage[]; clear: () => void }>;
  outboundQueueRef: RefObject<Map<string, any[]>>;
  flushTimersRef: RefObject<Map<string, ReturnType<typeof setTimeout>>>;
  handleIncomingP2PMessageRef: RefObject<((message: P2PMessage) => Promise<void>) | null>;
}

export interface ConnectionSetters {
  setP2PStatus: React.Dispatch<React.SetStateAction<P2PStatus>>;
  setIncomingMessages: React.Dispatch<React.SetStateAction<EncryptedMessage[]>>;
  setLastError: (error: unknown) => void;
  clearLastError: () => void;
}

export interface ConnectionOptions {
  signalingTokenProvider?: () => Promise<string | null>;
  onServiceReady?: (service: SecureP2PService | null) => void;
}

// Tears down the current peer service, clears caches, and resets status indicators
export function createDestroyService(
  refs: ConnectionRefs,
  setters: ConnectionSetters,
  options?: ConnectionOptions
) {
  return () => {
    if (refs.p2pServiceRef.current) {
      try {
        refs.p2pServiceRef.current.destroy();
      } catch { }
      options?.onServiceReady?.(null);
      (refs.p2pServiceRef as { current: SecureP2PService | null }).current = null;
    }

    refs.routeProofCacheRef.current.clear();
    refs.peerCertificateCacheRef.current.clear();
    (refs.peerAuthCacheRef as { current: ReturnType<typeof buildAuthenticator> }).current = buildAuthenticator();
    try {
      refs.outboundQueueRef.current.forEach((arr) => arr.forEach(it => { try { it.envelope = null; } catch { } }));
      refs.outboundQueueRef.current.clear();
    } catch { }

    refs.flushTimersRef.current.forEach(t => clearTimeout(t));
    refs.flushTimersRef.current.clear();
    refs.incomingQueueRef.current.clear();
    setters.setIncomingMessages([]);
    setters.setP2PStatus((prev) => ({
      ...prev,
      isInitialized: false,
      connectedPeers: [],
      signalingConnected: false,
    }));
  };
}

// Starts or restarts the P2P service, registers the current identity, and wires event callbacks
export function createInitializeP2P(
  refs: ConnectionRefs,
  setters: ConnectionSetters,
  username: string,
  hybridKeys: HybridKeys | null,
  destroyService: () => void,
  options?: ConnectionOptions
) {
  return async (signalingServerUrl: string) => {
    setters.clearLastError();
    try {
      if (refs.p2pServiceRef.current) {
        const currentService = refs.p2pServiceRef.current;
        if (currentService.isCompatible(username, signalingServerUrl)) {
          return;
        }

        try {
          currentService.destroy();
        } catch { }
        options?.onServiceReady?.(null);
        (refs.p2pServiceRef as { current: SecureP2PService | null }).current = null;
      }

      refs.routeProofCacheRef.current.clear();
      refs.peerCertificateCacheRef.current.clear();
      (refs.peerAuthCacheRef as { current: ReturnType<typeof buildAuthenticator> }).current = buildAuthenticator();

      refs.outboundQueueRef.current.forEach((arr) => arr.forEach(it => { try { it.envelope = null; } catch { } }));
      refs.outboundQueueRef.current.clear();

      refs.flushTimersRef.current.forEach(t => clearTimeout(t));
      refs.flushTimersRef.current.clear();

      refs.incomingQueueRef.current.clear();
      setters.setIncomingMessages([]);

      if (!username || !hybridKeys?.dilithium?.secretKey) {
        throw createP2PError('AUTH_REQUIRED');
      }

      const service = new SecureP2PService(username);
      service.setChannelSequenceMap(refs.channelSequenceRef.current);
      (refs.p2pServiceRef as { current: SecureP2PService | null }).current = service;
      options?.onServiceReady?.(service);
      if (hybridKeys) {
        service.setHybridKeys(hybridKeys);
      }

      service.onMessage((message: P2PMessage) => {
        refs.handleIncomingP2PMessageRef.current?.(message).catch(() => { });
      });

      service.onPeerConnected((peerUsername: string) => {
        setters.setP2PStatus((prev) => ({
          ...prev,
          connectedPeers: [...new Set([...prev.connectedPeers, peerUsername])],
        }));
        try {
          const set = refs.peerWaitersRef.current.get(peerUsername);
          if (set) {
            set.forEach(fn => { try { fn(true); } catch { } });
            refs.peerWaitersRef.current.delete(peerUsername);
          }
        } catch { }

        try {
          window.dispatchEvent(new CustomEvent(EventType.P2P_PEER_RECONNECTED, { detail: { peer: peerUsername } }));
        } catch { }

        try {
          window.dispatchEvent(new CustomEvent(EventType.P2P_PEER_CONNECTED, { detail: { peer: peerUsername } }));
        } catch { }
        setters.clearLastError();
      });

      service.onPeerDisconnected((peerUsername: string) => {
        setters.setP2PStatus((prev) => ({
          ...prev,
          connectedPeers: prev.connectedPeers.filter((p) => p !== peerUsername),
        }));
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

      setters.setP2PStatus((prev) => ({
        ...prev,
        isInitialized: true,
        signalingConnected: true,
        lastError: null,
      }));
    } catch (_error) {
      setters.setLastError(_error);
      destroyService();
    }
  };
}

// Initiates peer connection with authentication.
export function createConnectToPeer(
  refs: ConnectionRefs,
  hybridKeys: HybridKeys | null,
  deriveConversationKey: (peer: string) => string | null,
  getPeerCertificate: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>,
  setLastError: (error: unknown) => void
) {
  return async (peerUsername: string) => {
    if (!refs.p2pServiceRef.current) {
      throw createP2PError('SERVICE_UNINITIALIZED');
    }

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

    if (!refs.authLockRef.current) {
      (refs.authLockRef as { current: Promise<void> | null }).current = (async () => {
        const channelId = getChannelId(hybridKeys.dilithium.publicKeyBase64, cert.dilithiumPublicKey);
        const sequence = (refs.channelSequenceRef.current.get(conversationKey) ?? 0) + 1;

        const routeProof = await buildRouteProof(
          hybridKeys.dilithium.secretKey,
          hybridKeys.dilithium.publicKeyBase64,
          cert.dilithiumPublicKey,
          channelId,
          sequence,
        );

        refs.routeProofCacheRef.current.set(conversationKey, {
          proof: routeProof,
          expiresAt: Date.now() + P2P_ROUTE_PROOF_TTL_MS,
        });
        refs.channelSequenceRef.current.set(conversationKey, sequence);
      })();
    }
    await refs.authLockRef.current.finally(() => {
      (refs.authLockRef as { current: Promise<void> | null }).current = null;
    });

    try {
      try {
        const pk = toUint8(cert.dilithiumPublicKey);
        if (pk) refs.p2pServiceRef.current.addPeerDilithiumKey(peerUsername, pk);
      } catch { }

      await refs.p2pServiceRef.current.connectToPeer(peerUsername, {
        peerCertificate: cert,
        routeProof: refs.routeProofCacheRef.current.get(conversationKey)?.proof,
      });
    } catch (_error) {
      try { SecurityAuditLogger.log('warn', 'p2p-connect-error', { peer: peerUsername, error: String((_error as any)?.message || _error) }); } catch { }
      setLastError(_error);
      throw _error;
    }
  };
}

// Tears down a peer link
export function createDisconnectPeer(refs: ConnectionRefs) {
  return (peerUsername: string) => {
    refs.p2pServiceRef.current?.disconnectPeer(peerUsername);
  };
}

// Queries whether the peer currently appears connected in state
export function createIsPeerConnected(connectedPeers: string[]) {
  return (peerUsername: string): boolean => connectedPeers.includes(peerUsername);
}

// Returns a promise that resolves once the peer connects or the timeout elapses
export function createWaitForPeerConnection(
  refs: ConnectionRefs,
  isPeerConnected: (peer: string) => boolean
) {
  return (peerUsername: string, timeoutMs = 5000): Promise<boolean> => {
    if (!peerUsername) return Promise.resolve(false);
    if (isPeerConnected(peerUsername)) return Promise.resolve(true);

    return new Promise<boolean>((resolve) => {
      let resolved = false;
      const resolver = (ok: boolean) => {
        if (resolved) return;
        resolved = true;
        try { clearTimeout(timer); } catch { }
        resolve(ok);
      };

      const set = refs.peerWaitersRef.current.get(peerUsername) || new Set<(ok: boolean) => void>();
      set.add(resolver);
      refs.peerWaitersRef.current.set(peerUsername, set);

      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        try {
          const s = refs.peerWaitersRef.current.get(peerUsername);
          if (s) {
            s.delete(resolver);
            if (s.size === 0) refs.peerWaitersRef.current.delete(peerUsername);
          }
        } catch { }
        resolve(false);
      }, Math.max(0, timeoutMs | 0));
    });
  };
}
