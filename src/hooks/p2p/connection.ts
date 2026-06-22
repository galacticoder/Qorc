import React, { RefObject } from "react";
import { SecureP2PService } from "../../lib/transport/secure-p2p-service";
import { SecurityAuditLogger } from "../../lib/cryptography/audit-logger";
import { EventType } from "../../lib/types/event-types";
import { p2pTransport } from "../../lib/transport/p2p-transport";
import type { P2PStatus, HybridKeys, PeerCertificateBundle, P2PMessage, RouteProofRecord, CertCacheEntry } from "../../lib/types/p2p-types";
import { P2P_ROUTE_PROOF_TTL_MS } from "../../lib/constants";
import {
  createP2PError,
  toUint8,
  buildRouteProof,
  getChannelId,
  buildAuthenticator
} from "../../lib/utils/p2p-utils";

export interface ConnectionRefs {
  p2pServiceRef: RefObject<SecureP2PService | null>;
  routeProofCacheRef: RefObject<Map<string, RouteProofRecord>>;
  peerCertificateCacheRef: RefObject<Map<string, CertCacheEntry>>;
  peerAuthCacheRef: RefObject<ReturnType<typeof buildAuthenticator>>;
  channelSequenceRef: RefObject<Map<string, number>>;
  authLockRef: RefObject<Promise<void> | null>;
  peerWaitersRef: RefObject<Map<string, Set<(ok: boolean) => void>>>;
  handleIncomingP2PMessageRef: RefObject<((message: P2PMessage) => Promise<void>) | null>;
}

export interface ConnectionSetters {
  setP2PStatus: React.Dispatch<React.SetStateAction<P2PStatus>>;
  setLastError: (error: unknown) => void;
  clearLastError: () => void;
}

export interface ConnectionOptions {
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
      void refs.p2pServiceRef.current.shutdown().catch(() => { });
      options?.onServiceReady?.(null);
      (refs.p2pServiceRef as { current: SecureP2PService | null }).current = null;
    }

    refs.routeProofCacheRef.current.clear();
    refs.peerCertificateCacheRef.current.clear();
    (refs.peerAuthCacheRef as { current: ReturnType<typeof buildAuthenticator> }).current = buildAuthenticator();
    setters.setP2PStatus((prev) => ({
      ...prev,
      isInitialized: false,
      connectedPeers: [],
      transportConnected: false,
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
  return async () => {
    setters.clearLastError();
    try {
      if (refs.p2pServiceRef.current) {
        const currentService = refs.p2pServiceRef.current;
        if (currentService.isCompatible(username)) {
          return;
        }

        await currentService.shutdown().catch(() => { });
        options?.onServiceReady?.(null);
        (refs.p2pServiceRef as { current: SecureP2PService | null }).current = null;
      }

      refs.routeProofCacheRef.current.clear();
      refs.peerCertificateCacheRef.current.clear();
      (refs.peerAuthCacheRef as { current: ReturnType<typeof buildAuthenticator> }).current = buildAuthenticator();

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
        console.log('[MSG-RECV] -> handleIncomingP2PMessage (app)', {
          type: (message as any)?.type, from: String((message as any)?.from).slice(0, 24),
          hasHandler: !!refs.handleIncomingP2PMessageRef.current
        });
        if (!refs.handleIncomingP2PMessageRef.current) {
          console.warn('[MSG-RECV] DROP: handleIncomingP2PMessageRef not set');
        }
        refs.handleIncomingP2PMessageRef.current?.(message).catch((err) => {
          console.error('[MSG-RECV] handleIncomingP2PMessage threw:', (err as Error)?.message || err);
        });
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

      await service.initialize();

      setters.setP2PStatus((prev) => ({
        ...prev,
        isInitialized: true,
        transportConnected: true,
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

    // Prefer cached certificate first
    let cert = await getPeerCertificate(peerUsername);
    if (!cert) {
      cert = await getPeerCertificate(peerUsername, true);
    }
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
  return (peerUsername: string): boolean => {
    if (!peerUsername) return false;

    if (connectedPeers.includes(peerUsername)) {
      return true;
    }

    let alias: string | undefined;
    try {
      alias = p2pTransport.resolveUsernameAlias(peerUsername);
    } catch {
      alias = undefined;
    }
    if (alias && connectedPeers.includes(alias)) {
      return true;
    }

    try {
      if (p2pTransport.isConnected(peerUsername)) {
        return true;
      }
      if (alias && p2pTransport.isConnected(alias)) {
        return true;
      }
    } catch { }

    return false;
  };
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
