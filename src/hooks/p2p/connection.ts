import React, { RefObject } from "react";
import { SecureP2PService } from "../../lib/transport/secure-p2p-service";
import { EventType } from "../../lib/types/event-types";
import { p2pTransport } from "../../lib/transport/p2p-transport";
import type { P2PStatus, HybridKeys, PeerCertificateBundle, P2PMessage, CertCacheEntry } from "../../lib/types/p2p-types";
import {
  createP2PError
} from "../../lib/utils/p2p-utils";
import { loadPersistedPeerEndpoint } from "../../lib/p2p/persisted-peer-cert";

export interface ConnectionRefs {
  p2pServiceRef: RefObject<SecureP2PService | null>;
  peerCertificateCacheRef: RefObject<Map<string, CertCacheEntry>>;
  channelSequenceRef: RefObject<Map<string, number>>;
  handleIncomingP2PMessageRef: RefObject<((message: P2PMessage) => Promise<boolean>) | null>;
}

export interface ConnectionSetters {
  setP2PStatus: React.Dispatch<React.SetStateAction<P2PStatus>>;
}

export interface ConnectionOptions {
  onServiceReady?: (service: SecureP2PService | null) => void;
}

// Tears down current peer service, clears caches, and resets status indicators
export function createDestroyService(
  refs: ConnectionRefs,
  setters: ConnectionSetters,
  options?: ConnectionOptions
) {
  return async () => {
    const service = refs.p2pServiceRef.current;
    if (service) {
      options?.onServiceReady?.(null);
      (refs.p2pServiceRef as { current: SecureP2PService | null }).current = null;
    }
    refs.peerCertificateCacheRef.current.clear();
    setters.setP2PStatus((prev) => ({
      ...prev,
      isInitialized: false,
      connectedPeers: [],
    }));
    if (service) await service.shutdown().catch(() => { });
  };
}

// Starts or restarts P2P service, registers the current identity, and wires event callbacks
export function createInitializeP2P(
  refs: ConnectionRefs,
  setters: ConnectionSetters,
  username: string,
  hybridKeys: HybridKeys | null,
  destroyService: () => Promise<void>,
  options?: ConnectionOptions
) {
  return async () => {
    let candidateService: SecureP2PService | null = null;
    try {
      if (refs.p2pServiceRef.current) {
        const currentService = refs.p2pServiceRef.current;
        if (currentService.isCompatible(username, hybridKeys)) {
          return;
        }

        await currentService.shutdown().catch(() => { });
        if (refs.p2pServiceRef.current !== currentService) {
          return;
        }
        options?.onServiceReady?.(null);
        (refs.p2pServiceRef as { current: SecureP2PService | null }).current = null;
      }
      refs.peerCertificateCacheRef.current.clear();

      if (!username || hybridKeys?.native !== true) {
        throw createP2PError('AUTH_REQUIRED');
      }

      const service = new SecureP2PService(username);
      candidateService = service;
      service.setChannelSequenceMap(refs.channelSequenceRef.current);
      (refs.p2pServiceRef as { current: SecureP2PService | null }).current = service;
      if (hybridKeys) {
        service.setHybridKeys(hybridKeys);
      }

      service.onMessage(async (message: P2PMessage) => {
        if (refs.p2pServiceRef.current !== service) return false;
        if (!refs.handleIncomingP2PMessageRef.current) {
          console.warn('[MSG-RECV] DROP: handleIncomingP2PMessageRef not set');
          return false;
        }
        try {
          return await refs.handleIncomingP2PMessageRef.current(message);
        } catch (err) {
          console.error('[MSG-RECV] handleIncomingP2PMessage threw:', (err as Error)?.message || err);
          return false;
        }
      });

      service.onPeerConnected((peerUsername: string) => {
        if (refs.p2pServiceRef.current !== service) return;
        setters.setP2PStatus((prev) => ({
          ...prev,
          connectedPeers: [...new Set([...prev.connectedPeers, peerUsername])],
        }));
        try {
          window.dispatchEvent(new CustomEvent(EventType.P2P_PEER_CONNECTED, {
            detail: { account: username, peer: peerUsername }
          }));
        } catch { }
      });

      service.onPeerDisconnected((peerUsername: string) => {
        if (refs.p2pServiceRef.current !== service) return;
        setters.setP2PStatus((prev) => ({
          ...prev,
          connectedPeers: prev.connectedPeers.filter((p) => p !== peerUsername),
        }));
      });

      await service.initialize();
      if (refs.p2pServiceRef.current !== service) {
        await service.shutdown().catch(() => { });
        return;
      }
      options?.onServiceReady?.(service);

      setters.setP2PStatus((prev) => ({
        ...prev,
        isInitialized: true,
      }));
    } catch {
      if (candidateService && refs.p2pServiceRef.current !== candidateService) {
        await candidateService.shutdown().catch(() => { });
        return;
      }
      if (!candidateService && refs.p2pServiceRef.current) return;
      await destroyService();
    }
  };
}

// Initiates peer connection
export function createConnectToPeer(
  refs: ConnectionRefs,
  hybridKeys: HybridKeys | null,
  getPeerCertificate: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>,
  ownerUsername?: string
) {
  return async (peerUsername: string) => {
    const service = refs.p2pServiceRef.current;
    if (!service) {
      throw createP2PError('SERVICE_UNINITIALIZED');
    }

    if (hybridKeys?.native !== true) {
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
    if (refs.p2pServiceRef.current !== service) throw createP2PError('AUTH_REQUIRED');

    if (ownerUsername && !p2pTransport.hasAuthenticatedEndpoint(peerUsername)) {
      const persisted = await loadPersistedPeerEndpoint(ownerUsername, peerUsername).catch(() => null);
      if (refs.p2pServiceRef.current !== service) throw createP2PError('AUTH_REQUIRED');
      if (persisted) {
        await p2pTransport.registerPeerCertificate(peerUsername, cert);
        if (refs.p2pServiceRef.current !== service) throw createP2PError('AUTH_REQUIRED');
        p2pTransport.updateAuthenticatedEndpoint(
          peerUsername,
          persisted.endpointUrl,
          persisted.signerPublicKeyBase64,
          persisted.announcedAt
        );
      }
    }

    await service.connectToPeer(peerUsername, {
      peerCertificate: cert,
    });
  };
}

// Queries whether the peer currently appears connected in state
export function createIsPeerConnected(connectedPeers: string[]) {
  return (peerUsername: string): boolean => {
    if (!peerUsername) return false;

    if (connectedPeers.includes(peerUsername)) {
      return true;
    }

    try {
      if (p2pTransport.isConnected(peerUsername)) {
        return true;
      }
    } catch { }

    return false;
  };
}
