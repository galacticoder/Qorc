import { useEffect, useRef, useState, useCallback } from 'react';
import { SecureP2PService } from '../../lib/transport/secure-p2p-service';
import { EventType } from '../../lib/types/event-types';
import { RECEIPT_RETENTION_MS } from '../../lib/constants';
import { p2pTransport } from '../../lib/transport/p2p-transport';
import { createSendP2PReadReceipt } from './receipts';
import { sanitizeErrorMessage } from '../../lib/sanitizers';
import type {
  P2PStatus,
  P2PMessage,
  HybridKeys,
  PeerCertificateBundle,
  RouteProofRecord,
  CertCacheEntry,
} from '../../lib/types/p2p-types';
import {
  buildAuthenticator,
  toUint8,
  createP2PError,
} from '../../lib/utils/p2p-utils';
import { normalizeP2PEndpointUrl } from '../../lib/utils/p2p-endpoint';
import {
  createGetPeerCertificate,
  createInvalidatePeerCert,
  createDeriveConversationKey,
} from './certificates';
import {
  createDestroyService,
  createInitializeP2P,
  createConnectToPeer,
  createDisconnectPeer,
  createIsPeerConnected,
  createWaitForPeerConnection,
} from './connection';
import {
  createHandleIncomingP2PMessage,
} from './messaging';
import { invalidateDiscoveryCache } from '../discovery/useDiscovery';

export { type P2PMessage, type P2PStatus, type PeerCertificateBundle, type HybridKeys } from '../../lib/types/p2p-types';

// Hook that wires certificate, connection, and messaging helpers
export function useP2PMessaging(
  username: string,
  hybridKeys: HybridKeys | null,
  options?: {
    fetchPeerCertificates?: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>;
    onServiceReady?: (service: SecureP2PService | null) => void;
    handleEncryptedMessagePayload?: (msg: any) => Promise<void>;
    ensureDiscoveryPublished?: (force?: boolean) => Promise<boolean>;
  },
) {
  const p2pServiceRef = useRef<SecureP2PService | null>(null);
  const [p2pStatus, setP2PStatus] = useState<P2PStatus>({
    isInitialized: false,
    connectedPeers: [],
    transportConnected: false,
    lastError: null,
  });
  const peerAuthCacheRef = useRef(buildAuthenticator());
  const peerWaitersRef = useRef(new Map<string, Set<(ok: boolean) => void>>());
  const peerCertificateCacheRef = useRef(new Map<string, CertCacheEntry>());
  const peerCertFailureRef = useRef(new Map<string, { until: number; failures: number }>());
  const routeProofCacheRef = useRef(new Map<string, RouteProofRecord>());
  const channelSequenceRef = useRef(new Map<string, number>());
  const authLockRef = useRef<Promise<void> | null>(null);
  const handleIncomingP2PMessageRef = useRef<((message: P2PMessage) => Promise<void>) | null>(null);
  const handleEncryptedMessagePayloadRef = useRef<((message: any) => Promise<void>) | null>(null);

  const sentP2PReceiptsRef = useRef<Map<string, number>>(new Map());
  const connectInFlightRef = useRef(new Map<string, Promise<void>>());
  const connectBackoffRef = useRef(new Map<string, { until: number; failures: number }>());
  const initInFlightRef = useRef<Promise<void> | null>(null);

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

  const certificateRefs = {
    peerCertificateCacheRef,
    routeProofCacheRef,
    peerAuthCacheRef,
    channelSequenceRef,
  };

  const connectionRefs = {
    p2pServiceRef,
    routeProofCacheRef,
    peerCertificateCacheRef,
    peerAuthCacheRef,
    channelSequenceRef,
    authLockRef,
    peerWaitersRef,
    handleIncomingP2PMessageRef,
  };

  const connectionSetters = {
    setP2PStatus,
    setLastError,
    clearLastError,
  };

  const receiptRefs = {
    sentP2PReceiptsRef,
  };

  const incomingMessageRefs = {
    handleEncryptedMessagePayloadRef,
  };

  const deriveConversationKey = useCallback(
    createDeriveConversationKey(hybridKeys),
    [hybridKeys?.dilithium?.publicKeyBase64]
  );

  const getPeerCertificateBase = useCallback(
    createGetPeerCertificate(certificateRefs, {
      fetchPeerCertificates: options?.fetchPeerCertificates,
    }),
    [options?.fetchPeerCertificates]
  );

  const getPeerCertificate = useCallback(
    async (peer: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
      if (!peer) return null;
      const now = Date.now();
      const failure = peerCertFailureRef.current.get(peer);
      if (!bypassCache && failure && failure.until > now) {
        return null;
      }

      const cert = await getPeerCertificateBase(peer, bypassCache);
      if (cert) {
        peerCertFailureRef.current.delete(peer);
        const kyber = toUint8(cert.kyberPublicKey);
        const dilithium = toUint8(cert.dilithiumPublicKey);
        const x25519 = toUint8(cert.x25519PublicKey);
        if (kyber && dilithium && x25519) {
          p2pTransport.registerPeerIdentity(peer, {
            username: peer,
            kyberPublicKey: kyber,
            dilithiumPublicKey: dilithium,
            x25519PublicKey: x25519,
            endpointUrl: normalizeP2PEndpointUrl(cert.p2pEndpointUrl)
          });
        }
        return cert;
      }

      const failures = (failure?.failures ?? 0) + 1;
      const backoff = Math.min(1500 * Math.pow(2, failures - 1), 15000);
      peerCertFailureRef.current.set(peer, { until: now + backoff, failures });
      return null;
    },
    [getPeerCertificateBase]
  );

  const invalidatePeerCert = useCallback(
    createInvalidatePeerCert(certificateRefs),
    []
  );

  const destroyService = useCallback(
    createDestroyService(connectionRefs, connectionSetters, options),
    []
  );

  const initializeP2P = useCallback(
    createInitializeP2P(connectionRefs, connectionSetters, username, hybridKeys, destroyService, options),
    [username, hybridKeys, destroyService, options]
  );

  const ensureInitialized = useCallback(async (): Promise<boolean> => {
    if (p2pServiceRef.current && p2pStatus.isInitialized) {
      return true;
    }
    if (!username || !hybridKeys?.dilithium?.secretKey) {
      return false;
    }

    if (!initInFlightRef.current) {
      initInFlightRef.current = initializeP2P().finally(() => {
        initInFlightRef.current = null;
      });
    }

    await initInFlightRef.current;
    return !!p2pServiceRef.current;
  }, [initializeP2P, username, hybridKeys?.dilithium?.secretKey, p2pStatus.isInitialized]);

  const isPeerConnected = useCallback(
    createIsPeerConnected(p2pStatus.connectedPeers),
    [p2pStatus.connectedPeers]
  );

  const connectToPeerBase = useCallback(
    createConnectToPeer(connectionRefs, hybridKeys, deriveConversationKey, getPeerCertificate, setLastError),
    [hybridKeys?.dilithium, deriveConversationKey, getPeerCertificate, setLastError]
  );

  const connectToPeer = useCallback(async (peer: string): Promise<void> => {
    if (!peer) return;
    if (isPeerConnected(peer)) return;

    if (options?.ensureDiscoveryPublished) {
      void options.ensureDiscoveryPublished(false).catch(() => false);
    }

    const ready = await ensureInitialized();
    if (!ready) {
      throw createP2PError('SERVICE_UNINITIALIZED');
    }

    const now = Date.now();
    const cooldown = connectBackoffRef.current.get(peer);
    if (cooldown && cooldown.until > now) {
      return;
    }

    const inflight = connectInFlightRef.current.get(peer);
    if (inflight) return inflight;

    const promise = (async () => {
      try {
        await connectToPeerBase(peer);
        connectBackoffRef.current.delete(peer);
      } catch (err) {
        let finalError: unknown = err;
        let errorCode = String((err as any)?.code || (err as any)?.message || '');
        let errorLower = errorCode.toLowerCase();
        let isHandshakeSigningKeyMismatch =
          errorLower.includes('peer handshake signing key mismatch') ||
          errorCode.includes('PEER_HANDSHAKE_SIGNING_KEY_MISMATCH');
        let isCertOrDescriptorIssue =
          errorCode.includes('PEER_CERT_MISSING') ||
          isHandshakeSigningKeyMismatch;
        let isEndpointUnavailable =
          errorLower.includes('p2p_endpoint_missing') ||
          errorLower.includes('no endpoint available') ||
          errorLower.includes('no p2p endpoint available') ||
          errorLower.includes('invalid endpoint url') ||
          errorLower.includes('unsupported endpoint protocol') ||
          errorLower.includes('unsupported endpoint');
        let isHostUnreachable =
          errorLower.includes('host unreachable') ||
          errorLower.includes('socks5') ||
          errorLower.includes('resolve failed') ||
          errorLower.includes('no more hsdir');
        let isTimeoutLike =
          errorLower.includes('timeout') ||
          errorLower.includes('timed out') ||
          errorLower.includes('handshake response timeout');

        const shouldForceRefreshAndRetry =
          isCertOrDescriptorIssue || isEndpointUnavailable || isHostUnreachable || isTimeoutLike;

        if (shouldForceRefreshAndRetry) {          invalidateDiscoveryCache(peer);
          const refreshedCert = await getPeerCertificate(peer, true).catch(() => null);
          if (refreshedCert) {
            try {
              await connectToPeerBase(peer);
              connectBackoffRef.current.delete(peer);
              return;
            } catch (retryErr) {
              finalError = retryErr;
              errorCode = String((retryErr as any)?.code || (retryErr as any)?.message || '');
              errorLower = errorCode.toLowerCase();
              isHandshakeSigningKeyMismatch =
                errorLower.includes('peer handshake signing key mismatch') ||
                errorCode.includes('PEER_HANDSHAKE_SIGNING_KEY_MISMATCH');
              isCertOrDescriptorIssue =
                errorCode.includes('PEER_CERT_MISSING') ||
                isHandshakeSigningKeyMismatch;
              isEndpointUnavailable =
                errorLower.includes('p2p_endpoint_missing') ||
                errorLower.includes('no endpoint available') ||
                errorLower.includes('no p2p endpoint available') ||
                errorLower.includes('invalid endpoint url') ||
                errorLower.includes('unsupported endpoint protocol') ||
                errorLower.includes('unsupported endpoint');
              isHostUnreachable =
                errorLower.includes('host unreachable') ||
                errorLower.includes('socks5') ||
                errorLower.includes('resolve failed') ||
                errorLower.includes('no more hsdir');
              isTimeoutLike =
                errorLower.includes('timeout') ||
                errorLower.includes('timed out') ||
                errorLower.includes('handshake response timeout');
            }
          }
        }

        const prior = connectBackoffRef.current.get(peer);
        const failures = (prior?.failures ?? 0) + 1;
        const backoff =
          isEndpointUnavailable
            ? Math.min(60_000 * Math.pow(2, failures - 1), 10 * 60_000)
            : isCertOrDescriptorIssue
              ? Math.min(5000 * failures, 30_000)
            : isHostUnreachable
              ? Math.min(15000 * Math.pow(2, failures - 1), 180000)
              : isTimeoutLike
                ? Math.min(5000 * Math.pow(2, failures - 1), 90000)
                : Math.min(2000 * Math.pow(2, failures - 1), 30000);
        connectBackoffRef.current.set(peer, { until: Date.now() + backoff, failures });
        console.warn('[P2P] connectToPeer failed', {
          peer,
          error: errorCode,
          category: isEndpointUnavailable
            ? 'endpoint-unavailable'
            : (isCertOrDescriptorIssue ? 'descriptor' : (isHostUnreachable ? 'network-unreachable' : (isTimeoutLike ? 'timeout' : 'generic'))),
          backoffMs: backoff
        });
        throw finalError;
      } finally {
        connectInFlightRef.current.delete(peer);
      }
    })();

    connectInFlightRef.current.set(peer, promise);
    return promise;
  }, [connectToPeerBase, getPeerCertificate, invalidatePeerCert, isPeerConnected, ensureInitialized, options?.ensureDiscoveryPublished]);

  const disconnectPeer = useCallback(
    createDisconnectPeer(connectionRefs),
    []
  );

  const waitForPeerConnection = useCallback(
    createWaitForPeerConnection(connectionRefs, isPeerConnected),
    [isPeerConnected]
  );

  useEffect(() => {
    handleEncryptedMessagePayloadRef.current = options?.handleEncryptedMessagePayload || null;
  }, [options?.handleEncryptedMessagePayload]);

  const handleIncomingP2PMessage = useCallback(
    createHandleIncomingP2PMessage(incomingMessageRefs),
    []
  );

  useEffect(() => {
    handleIncomingP2PMessageRef.current = handleIncomingP2PMessage;
  }, [handleIncomingP2PMessage]);

  const getP2PStats = useCallback(
    () => ({
      isInitialized: p2pStatus.isInitialized,
      connectedPeers: [...p2pStatus.connectedPeers],
      totalConnections: p2pStatus.connectedPeers.length,
      transportConnected: p2pStatus.transportConnected,
      lastError: p2pStatus.lastError,
    }),
    [p2pStatus]
  );

  const sendP2PReadReceipt = useCallback(
    createSendP2PReadReceipt(receiptRefs, isPeerConnected),
    [isPeerConnected]
  );

  useEffect(() => {
    return () => {
      destroyService();
    };
  }, [destroyService]);

  useEffect(() => {
    if (!username || !hybridKeys?.dilithium?.secretKey) {
      return;
    }
    if (p2pStatus.isInitialized && p2pServiceRef.current) {
      return;
    }
    ensureInitialized().catch((error) => {
      console.warn('[P2P] initialize failed', error);
    });
  }, [username, hybridKeys?.dilithium?.secretKey, p2pStatus.isInitialized, ensureInitialized]);

  useEffect(() => {
    const interval = setInterval(() => {
      try {
        const cutoff = Date.now() - RECEIPT_RETENTION_MS;
        for (const [id, ts] of sentP2PReceiptsRef.current.entries()) {
          if (ts < cutoff) sentP2PReceiptsRef.current.delete(id);
        }

        if (channelSequenceRef.current.size > 256) {
          const entries = [...channelSequenceRef.current.entries()];
          entries.slice(0, entries.length - 256).forEach(([key]) => channelSequenceRef.current.delete(key));
        }
      } catch { }
    }, RECEIPT_RETENTION_MS);
    return () => { try { clearInterval(interval); } catch { } };
  }, []);

  useEffect(() => {
    const onPeerConnected = (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const peer = d?.peer;
        if (peer) {
          connectBackoffRef.current.delete(peer);
          invalidatePeerCert(peer);
          getPeerCertificate(peer, true).then(cert => {
            if (cert) {
              const pk = toUint8(cert.dilithiumPublicKey);
              if (pk && p2pServiceRef.current) {
                p2pServiceRef.current.addPeerDilithiumKey(peer, pk);
              }
            }
          }).catch(() => { });
        }
      } catch { }
    };
    try {
      window.addEventListener(EventType.P2P_PEER_CONNECTED, onPeerConnected as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.P2P_PEER_CONNECTED, onPeerConnected as EventListener);
      } catch { }
    };
  }, [getPeerCertificate, invalidatePeerCert]);

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
          }).catch(() => { });
        }
      } catch { }
    };
    try {
      window.addEventListener(EventType.P2P_FETCH_PEER_CERT, onFetchPeerCert as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.P2P_FETCH_PEER_CERT, onFetchPeerCert as EventListener);
      } catch { }
    };
  }, [getPeerCertificate]);

  useEffect(() => {
    const onKeysUpdated = () => {
      peerCertificateCacheRef.current.clear();
      routeProofCacheRef.current.clear();
      peerAuthCacheRef.current = buildAuthenticator();
      peerCertFailureRef.current.clear();
      connectBackoffRef.current.clear();
    };
    try {
      window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
      } catch { }
    };
  }, []);

  return {
    p2pStatus,
    initializeP2P,
    connectToPeer,
    disconnectPeer,
    isPeerConnected,
    getP2PStats,
    waitForPeerConnection,
    sendP2PReadReceipt,
    p2pServiceRef,
  };
}
