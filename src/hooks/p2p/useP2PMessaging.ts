import { useEffect, useLayoutEffect, useRef, useState, useCallback, useMemo } from 'react';
import { SecureP2PService } from '../../lib/transport/secure-p2p-service';
import { EventType } from '../../lib/types/event-types';
import { AUTH_USERNAME_REGEX, MAX_CONCURRENT_P2P_CONNECTS } from '../../lib/constants';
import { p2pTransport } from '../../lib/transport/p2p-transport';
import { hasPrototypePollutionKeys, isPlainObject } from '../../lib/sanitizers';
import type {
  P2PStatus,
  P2PMessage,
  HybridKeys,
  PeerCertificateBundle,
  CertCacheEntry,
} from '../../lib/types/p2p-types';
import {
  createP2PError,
} from '../../lib/utils/p2p-utils';
import {
  createGetPeerCertificate,
} from './certificates';
import {
  createDestroyService,
  createInitializeP2P,
  createConnectToPeer,
  createIsPeerConnected,
} from './connection';
import {
  createHandleIncomingP2PMessage,
} from './messaging';
import { invalidateDiscoveryCache } from '../discovery/useDiscovery';
import {
  KEY_TRANSPARENCY_MAX_LOG_SIZE,
  isKeyTransparencyHash,
} from '../../../shared/key-transparency-protocol.js';
import { isKeyTransparencyPeerRevoked } from '../../lib/key-transparency/verified-material';
import { awaitPeerIdentityRevocation } from '../../lib/key-transparency/revocation';

const MAX_P2P_FAILURE_CACHE_ENTRIES = 512;
const ENDPOINT_UNAVAILABLE_COOLDOWN_MS = 60_000;
const MAX_CONCURRENT_P2P_CERT_REQUESTS = 32;

function setBoundedFailure<K, V>(map: Map<K, V>, key: K, value: V): void {
  if (!map.has(key) && map.size >= MAX_P2P_FAILURE_CACHE_ENTRIES) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.delete(key);
  map.set(key, value);
}

// Hook that wires certificate, connection, and messaging helpers
export function useP2PMessaging(
  username: string,
  hybridKeys: HybridKeys | null,
  options?: {
    fetchPeerCertificates?: (peer: string, bypassCache?: boolean) => Promise<PeerCertificateBundle | null>;
    onServiceReady?: (service: SecureP2PService | null) => void;
    handleEncryptedMessagePayload?: (msg: any) => Promise<boolean | void>;
    ensureDiscoveryPublished?: (force?: boolean) => Promise<boolean>;
  },
) {
  const p2pServiceRef = useRef<SecureP2PService | null>(null);
  const [p2pStatus, setP2PStatus] = useState<P2PStatus>({
    isInitialized: false,
    connectedPeers: [],
  });
  const peerCertificateCacheRef = useRef(new Map<string, CertCacheEntry>());
  const peerCertFailureRef = useRef(new Map<string, { until: number; failures: number }>());
  const peerCertInFlightRef = useRef(new Map<string, Promise<PeerCertificateBundle | null>>());
  const channelSequenceRef = useRef(new Map<string, number>());
  const handleIncomingP2PMessageRef = useRef<((message: P2PMessage) => Promise<boolean>) | null>(null);
  const handleEncryptedMessagePayloadRef = useRef<((message: any) => Promise<boolean | void>) | null>(null);

  const connectInFlightRef = useRef(new Map<string, Promise<void>>());
  const connectBackoffRef = useRef(new Map<string, { until: number; failures: number; endpointUnavailable: boolean }>());
  const initInFlightRef = useRef<Promise<void> | null>(null);
  const accountGenerationRef = useRef(0);
  const inFlightP2PRetriesRef = useRef({ generation: 0, count: 0, bytes: 0 });
  const activeUsernameRef = useRef<string | null>(null);
  const onServiceReadyRef = useRef(options?.onServiceReady);
  useLayoutEffect(() => {
    onServiceReadyRef.current = options?.onServiceReady;
  }, [options?.onServiceReady]);
  const stableConnectionOptions = useMemo(() => ({
    onServiceReady: (service: SecureP2PService | null) => onServiceReadyRef.current?.(service),
  }), []);

  const certificateRefs = {
    peerCertificateCacheRef,
  };

  const connectionRefs = {
    p2pServiceRef,
    peerCertificateCacheRef,
    channelSequenceRef,
    handleIncomingP2PMessageRef,
  };

  const connectionSetters = {
    setP2PStatus,
  };

  const incomingMessageRefs = {
    handleEncryptedMessagePayloadRef,
    accountGenerationRef,
    inFlightRetriesRef: inFlightP2PRetriesRef,
  };

  const getPeerCertificateBase = useCallback(
    createGetPeerCertificate(certificateRefs, {
      ownerUsername: username,
      fetchPeerCertificates: options?.fetchPeerCertificates,
      isCurrentOwner: () => activeUsernameRef.current === username,
    }),
    [username, options?.fetchPeerCertificates]
  );

  const getPeerCertificate = useCallback(
    async (peer: string, bypassCache = false): Promise<PeerCertificateBundle | null> => {
      if (activeUsernameRef.current !== username) return null;
      const normalizedPeer = typeof peer === 'string' ? peer.trim().toLowerCase() : '';
      if (normalizedPeer !== peer || !AUTH_USERNAME_REGEX.test(normalizedPeer)) return null;
      peer = normalizedPeer;
      const generation = accountGenerationRef.current;
      const now = Date.now();
      const failure = peerCertFailureRef.current.get(peer);
      if (!bypassCache && failure && failure.until > now) {
        return null;
      }

      const requestKey = `${peer}\0${bypassCache ? 'refresh' : 'cached'}`;
      const existing = peerCertInFlightRef.current.get(requestKey);
      if (existing) return existing;
      if (peerCertInFlightRef.current.size >= MAX_CONCURRENT_P2P_CERT_REQUESTS) {
        return null;
      }

      let pending!: Promise<PeerCertificateBundle | null>;
      pending = (async () => {
        const cert = await getPeerCertificateBase(peer, bypassCache);
        if (generation !== accountGenerationRef.current || activeUsernameRef.current !== username) return null;
        if (cert) {
          peerCertFailureRef.current.delete(peer);
          return cert;
        }

        const latestFailure = peerCertFailureRef.current.get(peer);
        const failures = (latestFailure?.failures ?? failure?.failures ?? 0) + 1;
        const backoff = Math.min(1500 * Math.pow(2, failures - 1), 15000);
        setBoundedFailure(peerCertFailureRef.current, peer, { until: Date.now() + backoff, failures });
        return null;
      })().finally(() => {
        if (peerCertInFlightRef.current.get(requestKey) === pending) {
          peerCertInFlightRef.current.delete(requestKey);
        }
      });
      peerCertInFlightRef.current.set(requestKey, pending);
      return pending;
    },
    [getPeerCertificateBase]
  );

  const destroyService = useCallback(
    createDestroyService(connectionRefs, connectionSetters, stableConnectionOptions),
    []
  );

  const initializeP2P = useCallback(
    createInitializeP2P(connectionRefs, connectionSetters, username, hybridKeys, destroyService, stableConnectionOptions),
    [username, hybridKeys, destroyService, stableConnectionOptions]
  );

  const ensureInitialized = useCallback(async (): Promise<boolean> => {
    if (!username || activeUsernameRef.current !== username) {
      return false;
    }
    if (p2pServiceRef.current && p2pStatus.isInitialized) {
      return true;
    }
    if (!username || hybridKeys?.native !== true) {
      return false;
    }

    if (!initInFlightRef.current) {
      let pending: Promise<void>;
      pending = initializeP2P().finally(() => {
        if (initInFlightRef.current === pending) initInFlightRef.current = null;
      });
      initInFlightRef.current = pending;
    }

    await initInFlightRef.current;
    return !!p2pServiceRef.current;
  }, [initializeP2P, username, hybridKeys?.native, p2pStatus.isInitialized]);

  const isPeerConnected = useCallback(
    createIsPeerConnected(p2pStatus.connectedPeers),
    [p2pStatus.connectedPeers]
  );

  const connectToPeerBase = useCallback(
    createConnectToPeer(connectionRefs, hybridKeys, getPeerCertificate, username),
    [hybridKeys?.dilithium, getPeerCertificate, username]
  );

  const connectToPeer = useCallback(async (peer: string): Promise<void> => {
    const normalizedPeer = typeof peer === 'string' ? peer.trim().toLowerCase() : '';
    if (normalizedPeer !== peer || !AUTH_USERNAME_REGEX.test(normalizedPeer)) {
      throw createP2PError('INVALID_PEER');
    }
    peer = normalizedPeer;
    const generation = accountGenerationRef.current;
    if (isPeerConnected(peer)) return;

    if (options?.ensureDiscoveryPublished) {
      void options.ensureDiscoveryPublished(false).catch(() => false);
    }

    const ready = await ensureInitialized();
    if (generation !== accountGenerationRef.current) throw createP2PError('AUTH_REQUIRED');
    if (!ready) {
      throw createP2PError('SERVICE_UNINITIALIZED');
    }

    const now = Date.now();
    const cooldown = connectBackoffRef.current.get(peer);
    if (cooldown && cooldown.until > now) {
      if (cooldown.endpointUnavailable && p2pTransport.hasAuthenticatedEndpoint(peer)) {
        connectBackoffRef.current.delete(peer);
      } else {
        return;
      }
    }

    const inflight = connectInFlightRef.current.get(peer);
    if (inflight) return inflight;
    if (connectInFlightRef.current.size >= MAX_CONCURRENT_P2P_CONNECTS) {
      throw createP2PError('TOO_MANY_CONNECTIONS');
    }

    const promise = (async () => {
      try {
        await connectToPeerBase(peer);
        if (generation !== accountGenerationRef.current) throw createP2PError('AUTH_REQUIRED');
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

        if (shouldForceRefreshAndRetry) {
          invalidateDiscoveryCache(peer);
          const refreshedCert = await getPeerCertificate(peer, true).catch(() => null);
          if (generation !== accountGenerationRef.current) throw createP2PError('AUTH_REQUIRED');
          if (refreshedCert) {
            try {
              await connectToPeerBase(peer);
              if (generation !== accountGenerationRef.current) throw createP2PError('AUTH_REQUIRED');
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
            ? ENDPOINT_UNAVAILABLE_COOLDOWN_MS
            : isCertOrDescriptorIssue
              ? Math.min(5000 * failures, 30_000)
            : isHostUnreachable
              ? Math.min(15000 * Math.pow(2, failures - 1), 180000)
              : isTimeoutLike
                ? Math.min(5000 * Math.pow(2, failures - 1), 90000)
                : Math.min(2000 * Math.pow(2, failures - 1), 30000);
        if (generation === accountGenerationRef.current) {
          setBoundedFailure(connectBackoffRef.current, peer, {
            until: Date.now() + backoff,
            failures,
            endpointUnavailable: isEndpointUnavailable,
          });
        }
        throw finalError;
      } finally {
        if (connectInFlightRef.current.get(peer) === promise) {
          connectInFlightRef.current.delete(peer);
        }
      }
    })();

    connectInFlightRef.current.set(peer, promise);
    return promise;
  }, [connectToPeerBase, getPeerCertificate, isPeerConnected, ensureInitialized, options?.ensureDiscoveryPublished]);

  useLayoutEffect(() => {
    handleEncryptedMessagePayloadRef.current = options?.handleEncryptedMessagePayload || null;
  }, [options?.handleEncryptedMessagePayload]);

  const handleIncomingP2PMessage = useCallback(
    createHandleIncomingP2PMessage(incomingMessageRefs),
    []
  );

  useLayoutEffect(() => {
    handleIncomingP2PMessageRef.current = handleIncomingP2PMessage;
  }, [handleIncomingP2PMessage]);

  useLayoutEffect(() => {
    const account = username || null;
    if (activeUsernameRef.current === account) return;
    const previous = activeUsernameRef.current;
    activeUsernameRef.current = account;
    accountGenerationRef.current += 1;

    peerCertificateCacheRef.current.clear();
    peerCertFailureRef.current.clear();
    peerCertInFlightRef.current.clear();
    channelSequenceRef.current.clear();
    connectInFlightRef.current.clear();
    connectBackoffRef.current.clear();
    inFlightP2PRetriesRef.current = { generation: accountGenerationRef.current, count: 0, bytes: 0 };
    initInFlightRef.current = null;

    if (previous !== null) void destroyService();
  }, [username, destroyService]);

  useEffect(() => {
    return () => {
      accountGenerationRef.current += 1;
      handleEncryptedMessagePayloadRef.current = null;
      handleIncomingP2PMessageRef.current = null;
      inFlightP2PRetriesRef.current = {
        generation: accountGenerationRef.current,
        count: 0,
        bytes: 0,
      };
      void destroyService();
    };
  }, [destroyService]);

  useEffect(() => {
    if (!username || hybridKeys?.native !== true) {
      if (p2pServiceRef.current) {
        void destroyService();
      }
      return;
    }
    if (p2pStatus.isInitialized && p2pServiceRef.current) {
      return;
    }
    ensureInitialized().catch((error) => {
      console.warn('[P2P] initialize failed', error);
    });
  }, [username, hybridKeys?.native, p2pStatus.isInitialized, ensureInitialized, destroyService]);

  useEffect(() => {
    const onPeerConnected = (evt: Event) => {
      try {
        if (!(evt instanceof CustomEvent)) return;
        const detail = evt.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        if (Object.keys(detail).sort().join(',') !== 'account,peer') return;
        if (detail.account !== username || activeUsernameRef.current !== username) return;
        if (typeof detail.peer !== 'string' || !AUTH_USERNAME_REGEX.test(detail.peer)) return;
        connectBackoffRef.current.delete(detail.peer);
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
  }, [username]);

  useEffect(() => {
    const onFetchPeerCert = (evt: Event) => {
      try {
        if (!(evt instanceof CustomEvent)) return;
        const detail = evt.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        if (Object.keys(detail).sort().join(',') !== 'account,peer') return;
        if (detail.account !== username || activeUsernameRef.current !== username) return;
        const peer = detail.peer;
        if (typeof peer !== 'string' || !AUTH_USERNAME_REGEX.test(peer)) return;
        void getPeerCertificate(peer, true)
          .then((cert) => cert ? p2pTransport.registerPeerCertificate(peer, cert) : undefined)
          .catch(() => { });
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
  }, [getPeerCertificate, username]);

  useEffect(() => {
    const onTransparencyRootChanged = (evt: Event) => {
      try {
        if (!(evt instanceof CustomEvent)) return;
        const detail = evt.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        if (Object.keys(detail).sort().join(',') !== 'account,peer,rootCommitment,version') return;
        if (detail.account !== username || activeUsernameRef.current !== username) return;
        const peer = detail.peer;
        if (
          typeof peer !== 'string' ||
          peer === username ||
          peer !== peer.trim().toLowerCase() ||
          !AUTH_USERNAME_REGEX.test(peer) ||
          !isKeyTransparencyHash(detail.rootCommitment) ||
          typeof detail.version !== 'number' ||
          !Number.isSafeInteger(detail.version) ||
          detail.version < 1 ||
          detail.version > KEY_TRANSPARENCY_MAX_LOG_SIZE ||
          !isKeyTransparencyPeerRevoked(username, peer)
        ) return;
        const generation = accountGenerationRef.current;
        peerCertificateCacheRef.current.delete(peer);
        peerCertFailureRef.current.delete(peer);
        peerCertInFlightRef.current.clear();
        connectInFlightRef.current.delete(peer);
        connectBackoffRef.current.delete(peer);
        invalidateDiscoveryCache(peer);

        void (async () => {
          await p2pTransport.revokePeerCertificate(username, peer);
          if (
            generation !== accountGenerationRef.current ||
            activeUsernameRef.current !== username ||
            !await awaitPeerIdentityRevocation(username, peer)
          ) return;
          const cert = await getPeerCertificate(peer, true);
          if (
            !cert ||
            generation !== accountGenerationRef.current ||
            activeUsernameRef.current !== username
          ) return;
          await p2pTransport.registerPeerCertificate(peer, cert);
        })().catch(() => { });
      } catch { }
    };
    window.addEventListener(
      EventType.KEY_TRANSPARENCY_ROOT_CHANGED,
      onTransparencyRootChanged as EventListener,
    );
    return () => window.removeEventListener(
      EventType.KEY_TRANSPARENCY_ROOT_CHANGED,
      onTransparencyRootChanged as EventListener,
    );
  }, [getPeerCertificate, username]);

  useEffect(() => {
    const onKeysUpdated = () => {
      peerCertificateCacheRef.current.clear();
      peerCertFailureRef.current.clear();
      peerCertInFlightRef.current.clear();
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
    connectToPeer,
    isPeerConnected,
    p2pServiceRef,
  };
}
