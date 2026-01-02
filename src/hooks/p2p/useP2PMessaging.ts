import React, { useEffect, useRef, useState, useCallback } from 'react';
import { WebRTCP2PService } from '../../lib/webrtc-p2p';
import { EventType } from '../../lib/types/event-types';
import { MAX_P2P_INCOMING_QUEUE, RECEIPT_RETENTION_MS, RATE_LIMIT_WINDOW_MS } from '../../lib/constants';
import { createSendP2PReadReceipt } from './receipts';
import { sanitizeErrorMessage } from '../../lib/sanitizers';
import type {
  P2PStatus,
  P2PMessage,
  EncryptedMessage,
  HybridKeys,
  PeerCertificateBundle,
  RouteProofRecord,
  CertCacheEntry,
  QueuedItem,
} from '../../lib/types/p2p-types';
import {
  createBoundedQueue,
  buildAuthenticator,
  toUint8,
} from '../../lib/utils/p2p-utils';
import {
  createGetPeerCertificate,
  createInvalidatePeerCert,
  createDeriveConversationKey,
  createEnsurePeerAuthenticated,
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
  createEnqueueOutbound,
  createFlushPeerQueue,
  createSendP2PMessage,
  createHandleIncomingP2PMessage,
} from './messaging';

export { type P2PMessage, type EncryptedMessage, type P2PStatus, type P2PSendResult, type P2PSendStatus, type PeerCertificateBundle, type HybridKeys, type RemoteHybridKeys } from '../../lib/types/p2p-types';

// Hook that wires certificate, connection, and messaging helpers
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
  const incomingQueueRef = useRef(createBoundedQueue<EncryptedMessage>(MAX_P2P_INCOMING_QUEUE));
  const [incomingMessages, setIncomingMessages] = useState<EncryptedMessage[]>([]);
  const messageCallbackRef = useRef<((message: EncryptedMessage) => void) | null>(null);
  const peerAuthCacheRef = useRef(buildAuthenticator());
  const peerWaitersRef = useRef(new Map<string, Set<(ok: boolean) => void>>());
  const peerCertificateCacheRef = useRef(new Map<string, CertCacheEntry>());
  const routeProofCacheRef = useRef(new Map<string, RouteProofRecord>());
  const channelSequenceRef = useRef(new Map<string, number>());
  const authLockRef = useRef<Promise<void> | null>(null);
  const rateLimitRef = useRef<Map<string, { windowStart: number; count: number }>>(new Map());
  const handleIncomingP2PMessageRef = useRef<((message: P2PMessage) => Promise<void>) | null>(null);

  const sentP2PReceiptsRef = useRef<Map<string, number>>(new Map());
  const processedReadReceiptsRef = useRef<Set<string>>(new Set());

  const outboundQueueRef = useRef(new Map<string, QueuedItem[]>());
  const flushTimersRef = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  const flushPeerQueueRef = useRef<(peer: string) => void>(() => { });

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
    incomingQueueRef,
    outboundQueueRef,
    flushTimersRef,
    handleIncomingP2PMessageRef,
  };

  const connectionSetters = {
    setP2PStatus,
    setIncomingMessages,
    setLastError,
    clearLastError,
  };

  const messagingRefs = {
    p2pServiceRef,
    routeProofCacheRef,
    channelSequenceRef,
    rateLimitRef,
    outboundQueueRef,
    flushTimersRef,
    messageCallbackRef,
    sentP2PReceiptsRef,
    processedReadReceiptsRef,
  };

  const receiptRefs = {
    p2pServiceRef,
    sentP2PReceiptsRef,
  };

  const deriveConversationKey = useCallback(
    createDeriveConversationKey(hybridKeys),
    [hybridKeys?.dilithium?.publicKeyBase64]
  );

  const getPeerCertificate = useCallback(
    createGetPeerCertificate(certificateRefs, {
      fetchPeerCertificates: options?.fetchPeerCertificates,
      trustedIssuerDilithiumPublicKeyBase64: options?.trustedIssuerDilithiumPublicKeyBase64,
    }),
    [options?.fetchPeerCertificates, options?.trustedIssuerDilithiumPublicKeyBase64]
  );

  const invalidatePeerCert = useCallback(
    createInvalidatePeerCert(certificateRefs),
    []
  );

  const ensurePeerAuthenticated = useCallback(
    createEnsurePeerAuthenticated(certificateRefs, hybridKeys, deriveConversationKey, getPeerCertificate),
    [hybridKeys?.dilithium, deriveConversationKey, getPeerCertificate]
  );

  const destroyService = useCallback(
    createDestroyService(connectionRefs, connectionSetters, options),
    []
  );

  const initializeP2P = useCallback(
    createInitializeP2P(connectionRefs, connectionSetters, username, hybridKeys, destroyService, options),
    [username, hybridKeys, destroyService, options]
  );

  const isPeerConnected = useCallback(
    createIsPeerConnected(p2pStatus.connectedPeers),
    [p2pStatus.connectedPeers]
  );

  const connectToPeer = useCallback(
    createConnectToPeer(connectionRefs, hybridKeys, deriveConversationKey, getPeerCertificate, setLastError),
    [hybridKeys?.dilithium, deriveConversationKey, getPeerCertificate, setLastError]
  );

  const disconnectPeer = useCallback(
    createDisconnectPeer(connectionRefs),
    []
  );

  const waitForPeerConnection = useCallback(
    createWaitForPeerConnection(connectionRefs, isPeerConnected),
    [isPeerConnected]
  );

  const enqueueOutbound = useCallback(
    createEnqueueOutbound(messagingRefs),
    []
  );

  const flushPeerQueue = useCallback(
    createFlushPeerQueue(messagingRefs, flushPeerQueueRef),
    []
  );

  useEffect(() => {
    flushPeerQueueRef.current = flushPeerQueue;
  }, [flushPeerQueue]);

  const sendP2PMessage = useCallback(
    createSendP2PMessage(
      messagingRefs,
      hybridKeys,
      deriveConversationKey,
      ensurePeerAuthenticated,
      getPeerCertificate,
      enqueueOutbound,
      connectToPeer,
      setLastError
    ),
    [hybridKeys?.dilithium, deriveConversationKey, ensurePeerAuthenticated, getPeerCertificate, enqueueOutbound, connectToPeer, setLastError]
  );

  const handleIncomingP2PMessage = useCallback(
    createHandleIncomingP2PMessage(
      messagingRefs,
      username,
      hybridKeys,
      deriveConversationKey,
      ensurePeerAuthenticated,
      getPeerCertificate,
      invalidatePeerCert,
      appendIncoming
    ),
    [username, hybridKeys, deriveConversationKey, ensurePeerAuthenticated, getPeerCertificate, invalidatePeerCert, appendIncoming]
  );

  useEffect(() => {
    handleIncomingP2PMessageRef.current = handleIncomingP2PMessage;
  }, [handleIncomingP2PMessage]);

  const onMessage = useCallback((callback: (message: EncryptedMessage) => void) => {
    messageCallbackRef.current = callback;
  }, []);

  const getP2PStats = useCallback(
    () => ({
      isInitialized: p2pStatus.isInitialized,
      connectedPeers: [...p2pStatus.connectedPeers],
      totalConnections: p2pStatus.connectedPeers.length,
      signalingConnected: p2pStatus.signalingConnected,
      lastError: p2pStatus.lastError,
    }),
    [p2pStatus]
  );

  const sendP2PReadReceipt = useCallback(
    createSendP2PReadReceipt(receiptRefs, hybridKeys, isPeerConnected, getPeerCertificate),
    [hybridKeys?.dilithium, isPeerConnected, getPeerCertificate]
  );

  useEffect(() => {
    const onPqEstablished = (evt: Event) => {
      try {
        const d: any = (evt as CustomEvent).detail || {};
        const peer = d?.peer;
        if (peer) {
          flushPeerQueueRef.current?.(peer);
        }
      } catch { }
    };
    try {
      window.addEventListener(EventType.P2P_PQ_ESTABLISHED, onPqEstablished as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.P2P_PQ_ESTABLISHED, onPqEstablished as EventListener);
      } catch { }
    };
  }, []);

  useEffect(() => {
    return () => {
      destroyService();
    };
  }, [destroyService]);

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

        const rateLimitCutoff = Date.now() - RATE_LIMIT_WINDOW_MS * 2;
        for (const [peer, bucket] of rateLimitRef.current.entries()) {
          if (bucket.windowStart < rateLimitCutoff) {
            rateLimitRef.current.delete(peer);
          }
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
    p2pServiceRef,
  };
}
