import React, { useEffect, useRef } from 'react';
import { SecurityAuditLogger } from '../../lib/cryptography/audit-logger';
import { getSignalingServerUrl } from '../../config/p2p.config';
import { EventType } from '../../lib/types/event-types';

interface P2PStatus {
  isInitialized?: boolean;
  signalingConnected?: boolean;
  connectedPeers?: string[];
}

interface UseP2PConnectionManagerProps {
  isLoggedIn: boolean;
  selectedServerUrl: string;
  p2pHybridKeys: any;
  selectedConversation: string | null;
  conversations?: any[];
  p2pMessaging: {
    p2pStatus: P2PStatus | null;
    initializeP2P: (url: string) => Promise<void>;
    isPeerConnected: (peer: string) => boolean;
    connectToPeer: (peer: string) => Promise<void>;
  };
}

export function useP2PConnectionManager({
  isLoggedIn,
  selectedServerUrl,
  p2pHybridKeys,
  selectedConversation,
  conversations = [],
  p2pMessaging,
}: UseP2PConnectionManagerProps) {
  const p2pMessagingRef = useRef(p2pMessaging);

  useEffect(() => {
    p2pMessagingRef.current = p2pMessaging;
  }, [p2pMessaging]);

  const p2pInitAttemptRef = useRef(0);
  const p2pInitializedRef = useRef(false);
  const p2pSignalingConnectedRef = useRef(false);
  const userInitiatedSelectionRef = useRef(false);
  const lastSelectedConversationRef = useRef<string | null>(null);
  const connectionAttemptsRef = useRef<Map<string, { inProgress: boolean; lastAttempt: number }>>(new Map());
  const processedPeerConnectionsRef = useRef<Set<string>>(new Set());

  // Initialize P2P
  useEffect(() => {
    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    if (!isLoggedIn || !selectedServerUrl || !p2pHybridKeys) {
      p2pInitAttemptRef.current = 0;
      return () => { if (retryTimer) clearTimeout(retryTimer); };
    }

    const tryInit = () => {
      if (cancelled) return;
      if (p2pMessaging.p2pStatus?.isInitialized && p2pMessaging.p2pStatus?.signalingConnected) {
        p2pInitAttemptRef.current = 0;
        return;
      }
      if (p2pInitAttemptRef.current >= 5) return;

      p2pInitAttemptRef.current += 1;
      const attempt = p2pInitAttemptRef.current;
      const signalingUrl = getSignalingServerUrl(selectedServerUrl);

      p2pMessaging.initializeP2P(signalingUrl).catch(() => {
        SecurityAuditLogger.log('warn', 'p2p-init-retry-failed', { attempt });
      }).finally(() => {
        if (cancelled) return;
        if (p2pMessaging.p2pStatus?.isInitialized && p2pMessaging.p2pStatus?.signalingConnected) {
          p2pInitAttemptRef.current = 0;
          return;
        }
        const backoff = Math.min(2000 * attempt, 10000);
        retryTimer = setTimeout(tryInit, backoff);
      });
    };

    tryInit();

    return () => {
      cancelled = true;
      if (retryTimer) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
    };
  }, [isLoggedIn, selectedServerUrl, p2pHybridKeys]);

  // Track P2P status changes
  useEffect(() => {
    const isInit = p2pMessaging.p2pStatus?.isInitialized ?? false;
    const signaling = p2pMessaging.p2pStatus?.signalingConnected ?? false;
    if (p2pInitializedRef.current !== isInit || p2pSignalingConnectedRef.current !== signaling) {
      p2pInitializedRef.current = isInit;
      p2pSignalingConnectedRef.current = signaling;
    }
  }, [p2pMessaging.p2pStatus?.isInitialized, p2pMessaging.p2pStatus?.signalingConnected]);

  // Listen for peer connection events
  useEffect(() => {
    const handlePeerConnected = (evt: Event) => {
      try {
        const peer = (evt as CustomEvent).detail?.peer;
        if (peer) {
          if (processedPeerConnectionsRef.current.has(peer)) return;
          processedPeerConnectionsRef.current.add(peer);
          connectionAttemptsRef.current.set(peer, { inProgress: false, lastAttempt: Date.now() });
        }
      } catch { }
    };

    const handlePeerDisconnected = (evt: Event) => {
      try {
        const peer = (evt as CustomEvent).detail?.peer;
        if (peer) processedPeerConnectionsRef.current.delete(peer);
      } catch { }
    };

    const handlePeerInteraction = (evt: Event) => {
      try {
        const peer = (evt as CustomEvent).detail?.peer || (evt as CustomEvent).detail?.from;
        if (peer && p2pMessagingRef.current.p2pStatus?.signalingConnected) {
          const p2p = p2pMessagingRef.current;
          if (!p2p.isPeerConnected(peer)) {
            const now = Date.now();
            const attemptInfo = connectionAttemptsRef.current.get(peer);
            if (attemptInfo?.inProgress) return;
            if (attemptInfo && (now - attemptInfo.lastAttempt) < 10000) return;

            connectionAttemptsRef.current.set(peer, { inProgress: true, lastAttempt: now });
            p2p.connectToPeer(peer)
              .finally(() => {
                const info = connectionAttemptsRef.current.get(peer);
                if (info) info.inProgress = false;
              });
          }
        }
      } catch { }
    };

    window.addEventListener(EventType.P2P_PEER_CONNECTED, handlePeerConnected as EventListener);
    window.addEventListener(EventType.P2P_PEER_DISCONNECTED, handlePeerDisconnected as EventListener);
    window.addEventListener('peer-interaction', handlePeerInteraction as EventListener);

    return () => {
      window.removeEventListener(EventType.P2P_PEER_CONNECTED, handlePeerConnected as EventListener);
      window.removeEventListener(EventType.P2P_PEER_DISCONNECTED, handlePeerDisconnected as EventListener);
      window.removeEventListener('peer-interaction', handlePeerInteraction as EventListener);
    };
  }, []);

  // Proactively connect to online peers in the conversation list
  useEffect(() => {
    const isInitialized = p2pMessaging.p2pStatus?.isInitialized ?? false;
    const signalingConnected = p2pMessaging.p2pStatus?.signalingConnected ?? false;

    if (!isInitialized || !signalingConnected || !p2pHybridKeys) return;

    const p2p = p2pMessagingRef.current;
    const now = Date.now();

    // Limit to online peers or top 10 recent conversations to avoid flooding
    const activePeers = conversations
      .filter(c => c.isOnline || (c.unreadCount && c.unreadCount > 0))
      .slice(0, 10);

    for (const conv of activePeers) {
      const peer = conv.username;
      if (p2p.isPeerConnected(peer)) continue;

      const attemptInfo = connectionAttemptsRef.current.get(peer);
      if (attemptInfo?.inProgress) continue;
      if (attemptInfo && (now - attemptInfo.lastAttempt) < 30000) continue;

      connectionAttemptsRef.current.set(peer, { inProgress: true, lastAttempt: now });
      p2p.connectToPeer(peer)
        .finally(() => {
          const info = connectionAttemptsRef.current.get(peer);
          if (info) info.inProgress = false;
        });
    }
  }, [conversations, p2pHybridKeys, p2pMessaging.p2pStatus?.isInitialized, p2pMessaging.p2pStatus?.signalingConnected]);

  // Connect to peer when conversation is selected
  useEffect(() => {
    if (selectedConversation !== lastSelectedConversationRef.current) {
      if (lastSelectedConversationRef.current !== null) {
        userInitiatedSelectionRef.current = true;
      }
      lastSelectedConversationRef.current = selectedConversation;
    }

    const isInitialized = p2pMessaging.p2pStatus?.isInitialized ?? false;
    const signalingConnected = p2pMessaging.p2pStatus?.signalingConnected ?? false;

    if (!isInitialized || !signalingConnected) {
      return;
    }
    if (!selectedConversation || !p2pHybridKeys) return;

    const p2p = p2pMessagingRef.current;
    if (!p2p?.isPeerConnected || !p2p?.connectToPeer) return;

    const connected = p2p.isPeerConnected(selectedConversation);

    if (!connected) {
      const now = Date.now();
      const attemptInfo = connectionAttemptsRef.current.get(selectedConversation);

      if (attemptInfo?.inProgress) return;
      if (attemptInfo && (now - attemptInfo.lastAttempt) < 10000) return;

      connectionAttemptsRef.current.set(selectedConversation, { inProgress: true, lastAttempt: now });

      p2p.connectToPeer(selectedConversation)
        .then(() => {
          connectionAttemptsRef.current.set(selectedConversation, { inProgress: false, lastAttempt: now });
        })
        .catch(() => {
          connectionAttemptsRef.current.set(selectedConversation, { inProgress: false, lastAttempt: now });
        });
    }
  }, [selectedConversation, p2pHybridKeys, p2pMessaging.p2pStatus?.isInitialized, p2pMessaging.p2pStatus?.signalingConnected]);
}

