/**
 * P2P Messaging Hook
 * Integrates WebRTC P2P transport with encrypted messaging
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { WebRTCP2PService } from '../lib/webrtc-p2p';
import { CryptoUtils } from '../lib/unified-crypto';

interface P2PMessage {
  type: 'chat' | 'signal' | 'heartbeat' | 'dummy';
  from: string;
  to: string;
  timestamp: number;
  payload: any;
  signature?: string;
}

interface EncryptedMessage {
  id: string;
  from: string;
  to: string;
  content: string;
  timestamp: number;
  encrypted: boolean;
  p2p: boolean;
}

interface P2PStatus {
  isInitialized: boolean;
  connectedPeers: string[];
  signalingConnected: boolean;
  lastError: string | null;
}

export function useP2PMessaging(username: string, hybridKeys: any) {
  const p2pServiceRef = useRef<WebRTCP2PService | null>(null);
  const [p2pStatus, setP2PStatus] = useState<P2PStatus>({
    isInitialized: false,
    connectedPeers: [],
    signalingConnected: false,
    lastError: null
  });

  const [incomingMessages, setIncomingMessages] = useState<EncryptedMessage[]>([]);
  const messageCallbackRef = useRef<((message: EncryptedMessage) => void) | null>(null);

  /**
   * Initialize P2P service
   */
  const initializeP2P = useCallback(async (signalingServerUrl: string) => {
    try {
      if (p2pServiceRef.current) {
        p2pServiceRef.current.destroy();
      }

      const p2pService = new WebRTCP2PService(username);
      p2pServiceRef.current = p2pService;

      // Set up message handler
      p2pService.onMessage((message: P2PMessage) => {
        handleIncomingP2PMessage(message);
      });

      // Set up connection handlers
      p2pService.onPeerConnected((peerUsername: string) => {
        console.log(`[P2P] Connected to peer: ${peerUsername}`);
        setP2PStatus(prev => ({
          ...prev,
          connectedPeers: [...prev.connectedPeers.filter(p => p !== peerUsername), peerUsername]
        }));
      });

      p2pService.onPeerDisconnected((peerUsername: string) => {
        console.log(`[P2P] Disconnected from peer: ${peerUsername}`);
        setP2PStatus(prev => ({
          ...prev,
          connectedPeers: prev.connectedPeers.filter(p => p !== peerUsername)
        }));
      });

      await p2pService.initialize(signalingServerUrl);

      setP2PStatus(prev => ({
        ...prev,
        isInitialized: true,
        signalingConnected: true,
        lastError: null
      }));

      console.log('[P2P] Service initialized successfully');
    } catch (error) {
      console.error('[P2P] Failed to initialize:', error);
      setP2PStatus(prev => ({
        ...prev,
        isInitialized: false,
        lastError: error instanceof Error ? error.message : 'Unknown error'
      }));
    }
  }, [username]);

  /**
   * Connect to a specific peer
   */
  const connectToPeer = useCallback(async (peerUsername: string) => {
    if (!p2pServiceRef.current) {
      throw new Error('P2P service not initialized');
    }

    try {
      await p2pServiceRef.current.connectToPeer(peerUsername);
      console.log(`[P2P] Connecting to peer: ${peerUsername}`);
    } catch (error) {
      console.error(`[P2P] Failed to connect to ${peerUsername}:`, error);
      throw error;
    }
  }, []);

  /**
   * Send encrypted message via P2P
   */
  const sendP2PMessage = useCallback(async (
    to: string, 
    content: string, 
    remoteHybridKeys: any
  ): Promise<void> => {
    if (!p2pServiceRef.current) {
      throw new Error('P2P service not initialized');
    }

    if (!hybridKeys) {
      throw new Error('Local hybrid keys not available');
    }

    try {
      // Create message object
      const messageObj = {
        id: crypto.randomUUID(),
        content,
        timestamp: Date.now(),
        from: username,
        to
      };

      // Encrypt message using hybrid encryption
      const encryptedPayload = await CryptoUtils.Hybrid.encryptMessage(
        messageObj,
        remoteHybridKeys,
        hybridKeys
      );

      // Send via P2P
      await p2pServiceRef.current.sendMessage(to, encryptedPayload, 'chat');

      console.log(`[P2P] Message sent to ${to} via P2P`);
    } catch (error) {
      console.error('[P2P] Failed to send message:', error);
      throw error;
    }
  }, [username, hybridKeys]);

  /**
   * Handle incoming P2P messages
   */
  const handleIncomingP2PMessage = useCallback(async (message: P2PMessage) => {
    if (message.type !== 'chat') {
      return; // Ignore non-chat messages
    }

    try {
      if (!hybridKeys) {
        console.error('[P2P] Cannot decrypt message - no local keys');
        return;
      }

      // Decrypt the message payload
      const decryptedMessage = await CryptoUtils.Hybrid.decryptMessage(
        message.payload,
        hybridKeys
      );

      const encryptedMessage: EncryptedMessage = {
        id: decryptedMessage.id || crypto.randomUUID(),
        from: message.from,
        to: message.to,
        content: decryptedMessage.content,
        timestamp: decryptedMessage.timestamp || message.timestamp,
        encrypted: true,
        p2p: true
      };

      // Add to incoming messages
      setIncomingMessages(prev => [...prev, encryptedMessage]);

      // Call external callback if set
      if (messageCallbackRef.current) {
        messageCallbackRef.current(encryptedMessage);
      }

      console.log(`[P2P] Received encrypted message from ${message.from}`);
    } catch (error) {
      console.error('[P2P] Failed to decrypt incoming message:', error);
    }
  }, [hybridKeys]);

  /**
   * Set callback for incoming messages
   */
  const onMessage = useCallback((callback: (message: EncryptedMessage) => void) => {
    messageCallbackRef.current = callback;
  }, []);

  /**
   * Check if peer is connected via P2P
   */
  const isPeerConnected = useCallback((peerUsername: string): boolean => {
    return p2pStatus.connectedPeers.includes(peerUsername);
  }, [p2pStatus.connectedPeers]);

  /**
   * Disconnect from a peer
   */
  const disconnectPeer = useCallback((peerUsername: string) => {
    if (p2pServiceRef.current) {
      p2pServiceRef.current.disconnectPeer(peerUsername);
    }
  }, []);

  /**
   * Get P2P connection statistics
   */
  const getP2PStats = useCallback(() => {
    return {
      isInitialized: p2pStatus.isInitialized,
      connectedPeers: p2pStatus.connectedPeers,
      totalConnections: p2pStatus.connectedPeers.length,
      signalingConnected: p2pStatus.signalingConnected,
      lastError: p2pStatus.lastError
    };
  }, [p2pStatus]);

  /**
   * Cleanup on unmount
   */
  useEffect(() => {
    return () => {
      if (p2pServiceRef.current) {
        p2pServiceRef.current.destroy();
      }
    };
  }, []);

  /**
   * Auto-initialize P2P service when username and keys are available
   */
  useEffect(() => {
    if (username && hybridKeys && !p2pStatus.isInitialized) {
      // Use WebSocket server URL for signaling
      const signalingUrl = process.env.NODE_ENV === 'production' 
        ? 'wss://your-signaling-server.com/ws'
        : 'ws://localhost:3001/ws';
      
      initializeP2P(signalingUrl).catch(console.error);
    }
  }, [username, hybridKeys, p2pStatus.isInitialized, initializeP2P]);

  return {
    // State
    p2pStatus,
    incomingMessages,
    
    // Actions
    initializeP2P,
    connectToPeer,
    sendP2PMessage,
    disconnectPeer,
    onMessage,
    
    // Utilities
    isPeerConnected,
    getP2PStats,
    
    // Service reference (for advanced usage)
    p2pService: p2pServiceRef.current
  };
}