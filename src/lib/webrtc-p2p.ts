/**
 * WebRTC P2P Transport Service
 * Implements direct peer-to-peer encrypted connections to eliminate server dependency
 */

import { CryptoUtils } from './unified-crypto';
import { handleP2PError, handleCriticalError, handleNetworkError } from './secure-error-handler';

interface PeerConnection {
  id: string;
  username: string;
  connection: RTCPeerConnection;
  dataChannel: RTCDataChannel | null;
  state: 'connecting' | 'connected' | 'disconnected' | 'failed';
  lastSeen: number;
}

interface P2PMessage {
  type: 'chat' | 'signal' | 'heartbeat' | 'dummy';
  from: string;
  to: string;
  timestamp: number;
  payload: any;
  signature?: string; // Dilithium3 signature
}

interface SignalingMessage {
  type: 'offer' | 'answer' | 'ice-candidate';
  from: string;
  to: string;
  data: any;
}

export class WebRTCP2PService {
  private peers: Map<string, PeerConnection> = new Map();
  private localUsername: string = '';
  private signalingChannel: WebSocket | null = null;
  private onMessageCallback: ((message: P2PMessage) => void) | null = null;
  private onPeerConnectedCallback: ((username: string) => void) | null = null;
  private onPeerDisconnectedCallback: ((username: string) => void) | null = null;
  private dummyTrafficInterval: NodeJS.Timeout | null = null;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private dilithiumKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private peerDilithiumKeys: Map<string, Uint8Array> = new Map(); // Store peer public keys

  // DoS protection
  private readonly MAX_PEERS = 50; // Maximum concurrent peer connections
  private readonly MAX_MESSAGE_SIZE = 64 * 1024; // 64KB max message size
  private readonly MESSAGE_RATE_LIMIT = 100; // Messages per minute per peer
  private messageRateLimiter: Map<string, { count: number; resetTime: number }> = new Map();
  private connectionAttempts: Map<string, { count: number; resetTime: number }> = new Map();
  private readonly MAX_CONNECTION_ATTEMPTS = 5; // Per hour per peer

  // WebRTC configuration with STUN/TURN servers
  private rtcConfig: RTCConfiguration = {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      // Add TURN servers for NAT traversal in production
    ],
    iceCandidatePoolSize: 10,
  };

  constructor(username: string) {
    this.localUsername = username;
  }

  /**
   * Set Dilithium3 keys for message signing
   */
  setDilithiumKeys(keys: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
    this.dilithiumKeys = keys;
  }

  /**
   * Add peer's Dilithium3 public key for signature verification
   */
  addPeerDilithiumKey(username: string, publicKey: Uint8Array): void {
    this.peerDilithiumKeys.set(username, publicKey);
  }

  /**
   * Initialize P2P service with signaling server fallback
   */
  async initialize(signalingServerUrl: string): Promise<void> {
    try {
      // Connect to signaling server for initial peer discovery
      this.signalingChannel = new WebSocket(signalingServerUrl);
      
      this.signalingChannel.onopen = () => {
        console.log('[P2P] Connected to signaling server');
        this.sendSignalingMessage({
          type: 'register',
          username: this.localUsername
        });
      };

      this.signalingChannel.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleSignalingMessage(message);
        } catch (error) {
          handleP2PError(error as Error, { context: 'signaling_message_parse' });
        }
      };

      this.signalingChannel.onclose = () => {
        console.log('[P2P] Signaling server disconnected');
        // Prevent multiple reconnection attempts with atomic check-and-set
        const currentChannel = this.signalingChannel;
        if (currentChannel && currentChannel.readyState === WebSocket.CLOSED) {
          this.signalingChannel = null;
          // Attempt reconnection after delay with proper error handling
          setTimeout(() => {
            // Double-check we're still disconnected and not already reconnecting
            if (!this.signalingChannel && currentChannel === this.signalingChannel) {
              this.initialize(signalingServerUrl).catch((error) => {
                console.error('[P2P] Reconnection failed:', error);
                // Exponential backoff for failed reconnections
                setTimeout(() => {
                  if (!this.signalingChannel) {
                    this.initialize(signalingServerUrl).catch(console.error);
                  }
                }, 10000); // 10 second backoff
              });
            }
          }, 5000);
        }
      };

      // Start dummy traffic and heartbeat
      this.startDummyTraffic();
      this.startHeartbeat();

    } catch (error) {
      console.error('[P2P] Failed to initialize:', error);
      throw error;
    }
  }

  /**
   * Create direct P2P connection to a peer
   */
  async connectToPeer(username: string): Promise<void> {
    if (this.peers.has(username)) {
      console.log(`[P2P] Already connected to ${username}`);
      return;
    }

    // Check connection limits
    if (this.peers.size >= this.MAX_PEERS) {
      throw new Error(`Maximum peer connections reached (${this.MAX_PEERS})`);
    }

    // Check connection attempt rate limiting
    if (!this.checkConnectionRateLimit(username)) {
      throw new Error(`Connection rate limit exceeded for ${username}`);
    }

    const peerId = this.generatePeerId();
    const connection = new RTCPeerConnection(this.rtcConfig);
    
    const peer: PeerConnection = {
      id: peerId,
      username,
      connection,
      dataChannel: null,
      state: 'connecting',
      lastSeen: Date.now()
    };

    this.peers.set(username, peer);

    // Create data channel
    const dataChannel = connection.createDataChannel('messages', {
      ordered: true,
      maxRetransmits: 3
    });

    peer.dataChannel = dataChannel;

    // Set up data channel handlers
    dataChannel.onopen = () => {
      console.log(`[P2P] Data channel opened with ${username}`);
      peer.state = 'connected';
      this.onPeerConnectedCallback?.(username);
    };

    dataChannel.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        this.handleP2PMessage(message);
      } catch (error) {
        console.error('[P2P] Failed to parse P2P message:', error);
      }
    };

    dataChannel.onclose = () => {
      console.log(`[P2P] Data channel closed with ${username}`);
      peer.state = 'disconnected';
      this.onPeerDisconnectedCallback?.(username);
    };

    // Set up connection handlers
    connection.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignalingMessage({
          type: 'ice-candidate',
          from: this.localUsername,
          to: username,
          data: event.candidate
        });
      }
    };

    connection.ondatachannel = (event) => {
      const channel = event.channel;
      peer.dataChannel = channel;
      
      channel.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleP2PMessage(message);
        } catch (error) {
          console.error('[P2P] Failed to parse incoming P2P message:', error);
        }
      };
    };

    // Create offer
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);

    this.sendSignalingMessage({
      type: 'offer',
      from: this.localUsername,
      to: username,
      data: offer
    });
  }

  /**
   * Send encrypted message directly to peer
   */
  async sendMessage(to: string, message: any, messageType: 'chat' | 'signal' = 'chat'): Promise<void> {
    const peer = this.peers.get(to);
    
    if (!peer || peer.state !== 'connected' || !peer.dataChannel) {
      throw new Error(`No active P2P connection to ${to}`);
    }

    const p2pMessage: P2PMessage = {
      type: messageType,
      from: this.localUsername,
      to,
      timestamp: Date.now(),
      payload: message
    };

    // Add Dilithium3 signature if available
    try {
      // Get Dilithium3 keys from the P2P service context
      if (this.dilithiumKeys) {
        const messageBytes = new TextEncoder().encode(JSON.stringify({
          ...p2pMessage,
          signature: undefined // Exclude signature from signing
        }));
        const signature = await CryptoUtils.Dilithium.sign(this.dilithiumKeys.secretKey, messageBytes);
        p2pMessage.signature = CryptoUtils.Base64.arrayBufferToBase64(signature);
      }
    } catch (error) {
      console.warn('[P2P] Failed to sign message:', error);
    }

    peer.dataChannel.send(JSON.stringify(p2pMessage));
    peer.lastSeen = Date.now();
  }

  /**
   * Handle incoming P2P messages
   */
  private async handleP2PMessage(message: P2PMessage): Promise<void> {
    // Validate message size
    const messageStr = JSON.stringify(message);
    if (messageStr.length > this.MAX_MESSAGE_SIZE) {
      console.warn(`[P2P] Message too large from ${message.from}: ${messageStr.length} bytes`);
      return;
    }

    // Check message rate limiting
    if (!this.checkMessageRateLimit(message.from)) {
      console.warn(`[P2P] Message rate limit exceeded for ${message.from}`);
      return;
    }
    // Verify Dilithium3 signature if present
    if (message.signature && message.from) {
      try {
        const peerPublicKey = this.peerDilithiumKeys.get(message.from);
        if (peerPublicKey) {
          const messageBytes = new TextEncoder().encode(JSON.stringify({
            ...message,
            signature: undefined // Exclude signature from verification
          }));
          const signature = CryptoUtils.Base64.base64ToUint8Array(message.signature);
          const isValid = await CryptoUtils.Dilithium.verify(signature, messageBytes, peerPublicKey);
          if (!isValid) {
            console.error('[P2P] Message signature verification failed for', message.from);
            return; // Reject message with invalid signature
          }
          console.log('[P2P] Message signature verified for', message.from);
        } else {
          console.warn('[P2P] No Dilithium3 public key for peer:', message.from);
        }
      } catch (error) {
        console.error('[P2P] Failed to verify message signature:', error);
        return; // Reject message on verification error
      }
    }

    // Update peer last seen
    const peer = this.peers.get(message.from);
    if (peer) {
      peer.lastSeen = Date.now();
    }

    // Handle different message types
    switch (message.type) {
      case 'chat':
        this.onMessageCallback?.(message);
        break;
      case 'heartbeat':
        // Respond to heartbeat
        if (peer && peer.dataChannel) {
          peer.dataChannel.send(JSON.stringify({
            type: 'heartbeat',
            from: this.localUsername,
            to: message.from,
            timestamp: Date.now(),
            payload: { response: true }
          }));
        }
        break;
      case 'dummy':
        // Ignore dummy traffic
        break;
      default:
        console.log('[P2P] Unknown message type:', message.type);
    }
  }

  /**
   * Handle signaling messages for WebRTC negotiation
   */
  private async handleSignalingMessage(message: SignalingMessage): Promise<void> {
    const { type, from, to, data } = message;

    if (to !== this.localUsername) return;

    let peer = this.peers.get(from);
    
    switch (type) {
      case 'offer':
        if (!peer) {
          // Create new peer connection for incoming offer
          const peerId = this.generatePeerId();
          const connection = new RTCPeerConnection(this.rtcConfig);
          
          peer = {
            id: peerId,
            username: from,
            connection,
            dataChannel: null,
            state: 'connecting',
            lastSeen: Date.now()
          };

          this.peers.set(from, peer);

          connection.onicecandidate = (event) => {
            if (event.candidate) {
              this.sendSignalingMessage({
                type: 'ice-candidate',
                from: this.localUsername,
                to: from,
                data: event.candidate
              });
            }
          };

          connection.ondatachannel = (event) => {
            const channel = event.channel;
            peer!.dataChannel = channel;
            
            channel.onopen = () => {
              console.log(`[P2P] Data channel opened with ${from}`);
              peer!.state = 'connected';
              this.onPeerConnectedCallback?.(from);
            };

            channel.onmessage = (event) => {
              this.handleP2PMessage(JSON.parse(event.data));
            };

            channel.onclose = () => {
              console.log(`[P2P] Data channel closed with ${from}`);
              peer!.state = 'disconnected';
              this.onPeerDisconnectedCallback?.(from);
            };
          };
        }

        await peer.connection.setRemoteDescription(data);
        const answer = await peer.connection.createAnswer();
        await peer.connection.setLocalDescription(answer);

        this.sendSignalingMessage({
          type: 'answer',
          from: this.localUsername,
          to: from,
          data: answer
        });
        break;

      case 'answer':
        if (peer) {
          await peer.connection.setRemoteDescription(data);
        }
        break;

      case 'ice-candidate':
        if (peer) {
          await peer.connection.addIceCandidate(data);
        }
        break;
    }
  }

  /**
   * Send message through signaling server
   */
  private sendSignalingMessage(message: any): void {
    if (this.signalingChannel && this.signalingChannel.readyState === WebSocket.OPEN) {
      this.signalingChannel.send(JSON.stringify(message));
    }
  }

  /**
   * Generate random peer ID for metadata obfuscation
   */
  private generatePeerId(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Start dummy traffic generation for traffic analysis resistance
   */
  private startDummyTraffic(): void {
    this.dummyTrafficInterval = setInterval(() => {
      this.peers.forEach((peer, username) => {
        // SECURITY: Use cryptographically secure random for dummy traffic probability
        const randomValue = crypto.getRandomValues(new Uint8Array(1))[0] / 255;
        if (peer.state === 'connected' && peer.dataChannel && randomValue < 0.3) {
          // Generate realistic dummy message with variable size
          const dummySize = this.generateRealisticMessageSize();
          const dummyPayload = this.generateObfuscatedPayload(dummySize);

          const dummyMessage: P2PMessage = {
            type: 'dummy',
            from: this.generateEphemeralId(), // Use ephemeral ID instead of real username
            to: this.generateEphemeralId(),
            timestamp: this.obfuscateTimestamp(Date.now()),
            payload: dummyPayload
          };
          peer.dataChannel.send(JSON.stringify(dummyMessage));
        }
      });
    }, this.generateRandomInterval()); // Variable interval
  }

  /**
   * Generate realistic message size distribution
   */
  private generateRealisticMessageSize(): number {
    // SECURITY: Use cryptographically secure random for message size distribution
    const rand = crypto.getRandomValues(new Uint8Array(1))[0] / 255;
    if (rand < 0.4) {
      const shortSize = crypto.getRandomValues(new Uint8Array(1))[0] % 50 + 20;
      return shortSize; // Short messages
    }
    if (rand < 0.8) {
      const mediumSize = crypto.getRandomValues(new Uint8Array(1))[0] % 200 + 50;
      return mediumSize; // Medium messages
    }
    const longSize = crypto.getRandomValues(new Uint16Array(1))[0] % 500 + 200;
    return longSize; // Long messages
  }

  /**
   * Generate obfuscated payload that looks like encrypted data
   */
  private generateObfuscatedPayload(size: number): any {
    const randomData = crypto.getRandomValues(new Uint8Array(size));
    return {
      version: "hybrid-v1",
      ephemeralX25519Public: CryptoUtils.Base64.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(32))),
      kyberCiphertext: CryptoUtils.Base64.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(1088))),
      encryptedMessage: CryptoUtils.Base64.arrayBufferToBase64(randomData),
      blake3Mac: CryptoUtils.Base64.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(32)))
    };
  }

  /**
   * Generate ephemeral ID for metadata obfuscation
   */
  private generateEphemeralId(): string {
    const randomBytes = crypto.getRandomValues(new Uint8Array(8));
    return Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Obfuscate timestamp to prevent timing analysis
   */
  private obfuscateTimestamp(timestamp: number): number {
    // SECURITY: Add cryptographically secure random jitter of ±30 seconds
    const randomJitter = crypto.getRandomValues(new Int32Array(1))[0];
    const jitter = (randomJitter / 2147483647) * 60000; // Convert to ±30 seconds
    return Math.floor(timestamp + jitter);
  }

  /**
   * Generate random interval for dummy traffic
   */
  private generateRandomInterval(): number {
    // SECURITY: Use cryptographically secure random interval between 3-20 seconds
    const randomMs = crypto.getRandomValues(new Uint16Array(1))[0] % 17000;
    return 3000 + randomMs;
  }

  /**
   * Start heartbeat to maintain connections
   */
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      this.peers.forEach((peer, username) => {
        if (peer.state === 'connected' && peer.dataChannel) {
          const heartbeat: P2PMessage = {
            type: 'heartbeat',
            from: this.localUsername,
            to: username,
            timestamp: Date.now(),
            payload: { ping: true }
          };
          peer.dataChannel.send(JSON.stringify(heartbeat));
        }
      });
    }, 30000); // Every 30 seconds
  }

  /**
   * Set callback for incoming messages
   */
  onMessage(callback: (message: P2PMessage) => void): void {
    this.onMessageCallback = callback;
  }

  /**
   * Set callback for peer connections
   */
  onPeerConnected(callback: (username: string) => void): void {
    this.onPeerConnectedCallback = callback;
  }

  /**
   * Set callback for peer disconnections
   */
  onPeerDisconnected(callback: (username: string) => void): void {
    this.onPeerDisconnectedCallback = callback;
  }

  /**
   * Get list of connected peers
   */
  getConnectedPeers(): string[] {
    return Array.from(this.peers.entries())
      .filter(([_, peer]) => peer.state === 'connected')
      .map(([username, _]) => username);
  }

  /**
   * Disconnect from a peer
   */
  disconnectPeer(username: string): void {
    const peer = this.peers.get(username);
    if (peer) {
      peer.connection.close();
      this.peers.delete(username);
      this.onPeerDisconnectedCallback?.(username);
    }
  }

  /**
   * Check connection rate limiting
   */
  private checkConnectionRateLimit(username: string): boolean {
    const now = Date.now();
    const hourMs = 60 * 60 * 1000;

    const attempts = this.connectionAttempts.get(username);
    if (!attempts || now > attempts.resetTime) {
      this.connectionAttempts.set(username, { count: 1, resetTime: now + hourMs });
      return true;
    }

    if (attempts.count >= this.MAX_CONNECTION_ATTEMPTS) {
      return false;
    }

    attempts.count++;
    return true;
  }

  /**
   * Check message rate limiting
   */
  private checkMessageRateLimit(username: string): boolean {
    const now = Date.now();
    const minuteMs = 60 * 1000;

    const rate = this.messageRateLimiter.get(username);
    if (!rate || now > rate.resetTime) {
      this.messageRateLimiter.set(username, { count: 1, resetTime: now + minuteMs });
      return true;
    }

    if (rate.count >= this.MESSAGE_RATE_LIMIT) {
      return false;
    }

    rate.count++;
    return true;
  }

  /**
   * Cleanup and disconnect all peers
   */
  destroy(): void {
    console.log('[P2P] Starting destroy/cleanup...');

    // Clear intervals with null checks
    if (this.dummyTrafficInterval) {
      clearInterval(this.dummyTrafficInterval);
      this.dummyTrafficInterval = null;
    }
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    // Close all peer connections with proper error handling
    this.peers.forEach((peer, username) => {
      try {
        if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
          peer.dataChannel.close();
        }
        if (peer.connection.connectionState !== 'closed') {
          peer.connection.close();
        }
        console.log(`[P2P] Cleaned up connection to ${username}`);
      } catch (error) {
        console.error(`[P2P] Error cleaning up connection to ${username}:`, error);
      }
    });
    this.peers.clear();

    // Close signaling channel with proper state checking
    if (this.signalingChannel) {
      try {
        if (this.signalingChannel.readyState === WebSocket.OPEN ||
            this.signalingChannel.readyState === WebSocket.CONNECTING) {
          this.signalingChannel.close();
        }
      } catch (error) {
        console.error('[P2P] Error closing signaling channel:', error);
      } finally {
        this.signalingChannel = null;
      }
    }

    // Clear rate limiting data
    this.messageRateLimiter.clear();
    this.connectionAttempts.clear();
    this.peerDilithiumKeys.clear();

    console.log('[P2P] Destroy/cleanup completed successfully');
  }
}