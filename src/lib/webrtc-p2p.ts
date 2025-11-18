/**
 * WebRTC/Tor P2P transport for end-to-end encrypted peer messaging.
 */

import { CryptoUtils } from './unified-crypto';
import {
  PostQuantumKEM,
  PostQuantumAEAD,
  PostQuantumHash,
  PostQuantumRandom,
  PostQuantumUtils,
  SecurityAuditLogger
} from './post-quantum-crypto';
import { handleP2PError } from './secure-error-handler';
import { torNetworkManager } from './tor-network';

interface PeerConnection {
  id: string;
  username: string;
  connection: RTCPeerConnection;
  dataChannel: RTCDataChannel | null;
  onionSocket: WebSocket | null;
  transport: 'webrtc' | 'onion' | 'unknown';
  state: 'connecting' | 'connected' | 'disconnected' | 'failed';
  lastSeen: number;
}

interface P2PMessage {
  type: 'chat' | 'signal' | 'heartbeat' | 'dummy' | 'typing' | 'reaction' | 'file' | 'delivery-ack' | 'read-receipt' | 'edit' | 'delete';
  from: string;
  to: string;
  timestamp: number;
  payload: any;
  signature?: string;
}

interface SignalingMeta {
  cert?: { dilithiumPublicKey: string; kyberPublicKey: string; x25519PublicKey?: string };
  routeProof?: { payload: any; signature: string };
}

interface SignalingMessage {
  type: 'offer' | 'answer' | 'ice-candidate' | 'onion-offer' | 'onion-answer';
  from: string;
  to: string;
  payload: any;
  meta?: SignalingMeta;
}

export class WebRTCP2PService {
  private peers: Map<string, PeerConnection> = new Map();
  private localUsername: string = '';
  private signalingChannel: WebSocket | null = null;
  private bufferedLowHandlers: Map<string, Set<() => void>> = new Map();
  private onMessageCallback: ((message: P2PMessage) => void) | null = null;
  private onPeerConnectedCallback: ((username: string) => void) | null = null;
  private onPeerDisconnectedCallback: ((username: string) => void) | null = null;
  private dummyTrafficInterval: ReturnType<typeof setInterval> | null = null;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private dilithiumKeys: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private peerDilithiumKeys: Map<string, Uint8Array> = new Map();
  private pqSessions: Map<string, {
    kyberKeyPair?: { publicKey: Uint8Array; secretKey: Uint8Array };
    sharedSecret: Uint8Array | null;
    sendKey: Uint8Array | null;
    receiveKey: Uint8Array | null;
    established: boolean;
    inProgress: boolean;
    role: 'initiator' | 'responder' | null;
  }> = new Map();
  private sessionRekeyIntervals: Map<string, ReturnType<typeof setInterval>> = new Map();
  private connectionHealthChecks: Map<string, { lastHeartbeat: number; missedCount: number }> = new Map();
  private messageNonces: Map<string, Map<string, number>> = new Map();
  private auditLogger = SecurityAuditLogger;
  private pendingIceCandidates: Map<string, RTCIceCandidateInit[]> = new Map();
  private lastPqRekeyAttempt: Map<string, number> = new Map();
  private readonly MAX_PEERS = 50;
  private readonly MAX_MESSAGE_SIZE = 5 * 1024 * 1024; // 5MB max message size
  private readonly MESSAGE_RATE_LIMIT = 100;
  private messageRateLimiter: Map<string, { count: number; resetTime: number }> = new Map();
  private connectionAttempts: Map<string, { count: number; resetTime: number }> = new Map();
  private readonly MAX_CONNECTION_ATTEMPTS = 5;
  private readonly MAX_MISSED_HEARTBEATS = 3;
  private readonly REPLAY_WINDOW_MS = 5 * 60 * 1000;
  private readonly MAX_NONCES_PER_PEER = 2048;
  private readonly SESSION_REKEY_INTERVAL_MS = 60 * 60 * 1000;

  // WebRTC configuration
  private rtcConfig: RTCConfiguration = {
    iceServers: [],
    iceCandidatePoolSize: 0,
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require',
    iceTransportPolicy: 'all'
  };

  constructor(username: string) {
    this.localUsername = username;
    
    // Listen for block events to disconnect P2P connections
    if (typeof window !== 'undefined') {
      window.addEventListener('user-blocked', (event: Event) => {
        const customEvent = event as CustomEvent;
        const blockedUsername = customEvent.detail?.username;
        if (blockedUsername) {
          this.disconnectPeer(blockedUsername);
        }
      });
    }
  }

  /**
   * Load ICE configuration from the Electron bridge when available
   */
  private async hydrateRtcConfigFromElectron(signalingServerUrl?: string): Promise<void> {
    try {
      const next: RTCConfiguration = { ...this.rtcConfig, iceServers: [], iceTransportPolicy: 'all' };

      // 0) Env-provided public STUN/TURN 
      try {
        const env: any = (import.meta as any).env || {};
        const turnRaw = env.VITE_TURN_SERVERS || env.TURN_SERVERS || '';
        const stunRaw = env.VITE_STUN_SERVERS || env.STUN_SERVERS || '';
        const parsed: any[] = [];
        if (turnRaw) {
          const val = typeof turnRaw === 'string' ? JSON.parse(turnRaw) : turnRaw;
          if (Array.isArray(val)) parsed.push(...val);
        }
        if (stunRaw) {
          let list: any = [];
          if (typeof stunRaw === 'string') {
            list = stunRaw.trim().startsWith('[') ? JSON.parse(stunRaw) : stunRaw.split(',').map((s: string) => s.trim()).filter(Boolean);
          } else {
            list = stunRaw;
          }
          if (Array.isArray(list) && list.length > 0) parsed.push({ urls: list });
        }
        if (parsed.length > 0) next.iceServers = parsed;
      } catch {}

      // 1) Prefer Electron-provided ICE if env not provided
      try {
        if (!next.iceServers || next.iceServers.length === 0) {
          const api: any = (window as any).electronAPI || (window as any).edgeApi || null;
          if (api && typeof api.getIceConfiguration === 'function') {
            const cfg = await api.getIceConfiguration();
            if (cfg && Array.isArray(cfg.iceServers) && cfg.iceServers.length > 0) {
              next.iceServers = cfg.iceServers;
              if (cfg.iceTransportPolicy === 'relay' || cfg.iceTransportPolicy === 'all') {
                next.iceTransportPolicy = cfg.iceTransportPolicy;
              }
            }
          }
        }
      } catch {}

      // 2) Try self-host ICE from server endpoint if still empty
      try {
        if (!next.iceServers || next.iceServers.length === 0) {
        // Derive base HTTP URL
        let baseHttp = '';
        try {
          const envUrl = (import.meta as any).env?.VITE_WS_URL as string | undefined;
          if (envUrl && typeof envUrl === 'string') {
            const u = new URL(envUrl.replace('ws://','http://').replace('wss://','https://'));
            baseHttp = `${u.protocol}//${u.host}`;
          }
        } catch {}

        try {
          if (!baseHttp && typeof signalingServerUrl === 'string' && signalingServerUrl) {
            const u2 = new URL(signalingServerUrl.replace('ws://','http://').replace('wss://','https://'));
            baseHttp = `${u2.protocol}//${u2.host}`;
          }
        } catch {}

        try {
          if (!baseHttp && typeof window !== 'undefined' && window.location?.origin) {
            const { protocol, origin } = window.location as Location;
            if (protocol === 'http:' || protocol === 'https:') {
              baseHttp = origin;
            }
          }
        } catch {}

        if (baseHttp && (baseHttp.startsWith('http://') || baseHttp.startsWith('https://'))) {
          const resp = await fetch(`${baseHttp}/api/ice/config`, { method: 'GET', credentials: 'omit' });
          if (resp.ok) {
            const ice = await resp.json();
            if (ice && Array.isArray(ice.iceServers) && ice.iceServers.length > 0 && (!next.iceServers || next.iceServers.length === 0)) {
              next.iceServers = ice.iceServers;
              if (ice.iceTransportPolicy === 'relay' || ice.iceTransportPolicy === 'all') {
                next.iceTransportPolicy = ice.iceTransportPolicy;
              }
            }
          }
        }
        }
      } catch {}

      const sanitized: any[] = [];
      for (const srv of (next.iceServers || [])) {
        const urls = Array.isArray(srv.urls) ? srv.urls : [srv.urls];
        const isTurn = urls.some((u: any) => typeof u === 'string' && (u.startsWith('turn:') || u.startsWith('turns:')));
        const isStun = urls.some((u: any) => typeof u === 'string' && u.startsWith('stun:'));
        
        if (isTurn && (!srv.username || !srv.credential)) {
          continue;
        }
        
        if (isStun || (isTurn && srv.username && srv.credential)) {
          sanitized.push(srv);
        }
      }
      next.iceServers = sanitized;
      
      const hasTurn = sanitized.some((srv: any) => {
        const urls = Array.isArray(srv.urls) ? srv.urls : [srv.urls];
        return urls.some((u: any) => typeof u === 'string' && (u.startsWith('turn:') || u.startsWith('turns:')));
      });
      if (hasTurn && next.iceTransportPolicy === 'all') {
        next.iceTransportPolicy = 'relay';
      }
      if (next.iceTransportPolicy === 'relay' && !hasTurn) {
        next.iceTransportPolicy = 'all';
      }

      this.rtcConfig = next;
      try {
        this.auditLogger.log('info', 'p2p-ice-config-final', {
          iceServers: (next.iceServers || []).length,
          policy: next.iceTransportPolicy
        });
      } catch {}
    } catch {}
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
  async initialize(signalingServerUrl: string, options?: {
    registerPayload: Record<string, unknown>;
    registrationSignature: string;
    registrationPublicKey: string;
  }): Promise<void> {
    try {
      await this.hydrateRtcConfigFromElectron(signalingServerUrl);
      try { this.auditLogger.log('info', 'p2p-init-start', { server: signalingServerUrl || '' }); } catch {}
      this.signalingChannel = new WebSocket(signalingServerUrl);

      this.signalingChannel.onopen = () => {
        this.logAuditEvent('signaling-connected', 'server');
        try { this.auditLogger.log('info', 'p2p-signaling-open', {}); } catch {}
this.sendSignalingMessage({
          type: 'register',
          from: this.localUsername,
          payload: {
            register: options?.registerPayload,
            signature: options?.registrationSignature,
            publicKey: options?.registrationPublicKey
          }
        });
      };

this.signalingChannel.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          try { this.auditLogger.log('info', 'p2p-signaling-msg', { type: message?.type, from: message?.from, to: message?.to }); } catch {}
          this.handleSignalingMessage(message as any);
        } catch (_error) {
          handleP2PError(_error as Error, { context: 'signaling_message_parse' });
          try { this.auditLogger.log('warn', 'p2p-signaling-parse-error', {}); } catch {}
        }
      };

      this.signalingChannel.onclose = () => {
        this.logAuditEvent('signaling-disconnect', 'server');
        try { this.auditLogger.log('info', 'p2p-signaling-close', {}); } catch {}
        if (this.signalingChannel?.readyState === WebSocket.CLOSED) {
          this.signalingChannel = null;
          setTimeout(() => {
            if (!this.signalingChannel) {
              this.initialize(signalingServerUrl).catch(() => {
                this.logAuditEvent('signaling-reconnect-failed', 'server');
              });
            }
          }, 5000);
        }
      };

      this.startDummyTraffic();
      this.startHeartbeat();

      // Subscribe to inbound onion messages from Electron main
      try {
        const api: any = (window as any).electronAPI || (window as any).edgeApi || null;
        if (api && typeof api.onOnionMessage === 'function') {
          api.onOnionMessage((_evt: any, data: any) => {
            try { this.handleP2PMessage(data); } catch {}
          });
        }
      } catch {}
    } catch (_error) {
      handleP2PError(_error as Error, { context: 'p2p_initialization' });
      throw _error;
    }
  }

  /**
   * Create direct P2P connection to a peer
   */
  async connectToPeer(username: string, options?: {
    peerCertificate?: { dilithiumPublicKey: string; kyberPublicKey: string; x25519PublicKey?: string };
    routeProof?: { payload: any; signature: string };
  }): Promise<void> {
    try { this.auditLogger.log('info', 'p2p-connect-attempt', { peer: username }); } catch {}
    
    // Check if user is blocked before allowing P2P connection
    try {
      const { blockStatusCache } = await import('./block-status-cache');
      const isBlocked = blockStatusCache.get(username);
      if (isBlocked === true) {
        throw new Error(`Cannot connect to blocked user: ${username}`);
      }
    } catch (_error) {
      if ((_error as Error).message?.includes('blocked')) {
        throw _error;
      }
    }
    
    // Check if peer already exists
    if (this.peers.has(username)) {
      const existing = this.peers.get(username);
      if (existing && (existing.state === 'connecting' || existing.state === 'connected')) {
        return;
      }
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
    try { this.auditLogger.log('info', 'p2p-pc-created', { peer: username, iceServers: (this.rtcConfig.iceServers || []).length, policy: this.rtcConfig.iceTransportPolicy }); } catch {}
    
    const peer: PeerConnection = {
      id: peerId,
      username,
      connection,
      dataChannel: null,
      onionSocket: null,
      transport: 'unknown',
      state: 'connecting',
      lastSeen: Date.now()
    };

    this.peers.set(username, peer);
    
    // Set timeout to detect if offer was never received by peer
    const connectionTimeout = setTimeout(() => {
      const currentPeer = this.peers.get(username);
      if (currentPeer && currentPeer.state === 'connecting' && 
          currentPeer.connection.signalingState === 'have-local-offer' &&
          !currentPeer.connection.remoteDescription) {
        try { this.auditLogger.log('warn', 'p2p-connection-timeout', { peer: username }); } catch {}
        try {
          currentPeer.connection.close();
          if (currentPeer.dataChannel) currentPeer.dataChannel.close();
        } catch {}
        this.peers.delete(username);
      }
    }, 15000);
    
    const originalOnOpen = () => {
      clearTimeout(connectionTimeout);
      peer.state = 'connected';
      peer.transport = 'webrtc';
      this.logAuditEvent('p2p-connected', username);
      if (this.shouldInitiateHandshake(username)) {
        this.initiatePostQuantumKeyExchange(username);
      }
      this.startSessionRekey(username);
      try { this.auditLogger.log('info', 'p2p-dc-open', { peer: username }); } catch {}
      this.onPeerConnectedCallback?.(username);
    };

    // Create data channel
    const dataChannel = connection.createDataChannel('messages', {
      ordered: true,
      maxRetransmits: 3
    });

    peer.dataChannel = dataChannel;

    this.setupBackpressureHandlers(dataChannel, username);

    // Set up data channel handlers
    dataChannel.onopen = originalOnOpen;

    dataChannel.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        try { this.auditLogger.log('info', 'p2p-dc-in', { peer: username, type: message?.type }); } catch {}
        this.handleP2PMessage(message);
      } catch (_error) {
        this.logAuditEvent('message-parse-failed', username);
      }
    };

    dataChannel.onclose = () => {
      peer.state = 'disconnected';
      this.logAuditEvent('p2p-disconnected', username);
      try { this.auditLogger.log('info', 'p2p-dc-close', { peer: username }); } catch {}
      this.onPeerDisconnectedCallback?.(username);
      this.cleanupPeer(username);
    };

    // Set up connection handlers
    let iceCount = 0;
    let onionFallbackScheduled = false;
    const scheduleOnionFallback = () => {
      if (onionFallbackScheduled) return;
      onionFallbackScheduled = true;
      setTimeout(() => {
        if (peer.state !== 'connected') {
          this.fallbackToOnion(username).catch(() => {});
        }
      }, 12000);
    };

    connection.onicecandidate = (event) => {
      if (event.candidate) {
        iceCount++;
        try { this.auditLogger.log('info', 'p2p-ice-candidate', { peer: username, count: iceCount }); } catch {}
this.sendSignalingMessage({
          type: 'ice-candidate',
          from: this.localUsername,
          to: username,
          payload: event.candidate
        });
      }
    };

    try {
      connection.oniceconnectionstatechange = () => {
        const st = connection.iceConnectionState;
        if (st === 'failed' || st === 'disconnected') {
          scheduleOnionFallback();
        }
      };
      scheduleOnionFallback();
    } catch {}

    // Create offer
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    try { this.auditLogger.log('info', 'p2p-offer-created', { peer: username }); } catch {}

    this.sendSignalingMessage({
      type: 'offer',
      from: this.localUsername,
      to: username,
      payload: offer,
      meta: {
        cert: options?.peerCertificate,
        routeProof: options?.routeProof
      }
    });
  }

  /**
   * Send encrypted message directly to peer.
   */
  async sendMessage(
    to: string,
    message: any,
    messageType: 'chat' | 'signal' | 'typing' | 'reaction' | 'file' | 'delivery-ack' | 'read-receipt' | 'edit' | 'delete' = 'chat'
  ): Promise<void> {
    const peer = this.peers.get(to);
    if (!peer || peer.state !== 'connected') {
      try { this.auditLogger.log('warn', 'p2p-send-no-connection', { peer: to, type: messageType }); } catch {}
      throw new Error(`No active P2P connection to ${to}`);
    }

    const isHandshakeMessage = messageType === 'signal' && (message?.kind?.startsWith('pq-key') || message?.kind?.startsWith('session-'));
    
    if (!isHandshakeMessage) {
      const session = this.pqSessions.get(to);
      if (!session || !session.established || !session.sendKey || !session.receiveKey) {
        console.error('[P2P] SECURITY: Cannot send message - no PQ session established', { peer: to, type: messageType });
        try { this.auditLogger.log('error', 'p2p-send-no-session', { peer: to, type: messageType }); } catch {}
        throw new Error(`SECURITY: Cannot send ${messageType} message without established PQ session`);
      }
    }

    const payload = isHandshakeMessage
      ? message
      : await this.encryptPayload(to, message);

    const p2pMessage: P2PMessage = {
      type: messageType,
      from: this.localUsername,
      to,
      timestamp: Date.now(),
      payload
    };
    try { this.auditLogger.log('info', 'p2p-send', { peer: to, type: messageType, size: JSON.stringify(p2pMessage).length }); } catch {}

    try {
      if (this.dilithiumKeys) {
        const messageBytes = new TextEncoder().encode(JSON.stringify({
          ...p2pMessage,
          signature: undefined
        }));
        const signature = await CryptoUtils.Dilithium.sign(this.dilithiumKeys.secretKey, messageBytes);
        p2pMessage.signature = CryptoUtils.Base64.arrayBufferToBase64(signature);
      }
    } catch (_error) {
      this.logAuditEvent('message-signing-failed', to);
    }

    if (peer.transport === 'onion' && peer.onionSocket && peer.onionSocket.readyState === 1) {
      peer.onionSocket.send(JSON.stringify(p2pMessage));
    } else if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
      peer.dataChannel.send(JSON.stringify(p2pMessage));
    } else {
      throw new Error('No active transport');
    }
    peer.lastSeen = Date.now();
    this.logAuditEvent('message-send', to, { type: messageType });
  }

  /**
   * Handle incoming P2P messages
   */
  private async handleP2PMessage(message: P2PMessage): Promise<void> {
    try { this.auditLogger.log('info', 'p2p-recv', { from: message?.from || '', type: message?.type }); } catch {}
    // Validate message size
    const messageStr = JSON.stringify(message);
    if (messageStr.length > this.MAX_MESSAGE_SIZE) {
      this.logAuditEvent('message-too-large', message.from);
      return;
    }

    // Check message rate limiting
    if (!this.checkMessageRateLimit(message.from)) {
      this.logAuditEvent('rate-limit-exceeded', message.from);
      return;
    }
    // Verify Dilithium3 signature if present
    if (message.signature && message.from) {
      try {
        const peerPublicKey = this.peerDilithiumKeys.get(message.from);
        if (peerPublicKey) {
          const messageBytes = new TextEncoder().encode(JSON.stringify({
            ...message,
            signature: undefined
          }));
          const signature = CryptoUtils.Base64.base64ToUint8Array(message.signature);
          const isValid = await CryptoUtils.Dilithium.verify(signature, messageBytes, peerPublicKey);
          if (!isValid) {
            this.logAuditEvent('signature-verification-failed', message.from);
            try { this.auditLogger.log('warn', 'p2p-sig-invalid', { from: message.from }); } catch {}
            return; // Reject message with invalid signature
          }
          this.logAuditEvent('message-verified', message.from);
          try { this.auditLogger.log('info', 'p2p-sig-ok', { from: message.from }); } catch {}
        } else {
          this.logAuditEvent('missing-peer-key', message.from);
        }
      } catch (error) {
        this.logAuditEvent('signature-verification-error', message.from);
        return; // Reject message on verification error
      }
    }

    if (!this.validateMessageFreshness(message)) {
      this.logAuditEvent('message-stale', message.from);
      try { this.auditLogger.log('warn', 'p2p-stale', { from: message.from }); } catch {}
      return;
    }

    // Update peer last seen
    const peer = this.peers.get(message.from);
    if (peer) {
      peer.lastSeen = Date.now();
    }

    // Handle different message types
    switch (message.type) {
      case 'signal': {
        const kind = message.payload?.kind;
        try { this.auditLogger.log('info', 'p2p-signal', { from: message.from, kind }); } catch {}
        if (kind === 'pq-key-exchange-init') {
          await this.handlePQKeyExchangeInit(message.from, message.payload);
        } else if (kind === 'pq-key-exchange-response') {
          await this.handlePQKeyExchangeResponse(message.from, message.payload);
        } else if (kind === 'pq-key-exchange-finalize') {
          this.handlePQKeyExchangeFinalize(message.from);
        } else if (kind === 'session-reset-request') {
          // Clear local session state and acknowledge. Initiator will re-initiate.
          try {
            const evt = new CustomEvent('p2p-session-reset-request', { detail: { from: message.from, reason: message?.payload?.reason } });
            window.dispatchEvent(evt);
          } catch {}
          try {
            this.resetPqSession(message.from);
          } catch {}
          try { await this.sendMessage(message.from, { kind: 'session-reset-ack' }, 'signal'); } catch {}
          try { if (this.isLocalInitiator(message.from)) { this.initiatePostQuantumKeyExchange(message.from); } } catch {}
        } else if (kind === 'session-reset-ack') {
          try {
            const evt = new CustomEvent('p2p-session-reset-ack', { detail: { from: message.from } });
            window.dispatchEvent(evt);
          } catch {}
          try {
            const s = this.pqSessions.get(message.from);
            if (this.isLocalInitiator(message.from) && (!s || !s.inProgress)) {
              this.initiatePostQuantumKeyExchange(message.from);
            }
          } catch {}
        } else {
          this.onMessageCallback?.(message);
        }
        break;
      }
      case 'chat':
      case 'typing':
      case 'reaction':
      case 'file':
      case 'edit':
      case 'delete': {
        const session = this.pqSessions.get(message.from);
        if (!session || !session.established || !session.sendKey || !session.receiveKey) {
          console.error('[P2P] SECURITY: Rejecting message - no PQ session established', { from: message.from, type: message.type });
          try { this.auditLogger.log('error', 'p2p-no-session-reject', { from: message.from, type: message.type }); } catch {}
          try {
            if (this.shouldInitiateHandshake(message.from)) {
              this.initiatePostQuantumKeyExchange(message.from);
            }
          } catch {}
          return;
        }
        
        if (!message.payload || message.payload.version !== 'pq-aead-v1') {
          console.error('[P2P] SECURITY: Rejecting unencrypted payload', { from: message.from, type: message.type });
          try { this.auditLogger.log('error', 'p2p-unencrypted-reject', { from: message.from, type: message.type }); } catch {}
          return;
        }
        
        try {
          const decrypted = await this.decryptPayload(message.from, message.payload);
          message.payload = decrypted;
          try { this.auditLogger.log('info', 'p2p-decrypt-ok', { from: message.from }); } catch {}
        } catch (_error) {
          console.error('[P2P] Failed to decrypt PQ payload:', (_error as any)?.message || _error);
          try { this.auditLogger.log('error', 'p2p-decrypt-failed', { from: message.from }); } catch {}
          try {
            const last = this.lastPqRekeyAttempt.get(message.from) || 0;
            const now = Date.now();
            if (now - last > 5000) {
              this.lastPqRekeyAttempt.set(message.from, now);
              if (this.isLocalInitiator(message.from)) {
                if (this.shouldInitiateHandshake(message.from)) {
                  this.initiatePostQuantumKeyExchange(message.from);
                }
              } else {
                // Ask initiator to reset session
                try { await this.sendMessage(message.from, { kind: 'session-reset-request', reason: 'decrypt-failed' }, 'signal'); } catch {}
              }
            }
          } catch {}
          return;
        }

        try {
          const kind = message?.payload?.kind;
          if (kind === 'file-chunk') {
            const evt = new CustomEvent('p2p-file-chunk', { detail: { from: message.from, to: message.to, payload: message.payload } });
            window.dispatchEvent(evt);
          } else if (kind === 'file-ack') {
            const evt = new CustomEvent('p2p-file-ack', { detail: { from: message.from, to: message.to, payload: message.payload } });
            window.dispatchEvent(evt);
          }
        } catch (_e) {}
        this.onMessageCallback?.(message);
        break;
      }
      case 'delivery-ack':
      case 'read-receipt': {
        const session = this.pqSessions.get(message.from);
        if (!session || !session.established || !session.sendKey || !session.receiveKey) {
          console.error('[P2P] SECURITY: Rejecting receipt - no PQ session established', { from: message.from, type: message.type });
          try { this.auditLogger.log('error', 'p2p-no-session-reject', { from: message.from, type: message.type }); } catch {}
          return;
        }
        
        if (!message.payload || message.payload.version !== 'pq-aead-v1') {
          console.error('[P2P] SECURITY: Rejecting unencrypted receipt', { from: message.from, type: message.type });
          try { this.auditLogger.log('error', 'p2p-unencrypted-reject', { from: message.from, type: message.type }); } catch {}
          return;
        }
        
        // Decrypt PQ AEAD layer to get the hybrid envelope
        try {
          const decrypted = await this.decryptPayload(message.from, message.payload);
          message.payload = decrypted;
          try { this.auditLogger.log('info', 'p2p-receipt-decrypt-ok', { from: message.from, type: message.type }); } catch {}
        } catch (_error) {
          console.error('[P2P] Failed to decrypt PQ receipt payload:', (_error as any)?.message || _error);
          try { this.auditLogger.log('error', 'p2p-receipt-decrypt-failed', { from: message.from, type: message.type }); } catch {}
          return;
        }
        this.onMessageCallback?.(message);
        break;
      }
      case 'heartbeat':
        if (message.payload?.ping) {
          this.updateConnectionHealth(message.from, true);
          if (peer && peer.dataChannel) {
            peer.dataChannel.send(JSON.stringify({
              type: 'heartbeat',
              from: this.localUsername,
              to: message.from,
              timestamp: Date.now(),
              payload: { response: true }
            }));
          }
        } else if (message.payload?.response) {
          this.updateConnectionHealth(message.from, true);
        }
        break;
      case 'dummy':
        break;
      default:
        break;
    }
  }

  private async initiatePostQuantumKeyExchange(peerUsername: string): Promise<void> {
    try { this.auditLogger.log('info', 'p2p-pq-init', { peer: peerUsername }); } catch {}
    const peer = this.peers.get(peerUsername);
    if (!peer || !peer.dataChannel) {
      return;
    }

    if (!this.isLocalInitiator(peerUsername)) {
      return;
    }

    try {
      const session = await this.getOrCreateSession(peerUsername);
      if (session.inProgress) return;
      session.inProgress = true;
      session.role = 'initiator';
      this.pqSessions.set(peerUsername, session);

      const keyExchangeMessage = {
        type: 'signal',
        from: this.localUsername,
        to: peerUsername,
        timestamp: Date.now(),
        payload: {
          kind: 'pq-key-exchange-init',
          kyberPublicKey: PostQuantumUtils.uint8ArrayToBase64(session.kyberKeyPair!.publicKey)
        }
      };

      peer.dataChannel.send(JSON.stringify(keyExchangeMessage));
      this.logAuditEvent('pq-key-init', peerUsername);
    } catch (_error) {
      console.error('[P2P] Post-quantum key exchange initiation failed:', (_error as any)?.message || _error);
    }
  }

  private async handlePQKeyExchangeInit(from: string, payload: any): Promise<void> {
    const peer = this.peers.get(from);
    if (!peer || !peer.dataChannel) return;

    if (this.isLocalInitiator(from)) {
      try { this.auditLogger.log('info', 'p2p-pq-init-ignored-collision', { peer: from }); } catch {}
      return;
    }

    try {
      const peerPublicKey = PostQuantumUtils.base64ToUint8Array(payload.kyberPublicKey);
      const session = await this.getOrCreateSession(from);
      session.inProgress = true;
      session.role = 'responder';

      const { ciphertext, sharedSecret } = PostQuantumKEM.encapsulate(peerPublicKey);
      session.sharedSecret = sharedSecret;
      const keys = this.deriveBidirectionalSessionKeys(sharedSecret, from);
      session.sendKey = keys.sendKey;
      session.receiveKey = keys.receiveKey;
      this.pqSessions.set(from, session);

      const response = {
        type: 'signal',
        from: this.localUsername,
        to: from,
        timestamp: Date.now(),
        payload: {
          kind: 'pq-key-exchange-response',
          kyberCiphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext)
        }
      };
      try { this.auditLogger.log('info', 'p2p-pq-response', { peer: from }); } catch {}

      peer.dataChannel.send(JSON.stringify(response));
      this.logAuditEvent('pq-key-response', from);
    } catch (_error) {
      console.error('[P2P] Post-quantum key exchange handling failed:', (_error as any)?.message || _error);
    }
  }

  private async handlePQKeyExchangeResponse(from: string, payload: any): Promise<void> {
    const peer = this.peers.get(from);
    if (!peer || !peer.dataChannel) return;

    try {
      const session = await this.getOrCreateSession(from);
      if (session.role !== 'initiator' || !session.kyberKeyPair) return;

      const ciphertext = PostQuantumUtils.base64ToUint8Array(payload.kyberCiphertext);
      const sharedSecret = PostQuantumKEM.decapsulate(ciphertext, session.kyberKeyPair.secretKey);
      session.sharedSecret = sharedSecret;
      const keys = this.deriveBidirectionalSessionKeys(sharedSecret, from);
      session.sendKey = keys.sendKey;
      session.receiveKey = keys.receiveKey;
      session.established = true;
      session.inProgress = false;
      this.pqSessions.set(from, session);
      
      this.logAuditEvent('pq-key-established', from);
      try { this.auditLogger.log('info', 'p2p-pq-established', { peer: from }); } catch {}
      try { window.dispatchEvent(new CustomEvent('p2p-pq-established', { detail: { peer: from } })); } catch {}

      const finalize = {
        type: 'signal',
        from: this.localUsername,
        to: from,
        timestamp: Date.now(),
        payload: {
          kind: 'pq-key-exchange-finalize'
        }
      };
      try { this.auditLogger.log('info', 'p2p-pq-finalize', { peer: from }); } catch {}

      peer.dataChannel.send(JSON.stringify(finalize));
      this.logAuditEvent('pq-key-finalize', from);
    } catch (_error) {
      console.error('[P2P] Post-quantum key exchange response handling failed:', (_error as any)?.message || _error);
    }
  }

  private handlePQKeyExchangeFinalize(from: string): void {
    const session = this.pqSessions.get(from);
    if (session) {
      if (session.role === 'responder') {
        session.established = true;
        session.inProgress = false;
        this.pqSessions.set(from, session);
        this.logAuditEvent('pq-key-established', from);
        try { this.auditLogger.log('info', 'p2p-pq-established', { peer: from }); } catch {}
        try { window.dispatchEvent(new CustomEvent('p2p-pq-established', { detail: { peer: from } })); } catch {}
      }
    }
  }

  private deriveBidirectionalSessionKeys(sharedSecret: Uint8Array, peer: string): { sendKey: Uint8Array; receiveKey: Uint8Array } {
    // Deterministic key schedule: two keys derived from sharedSecret and a stable channelId
    const aUser = this.localUsername || '';
    const bUser = peer || '';
    const low = aUser < bUser ? aUser : bUser;
    const high = aUser < bUser ? bUser : aUser;
    const channelId = `${low}|${high}`;

    const encoder = new TextEncoder();
    const salt = encoder.encode(`p2p-salt-${channelId}`);
    const infoA = PostQuantumUtils.bytesToString(encoder.encode(`p2p-keyA-${channelId}`));
    const infoB = PostQuantumUtils.bytesToString(encoder.encode(`p2p-keyB-${channelId}`));

    const keyA = PostQuantumHash.deriveKey(sharedSecret, salt, infoA, 32);
    const keyB = PostQuantumHash.deriveKey(sharedSecret, salt, infoB, 32);

    // Assign directions deterministically based on username ordering
    if (aUser === low) {
      return { sendKey: keyA, receiveKey: keyB };
    }
    return { sendKey: keyB, receiveKey: keyA };
  }

  private shouldInitiateHandshake(peerUsername: string): boolean {
    const session = this.pqSessions.get(peerUsername);
    if (session?.established || session?.inProgress) return false;
    return this.isLocalInitiator(peerUsername);
  }

  private isLocalInitiator(peerUsername: string): boolean {
    const aUser = this.localUsername || '';
    const bUser = peerUsername || '';
    return aUser < bUser;
  }

  private async getOrCreateSession(peer: string) {
    let session = this.pqSessions.get(peer);
    if (!session) {
      const kyberKeyPair = await PostQuantumKEM.generateKeyPair();
      session = {
        kyberKeyPair,
        sharedSecret: null,
        sendKey: null,
        receiveKey: null,
        established: false,
        inProgress: false,
        role: null
      };
      this.pqSessions.set(peer, session);
    }
    return session;
  }

  private startSessionRekey(username: string): void {
    if (this.sessionRekeyIntervals.has(username)) {
      return;
    }

    const interval = setInterval(() => {
      const session = this.pqSessions.get(username);
      const isInitiator = this.isLocalInitiator(username);
      if (isInitiator && session?.established && !session.inProgress) {
        this.initiatePostQuantumKeyExchange(username);
      }
    }, this.SESSION_REKEY_INTERVAL_MS);

    this.sessionRekeyIntervals.set(username, interval);
  }

  private updateConnectionHealth(username: string, receivedHeartbeat: boolean): void {
    const now = Date.now();
    const health = this.connectionHealthChecks.get(username) || { lastHeartbeat: now, missedCount: 0 };

    if (receivedHeartbeat) {
      health.lastHeartbeat = now;
      health.missedCount = 0;
    } else {
      if (now - health.lastHeartbeat > 60000) {
        health.missedCount += 1;
        if (health.missedCount >= this.MAX_MISSED_HEARTBEATS) {
          this.disconnectPeer(username);
          return;
        }
      }
    }

    this.connectionHealthChecks.set(username, health);
  }

  private validateMessageFreshness(message: P2PMessage): boolean {
    const now = Date.now();
    if (Math.abs(now - message.timestamp) > this.REPLAY_WINDOW_MS) {
      return false;
    }

    if (!message.payload?.nonce) {
      return true;
    }

    const nonces = this.messageNonces.get(message.from) || new Map<string, number>();
    const nonce = message.payload.nonce;
    if (nonces.has(nonce)) {
      return false;
    }

    nonces.set(nonce, now);
    
    if (nonces.size > this.MAX_NONCES_PER_PEER) {
      const entries = Array.from(nonces.entries());
      const validEntries = entries.filter(([_, timestamp]) => now - timestamp <= this.REPLAY_WINDOW_MS);
      this.messageNonces.set(message.from, new Map(validEntries));
    } else {
      this.messageNonces.set(message.from, nonces);
    }
    
    return true;
  }

  private logAuditEvent(event: string, peer: string, details: Record<string, unknown> = {}): void {
    try {
      this.auditLogger.log('info', event, {
        peer,
        ...details
      });
    } catch {}
  }

  private async encryptPayload(to: string, payload: any): Promise<any> {
    const session = this.pqSessions.get(to);
    if (!session || !session.sendKey || !session.established) {
      throw new Error('SECURITY: Cannot send message without established PQ session');
    }

    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const nonce = PostQuantumRandom.randomBytes(36);
    const { ciphertext, tag } = PostQuantumAEAD.encrypt(plaintext, session.sendKey, undefined, nonce);

    return {
      version: 'pq-aead-v1',
      nonce: PostQuantumUtils.uint8ArrayToBase64(nonce),
      ciphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext),
      tag: PostQuantumUtils.uint8ArrayToBase64(tag)
    };
  }

  private async decryptPayload(from: string, payload: any): Promise<any> {
    if (!payload || payload.version !== 'pq-aead-v1') {
      throw new Error('SECURITY: Payload must be PQ-encrypted (pq-aead-v1)');
    }

    const session = this.pqSessions.get(from);
    if (!session || !session.receiveKey || !session.established) {
      throw new Error('SECURITY: No post-quantum session established');
    }

    const nonce = PostQuantumUtils.base64ToUint8Array(payload.nonce);
    const ciphertext = PostQuantumUtils.base64ToUint8Array(payload.ciphertext);
    const tag = PostQuantumUtils.base64ToUint8Array(payload.tag);

    const decrypted = PostQuantumAEAD.decrypt(ciphertext, nonce, tag, session.receiveKey);
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  /**
   * Handle signaling messages for WebRTC negotiation
   */
private async handleSignalingMessage(message: SignalingMessage & { meta?: any }): Promise<void> {
    const { type, from, to, payload, meta } = message;

    if (to !== this.localUsername) return;

    try {
      const { blockStatusCache } = await import('./block-status-cache');
      const isBlocked = blockStatusCache.get(from);
      if (isBlocked === true) {
        return;
      }
    } catch {}

    let peer = this.peers.get(from);
    
    switch (type) {
      case 'offer':
        if (peer && peer.state === 'connecting') {
          const shouldBackOff = this.localUsername < from;
          if (shouldBackOff) {
            try {
              if (peer.dataChannel) {
                peer.dataChannel.onopen = null;
                peer.dataChannel.onmessage = null;
                peer.dataChannel.onclose = null;
                peer.dataChannel.onerror = null;
                peer.dataChannel.close();
              }
              peer.connection.onconnectionstatechange = null;
              peer.connection.oniceconnectionstatechange = null;
              peer.connection.onicecandidate = null;
              peer.connection.ondatachannel = null;
              peer.connection.close();
            } catch {}
            this.peers.delete(from);
            peer = undefined;
          } else {
            return;
          }
        }
        
        // Reconnection case: peer reconnects after disconnect that we didn't detect
        if (peer && peer.state === 'connected') {
          try {
            if (peer.dataChannel) {
              peer.dataChannel.onopen = null;
              peer.dataChannel.onmessage = null;
              peer.dataChannel.onclose = null;
              peer.dataChannel.onerror = null;
              peer.dataChannel.close();
            }
            peer.connection.onconnectionstatechange = null;
            peer.connection.oniceconnectionstatechange = null;
            peer.connection.onicecandidate = null;
            peer.connection.ondatachannel = null;
            peer.connection.close();
          } catch {}
          this.cleanupPeer(from);
          peer = undefined;
        }
        
        if (!peer) {
          // Create new peer connection for incoming offer
          const peerId = this.generatePeerId();
          const connection = new RTCPeerConnection(this.rtcConfig);
          
          peer = {
            id: peerId,
            username: from,
            connection,
            dataChannel: null,
            onionSocket: null,
            transport: 'unknown',
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
                payload: event.candidate
              });
            }
          };

          connection.ondatachannel = (event) => {
            const channel = event.channel;
            peer!.dataChannel = channel;
            this.setupBackpressureHandlers(channel, from);
            
            channel.onopen = () => {
              peer!.state = 'connected';
              peer!.transport = 'webrtc';
              try {
                window.dispatchEvent(new CustomEvent('p2p-fetch-peer-cert', { detail: { peer: from } }));
              } catch {}
              if (this.shouldInitiateHandshake(from)) {
                this.initiatePostQuantumKeyExchange(from);
              }
              this.startSessionRekey(from);
              this.onPeerConnectedCallback?.(from);
            };

            channel.onmessage = (event) => {
              try {
                this.handleP2PMessage(JSON.parse(event.data));
              } catch (_error) {
                this.logAuditEvent('message-parse-failed', from);
              }
            };

            channel.onclose = () => {
              peer!.state = 'disconnected';
              this.onPeerDisconnectedCallback?.(from);
              this.cleanupPeer(from);
            };
          };
        }

        await peer.connection.setRemoteDescription(payload);
        const queued = this.pendingIceCandidates.get(from);
        if (queued && queued.length) {
          for (const c of queued) {
            try { await peer.connection.addIceCandidate(c); } catch (_e) {}
          }
          this.pendingIceCandidates.delete(from);
        }
        const answer = await peer.connection.createAnswer();
        await peer.connection.setLocalDescription(answer);

        this.sendSignalingMessage({
          type: 'answer',
          from: this.localUsername,
          to: from,
          payload: answer,
          meta: {
            routeProof: meta?.routeProof
          }
        });
        break;

      case 'onion-offer': {
        try {
          const wsUrl = message.payload?.wsUrl;
          const token = message.payload?.token;
          if (typeof wsUrl === 'string' && wsUrl.startsWith('ws')) {
            await this.connectOnionSocket(from, wsUrl, token);
            try { await this.sendOnionAnswer(from); } catch {}
          }
        } catch {}
        break;
      }

      case 'onion-answer': {
        try {
          const wsUrl = message.payload?.wsUrl;
          const token = message.payload?.token;
          if (typeof wsUrl === 'string' && wsUrl.startsWith('ws')) {
            await this.connectOnionSocket(from, wsUrl, token);
          }
        } catch {}
        break;
      }

      case 'answer':
        if (peer) {
          await peer.connection.setRemoteDescription(payload);
          const queuedAns = this.pendingIceCandidates.get(from);
          if (queuedAns && queuedAns.length) {
            for (const c of queuedAns) {
              try { await peer.connection.addIceCandidate(c); } catch (_e) {}
            }
            this.pendingIceCandidates.delete(from);
          }
        }
        break;

      case 'ice-candidate':
        if (peer) {
          if (peer.connection.remoteDescription) {
            await peer.connection.addIceCandidate(payload);
          } else {
            const list = this.pendingIceCandidates.get(from) || [];
            list.push(payload);
            this.pendingIceCandidates.set(from, list);
          }
        }
        break;
      
      case 'error':
        try { this.auditLogger.log('warn', 'p2p-signaling-error', { from, to, messageType: message?.type }); } catch {}
        console.error('[P2P] Signaling error', {
          from,
          to,
          messageType: message?.type
        });
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
    const randomBytes = PostQuantumRandom.randomBytes(16);
    return Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Start dummy traffic generation for traffic analysis resistance
   */
  private startDummyTraffic(): void {
    this.dummyTrafficInterval = setInterval(() => {
      this.peers.forEach((peer, _username) => {
        const randomValue = PostQuantumRandom.randomBytes(1)[0] / 255;
        if (peer.state === 'connected' && peer.dataChannel && randomValue < 0.3) {
          const dummySize = this.generateRealisticMessageSize();
          const dummyPayload = this.generateObfuscatedPayload(dummySize);

          const dummyMessage: P2PMessage = {
            type: 'dummy',
            from: this.generateEphemeralId(),
            to: this.generateEphemeralId(),
            timestamp: this.obfuscateTimestamp(Date.now()),
            payload: dummyPayload
          };
          peer.dataChannel.send(JSON.stringify(dummyMessage));
        }
      });
    }, this.generateRandomInterval());
  }

  /**
   * Generate realistic message size distribution
   */
  private generateRealisticMessageSize(): number {
    const rand = PostQuantumRandom.randomBytes(1)[0] / 255;
    if (rand < 0.4) {
      return PostQuantumRandom.randomBytes(1)[0] % 50 + 20;
    }
    if (rand < 0.8) {
      return PostQuantumRandom.randomBytes(1)[0] % 200 + 50;
    }
    return new DataView(PostQuantumRandom.randomBytes(2).buffer).getUint16(0) % 500 + 200;
  }

  /**
   * Generate obfuscated payload that looks like encrypted data
   */
  private generateObfuscatedPayload(size: number): any {
    const randomData = PostQuantumRandom.randomBytes(size);
    return {
      version: "hybrid-v1",
      ephemeralX25519Public: CryptoUtils.Base64.arrayBufferToBase64(PostQuantumRandom.randomBytes(32)),
      kyberCiphertext: CryptoUtils.Base64.arrayBufferToBase64(PostQuantumRandom.randomBytes(1088)),
      encryptedMessage: CryptoUtils.Base64.arrayBufferToBase64(randomData),
      blake3Mac: CryptoUtils.Base64.arrayBufferToBase64(PostQuantumRandom.randomBytes(32))
    };
  }

  /**
   * Generate ephemeral ID for metadata obfuscation
   */
  private generateEphemeralId(): string {
    const randomBytes = PostQuantumRandom.randomBytes(8);
    return Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Obfuscate timestamp to prevent timing analysis
   */
  private obfuscateTimestamp(timestamp: number): number {
    const jitterBytes = new DataView(PostQuantumRandom.randomBytes(4).buffer).getInt32(0);
    const jitter = (jitterBytes / 2147483647) * 60000;
    return Math.floor(timestamp + jitter);
  }

  /**
   * Generate random interval for dummy traffic
   */
  private generateRandomInterval(): number {
    const randomMs = new DataView(PostQuantumRandom.randomBytes(2).buffer).getUint16(0) % 17000;
    return 3000 + randomMs;
  }

  /**
   * Start heartbeat to maintain connections
   */
  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      this.peers.forEach((peer, username) => {
        if (peer.state === 'connected' && peer.dataChannel) {
          this.updateConnectionHealth(username, false);
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
    }, 30000);
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
   * Inspect PQ session status and keys for a peer.
   */
  getSessionStatus(peer: string): { established: boolean; sendKey: Uint8Array | null; receiveKey: Uint8Array | null } {
    const s = this.pqSessions.get(peer);
    if (!s || !s.established || !s.sendKey || !s.receiveKey) {
      return { established: false, sendKey: null, receiveKey: null };
    }
    return {
      established: true,
      sendKey: new Uint8Array(s.sendKey),
      receiveKey: new Uint8Array(s.receiveKey)
    };
  }

  /**
   * Backpressure APIs for DataChannel flow control
   */
  getBufferedAmount(username: string): number {
    const peer = this.peers.get(username);
    return peer?.dataChannel?.bufferedAmount ?? 0;
  }

  setBufferedAmountLowThreshold(username: string, threshold: number): void {
    const peer = this.peers.get(username);
    if (peer?.dataChannel) {
      try { peer.dataChannel.bufferedAmountLowThreshold = threshold; } catch {}
    }
  }

  onBufferedAmountLow(username: string, handler: () => void): void {
    let set = this.bufferedLowHandlers.get(username);
    if (!set) {
      set = new Set();
      this.bufferedLowHandlers.set(username, set);
    }
    set.add(handler);
  }

  offBufferedAmountLow(username: string, handler: () => void): void {
    const set = this.bufferedLowHandlers.get(username);
    if (set) {
      set.delete(handler);
      if (set.size === 0) this.bufferedLowHandlers.delete(username);
    }
  }

  /**
   * Disconnect from a peer
   */
  disconnectPeer(username: string): void {
    const peer = this.peers.get(username);
    if (peer) {
      try { peer.connection.close(); } catch {}
      if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
        try { peer.dataChannel.close(); } catch {}
      }
      this.cleanupPeer(username);
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
    if (this.dummyTrafficInterval) {
      clearInterval(this.dummyTrafficInterval);
      this.dummyTrafficInterval = null;
    }
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    this.peers.forEach((peer, username) => {
      try {
        if (peer.dataChannel?.readyState === 'open') {
          peer.dataChannel.close();
        }
        if (peer.connection.connectionState !== 'closed') {
          peer.connection.close();
        }
      } catch (_error) {
        console.error(`[P2P] Error cleaning up connection to ${username}:`, (_error as any)?.message || _error);
      }
    });
    this.peers.clear();
    this.cleanupAllSessions();

    if (this.signalingChannel) {
      try {
        if (this.signalingChannel.readyState === WebSocket.OPEN ||
            this.signalingChannel.readyState === WebSocket.CONNECTING) {
          this.signalingChannel.close();
        }
      } catch (_error) {
        console.error('[P2P] Error closing signaling channel:', (_error as any)?.message || _error);
      } finally {
        this.signalingChannel = null;
      }
    }

    this.messageRateLimiter.clear();
    this.connectionAttempts.clear();
    this.peerDilithiumKeys.clear();
    this.connectionHealthChecks.clear();
    this.messageNonces.clear();
    this.bufferedLowHandlers.clear();
    this.sessionRekeyIntervals.forEach(interval => clearInterval(interval));
    this.sessionRekeyIntervals.clear();
    this.pqSessions.clear();
  }

  private cleanupPeer(username: string): void {
    this.peers.delete(username);
    this.connectionHealthChecks.delete(username);
    this.messageRateLimiter.delete(username);
    this.messageNonces.delete(username);
    const interval = this.sessionRekeyIntervals.get(username);
    if (interval) {
      clearInterval(interval);
      this.sessionRekeyIntervals.delete(username);
    }
    this.pqSessions.delete(username);
  }

  private resetPqSession(username: string): void {
    const s = this.pqSessions.get(username);
    if (s) {
      try { if (s.sharedSecret) s.sharedSecret.fill(0); } catch {}
      try { if (s.sendKey) s.sendKey.fill(0); } catch {}
      try { if (s.receiveKey) s.receiveKey.fill(0); } catch {}
    }
    this.pqSessions.set(username, {
      kyberKeyPair: s?.kyberKeyPair,
      sharedSecret: null,
      sendKey: null,
      receiveKey: null,
      established: false,
      inProgress: false,
      role: null
    });
    this.lastPqRekeyAttempt.delete(username);
  }

  private cleanupAllSessions(): void {
    this.sessionRekeyIntervals.forEach(interval => clearInterval(interval));
    this.sessionRekeyIntervals.clear();
    this.pqSessions.clear();
  }

  private async fallbackToOnion(username: string): Promise<void> {
    try {
      const peer = this.peers.get(username);
      if (!peer || peer.state === 'connected' || peer.transport === 'onion') return;

      // Require Tor to be available
      if (!torNetworkManager.isSupported() || !torNetworkManager.isConnected()) {
        return;
      }

      await this.advertiseOnionEndpoint(username);
    } catch {}
  }

  private async advertiseOnionEndpoint(toUser: string): Promise<void> {
    try {
      const api: any = (window as any).electronAPI || (window as any).edgeApi || null;
      let endpoint: any = null;
      if (api && typeof api.createOnionEndpoint === 'function') {
        endpoint = await api.createOnionEndpoint({ purpose: 'p2p', ttlSeconds: 600 });
      }
      if (!endpoint || typeof endpoint.wsUrl !== 'string') {
        return;
      }
      this.sendSignalingMessage({
        type: 'onion-offer',
        from: this.localUsername,
        to: toUser,
        payload: { wsUrl: endpoint.wsUrl, token: endpoint.token || null }
      });
    } catch {}
  }

  private async sendOnionAnswer(toUser: string): Promise<void> {
    try {
      const api: any = (window as any).electronAPI || (window as any).edgeApi || null;
      let endpoint: any = null;
      if (api && typeof api.createOnionEndpoint === 'function') {
        endpoint = await api.createOnionEndpoint({ purpose: 'p2p', ttlSeconds: 600 });
      }
      if (!endpoint || typeof endpoint.wsUrl !== 'string') return;
      this.sendSignalingMessage({
        type: 'onion-answer',
        from: this.localUsername,
        to: toUser,
        payload: { wsUrl: endpoint.wsUrl, token: endpoint.token || null }
      });
    } catch {}
  }

  private async connectOnionSocket(fromUser: string, wsUrl: string, token?: string): Promise<void> {
    try {
      const existing = this.peers.get(fromUser);
      if (!existing) return;
      if (existing.transport === 'onion' && existing.onionSocket && existing.onionSocket.readyState === 1) {
        return;
      }

      // Validate wsUrl scheme before attempting connection
      if (!wsUrl || typeof wsUrl !== 'string') {
        console.error('[P2P] Invalid onion WebSocket URL: empty or non-string');
        return;
      }
      const lowerUrl = wsUrl.toLowerCase();
      if (!lowerUrl.startsWith('ws://') && !lowerUrl.startsWith('wss://')) {
        console.error(`[P2P] Invalid onion WebSocket URL scheme: ${wsUrl.split(':')[0]}. Only ws:// or wss:// allowed.`);
        return;
      }

      let socket: WebSocket | null = null;
      // Prefer Electron-provided connector
      const api: any = (window as any).electronAPI || (window as any).edgeApi || null;
      if (api && typeof api.connectOnionWebSocket === 'function') {
        socket = await api.connectOnionWebSocket({ wsUrl, token });
      }
      if (!socket) {
        socket = await torNetworkManager.createTorWebSocket(wsUrl);
      }
      if (!socket) return;

      existing.onionSocket = socket;

      socket.onopen = () => {
        existing.state = 'connected';
        existing.transport = 'onion';
        this.onPeerConnectedCallback?.(fromUser);
        // Start PQ key exchange over onion
        if (this.shouldInitiateHandshake(fromUser)) {
          this.initiatePostQuantumKeyExchange(fromUser);
        }
      };
      socket.onmessage = (event: MessageEvent) => {
        try {
          const msg: P2PMessage = JSON.parse(String(event.data));
          this.handleP2PMessage(msg);
        } catch {}
      };
      socket.onclose = () => {
        if (existing.transport === 'onion') {
          existing.state = 'disconnected';
          this.onPeerDisconnectedCallback?.(fromUser);
        }
      };
      socket.onerror = () => {
      };
    } catch {}
  }

  private setupBackpressureHandlers(channel: RTCDataChannel, username: string): void {
    try {
      channel.bufferedAmountLowThreshold = 262144;
      try { this.auditLogger.log('info', 'p2p-dc-buffer-threshold', { peer: username, value: 262144 }); } catch {}
    } catch {}
    
    channel.onbufferedamountlow = () => {
      const handlers = this.bufferedLowHandlers.get(username);
      if (handlers) {
        handlers.forEach(h => {
          try {
            h();
          } catch (_error) {
            console.error('[P2P] Backpressure handler error:', (_error as any)?.message || _error);
          }
        });
      }
    };
  }
}