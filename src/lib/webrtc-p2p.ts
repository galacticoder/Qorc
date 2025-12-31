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
import { EventType } from './event-types';
import {
  isPlainObject,
  hasPrototypePollutionKeys,
  sanitizeEventUsername
} from './sanitizers';
import {
  DEFAULT_EVENT_RATE_WINDOW_MS,
  DEFAULT_EVENT_RATE_MAX,
  MAX_EVENT_USERNAME_LENGTH
} from './constants';


interface PeerConnection {
  id: string;
  username: string;
  connection: RTCPeerConnection;
  dataChannel: RTCDataChannel | null;
  transport: 'webrtc' | 'unknown';
  state: 'connecting' | 'connected' | 'disconnected' | 'failed';
  lastSeen: number;
}

interface P2PMessage {
  type: 'chat' | 'signal' | 'heartbeat' | 'dummy' | 'typing' | 'reaction' | SignalType.FILE | 'delivery-ack' | 'read-receipt' | 'edit' | 'delete';
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
  type: 'offer' | 'answer' | 'ice-candidate' | 'error' | 'relayed';
  from: string;
  to: string;
  payload: any;
  meta?: SignalingMeta;
}

export class WebRTCP2PService {
  private peers: Map<string, PeerConnection> = new Map();
  private localUsername: string = '';
  private signalingChannel: WebSocket | null = null;
  private signalingReady = false;
  private signalingReadyWaiters: Set<() => void> = new Set();
  private signalingQueue: any[] = [];
  private readonly MAX_SIGNALING_QUEUE = 256;
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
  private processingOffers: Set<string> = new Set();
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

  private readonly userBlockedEventRateState = { windowStart: Date.now(), count: 0 };
  private userBlockedListener: ((event: Event) => void) | null = null;

  private rtcConfig: RTCConfiguration = {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' }
    ],
    iceCandidatePoolSize: 2,
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require',
    iceTransportPolicy: 'all'
  };

  constructor(username: string) {
    this.localUsername = username;

    if (typeof window !== 'undefined') {
      this.userBlockedListener = (event: Event) => {
        try {
          const now = Date.now();
          const bucket = this.userBlockedEventRateState;
          if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
            bucket.windowStart = now;
            bucket.count = 0;
          }
          bucket.count += 1;
          if (bucket.count > DEFAULT_EVENT_RATE_MAX) {
            return;
          }

          if (!(event instanceof CustomEvent)) return;
          const detail = event.detail;
          if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
          const blockedUsername = sanitizeEventUsername((detail as any).username, MAX_EVENT_USERNAME_LENGTH);
          if (blockedUsername) {
            this.disconnectPeer(blockedUsername);
          }
        } catch { }
      };

      window.addEventListener('user-blocked', this.userBlockedListener as EventListener);
    }
  }

  private markSignalingReady(): void {
    if (this.signalingReady) {
      return;
    }
    this.signalingReady = true;
    try {
      for (const fn of this.signalingReadyWaiters) {
        try { fn(); } catch { }
      }
    } catch { }
    try { this.signalingReadyWaiters.clear(); } catch { }
    try { this.flushSignalingQueue(); } catch { }
  }

  private markSignalingNotReady(): void {
    this.signalingReady = false;
  }

  private async waitForSignalingReady(timeoutMs: number): Promise<void> {
    if (this.signalingReady) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        try { clearTimeout(timer); } catch { }
        try { this.signalingReadyWaiters.delete(onReady); } catch { }
        if (err) return reject(err);
        resolve();
      };
      const onReady = () => finish();
      try { this.signalingReadyWaiters.add(onReady); } catch { }
      const timer = setTimeout(() => finish(new Error('P2P signaling not ready (timeout)')), timeoutMs);
    });
  }

  private enqueueSignalingMessage(message: any): void {
    try {
      if (this.signalingQueue.length >= this.MAX_SIGNALING_QUEUE) {
        this.signalingQueue.shift();
      }
      this.signalingQueue.push(message);
    } catch { }
  }

  private flushSignalingQueue(): void {
    if (!this.signalingReady || this.signalingQueue.length === 0) {
      return;
    }
    const items = this.signalingQueue.splice(0, this.signalingQueue.length);
    for (const msg of items) {
      try { this.sendSignalingMessageNow(msg); } catch { }
    }
  }

  private async hydrateRtcConfigFromElectron(signalingServerUrl?: string): Promise<void> {
    try {
      const next: RTCConfiguration = { ...this.rtcConfig, iceServers: [], iceTransportPolicy: 'all' };

      try {
        let baseHttp = '';
        try {
          const envUrl = (import.meta as any).env?.VITE_WS_URL as string | undefined;
          if (envUrl && typeof envUrl === 'string') {
            const u = new URL(envUrl.replace('ws://', 'http://').replace('wss://', 'https://'));
            baseHttp = `${u.protocol}//${u.host}`;
          }
        } catch { }

        try {
          if (!baseHttp && typeof signalingServerUrl === 'string' && signalingServerUrl) {
            const u2 = new URL(signalingServerUrl.replace('ws://', 'http://').replace('wss://', 'https://'));
            baseHttp = `${u2.protocol}//${u2.host}`;
          }
        } catch { }

        try {
          if (!baseHttp && typeof window !== 'undefined' && window.location?.origin) {
            const { protocol, origin } = window.location as Location;
            if (protocol === 'http:' || protocol === 'https:') {
              baseHttp = origin;
            }
          }
        } catch { }

        if (baseHttp && (baseHttp.startsWith('http://') || baseHttp.startsWith('https://'))) {
          const resp = await fetch(`${baseHttp}/api/ice/config`, { method: 'GET', credentials: 'omit' });
          if (resp.ok) {
            const ice = await resp.json();
            if (ice && Array.isArray(ice.iceServers) && ice.iceServers.length > 0) {
              next.iceServers = ice.iceServers;
              if (ice.iceTransportPolicy === 'relay' || ice.iceTransportPolicy === 'all') {
                next.iceTransportPolicy = ice.iceTransportPolicy;
              }
            }
          }
        }
      } catch (err: any) {
        console.warn('[P2P] Failed to fetch server ICE config', err?.message);
      }


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

      if (!sanitized.length) {
        next.iceServers = [
          { urls: 'stun:stun.l.google.com:19302' },
          { urls: 'stun:stun1.l.google.com:19302' },
          { urls: 'stun:stun2.l.google.com:19302' }
        ];
      }

      this.rtcConfig = next;

      const hasTurnServer = (next.iceServers || []).some((srv: any) => {
        const urls = Array.isArray(srv.urls) ? srv.urls : [srv.urls];
        return urls.some((u: any) => typeof u === 'string' && (u.startsWith('turn:') || u.startsWith('turns:')));
      });

      if (!hasTurnServer) {
        console.warn('[P2P] WARNING: No TURN servers configured - P2P may fail between NAT');
      }
      try {
        this.auditLogger.log('info', 'p2p-ice-config-final', {
          iceServers: (next.iceServers || []).length,
          policy: next.iceTransportPolicy
        });
      } catch { }
    } catch (e) {
      console.error('[P2P] Failed to hydrate ICE config', e);
    }
  }

  setDilithiumKeys(keys: { publicKey: Uint8Array; secretKey: Uint8Array }): void {
    this.dilithiumKeys = keys;
  }

  addPeerDilithiumKey(username: string, publicKey: Uint8Array): void {
    this.peerDilithiumKeys.set(username, publicKey);
  }

  private signalingMessageUnsubscribe: (() => void) | null = null;
  private useMainProcessSignaling: boolean = false;

  async initialize(signalingServerUrl: string, options?: {
    registerPayload: Record<string, unknown>;
    registrationSignature: string;
    registrationPublicKey: string;
  }): Promise<void> {
    try {
      await this.hydrateRtcConfigFromElectron(signalingServerUrl);
      try { this.auditLogger.log('info', 'p2p-init-start', { server: signalingServerUrl || '' }); } catch { }

      const edgeApi: any = (window as any).edgeApi || null;
      const electronApi: any = (window as any).electronAPI || null;
      const api: any = (edgeApi?.p2pSignalingConnect ? edgeApi : electronApi) || edgeApi || electronApi || null;
      if (api && typeof api.p2pSignalingConnect === 'function') {
        this.useMainProcessSignaling = true;
        await this.initializeMainProcessSignaling(signalingServerUrl, options, api);
      } else {
        this.useMainProcessSignaling = false;
        await this.initializeDirectSignaling(signalingServerUrl, options);
      }

      this.startDummyTraffic();
      this.startHeartbeat();
    } catch (_error) {
      handleP2PError(_error as Error, { context: 'p2p_initialization' });
      throw _error;
    }
  }

  private async initializeMainProcessSignaling(signalingServerUrl: string, options?: {
    registerPayload: Record<string, unknown>;
    registrationSignature: string;
    registrationPublicKey: string;
  }, api?: any): Promise<void> {
    if (!api) return;

    if (this.signalingMessageUnsubscribe) {
      this.signalingMessageUnsubscribe();
      this.signalingMessageUnsubscribe = null;
    }

    this.signalingMessageUnsubscribe = api.onP2PSignalingMessage((data: any) => {
      try {
        if (data.type === '__p2p_signaling_connected') {
          this.logAuditEvent('signaling-connected', 'server');
          try { this.auditLogger.log('info', 'p2p-signaling-open', {}); } catch { }
          try { this.markSignalingReady(); } catch { }
          return;
        }
        if (data.type === '__p2p_signaling_closed') {
          this.logAuditEvent('signaling-disconnect', 'server');
          try { this.auditLogger.log('info', 'p2p-signaling-close', {}); } catch { }
          try { this.markSignalingNotReady(); } catch { }
          return;
        }
        try { this.auditLogger.log('info', 'p2p-signaling-msg', { type: data?.type, from: data?.from, to: data?.to }); } catch { }
        void this.handleSignalingMessage(data as any).catch((err) => {
          console.error('[P2P] handleSignalingMessage failed', { type: data?.type, error: (err as any)?.message || String(err) });
        });
      } catch (_error) {
        handleP2PError(_error as Error, { context: 'signaling_message_parse' });
      }
    });

    const result = await api.p2pSignalingConnect(signalingServerUrl, {
      username: this.localUsername,
      registrationPayload: {
        register: options?.registerPayload,
        signature: options?.registrationSignature,
        publicKey: options?.registrationPublicKey
      }
    });

    if (!result.success && !result.alreadyConnected) {
      throw new Error(result.error || 'Failed to connect to signaling server');
    }

    try { this.markSignalingReady(); } catch { }
    try { this.auditLogger.log('info', 'p2p-signaling-main-process', { connected: true }); } catch { }
  }

  private async initializeDirectSignaling(signalingServerUrl: string, options?: {
    registerPayload: Record<string, unknown>;
    registrationSignature: string;
    registrationPublicKey: string;
  }): Promise<void> {
    this.signalingChannel = new WebSocket(signalingServerUrl);

    this.signalingChannel.onopen = () => {
      try { this.markSignalingReady(); } catch { }
      this.logAuditEvent('signaling-connected', 'server');
      try { this.auditLogger.log('info', 'p2p-signaling-open', {}); } catch { }
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
        try { this.auditLogger.log('info', 'p2p-signaling-msg', { type: message?.type, from: message?.from, to: message?.to }); } catch { }
        void this.handleSignalingMessage(message as any).catch((err) => {
          console.error('[P2P] handleSignalingMessage failed', { type: message?.type, error: (err as any)?.message || String(err) });
        });
      } catch (_error) {
        handleP2PError(_error as Error, { context: 'signaling_message_parse' });
        try { this.auditLogger.log('warn', 'p2p-signaling-parse-error', {}); } catch { }
      }
    };

    this.signalingChannel.onclose = () => {
      try { this.markSignalingNotReady(); } catch { }
      this.logAuditEvent('signaling-disconnect', 'server');
      try { this.auditLogger.log('info', 'p2p-signaling-close', {}); } catch { }
      if (this.signalingChannel?.readyState === WebSocket.CLOSED) {
        this.signalingChannel = null;
        setTimeout(() => {
          if (!this.signalingChannel) {
            this.initializeDirectSignaling(signalingServerUrl, options).catch(() => {
              this.logAuditEvent('signaling-reconnect-failed', 'server');
            });
          }
        }, 5000);
      }
    };
  }

  async connectToPeer(username: string, options?: {
    peerCertificate?: { dilithiumPublicKey: string; kyberPublicKey: string; x25519PublicKey?: string };
    routeProof?: { payload: any; signature: string };
  }): Promise<void> {
    try { this.auditLogger.log('info', 'p2p-connect-attempt', { peer: username }); } catch { }

    try {
      await this.waitForSignalingReady(15000);
    } catch {
      throw new Error('P2P signaling not ready');
    }

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
      if (existing) {
        if (existing.state === 'connected' && existing.dataChannel?.readyState === 'open') {
          return;
        }
        const iceState = existing.connection?.iceConnectionState;
        const isIceFailed = iceState === 'failed' || iceState === 'disconnected' || iceState === 'closed';

        if (existing.state === 'connecting' && isIceFailed) {
          try {
            if (existing.dataChannel) existing.dataChannel.close();
            existing.connection.close();
          } catch { }
          this.peers.delete(username);
        } else if (existing.state === 'connecting') {
          return;
        }
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
    try { this.auditLogger.log('info', 'p2p-pc-created', { peer: username, iceServers: (this.rtcConfig.iceServers || []).length, policy: this.rtcConfig.iceTransportPolicy }); } catch { }

    const peer: PeerConnection = {
      id: peerId,
      username,
      connection,
      dataChannel: null,
      transport: 'unknown',
      state: 'connecting',
      lastSeen: Date.now()
    };

    this.peers.set(username, peer);

    const connectionTimeout = setTimeout(() => {
      const currentPeer = this.peers.get(username);
      if (currentPeer && currentPeer.state === 'connecting' &&
        currentPeer.connection.signalingState === 'have-local-offer' &&
        !currentPeer.connection.remoteDescription) {
        try { this.auditLogger.log('warn', 'p2p-connection-timeout', { peer: username }); } catch { }
        try {
          currentPeer.connection.close();
          if (currentPeer.dataChannel) currentPeer.dataChannel.close();
        } catch { }
        this.peers.delete(username);
      }
    }, 25000);

    const originalOnOpen = () => {
      clearTimeout(connectionTimeout);
      peer.state = 'connected';
      peer.transport = 'webrtc';
      this.logAuditEvent('p2p-connected', username);
      if (this.shouldInitiateHandshake(username)) {
        this.initiatePostQuantumKeyExchange(username);
      }
      this.startSessionRekey(username);
      this.onPeerConnectedCallback?.(username);
    };

    const dataChannel = connection.createDataChannel('messages', {
      ordered: true,
      maxRetransmits: 3
    });

    peer.dataChannel = dataChannel;

    this.setupBackpressureHandlers(dataChannel, username);
    dataChannel.onopen = originalOnOpen;

    dataChannel.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        this.handleP2PMessage(message);
      } catch {
        this.logAuditEvent('message-parse-failed', username);
      }
    };

    dataChannel.onclose = () => {
      peer.state = 'disconnected';
      this.logAuditEvent('p2p-disconnected', username);
      try { this.auditLogger.log('info', 'p2p-dc-close', { peer: username }); } catch { }
      this.onPeerDisconnectedCallback?.(username);
      this.cleanupPeer(username);
    };

    let iceCount = 0;
    connection.onicecandidate = (event) => {
      if (event.candidate) {
        iceCount++;
        this.sendSignalingMessage({
          type: 'ice-candidate',
          from: this.localUsername,
          to: username,
          payload: event.candidate.toJSON()
        });
      }
    };

    // Timeout to detect stuck ICE gathering (TURN unreachable)
    const gatherTimeout = setTimeout(() => {
      if (connection.iceGatheringState === 'gathering' && iceCount === 0) {
        try { this.auditLogger.log('warn', 'p2p-ice-timeout', { peer: username }); } catch { }
      }
    }, 10000);

    connection.onicegatheringstatechange = () => {
      const gatherState = connection.iceGatheringState;
      if (gatherState === 'complete') {
        clearTimeout(gatherTimeout);
      }
    };

    try {
      connection.oniceconnectionstatechange = () => {
        const st = connection.iceConnectionState;
        if (st === 'failed' || st === 'disconnected') {
          try { this.auditLogger.log('warn', 'p2p-ice-state', { peer: username, state: st }); } catch { }
        }
      };
    } catch { }

    // Create offer
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    try { this.auditLogger.log('info', 'p2p-offer-created', { peer: username }); } catch { }

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
    messageType: 'chat' | 'signal' | 'typing' | 'reaction' | SignalType.FILE | 'delivery-ack' | 'read-receipt' | 'edit' | 'delete' = 'chat'
  ): Promise<void> {
    const peer = this.peers.get(to);
    const isHandshakeMessage = messageType === 'signal' && (message?.kind?.startsWith('pq-key') || message?.kind?.startsWith('session-'));
    const canUseDataChannel = !!(peer?.dataChannel && peer.dataChannel.readyState === 'open');

    if (!peer) {
      try { this.auditLogger.log('warn', 'p2p-send-no-connection', { peer: to, type: messageType }); } catch { }
      throw new Error(`No active P2P connection to ${to}`);
    }

    if (peer.state !== 'connected' || !canUseDataChannel) {
      try { this.auditLogger.log('warn', 'p2p-send-no-connection', { peer: to, type: messageType }); } catch { }
      throw new Error(`No active WebRTC channel to ${to}`);
    }

    if (!isHandshakeMessage) {
      const session = this.pqSessions.get(to);
      if (!session || !session.established || !session.sendKey || !session.receiveKey) {
        try { this.auditLogger.log('error', 'p2p-send-no-session', { peer: to, type: messageType }); } catch { }
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
    try { this.auditLogger.log('info', 'p2p-send', { peer: to, type: messageType, size: JSON.stringify(p2pMessage).length }); } catch { }

    try {
      if (this.dilithiumKeys) {
        const messageBytes = new TextEncoder().encode(JSON.stringify({
          ...p2pMessage,
          signature: undefined
        }));
        const signature = await CryptoUtils.Dilithium.sign(this.dilithiumKeys.secretKey, messageBytes);
        p2pMessage.signature = CryptoUtils.Base64.arrayBufferToBase64(signature);
      }
    } catch {
      this.logAuditEvent('message-signing-failed', to);
    }

    if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
      try {
        peer.dataChannel.send(JSON.stringify(p2pMessage));
      } catch (err: any) {
        if (err.name === 'InvalidStateError') {
          try { peer.dataChannel.close(); } catch { }
          peer.state = 'disconnected';
          this.onPeerDisconnectedCallback?.(to);
        }
        throw err;
      }
    } else {
      throw new Error('No active WebRTC channel');
    }
    peer.lastSeen = Date.now();
    this.logAuditEvent('message-send', to, { type: messageType });
  }

  /**
   * Handle incoming P2P messages
   */
  private async handleP2PMessage(message: P2PMessage): Promise<void> {
    try { this.auditLogger.log('info', 'p2p-recv', { from: message?.from || '', type: message?.type }); } catch { }
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
            try { this.auditLogger.log('warn', 'p2p-sig-invalid', { from: message.from }); } catch { }
            return;
          }
          this.logAuditEvent('message-verified', message.from);
          try { this.auditLogger.log('info', 'p2p-sig-ok', { from: message.from }); } catch { }
        } else {
          this.logAuditEvent('missing-peer-key', message.from);
        }
      } catch {
        this.logAuditEvent('signature-verification-error', message.from);
        return;
      }
    }

    if (!this.validateMessageFreshness(message)) {
      this.logAuditEvent('message-stale', message.from);
      return;
    }

    const peer = this.peers.get(message.from);
    if (peer) {
      peer.lastSeen = Date.now();
    }

    switch (message.type) {
      case 'signal': {
        let kind = message.payload?.kind;

        if (!kind && message.payload?.version === 'pq-aead-v1') {
          const session = this.pqSessions.get(message.from);
          if (session?.established && session?.receiveKey) {
            try {
              const decrypted = await this.decryptPayload(message.from, message.payload);
              message.payload = decrypted;
              kind = decrypted?.kind;
            } catch {
            }
          }
        }

        if (kind === 'pq-key-exchange-init') {
          await this.handlePQKeyExchangeInit(message.from, message.payload);
        } else if (kind === 'pq-key-exchange-response') {
          await this.handlePQKeyExchangeResponse(message.from, message.payload);
        } else if (kind === 'pq-key-exchange-finalize') {
          this.handlePQKeyExchangeFinalize(message.from);
        } else if (kind === 'session-reset-request') {
          try {
            const evt = new CustomEvent(EventType.P2P_SESSION_RESET_REQUEST, { detail: { from: message.from, reason: message?.payload?.reason } });
            window.dispatchEvent(evt);
          } catch { }
          try {
            this.resetPqSession(message.from);
          } catch { }
          try { await this.sendMessage(message.from, { kind: 'session-reset-ack' }, 'signal'); } catch { }
          try { if (this.isLocalInitiator(message.from)) { this.initiatePostQuantumKeyExchange(message.from); } } catch { }
        } else if (kind === 'session-reset-ack') {
          try {
            const evt = new CustomEvent(EventType.P2P_SESSION_RESET_ACK, { detail: { from: message.from } });
            window.dispatchEvent(evt);
          } catch { }
          try {
            const s = this.pqSessions.get(message.from);
            if (this.isLocalInitiator(message.from) && (!s || !s.inProgress)) {
              this.initiatePostQuantumKeyExchange(message.from);
            }
          } catch { }
        } else {
          this.onMessageCallback?.(message);
        }
        break;
      }
      case 'chat':
      case 'typing':
      case 'reaction':
      case SignalType.FILE:
      case 'edit':
      case 'delete': {
        const session = this.pqSessions.get(message.from);
        if (!session || !session.established || !session.sendKey || !session.receiveKey) {
          try { this.auditLogger.log('error', 'p2p-no-session-reject', { from: message.from, type: message.type }); } catch { }
          try {
            if (this.shouldInitiateHandshake(message.from)) {
              this.initiatePostQuantumKeyExchange(message.from);
            }
          } catch { }
          return;
        }

        if (!message.payload || message.payload.version !== 'pq-aead-v1') {
          try { this.auditLogger.log('error', 'p2p-unencrypted-reject', { from: message.from, type: message.type }); } catch { }
          return;
        }

        try {
          const decrypted = await this.decryptPayload(message.from, message.payload);
          message.payload = decrypted;
          try { this.auditLogger.log('info', 'p2p-decrypt-ok', { from: message.from }); } catch { }
        } catch {
          try { this.auditLogger.log('error', 'p2p-decrypt-failed', { from: message.from }); } catch { }
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
                try { await this.sendMessage(message.from, { kind: 'session-reset-request', reason: 'decrypt-failed' }, 'signal'); } catch { }
              }
            }
          } catch { }
          return;
        }

        try {
          const kind = message?.payload?.kind;
          if (kind === 'file-chunk') {
            const evt = new CustomEvent(EventType.P2P_FILE_CHUNK, { detail: { from: message.from, to: message.to, payload: message.payload } });
            window.dispatchEvent(evt);
          } else if (kind === 'file-ack') {
            const evt = new CustomEvent(EventType.P2P_FILE_ACK, { detail: { from: message.from, to: message.to, payload: message.payload } });
            window.dispatchEvent(evt);
          }
        } catch { }
        this.onMessageCallback?.(message);
        break;
      }
      case 'delivery-ack':
      case 'read-receipt': {
        const session = this.pqSessions.get(message.from);
        if (!session || !session.established || !session.sendKey || !session.receiveKey) {
          try { this.auditLogger.log('error', 'p2p-no-session-reject', { from: message.from, type: message.type }); } catch { }
          return;
        }

        if (!message.payload || message.payload.version !== 'pq-aead-v1') {
          try { this.auditLogger.log('error', 'p2p-unencrypted-reject', { from: message.from, type: message.type }); } catch { }
          return;
        }

        // Decrypt PQ AEAD layer to get the hybrid envelope
        try {
          const decrypted = await this.decryptPayload(message.from, message.payload);
          message.payload = decrypted;
          try { this.auditLogger.log('info', 'p2p-receipt-decrypt-ok', { from: message.from, type: message.type }); } catch { }
        } catch {
          try { this.auditLogger.log('error', 'p2p-receipt-decrypt-failed', { from: message.from, type: message.type }); } catch { }
          return;
        }
        this.onMessageCallback?.(message);
        break;
      }
      case 'heartbeat':
        if (message.payload?.ping) {
          this.updateConnectionHealth(message.from, true);
          if (peer) {
            const response: P2PMessage = {
              type: 'heartbeat',
              from: this.localUsername,
              to: message.from,
              timestamp: Date.now(),
              payload: { response: true }
            };
            try {
              if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
                peer.dataChannel.send(JSON.stringify(response));
              }
            } catch { }
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
    try { this.auditLogger.log('info', 'p2p-pq-init', { peer: peerUsername }); } catch { }
    const peer = this.peers.get(peerUsername);
    const hasTransport = !!(peer?.dataChannel && peer.dataChannel.readyState === 'open');
    if (!peer || !hasTransport) {
      return;
    }

    if (!this.isLocalInitiator(peerUsername)) {
      return;
    }

    try {
      const session = await this.getOrCreateSession(peerUsername);
      if (session.inProgress) {
        return;
      }
      session.inProgress = true;
      session.role = 'initiator';
      this.pqSessions.set(peerUsername, session);

      const initPayload = {
        kind: 'pq-key-exchange-init',
        kyberPublicKey: PostQuantumUtils.uint8ArrayToBase64(session.kyberKeyPair!.publicKey)
      };

      await this.sendMessage(peerUsername, initPayload, 'signal');
      this.logAuditEvent('pq-key-init', peerUsername);
    } catch {
    }
  }

  private async handlePQKeyExchangeInit(from: string, payload: any): Promise<void> {
    let peer = this.peers.get(from);
    if (!peer) {
      try {
        const peerId = this.generatePeerId();
        const connection = new RTCPeerConnection(this.rtcConfig);
        peer = {
          id: peerId,
          username: from,
          connection,
          dataChannel: null,
          transport: 'unknown',
          state: 'connected',
          lastSeen: Date.now()
        };
        this.peers.set(from, peer);
        this.onPeerConnectedCallback?.(from);
      } catch { }
    } else {
      try {
        if (peer.state !== 'connected') {
          peer.state = 'connected';
        }
      } catch { }
    }
    const hasTransport = !!(peer?.dataChannel && peer.dataChannel.readyState === 'open');
    if (!peer || !hasTransport) {
      return;
    }

    try {
      const localWouldInitiate = this.isLocalInitiator(from);
      const existingSession = this.pqSessions.get(from);
      if (localWouldInitiate && (existingSession?.inProgress || existingSession?.established)) {
        try { this.auditLogger.log('info', 'p2p-pq-init-ignored-collision', { peer: from }); } catch { }
        return;
      }
    } catch { }

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
        kind: 'pq-key-exchange-response',
        kyberCiphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext)
      };
      try { this.auditLogger.log('info', 'p2p-pq-response', { peer: from }); } catch { }

      await this.sendMessage(from, response, 'signal');
      this.logAuditEvent('pq-key-response', from);
    } catch {
    }
  }

  private async handlePQKeyExchangeResponse(from: string, payload: any): Promise<void> {
    let peer = this.peers.get(from);
    if (!peer) {
      try {
        const peerId = this.generatePeerId();
        const connection = new RTCPeerConnection(this.rtcConfig);
        peer = {
          id: peerId,
          username: from,
          connection,
          dataChannel: null,
          transport: 'unknown',
          state: 'connected',
          lastSeen: Date.now()
        };
        this.peers.set(from, peer);
        this.onPeerConnectedCallback?.(from);
      } catch { }
    } else {
      try {
        if (peer.state !== 'connected') {
          peer.state = 'connected';
        }
      } catch { }
    }

    try {
      const ciphertext = PostQuantumUtils.base64ToUint8Array(payload.kyberCiphertext);
      const session = this.pqSessions.get(from);
      if (!session || !session.kyberKeyPair) {
        throw new Error('No session/keypair found for PQ response');
      }

      const sharedSecret = PostQuantumKEM.decapsulate(ciphertext, session.kyberKeyPair.secretKey);
      if (!sharedSecret) throw new Error('Decapsulate returned null/undefined');

      session.sharedSecret = sharedSecret;
      const keys = this.deriveBidirectionalSessionKeys(sharedSecret, from);
      session.sendKey = keys.sendKey;
      session.receiveKey = keys.receiveKey;
      session.established = true;
      session.inProgress = false;
      this.pqSessions.set(from, session);

      this.logAuditEvent('pq-key-established', from);
      try { this.auditLogger.log('info', 'p2p-pq-established', { peer: from }); } catch { }
      try { window.dispatchEvent(new CustomEvent(EventType.P2P_PQ_ESTABLISHED, { detail: { peer: from } })); } catch { }

      const finalize = { kind: 'pq-key-exchange-finalize' };
      try { this.auditLogger.log('info', 'p2p-pq-finalize', { peer: from }); } catch { }

      await this.sendMessage(from, finalize, 'signal');
      this.logAuditEvent('pq-key-finalize', from);
    } catch {
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
        try { this.auditLogger.log('info', 'p2p-pq-established', { peer: from }); } catch { }
        try { window.dispatchEvent(new CustomEvent(EventType.P2P_PQ_ESTABLISHED, { detail: { peer: from } })); } catch { }
      }
    }
  }

  private deriveBidirectionalSessionKeys(sharedSecret: Uint8Array, peer: string): { sendKey: Uint8Array; receiveKey: Uint8Array } {
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
    } catch { }
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

    if (type === 'relayed') {
      if (payload && typeof payload === 'object') {
        if (payload.type !== 'relayed') {
          await this.handleSignalingMessage({
            ...payload,
            from: payload.from || from,
            to: payload.to || to
          });
        }
      }
      return;
    }

    if (to !== this.localUsername) return;

    const existingPeer = this.peers.get(from);
    if (existingPeer) {
      existingPeer.lastSeen = Date.now();
    }

    try {
      const { blockStatusCache } = await import('./block-status-cache');
      const isBlocked = blockStatusCache.get(from);
      if (isBlocked === true) {
        return;
      }
    } catch { }

    let peer = this.peers.get(from);

    switch (type) {
      case 'offer':
        if (this.processingOffers.has(from)) {
          return;
        }
        this.processingOffers.add(from);
        try {
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
              } catch { }
              this.peers.delete(from);
              peer = undefined;
            } else {
              return;
            }
          }

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
            } catch { }
            this.cleanupPeer(from);
            peer = undefined;
          }

          if (!peer) {
            try {
              const peerId = this.generatePeerId();
              const connection = new RTCPeerConnection(this.rtcConfig);

              peer = {
                id: peerId,
                username: from,
                connection,
                dataChannel: null,
                transport: 'unknown',
                state: 'connecting',
                lastSeen: Date.now()
              };

              this.peers.set(from, peer);

              let receiverIceCount = 0;
              connection.onicecandidate = (event) => {
                if (event.candidate) {
                  receiverIceCount++;
                  this.sendSignalingMessage({
                    type: 'ice-candidate',
                    from: this.localUsername,
                    to: from,
                    payload: event.candidate.toJSON()
                  });
                }
              };

              // Timeout to detect stuck ICE gathering on receiver
              const receiverGatherTimeout = setTimeout(() => {
                if (connection.iceGatheringState === 'gathering' && receiverIceCount === 0) {
                }
              }, 10000);

              connection.onicegatheringstatechange = () => {
                const gatherState = connection.iceGatheringState;
                if (gatherState === 'complete') {
                  clearTimeout(receiverGatherTimeout);
                }
              };

              connection.oniceconnectionstatechange = () => {
              };

              setTimeout(() => {
                const currentPeer = this.peers.get(from);
                if (currentPeer && currentPeer.state !== 'connected') {
                  this.cleanupPeer(from);
                }
              }, 25000);

              connection.ondatachannel = (event) => {
                const channel = event.channel;
                peer!.dataChannel = channel;
                this.setupBackpressureHandlers(channel, from);

                channel.onopen = () => {
                  peer!.state = 'connected';
                  peer!.transport = 'webrtc';
                  try {
                    window.dispatchEvent(new CustomEvent(EventType.P2P_FETCH_PEER_CERT, { detail: { peer: from } }));
                  } catch { }
                  if (this.shouldInitiateHandshake(from)) {
                    this.initiatePostQuantumKeyExchange(from);
                  }
                  this.startSessionRekey(from);
                  this.onPeerConnectedCallback?.(from);
                };

                channel.onmessage = (event) => {
                  try {
                    this.handleP2PMessage(JSON.parse(event.data));
                  } catch {
                    this.logAuditEvent('message-parse-failed', from);
                  }
                };

                channel.onclose = () => {
                  peer!.state = 'disconnected';
                  this.onPeerDisconnectedCallback?.(from);
                  this.cleanupPeer(from);
                };
              };
            } catch { }
          }

          await peer.connection.setRemoteDescription(payload);
          const queued = this.pendingIceCandidates.get(from);
          if (queued && queued.length) {
            for (const c of queued) {
              try {
                await peer.connection.addIceCandidate(c);
              } catch {
              }
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
        } finally {
          this.processingOffers.delete(from);
        }
        break;

      case 'answer':
        if (!peer) {
          try { this.auditLogger.log('warn', 'p2p-answer-no-peer', { from }); } catch { }
          break;
        }
        if (peer.connection.remoteDescription) {
          try { this.auditLogger.log('info', 'p2p-answer-duplicate', { from, signalingState: peer.connection.signalingState }); } catch { }
          break;
        }
        const sigState = peer.connection.signalingState;
        if (sigState !== 'have-local-offer') {
          try { this.auditLogger.log('warn', 'p2p-answer-wrong-state', { from, signalingState: sigState }); } catch { }
          break;
        }
        await peer.connection.setRemoteDescription(payload);
        const queuedAns = this.pendingIceCandidates.get(from);
        if (queuedAns && queuedAns.length) {
          for (const c of queuedAns) {
            try {
              await peer.connection.addIceCandidate(c);
            } catch (e) {
              console.error('[P2P] Failed to add queued ICE candidate', { from, error: (e as Error).message });
            }
          }
          this.pendingIceCandidates.delete(from);

        }
        break;

      case 'ice-candidate':
        if (!peer) {

          const list = this.pendingIceCandidates.get(from) || [];
          list.push(payload);
          this.pendingIceCandidates.set(from, list);
        } else if (peer.connection.remoteDescription) {
          try {
            await peer.connection.addIceCandidate(payload);
          } catch (e) {
            console.error('[P2P] Failed to add ICE candidate', { from, error: (e as Error).message, payload });
          }
        } else {

          const list = this.pendingIceCandidates.get(from) || [];
          list.push(payload);
          this.pendingIceCandidates.set(from, list);
        }
        break;

      case 'error':
        try { this.auditLogger.log('warn', 'p2p-signaling-error', { from, to, messageType: message?.type }); } catch { }
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
    try {

    } catch { }
    if (!this.signalingReady) {
      this.enqueueSignalingMessage(message);
      return;
    }
    this.sendSignalingMessageNow(message);
  }

  private sendSignalingMessageNow(message: any): void {
    if (this.useMainProcessSignaling) {
      const api: any = (window as any).edgeApi || (window as any).electronAPI || null;
      if (api && typeof api.p2pSignalingSend === 'function') {
        api.p2pSignalingSend(message);
      } else {
        console.error('[P2P] No p2pSignalingSend API available (edgeApi:', !!(window as any).edgeApi, 'electronAPI:', !!(window as any).electronAPI, ')');
      }
    } else if (this.signalingChannel && this.signalingChannel.readyState === WebSocket.OPEN) {
      this.signalingChannel.send(JSON.stringify(message));
    } else {
      console.error('[P2P] No signaling channel available');
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
        if (peer.state === 'connected' && randomValue < 0.3) {
          const dummySize = this.generateRealisticMessageSize();
          const dummyPayload = this.generateObfuscatedPayload(dummySize);

          const dummyMessage: P2PMessage = {
            type: 'dummy',
            from: this.generateEphemeralId(),
            to: this.generateEphemeralId(),
            timestamp: this.obfuscateTimestamp(Date.now()),
            payload: dummyPayload
          };
          try {
            if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
              peer.dataChannel.send(JSON.stringify(dummyMessage));
            }
          } catch { }
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
        if (peer.state !== 'connected') return;

        const canDc = peer.dataChannel && peer.dataChannel.readyState === 'open';
        if (!canDc) return;

        this.updateConnectionHealth(username, false);
        const heartbeat: P2PMessage = {
          type: 'heartbeat',
          from: this.localUsername,
          to: username,
          timestamp: Date.now(),
          payload: { ping: true }
        };
        try {
          peer.dataChannel!.send(JSON.stringify(heartbeat));
        } catch { }
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
      try { peer.dataChannel.bufferedAmountLowThreshold = threshold; } catch { }
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
      try { peer.connection.close(); } catch { }
      if (peer.dataChannel && peer.dataChannel.readyState === 'open') {
        try { peer.dataChannel.close(); } catch { }
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
    if (typeof window !== 'undefined' && this.userBlockedListener) {
      try {
        window.removeEventListener('user-blocked', this.userBlockedListener as EventListener);
      } catch { }
      this.userBlockedListener = null;
    }

    try { this.markSignalingNotReady(); } catch { }
    try { this.signalingQueue.splice(0, this.signalingQueue.length); } catch { }

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

    // Cleanup signaling message subscription
    if (this.signalingMessageUnsubscribe) {
      try { this.signalingMessageUnsubscribe(); } catch { }
      this.signalingMessageUnsubscribe = null;
    }

    // Disconnect signaling
    if (this.useMainProcessSignaling) {
      try {
        const api: any = (window as any).electronAPI || (window as any).edgeApi || null;
        if (api && typeof api.p2pSignalingDisconnect === 'function') {
          api.p2pSignalingDisconnect().catch(() => { });
        }
      } catch { }
    } else if (this.signalingChannel) {
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
    try { this.signalingReadyWaiters.clear(); } catch { }
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
      try { if (s.sharedSecret) s.sharedSecret.fill(0); } catch { }
      try { if (s.sendKey) s.sendKey.fill(0); } catch { }
      try { if (s.receiveKey) s.receiveKey.fill(0); } catch { }
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


  private setupBackpressureHandlers(channel: RTCDataChannel, username: string): void {
    try {
      channel.bufferedAmountLowThreshold = 262144;
      try { this.auditLogger.log('info', 'p2p-dc-buffer-threshold', { peer: username, value: 262144 }); } catch { }
    } catch { }

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