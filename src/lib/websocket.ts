import { v4 as uuidv4 } from 'uuid';
import { SignalType } from './signal-types';
import { torNetworkManager } from './tor-network';
import {
  PostQuantumAEAD,
  PostQuantumHash,
  PostQuantumKEM,
  PostQuantumRandom,
  PostQuantumUtils,
  PostQuantumSignature,
  SecurityAuditLogger
} from './post-quantum-crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { SecureAuditLogger, handleNetworkError, handleCriticalError } from './secure-error-handler';

type WebSocketLifecycleState =
  | 'idle'
  | 'tor-check'
  | 'connecting'
  | 'handshaking'
  | 'connected'
  | 'disconnected'
  | 'paused'
  | 'error';

interface PendingSend {
  id: string;
  payload: unknown;
  createdAt: number;
  attempt: number;
  flushAfter: number;
  highPriority?: boolean;
}

interface ServerKeyMaterial {
  kyberPublicKey: Uint8Array;
  dilithiumPublicKey?: Uint8Array;
  x25519PublicKey?: Uint8Array;
  fingerprint: string;
  serverId?: string;
}

interface ConnectionMetrics {
  lastConnectedAt: number | null;
  totalReconnects: number;
  consecutiveFailures: number;
  lastFailureAt: number | null;
  lastRateLimitAt: number | null;
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
  averageLatencyMs: number;
  lastLatencyMs: number | null;
  securityEvents: {
    replayAttempts: number;
    signatureFailures: number;
    rateLimitHits: number;
    fingerprintMismatches: number;
  };
}

interface RateLimitState {
  messageTimestamps: number[];
  lastResetTime: number;
  violationCount: number;
}

interface ConnectionHealth {
  state: WebSocketLifecycleState;
  isHealthy: boolean;
  metrics: ConnectionMetrics;
  queueDepth: number;
  sessionAge: number | null;
  torStatus: {
    ready: boolean;
    circuitHealth: 'unknown' | 'good' | 'degraded' | 'poor';
  };
  lastHeartbeat: number | null;
  quality: 'excellent' | 'good' | 'fair' | 'poor' | 'unknown';
}


const MAX_PENDING_QUEUE = 500;
const MAX_REPLAY_WINDOW_MS = 5 * 60 * 1000;
const REPLAY_CACHE_LIMIT = 10_000;
const INITIAL_RECONNECT_DELAY_MS = 1_000;
const MAX_RECONNECT_DELAY_MS = 60_000;
const RATE_LIMIT_BACKOFF_MS = 5_000;
const MAX_HANDSHAKE_ATTEMPTS = 3;
const MAX_MESSAGE_AAD_LENGTH = 256;
const SESSION_REKEY_INTERVAL_MS = 60 * 60 * 1000;
const KEY_ROTATION_WARNING_MS = 45 * 60 * 1000;
const QUEUE_FLUSH_INTERVAL_MS = 1_000;

const MAX_MESSAGES_PER_MINUTE = 120;
const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_BURST_MESSAGES = 20;
const RATE_LIMIT_VIOLATION_THRESHOLD = 3;

const HEARTBEAT_INTERVAL_MS = 35_000;
const HEARTBEAT_TIMEOUT_MS = 90_000;
const MAX_MISSED_HEARTBEATS = 4;
const LATENCY_SAMPLE_WEIGHT = 0.2;
const CIRCUIT_BREAKER_THRESHOLD = 5;
const CIRCUIT_BREAKER_TIMEOUT_MS = 60_000;

const MAX_NONCE_SEQUENCE_GAP = 1000;
const TIMESTAMP_SKEW_TOLERANCE_MS = 5_000;

const SESSION_FAILOVER_GRACE_PERIOD_MS = 10_000;

interface MessageHandler {
  (message: unknown): void;
}

class WebSocketClient {
  private lifecycleState: WebSocketLifecycleState = 'idle';
  private messageHandlers: Map<string, MessageHandler> = new Map();
  private setLoginError?: (error: string) => void;
  private globalRateLimitUntil = 0;
  private reconnectAttempts = 0;
  private reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
  private handshakeAttempts = 0;
  private isManualClose = false;
  private pendingQueue: PendingSend[] = [];
  private flushTimer?: ReturnType<typeof setTimeout>;
  private flushInFlight = false;
  private serverKeyMaterial?: ServerKeyMaterial;
  private sessionKeyMaterial?: {
    sessionId: string;
    sendKey: Uint8Array;
    recvKey: Uint8Array;
    establishedAt: number;
    fingerprint: string;
  };
  private previousSessionFingerprint?: string;
  private sessionTransitionTime?: number;
  private sessionNonceCounter = 0;
  private expectedRemoteNonceCounter = 0;
  private metrics: ConnectionMetrics = {
    lastConnectedAt: null,
    totalReconnects: 0,
    consecutiveFailures: 0,
    lastFailureAt: null,
    lastRateLimitAt: null,
    messagesSent: 0,
    messagesReceived: 0,
    bytesSent: 0,
    bytesReceived: 0,
    averageLatencyMs: 0,
    lastLatencyMs: null,
    securityEvents: {
      replayAttempts: 0,
      signatureFailures: 0,
      rateLimitHits: 0,
      fingerprintMismatches: 0
    }
  };
  private torReady = false;
  private torListener?: (connected: boolean) => void;
  private connectivityWatchdog?: ReturnType<typeof setInterval>;
  private sessionRekeyTimer: ReturnType<typeof setTimeout> | null = null;
  private handshakeInFlight = false;
  private handshakePromise: Promise<void> | null = null;
  private seenMessageFingerprints: Map<string, number> = new Map();
  
  // Rate limiting state
  private rateLimitState: RateLimitState = {
    messageTimestamps: [],
    lastResetTime: Date.now(),
    violationCount: 0
  };
  
  // Health monitoring
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private heartbeatTimeoutTimer?: ReturnType<typeof setTimeout>;
  private lastHeartbeatSent: number | null = null;
  private lastHeartbeatReceived: number | null = null;
  private missedHeartbeats = 0;
  private connectionStateCallbacks = new Set<(health: ConnectionHealth) => void>();
  
  // Circuit breaker
  private circuitBreakerFailures = 0;
  private circuitBreakerOpenUntil = 0;
  
  // Message signing
  private signingKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
  private serverSignatureKey?: Uint8Array;
  
  // Tor circuit tracking
  private lastTorCircuitRotation: number | null = null;
private torCircuitListener?: () => void;
  private torCircuitInterval?: ReturnType<typeof setInterval>;

  // Token validation single-run guard per session lifecycle
  private tokenValidationAttempted = false;

  constructor() {
    void this.initializeSigningKeys();
    this.setupMessageListener();
  }

  private setupMessageListener(): void {
    window.addEventListener('edge:server-message', ((event: CustomEvent) => {
      const message = event.detail;
      const messageType = message?.type;
      
      if (messageType === '__ws_connection_closed') {
        SecureAuditLogger.info('ws', 'connection', 'closed-by-electron', {
          code: message.code,
          reason: message.reason,
          duration: message.duration
        });
        this.resetSessionKeys(false);
        this.lifecycleState = 'disconnected';
        return;
      }
      
      if (messageType === '__ws_connection_error') {
        SecureAuditLogger.error('ws', 'connection', 'error-from-electron', {
          error: message.error
        });
        this.resetSessionKeys(false);
        this.lifecycleState = 'error';
        return;
      }
      
      if (messageType === '__ws_connection_opened') {
        SecureAuditLogger.info('ws', 'connection', 'opened-by-electron', {
          previousState: this.lifecycleState
        });
        const wasConnectedBefore = this.lifecycleState !== 'idle' || this.sessionKeyMaterial != null;
        
        if (this.lifecycleState === 'disconnected' || this.lifecycleState === 'error' || this.lifecycleState === 'idle') {
          this.lifecycleState = 'handshaking';
          this.performHandshake(false)
            .then(() => {
              this.lifecycleState = 'connected';
              SecureAuditLogger.info('ws', 'reconnect', 'handshake-success', {});
              
              this.startHeartbeat();
              void this.flushPendingQueue();

              if (wasConnectedBefore) {
                window.dispatchEvent(new CustomEvent('ws-reconnected', {
                  detail: { timestamp: Date.now() }
                }));
              }
            })
            .catch((error) => {
              SecureAuditLogger.error('ws', 'reconnect', 'handshake-failed', {
                error: error instanceof Error ? error.message : String(error)
              });
              
              this.lifecycleState = 'error';
            });
        }
        return;
      }
      
      if (typeof messageType === 'string' && this.messageHandlers.has(messageType)) {
        void this.handleMessage(message);
      }
    }) as EventListener);
  }

  private async initializeSigningKeys(): Promise<void> {
    try {
      const { encryptedStorage } = await import('./encrypted-storage');
      const stored = await encryptedStorage.getItem('ws_client_signing_key_v1');
      if (stored) {
        try {
          const parsed = typeof stored === 'string' ? JSON.parse(stored) : stored;
          if (parsed?.publicKey && parsed?.privateKey) {
            this.signingKeyPair = {
              publicKey: PostQuantumUtils.base64ToUint8Array(parsed.publicKey),
              privateKey: PostQuantumUtils.base64ToUint8Array(parsed.privateKey)
            };
            return;
          }
        } catch {}
      }

      const kp = await PostQuantumSignature.generateKeyPair();
      this.signingKeyPair = { publicKey: kp.publicKey, privateKey: kp.secretKey };
      try {
        const publicKey = PostQuantumUtils.asUint8Array(this.signingKeyPair.publicKey);
        const privateKey = PostQuantumUtils.asUint8Array(this.signingKeyPair.privateKey);
        await encryptedStorage.setItem('ws_client_signing_key_v1', JSON.stringify({
          publicKey: PostQuantumUtils.uint8ArrayToBase64(publicKey),
          privateKey: PostQuantumUtils.uint8ArrayToBase64(privateKey)
        }));
      } catch {}
    } catch (_error) {
      handleCriticalError(_error as Error, { context: 'ws-signing-init' });
    }
  }

  public async connect(): Promise<void> {
    if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
      if (this.handshakeInFlight && this.handshakePromise) {
        try { await this.handshakePromise; } catch {}
      }
      return;
    }
    if (this.lifecycleState === 'connected') {
      return;
    }

    this.isManualClose = false;
    this.lifecycleState = 'tor-check' as any;
    this.ensureTorListener();

    if (!this.ensureTorReady()) {
      throw new Error('Tor network not ready');
    }

    try {
      this.lifecycleState = 'connecting';
      await this.establishConnection();
    } catch (_error) {
      if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
        this.lifecycleState = 'error';
      }
      this.handleConnectionError(_error as Error, 'connect');
      throw _error;
    }
  }

  private ensureTorListener(): void {
    if (this.torListener) {
      return;
    }

    const listener = (connected: boolean) => {
      this.torReady = connected;
      if (!connected && this.lifecycleState === 'connected') {
        SecureAuditLogger.warn('ws', 'tor', 'disconnected');
        this.lifecycleState = 'paused';
      }
    };

    try {
      torNetworkManager.onConnectionChange(listener);
      this.torListener = listener;
    } catch {
      SecureAuditLogger.warn('ws', 'tor-listener', 'attach-failed');
    }
  }

  private clampX25519Scalar(sk: Uint8Array): Uint8Array {
    const out = new Uint8Array(sk);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    return out;
  }

  private generateEphemeralX25519(): { secretKey: Uint8Array; publicKey: Uint8Array } {
    const raw = PostQuantumRandom.randomBytes(32);
    const secretKey = this.clampX25519Scalar(raw);
    const publicKey = x25519.getPublicKey(secretKey);
    return { secretKey, publicKey: new Uint8Array(publicKey) };
  }

  private computeClassicalSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const shared = x25519.getSharedSecret(privateKey, publicKey);
    return new Uint8Array(shared.slice(0, 32));
  }

  private ensureTorReady(): boolean {
    try {
      if (!torNetworkManager.isSupported()) {
        this.torReady = true;
        return true;
      }
      const connected = torNetworkManager.isConnected();
      this.torReady = connected;
      return connected;
    } catch {
      return false;
    }
  }

  private async establishConnection(): Promise<void> {
    const edgeApi = (window as any).edgeApi as { wsConnect?: () => Promise<any> } | undefined;
    if (!edgeApi?.wsConnect) {
      throw new Error('edgeApi.wsConnect not available');
    }

    let result: any;
    try {
      result = await edgeApi.wsConnect();
    } catch (_error) {
      handleNetworkError(_error as Error, { context: 'ws-connect' });
      throw _error;
    }

    if (result && result.success === false) {
      const msg = result.error || 'Failed to establish WebSocket connection';
      handleNetworkError(new Error(msg), { context: 'ws-connect' });
      throw new Error(msg);
    }

    this.lifecycleState = 'handshaking';
    this.metrics.lastConnectedAt = Date.now();
    this.metrics.consecutiveFailures = 0;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;

    await this.performHandshake(false);

    this.lifecycleState = 'connected';
    SecureAuditLogger.info('ws', 'connection', 'established', {
      torReady: this.torReady,
      pendingQueue: this.pendingQueue.length
    });

    this.registerSessionErrorHandler();

    this.scheduleQueueFlush();
    this.startConnectivityWatchdog();
    this.startHeartbeat();
    this.attachTorCircuitListener();
  }

  /**
   * Register handler for ERROR messages from server
   */
  private registerSessionErrorHandler(): void {
    this.registerMessageHandler(SignalType.ERROR, async (message: any) => {
      const errorMsg = message.message || '';
      
      if (errorMsg.includes('Unknown PQ session') || errorMsg.includes('PQ session')) {
        SecureAuditLogger.warn('ws', 'session-error', 'unknown-session', {
          message: errorMsg,
          action: 'rehandshaking'
        });
        
        // Reset session keys to force new handshake
        this.resetSessionKeys(true);
        
        // Perform new handshake
        try {
          await this.performHandshake(false);
          SecureAuditLogger.info('ws', 'session-error', 'rehandshake-success', {});
          
          // Retry pending queue after successful handshake
          void this.flushPendingQueue();
        } catch (_error) {
          SecureAuditLogger.error('ws', 'session-error', 'rehandshake-failed', {
            error: _error instanceof Error ? _error.message : String(_error)
          });
        }
      } else {
        SecureAuditLogger.warn('ws', 'server-error', 'received', {
          message: errorMsg
        });
      }
    });
  }

  private startConnectivityWatchdog(): void {
    if (this.connectivityWatchdog) {
      return;
    }

    this.connectivityWatchdog = setInterval(() => {
      if (this.lifecycleState === 'connected') {
        void this.flushPendingQueue();
      }
      this.pruneReplayCache();
      this.notifyConnectionStateCallbacks();
    }, 5000);
  }

  private stopConnectivityWatchdog(): void {
    if (this.connectivityWatchdog) {
      clearInterval(this.connectivityWatchdog);
      this.connectivityWatchdog = undefined;
    }
  }

  /**
   * Check if message is within rate limits (token bucket + burst detection)
   */
  private checkRateLimit(): boolean {
    const now = Date.now();
    
    // Remove timestamps outside the window
    this.rateLimitState.messageTimestamps = this.rateLimitState.messageTimestamps.filter(
      ts => now - ts < RATE_LIMIT_WINDOW_MS
    );

    // Check burst limit
    const recentMessages = this.rateLimitState.messageTimestamps.filter(
      ts => now - ts < 1000
    ).length;
    
    if (recentMessages >= MAX_BURST_MESSAGES) {
      this.rateLimitState.violationCount += 1;
      this.metrics.securityEvents.rateLimitHits += 1;
      SecurityAuditLogger.log('warn', 'ws-rate-limit-burst', {
        recentMessages,
        limit: MAX_BURST_MESSAGES,
        violations: this.rateLimitState.violationCount
      });
      
      if (this.rateLimitState.violationCount >= RATE_LIMIT_VIOLATION_THRESHOLD) {
        SecureAuditLogger.warn('ws', 'rate-limit', 'threshold-exceeded', {
          violations: this.rateLimitState.violationCount
        });
      }
      
      return false;
    }

    // Check window limit
    if (this.rateLimitState.messageTimestamps.length >= MAX_MESSAGES_PER_MINUTE) {
      this.rateLimitState.violationCount += 1;
      this.metrics.securityEvents.rateLimitHits += 1;
      SecurityAuditLogger.log('warn', 'ws-rate-limit-window', {
        messagesInWindow: this.rateLimitState.messageTimestamps.length,
        limit: MAX_MESSAGES_PER_MINUTE,
        violations: this.rateLimitState.violationCount
      });
      return false;
    }

    // Reset violation count on successful check after cooldown
    if (this.rateLimitState.violationCount > 0 && now - this.rateLimitState.lastResetTime > RATE_LIMIT_WINDOW_MS) {
      this.rateLimitState.violationCount = 0;
      this.rateLimitState.lastResetTime = now;
    }

    // Add current timestamp
    this.rateLimitState.messageTimestamps.push(now);
    return true;
  }

  /**
   * Reset rate limit state
   */
  private resetRateLimit(): void {
    this.rateLimitState = {
      messageTimestamps: [],
      lastResetTime: Date.now(),
      violationCount: 0
    };
    SecurityAuditLogger.log('info', 'ws-rate-limit-reset', {});
  }

  /**
   * Validate nonce sequence to detect out-of-order or replayed messages
   */
  private validateNonceSequence(counter: number): boolean {
    // Allow for some reordering but detect large gaps or duplicates
    if (counter <= this.expectedRemoteNonceCounter - MAX_NONCE_SEQUENCE_GAP) {
      this.metrics.securityEvents.replayAttempts += 1;
      SecurityAuditLogger.log('error', 'ws-nonce-replay', {
        received: counter,
        expected: this.expectedRemoteNonceCounter,
        gap: this.expectedRemoteNonceCounter - counter
      });
      return false;
    }

    if (counter > this.expectedRemoteNonceCounter + MAX_NONCE_SEQUENCE_GAP) {
      SecurityAuditLogger.log('warn', 'ws-nonce-future', {
        received: counter,
        expected: this.expectedRemoteNonceCounter,
        gap: counter - this.expectedRemoteNonceCounter
      });
    }

    if (counter >= this.expectedRemoteNonceCounter) {
      this.expectedRemoteNonceCounter = counter + 1;
    }

    return true;
  }

  /**
   * Validate timestamp with skew tolerance
   */
  private validateTimestamp(timestamp: number): boolean {
    const now = Date.now();
    const skew = Math.abs(now - timestamp);

    if (skew > MAX_REPLAY_WINDOW_MS) {
      this.metrics.securityEvents.replayAttempts += 1;
      SecurityAuditLogger.log('error', 'ws-timestamp-invalid', {
        timestamp,
        now,
        skew,
        maxAllowed: MAX_REPLAY_WINDOW_MS
      });
      return false;
    }

    if (skew > TIMESTAMP_SKEW_TOLERANCE_MS) {
      SecurityAuditLogger.log('warn', 'ws-timestamp-skew', {
        timestamp,
        now,
        skew,
        tolerance: TIMESTAMP_SKEW_TOLERANCE_MS
      });
    }

    return true;
  }

  /**
   * Sign outgoing message for integrity verification
   */
  private async signMessage(envelope: any): Promise<string | undefined> {
    if (!this.signingKeyPair) {
      return undefined;
    }

    try {
      const payload = `${envelope.messageId}:${envelope.timestamp}:${envelope.counter}:${envelope.sessionId}`;
      const message = new TextEncoder().encode(payload);
      const signature = PostQuantumSignature.sign(message, this.signingKeyPair.privateKey);
      return PostQuantumUtils.uint8ArrayToBase64(signature);
    } catch (_error) {
      SecurityAuditLogger.log('error', 'ws-message-signing-failed', {});
      return undefined;
    }
  }

  /**
   * Verify incoming message signature
   */
  private async verifyMessageSignature(envelope: any): Promise<boolean> {
    if (!envelope.signature) {
      SecurityAuditLogger.log('error', 'ws-signature-missing', {
        messageId: envelope.messageId
      });
      this.metrics.securityEvents.signatureFailures += 1;
      return false;
    }

    if (!this.serverSignatureKey) {
      SecurityAuditLogger.log('warn', 'ws-signature-key-unavailable', {
        messageId: envelope.messageId
      });
      return true;
    }

    try {
      const payload = `${envelope.messageId}:${envelope.timestamp}:${envelope.counter}:${envelope.sessionId}`;
      const message = new TextEncoder().encode(payload);
      const signature = PostQuantumUtils.base64ToUint8Array(envelope.signature);
      const valid = PostQuantumSignature.verify(signature, message, this.serverSignatureKey);
      
      if (!valid) {
        this.metrics.securityEvents.signatureFailures += 1;
        SecurityAuditLogger.log('error', 'ws-signature-invalid', {
          messageId: envelope.messageId
        });
      }
      
      return valid;
    } catch (_error) {
      this.metrics.securityEvents.signatureFailures += 1;
      return false;
    }
  }

  /**
   * Start heartbeat mechanism
   */
  private startHeartbeat(): void {
    if (this.heartbeatTimer) {
      return;
    }

    this.heartbeatTimer = setInterval(() => {
      if (this.lifecycleState === 'connected') {
        void this.sendHeartbeat();
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  /**
   * Stop heartbeat mechanism
   */
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = undefined;
    }
  }

  /**
   * Send heartbeat ping
   */
  private async sendHeartbeat(): Promise<void> {
    try {
      this.lastHeartbeatSent = Date.now();

      const heartbeatMessage = {
        type: 'pq-heartbeat-ping',
        timestamp: this.lastHeartbeatSent,
        sessionId: this.sessionKeyMaterial?.sessionId
      };

      await this.transmit(JSON.stringify(heartbeatMessage));

      // Set timeout for response
      if (this.heartbeatTimeoutTimer) {
        clearTimeout(this.heartbeatTimeoutTimer);
      }

      this.heartbeatTimeoutTimer = setTimeout(() => {
        this.handleMissedHeartbeat();
      }, HEARTBEAT_TIMEOUT_MS);

      SecurityAuditLogger.log('info', 'ws-heartbeat-sent', {
        timestamp: this.lastHeartbeatSent
      });
    } catch (_error) {
      SecureAuditLogger.warn('ws', 'heartbeat', 'send-failed');
      this.handleMissedHeartbeat();
    }
  }

  /**
   * Handle heartbeat response
   */
  public noteHeartbeatPong(message: any): void {
    this.handleHeartbeatResponse(message);
  }

  private handleHeartbeatResponse(message: any): void {
    if (message?.type === 'pq-heartbeat-pong') {
      if (!this.sessionKeyMaterial || message.sessionId !== this.sessionKeyMaterial.sessionId) {
        void this.performHandshake(true).catch((error) => this.handleConnectionError(error as Error, 'heartbeat-rehandshake'));
        return;
      }
    }
    const now = Date.now();
    this.lastHeartbeatReceived = now;
    this.missedHeartbeats = 0;

    if (this.heartbeatTimeoutTimer) {
      clearTimeout(this.heartbeatTimeoutTimer);
      this.heartbeatTimeoutTimer = undefined;
    }

    if (this.lastHeartbeatSent) {
      const latency = now - this.lastHeartbeatSent;
      this.updateLatencyMetrics(latency);
      
      SecurityAuditLogger.log('info', 'ws-heartbeat-received', {
        latency,
        timestamp: now
      });
    }
  }

  /**
   * Handle missed heartbeat
   */
  private handleMissedHeartbeat(): void {
    this.missedHeartbeats += 1;
    
    SecurityAuditLogger.log('warn', 'ws-heartbeat-missed', {
      consecutive: this.missedHeartbeats,
      maxAllowed: MAX_MISSED_HEARTBEATS
    });

    if (this.missedHeartbeats >= MAX_MISSED_HEARTBEATS) {
      SecureAuditLogger.error('ws', 'heartbeat', 'connection-lost', {
        missedCount: this.missedHeartbeats
      });
      
      // Connection appears dead, trigger reconnect
      this.handleConnectionError(new Error('Heartbeat timeout'), 'heartbeat-timeout');
    }
  }

  /**
   * Update latency metrics with exponential moving average
   */
  private updateLatencyMetrics(latency: number): void {
    this.metrics.lastLatencyMs = latency;
    
    if (this.metrics.averageLatencyMs === 0) {
      this.metrics.averageLatencyMs = latency;
    } else {
      this.metrics.averageLatencyMs = 
        this.metrics.averageLatencyMs * (1 - LATENCY_SAMPLE_WEIGHT) + 
        latency * LATENCY_SAMPLE_WEIGHT;
    }
  }

  /**
   * Get connection quality assessment
   */
  private assessConnectionQuality(): 'excellent' | 'good' | 'fair' | 'poor' | 'unknown' {
    if (this.lifecycleState !== 'connected' || this.metrics.averageLatencyMs === 0) {
      return 'unknown';
    }

    const latency = this.metrics.averageLatencyMs;
    
    if (latency < 100) return 'excellent';
    if (latency < 300) return 'good';
    if (latency < 1000) return 'fair';
    return 'poor';
  }

  /**
   * Circuit breaker check
   */
  private checkCircuitBreaker(): boolean {
    const now = Date.now();
    
    if (now < this.circuitBreakerOpenUntil) {
      SecurityAuditLogger.log('warn', 'ws-circuit-breaker-open', {
        opensUntil: this.circuitBreakerOpenUntil,
        remainingMs: this.circuitBreakerOpenUntil - now
      });
      return false;
    }

    return true;
  }

  /**
   * Record circuit breaker failure
   */
  private recordCircuitBreakerFailure(): void {
    this.circuitBreakerFailures += 1;
    
    if (this.circuitBreakerFailures >= CIRCUIT_BREAKER_THRESHOLD) {
      this.circuitBreakerOpenUntil = Date.now() + CIRCUIT_BREAKER_TIMEOUT_MS;
      
      SecurityAuditLogger.log('error', 'ws-circuit-breaker-triggered', {
        failures: this.circuitBreakerFailures,
        openDurationMs: CIRCUIT_BREAKER_TIMEOUT_MS
      });
      
      // Reset failure count
      this.circuitBreakerFailures = 0;
    }
  }

  /**
   * Reset circuit breaker on successful operation
   */
  private resetCircuitBreaker(): void {
    if (this.circuitBreakerFailures > 0) {
      this.circuitBreakerFailures = 0;
      SecurityAuditLogger.log('info', 'ws-circuit-breaker-reset', {});
    }
  }

  /**
   * Register callback for connection state changes
   */
  public onConnectionStateChange(callback: (health: ConnectionHealth) => void): () => void {
    this.connectionStateCallbacks.add(callback);
    return () => this.connectionStateCallbacks.delete(callback);
  }

  /**
   * Notify all connection state callbacks
   */
  private notifyConnectionStateCallbacks(): void {
    const health = this.getConnectionHealth();
    for (const callback of Array.from(this.connectionStateCallbacks)) {
      try {
        callback(health);
      } catch (_error) {
        
      }
    }
  }

  /**
   * Get comprehensive connection health metrics
   */
  public getConnectionHealth(): ConnectionHealth {
    const sessionAge = this.sessionKeyMaterial 
      ? Date.now() - this.sessionKeyMaterial.establishedAt 
      : null;

    const torHealth = torNetworkManager.isSupported()
      ? torNetworkManager.getStats?.()?.circuitHealth ?? 'unknown'
      : 'unknown';

    return {
      state: this.lifecycleState,
      isHealthy: this.lifecycleState === 'connected' && this.missedHeartbeats < MAX_MISSED_HEARTBEATS,
      metrics: { ...this.metrics },
      queueDepth: this.pendingQueue.length,
      sessionAge,
      torStatus: {
        ready: this.torReady,
        circuitHealth: torHealth
      },
      lastHeartbeat: this.lastHeartbeatReceived,
      quality: this.assessConnectionQuality()
    };
  }


  /**
   * Attach Tor circuit rotation listener
   */
  private attachTorCircuitListener(): void {
    if (!torNetworkManager.isSupported() || this.torCircuitListener) {
      return;
    }

    // Listen for circuit rotations
    const checkCircuitRotation = () => {
      try {
        const stats = torNetworkManager.getStats?.();
        if (stats && stats.lastCircuitRotation) {
          if (this.lastTorCircuitRotation && 
              stats.lastCircuitRotation > this.lastTorCircuitRotation) {
            this.handleTorCircuitRotation();
          }
          this.lastTorCircuitRotation = stats.lastCircuitRotation;
        }
      } catch (_error) {
        
      }
    };

    this.torCircuitListener = checkCircuitRotation;
    
// Check periodically
    this.torCircuitInterval = setInterval(checkCircuitRotation, 10000);
  }

  /**
   * Handle Tor circuit rotation
   */
  private handleTorCircuitRotation(): void {
    SecurityAuditLogger.log('info', 'ws-tor-circuit-rotated', {
      timestamp: Date.now(),
      connectionState: this.lifecycleState
    });

    // Adapt reconnect strategy for Tor
    if (this.lifecycleState === 'connected') {
      this.missedHeartbeats = 0;
    }

    // Log for metrics
    this.lastTorCircuitRotation = Date.now();
  }

  /**
   * Adapt timeouts for Tor network conditions
   */
  private getTorAdaptedTimeout(baseTimeout: number): number {
    if (!torNetworkManager.isSupported() || !this.torReady) {
      return baseTimeout;
    }

    try {
      const stats = torNetworkManager.getStats?.();
      if (!stats) {
        return baseTimeout;
      }

      // Increase timeout based on circuit health
      let multiplier = 1.0;
      switch (stats.circuitHealth) {
        case 'poor':
          multiplier = 3.0;
          break;
        case 'degraded':
          multiplier = 2.0;
          break;
        case 'good':
          multiplier = 1.5;
          break;
        default:
          multiplier = 1.0;
      }

      // Also consider average latency
      if (stats.averageLatency > 1000) {
        multiplier *= 1.5;
      } else if (stats.averageLatency > 2000) {
        multiplier *= 2.0;
      }

      const adapted = Math.floor(baseTimeout * multiplier);
      
      SecurityAuditLogger.log('info', 'ws-tor-timeout-adapted', {
        base: baseTimeout,
        adapted,
        multiplier,
        circuitHealth: stats.circuitHealth,
        avgLatency: stats.averageLatency
      });

      return adapted;
      } catch (_error) {
        return baseTimeout;
      }
  }

  /**
   * Check if Tor circuit is healthy for WebSocket
   */
  private isTorCircuitHealthy(): boolean {
    if (!torNetworkManager.isSupported()) {
      return true;
    }

    try {
      const stats = torNetworkManager.getStats?.();
      if (!stats) {
        return false;
      }

      // Reject poor circuits
      if (stats.circuitHealth === 'poor') {
        SecurityAuditLogger.log('warn', 'ws-tor-circuit-unhealthy', {
          health: stats.circuitHealth,
          avgLatency: stats.averageLatency
        });
        return false;
      }

      return true;
    } catch (_error) {
      return false;
    }
  }

  private pruneReplayCache(): void {
    if (this.seenMessageFingerprints.size === 0) {
      return;
    }

    const now = Date.now();
    for (const [messageId, seenAt] of Array.from(this.seenMessageFingerprints.entries())) {
      if (now - seenAt > MAX_REPLAY_WINDOW_MS) {
        this.seenMessageFingerprints.delete(messageId);
      }
    }

    if (this.seenMessageFingerprints.size > REPLAY_CACHE_LIMIT) {
      const entries = Array.from(this.seenMessageFingerprints.entries()).sort((a, b) => a[1] - b[1]);
      while (this.seenMessageFingerprints.size > Math.floor(REPLAY_CACHE_LIMIT * 0.9) && entries.length > 0) {
        const [id] = entries.shift()!;
        this.seenMessageFingerprints.delete(id);
      }
    }
  }

  private handleConnectionError(error: Error, stage: string): void {
    SecureAuditLogger.error('ws', stage, 'failure', { message: error.message });
    this.metrics.lastFailureAt = Date.now();
    this.lifecycleState = 'error';
    this.resetSessionKeys(false);
    if (!this.isManualClose) {
      this.attemptReconnect();
    }
  }

  public resetSessionKeys(preserveServerKeys: boolean = true): void {
    this.tokenValidationAttempted = false;
    if (this.sessionKeyMaterial) {
      PostQuantumUtils.clearMemory(this.sessionKeyMaterial.sendKey);
      PostQuantumUtils.clearMemory(this.sessionKeyMaterial.recvKey);
    }
    this.sessionKeyMaterial = undefined;
    this.sessionNonceCounter = 0;
    this.expectedRemoteNonceCounter = 0;

    if (!preserveServerKeys) {
      this.serverKeyMaterial = undefined;
    }

    this.previousSessionFingerprint = undefined;
    this.sessionTransitionTime = undefined;

    if (this.sessionRekeyTimer) {
      clearTimeout(this.sessionRekeyTimer);
      this.sessionRekeyTimer = null;
    }
  }

  private clearSession(): void {
    this.resetSessionKeys(false);
    this.seenMessageFingerprints.clear();
    this.missedHeartbeats = 0;
    this.lastHeartbeatSent = null;
    this.lastHeartbeatReceived = null;
  }

  private attemptReconnect(): void {
    if (this.isManualClose) {
      return;
    }

    this.reconnectAttempts += 1;
    this.metrics.totalReconnects += 1;
    this.metrics.consecutiveFailures += 1;
    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);

    const jitterBytes = PostQuantumRandom.randomBytes(4);
    const jitterValue =
      (jitterBytes[0]! << 24) >>> 0 ^
      (jitterBytes[1]! << 16) ^
      (jitterBytes[2]! << 8) ^
      jitterBytes[3]!;
    const jitterMs = Math.floor((jitterValue / 0xffffffff) * 500);

    const delayWithJitter = this.reconnectDelayMs + jitterMs;
    SecureAuditLogger.info('ws', 'reconnect-scheduled', 'attempt', {
      attempt: this.reconnectAttempts,
      delay: delayWithJitter
    });

    setTimeout(() => {
      void this.connect().catch((error) => {
        this.handleConnectionError(error as Error, 'connect-retry');
      });
    }, delayWithJitter);
  }

  public send(data: unknown): void {
    const msgType = typeof data === 'string' ? (JSON.parse(data).type || 'unknown') : (data as any)?.type || 'unknown';
    void this.dispatchPayload(data, true).catch((error) => {
      SecureAuditLogger.error('ws', 'send', 'failed', { error: error instanceof Error ? error.message : String(error) });
    });
  }

  private async dispatchPayload(data: unknown, allowQueue: boolean): Promise<void> {
    const msgType = typeof data === 'string' ? (JSON.parse(data).type || 'unknown') : (data as any)?.type || 'unknown';
    
    const needsBypassEncryption = this.shouldBypassEncryption(data);
    
    if (needsBypassEncryption) {
      const message = typeof data === 'string' ? data : JSON.stringify(data);
      this.metrics.messagesSent += 1;
      this.metrics.bytesSent += message.length;
      this.resetCircuitBreaker();
      await this.transmit(message);
      return;
    }
    
    // Check circuit breaker
    if (!this.checkCircuitBreaker()) {
      if (allowQueue) {
        this.enqueuePending({
          id: uuidv4(),
          payload: data,
          createdAt: Date.now(),
          attempt: 0,
          flushAfter: Date.now() + (this.circuitBreakerOpenUntil - Date.now())
        });
      }
      return;
    }

    // Check per-connection rate limit
    if (!this.checkRateLimit()) {
      if (allowQueue) {
        this.enqueuePending({
          id: uuidv4(),
          payload: data,
          createdAt: Date.now(),
          attempt: 0,
          flushAfter: Date.now() + RATE_LIMIT_BACKOFF_MS
        });
      }
      return;
    }

    if (this.isGloballyRateLimited()) {
      SecureAuditLogger.warn('ws', 'send', 'rate-limited', { queued: allowQueue });
      if (allowQueue) {
        this.enqueuePending({
          id: uuidv4(),
          payload: data,
          createdAt: Date.now(),
          attempt: 0,
          flushAfter: this.globalRateLimitUntil
        });
      }
      return;
    }

    if (this.lifecycleState !== 'connected') {
      if (allowQueue) {
        this.enqueuePending({
          id: uuidv4(),
          payload: data,
          createdAt: Date.now(),
          attempt: 0,
          flushAfter: Date.now()
        });
      } else {
        throw new Error('WebSocket not connected');
      }
      return;
    }

    // Check Tor circuit health
    if (!this.isTorCircuitHealthy()) {
      SecurityAuditLogger.log('warn', 'ws-send-tor-unhealthy', {});
      if (allowQueue) {
        this.enqueuePending({
          id: uuidv4(),
          payload: data,
          createdAt: Date.now(),
          attempt: 0,
          flushAfter: Date.now() + 5000
        });
      }
      return;
    }

    await this.ensureSessionKeys(false);

    const message = await this.prepareSecureEnvelope(data);
    
    // Update metrics
    this.metrics.messagesSent += 1;
    this.metrics.bytesSent += message.length;
    
    // Reset circuit breaker on successful send
    this.resetCircuitBreaker();
    
    await this.transmit(message);
  }

  private shouldBypassEncryption(data: unknown): boolean {
    if (!data) {
      return false;
    }
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data;
      const type = (parsed as any)?.type;
      void type;
    } catch {
    }

    return false;
  }

  private enqueuePending(entry: PendingSend): void {
    if (this.pendingQueue.length >= MAX_PENDING_QUEUE) {
      const dropped = this.pendingQueue.shift();
      SecureAuditLogger.warn('ws', 'queue', 'drop', {
        reason: 'capacity',
        droppedId: dropped?.id,
        queueSize: this.pendingQueue.length
      });
    }

    this.pendingQueue.push(entry);
    this.pendingQueue.sort((a, b) => a.flushAfter - b.flushAfter);
    this.scheduleQueueFlush();
  }

  private scheduleQueueFlush(delayMs?: number): void {
    if (this.flushTimer || this.pendingQueue.length === 0) {
      return;
    }

    const now = Date.now();
    const nextDue = Math.max(0, this.pendingQueue[0].flushAfter - now);
    const effectiveDelay = delayMs !== undefined ? delayMs : Math.min(QUEUE_FLUSH_INTERVAL_MS, nextDue);

    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flushPendingQueue();
    }, effectiveDelay);
  }

  public async flushPendingQueue(): Promise<void> {
    if (this.flushInFlight || this.pendingQueue.length === 0) {
      return;
    }

    if (this.lifecycleState !== 'connected') {
      this.scheduleQueueFlush();
      return;
    }

    this.flushInFlight = true;

    try {
      while (this.pendingQueue.length > 0) {
        const entry = this.pendingQueue[0];
        if (entry.flushAfter > Date.now()) {
          this.scheduleQueueFlush(entry.flushAfter - Date.now());
          break;
        }

        this.pendingQueue.shift();

        try {
          await this.dispatchPayload(entry.payload, false);
          SecureAuditLogger.info('ws', 'queue', 'flushed', {
            entryId: entry.id,
            attempts: entry.attempt
          });
        } catch (_error) {
          entry.attempt += 1;
          if (entry.attempt >= 3) {
            SecureAuditLogger.error('ws', 'queue', 'dropped', {
              entryId: entry.id,
              error: _error instanceof Error ? _error.message : String(_error)
            });
          } else {
            entry.flushAfter = Date.now() + RATE_LIMIT_BACKOFF_MS * entry.attempt;
            this.pendingQueue.unshift(entry);
            this.scheduleQueueFlush(entry.flushAfter - Date.now());
          }
          break;
        }
      }
    } finally {
      this.flushInFlight = false;
      if (this.pendingQueue.length > 0 && this.lifecycleState === 'connected') {
        this.scheduleQueueFlush();
      }
    }
  }

  private async ensureSessionKeys(force: boolean): Promise<void> {
    if (!force && this.sessionKeyMaterial) {
      const age = Date.now() - this.sessionKeyMaterial.establishedAt;
      if (age < SESSION_REKEY_INTERVAL_MS) {
        if (age > KEY_ROTATION_WARNING_MS) {
          SecureAuditLogger.warn('ws', 'handshake', 'aging-session', { age });
        }
        return;
      }
    }

    await this.performHandshake(force);
  }

  public async performHandshake(force: boolean): Promise<void> {
    if (!force && this.handshakeInFlight) {
      return;
    }

    let serverMaterial = this.serverKeyMaterial;
    
    if (!serverMaterial) {
      const startTime = Date.now();
      const timeout = 10000;
      let requested = false;
      
      while (!serverMaterial && (Date.now() - startTime) < timeout) {
        if (!requested && (Date.now() - startTime) > 500) {
          try {
            await this.transmit(JSON.stringify({ type: 'request-server-public-key' }));
            SecureAuditLogger.info('ws', 'handshake', 'requested-server-keys', {});
          } catch {}
          requested = true;
        }
        await new Promise(resolve => setTimeout(resolve, 100));
        serverMaterial = this.serverKeyMaterial;
      }
      
      if (!serverMaterial) {
        throw new Error('Server key material unavailable (timeout)');
      }
    }
    
    this.serverKeyMaterial = serverMaterial;

    if (this.handshakeInFlight) {
      return;
    }

    this.handshakeInFlight = true;
    this.handshakePromise = (async () => {
      this.resetSessionKeys(true);

      const sessionId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
      const handshakeNonce = PostQuantumRandom.randomBytes(32);
      const timestamp = Date.now();
      const { ciphertext: kemCiphertext, sharedSecret: pqSharedSecret } = PostQuantumKEM.encapsulate(serverMaterial.kyberPublicKey);

      // Generate ephemeral X25519 keypair for classical ECDH
      if (!serverMaterial.x25519PublicKey) {
        throw new Error('Server X25519 public key not available for hybrid WS handshake');
      }
      const ephemeral = this.generateEphemeralX25519();
      const classicalShared = this.computeClassicalSharedSecret(ephemeral.secretKey, serverMaterial.x25519PublicKey);

      let sendKey: Uint8Array | undefined;
      let recvKey: Uint8Array | undefined;
      try {
        const encoder = new TextEncoder();
        const baseInfo = `${serverMaterial.fingerprint}:${sessionId}`;
        const sendSalt = encoder.encode(`${baseInfo}:send-${timestamp}`);
        const recvSalt = encoder.encode(`${baseInfo}:recv-${timestamp}`);

        // XOR pqSharedSecret with classicalShared
        const combined = new Uint8Array(pqSharedSecret.length);
        for (let i = 0; i < pqSharedSecret.length; i++) {
          combined[i] = pqSharedSecret[i] ^ classicalShared[i % classicalShared.length];
        }

        sendKey = PostQuantumHash.deriveKey(combined, sendSalt, 'ws-pq-hybrid-send', 32);
        recvKey = PostQuantumHash.deriveKey(combined, recvSalt, 'ws-pq-hybrid-recv', 32);

        combined.fill(0);
      } finally {
        PostQuantumUtils.clearMemory(pqSharedSecret);
        PostQuantumUtils.clearMemory(classicalShared);
        PostQuantumUtils.clearMemory(ephemeral.secretKey);
      }

      const pendingSession = {
        sessionId,
        sendKey: sendKey!,
        recvKey: recvKey!,
        establishedAt: timestamp,
        fingerprint: serverMaterial.fingerprint
      };
      
      // Store server's Dilithium public key for signature verification
      this.serverSignatureKey = serverMaterial.dilithiumPublicKey;

      const handshakeMessage = {
        type: 'pq-handshake-init',
        payload: {
          version: 'pq-ws-1',
          sessionId,
          timestamp,
          clientNonce: PostQuantumUtils.uint8ArrayToBase64(handshakeNonce),
          kemCiphertext: PostQuantumUtils.uint8ArrayToBase64(kemCiphertext),
          clientX25519PublicKey: PostQuantumUtils.uint8ArrayToBase64(ephemeral.publicKey),
          fingerprint: serverMaterial.fingerprint,
          capabilities: {
            queueSize: this.pendingQueue.length,
            chunkingEnabled: false
          }
        }
      };

      const ackPromise = new Promise<void>((resolve, reject) => {
        const timeoutDuration = this.getTorAdaptedTimeout(15000);
        const timeout = setTimeout(() => {
          this.unregisterMessageHandler('pq-handshake-ack');
          SecureAuditLogger.error('ws', 'handshake', 'ack-timeout', {
            sessionId: sessionId.slice(0, 16),
            timeoutMs: timeoutDuration,
            handlerRegistered: this.messageHandlers.has('pq-handshake-ack')
          });
          reject(new Error('Handshake acknowledgment timeout'));
        }, timeoutDuration);

        const handleAck = (msg: any) => {
          SecureAuditLogger.info('ws', 'handshake', 'ack-received', {
            receivedSessionId: msg.sessionId?.slice(0, 16),
            expectedSessionId: sessionId.slice(0, 16),
            matches: msg.sessionId === sessionId,
            messageType: msg.type
          });
          
          if (msg.sessionId === sessionId) {
            clearTimeout(timeout);
            this.unregisterMessageHandler('pq-handshake-ack');
            
            if (this.sessionKeyMaterial?.fingerprint && 
                this.sessionKeyMaterial.fingerprint !== pendingSession.fingerprint) {
              this.previousSessionFingerprint = this.sessionKeyMaterial.fingerprint;
              this.sessionTransitionTime = Date.now();
            }
            
            this.sessionKeyMaterial = pendingSession;
            this.sessionNonceCounter = 0;
            
            SecureAuditLogger.info('ws', 'handshake', 'acknowledged', {
              sessionId: sessionId.slice(0, 16)
            });

            resolve();
          } else {
            SecureAuditLogger.warn('ws', 'handshake', 'ack-session-mismatch', {
              receivedSessionId: msg.sessionId?.slice(0, 16),
              expectedSessionId: sessionId.slice(0, 16)
            });
          }
        };

        this.registerMessageHandler('pq-handshake-ack', handleAck);
        SecureAuditLogger.info('ws', 'handshake', 'ack-handler-registered', {
          sessionId: sessionId.slice(0, 16)
        });
      });
      
      await this.transmit(JSON.stringify(handshakeMessage));
      SecureAuditLogger.info('ws', 'handshake', 'sent', {
        sessionId: sessionId.slice(0, 8),
        fingerprint: serverMaterial.fingerprint.slice(0, 8)
      });

      await ackPromise;

      this.handshakeAttempts = 0;
      this.seenMessageFingerprints.clear();
      this.scheduleRekey();
      
      try { 
        void this.attemptTokenValidationOnce('pq-handshake-complete'); 
      } catch (tokenError) {
        SecureAuditLogger.warn('ws', 'handshake', 'token-validation-error', {
          error: tokenError instanceof Error ? tokenError.message : String(tokenError)
        });
      }
    })()
      .catch((error) => {
        this.handshakeAttempts += 1;
        handleNetworkError(error as Error, { context: 'pq-handshake', attempts: this.handshakeAttempts });
        this.resetSessionKeys();
        if (this.handshakeAttempts >= MAX_HANDSHAKE_ATTEMPTS) {
          handleCriticalError(error as Error, { context: 'pq-handshake-max' });
        }
        throw error;
      })
      .finally(() => {
        this.handshakeInFlight = false;
      });

    await this.handshakePromise;

    if (this.lifecycleState !== 'connected') {
      this.lifecycleState = 'connected';
      this.startHeartbeat();
      void this.flushPendingQueue();
    }
  }

  private scheduleRekey(): void {
    if (this.sessionRekeyTimer) {
      clearTimeout(this.sessionRekeyTimer);
    }

    this.sessionRekeyTimer = setTimeout(() => {
      void this.performHandshake(true).catch((error) => {
        this.handleConnectionError(error as Error, 'handshake-rekey');
      });
    }, SESSION_REKEY_INTERVAL_MS);
  }

  private computeServerFingerprint(keys: { kyber: string; dilithium: string; x25519: string }): string {
    const encoded = JSON.stringify({
      kyberPublicBase64: keys.kyber,
      dilithiumPublicBase64: keys.dilithium,
      x25519PublicBase64: keys.x25519
    });
    const digest = PostQuantumHash.blake3(new TextEncoder().encode(encoded));
    return PostQuantumUtils.bytesToHex(digest);
  }

  private normalizePayload(data: unknown): { type: string; body: any } {
    if (data && typeof data === 'object') {
      const body = this.sanitize(data);
      const type = typeof body.type === 'string' ? String(body.type) : 'generic';
      if (typeof body.type !== 'string') {
        body.type = type;
      }
      return { type, body };
    }

    if (typeof data === 'string') {
      try {
        const parsed = JSON.parse(data);
        if (parsed && typeof parsed === 'object') {
          const body = this.sanitize(parsed);
          const type = typeof body.type === 'string' ? String(body.type) : 'raw-string';
          if (typeof body.type !== 'string') {
            body.type = type;
          }
          return { type, body };
        }
      } catch {
      }
      return { type: 'raw-string', body: { type: 'raw-string', data } };
    }

    return { type: 'raw-scalar', body: { type: 'raw-scalar', data: String(data) } };
  }

  private sanitize(input: any): any {
    try {
      return JSON.parse(JSON.stringify(input));
    } catch {
      return { type: 'raw-string', data: String(input) };
    }
  }

  private buildEnvelopeAAD(type: string, messageId: string, timestamp: number, counter: number): Uint8Array {
    const encoder = new TextEncoder();
    const parts = `${type}|${messageId}|${timestamp}|${counter}`;
    const bytes = encoder.encode(parts);
    if (bytes.length <= MAX_MESSAGE_AAD_LENGTH) {
      return bytes;
    }
    return bytes.slice(0, MAX_MESSAGE_AAD_LENGTH);
  }

  private async prepareSecureEnvelope(data: unknown): Promise<string> {
    if (!this.sessionKeyMaterial) {
      throw new Error('Post-quantum session not established');
    }

    const canonical = this.normalizePayload(data);
    const messageId = PostQuantumUtils.bytesToHex(PostQuantumRandom.randomBytes(16));
    const timestamp = Date.now();
    const counter = ++this.sessionNonceCounter;

    if (typeof canonical.body.type !== 'string') {
      canonical.body.type = canonical.type;
    }

    const isEncryptedMessage = canonical.type === 'encrypted-message';
    let payloadToEncrypt: any;
    
    if (isEncryptedMessage && canonical.body.to && canonical.body.encryptedPayload) {
      payloadToEncrypt = {
        to: canonical.body.to,
        encryptedPayload: canonical.body.encryptedPayload
      };
    } else {
      payloadToEncrypt = canonical.body;
    }

    const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadToEncrypt));
    const nonce = PostQuantumRandom.randomBytes(36);
    const aadBytes = this.buildEnvelopeAAD(canonical.type, messageId, timestamp, counter);

    const { ciphertext, tag } = PostQuantumAEAD.encrypt(
      payloadBytes,
      this.sessionKeyMaterial.sendKey,
      aadBytes,
      nonce
    );

    PostQuantumUtils.clearMemory(payloadBytes);

    const envelope = {
      type: 'pq-envelope',
      version: 'pq-ws-1',
      sessionId: this.sessionKeyMaterial.sessionId,
      sessionFingerprint: this.sessionKeyMaterial.fingerprint,
      messageId,
      counter,
      timestamp,
      nonce: PostQuantumUtils.uint8ArrayToBase64(nonce),
      ciphertext: PostQuantumUtils.uint8ArrayToBase64(ciphertext),
      tag: PostQuantumUtils.uint8ArrayToBase64(tag),
      aad: PostQuantumUtils.uint8ArrayToBase64(aadBytes)
    };

    // Add message signature
    const signature = await this.signMessage(envelope);
    if (signature) {
      (envelope as any).signature = signature;
    }

    return JSON.stringify(envelope);
  }

  public async decryptIncomingEnvelope(envelope: any): Promise<any | null> {
    return this.decryptEnvelope(envelope);
  }

  private async decryptEnvelope(envelope: any): Promise<any | null> {
    if (!this.sessionKeyMaterial) {
      SecureAuditLogger.warn('ws', 'decrypt', 'no-session');
      return null;
    }

    const currentFingerprint = this.sessionKeyMaterial.fingerprint;
    const receivedFingerprint = envelope.sessionFingerprint;
    
    if (receivedFingerprint !== currentFingerprint) {
      const now = Date.now();
      const isWithinGracePeriod = this.previousSessionFingerprint && 
                                  this.sessionTransitionTime &&
                                  (now - this.sessionTransitionTime) < SESSION_FAILOVER_GRACE_PERIOD_MS;
      
      if (isWithinGracePeriod && receivedFingerprint === this.previousSessionFingerprint) {
        if (!this.validateTimestamp(envelope.timestamp)) {
          this.recordCircuitBreakerFailure();
          return null;
        }
        SecureAuditLogger.info('ws', 'decrypt', 'old-session-stale-drop', {
          timeSinceTransition: now - (this.sessionTransitionTime || 0)
        });
        return null;
      }
      
      this.metrics.securityEvents.fingerprintMismatches += 1;
      SecureAuditLogger.warn('ws', 'decrypt', 'fingerprint-mismatch', {
        expected: currentFingerprint,
        received: receivedFingerprint,
        hadPreviousSession: !!this.previousSessionFingerprint,
        gracePeriodExpired: !isWithinGracePeriod
      });
      this.recordCircuitBreakerFailure();
      return null;
    }

    const messageId = typeof envelope.messageId === 'string' ? envelope.messageId : '';
    if (!messageId) {
      SecureAuditLogger.warn('ws', 'decrypt', 'missing-message-id');
      return null;
    }

    if (!this.validateTimestamp(envelope.timestamp)) {
      return null;
    }

    const signatureValid = await this.verifyMessageSignature(envelope);
    if (!signatureValid) {
      return null;
    }

    if (typeof envelope.counter === 'number' && !this.validateNonceSequence(envelope.counter)) {
      return null;
    }

    if (this.hasSeenMessage(messageId, envelope.timestamp)) {
      this.metrics.securityEvents.replayAttempts += 1;
      SecureAuditLogger.warn('ws', 'decrypt', 'replay', { messageId });
      return null;
    }

    try {
      const nonce = PostQuantumUtils.base64ToUint8Array(envelope.nonce);
      const ciphertext = PostQuantumUtils.base64ToUint8Array(envelope.ciphertext);
      const tag = PostQuantumUtils.base64ToUint8Array(envelope.tag);
      const aadBytes = envelope.aad ? PostQuantumUtils.base64ToUint8Array(envelope.aad) : new Uint8Array();

      const decrypted = PostQuantumAEAD.decrypt(
        ciphertext,
        nonce,
        tag,
        this.sessionKeyMaterial.recvKey,
        aadBytes
      );

      const decodedText = new TextDecoder().decode(decrypted);
      const canonical = JSON.parse(decodedText);

      try {
        const innerType = typeof (canonical as any)?.type === 'string' ? (canonical as any).type : '';
        if (innerType === SignalType.ENCRYPTED_MESSAGE || innerType === 'encrypted-message') {
          const env: any = (canonical as any)?.encryptedPayload || {};
          const hasChunk = typeof env?.chunkData === 'string' && env.chunkData.length > 0;
          const len = hasChunk ? env.chunkData.length : 0;
        }
      } catch {}

      this.trackMessageFingerprint(messageId, envelope.timestamp ?? Date.now());

      this.metrics.messagesReceived += 1;
      this.metrics.bytesReceived += ciphertext.length;

      if (canonical?.data && typeof canonical.data === 'object' && canonical.type) {
        return canonical.data;
      }

      return canonical;
    } catch (_error) {
      SecureAuditLogger.error('ws', 'decrypt', 'failed', {
        error: _error instanceof Error ? _error.message : String(_error)
      });
      this.recordCircuitBreakerFailure();
      return null;
    }
  }

  private hasSeenMessage(messageId: string, timestamp: number): boolean {
    const seenAt = this.seenMessageFingerprints.get(messageId);
    if (seenAt === undefined) {
      return false;
    }
    if (Math.abs(seenAt - timestamp) <= MAX_REPLAY_WINDOW_MS) {
      return true;
    }
    return false;
  }

  private trackMessageFingerprint(messageId: string, timestamp: number): void {
    this.seenMessageFingerprints.set(messageId, timestamp);
    this.pruneReplayCache();
  }

  private async transmit(message: string): Promise<void> {
    const edgeApi = (window as any).edgeApi as { wsSend?: (payload: string) => Promise<any> } | undefined;
    
    if (!edgeApi?.wsSend) {
      throw new Error('edgeApi.wsSend not available');
    }

    const result = await edgeApi.wsSend(message);
    
    if (result && result.success === false) {
      throw new Error(result.error || 'Failed to dispatch websocket payload');
    }
  }

  public setGlobalRateLimit(seconds: number) {
    const ms = Math.max(0, Math.floor(seconds * 1000));
    const until = Date.now() + ms;
    this.globalRateLimitUntil = Math.max(this.globalRateLimitUntil, until);
    if (seconds > 0) {
      this.metrics.lastRateLimitAt = Date.now();
      SecureAuditLogger.warn('ws', 'global-rate-limit', 'entered', { seconds });
    }
  }

  public isGloballyRateLimited(): boolean {
    return Date.now() < this.globalRateLimitUntil;
  }

  public registerMessageHandler(type: string, handler: MessageHandler): void {
    this.messageHandlers.set(type, handler);
  }

  public unregisterMessageHandler(type: string): void {
    this.messageHandlers.delete(type);
  }

  private async handleMessage(data: unknown): Promise<void> {
    try {
      if (data === null || data === undefined) {
        return;
      }

      let message: any;
      
      if (typeof data === 'object' && data !== null) {
        message = data;
      } else {
        const dataString = String(data);
        try {
          message = JSON.parse(dataString);
        } catch {
          message = { type: 'raw', data: dataString };
        }
      }

      if (typeof message === 'object' && message?.type === 'pq-heartbeat-pong') {
        this.handleHeartbeatResponse(message);
        return;
      }

      if (typeof message === 'object' && message?.type === 'pq-envelope') {
        const decrypted = await this.decryptEnvelope(message);
        if (!decrypted) {
          return;
        }
        message = decrypted;
      }

      if (typeof message !== 'object' || message === null) {
        return;
      }

      if (typeof message.type === 'string') {
        if (message.type.length > 100) {
          return;
        }

        const handler = this.messageHandlers.get(message.type);
        if (handler) {
          try {
            handler(message);
          } catch (handlerError) {
            
          }
          return;
        }
      }

      const rawHandler = this.messageHandlers.get('raw');
      if (rawHandler) {
        try {
          rawHandler(message);
        } catch (handlerError) {}
      }
    } catch (_error) {
      
    }
  }

  public async attemptTokenValidationOnce(source: string = 'auto'): Promise<void> {
    if (this.tokenValidationAttempted) {
      try { SecureAuditLogger.info('auth', 'token-validate', 'skip-already-attempted', { source }); } catch {}
      return;
    }
    this.tokenValidationAttempted = true;
    try {
      const api = (window as any).electronAPI;
      if (!api?.secureStore) {
        try { SecureAuditLogger.warn('auth', 'token-validate', 'secure-store-missing', { source }); } catch {}
        return;
      }
      try { await api.secureStore.init?.(); } catch { try { SecureAuditLogger.warn('auth', 'token-validate', 'secure-store-init-failed', { source }); } catch {} }
      const inst = api?.instanceId ? String(api.instanceId) : '1';
      try { SecureAuditLogger.info('auth', 'token-validate', 'lookup', { slot: `tok:${inst}`, instanceId: inst, source }); } catch {}
      const raw = await api.secureStore.get?.(`tok:${inst}`);
      if (!raw || typeof raw !== 'string') {
        try { SecureAuditLogger.warn('auth', 'token-validate', 'no-tokens', { slot: `tok:${inst}`, instanceId: inst, source }); } catch {}
        return;
      }
      let parsed: any;
      try { parsed = JSON.parse(raw); } catch {
      try { SecureAuditLogger.warn('auth', 'token-validate', 'parse-failed', { source }); } catch {}
        return;
      }
      const accessToken = typeof parsed?.a === 'string' ? parsed.a : '';
      const refreshToken = typeof parsed?.r === 'string' ? parsed.r : '';
      if (!accessToken || !refreshToken) {
        try { SecureAuditLogger.warn('auth', 'token-validate', 'tokens-incomplete', { hasA: !!accessToken, hasR: !!refreshToken, source }); } catch {}
        return;
      }
      try {
        window.dispatchEvent(new CustomEvent('token-validation-start', { detail: { source } }));
        SecureAuditLogger.info('auth', 'token-validate', 'sending', { source });
      } catch {}
      await this.sendSecureControlMessage({
        type: SignalType.TOKEN_VALIDATION,
        accessToken,
        refreshToken,
      });
      try { SecureAuditLogger.info('auth', 'token-validate', 'sent', { source }); } catch {}
    } catch (e) {
      try { SecureAuditLogger.error('auth', 'token-validate', 'failed', { source, error: e instanceof Error ? e.message : String(e) }); } catch {}
    }
  }

  public close(): void {
    this.isManualClose = true;
    this.lifecycleState = 'idle';
    this.messageHandlers.clear();
    this.setLoginError = undefined;
    this.globalRateLimitUntil = 0;

    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }

    this.pendingQueue = [];
    this.flushInFlight = false;
    this.clearSession();
    this.stopConnectivityWatchdog();
    this.stopHeartbeat();

    // Clear Tor circuit interval if any
    if (this.torCircuitInterval) {
      clearInterval(this.torCircuitInterval);
      this.torCircuitInterval = undefined;
    }

    // Reset rate limiting
    this.resetRateLimit();

    // Reset circuit breaker
    this.circuitBreakerFailures = 0;
    this.circuitBreakerOpenUntil = 0;

    // Clear connection state callbacks
    this.connectionStateCallbacks.clear();

    if (this.torListener) {
      try {
        torNetworkManager.offConnectionChange(this.torListener);
      } catch {}
      this.torListener = undefined;
    }

    SecurityAuditLogger.log('info', 'ws-close', {
      messagesSent: this.metrics.messagesSent,
      messagesReceived: this.metrics.messagesReceived,
      securityEvents: this.metrics.securityEvents
    });
  }

  public isConnectedToServer(): boolean {
    return this.lifecycleState === 'connected';
  }

  public isPQSessionEstablished(): boolean {
    return !!this.sessionKeyMaterial;
  }

  /**
   * Send a control message securely through PQ envelope
   */
  public async sendSecureControlMessage(message: any): Promise<void> {
    if (!this.isPQSessionEstablished()) {
      SecureAuditLogger.warn('ws', 'control-message', 'waiting-for-pq-session', { 
        messageType: message?.type 
      });
      
      if (this.lifecycleState !== 'connected') {
        this.enqueuePending({
          id: uuidv4(),
          payload: message,
          createdAt: Date.now(),
          attempt: 0,
          flushAfter: Date.now(),
          highPriority: true
        });
        return;
      }
      
      const maxWaitTime = 10000; // 10 seconds
      const startTime = Date.now();
      while (!this.isPQSessionEstablished() && (Date.now() - startTime) < maxWaitTime) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      if (!this.isPQSessionEstablished()) {
        throw new Error('PQ session not established - cannot send control message securely');
      }
    }
    
    // Ensure message is properly formatted
    const payload = typeof message === 'string' ? message : JSON.stringify(message);
    
    SecureAuditLogger.info('ws', 'control-message', 'sending-pq-encrypted', { 
      messageType: message?.type || 'unknown' 
    });
    
    // Send via PQ envelope
    await this.dispatchPayload(payload, true);
  }

  /**
   * Set server key material when received via WebSocket
   */
  public setServerKeyMaterial(hybridKeys: {
    kyberPublicBase64: string;
    dilithiumPublicBase64?: string;
    x25519PublicBase64?: string;
  }, serverId?: string): void {
    try {
      const kyberPublicKey = PostQuantumUtils.base64ToUint8Array(hybridKeys.kyberPublicBase64);
      const dilithiumPublicKey = 
        hybridKeys.dilithiumPublicBase64 
          ? PostQuantumUtils.base64ToUint8Array(hybridKeys.dilithiumPublicBase64)
          : undefined;
      const x25519PublicKey =
        hybridKeys.x25519PublicBase64
          ? PostQuantumUtils.base64ToUint8Array(hybridKeys.x25519PublicBase64)
          : undefined;
      
      const fingerprint = this.computeServerFingerprint({
        kyber: hybridKeys.kyberPublicBase64,
        dilithium: hybridKeys.dilithiumPublicBase64 || '',
        x25519: hybridKeys.x25519PublicBase64 || ''
      });

      this.serverKeyMaterial = {
        kyberPublicKey,
        dilithiumPublicKey,
        x25519PublicKey,
        fingerprint,
        serverId
      };

      SecureAuditLogger.info('ws', 'server-keys', 'updated', {
        serverId: serverId?.substring(0, 16) + '...',
        fingerprintPrefix: fingerprint.slice(0, 16)
      });
    } catch (_error) {
      console.error('[WS] setServerKeyMaterial failed:', _error);
      SecureAuditLogger.error('ws', 'server-keys', 'update-failed', {
        error: _error instanceof Error ? _error.message : 'Unknown error'
      });
    }
  }
}

const websocketClient = new WebSocketClient();
export default websocketClient;