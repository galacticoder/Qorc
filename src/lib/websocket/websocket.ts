/**
 * WebSocket Connection Manager
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumRandom } from '../cryptography/random';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { blockingSystem } from '../blocking/blocking-system';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import type { ConnectionMetrics, ConnectionHealth, MessageHandler, SessionKeyMaterial } from '../types/websocket-types';
import {
  INITIAL_RECONNECT_DELAY_MS,
  MAX_RECONNECT_DELAY_MS,
  RATE_LIMIT_BACKOFF_MS,
  SESSION_REKEY_INTERVAL_MS,
  KEY_ROTATION_WARNING_MS,
  MAX_MISSED_HEARTBEATS,
} from '../constants';

import { WebSocketRateLimiter } from './rate-limiter';
import { WebSocketCircuitBreaker } from './circuit-breaker';
import { WebSocketHeartbeat } from './heartbeat';
import { WebSocketTorIntegration } from './tor-integration';
import { WebSocketQueue } from './queue';
import { WebSocketEncryption } from './encryption';
import { WebSocketHandshake } from './handshake';
import { WebSocketMessageHandler } from './message-handler';

// WebSocket Connection Manager
export class WebSocketConnection {
  lifecycleState: string = 'idle';
  private isManualClose = false;
  private reconnectAttempts = 0;
  private reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
  private globalRateLimitUntil = 0;
  private tokenValidationAttempted = false;
  private _username?: string;
  private connectivityWatchdog?: ReturnType<typeof setInterval>;

  // Connection metrics
  metrics: ConnectionMetrics = {
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

  private connectionStateCallbacks = new Set<(health: ConnectionHealth) => void>();
  
  // Session key material
  sessionKeyMaterial?: SessionKeyMaterial;
  private previousSessionFingerprint?: string;
  private sessionTransitionTime?: number;
  signingKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };

  rateLimiter: WebSocketRateLimiter;
  circuitBreaker: WebSocketCircuitBreaker;
  heartbeat: WebSocketHeartbeat;
  torIntegration: WebSocketTorIntegration;
  queue: WebSocketQueue;
  encryption: WebSocketEncryption;
  handshake: WebSocketHandshake;
  messageHandler: WebSocketMessageHandler;

  constructor() {
    this.rateLimiter = new WebSocketRateLimiter(this.metrics);
    this.circuitBreaker = new WebSocketCircuitBreaker();

    this.heartbeat = new WebSocketHeartbeat(this.metrics, {
      onSendHeartbeat: () => this.sendHeartbeatMessage(),
      onConnectionLost: (error) => this.handleConnectionError(error, 'heartbeat-timeout'),
      onRehandshakeNeeded: () => { void this.performHandshake(true); },
      getLifecycleState: () => this.lifecycleState,
      getSessionId: () => this.sessionKeyMaterial?.sessionId
    });

    this.torIntegration = new WebSocketTorIntegration(() => {
      if (this.lifecycleState === 'connected') {
        this.lifecycleState = 'paused';
      }
    });

    this.queue = new WebSocketQueue(
      (data, allowQueue) => this.dispatchPayload(data, allowQueue),
      () => this.lifecycleState
    );

    const self = this;
    this.encryption = new WebSocketEncryption(
      {
        get sessionKeyMaterial() { return self.sessionKeyMaterial; },
        get previousSessionFingerprint() { return self.previousSessionFingerprint; },
        get sessionTransitionTime() { return self.sessionTransitionTime; },
        get serverSignatureKey() { return self.handshake.getServerKeyMaterial()?.dilithiumPublicKey; },
        get signingKeyPair() { return self.signingKeyPair; }
      },
      this.metrics,
      () => this.circuitBreaker.recordFailure()
    );

    this.handshake = new WebSocketHandshake({
      transmit: (msg) => this.transmit(msg),
      registerMessageHandler: (type, handler) => this.messageHandler.registerHandler(type, handler),
      unregisterMessageHandler: (type) => this.messageHandler.unregisterHandler(type),
      getQueueLength: () => this.queue.getQueueLength(),
      getTorAdaptedTimeout: (timeout) => this.torIntegration.getAdaptedTimeout(timeout),
      onSessionEstablished: (session, serverSigKey) => this.onSessionEstablished(session, serverSigKey),
      onHandshakeError: (error) => this.handleConnectionError(error, 'handshake')
    });

    this.messageHandler = new WebSocketMessageHandler({
      decryptEnvelope: (env) => this.encryption.decryptEnvelope(env),
      handleHeartbeatResponse: (msg) => this.heartbeat.handleResponse(msg)
    });

    void this.initializeSigningKeys();
  }

  // Initialize signing keys
  private async initializeSigningKeys(): Promise<void> {
    const keys = await this.handshake.initializeSigningKeys();
    if (keys) {
      this.signingKeyPair = keys;
    }
  }

  // Handle session established
  private onSessionEstablished(session: SessionKeyMaterial, _serverSignatureKey?: Uint8Array): void {
    if (this.sessionKeyMaterial?.fingerprint &&
      this.sessionKeyMaterial.fingerprint !== session.fingerprint) {
      this.previousSessionFingerprint = this.sessionKeyMaterial.fingerprint;
      this.sessionTransitionTime = Date.now();
    }

    this.sessionKeyMaterial = session;
    this.encryption.resetCounters();
    this.encryption.clearReplayCache();
  }

  // Set and get username
  setUsername(username: string) { this._username = username; }
  getUsername(): string | undefined { return this._username; }

  // Handle edge server message
  handleEdgeServerMessage(message: any): boolean {
    if (!isPlainObject(message) || hasPrototypePollutionKeys(message)) {
      return false;
    }

    const messageType = typeof message.type === 'string' ? message.type : '';

    if (messageType === '__ws_connection_closed') {
      this.resetSessionKeys(false);
      this.lifecycleState = 'disconnected';
      return true;
    }

    if (messageType === '__ws_connection_error') {
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-connection-error-from-electron', { error: message.error });
      this.resetSessionKeys(false);
      this.lifecycleState = SignalType.ERROR;
      return true;
    }

    if (messageType === '__ws_connection_opened') {
      this.handleConnectionOpened();
      return true;
    }

    if (messageType === 'pq-heartbeat-pong' || this.messageHandler.hasHandler(messageType)) {
      void this.messageHandler.handleMessage(message);
      return true;
    }

    return false;
  }

  // Handle connection opened
  private handleConnectionOpened(): void {
    const wasConnectedBefore = this.lifecycleState !== 'idle' || this.sessionKeyMaterial != null;

    if (this.lifecycleState === 'disconnected' || this.lifecycleState === SignalType.ERROR || this.lifecycleState === 'idle') {
      (async () => {
        try {
          const api = (window as any).edgeApi;
          const pqKeysResult = await api?.getPQSessionKeys?.();
          if (pqKeysResult?.success && pqKeysResult.keys && this.importSessionKeys(pqKeysResult.keys)) {
            await api?.clearPQSessionKeys?.();
            this.heartbeat.start();
            void this.queue.flush();
            window.dispatchEvent(new CustomEvent(EventType.WS_RECONNECTED, { detail: { timestamp: Date.now(), restoredFromBackground: true } }));
            return;
          }
        } catch { }

        this.lifecycleState = 'handshaking';
        this.performHandshake(false)
          .then(async () => {
            this.lifecycleState = 'connected';
            this.heartbeat.start();
            void this.queue.flush();
            void blockingSystem.processQueuedMessages();
            try { await (window as any).edgeApi?.requestPendingMessages?.(); } catch { }
            if (wasConnectedBefore) {
              window.dispatchEvent(new CustomEvent(EventType.WS_RECONNECTED, { detail: { timestamp: Date.now() } }));
            }
          })
          .catch((error) => {
            SecurityAuditLogger.log(SignalType.ERROR, 'ws-reconnect-handshake-failed', { error: error instanceof Error ? error.message : String(error) });
            this.lifecycleState = SignalType.ERROR;
          });
      })();
    }
  }

  // Connect to WebSocket
  async connect(): Promise<void> {
    if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
      if (this.handshake.isInFlight() && this.handshake.getPromise()) {
        try { await this.handshake.getPromise(); } catch { }
      }
      return;
    }
    if (this.lifecycleState === 'connected') return;

    this.isManualClose = false;
    this.torIntegration.ensureTorListener();

    if (!this.torIntegration.ensureTorReady()) {
      throw new Error('Tor network not ready');
    }

    try {
      this.lifecycleState = 'connecting';
      await this.establishConnection();
    } catch (_error) {
      if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
        this.lifecycleState = SignalType.ERROR;
      }
      this.handleConnectionError(_error as Error, 'connect');
      throw _error;
    }
  }

  // Establish WebSocket connection
  private async establishConnection(): Promise<void> {
    const edgeApi = (window as any).edgeApi as { wsConnect?: () => Promise<any> } | undefined;
    if (!edgeApi?.wsConnect) throw new Error('edgeApi.wsConnect not available');

    const result = await edgeApi.wsConnect();
    if (result?.success === false) throw new Error(result.error || 'Failed to establish WebSocket connection');

    this.lifecycleState = 'handshaking';
    this.metrics.lastConnectedAt = Date.now();
    this.metrics.consecutiveFailures = 0;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;

    await this.performHandshake(false);

    this.lifecycleState = 'connected';

    this.registerSessionErrorHandler();
    this.queue.scheduleFlush();
    this.startConnectivityWatchdog();
    this.heartbeat.start();
    this.torIntegration.attachCircuitListener(() => { if (this.lifecycleState === 'connected') this.heartbeat.reset(); });
    void blockingSystem.processQueuedMessages();
  }

  // Register session error handler
  private registerSessionErrorHandler(): void {
    this.messageHandler.registerHandler(SignalType.ERROR, async (message: any) => {
      const errorMsg = message.message || '';
      if (errorMsg.includes('Unknown PQ session') || errorMsg.includes('PQ session')) {
        this.resetSessionKeys(true);
        try {
          await this.performHandshake(false);
          void this.queue.flush();
        } catch { }
      }
    });
  }

  // Start connectivity watchdog
  private startConnectivityWatchdog(): void {
    if (this.connectivityWatchdog) return;
    this.connectivityWatchdog = setInterval(() => {
      if (this.lifecycleState === 'connected') void this.queue.flush();
      this.encryption.pruneReplayCache();
      this.notifyConnectionStateCallbacks();
    }, 5000);
  }

  // Stop connectivity watchdog
  private stopConnectivityWatchdog(): void {
    if (this.connectivityWatchdog) {
      clearInterval(this.connectivityWatchdog);
      this.connectivityWatchdog = undefined;
    }
  }

  // Handle connection error
  handleConnectionError(error: Error, stage: string): void {
    SecurityAuditLogger.log(SignalType.ERROR, `ws-${stage}-failure`, { message: error.message });
    this.metrics.lastFailureAt = Date.now();
    this.lifecycleState = SignalType.ERROR;
    this.resetSessionKeys(false);
    if (!this.isManualClose) this.attemptReconnect();
  }

  // Reset session keys
  resetSessionKeys(preserveServerKeys: boolean = true): void {
    this.tokenValidationAttempted = false;
    if (this.sessionKeyMaterial) {
      PostQuantumUtils.clearMemory(this.sessionKeyMaterial.sendKey);
      PostQuantumUtils.clearMemory(this.sessionKeyMaterial.recvKey);
    }
    this.sessionKeyMaterial = undefined;
    this.encryption.resetCounters();
    if (!preserveServerKeys) this.handshake.clearServerKeyMaterial();
    this.previousSessionFingerprint = undefined;
    this.sessionTransitionTime = undefined;
    this.handshake.cancelRekeyTimer();
  }

  // Clear session
  private clearSession(): void {
    this.resetSessionKeys(false);
    this.encryption.clearReplayCache();
    this.heartbeat.reset();
  }

  // Attempt reconnect
  private attemptReconnect(): void {
    if (this.isManualClose) return;

    this.reconnectAttempts += 1;
    this.metrics.totalReconnects += 1;
    this.metrics.consecutiveFailures += 1;
    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);

    const jitterBytes = PostQuantumRandom.randomBytes(4);
    const jitterValue = ((jitterBytes[0]! << 24) >>> 0) ^ (jitterBytes[1]! << 16) ^ (jitterBytes[2]! << 8) ^ jitterBytes[3]!;
    const jitterMs = Math.floor((jitterValue / 0xffffffff) * 500);
    const delayWithJitter = this.reconnectDelayMs + jitterMs;

    setTimeout(() => { void this.connect().catch((e) => this.handleConnectionError(e as Error, 'connect-retry')); }, delayWithJitter);
  }

  // Send data
  send(data: unknown): void {
    void this.dispatchPayload(data, true).catch(() => {});
  }

  // Dispatch payload
  async dispatchPayload(data: unknown, allowQueue: boolean): Promise<void> {
    if (!this.circuitBreaker.check()) {
      if (allowQueue) this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + (this.circuitBreaker.getOpenUntil() - Date.now())));
      return;
    }

    if (!this.rateLimiter.checkRateLimit()) {
      if (allowQueue) this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + RATE_LIMIT_BACKOFF_MS));
      return;
    }

    if (this.isGloballyRateLimited()) {
      const remainingMs = this.globalRateLimitUntil - Date.now();
      const remainingSeconds = Math.max(1, Math.ceil(remainingMs / 1000));
      let msgType = '';
      if (typeof data === 'string') { try { msgType = JSON.parse(data)?.type || ''; } catch { } }
      else if (typeof data === 'object' && data !== null) { msgType = (data as any)?.type || ''; }

      const isAuthMessage = ['account-sign-in', 'account-sign-up', 'password-hash', 'passphrase-hash', 'server-password'].includes(msgType);
      if (isAuthMessage) {
        try { window.dispatchEvent(new CustomEvent(EventType.AUTH_RATE_LIMITED, { detail: { remainingSeconds, rateLimitUntil: this.globalRateLimitUntil } })); } catch { }
        return;
      }
      if (allowQueue) this.queue.enqueuePending(this.queue.createEntry(data, this.globalRateLimitUntil));
      return;
    }

    if (this.lifecycleState !== 'connected') {
      if (allowQueue) this.queue.enqueuePending(this.queue.createEntry(data, Date.now()));
      else throw new Error('WebSocket not connected');
      return;
    }

    if (!this.torIntegration.isCircuitHealthy()) {
      if (allowQueue) this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + 5000));
      return;
    }

    await this.ensureSessionKeys(false);
    const message = await this.encryption.prepareSecureEnvelope(data);
    this.metrics.messagesSent += 1;
    this.metrics.bytesSent += message.length;
    this.circuitBreaker.reset();
    await this.transmit(message);
  }

  // Ensure session keys
  private async ensureSessionKeys(force: boolean): Promise<void> {
    if (!force && this.sessionKeyMaterial) {
      const age = Date.now() - this.sessionKeyMaterial.establishedAt;
      if (age < SESSION_REKEY_INTERVAL_MS) {
        if (age > KEY_ROTATION_WARNING_MS) SecurityAuditLogger.log('warn', 'ws-handshake-aging-session', { age });
        return;
      }
    }
    await this.performHandshake(force);
  }

  // Perform handshake
  async performHandshake(force: boolean): Promise<void> {
    await this.handshake.performHandshake(force);
    if (this.lifecycleState !== 'connected') {
      this.lifecycleState = 'connected';
      this.heartbeat.start();
      void this.queue.flush();
    }
  }

  // Send heartbeat message
  private async sendHeartbeatMessage(): Promise<void> {
    await this.transmit(JSON.stringify({ type: 'pq-heartbeat-ping', timestamp: Date.now(), sessionId: this.sessionKeyMaterial?.sessionId }));
  }

  // Transmit message
  async transmit(message: string): Promise<void> {
    const edgeApi = (window as any).edgeApi as { wsSend?: (payload: string) => Promise<any> } | undefined;
    if (!edgeApi?.wsSend) throw new Error('edgeApi.wsSend not available');
    const result = await edgeApi.wsSend(message);
    if (result?.success === false) throw new Error(result.error || 'Failed to dispatch websocket payload');
  }

  // Set global rate limit
  setGlobalRateLimit(seconds: number) {
    const ms = Math.max(0, Math.floor(seconds * 1000));
    this.globalRateLimitUntil = Math.max(this.globalRateLimitUntil, Date.now() + ms);
    if (seconds > 0) this.metrics.lastRateLimitAt = Date.now();
  }

  // Check if globally rate limited
  isGloballyRateLimited(): boolean { return Date.now() < this.globalRateLimitUntil; }
  
  // Register message handler
  registerMessageHandler(type: string, handler: MessageHandler): void { this.messageHandler.registerHandler(type, handler); }
  
  // Unregister message handler
  unregisterMessageHandler(type: string): void { this.messageHandler.unregisterHandler(type); }
  
  // Note heartbeat pong
  noteHeartbeatPong(message: any): void { this.heartbeat.handleResponse(message); }

  // Attempt token validation once
  async attemptTokenValidationOnce(source: string = 'auto'): Promise<void> {
    if (this.tokenValidationAttempted) return;
    this.tokenValidationAttempted = true;

    try {
      const api = (window as any).electronAPI;
      if (!api?.secureStore) return;
      try { await api.secureStore.init?.(); } catch { }
      const inst = api?.instanceId ? String(api.instanceId) : '1';
      const raw = await api.secureStore.get?.(`tok:${inst}`);
      if (!raw || typeof raw !== 'string') return;
      let parsed: any;
      try { parsed = JSON.parse(raw); } catch { return; }
      const accessToken = typeof parsed?.a === 'string' ? parsed.a : '';
      const refreshToken = typeof parsed?.r === 'string' ? parsed.r : '';
      if (!accessToken || !refreshToken) return;

      await this.sendSecureControlMessage({ type: SignalType.TOKEN_VALIDATION, accessToken, refreshToken });
    } catch { }
  }

  // Close connection
  close(): void {
    this.isManualClose = true;
    this.lifecycleState = 'idle';
    this.messageHandler.clearHandlers();
    this.globalRateLimitUntil = 0;
    this.queue.clear();
    this.clearSession();
    this.stopConnectivityWatchdog();
    this.heartbeat.stop();
    this.torIntegration.cleanup();
    this.rateLimiter.reset();
    this.circuitBreaker.fullReset();
    this.connectionStateCallbacks.clear();
  }

  // Check if connected to server
  isConnectedToServer(): boolean { return this.lifecycleState === 'connected'; }
  
  // Check if PQ session established
  isPQSessionEstablished(): boolean { return !!this.sessionKeyMaterial; }

  // Export session keys
  exportSessionKeys(): { sessionId: string; sendKey: string; recvKey: string; fingerprint: string; establishedAt: number } | null {
    if (!this.sessionKeyMaterial) return null;
    return {
      sessionId: this.sessionKeyMaterial.sessionId,
      sendKey: PostQuantumUtils.uint8ArrayToBase64(this.sessionKeyMaterial.sendKey),
      recvKey: PostQuantumUtils.uint8ArrayToBase64(this.sessionKeyMaterial.recvKey),
      fingerprint: this.sessionKeyMaterial.fingerprint,
      establishedAt: this.sessionKeyMaterial.establishedAt
    };
  }

  // Import session keys
  importSessionKeys(keys: { sessionId: string; sendKey: string; recvKey: string; fingerprint: string; establishedAt: number }): boolean {
    try {
      this.sessionKeyMaterial = {
        sessionId: keys.sessionId,
        sendKey: PostQuantumUtils.base64ToUint8Array(keys.sendKey),
        recvKey: PostQuantumUtils.base64ToUint8Array(keys.recvKey),
        fingerprint: keys.fingerprint,
        establishedAt: keys.establishedAt
      };
      this.lifecycleState = 'connected';
      return true;
    } catch { return false; }
  }

  // Send secure control message
  async sendSecureControlMessage(message: any): Promise<void> {
    if (!this.isPQSessionEstablished()) {
      if (this.lifecycleState !== 'connected') {
        this.queue.enqueuePending({ ...this.queue.createEntry(message, Date.now()), highPriority: true });
        return;
      }
      const maxWaitTime = 10000;
      const startTime = Date.now();
      while (!this.isPQSessionEstablished() && (Date.now() - startTime) < maxWaitTime) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      if (!this.isPQSessionEstablished()) throw new Error('PQ session not established');
    }
    await this.dispatchPayload(typeof message === 'string' ? message : JSON.stringify(message), true);
  }

  // Set server key material
  setServerKeyMaterial(hybridKeys: { kyberPublicBase64: string; dilithiumPublicBase64?: string; x25519PublicBase64?: string }, serverId?: string): void {
    try {
      const kyberPublicKey = PostQuantumUtils.base64ToUint8Array(hybridKeys.kyberPublicBase64);
      const dilithiumPublicKey = hybridKeys.dilithiumPublicBase64 ? PostQuantumUtils.base64ToUint8Array(hybridKeys.dilithiumPublicBase64) : undefined;
      const x25519PublicKey = hybridKeys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(hybridKeys.x25519PublicBase64) : undefined;
      const fingerprint = this.handshake.computeServerFingerprint({ kyber: hybridKeys.kyberPublicBase64, dilithium: hybridKeys.dilithiumPublicBase64 || '', x25519: hybridKeys.x25519PublicBase64 || '' });
      this.handshake.setServerKeyMaterial({ kyberPublicKey, dilithiumPublicKey, x25519PublicKey, fingerprint, serverId });
    } catch { }
  }

  // On connection state change
  onConnectionStateChange(callback: (health: ConnectionHealth) => void): () => void {
    this.connectionStateCallbacks.add(callback);
    return () => this.connectionStateCallbacks.delete(callback);
  }

  // Notify connection state callbacks
  private notifyConnectionStateCallbacks(): void {
    const health = this.getConnectionHealth();
    for (const callback of Array.from(this.connectionStateCallbacks)) {
      try { callback(health); } catch { }
    }
  }

  // Get connection health
  getConnectionHealth(): ConnectionHealth {
    const sessionAge = this.sessionKeyMaterial ? Date.now() - this.sessionKeyMaterial.establishedAt : null;
    return {
      state: this.lifecycleState as any,
      isHealthy: this.lifecycleState === 'connected' && this.heartbeat.getMissedHeartbeats() < MAX_MISSED_HEARTBEATS,
      metrics: { ...this.metrics },
      queueDepth: this.queue.getQueueLength(),
      sessionAge,
      torStatus: { ready: this.torIntegration.isTorReady(), circuitHealth: this.torIntegration.getCircuitHealth() as 'unknown' | 'good' | 'degraded' | 'poor' },
      lastHeartbeat: this.heartbeat.getLastHeartbeatReceived(),
      quality: this.heartbeat.assessConnectionQuality(this.lifecycleState)
    };
  }

  // Decrypt incoming envelope
  async decryptIncomingEnvelope(envelope: any): Promise<any | null> { return this.encryption.decryptEnvelope(envelope); }
  
  // Flush pending queue
  async flushPendingQueue(): Promise<void> { return this.queue.flush(); }
}

const websocketClient = new WebSocketConnection();
export default websocketClient;