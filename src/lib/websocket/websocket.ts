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
  WS_COVER_TRAFFIC_INTERVAL_MS,
  WS_COVER_TRAFFIC_JITTER_MS,
  WS_COVER_TRAFFIC_IDLE_GRACE_MS,
  COVER_TRAFFIC_PAYLOAD_TYPE,
  SESSION_FAILOVER_GRACE_PERIOD_MS,
} from '../constants';

import { WebSocketRateLimiter } from './rate-limiter';
import { WebSocketCircuitBreaker } from './circuit-breaker';
import { WebSocketHeartbeat } from './heartbeat';
import { WebSocketTorIntegration } from './tor-integration';
import { WebSocketQueue } from './queue';
import { WebSocketEncryption } from './encryption';
import { WebSocketHandshake } from './handshake';
import { WebSocketMessageHandler } from './message-handler';
import { websocket, session, events, signal } from '../tauri-bindings';
import { GatekeeperClient } from '../cryptography/gatekeeper-client';
import { Base64 } from '../cryptography/base64';
import { retrieveAuthTokens } from '../signals/token-storage';

// WebSocket Connection Manager
export class WebSocketConnection {
  lifecycleState: string = 'idle';
  private isManualClose = false;
  private reconnectAttempts = 0;
  private reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
  private globalRateLimitUntil = 0;
  private tokenValidationAttempted = false;
  private _username?: string;
  private lastAuthUsername?: string;
  private connectivityWatchdog?: ReturnType<typeof setInterval>;
  private bridgeReadyPromise: Promise<void>;
  private connectingPromise: Promise<void> | null = null;
  private transportEventReceived: boolean = false;
  private trustTransportUntil: number = 0;
  private isInUnlinkedMode: boolean = false;
  private coverTrafficTimer: ReturnType<typeof setTimeout> | null = null;
  private coverTrafficInFlight = false;
  private lastRealSendAt = 0;
  private gatekeeper?: GatekeeperClient;
  private gatekeeperPromise?: Promise<GatekeeperClient>;
  private serverAuthGranted = false;
  private hasOpenedTransport = false;

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
  private previousSessionKeyMaterial?: SessionKeyMaterial;
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
        get previousSessionKeyMaterial() { return self.previousSessionKeyMaterial; },
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
      onHandshakeError: (error) => this.handleConnectionError(error, 'handshake'),
      isConnected: async () => {
        const isInternalHealthy = this.lifecycleState !== 'disconnected' && this.lifecycleState !== 'idle' && this.lifecycleState !== SignalType.ERROR;
        if (!isInternalHealthy) return false;

        const now = Date.now();
        const isTrusted = now < this.trustTransportUntil;

        try {
          const state = await websocket.getState();
          const isHealthy = state.connected || state.connecting || isTrusted;
          return isHealthy;
        } catch (err) {
          console.warn('[WebSocket] Error in isConnected check:', err);
          return true;
        }
      }
    });

    this.messageHandler = new WebSocketMessageHandler({
      decryptEnvelope: (env) => this.encryption.decryptEnvelope(env),
      handleHeartbeatResponse: (msg) => this.heartbeat.handleResponse(msg)
    });

    this.bridgeReadyPromise = this.initializeBridge();
  }

  private async getGatekeeper(): Promise<GatekeeperClient> {
    if (this.gatekeeper) {
      await this.gatekeeper.ensureReady();
      return this.gatekeeper;
    }
    
    if (this.gatekeeperPromise) return this.gatekeeperPromise;

    this.gatekeeperPromise = (async () => {
      try {
        const url = await websocket.getServerUrl() || 'default';
        const gk = new GatekeeperClient(url);
        await gk.ensureReady();
        this.gatekeeper = gk;
        return gk;
      } finally {
        this.gatekeeperPromise = undefined;
      }
    })();

    return this.gatekeeperPromise;
  }

  private async initializeBridge(): Promise<void> {
    await this.initializeSigningKeys();
    await this.setupTauriBridge();

    // Check if already connected
    try {
      const state = await websocket.getState();
      if (state.connected && (this.lifecycleState === 'idle' || this.lifecycleState === 'disconnected')) {
        void this.handleConnectionOpened();
      }
    } catch (err) {
      console.warn('[WebSocket] Failed to check initial state:', err);
    }
  }

  // Setup bridge from Tauri events
  private async setupTauriBridge(): Promise<void> {
    if (typeof window === 'undefined') return;
    try {
      await events.onWsMessage(async (payload) => {
        await this.handleEdgeServerMessage(payload);
      });
    } catch (err) {
      console.error('[WebSocket] Failed to setup Tauri bridge:', err);
    }
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
    if (this.sessionKeyMaterial?.sessionId && this.sessionKeyMaterial.sessionId !== session.sessionId) {
      this.previousSessionKeyMaterial = this.sessionKeyMaterial;
      this.sessionTransitionTime = Date.now();
      const previousSessionId = this.previousSessionKeyMaterial.sessionId;
      const transitionTime = this.sessionTransitionTime;
      setTimeout(() => {
        if (this.sessionTransitionTime === transitionTime &&
          this.previousSessionKeyMaterial?.sessionId === previousSessionId) {
          this.previousSessionKeyMaterial = undefined;
        }
      }, SESSION_FAILOVER_GRACE_PERIOD_MS);
    }
    if (this.sessionKeyMaterial?.fingerprint &&
      this.sessionKeyMaterial.fingerprint !== session.fingerprint) {
      this.previousSessionFingerprint = this.sessionKeyMaterial.fingerprint;
      this.sessionTransitionTime = Date.now();
    }

    this.sessionKeyMaterial = session;
    this.encryption.resetCounters();
    this.encryption.clearReplayCache();
    this.startCoverTraffic();
  }

  // Set and get username
  setUsername(username: string) {
    this._username = username;
    this.lastAuthUsername = username;
  }
  getUsername(): string | undefined { return this._username; }

  // Handle edge server message
  async handleEdgeServerMessage(message: any, isSecure: boolean = false): Promise<boolean> {
    const now = Date.now();
    this.metrics.messagesReceived += 1;
    this.metrics.bytesReceived += typeof message === 'string' ? message.length : JSON.stringify(message).length;

    if (!isPlainObject(message) || hasPrototypePollutionKeys(message)) {
      console.warn('[WebSocket] Malformed message received:', message);
      return false;
    }

    const messageType = typeof message.type === 'string' ? message.type : '';

    if (this.trustTransportUntil > now) {
      void websocket.getState().then(_s => { });
    }

    // Handle handshake signals internally
    if (messageType === SignalType.SERVER_PUBLIC_KEY) {
      const hybridKeys = (message as any).hybridKeys;
      const sid = (message as any).serverId;

      if (hybridKeys) {
        this.setServerKeyMaterial(hybridKeys, sid);
      } else {
        console.warn('[WebSocket] server-public-key message missing hybridKeys');
      }

      // Check if server requires password and no tokens
      if ((message as any).requiresServerPassword) {
        void this.getGatekeeper().then(gk => {
          if (!gk.hasTokens) {
            window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
              detail: {
                type: 'SERVER_ENTRY_REQUIRED',
                message: 'This server requires an entry token. Please provide the server password.'
              }
            }));
          }
        });
      }

      this.dispatchToFrontend(message, isSecure);
      return true;
    }

    // Handle PQ envelope internally
    if (messageType === SignalType.PQ_ENVELOPE) {
      const decrypted = await this.decryptIncomingEnvelope(message);
      if (decrypted) {
        const innerType = typeof decrypted.type === 'string' ? decrypted.type : 'unknown';
        if (innerType === 'discovery-result' || innerType === 'oprf-blind-evaluate-response' || innerType === 'oprf-discovery-public-key') {
          console.log('[WebSocket] PQ envelope decrypted → inner type:', innerType);
        }
        return await this.handleEdgeServerMessage(decrypted, true);
      }
      console.warn('[WebSocket] PQ envelope decryption FAILED (returned null), fingerprint:', typeof message.sessionFingerprint === 'string' ? message.sessionFingerprint.slice(0, 16) : 'none');
      return true;
    }

    if (messageType === SignalType.PQ_HEARTBEAT_PONG) {
      this.noteHeartbeatPong(message);
      return true;
    }

    if (messageType === '__ws_connection_closed') {
      this.resetSessionKeys(this.isManualClose);
      this.lifecycleState = 'disconnected';
      this.dispatchToFrontend(message, isSecure);
      return true;
    }

    if (messageType === '__ws_connection_error') {
      console.error('[WebSocket] Connection error via bridge:', message.error);
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-connection-error-from', { error: message.error });
      this.resetSessionKeys(this.isManualClose);
      this.lifecycleState = SignalType.ERROR;
      this.dispatchToFrontend(message, isSecure);
      return true;
    }

    if (messageType === '__ws_connection_opened') {
      const wasReconnect = this.hasOpenedTransport;
      this.hasOpenedTransport = true;
      void this.handleConnectionOpened();
      this.dispatchToFrontend(message, isSecure);
      if (wasReconnect) {
        try {
          window.dispatchEvent(new CustomEvent(EventType.WS_RECONNECTED, {
            detail: { timestamp: Date.now() }
          }));
        } catch { }
      }
      return true;
    }

    // Pass through to internal handlers (heartbeat, handshake hooks)
    if (messageType === 'pq-heartbeat-pong' || this.messageHandler.hasHandler(messageType)) {
      void this.messageHandler.handleMessage(message);
      return true;
    }

    this.dispatchToFrontend(message, isSecure);
    return false;
  }

  // Dispatch message to frontend hooks via custom event
  private dispatchToFrontend(message: any, isSecure: boolean = false): void {
    if (typeof window === 'undefined') return;
    const eventType = isSecure ? EventType.SECURE_SERVER_MESSAGE : EventType.EDGE_SERVER_MESSAGE;
    window.dispatchEvent(new CustomEvent(eventType, { detail: message }));
  }

  // Handle connection opened
  private handleConnectionOpened(): void {
    this.transportEventReceived = true;
    this.trustTransportUntil = Date.now() + 5000;

    if (this.connectingPromise) {
      return;
    }

    void this.connect().catch(() => { });
  }

  private startCoverTraffic(): void {
    if (this.coverTrafficTimer) return;
    this.scheduleCoverTraffic();
  }

  private stopCoverTraffic(): void {
    if (this.coverTrafficTimer) {
      clearTimeout(this.coverTrafficTimer);
      this.coverTrafficTimer = null;
    }
  }

  private scheduleCoverTraffic(): void {
    if (this.coverTrafficTimer) return;
    const variance = WS_COVER_TRAFFIC_JITTER_MS;
    const jitter = variance > 0 ? (Math.random() * variance * 2 - variance) : 0;
    const delay = Math.max(500, WS_COVER_TRAFFIC_INTERVAL_MS + jitter);

    this.coverTrafficTimer = setTimeout(async () => {
      this.coverTrafficTimer = null;
      await this.sendCoverTraffic();
      if (this.lifecycleState === 'connected' && this.sessionKeyMaterial) {
        this.scheduleCoverTraffic();
      }
    }, delay);
  }

  private async sendCoverTraffic(): Promise<void> {
    if (this.coverTrafficInFlight) return;
    if (this.lifecycleState !== 'connected' || !this.sessionKeyMaterial) return;
    if (Date.now() - this.lastRealSendAt < WS_COVER_TRAFFIC_IDLE_GRACE_MS) return;
    if (this.queue.getQueueLength() > 0) return;

    this.coverTrafficInFlight = true;
    try {
      const { getBlindRoutingClient } = await import('../transport/blind-routing-client');
      const blindClient = getBlindRoutingClient(this.lastAuthUsername);
      const inboxId = blindClient.getMyInboxId();
      const recipientKyber = blindClient.getLocalKyberPublicKey();
      if (!inboxId || !recipientKyber) return;

      const sealedEnvelope = await blindClient.createSealedEnvelope(
        inboxId,
        recipientKyber,
        {
          type: COVER_TRAFFIC_PAYLOAD_TYPE,
          timestamp: Date.now(),
          nonce: PostQuantumUtils.uint8ArrayToBase64(PostQuantumRandom.randomBytes(16))
        }
      );

      await this.dispatchPayload({
        type: SignalType.BLIND_ROUTE,
        destinationInbox: inboxId,
        sealedEnvelope
      }, false, { isCoverTraffic: true });
    } catch {
    } finally {
      this.coverTrafficInFlight = false;
    }
  }

  // Connect to WebSocket
  async connect(): Promise<void> {
    if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
      if (this.connectingPromise) return this.connectingPromise;

      if (this.handshake.isInFlight() && this.handshake.getPromise()) {
        try { await this.handshake.getPromise(); } catch { }
      }
      return;
    }

    if (this.lifecycleState === 'connected') {
      return;
    }

    if (this.connectingPromise) {
      return this.connectingPromise;
    }

    this.connectingPromise = (async () => {
      this.isManualClose = false;
      this.torIntegration.ensureTorListener();

      if (!this.torIntegration.ensureTorReady()) {
        throw new Error('Tor network not ready');
      }

      try {
        await this.bridgeReadyPromise;
        const state = await websocket.getState();
        const hasGhost = this.transportEventReceived || state.connected;

        if (state.connected) {
          this.transportEventReceived = false;
          await this.establishConnection({ forceConnect: false });
        } else if (hasGhost) {
          this.transportEventReceived = false;
          this.lifecycleState = 'connecting';
          await this.establishConnection({ forceConnect: true });
        } else {
          this.lifecycleState = 'connecting';
          await this.establishConnection({ forceConnect: true });
        }
      } catch (_error) {
        if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
          this.lifecycleState = SignalType.ERROR;
        }
        this.handleConnectionError(_error as Error, 'connect');
        throw _error;
      } finally {
        this.connectingPromise = null;
      }
    })();

    return this.connectingPromise;
  }

  private async establishConnection(options: { forceConnect?: boolean } = {}): Promise<void> {
    const { forceConnect = true } = options;

    if (forceConnect) {
      const state = await websocket.getState();
      if (!state.connected) {
        const result = await websocket.connect();
        if (result?.success === false) throw new Error(result.error || 'Failed to establish WebSocket connection');
      }
    }

    this.lifecycleState = 'handshaking';
    this.metrics.lastConnectedAt = Date.now();
    this.metrics.consecutiveFailures = 0;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;

    await this.bridgeReadyPromise;

    // Try to restore session if available
    let restored = false;
    try {
      const pqKeys = await session.getPQKeys('current');
      if (pqKeys && this.importSessionKeys({
        sessionId: pqKeys.session_id,
        sendKey: pqKeys.aes_key,
        recvKey: pqKeys.mac_key,
        fingerprint: '',
        establishedAt: pqKeys.created_at
      })) {
        await session.deletePQKeys('current');
        restored = true;
      }
    } catch { }

    if (!restored) {
      await this.performHandshake(false);
    }

    // Redeem entry token
    try {
      const gk = await this.getGatekeeper();
      if (gk.hasTokens) {
        const redemption = await gk.getRedemptionPayload();
        if (redemption) {
          
          // Wait for server response
          const waitForOk = new Promise<boolean>((resolve) => {
            const timeout = setTimeout(() => {
              window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
              resolve(false);
            }, 5000);

            const handler = (ev: Event) => {
              const detail = (ev as CustomEvent).detail;
              if (detail?.type === 'ok') {
                clearTimeout(timeout);
                window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
                resolve(true);
              }
            };
            window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
          });

          await this.sendSecureControlMessage(redemption);
          const entryGranted = await waitForOk;
          
          if (entryGranted) {
            this.serverAuthGranted = true;
            window.dispatchEvent(new CustomEvent(EventType.SERVER_ENTRY_GRANTED));
          }
        }
      }
    } catch (e) {
      console.warn('[WebSocket] Automatic entry token redemption failed', e);
    }

    this.lifecycleState = 'connected';

    // If in unlinked mode then claim inbox anonymously
    if (this.isInUnlinkedMode) {
      try {
        const { getBlindRoutingClient } = await import('../transport/blind-routing-client');
        const bc = getBlindRoutingClient(this.lastAuthUsername);

        // Restore credentials from storage if not already in memory
        if (!bc.hasCredentials()) {
          await bc.loadPersistentCredentials();
        }

        // Re-set send function for the new PQ session
        const self = this;
        bc.setSendFunction(async (message: any) => {
          await self.sendSecureControlMessage(message);
        });

        // Wait for claim response before publishing bundle
        const waitForClaimResponse = new Promise<boolean>((resolve) => {
          const timeout = setTimeout(() => {
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
            resolve(false);
          }, 10000);

          const handler = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (detail?.type === SignalType.CLAIM_INBOX_RESPONSE) {
              clearTimeout(timeout);
              window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
              resolve(!!detail.success);
            }
          };
          window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
        });

        const claimSent = await bc.claimInbox();

        // Only wait for server response if the claim message was actually sent
        const claimSuccess = claimSent ? await waitForClaimResponse : false;

        // Publish Signal bundle in unlinked mode
        if (claimSuccess) {
          try {
            const username = bc.getLocalUsername();
            if (username && username !== 'anonymous') {
              const bundle = await signal.createPreKeyBundle(username);
              if (bundle && bundle.registrationId) {
                this.send(JSON.stringify({ type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE, bundle }));
              }
            }
          } catch (bundleErr) {
            console.warn('[WebSocket] Failed to publish bundle in unlinked mode:', bundleErr);
          }
          
          window.dispatchEvent(new CustomEvent(EventType.UNLINKED_SESSION_READY));
        } else {
          console.warn('[WebSocket] Skipping bundle publish - inbox claim failed or timed out');
        }
      } catch (e) {
        console.warn('[WebSocket] Failed to claim inbox in unlinked mode:', e);
      }
    }

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

    this.messageHandler.registerHandler(SignalType.AUTH_ERROR, async (message: any) => {
      if (message.code === 'SERVER_ENTRY_REQUIRED') {
        window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
          detail: {
            type: 'SERVER_ENTRY_REQUIRED',
            message: 'This server requires an entry token. Please provide the server password.'
          }
        }));
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
    this.resetSessionKeys(this.isManualClose);
    if (!this.isManualClose) this.attemptReconnect();
  }

  // Reset session keys
  resetSessionKeys(preserveServerKeys: boolean = true): void {
    this.tokenValidationAttempted = false;
    this.serverAuthGranted = false;
    this.stopCoverTraffic();
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
    void this.dispatchPayload(data, true).catch((err) => {
      console.error('[WebSocket] Send failed:', err);
    });
  }

  // Dispatch payload
  async dispatchPayload(data: unknown, allowQueue: boolean, options: { isCoverTraffic?: boolean } = {}): Promise<void> {
    const msgObj = typeof data === 'string' ? ((): any => { try { return JSON.parse(data); } catch { return {}; } })() : (data as any);

    // Identity leak protection for unlinked mode
    if (this.isInUnlinkedMode) {
      if (
        msgObj.type === SignalType.HYBRID_KEYS_UPDATE ||
        msgObj.type === SignalType.TOKEN_VALIDATION ||
        msgObj.username ||
        msgObj.accessToken
      ) {
        console.warn(`[WebSocket] Blocking account-linked message in unlinked mode: ${msgObj.type || 'unknown'}`);
        return;
      }
    }

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

      const isAuthMessage = ['account-sign-in', 'account-sign-up', 'server-entry-request'].includes(msgType);
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
    if (!options.isCoverTraffic) {
      this.lastRealSendAt = Date.now();
    }
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
  }

  // Send heartbeat message
  private async sendHeartbeatMessage(): Promise<void> {
    if (this.sessionKeyMaterial) {
      await this.dispatchPayload({
        type: SignalType.PQ_HEARTBEAT_PING,
        timestamp: Date.now(),
        sessionId: this.sessionKeyMaterial.sessionId
      }, false);
      return;
    }
    await this.transmit(JSON.stringify({ type: 'pq-heartbeat-ping', timestamp: Date.now(), sessionId: this.sessionKeyMaterial?.sessionId }));
  }

  markServerAuthGranted(): void {
    this.serverAuthGranted = true;
  }

  isServerAuthGranted(): boolean {
    return this.serverAuthGranted;
  }

  // Transmit message with local retry for transient queuing failures
  async transmit(message: string, retryCount = 0): Promise<void> {
    try {
      const result = await websocket.send(message);
      if (result?.success === false) {
        const error = result.error || 'Unknown error';
        if (error.includes('Failed to queue message') && retryCount < 5) {
          await new Promise(resolve => setTimeout(resolve, 300 * (retryCount + 1)));
          return this.transmit(message, retryCount + 1);
        }
        throw new Error(error);
      }
    } catch (err: any) {
      if (err.message?.includes('Failed to queue message') && retryCount < 5) {
        await new Promise(resolve => setTimeout(resolve, 300 * (retryCount + 1)));
        return this.transmit(message, retryCount + 1);
      }
      throw err;
    }
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
  async attemptTokenValidationOnce(_source: string = 'auto', force: boolean = false): Promise<void> {
    if (this.isInUnlinkedMode) return;
    if (this.tokenValidationAttempted && !force) return;
    this.tokenValidationAttempted = true;

    try {
      const accessToken = await retrieveAuthTokens();
      if (!accessToken || typeof accessToken !== 'string') {
        this.tokenValidationAttempted = false;
        return;
      }

      await this.sendSecureControlMessage({ type: SignalType.TOKEN_VALIDATION, accessToken });
    } catch { }
  }

  /**
   * Switch to unlinked mode
   */
  async switchToUnlinkedMode(): Promise<void> {
    this.isInUnlinkedMode = true;

    // Disconnect with reset
    await this.close();

    const jitter = 500 + Math.random() * 1500;
    await new Promise(resolve => setTimeout(resolve, jitter));

    // Reconnect
    await this.connect();
  }

  /**
   * Start the server gatekeeper flow to get entry tokens
   */
  async startServerGatekeeperFlow(password: string): Promise<boolean> {
    try {
      const gk = await this.getGatekeeper();
      const request = await gk.startEntryRequest(password);

      const responsePromise = new Promise<any>((resolve, reject) => {
        const timeout = setTimeout(() => {
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_CHALLENGE);
          reject(new Error('Gatekeeper challenge timeout'));
        }, 10000);

        this.messageHandler.registerHandler(SignalType.SERVER_ENTRY_CHALLENGE, async (msg: any) => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_CHALLENGE);
          resolve(msg);
        });
      });

      await this.sendSecureControlMessage(request);
      const challenge = await responsePromise;

      // Prepare issuance
      const issuanceRequest = await gk.prepareTokenIssuance(password, {
        evaluatedElement: Base64.base64ToUint8Array(challenge.evaluatedElement),
        serverNonce: Base64.base64ToUint8Array(challenge.serverNonce),
        envelope: Base64.base64ToUint8Array(challenge.envelope),
        maskedResponse: Base64.base64ToUint8Array(challenge.maskedResponse),
        salt: challenge.salt ? Base64.base64ToUint8Array(challenge.salt) : undefined
      });

      const issuancePromise = new Promise<any>((resolve, reject) => {
        const timeout = setTimeout(() => {
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE);
          reject(new Error('Token issuance timeout'));
        }, 15000);

        this.messageHandler.registerHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE, async (msg: any) => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE);
          resolve(msg);
        });
      });

      await this.sendSecureControlMessage(issuanceRequest);
      const tokenBatch = await issuancePromise;

      // Step 3: Finalize
      await gk.finalizeEntry(
        tokenBatch.signedBlindedTokens.map((t: string) => Base64.base64ToUint8Array(t)),
        Base64.base64ToUint8Array(tokenBatch.proof),
        Base64.base64ToUint8Array(tokenBatch.publicKey)
      );

      // Auto-redeem to fully establish connection
      const redemption = await gk.getRedemptionPayload();
      if (redemption) {
        await this.sendSecureControlMessage(redemption);
      }

      return true;
    } catch (error) {
      console.error('[WebSocket] Gatekeeper flow failed', error);
      return false;
    }
  }

  // Close connection
  async close(): Promise<void> {
    this.isManualClose = true;
    this.lifecycleState = 'idle';
    this.messageHandler.clearHandlers();
    this.globalRateLimitUntil = 0;
    this.queue.clear();
    this.resetSessionKeys(true);
    this.stopConnectivityWatchdog();
    this.heartbeat.stop();
    this.torIntegration.cleanup();
    this.rateLimiter.reset();
    this.circuitBreaker.fullReset();
    this.connectionStateCallbacks.clear();
    this.handshake.reset();

    try {
      await websocket.disconnect().catch(() => { });
    } catch { }
  }

  // Check if connected to server
  isConnectedToServer(): boolean { return this.lifecycleState === 'connected'; }

  // Check if unlinked mode is active
  isUnlinkedMode(): boolean { return this.isInUnlinkedMode; }

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
  setServerKeyMaterial(
    hybridKeys: { kyberPublicBase64: string; dilithiumPublicBase64?: string; x25519PublicBase64?: string },
    serverId?: string
  ): void {
    try {
      const kyberPublicKey = PostQuantumUtils.base64ToUint8Array(hybridKeys.kyberPublicBase64);
      const dilithiumPublicKey = hybridKeys.dilithiumPublicBase64 ? PostQuantumUtils.base64ToUint8Array(hybridKeys.dilithiumPublicBase64) : undefined;
      const x25519PublicKey = hybridKeys.x25519PublicBase64 ? PostQuantumUtils.base64ToUint8Array(hybridKeys.x25519PublicBase64) : undefined;
      const fingerprint = this.handshake.computeServerFingerprint({ kyber: hybridKeys.kyberPublicBase64, dilithium: hybridKeys.dilithiumPublicBase64 || '', x25519: hybridKeys.x25519PublicBase64 || '' });
      this.handshake.setServerKeyMaterial({
        kyberPublicKey,
        dilithiumPublicKey,
        x25519PublicKey,
        fingerprint,
        serverId
      });
    } catch (err) {
      console.error('[WebSocket] setServerKeyMaterial failed:', err);
    }
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
