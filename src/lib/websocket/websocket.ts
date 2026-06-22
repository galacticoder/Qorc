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
  WS_COVER_TRAFFIC_MIN_INTERVAL_MS,
  WS_COVER_TRAFFIC_MAX_INTERVAL_MS,
  SESSION_FAILOVER_GRACE_PERIOD_MS,
} from '../constants';

import { WebSocketRateLimiter } from './rate-limiter';
import { WebSocketHeartbeat } from './heartbeat';
import { WebSocketTorIntegration } from './tor-integration';
import { WebSocketQueue } from './queue';
import { WebSocketEncryption } from './encryption';
import { WebSocketHandshake } from './handshake';
import { WebSocketMessageHandler } from './message-handler';
import { websocket, events } from '../tauri-bindings';
import { GatekeeperClient } from '../cryptography/gatekeeper-client';
import { Base64 } from '../cryptography/base64';

interface ConnectOptions {
  autoReconnectOnFailure?: boolean;
}

const SECURE_CHUNK_MAX_TOTAL_CHUNKS = 128;
const SECURE_CHUNK_MAX_TOTAL_LENGTH = 48 * 1024 * 1024;
const SECURE_CHUNK_MAX_DATA_LENGTH = 8 * 1024 * 1024;
const SECURE_CHUNK_MAX_CONCURRENT = 4;
const SECURE_CHUNK_TIMEOUT_MS = 200_000;

interface SecureChunkBuffer {
  totalChunks: number;
  totalLength: number;
  payloadType: string;
  parts: (string | undefined)[];
  receivedCount: number;
  receivedLength: number;
  createdAt: number;
  timer: ReturnType<typeof setTimeout>;
}

// WebSocket Connection Manager
export class WebSocketConnection {
  lifecycleState: string = 'idle';
  private isManualClose = false;
  private readonly maxReconnectionAttempts = 10;
  private isGatekeeperFlowActive = false;
  private secureChunkBuffers: Map<string, SecureChunkBuffer> = new Map();
  private reconnectAttempts = 0;
  private reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
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
  private gatekeeper?: GatekeeperClient;
  private gatekeeperPromise?: Promise<GatekeeperClient>;
  private serverAuthGranted = false;
  private applicationAuthReady = false;
  private hasOpenedTransport = false;
  private unlinkedSessionReady = false;
  private secureSendLane: Promise<void> = Promise.resolve();
  private serverClockOffsetMs = 0;
  private timestampRecoveryInFlight: Promise<void> | null = null;
  private lastTimestampRecoveryAt = 0;
  private lastCoverBackpressureLogAt = 0;

  private sessionMismatchCount = 0;
  private lastMismatchTime = 0;
  private readonly MAX_SESSION_MISMATCHES = 5;
  private readonly SESSION_MISMATCH_WINDOW_MS = 60000;
  private pendingReconnectEnvelopes: any[] = [];

  private deliveryReadyRetryTimer: ReturnType<typeof setTimeout> | null = null;
  private deliveryReadyRetryAttempts = 0;
  private reconnectClaimListenerAttached = false;

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
  heartbeat: WebSocketHeartbeat;
  torIntegration: WebSocketTorIntegration;
  queue: WebSocketQueue;
  encryption: WebSocketEncryption;
  handshake: WebSocketHandshake;
  messageHandler: WebSocketMessageHandler;

  constructor() {
    this.rateLimiter = new WebSocketRateLimiter(this.metrics);

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
      () => this.getTrustedNow()
    );

    this.handshake = new WebSocketHandshake({
      transmit: (msg) => this.transmit(msg),
      registerMessageHandler: (type, handler) => this.messageHandler.registerHandler(type, handler),
      unregisterMessageHandler: (type, handler) => this.messageHandler.unregisterHandler(type, handler),
      getQueueLength: () => this.queue.getQueueLength(),
      getTorAdaptedTimeout: (timeout) => this.torIntegration.getAdaptedTimeout(timeout),
      onSessionEstablished: (session, serverSigKey, signingKeyPair) =>
        this.onSessionEstablished(session, serverSigKey, signingKeyPair),
      onHandshakeError: (error) => this.handleConnectionError(error, 'handshake'),
      getTrustedNow: () => this.getTrustedNow(),
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
      decryptEnvelope: async (env) => {
        const decrypted = await this.encryption.decryptEnvelope(env);

        // Session auto recovery
        if (!decrypted && env.sessionId && this.sessionKeyMaterial) {
          const now = Date.now();
          if (now - this.lastMismatchTime > this.SESSION_MISMATCH_WINDOW_MS) {
            this.sessionMismatchCount = 0;
          }

          this.sessionMismatchCount++;
          this.lastMismatchTime = now;

          if (this.sessionMismatchCount >= this.MAX_SESSION_MISMATCHES) {
            console.warn('[WebSocket] Detected persistent PQ decryption failures, forcing re-handshake', {
              hasReceivedSessionId: typeof env.sessionId === 'string',
              hasCurrentSession: !!this.sessionKeyMaterial?.sessionId,
              count: this.sessionMismatchCount
            });

            // Force a fresh re handshake to recover from desync
            this.sessionMismatchCount = 0;
            this.performHandshake(true).catch(() => {
              console.error('[WebSocket] PQ auto-recovery handshake failed');
            });
          }
        } else if (decrypted) {
          this.sessionMismatchCount = 0;
        }

        return decrypted;
      },
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

  private getTrustedNow(): number {
    return Date.now() + this.serverClockOffsetMs;
  }

  private updateServerClockOffset(serverTime: unknown): void {
    if (typeof serverTime !== 'number' || !Number.isFinite(serverTime)) return;
    const offset = Math.trunc(serverTime - Date.now());
    if (Math.abs(offset) > 24 * 60 * 60 * 1000) return;
    this.serverClockOffsetMs = offset;
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
    } catch {
      console.warn('[WebSocket] Failed to check initial state');
    }
  }

  // Setup bridge from Tauri events
  private async setupTauriBridge(): Promise<void> {
    if (typeof window === 'undefined') return;
    try {
      await events.onWsMessage(async (payload) => {
        await this.handleEdgeServerMessage(payload);
      });
    } catch {
      console.error('[WebSocket] Failed to setup Tauri bridge');
    }

    // after any reconnect the socket must reclaim inbox to keep receiving global mix broadcast
    if (!this.reconnectClaimListenerAttached) {
      this.reconnectClaimListenerAttached = true;
      window.addEventListener(EventType.WS_RECONNECTED, () => {
        if (this.isInUnlinkedMode && !this.unlinkedSessionReady) {
          this.scheduleDeliveryReadyRetry();
        }
      });
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
  private async onSessionEstablished(
    session: SessionKeyMaterial,
    _serverSignatureKey?: Uint8Array,
    signingKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array }
  ): Promise<void> {
    if (signingKeyPair) {
      this.signingKeyPair = signingKeyPair;
      session.clientSigningPublicKey = signingKeyPair.publicKey;
    }

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
    this.sessionMismatchCount = 0;

    // Flush PQ envelopes queued during reconnect
    if (this.pendingReconnectEnvelopes.length > 0) {
      const queued = this.pendingReconnectEnvelopes;
      this.pendingReconnectEnvelopes = [];
      for (const envelope of queued) {
        try {
          const decrypted = await this.decryptIncomingEnvelope(envelope);
          if (decrypted) {
            await this.handleEdgeServerMessage(decrypted, true);
          }
        } catch { }
      }
    }
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
    this.updateServerClockOffset((message as any).serverTime);
    if (messageType === SignalType.PQ_HANDSHAKE_ACK) {
      this.updateServerClockOffset((message as any).timestamp);
    }

    if (this.isGatekeeperDebugType(messageType)) {
      this.logGatekeeperDebug('received-message', {
        type: messageType,
        isSecure,
        hasInternalHandler: this.messageHandler.hasHandler(messageType)
      });
    }

    // Reassemble chunked secure messages
    if (isSecure && messageType === SignalType.SECURE_CHUNK) {
      const reassembled = this.ingestSecureChunk(message);
      if (!reassembled) return true;
      return await this.handleEdgeServerMessage(reassembled, true);
    }

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
      if (this.isGatekeeperFlowActive) {
        this.logGatekeeperDebug('received-pq-envelope', {
          hasReceivedSessionId: typeof message.sessionId === 'string',
          receivedSessionMatches: message.sessionId === this.sessionKeyMaterial?.sessionId,
          hasReceivedFingerprint: typeof message.sessionFingerprint === 'string',
          receivedFingerprintMatches: message.sessionFingerprint === this.sessionKeyMaterial?.fingerprint,
          hasSignature: typeof message.signature === 'string',
          hasAad: typeof message.aad === 'string'
        });
      }
      const decrypted = await this.decryptIncomingEnvelope(message);
      if (decrypted) {
        const decryptedType = this.getMessageTypeForDebug(decrypted);
        if (this.isGatekeeperDebugType(decryptedType)) {
          this.logGatekeeperDebug('decrypted-pq-envelope', {
            decryptedType,
            hasInternalHandler: this.messageHandler.hasHandler(decryptedType),
            receivedSessionMatches: message.sessionId === this.sessionKeyMaterial?.sessionId,
            receivedFingerprintMatches: message.sessionFingerprint === this.sessionKeyMaterial?.fingerprint
          });
        }
        return await this.handleEdgeServerMessage(decrypted, true);
      }
      console.warn('[WebSocket] PQ envelope decryption FAILED (returned null)', {
        hasReceivedFingerprint: typeof message.sessionFingerprint === 'string',
        hasReceivedSessionId: typeof message.sessionId === 'string',
        hasCurrentFingerprint: !!this.sessionKeyMaterial?.fingerprint,
        hasCurrentSession: !!this.sessionKeyMaterial?.sessionId
      });
      if (this.isGatekeeperFlowActive) {
        this.logGatekeeperDebug('pq-envelope-decrypt-failed', {
          hasReceivedSessionId: typeof message.sessionId === 'string',
          receivedSessionMatches: message.sessionId === this.sessionKeyMaterial?.sessionId,
          hasReceivedFingerprint: typeof message.sessionFingerprint === 'string',
          receivedFingerprintMatches: message.sessionFingerprint === this.sessionKeyMaterial?.fingerprint
        });
        this.dispatchToFrontend({
          type: SignalType.ERROR,
          code: 'SERVER_ENTRY_DECRYPT_FAILED',
          message: 'Failed to decrypt server entry response'
        }, true);
      }
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
      if (!this.isManualClose) {
        this.attemptReconnect();
      }
      return true;
    }

    if (messageType === '__ws_connection_error') {
      SecurityAuditLogger.log(SignalType.ERROR, 'ws-connection-error-from', { error: message.error });
      this.resetSessionKeys(this.isManualClose);
      this.lifecycleState = SignalType.ERROR;
      this.dispatchToFrontend(message, isSecure);
      if (!this.isManualClose) {
        this.attemptReconnect();
      }
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

    // Pass through to internal handlers
    if (messageType === SignalType.PQ_HEARTBEAT_PONG || this.messageHandler.hasHandler(messageType)) {
      if (this.isGatekeeperDebugType(messageType)) {
        this.logGatekeeperDebug('dispatching-internal-handler', {
          type: messageType,
          isSecure
        });
      }
      await this.messageHandler.handleMessage(message);
      if (this.isGatekeeperDebugType(messageType)) {
        this.logGatekeeperDebug('internal-handler-finished', {
          type: messageType,
          isSecure
        });
      }
      if (
        messageType === SignalType.SERVER_ENTRY_CHALLENGE ||
        messageType === SignalType.SERVER_ENTRY_TOKEN_ISSUANCE
      ) {
        this.dispatchToFrontend(message, isSecure);
      }

      if (messageType !== SignalType.ERROR && messageType !== SignalType.AUTH_ERROR) {
        return true;
      }
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

  private getMessageTypeForDebug(message: unknown): string {
    if (typeof message === 'string') {
      try {
        const parsed = JSON.parse(message);
        return typeof parsed?.type === 'string' ? parsed.type : 'raw-string';
      } catch {
        return 'raw-string';
      }
    }
    if (message && typeof message === 'object' && typeof (message as any).type === 'string') {
      return (message as any).type;
    }
    return typeof message;
  }

  private isGatekeeperDebugType(type: string): boolean {
    return this.isGatekeeperFlowActive || [
      SignalType.SERVER_ENTRY_REQUEST,
      SignalType.SERVER_ENTRY_CHALLENGE,
      SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
      SignalType.PRIVACY_PASS_REDEMPTION,
      SignalType.AUTH_OT_REGISTER_REQUEST,
      SignalType.AUTH_OT_REGISTER_RESPONSE,
      SignalType.AUTH_OT_REGISTER_FINALIZE,
      SignalType.AUTH_OT_REQUEST,
      SignalType.AUTH_OT_RESPONSE,
      SignalType.AUTH_OT_FINALIZE,
      SignalType.AUTH_FULL_SUCCESS,
      SignalType.PQ_ENVELOPE,
      SignalType.PQ_HANDSHAKE_ACK,
      SignalType.AUTH_ERROR,
      SignalType.ERROR
    ].includes(type as SignalType);
  }

  private logGatekeeperDebug(event: string, detail: Record<string, unknown> = {}): void {
    console.info('[GK-CLIENT]', event, {
      ...detail,
      lifecycleState: this.lifecycleState,
      gatekeeperFlowActive: this.isGatekeeperFlowActive,
      pqSessionEstablished: this.isPQSessionEstablished(),
      hasSessionId: !!this.sessionKeyMaterial?.sessionId,
      hasChallengeHandler: this.messageHandler.hasHandler(SignalType.SERVER_ENTRY_CHALLENGE),
      hasIssuanceHandler: this.messageHandler.hasHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE),
      hasAuthErrorHandler: this.messageHandler.hasHandler(SignalType.AUTH_ERROR),
      queueLength: this.queue.getQueueLength()
    });
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
    const minDelay = Math.max(500, WS_COVER_TRAFFIC_MIN_INTERVAL_MS);
    const maxDelay = Math.max(minDelay, WS_COVER_TRAFFIC_MAX_INTERVAL_MS);
    const delay = Math.floor(Math.random() * (maxDelay - minDelay + 1)) + minDelay;

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
    if (!this.isApplicationAuthReady()) return;

    this.coverTrafficInFlight = true;
    try {
      const state = await websocket.getState().catch(() => null);
      if (state && Number(state.queue_size || 0) > 0) {
        const now = Date.now();
        if (now - this.lastCoverBackpressureLogAt > 60000) {
          this.lastCoverBackpressureLogAt = now;
          console.info('[WebSocket] Skipping cover traffic while websocket writer is backlogged', {
            queueSize: state.queue_size
          });
        }
        return;
      }

      const { getBlindRoutingClient } = await import('../transport/blind-routing-client');
      const blindClient = getBlindRoutingClient(this.lastAuthUsername);
      const sealedEnvelope = blindClient.createCoverSealedEnvelope();

      await this.dispatchPayload({
        type: SignalType.BLIND_ROUTE,
        sealedEnvelope
      }, false, { isCoverTraffic: true });
    } catch {
    } finally {
      this.coverTrafficInFlight = false;
    }
  }

  // Connect to WebSocket
  async connect(options: ConnectOptions = {}): Promise<void> {
    const autoReconnectOnFailure = options.autoReconnectOnFailure !== false;

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

      try {
        this.torIntegration.ensureTorListener();

        if (!await this.torIntegration.ensureTorReadyAsync()) {
          throw new Error('Tor network not ready');
        }

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
        this.handleConnectionError(_error as Error, 'connect', { autoReconnect: autoReconnectOnFailure });
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
        await this.connectNativeTransport();
      }
    }

    this.lifecycleState = 'handshaking';
    this.metrics.lastConnectedAt = Date.now();
    this.metrics.consecutiveFailures = 0;
    this.reconnectAttempts = 0;
    this.reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;

    await this.bridgeReadyPromise;

    await this.performHandshake(false);

    let hasResumeTokenAvailable = false;
    try {
      const { hasResumeToken } = await import('../signals/resume-tokens');
      hasResumeTokenAvailable = await hasResumeToken();
    } catch { }
    try {
      const gkProbe = await this.getGatekeeper();
      console.log('[AUTOLOGIN] reopen connect decision', {
        unlinkedMode: this.isInUnlinkedMode,
        hasResumeTokenAvailable,
        gatekeeperHasTokens: gkProbe.hasTokens,
        gatekeeperCount: gkProbe.tokenCount
      });
    } catch { }

    // Always attempt automatic server-entry on (re)connect; redemption is a no-op when the gatekeeper
    // has no tokens. There is no stored access token any more — autologin is resume-pool only.
    {
      try {
        const gk = await this.getGatekeeper();
        if (gk.hasTokens) {
          let entryGranted = false;
          for (let attempt = 0; attempt < 2 && !entryGranted; attempt++) {
            const redemption = await gk.getRedemptionPayload();
            if (!redemption) break;
            await this.sendSecureControlMessage(redemption, { bypassStateCheck: true });
            const grantResult = await this.waitForServerEntryGrant(this.torIntegration.getAdaptedTimeout(10000));
            if (grantResult === 'granted') {
              entryGranted = true;
            } else if (grantResult === 'rejected') {
              // Explicit server rejection: this token is invalid/already spent, so
              // burn it and try a fresh one.
              try { await gk.commitPendingTokenUsage(); } catch { }
              if (attempt === 0) {
                console.warn('[WebSocket] Entry token rejected, retrying with fresh token');
                await new Promise(r => setTimeout(r, 300));
              }
            } else {
              // Transient timeout (no decryptable grant — usually a session reset
              // mid-redemption). Do NOT burn the token; release it for reuse and
              // stop churning this connection. A later reconnect retries once the
              // PQ session is stable.
              try { await gk.releasePendingTokenUsage(); } catch { }
              break;
            }
          }

          if (entryGranted) {
            await gk.commitPendingTokenUsage();
            this.serverAuthGranted = true;
            window.dispatchEvent(new CustomEvent(EventType.SERVER_ENTRY_GRANTED));
          }
        }
      } catch {
        console.warn('[WebSocket] Automatic entry token redemption failed');
      }
    }

    this.lifecycleState = 'connected';
    this.unlinkedSessionReady = false;

    // If in unlinked mode then reclaim inbox
    if (this.isInUnlinkedMode) {
      const deliveryReady = await this.ensureUnlinkedDeliveryReady();
      if (!deliveryReady) {
        this.scheduleDeliveryReadyRetry();
      }
    }

    this.registerSessionErrorHandler();
    this.queue.scheduleFlush();
    this.startConnectivityWatchdog();
    this.heartbeat.start();
    this.torIntegration.attachCircuitListener(() => { if (this.lifecycleState === 'connected') this.heartbeat.reset(); });
    void blockingSystem.processQueuedMessages();
  }

  // Claim inbox route on the current socket
  private async ensureUnlinkedDeliveryReady(): Promise<boolean> {
    if (!this.isInUnlinkedMode) return false;
    if (this.lifecycleState !== 'connected' || !this.sessionKeyMaterial) return false;
    try {
      const { getBlindRoutingClient } = await import('../transport/blind-routing-client');
      const bc = getBlindRoutingClient(this.lastAuthUsername);

      // Restore credentials from storage if not already in memory
      if (!bc.hasCredentials()) {
        await bc.loadPersistentCredentials();
      }

      // Reset send function for the new PQ session
      const self = this;
      bc.setSendFunction(async (message: any) => {
        await self.sendSecureControlMessage(message);
      });

      const claimTimeoutMs = this.torIntegration.getAdaptedTimeout(30000);
      let claimFailureReason = 'claim-timeout';

      // Wait for claim response before publishing bundle
      const waitForClaimResponse = new Promise<boolean>((resolve) => {
        const timeout = setTimeout(() => {
          window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
          window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as any);
          resolve(false);
        }, claimTimeoutMs);

        const handler = (ev: Event) => {
          const detail = (ev as CustomEvent).detail;
          if (detail?.type === SignalType.CLAIM_INBOX_RESPONSE) {
            clearTimeout(timeout);
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as any);
            claimFailureReason = detail?.error ? String(detail.error) : (detail?.success ? '' : 'claim-rejected');
            resolve(!!detail.success);
            return;
          }
          if (
            (detail?.type === SignalType.ERROR || detail?.type === SignalType.AUTH_ERROR)
            && typeof detail?.message === 'string'
          ) {
            const msg = detail.message.toLowerCase();
            if (msg.includes('claim') || msg.includes('inbox')) {
              clearTimeout(timeout);
              window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
              window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handler as any);
              claimFailureReason = detail.message;
              resolve(false);
            }
          }
        };
        window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
        window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handler as any);
      });

      const claimSent = await bc.claimInbox();
      if (!claimSent) {
        claimFailureReason = 'claim-send-skipped';
      }

      // Only wait for server response if the claim message was actually sent
      const claimSuccess = claimSent ? await waitForClaimResponse : false;

      if (claimSuccess) {
        // Prekey bundles are distributed via the discovery blob (and in-band) — there is no separate
        // server-side bundle publish. Keep driving automatic route rotation + its commitment event.
        bc.startAutomaticRouteRotation((rotation) => {
          try {
            window.dispatchEvent(new CustomEvent(EventType.ROUTE_COMMITMENTS_ROTATED, { detail: rotation }));
          } catch { }
        });

        this.unlinkedSessionReady = true;
        this.startCoverTraffic();
        window.dispatchEvent(new CustomEvent(EventType.UNLINKED_SESSION_READY));
        console.info('[DELIVERY] inbox claimed - socket is delivery-ready for global-mix broadcast', {
          retried: this.deliveryReadyRetryAttempts > 0
        });
        return true;
      }

      this.unlinkedSessionReady = false;
      console.warn('[DELIVERY] inbox claim failed/timed out - receiver will NOT get broadcast until re-claim', {
        reason: claimFailureReason,
        timeoutMs: claimTimeoutMs
      });
      return false;
    } catch {
      this.unlinkedSessionReady = false;
      console.warn('[WebSocket] Failed to claim inbox in unlinked mode');
      return false;
    }
  }

  // Retry the delivery ready inbox claim
  private scheduleDeliveryReadyRetry(): void {
    if (this.deliveryReadyRetryTimer) return;
    if (!this.isInUnlinkedMode) return;

    const attempt = this.deliveryReadyRetryAttempts++;
    const baseDelay = Math.min(3000 * Math.pow(1.6, attempt), 30000);
    const jitter = Math.floor(Math.random() * 1000);

    this.deliveryReadyRetryTimer = setTimeout(async () => {
      this.deliveryReadyRetryTimer = null;

      if (this.lifecycleState !== 'connected' || !this.sessionKeyMaterial) {
        return;
      }
      if (this.unlinkedSessionReady) {
        this.deliveryReadyRetryAttempts = 0;
        return;
      }

      const ready = await this.ensureUnlinkedDeliveryReady().catch(() => false);
      if (ready) {
        this.deliveryReadyRetryAttempts = 0;
      } else {
        this.scheduleDeliveryReadyRetry();
      }
    }, baseDelay + jitter);
  }

  private isNativeConnectionInProgress(error?: string): boolean {
    return typeof error === 'string' && error.toLowerCase().includes('connection in progress');
  }

  private async connectNativeTransport(): Promise<void> {
    let result = await websocket.connect();
    if (result?.success === false && this.isNativeConnectionInProgress(result.error)) {
      await new Promise(resolve => setTimeout(resolve, 500));
      const nativeState = await websocket.getState().catch(() => null);
      if (nativeState?.connected) {
        return;
      }
      if (nativeState?.connecting) {
        await websocket.disconnect().catch(() => { });
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      result = await websocket.connect();
    }

    if (result?.success === false) {
      throw new Error(result.error || 'Failed to establish WebSocket connection');
    }
  }

  // Register session error handler
  private registerSessionErrorHandler(): void {
    this.messageHandler.registerHandler(SignalType.ERROR, async (message: any) => {
      const errorMsg = message.message || '';
      if (message.code === 'ENVELOPE_TIMESTAMP_INVALID' || message.code === 'HANDSHAKE_TIMESTAMP_INVALID') {
        await this.recoverFromTimestampReject(message);
        return;
      }
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

  private async recoverFromTimestampReject(message: any): Promise<void> {
    this.updateServerClockOffset(message?.serverTime);

    if (this.timestampRecoveryInFlight) {
      return this.timestampRecoveryInFlight;
    }

    const now = Date.now();
    if (now - this.lastTimestampRecoveryAt < 3000) {
      return;
    }
    this.lastTimestampRecoveryAt = now;

    this.timestampRecoveryInFlight = (async () => {
      console.warn('[WebSocket] Server rejected a stale PQ envelope; reconnecting to drop queued ciphertext', {
        code: message?.code,
        replayWindowMs: message?.replayWindowMs
      });

      if (this.reconnectTimeout) {
        clearTimeout(this.reconnectTimeout);
        this.reconnectTimeout = null;
      }

      this.stopCoverTraffic();
      this.resetSessionKeys(true);
      this.encryption.clearReplayCache();
      this.handshake.reset();
      this.transportEventReceived = false;
      this.lifecycleState = 'disconnected';
      this.isManualClose = false;

      try {
        await websocket.disconnect().catch(() => { });
      } catch { }

      await new Promise(resolve => setTimeout(resolve, 250));
      await this.connect();
      try {
        const { hasResumeToken } = await import('../signals/resume-tokens');
        if (await hasResumeToken()) {
          await this.attemptTokenValidationOnce('timestamp-recovery', true);
        }
      } catch { }
      void this.queue.flush();
    })().finally(() => {
      this.timestampRecoveryInFlight = null;
    });

    return this.timestampRecoveryInFlight;
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
  handleConnectionError(error: Error, stage: string, options: { autoReconnect?: boolean } = {}): void {
    SecurityAuditLogger.log(SignalType.ERROR, `ws-${stage}-failure`, { message: error.message });
    this.metrics.lastFailureAt = Date.now();
    this.lifecycleState = SignalType.ERROR;
    this.resetSessionKeys(this.isManualClose);
    if (!this.isManualClose && options.autoReconnect !== false) this.attemptReconnect();
  }

  private ingestSecureChunk(chunk: any): any | null {
    const messageId = chunk?.messageId;
    const chunkIndex = chunk?.chunkIndex;
    const totalChunks = chunk?.totalChunks;
    const totalLength = chunk?.totalLength;
    const payloadType = chunk?.payloadType;
    const data = chunk?.data;

    if (typeof messageId !== 'string' || messageId.length === 0 || messageId.length > 128) return null;
    if (!Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > SECURE_CHUNK_MAX_TOTAL_CHUNKS) return null;
    if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= totalChunks) return null;
    if (!Number.isInteger(totalLength) || totalLength < 1 || totalLength > SECURE_CHUNK_MAX_TOTAL_LENGTH) return null;
    if (typeof payloadType !== 'string' || payloadType.length === 0 || payloadType.length > 100) return null;
    if (typeof data !== 'string' || data.length === 0 || data.length > SECURE_CHUNK_MAX_DATA_LENGTH) return null;

    let buf = this.secureChunkBuffers.get(messageId);
    if (!buf) {
      // Bound concurrent reassemblies by evicting oldest if at capacity.
      if (this.secureChunkBuffers.size >= SECURE_CHUNK_MAX_CONCURRENT) {
        let oldestKey: string | null = null;
        let oldestAt = Infinity;
        for (const [k, v] of this.secureChunkBuffers) {
          if (v.createdAt < oldestAt) { oldestAt = v.createdAt; oldestKey = k; }
        }
        if (oldestKey) {
          const ev = this.secureChunkBuffers.get(oldestKey);
          if (ev) clearTimeout(ev.timer);
          this.secureChunkBuffers.delete(oldestKey);
        }
      }
      const timer = setTimeout(() => {
        this.secureChunkBuffers.delete(messageId);
        console.warn('[SECURE-CHUNK] Reassembly timed out; discarded', { payloadType });
      }, SECURE_CHUNK_TIMEOUT_MS);
      buf = {
        totalChunks, totalLength, payloadType,
        parts: new Array(totalChunks), receivedCount: 0, receivedLength: 0,
        createdAt: Date.now(), timer
      };
      this.secureChunkBuffers.set(messageId, buf);
    } else if (buf.totalChunks !== totalChunks || buf.totalLength !== totalLength || buf.payloadType !== payloadType) {
      clearTimeout(buf.timer);
      this.secureChunkBuffers.delete(messageId);
      console.warn('[SECURE-CHUNK] Inconsistent chunk metadata; discarded', { payloadType });
      return null;
    }

    // Idempotent placement (a duplicate index is ignored; a different value at a filled index drops).
    const existing = buf.parts[chunkIndex];
    if (existing === undefined) {
      if (buf.receivedLength + data.length > buf.totalLength) {
        clearTimeout(buf.timer);
        this.secureChunkBuffers.delete(messageId);
        console.warn('[SECURE-CHUNK] Accumulated length exceeds declared total; discarded', { payloadType });
        return null;
      }
      buf.parts[chunkIndex] = data;
      buf.receivedCount += 1;
      buf.receivedLength += data.length;
      
      if (typeof window !== 'undefined') {
        try {
          window.dispatchEvent(new CustomEvent(EventType.SECURE_CHUNK_PROGRESS, {
            detail: { payloadType: buf.payloadType, received: buf.receivedCount, total: buf.totalChunks }
          }));
        } catch { }
      }
    } else if (existing !== data) {
      clearTimeout(buf.timer);
      this.secureChunkBuffers.delete(messageId);
      console.warn('[SECURE-CHUNK] Conflicting duplicate chunk. discarded', { payloadType });
      return null;
    }

    if (buf.receivedCount < buf.totalChunks) return null;

    clearTimeout(buf.timer);
    this.secureChunkBuffers.delete(messageId);

    for (let i = 0; i < buf.totalChunks; i++) {
      if (typeof buf.parts[i] !== 'string') {
        console.warn('[SECURE-CHUNK] Missing part at completion. discarded', { payloadType });
        return null;
      }
    }
    const full = buf.parts.join('');
    if (full.length !== buf.totalLength) {
      console.warn('[SECURE-CHUNK] Reassembled length mismatch. discarded', { expected: buf.totalLength, got: full.length });
      return null;
    }

    let parsed: any;
    try {
      parsed = JSON.parse(full);
    } catch {
      console.warn('[SECURE-CHUNK] Reassembled JSON parse failed. discarded', { payloadType });
      return null;
    }
    if (!isPlainObject(parsed) || hasPrototypePollutionKeys(parsed)) {
      console.warn('[SECURE-CHUNK] Reassembled object invalid. discarded', { payloadType });
      return null;
    }
    if (typeof parsed.type !== 'string' || parsed.type !== buf.payloadType) {
      console.warn('[SECURE-CHUNK] Reassembled type mismatch. discarded', { payloadType });
      return null;
    }
    return parsed;
  }

  // Drop all inflight reassemblies
  private clearSecureChunkBuffers(): void {
    for (const buf of this.secureChunkBuffers.values()) {
      try { clearTimeout(buf.timer); } catch { }
    }
    this.secureChunkBuffers.clear();
  }

  resetSessionKeys(preserveServerKeys: boolean = true): void {
    this.tokenValidationAttempted = false;
    this.serverAuthGranted = false;
    this.applicationAuthReady = false;
    this.unlinkedSessionReady = false;
    if (this.deliveryReadyRetryTimer) {
      clearTimeout(this.deliveryReadyRetryTimer);
      this.deliveryReadyRetryTimer = null;
    }
    this.deliveryReadyRetryAttempts = 0;
    this.stopCoverTraffic();
    if (this.sessionKeyMaterial) {
      PostQuantumUtils.clearMemory(this.sessionKeyMaterial.sendKey);
      PostQuantumUtils.clearMemory(this.sessionKeyMaterial.recvKey);
    }
    this.sessionKeyMaterial = undefined;
    this.pendingReconnectEnvelopes = [];
    this.clearSecureChunkBuffers();
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
    if (this.reconnectTimeout) return;

    this.reconnectAttempts += 1;
    this.metrics.totalReconnects += 1;
    this.metrics.consecutiveFailures += 1;
    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);

    const jitterBytes = PostQuantumRandom.randomBytes(4);
    const jitterValue = ((jitterBytes[0]! << 24) >>> 0) ^ (jitterBytes[1]! << 16) ^ (jitterBytes[2]! << 8) ^ jitterBytes[3]!;
    const jitterMs = Math.floor((jitterValue / 0xffffffff) * 500);
    const delayWithJitter = this.reconnectDelayMs + jitterMs;

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      void this.connect().catch((e) => this.handleConnectionError(e as Error, 'connect-retry'));
    }, delayWithJitter);
  }

  // Send data
  send(data: unknown): void {
    void this.dispatchPayload(data, true).catch((err) => {
      console.error('[WebSocket] Send failed:', err);
    });
  }

  private runOnSecureSendLane<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.secureSendLane.then(operation, operation);
    this.secureSendLane = run.then(() => undefined, () => undefined);
    return run;
  }

  // Dispatch payload
  async dispatchPayload(data: unknown, allowQueue: boolean, options: { isCoverTraffic?: boolean, bypassStateCheck?: boolean } = {}): Promise<void> {
    const msgObj = typeof data === 'string' ? ((): any => { try { return JSON.parse(data); } catch { return {}; } })() : (data as any);
    const debugType = typeof msgObj?.type === 'string' ? msgObj.type : this.getMessageTypeForDebug(data);

    if (this.isGatekeeperDebugType(debugType)) {
      this.logGatekeeperDebug('dispatch-payload-start', {
        type: debugType,
        allowQueue,
        bypassStateCheck: !!options.bypassStateCheck,
        isCoverTraffic: !!options.isCoverTraffic
      });
    }

    // Identity leak protection for unlinked mode
    if (this.isInUnlinkedMode) {
      if (
        msgObj.type === SignalType.TOKEN_VALIDATION ||
        msgObj.username
      ) {
        console.warn(`[WebSocket] Blocking account-linked message in unlinked mode: ${msgObj.type || 'unknown'}`);
        return;
      }
    }


    if (!this.rateLimiter.checkRateLimit()) {
      if (allowQueue) {
        this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + RATE_LIMIT_BACKOFF_MS));
      } else {
        throw new Error('WebSocket local rate limit exceeded');
      }
      return;
    }

    if (this.isGloballyRateLimited()) {
      const remainingMs = this.globalRateLimitUntil - Date.now();
      const remainingSeconds = Math.max(1, Math.ceil(remainingMs / 1000));
      let msgType = '';
      if (typeof data === 'string') { try { msgType = JSON.parse(data)?.type || ''; } catch { } }
      else if (typeof data === 'object' && data !== null) { msgType = (data as any)?.type || ''; }

      const isAuthMessage = [
        'account-sign-in',
        'account-sign-up',
        'server-entry-request',
        SignalType.AUTH_OT_REGISTER_REQUEST,
        SignalType.AUTH_OT_REGISTER_FINALIZE,
        SignalType.AUTH_OT_REQUEST,
        SignalType.AUTH_OT_FINALIZE,
        SignalType.SERVER_ENTRY_REQUEST,
        SignalType.PRIVACY_PASS_REDEMPTION
      ].includes(msgType as SignalType);
      if (isAuthMessage) {
        try { window.dispatchEvent(new CustomEvent(EventType.AUTH_RATE_LIMITED, { detail: { remainingSeconds, rateLimitUntil: this.globalRateLimitUntil } })); } catch { }
        if (!allowQueue) {
          throw new Error(`Authentication send rate limited for ${remainingSeconds}s`);
        }
        return;
      }
      if (allowQueue) {
        this.queue.enqueuePending(this.queue.createEntry(data, this.globalRateLimitUntil));
      } else {
        throw new Error(`WebSocket globally rate limited for ${remainingSeconds}s`);
      }
      return;
    }

    if (this.lifecycleState !== 'connected' && !options.bypassStateCheck) {
      if (this.isGatekeeperDebugType(debugType)) {
        this.logGatekeeperDebug('dispatch-payload-queued-not-connected', {
          type: debugType,
          allowQueue
        });
      }
      if (allowQueue) this.queue.enqueuePending(this.queue.createEntry(data, Date.now()));
      else throw new Error('WebSocket not connected');
      return;
    }

    if (!this.torIntegration.isCircuitHealthy()) {
      const circuitHealth = this.torIntegration.getCircuitHealth();
      if (this.isGatekeeperDebugType(debugType)) {
        this.logGatekeeperDebug('dispatch-payload-blocked-tor-circuit', {
          type: debugType,
          circuitHealth,
          allowQueue
        });
      }
      if (allowQueue) {
        this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + 5000));
      } else {
        throw new Error(`Tor circuit is not healthy enough to send ${debugType} (${circuitHealth})`);
      }
      return;
    }

    if (options.isCoverTraffic) {
      const state = await websocket.getState().catch(() => null);
      if (state && Number(state.queue_size || 0) > 0) {
        return;
      }
    }

    try {
      await this.runOnSecureSendLane(async () => {
        if (this.lifecycleState !== 'connected' && !options.bypassStateCheck) {
          throw new Error('WebSocket not connected');
        }

        await this.ensureSessionKeys(false);
        if (!this.sessionKeyMaterial) {
          throw new Error('Post-quantum session not established');
        }

        if (this.isGatekeeperDebugType(debugType)) {
          this.logGatekeeperDebug('dispatch-payload-encrypting', {
            type: debugType
          });
        }
        const message = await this.encryption.prepareSecureEnvelope(data);
        this.metrics.messagesSent += 1;
        this.metrics.bytesSent += message.length;
        await this.transmit(message);
        if (this.isGatekeeperDebugType(debugType)) {
          this.logGatekeeperDebug('dispatch-payload-transmitted', {
            type: debugType,
            bytes: message.length
          });
        }
      });
    } catch (err: any) {
      const reason = err instanceof Error ? err.message : String(err);
      if (this.isGatekeeperDebugType(debugType)) {
        this.logGatekeeperDebug('dispatch-payload-error', {
          type: debugType,
          error: reason
        });
      }
      const isSessionNotReady =
        reason.includes('Post-quantum session not established') ||
        reason.includes('PQ session not established');
      const isSigningBindingMismatch = reason.includes('PQ session signing key binding mismatch');

      if ((isSessionNotReady || isSigningBindingMismatch) && allowQueue) {
        if (isSigningBindingMismatch) {
          this.resetSessionKeys();
        }
        this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + 500));
        void this.performHandshake(isSigningBindingMismatch).catch(() => { });
        return;
      }

      throw err;
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
    await this.transmit(JSON.stringify({ type: SignalType.PQ_HEARTBEAT_PING, timestamp: Date.now(), sessionId: this.sessionKeyMaterial?.sessionId }));
  }

  markServerAuthGranted(): void {
    this.serverAuthGranted = true;
  }

  isServerAuthGranted(): boolean {
    return this.serverAuthGranted;
  }

  markApplicationAuthReady(): void {
    this.applicationAuthReady = true;
    this.startCoverTraffic();
  }

  isApplicationAuthReady(): boolean {
    return this.applicationAuthReady || (this.isInUnlinkedMode && this.unlinkedSessionReady);
  }

  isUnlinkedSessionReady(): boolean {
    return this.unlinkedSessionReady;
  }

  async transmit(message: string): Promise<void> {
    if (this.isManualClose) {
      console.warn('[WebSocket] Suppressing transmit during manual close to avoid write errors', { messageLength: message.length });
      throw new Error('WebSocket is manually closing');
    }
    try {
      const result = await websocket.send(message);
      if (result?.success === false) {
        throw new Error(result.error || 'Unknown error');
      }
    } catch (err: any) {
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
  unregisterMessageHandler(type: string, handler?: MessageHandler): void { this.messageHandler.unregisterHandler(type, handler); }

  // Note heartbeat pong
  noteHeartbeatPong(message: any): void { this.heartbeat.handleResponse(message); }

  // Attempt token validation once
  async attemptTokenValidationOnce(
    _source: string = 'auto',
    force: boolean = false,
    requestExtras: Record<string, unknown> = {}
  ): Promise<void> {
    if (this.isInUnlinkedMode) return;
    if (this.tokenValidationAttempted && !force) return;
    this.tokenValidationAttempted = true;

    try {
      // redeem a fresh one time anonymous token
      const { takeResumeRedemption } = await import('../signals/resume-tokens');
      const resumeRedemption = await takeResumeRedemption();

      if (!resumeRedemption) {
        this.tokenValidationAttempted = false;
        return;
      }

      if (!this.isPQSessionEstablished() && this.lifecycleState === 'connected') {
        try {
          await this.performHandshake(false);
        } catch {
        }
      }

      await this.sendSecureControlMessage({
        type: SignalType.TOKEN_VALIDATION,
        resumeRedemption,
        ...requestExtras
      });
    } catch (_err) {
      this.tokenValidationAttempted = false;
      console.warn('[WebSocket] Token validation send failed', {
        source: _source,
        error: _err instanceof Error ? _err.message : String(_err)
      });
    }
  }

  /**
   * Switch to unlinked mode
   */
  async switchToUnlinkedMode(): Promise<void> {
    this.isInUnlinkedMode = true;

    if (this.lifecycleState === 'connected' && this.unlinkedSessionReady) {
      return;
    }

    // Disconnect with reset
    await this.close();

    const jitter = 500 + Math.random() * 1500;
    await new Promise(resolve => setTimeout(resolve, jitter));

    // Reconnect
    await this.connect();
    if (!this.unlinkedSessionReady) {
      throw new Error('Unlinked session not ready after switch');
    }
  }

  /**
   * Start the server gatekeeper flow to get entry tokens
   */
  async startServerGatekeeperFlow(password: string, onProgress?: (status: string) => void): Promise<boolean> {
    if (this.isGatekeeperFlowActive) {
      console.warn('[WebSocket] Gatekeeper flow already active, ignoring request');
      return false;
    }
    this.isGatekeeperFlowActive = true;

    try {
      if (onProgress) onProgress("Initializing gatekeeper...");
      const gk = await this.getGatekeeper();
      if (onProgress) onProgress("Preparing entry request...");
      const request = await gk.startEntryRequest(password);

      const challengeTimeoutMs = this.torIntegration.getAdaptedTimeout(10000);
      const responsePromise = new Promise<any>((resolve, reject) => {
        let timeout: ReturnType<typeof setTimeout>;
        let settled = false;

        const cleanup = () => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_CHALLENGE, onChallenge);
          this.messageHandler.unregisterHandler(SignalType.AUTH_ERROR, onGatekeeperError);
          if (typeof window !== 'undefined') {
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
          }
        };

        const onGatekeeperError = async (msg: any) => {
          if (settled) return;
          settled = true;
          console.warn('[GK-FLOW] Error received during challenge wait:', msg.message || msg.code);
          cleanup();
          reject(new Error(msg.message || 'Authentication error'));
        };

        const onChallenge = async (msg: any) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(msg);
        };

        const onGatekeeperEvent = (ev: Event) => {
          const detail = (ev as CustomEvent).detail;
          if (detail?.type === SignalType.SERVER_ENTRY_CHALLENGE) {
            void onChallenge(detail);
          } else if (detail?.type === SignalType.AUTH_ERROR || detail?.type === SignalType.ERROR) {
            void onGatekeeperError(detail);
          }
        };

        timeout = setTimeout(() => {
          if (settled) return;
          settled = true;
          this.logGatekeeperDebug('challenge-timeout-state', {
            timeoutMs: challengeTimeoutMs
          });
          cleanup();
          reject(new Error('Gatekeeper challenge timeout'));
        }, challengeTimeoutMs);

        this.messageHandler.registerHandler(SignalType.AUTH_ERROR, onGatekeeperError);
        this.messageHandler.registerHandler(SignalType.SERVER_ENTRY_CHALLENGE, onChallenge);
        if (typeof window !== 'undefined') {
          window.addEventListener(EventType.EDGE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
          window.addEventListener(EventType.SECURE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
        }
        this.logGatekeeperDebug('challenge-wait-registered', {
          timeoutMs: challengeTimeoutMs
        });
      });

      if (onProgress) onProgress("Verifying challenge...");
      await this.sendSecureControlMessage(request);
      const challenge = await responsePromise;

      if (onProgress) onProgress("Requesting tokens...");
      // Prepare issuance
      const issuanceRequest = await gk.prepareTokenIssuance(password, {
        evaluatedElement: Base64.base64ToUint8Array(challenge.evaluatedElement),
        serverNonce: Base64.base64ToUint8Array(challenge.serverNonce),
        envelope: Base64.base64ToUint8Array(challenge.envelope),
        maskedResponse: Base64.base64ToUint8Array(challenge.maskedResponse),
        salt: challenge.salt ? Base64.base64ToUint8Array(challenge.salt) : undefined
      });
      console.log('[GK-FLOW] Step 3 complete: token issuance prepared (password correct)');

      const issuanceTimeoutMs = this.torIntegration.getAdaptedTimeout(15000);
      const issuancePromise = new Promise<any>((resolve, reject) => {
        let timeout: ReturnType<typeof setTimeout>;
        let settled = false;

        const cleanup = () => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE, onIssuance);
          this.messageHandler.unregisterHandler(SignalType.AUTH_ERROR, onGatekeeperError);
          if (typeof window !== 'undefined') {
            window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
            window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
          }
        };

        const onGatekeeperError = async (msg: any) => {
          if (settled) return;
          settled = true;
          console.warn('[GK-FLOW] Error received during issuance wait:', msg.message || msg.code);
          cleanup();
          reject(new Error(msg.message || 'Authentication error'));
        };

        const onIssuance = async (msg: any) => {
          if (settled) return;
          settled = true;
          console.log('[GK-FLOW] Step 4: SERVER_ENTRY_TOKEN_ISSUANCE received');
          cleanup();
          resolve(msg);
        };

        const onGatekeeperEvent = (ev: Event) => {
          const detail = (ev as CustomEvent).detail;
          if (detail?.type === SignalType.SERVER_ENTRY_TOKEN_ISSUANCE) {
            void onIssuance(detail);
          } else if (detail?.type === SignalType.AUTH_ERROR || detail?.type === SignalType.ERROR) {
            void onGatekeeperError(detail);
          }
        };

        timeout = setTimeout(() => {
          if (settled) return;
          settled = true;
          console.error('[GK-FLOW] no issuance received before timeout');
          this.logGatekeeperDebug('issuance-timeout-state', {
            timeoutMs: issuanceTimeoutMs
          });
          cleanup();
          reject(new Error('Token issuance timeout'));
        }, issuanceTimeoutMs);

        this.messageHandler.registerHandler(SignalType.AUTH_ERROR, onGatekeeperError);
        this.messageHandler.registerHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE, onIssuance);
        if (typeof window !== 'undefined') {
          window.addEventListener(EventType.EDGE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
          window.addEventListener(EventType.SECURE_SERVER_MESSAGE, onGatekeeperEvent as EventListener);
        }
        this.logGatekeeperDebug('issuance-wait-registered', {
          timeoutMs: issuanceTimeoutMs
        });
      });

      if (onProgress) onProgress("Issuing entry tokens...");
      await this.sendSecureControlMessage(issuanceRequest);
      const tokenBatch = await issuancePromise;

      if (onProgress) onProgress("Finalizing entry...");
      // Step 3: Finalize
      await gk.finalizeEntry(
        tokenBatch.signedBlindedTokens.map((t: string) => Base64.base64ToUint8Array(t)),
        Base64.base64ToUint8Array(tokenBatch.proof),
        Base64.base64ToUint8Array(tokenBatch.publicKey)
      );
      console.log('[GK-FLOW] Step 5: Tokens finalized, redeeming...');

      // Auto-redeem to fully establish connection
      const redemption = await gk.getRedemptionPayload();
      if (redemption) {
        await this.sendSecureControlMessage(redemption);
        const grantResult = await this.waitForServerEntryGrant(this.torIntegration.getAdaptedTimeout(10000));
        if (grantResult !== 'granted') {
          console.error('[GK-FLOW] server entry grant not received', { grantResult });
          // Burn only on an explicit rejection; a transient timeout keeps the
          // freshly-issued token for reuse instead of leaking it as stuck-pending.
          try {
            if (grantResult === 'rejected') await gk.commitPendingTokenUsage();
            else await gk.releasePendingTokenUsage();
          } catch { }
          return false;
        }
        await gk.commitPendingTokenUsage();
        this.serverAuthGranted = true;
        window.dispatchEvent(new CustomEvent(EventType.SERVER_ENTRY_GRANTED));
      }

      return true;
    } catch (error) {
      console.error('[GK-FLOW] FLOW FAILED at:', error);
      const message = error instanceof Error ? error.message : String(error);
      if (/invalid server password|incorrect password|failed to derive server entry proof/i.test(message)) {
        return false;
      }
      throw error;
    } finally {
      this.isGatekeeperFlowActive = false;
    }
  }

  private waitForServerEntryGrant(timeoutMs: number = 5000): Promise<'granted' | 'rejected' | 'timeout'> {
    return new Promise<'granted' | 'rejected' | 'timeout'>((resolve) => {
      const cleanup = () => {
        clearTimeout(timeout);
        window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
      };

      const timeout = setTimeout(() => {
        cleanup();
        resolve('timeout');
      }, timeoutMs);

      const handler = (ev: Event) => {
        const detail = (ev as CustomEvent).detail;
        if (detail?.type === 'ok') {
          cleanup();
          resolve('granted');
        } else if (detail?.type === 'auth-error' || detail?.type === 'error') {
          console.warn('[WebSocket] Server entry grant rejected:', detail.message || detail.code || 'unknown');
          cleanup();
          resolve('rejected');
        }
      };

      window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
    });
  }

  // Close connection
  async close(options: { killSession?: boolean } = {}): Promise<void> {
    this.isManualClose = true;
    this.lifecycleState = 'idle';
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.messageHandler.clearHandlers();
    this.globalRateLimitUntil = 0;
    this.queue.clear();
    
    if (options.killSession) {
      this.resetSessionKeys(false);
      this.encryption.clearReplayCache();
    } else {
      this.resetSessionKeys(true);
    }
    this.stopConnectivityWatchdog();
    this.heartbeat.stop();
    this.torIntegration.cleanup();
    this.rateLimiter.reset();
    this.connectionStateCallbacks.clear();
    this.handshake.reset();
    try {
      const { getBlindRoutingClient } = await import('../transport/blind-routing-client');
      getBlindRoutingClient(this.lastAuthUsername).stopAutomaticRouteRotation();
    } catch { }

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

  // Wait until the socket is fully connected with an established PQ session
  async waitUntilReady(timeoutMs: number = 30000): Promise<boolean> {
    const ready = () => this.isConnectedToServer() && this.isPQSessionEstablished();
    if (ready()) return true;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      await new Promise(resolve => setTimeout(resolve, 150));
      if (ready()) return true;
    }
    return ready();
  }

  // Send secure control message
  async sendSecureControlMessage(
    message: any,
    options: { bypassStateCheck?: boolean; failIfQueued?: boolean } = {}
  ): Promise<void> {
    const controlType = this.getMessageTypeForDebug(message);
    if (this.isGatekeeperDebugType(controlType)) {
      this.logGatekeeperDebug('send-secure-control-start', {
        type: controlType,
        bypassStateCheck: !!options.bypassStateCheck,
        failIfQueued: !!options.failIfQueued
      });
    }

    if (!this.isPQSessionEstablished()) {
      if (this.lifecycleState === 'connected' || options.bypassStateCheck) {
        try {
          if (this.isGatekeeperDebugType(controlType)) {
            this.logGatekeeperDebug('send-secure-control-performing-handshake', {
              type: controlType
            });
          }
          await this.performHandshake(false);
        } catch {
        }
      }
      if (this.lifecycleState !== 'connected' && !options.bypassStateCheck) {
        if (this.isGatekeeperDebugType(controlType)) {
          this.logGatekeeperDebug('send-secure-control-queued-not-connected', {
            type: controlType
          });
        }
        if (options.failIfQueued) {
          throw new Error('WebSocket not connected');
        }
        this.queue.enqueuePending({ ...this.queue.createEntry(message, Date.now()), highPriority: true });
        return;
      }
      const maxWaitTime = 10000;
      const startTime = Date.now();
      while (!this.isPQSessionEstablished() && (Date.now() - startTime) < maxWaitTime) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      if (!this.isPQSessionEstablished()) {
        if (this.isGatekeeperDebugType(controlType)) {
          this.logGatekeeperDebug('send-secure-control-queued-no-session', {
            type: controlType,
            waitedMs: Date.now() - startTime
          });
        }
        if (options.failIfQueued) {
          throw new Error('PQ session not established');
        }
        this.queue.enqueuePending({ ...this.queue.createEntry(message, Date.now() + 500), highPriority: true });
        void this.performHandshake(false).catch(() => { });
        return;
      }
    }
    if (this.isGatekeeperDebugType(controlType)) {
      this.logGatekeeperDebug('send-secure-control-dispatching', {
        type: controlType
      });
    }
    await this.dispatchPayload(typeof message === 'string' ? message : JSON.stringify(message), !options.failIfQueued, options);
  }

  // Set server key material
  setServerKeyMaterial(
    hybridKeys: { kyberPublicBase64: string; dilithiumPublicBase64?: string; x25519PublicBase64?: string },
    serverId?: string
  ): void {
    try {
      if (!hybridKeys?.kyberPublicBase64 || !hybridKeys?.dilithiumPublicBase64 || !hybridKeys?.x25519PublicBase64) {
        throw new Error('Incomplete server key material for authenticated PQ transport');
      }
      const kyberPublicKey = PostQuantumUtils.base64ToUint8Array(hybridKeys.kyberPublicBase64);
      const dilithiumPublicKey = PostQuantumUtils.base64ToUint8Array(hybridKeys.dilithiumPublicBase64);
      const x25519PublicKey = PostQuantumUtils.base64ToUint8Array(hybridKeys.x25519PublicBase64);
      const fingerprint = this.handshake.computeServerFingerprint({ kyber: hybridKeys.kyberPublicBase64, dilithium: hybridKeys.dilithiumPublicBase64, x25519: hybridKeys.x25519PublicBase64 });
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

  async decryptIncomingEnvelope(envelope: any): Promise<any | null> { return this.encryption.decryptEnvelope(envelope); }
  async flushPendingQueue(): Promise<void> { return this.queue.flush(); }
}

const websocketClient = new WebSocketConnection();
export default websocketClient;
