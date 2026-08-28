/**
 * WebSocket Connection Manager
 */

import { PostQuantumUtils } from '../utils/pq-utils';
import { PostQuantumRandom } from '../cryptography/random';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { hasExactKeys, isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import { PinnedServer } from '../utils/auth-utils';
import type { MessageHandler, ServerKeyMaterial, SessionKeyMaterial } from '../types/websocket-types';
import {
  INITIAL_RECONNECT_DELAY_MS,
  MAX_RECONNECT_DELAY_MS,
  RATE_LIMIT_BACKOFF_MS,
  SESSION_REKEY_INTERVAL_MS,
  WS_COVER_TRAFFIC_MIN_INTERVAL_MS,
  WS_COVER_TRAFFIC_MAX_INTERVAL_MS,
  KYBER_PUBLIC_KEY_LENGTH,
  DILITHIUM_PUBLIC_KEY_LENGTH,
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
import { Base64, decodeCanonicalBase64 as decodeBase64 } from '../cryptography/base64';
import { solvePowChallenge } from '../cryptography/proof-of-work';
import { getCurrentServerScope } from '../security/local-account-scope';
import { getBlindRoutingClient } from '../transport/blind-routing-client';
import { replenishResumePool, takeResumeRedemption } from '../signals/resume-tokens';
import { tokenVault } from '../database/token-vault';
import {
  createAuthChannelBinding,
} from '../../../shared/auth-channel-binding.js';
import { REQUEST_ID_RE } from '../../../shared/patterns.js';

interface ConnectOptions {
  autoReconnectOnFailure?: boolean;
}

interface DispatchOptions {
  isCoverTraffic?: boolean;
  bypassStateCheck?: boolean;
  signal?: AbortSignal;
  authBindingRequestId?: string;
}

interface SecureControlSendOptions extends DispatchOptions {
  failIfQueued?: boolean;
}

const SERVER_ENTRY_GRANT_BASE_TIMEOUT_MS = 30_000;

const SECURE_CHUNK_MAX_TOTAL_CHUNKS = 128;
const SECURE_CHUNK_MAX_TOTAL_LENGTH = 24 * 1024 * 1024;
const SECURE_CHUNK_MAX_DATA_LENGTH = 8 * 1024 * 1024;
const SECURE_CHUNK_MAX_CONCURRENT = 4;
const SECURE_CHUNK_MAX_RESERVED_LENGTH = 32 * 1024 * 1024;
const SECURE_CHUNK_MESSAGE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const WS_INBOUND_PENDING_MAX_COUNT = 128;
const WS_INBOUND_PENDING_MAX_BYTES = 24 * 1024 * 1024;
const AUTH_CHANNEL_BOUND_REQUEST_FIELDS = new Map<string, 'authRequestId' | 'requestId'>([
  [SignalType.AUTH_OT_REQUEST, 'authRequestId'],
  [SignalType.SERVER_ENTRY_REQUEST, 'requestId'],
]);
const NON_QUEUEABLE_CONTROL_TYPES = new Set<string>([
  SignalType.AUTH_OT_REGISTER_REQUEST,
  SignalType.AUTH_OT_REGISTER_FINALIZE,
  SignalType.AUTH_OT_REGISTER_CONFIRM,
  SignalType.AUTH_OT_REQUEST,
  SignalType.AUTH_OT_FINALIZE,
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
  SignalType.ACCOUNT_AUTH_TOKEN_REFRESH,
  SignalType.PRIVACY_PASS_REDEMPTION,
  SignalType.TOKEN_VALIDATION,
  SignalType.ACTIVATE_DELIVERY,
]);
const AUTHORIZED_TOKEN_REFRESH_BASE_TIMEOUT_MS = 45_000;
const ACCOUNT_AUTH_REPLACEMENT_BATCH_SIZE = 1;
const SECURE_CHUNK_TIMEOUT_MS = 200_000;
const PLAINTEXT_WIRE_TYPES = new Set<string>([
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.PQ_HANDSHAKE_ACK,
  SignalType.PQ_ENVELOPE
]);
const UNLINKED_FORBIDDEN_ACCOUNT_TYPES = new Set<string>([
  SignalType.AUTH_OT_REGISTER_REQUEST,
  SignalType.AUTH_OT_REGISTER_FINALIZE,
  SignalType.AUTH_OT_REGISTER_CONFIRM,
  SignalType.AUTH_OT_REQUEST,
  SignalType.AUTH_OT_FINALIZE,
  SignalType.SERVER_ENTRY_REQUEST,
  SignalType.SERVER_ENTRY_TOKEN_ISSUANCE
]);
const LINKED_FORBIDDEN_ANONYMOUS_TYPES = new Set<string>([
  SignalType.TOKEN_VALIDATION,
  SignalType.ACTIVATE_DELIVERY,
  SignalType.BLIND_ROUTE,
  SignalType.OPRF_DISCOVERY_PUBLIC_KEY,
  SignalType.PUBLISH_DISCOVERY
]);

function operationAbortError(message = 'WebSocket operation was cancelled'): Error {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

function throwIfOperationAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw operationAbortError();
}

function waitForAbortableDelay(delayMs: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(operationAbortError());
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      if (error) reject(error);
      else resolve();
    };
    const onAbort = () => finish(operationAbortError());
    const timer = setTimeout(() => finish(), Math.max(0, delayMs));
    signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

export type ResumeAuthorizationResponse = Readonly<
  | {
    type: SignalType.TOKEN_VALIDATION_RESPONSE;
    requestId: string;
    valid: true;
    serverEntryRequired: boolean;
    serverEntryGranted: boolean;
  }
  | {
    type: SignalType.TOKEN_VALIDATION_RESPONSE;
    requestId: string;
    valid: false;
    error: string;
  }
>;

export class UnlinkedAuthorizationError extends Error {
  readonly response: ResumeAuthorizationResponse;

  constructor(response: ResumeAuthorizationResponse) {
    super(response.valid ? 'Server entry is required' : 'Anonymous session authorization was rejected');
    this.name = 'UnlinkedAuthorizationError';
    this.response = response;
  }
}

const isTokenValidationResponse = (value: unknown): value is ResumeAuthorizationResponse => {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) return false;
  if (
    value.type !== SignalType.TOKEN_VALIDATION_RESPONSE ||
    typeof value.valid !== 'boolean' ||
    typeof value.requestId !== 'string' ||
    !REQUEST_ID_RE.test(value.requestId)
  ) return false;
  if (value.valid) {
    return hasExactKeys(value, ['requestId', 'type', 'valid', 'serverEntryRequired', 'serverEntryGranted']) &&
      typeof value.serverEntryRequired === 'boolean' &&
      typeof value.serverEntryGranted === 'boolean' &&
      value.serverEntryRequired !== value.serverEntryGranted;
  }
  return hasExactKeys(value, ['error', 'requestId', 'type', 'valid']) &&
    typeof value.error === 'string' &&
    value.error.length > 0 &&
    value.error.length <= 128;
};

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

interface InboundWsMessage {
  payload: unknown;
  bytes: number;
  generation: number;
  connectionToken: number;
}

interface OutboundTransportContext {
  connectionToken: number | null;
  operationGeneration: number;
  isInUnlinkedMode: boolean;
  username?: string;
}

interface PrivacyBoundaryTransition {
  targetMode: 'linked' | 'unlinked';
  promise: Promise<unknown>;
}

const secureRandomUnit = (): number => {
  const word = globalThis.crypto.getRandomValues(new Uint32Array(1))[0];
  return word / 0x1_0000_0000;
};

const secureRandomIntInclusive = (min: number, max: number): number => {
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || max < min) return min;
  return min + Math.floor(secureRandomUnit() * (max - min + 1));
};

const isNativeWsConnectionToken = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;

const decodeServerResponseBase64 = (value: unknown, expectedLength: number): Uint8Array =>
  decodeBase64(value, 'server response encoding', { exactBytes: expectedLength });

const decodeCanonicalBase64List = (
  values: unknown,
  expectedLength: number,
  maxItems: number
): Uint8Array[] => {
  if (!Array.isArray(values) || values.length < 1 || values.length > maxItems) {
    throw new Error('Invalid server response batch');
  }
  const decoded: Uint8Array[] = [];
  try {
    for (const value of values) decoded.push(decodeServerResponseBase64(value, expectedLength));
    return decoded;
  } catch (error) {
    for (const value of decoded) value.fill(0);
    throw error;
  }
};

interface ServerKeyBootstrap {
  type: SignalType.SERVER_PUBLIC_KEY;
  serverId: string;
  serverTime: number;
  requiresServerPassword: boolean;
  hybridKeys: {
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
    x25519PublicBase64: string;
  };
}

const parseServerKeyBootstrap = (value: unknown): ServerKeyBootstrap | null => {
  if (!isPlainObject(value) || hasPrototypePollutionKeys(value)) return null;
  if (
    Object.keys(value).sort().join(',') !== 'hybridKeys,requiresServerPassword,serverId,serverTime,type' ||
    value.type !== SignalType.SERVER_PUBLIC_KEY ||
    typeof value.serverId !== 'string' ||
    !/^[A-Za-z0-9._-]{1,128}$/.test(value.serverId) ||
    typeof value.requiresServerPassword !== 'boolean' ||
    !Number.isSafeInteger(value.serverTime) ||
    (value.serverTime as number) < 0 ||
    !isPlainObject(value.hybridKeys) ||
    hasPrototypePollutionKeys(value.hybridKeys) ||
    Object.keys(value.hybridKeys).sort().join(',') !== 'dilithiumPublicBase64,kyberPublicBase64,x25519PublicBase64'
  ) return null;

  const keys = value.hybridKeys;
  const decoded: Uint8Array[] = [];
  try {
    decoded.push(decodeServerResponseBase64(keys.kyberPublicBase64, KYBER_PUBLIC_KEY_LENGTH));
    decoded.push(decodeServerResponseBase64(keys.dilithiumPublicBase64, DILITHIUM_PUBLIC_KEY_LENGTH));
    decoded.push(decodeServerResponseBase64(keys.x25519PublicBase64, 32));
  } catch {
    return null;
  } finally {
    for (const key of decoded) key.fill(0);
  }

  return value as unknown as ServerKeyBootstrap;
};

// WebSocket Connection Manager
export class WebSocketConnection {
  private _lifecycleState: string = 'idle';
  get lifecycleState(): string { return this._lifecycleState; }
  set lifecycleState(next: string) {
    this._lifecycleState = next;
  }
  private isManualClose = false;
  private isGatekeeperFlowActive = false;
  private secureChunkBuffers: Map<string, SecureChunkBuffer> = new Map();
  private secureChunkReservedLength = 0;
  private reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private globalRateLimitUntil = 0;
  private _username?: string;
  private lastAuthUsername?: string;
  private connectivityWatchdog?: ReturnType<typeof setInterval>;
  private accountAuthReplacementConnectionToken: number | null = null;
  private bridgeReadyPromise: Promise<void>;
  private connectingPromise: Promise<void> | null = null;
  private connectingPromiseGeneration: number | null = null;
  private connectionOperationGeneration = 0;
  private privacyBoundaryTransition: PrivacyBoundaryTransition | null = null;
  private transportEventReceived: boolean = false;
  private trustTransportUntil: number = 0;
  private isInUnlinkedMode: boolean = false;
  private coverTrafficTimer: ReturnType<typeof setTimeout> | null = null;
  private coverTrafficGeneration = 0;
  private coverTrafficInFlightGeneration: number | null = null;
  private gatekeeper?: GatekeeperClient;
  private gatekeeperServerId?: string;
  private gatekeeperLifecycleTail: Promise<void> = Promise.resolve();
  private serverPasswordRequired = false;
  private serverAuthGranted = false;
  private serverEntryPromptPending = false;
  private applicationAuthReady = false;
  private hasOpenedTransport = false;
  private unlinkedSessionReady = false;
  private unlinkedAccountAuthorizationReady = false;
  private unlinkedAuthorizationResponse: ResumeAuthorizationResponse | null = null;
  private unlinkedAuthorizationBlocked = false;
  private unlinkedAuthorizationPromise: Promise<boolean> | null = null;
  private unlinkedDeliveryPromise: Promise<boolean> | null = null;
  private secureSendLane: Promise<void> = Promise.resolve();
  private inboundMessages: InboundWsMessage[] = [];
  private inboundMessageCount = 0;
  private inboundMessageBytes = 0;
  private inboundDrainActive = false;
  private inboundGeneration = 0;
  private nativeConnectionToken: number | null = null;
  private retiredNativeConnectionToken = 0;
  private connectionWaiterCancels = new Set<() => void>();
  private serverClockOffsetMs = 0;
  private serverBootstrapConnectionToken: number | null = null;
  private timestampRecoveryInFlight: Promise<void> | null = null;
  private timestampRecoveryGeneration = 0;
  private lastTimestampRecoveryAt = 0;
  private lastCoverBackpressureLogAt = 0;

  private deliveryReadyRetryTimer: ReturnType<typeof setTimeout> | null = null;
  private deliveryReadyRetryAttempts = 0;
  private reconnectClaimListenerAttached = false;
  private sessionErrorHandlersRegistered = false;

  // Session key material
  sessionKeyMaterial?: SessionKeyMaterial;

  rateLimiter: WebSocketRateLimiter;
  heartbeat: WebSocketHeartbeat;
  torIntegration: WebSocketTorIntegration;
  queue: WebSocketQueue;
  encryption: WebSocketEncryption;
  handshake: WebSocketHandshake;
  messageHandler: WebSocketMessageHandler;

  constructor() {
    this.rateLimiter = new WebSocketRateLimiter();

    this.heartbeat = new WebSocketHeartbeat({
      onSendHeartbeat: () => this.sendHeartbeatMessage(),
      onConnectionLost: () => this.handleConnectionError(),
      onRehandshakeNeeded: () => { void this.performHandshake(true); },
      getLifecycleState: () => this.lifecycleState,
      getSessionId: () => this.sessionKeyMaterial?.sessionId
    });

    this.torIntegration = new WebSocketTorIntegration((connected) => {
      if (!connected) {
        if (this.lifecycleState === 'connected') {
          void (async () => {
            const state = await websocket.getState().catch(() => null);
            if (this.lifecycleState !== 'connected') return;
            if (state?.connected) return;
            this.lifecycleState = 'paused';
          })();
        }
        return;
      }

      if (
        this.lifecycleState === 'paused' &&
        isNativeWsConnectionToken(this.nativeConnectionToken) &&
        !!this.sessionKeyMaterial
      ) {
        this.lifecycleState = 'connected';
        this.heartbeat.reset();
        void this.queue.flush();
      }
    });

    this.queue = new WebSocketQueue(
      async (data, allowQueue) => { await this.dispatchPayload(data, allowQueue); },
      () => this.lifecycleState
    );

    const self = this;
    this.encryption = new WebSocketEncryption(
      {
        get sessionKeyMaterial() { return self.sessionKeyMaterial; }
      },
      () => this.getTrustedNow()
    );

    this.handshake = new WebSocketHandshake({
      transmit: (msg) => this.transmit(msg),
      transmitHandshake: async (message) => {
        if (!this.sessionKeyMaterial) {
          await this.transmit(JSON.stringify(message));
          return;
        }
        const envelope = await this.encryption.prepareSecureEnvelope(message);
        await this.transmit(envelope);
      },
      runOnSecureSendLane: (operation) => this.runOnSecureSendLane(operation),
      registerMessageHandler: (type, handler) => this.messageHandler.registerHandler(type, handler),
      unregisterMessageHandler: (type, handler) => this.messageHandler.unregisterHandler(type, handler),
      getTorAdaptedTimeout: (timeout) => this.torIntegration.getAdaptedTimeout(timeout),
      onSessionEstablished: (session) => this.onSessionEstablished(session),
      onHandshakeError: () => this.handleConnectionError(),
      onAuthenticatedServerTime: (serverTime) => {
        if (!this.updateServerClockOffset(serverTime)) {
          throw new Error('Authenticated server time is outside the accepted clock window');
        }
      },
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
          return isTrusted;
        }
      }
    });

    this.messageHandler = new WebSocketMessageHandler();

    this.bridgeReadyPromise = this.initializeBridge();
  }

  getDiagnostics(): Record<string, unknown> {
    let queueLength: number | string = 'n/a';
    try { queueLength = ((this.queue as any).pendingQueue?.length) ?? 'n/a'; } catch { }
    const now = Date.now();
    return {
      lifecycleState: this._lifecycleState,
      nativeToken: this.nativeConnectionToken,
      retiredToken: this.retiredNativeConnectionToken,
      hasSessionKeys: !!this.sessionKeyMaterial,
      sessionId: this.sessionKeyMaterial?.sessionId?.slice?.(0, 8),
      connectingPromise: !!this.connectingPromise,
      opGeneration: this.connectionOperationGeneration,
      isManualClose: this.isManualClose,
      handshakeInFlight: this.handshake?.isInFlight?.(),
      queueLength,
      rateLimitedForMs: Math.max(0, this.globalRateLimitUntil - now),
      trustTransportForMs: Math.max(0, this.trustTransportUntil - now),
      torReady: (() => { try { return this.torIntegration.isTorReady(); } catch { return 'err'; } })(),
      torCircuitHealth: (() => { try { return this.torIntegration.getCircuitHealth(); } catch { return 'err'; } })(),
      unlinkedMode: this.isInUnlinkedMode,
      unlinkedSessionReady: this.unlinkedSessionReady,
      serverAuthGranted: this.serverAuthGranted,
    };
  }

  private async getGatekeeper(): Promise<GatekeeperClient> {
    const serverScope = await getCurrentServerScope();
    const previous = this.gatekeeperLifecycleTail;
    let release!: () => void;
    this.gatekeeperLifecycleTail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      if (this.gatekeeper && this.gatekeeperServerId === serverScope) {
        await this.gatekeeper.ensureReady();
        return this.gatekeeper;
      }

      if (this.gatekeeper) {
        const staleGatekeeper = this.gatekeeper;
        await staleGatekeeper.dispose();
        if (this.gatekeeper === staleGatekeeper) {
          this.gatekeeper = undefined;
          this.gatekeeperServerId = undefined;
        }
      }

      const gatekeeper = new GatekeeperClient(serverScope);
      try {
        await gatekeeper.ensureReady();
        if (await getCurrentServerScope() !== serverScope) {
          const error = new Error('Gatekeeper server scope changed during initialization');
          error.name = 'AbortError';
          throw error;
        }
        this.gatekeeper = gatekeeper;
        this.gatekeeperServerId = serverScope;
        return gatekeeper;
      } catch (error) {
        await gatekeeper.dispose();
        throw error;
      }
    } finally {
      release();
    }
  }

  private getTrustedNow(): number {
    return Date.now() + this.serverClockOffsetMs;
  }

  private updateServerClockOffset(serverTime: unknown): boolean {
    if (!isNativeWsConnectionToken(this.nativeConnectionToken)) return false;
    if (typeof serverTime !== 'number' || !Number.isFinite(serverTime)) return false;
    const offset = Math.trunc(serverTime - Date.now());
    if (Math.abs(offset) > 24 * 60 * 60 * 1000) return false;
    this.serverClockOffsetMs = offset;
    return true;
  }

  private adoptNativeConnectionToken(connectionToken: number): void {
    if (!isNativeWsConnectionToken(connectionToken)) {
      throw new Error('Native WebSocket connection token unavailable');
    }
    if (
      connectionToken <= this.retiredNativeConnectionToken &&
      connectionToken !== this.nativeConnectionToken
    ) {
      throw operationAbortError('Refusing retired WebSocket connection generation');
    }
    if (connectionToken !== this.nativeConnectionToken) {
      this.serverClockOffsetMs = 0;
      this.serverBootstrapConnectionToken = null;
      this.trustTransportUntil = 0;
    }
    this.nativeConnectionToken = connectionToken;
  }

  private clearCurrentConnectionClock(): void {
    this.serverClockOffsetMs = 0;
    this.serverBootstrapConnectionToken = null;
    this.trustTransportUntil = 0;
  }

  private assertConnectionOperationCurrent(generation: number): void {
    if (generation !== this.connectionOperationGeneration || this.isManualClose) {
      throw operationAbortError('WebSocket connection operation was cancelled');
    }
  }

  private async rejectStaleConnectionOperation(
    generation: number,
    possibleConnectionToken?: unknown
  ): Promise<void> {
    try {
      this.assertConnectionOperationCurrent(generation);
    } catch (error) {
      if (isNativeWsConnectionToken(possibleConnectionToken)) {
        this.retiredNativeConnectionToken = Math.max(
          this.retiredNativeConnectionToken,
          possibleConnectionToken
        );
        if (this.nativeConnectionToken === possibleConnectionToken) {
          this.nativeConnectionToken = null;
          this.clearCurrentConnectionClock();
          this.invalidateInboundMessages();
          this.resetSessionKeys(true);
        }
        await websocket.disconnect(possibleConnectionToken).catch(() => { });
      }
      throw error;
    }
  }

  private captureOutboundTransportContext(): OutboundTransportContext {
    return {
      connectionToken: this.nativeConnectionToken,
      operationGeneration: this.connectionOperationGeneration,
      isInUnlinkedMode: this.isInUnlinkedMode,
      username: this._username,
    };
  }

  private isOutboundTransportContextCurrent(context: OutboundTransportContext): boolean {
    return !this.isManualClose &&
      context.connectionToken === this.nativeConnectionToken &&
      context.operationGeneration === this.connectionOperationGeneration &&
      context.isInUnlinkedMode === this.isInUnlinkedMode &&
      context.username === this._username;
  }

  private assertOutboundTransportContextCurrent(context: OutboundTransportContext): void {
    if (!this.isOutboundTransportContextCurrent(context)) {
      throw operationAbortError('Outbound payload crossed a connection privacy boundary');
    }
  }

  private async waitForCurrentServerBootstrap(connectionToken: number): Promise<void> {
    const timeoutMs = Math.min(30_000, this.torIntegration.getAdaptedTimeout(5_000));
    const startedAt = Date.now();
    let lastRequestAt = 0;
    while (this.serverBootstrapConnectionToken !== connectionToken) {
      if (this.nativeConnectionToken !== connectionToken) {
        throw operationAbortError('WebSocket connection generation changed before server bootstrap');
      }
      const now = Date.now();
      if (now - startedAt >= timeoutMs) {
        throw new Error('Current WebSocket generation did not provide a valid server bootstrap');
      }
      if (now - lastRequestAt >= 1_500) {
        try {
          await this.transmit(JSON.stringify({ type: SignalType.REQUEST_SERVER_PUBLIC_KEY }));
        } catch { }
        lastRequestAt = now;
      }
      await waitForAbortableDelay(100);
    }
  }

  private invalidateInboundMessages(): void {
    this.inboundGeneration += 1;
    for (const entry of this.inboundMessages) {
      this.inboundMessageCount = Math.max(0, this.inboundMessageCount - 1);
      this.inboundMessageBytes = Math.max(0, this.inboundMessageBytes - entry.bytes);
    }
    this.inboundMessages = [];
  }

  private registerConnectionWaiterCancel(cancel: () => void): () => void {
    this.connectionWaiterCancels.add(cancel);
    return () => this.connectionWaiterCancels.delete(cancel);
  }

  private cancelConnectionWaiters(): void {
    const waiters = Array.from(this.connectionWaiterCancels);
    this.connectionWaiterCancels.clear();
    for (const cancel of waiters) {
      try { cancel(); } catch { }
    }
  }

  private enqueueInboundMessage(payload: unknown, connectionToken: number): void {
    let bytes: number;
    try {
      const serialized = JSON.stringify(payload);
      if (typeof serialized !== 'string') throw new Error('Invalid WebSocket payload');
      bytes = serialized.length;
    } catch {
      this.handleConnectionError();
      void websocket.disconnect(connectionToken).catch(() => { });
      return;
    }

    if (
      this.inboundMessageCount + 1 > WS_INBOUND_PENDING_MAX_COUNT ||
      this.inboundMessageBytes + bytes > WS_INBOUND_PENDING_MAX_BYTES
    ) {
      this.invalidateInboundMessages();
      this.handleConnectionError();
      void websocket.disconnect(connectionToken).catch(() => { });
      return;
    }

    this.inboundMessages.push({
      payload,
      bytes,
      generation: this.inboundGeneration,
      connectionToken,
    });
    this.inboundMessageCount += 1;
    this.inboundMessageBytes += bytes;
    void this.drainInboundMessages();
  }

  private async drainInboundMessages(): Promise<void> {
    if (this.inboundDrainActive) return;
    this.inboundDrainActive = true;
    try {
      while (this.inboundMessages.length > 0) {
        const entry = this.inboundMessages.shift()!;
        try {
          if (
            entry.generation === this.inboundGeneration &&
            entry.connectionToken === this.nativeConnectionToken
          ) {
            await this.handleEdgeServerMessage(entry.payload, false, entry.connectionToken);
          }
        } catch {
          this.handleConnectionError();
          void websocket.disconnect(entry.connectionToken).catch(() => { });
        } finally {
          this.inboundMessageCount = Math.max(0, this.inboundMessageCount - 1);
          this.inboundMessageBytes = Math.max(0, this.inboundMessageBytes - entry.bytes);
        }
      }
    } finally {
      this.inboundDrainActive = false;
      if (this.inboundMessages.length > 0) {
        void this.drainInboundMessages();
      }
    }
  }

  private async initializeBridge(): Promise<void> {
    await this.setupTauriBridge();

    // Check if already connected
    try {
      const state = await websocket.getState();
      if (this.isManualClose) {
        if (state.connected && isNativeWsConnectionToken(state.connectionToken)) {
          await websocket.disconnect(state.connectionToken).catch(() => { });
        }
        return;
      }
      if (state.connected && (this.lifecycleState === 'idle' || this.lifecycleState === 'disconnected')) {
        if (!isNativeWsConnectionToken(state.connectionToken)) return;
        this.adoptNativeConnectionToken(state.connectionToken);
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
      await events.onWsMessage((payload) => {
        if (
          !isPlainObject(payload) ||
          hasPrototypePollutionKeys(payload) ||
          Object.keys(payload).sort().join(',') !== 'connectionToken,data' ||
          !isNativeWsConnectionToken(payload.connectionToken) ||
          payload.connectionToken !== this.nativeConnectionToken
        ) return;
        this.enqueueInboundMessage(payload.data, payload.connectionToken);
      });
      await events.onWsLifecycle((payload) => {
        this.handleNativeLifecycleEvent(payload);
      });
    } catch {
      console.error('[WebSocket] Failed to setup Tauri bridge');
    }

    // reconnect creates a new socket which must be reactivated for global mix stream.
    if (!this.reconnectClaimListenerAttached) {
      this.reconnectClaimListenerAttached = true;
      window.addEventListener(EventType.WS_RECONNECTED, () => {
        if (this.isInUnlinkedMode && !this.unlinkedSessionReady) {
          this.scheduleDeliveryReadyRetry();
        }
      });
    }
  }

  private handleNativeLifecycleEvent(message: unknown): void {
    if (!isPlainObject(message) || hasPrototypePollutionKeys(message)) return;
    const type = message.type;

    if (type === '__ws_connection_opened') {
      if (
        Object.keys(message).sort().join(',') !== 'connectionToken,type' ||
        !isNativeWsConnectionToken(message.connectionToken)
      ) return;
      const connectionToken = message.connectionToken as number;
      if (this.isManualClose) {
        this.retiredNativeConnectionToken = Math.max(this.retiredNativeConnectionToken, connectionToken);
        void websocket.disconnect(connectionToken).catch(() => { });
        return;
      }
      if (
        connectionToken <= this.retiredNativeConnectionToken ||
        this.nativeConnectionToken !== null &&
        connectionToken < this.nativeConnectionToken
      ) return;
      if (this.nativeConnectionToken === connectionToken) return;

      const openedByCurrentDial =
        this.lifecycleState === 'connecting' &&
        this.connectingPromise !== null &&
        this.connectingPromiseGeneration === this.connectionOperationGeneration;
      if (!openedByCurrentDial) {
        this.invalidateInboundMessages();
        this.resetSessionKeys(true);
      }
      this.adoptNativeConnectionToken(connectionToken);
      if (!openedByCurrentDial) {
        this.lifecycleState = 'disconnected';
      }
      const wasReconnect = this.hasOpenedTransport;
      this.hasOpenedTransport = true;
      this.handleConnectionOpened(openedByCurrentDial);
      this.dispatchToFrontend(message, false);
      if (wasReconnect) {
        window.dispatchEvent(new Event(EventType.WS_RECONNECTED));
      }
      return;
    }

    if (type === '__ws_connection_closed') {
      if (
        Object.keys(message).sort().join(',') !== 'connectionToken,type' ||
        !isNativeWsConnectionToken(message.connectionToken)
      ) return;
      if (message.connectionToken !== this.nativeConnectionToken) return;
      this.retiredNativeConnectionToken = Math.max(
        this.retiredNativeConnectionToken,
        message.connectionToken as number
      );
      this.nativeConnectionToken = null;
      this.clearCurrentConnectionClock();
      this.invalidateInboundMessages();
      this.resetSessionKeys(this.isManualClose);
      this.lifecycleState = 'disconnected';
      this.dispatchToFrontend(message, false);
      if (!this.isManualClose) this.attemptReconnect();
      return;
    }

    if (type === '__ws_connection_error') {
      if (
        Object.keys(message).sort().join(',') !== 'connectionToken,error,type' ||
        !isNativeWsConnectionToken(message.connectionToken) ||
        typeof message.error !== 'string' ||
        message.error.length > 512
      ) return;
      if (message.connectionToken !== this.nativeConnectionToken) return;
      this.retiredNativeConnectionToken = Math.max(
        this.retiredNativeConnectionToken,
        message.connectionToken as number
      );
      this.nativeConnectionToken = null;
      this.clearCurrentConnectionClock();
      this.invalidateInboundMessages();
      this.resetSessionKeys(this.isManualClose);
      this.lifecycleState = SignalType.ERROR;
      this.dispatchToFrontend({
        type: '__ws_connection_error',
        error: 'Transport connection failed'
      }, false);
      if (!this.isManualClose) this.attemptReconnect();
    }
  }

  // Handle session established
  private onSessionEstablished(session: SessionKeyMaterial): void {
    const previousSession = this.sessionKeyMaterial;
    if (previousSession && previousSession !== session) {
      PostQuantumUtils.clearMemory(previousSession.sendKey);
      PostQuantumUtils.clearMemory(previousSession.recvKey);
    }

    this.sessionKeyMaterial = session;
    this.encryption.resetCounters();
  }

  // Set and get username
  setUsername(username: string) {
    this._username = username;
    this.lastAuthUsername = username;
  }
  getUsername(): string | undefined { return this._username; }

  // Handle edge server message
  async handleEdgeServerMessage(
    message: any,
    isSecure: boolean = false,
    expectedConnectionToken: number | null = this.nativeConnectionToken
  ): Promise<boolean> {
    if (expectedConnectionToken !== this.nativeConnectionToken) return true;
    if (!isPlainObject(message) || hasPrototypePollutionKeys(message)) {
      console.warn('[WebSocket] Malformed message rejected');
      return false;
    }

    const messageType = typeof message.type === 'string' ? message.type : '';
    if (!isSecure && !PLAINTEXT_WIRE_TYPES.has(messageType)) {
      return true;
    }
    // Reassemble chunked secure messages
    if (isSecure && messageType === SignalType.SECURE_CHUNK) {
      const reassembled = this.ingestSecureChunk(message);
      if (!reassembled) return true;
      return await this.handleEdgeServerMessage(reassembled, true, expectedConnectionToken);
    }

    // Handle handshake signals internally
    if (messageType === SignalType.SERVER_PUBLIC_KEY) {
      const bootstrap = parseServerKeyBootstrap(message);
      if (!bootstrap) return true;
      if (!this.updateServerClockOffset(bootstrap.serverTime)) return true;

      const connectionEpoch = expectedConnectionToken;
      const isCurrent = () => this.isConnectionPrivacyEpochCurrent(connectionEpoch);
      try {
        await PinnedServer.establish(bootstrap.hybridKeys, isCurrent);
        if (!isCurrent()) return true;
        if (this.setServerKeyMaterial(bootstrap.hybridKeys, bootstrap.serverId) !== 'activated') {
          throw new Error('Server identity activation failed');
        }
        this.serverPasswordRequired = bootstrap.requiresServerPassword;
      } catch {
        if (!isCurrent()) return true;
        await this.close({ killSession: true }).catch(() => { });
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
            detail: {
              type: 'SERVER_IDENTITY_REJECTED',
              code: 'SERVER_IDENTITY_REJECTED',
              message: 'Server identity verification failed. Connection blocked.'
            }
          }));
        }
        return true;
      }

      if (!isCurrent()) return true;
      this.serverBootstrapConnectionToken = expectedConnectionToken;
      this.dispatchToFrontend(bootstrap, false);
      return true;
    }

    // Handle PQ envelope internally
    if (messageType === SignalType.PQ_ENVELOPE) {
      const decrypted = await this.decryptIncomingEnvelope(message);
      if (decrypted) {
        return await this.handleEdgeServerMessage(decrypted, true, expectedConnectionToken);
      }
      console.warn('[WebSocket] PQ envelope decryption FAILED (returned null)', {
        hasReceivedFingerprint: typeof message.sessionFingerprint === 'string',
        hasReceivedSessionId: typeof message.sessionId === 'string',
        hasCurrentFingerprint: !!this.sessionKeyMaterial?.fingerprint,
        hasCurrentSession: !!this.sessionKeyMaterial?.sessionId
      });
      if (this.isGatekeeperFlowActive) {
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

    // Pass through to internal handlers
    if (messageType === SignalType.PQ_HEARTBEAT_PONG || this.messageHandler.hasHandler(messageType)) {
      await this.messageHandler.handleMessage(message);
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

  // Handle connection opened
  private handleConnectionOpened(openedByCurrentDial = false): void {
    this.transportEventReceived = !openedByCurrentDial;
    this.trustTransportUntil = Date.now() + 5000;

    if (this.connectingPromise) {
      return;
    }

    void this.connect().catch(() => { });
  }

  private startCoverTraffic(): void {
    if (this.coverTrafficTimer) return;
    this.scheduleCoverTraffic(this.coverTrafficGeneration);
  }

  private stopCoverTraffic(): void {
    this.coverTrafficGeneration += 1;
    this.coverTrafficInFlightGeneration = null;
    if (this.coverTrafficTimer) {
      clearTimeout(this.coverTrafficTimer);
      this.coverTrafficTimer = null;
    }
  }

  private scheduleCoverTraffic(generation: number): void {
    if (generation !== this.coverTrafficGeneration || this.coverTrafficTimer) return;
    const minDelay = Math.max(500, WS_COVER_TRAFFIC_MIN_INTERVAL_MS);
    const maxDelay = Math.max(minDelay, WS_COVER_TRAFFIC_MAX_INTERVAL_MS);
    const delay = secureRandomIntInclusive(minDelay, maxDelay);

    this.coverTrafficTimer = setTimeout(async () => {
      if (generation !== this.coverTrafficGeneration) return;
      this.coverTrafficTimer = null;
      await this.sendCoverTraffic(generation);
      if (
        generation === this.coverTrafficGeneration &&
        this.lifecycleState === 'connected' &&
        this.sessionKeyMaterial
      ) {
        this.scheduleCoverTraffic(generation);
      }
    }, delay);
  }

  private async sendCoverTraffic(generation: number): Promise<void> {
    if (generation !== this.coverTrafficGeneration) return;
    if (this.coverTrafficInFlightGeneration === generation) return;
    if (this.lifecycleState !== 'connected' || !this.sessionKeyMaterial) return;
    if (!this.isApplicationAuthReady()) return;

    this.coverTrafficInFlightGeneration = generation;
    try {
      const state = await websocket.getState().catch(() => null);
      if (generation !== this.coverTrafficGeneration) return;
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

      if (generation !== this.coverTrafficGeneration) return;
      const blindClient = getBlindRoutingClient(this.lastAuthUsername);
      const sealedEnvelope = blindClient.createCoverSealedEnvelope();

      await this.dispatchPayload({
        type: SignalType.BLIND_ROUTE,
        requestId: crypto.randomUUID(),
        sealedEnvelope
      }, false, { isCoverTraffic: true });
    } catch {
    } finally {
      if (this.coverTrafficInFlightGeneration === generation) {
        this.coverTrafficInFlightGeneration = null;
      }
    }
  }

  // Connect to WebSocket
  async connect(options: ConnectOptions = {}): Promise<void> {
    const transition = this.privacyBoundaryTransition;
    if (transition) {
      await transition.promise;
      if (this.lifecycleState !== 'connected') {
        throw new Error('Tor privacy-boundary transition did not establish a connection');
      }
      return;
    }
    return this.connectTransport(options);
  }

  private async connectTransport(options: ConnectOptions = {}): Promise<void> {
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

    if (
      this.lifecycleState === 'paused' &&
      isNativeWsConnectionToken(this.nativeConnectionToken) &&
      !!this.sessionKeyMaterial
    ) {
      const resumed = await this.waitForConnectedSettle(this.torIntegration.getAdaptedTimeout(3000));
      if (resumed) return;
    }

    if (this.connectingPromise) {
      const pending = this.connectingPromise;
      if (
        this.connectingPromiseGeneration === this.connectionOperationGeneration &&
        !this.isManualClose
      ) {
        return pending;
      }
      try { await pending; } catch { }
      return this.connectTransport(options);
    }

    this.isManualClose = false;
    const operationGeneration = ++this.connectionOperationGeneration;
    const operation = (async () => {

      try {
        await PinnedServer.load();
        this.assertConnectionOperationCurrent(operationGeneration);
        this.torIntegration.ensureTorListener();

        if (!await this.torIntegration.ensureTorReadyAsync()) {
          throw new Error('Tor network not ready');
        }
        this.assertConnectionOperationCurrent(operationGeneration);

        if (
          this.lifecycleState === 'connected' &&
          isNativeWsConnectionToken(this.nativeConnectionToken) &&
          !!this.sessionKeyMaterial
        ) {
          return;
        }

        await this.bridgeReadyPromise;
        this.assertConnectionOperationCurrent(operationGeneration);
        const state = await websocket.getState();
        await this.rejectStaleConnectionOperation(
          operationGeneration,
          state.connected ? state.connectionToken : undefined
        );
        const hasGhost = this.transportEventReceived || state.connected;

        if (state.connected) {
          if (!isNativeWsConnectionToken(state.connectionToken)) {
            throw new Error('Native WebSocket connection token unavailable');
          }
          this.adoptNativeConnectionToken(state.connectionToken);
          this.transportEventReceived = false;
          await this.establishConnection({ forceConnect: false }, operationGeneration);
        } else if (hasGhost) {
          this.transportEventReceived = false;
          this.lifecycleState = 'connecting';
          await this.establishConnection({ forceConnect: true }, operationGeneration);
        } else {
          this.lifecycleState = 'connecting';
          await this.establishConnection({ forceConnect: true }, operationGeneration);
        }
      } catch (_error: unknown) {
        if (
          operationGeneration !== this.connectionOperationGeneration ||
          this.isManualClose
        ) {
          throw operationAbortError('WebSocket connection operation was cancelled');
        }
        if (this.lifecycleState === 'connecting' || this.lifecycleState === 'handshaking') {
          this.lifecycleState = SignalType.ERROR;
        }
        this.handleConnectionError({ autoReconnect: autoReconnectOnFailure });
        throw _error;
      } finally {
        if (this.connectingPromise === operation) {
          this.connectingPromise = null;
          this.connectingPromiseGeneration = null;
        }
      }
    })();
    this.connectingPromise = operation;
    this.connectingPromiseGeneration = operationGeneration;

    return operation;
  }

  private async establishConnection(
    options: { forceConnect?: boolean } = {},
    operationGeneration: number
  ): Promise<void> {
    const { forceConnect = true } = options;
    this.assertConnectionOperationCurrent(operationGeneration);

    if (forceConnect) {
      const state = await websocket.getState();
      await this.rejectStaleConnectionOperation(
        operationGeneration,
        state.connected ? state.connectionToken : undefined
      );
      if (state.connected) {
        if (!isNativeWsConnectionToken(state.connectionToken)) {
          throw new Error('Native WebSocket connection token unavailable');
        }
        this.adoptNativeConnectionToken(state.connectionToken);
      } else {
        await this.connectNativeTransport(operationGeneration);
      }
    }

    const connectionToken = this.nativeConnectionToken;
    const assertConnectionCurrent = () => {
      if (
        operationGeneration !== this.connectionOperationGeneration ||
        this.isManualClose ||
        !isNativeWsConnectionToken(connectionToken) ||
        this.nativeConnectionToken !== connectionToken
      ) {
        const error = new Error('WebSocket connection generation changed');
        error.name = 'AbortError';
        throw error;
      }
    };
    assertConnectionCurrent();

    this.lifecycleState = 'handshaking';

    await this.bridgeReadyPromise;
    assertConnectionCurrent();

    await this.waitForCurrentServerBootstrap(connectionToken);
    assertConnectionCurrent();

    await this.performHandshake(false);
    assertConnectionCurrent();

    {
      try {
        const gk = await this.getGatekeeper();
        assertConnectionCurrent();
        if (gk.hasTokens) {
          let entryGranted = false;
          for (let attempt = 0; attempt < 3 && !entryGranted; attempt++) {
            const redemption = await gk.getRedemptionPayload();
            assertConnectionCurrent();
            if (!redemption) break;
            const redemptionRequestId = crypto.randomUUID();
            const grantWaiter = this.createServerEntryGrantWaiter(
              this.torIntegration.getAdaptedTimeout(SERVER_ENTRY_GRANT_BASE_TIMEOUT_MS),
              undefined,
              redemptionRequestId
            );
            try {
              await this.sendSecureControlMessage({
                ...redemption,
                requestId: redemptionRequestId
              }, { bypassStateCheck: true });
              assertConnectionCurrent();
            } catch (error) {
              grantWaiter.cancel();
              try { await gk.commitPendingTokenUsage(); } catch { }
              throw error;
            }
            const grantResult = await grantWaiter.promise;
            assertConnectionCurrent();
            if (grantResult === 'granted') {
              entryGranted = true;
            } else if (grantResult === 'rejected') {
              try { await gk.commitPendingTokenUsage(); } catch { }
              assertConnectionCurrent();
              if (attempt === 0) {
                console.warn('[WebSocket] Entry token rejected, retrying with fresh token');
                await new Promise(r => setTimeout(r, 300));
                assertConnectionCurrent();
              }
            } else {
              try { await gk.commitPendingTokenUsage(); } catch { }
              assertConnectionCurrent();
              if (attempt === 0) {
                await new Promise(r => setTimeout(r, 300));
                assertConnectionCurrent();
              }
            }
          }

          if (entryGranted) {
            await gk.commitPendingTokenUsage();
            assertConnectionCurrent();
            this.serverAuthGranted = true;
            window.dispatchEvent(new CustomEvent(EventType.SERVER_ENTRY_GRANTED));
          }
        }
      } catch {
        assertConnectionCurrent();
        console.warn('[WebSocket] Automatic entry token redemption failed');
      }
    }

    assertConnectionCurrent();
    this.lifecycleState = 'connected';
    
    this.reconnectDelayMs = INITIAL_RECONNECT_DELAY_MS;
    this.unlinkedSessionReady = false;
    this.unlinkedAccountAuthorizationReady = false;
    this.unlinkedAuthorizationResponse = null;
    this.unlinkedAuthorizationBlocked = false;
    this.unlinkedAuthorizationPromise = null;
    this.unlinkedDeliveryPromise = null;
    
    if (this.isInUnlinkedMode) {
      if (this.serverPasswordRequired && !this.serverAuthGranted) {
        this.unlinkedAuthorizationBlocked = true;
        window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
          detail: {
            type: 'SERVER_ENTRY_REQUIRED',
            code: 'SERVER_ENTRY_REQUIRED',
            message: 'This server requires its password before account recovery.'
          }
        }));
      } else {
        const deliveryReady = await this.ensureUnlinkedDeliveryReady();
        assertConnectionCurrent();
        if (!deliveryReady) {
          this.scheduleDeliveryReadyRetry();
        } else {
          void this.replaceConsumedAccountAuthorizationToken().catch(() => { });
        }
      }
    }

    assertConnectionCurrent();
    this.registerSessionErrorHandler();
    this.queue.scheduleFlush();
    this.startConnectivityWatchdog();
    this.heartbeat.start();
  }

  // Redeem one unlinkable authorization token on the current socket.
  private async authorizeUnlinkedConnection(): Promise<boolean> {
    if (this.unlinkedAccountAuthorizationReady) return true;
    if (this.unlinkedAuthorizationPromise) return this.unlinkedAuthorizationPromise;
    const operation = this.performAuthorizeUnlinkedConnection();
    this.unlinkedAuthorizationPromise = operation;
    try {
      return await operation;
    } finally {
      if (this.unlinkedAuthorizationPromise === operation) {
        this.unlinkedAuthorizationPromise = null;
      }
    }
  }

  private async performAuthorizeUnlinkedConnection(): Promise<boolean> {
    if (this.unlinkedAccountAuthorizationReady) return true;
    const connectionToken = this.nativeConnectionToken;
    if (!isNativeWsConnectionToken(connectionToken)) return false;
    const isCurrent = () => this.nativeConnectionToken === connectionToken;

    if (!isCurrent()) return false;
    const account = this._username;
    if (typeof account !== 'string' || !account) return false;
    const resumeRedemption = await takeResumeRedemption(account);
    if (!isCurrent() || !resumeRedemption) return false;
    const requestId = crypto.randomUUID();
    if (!REQUEST_ID_RE.test(requestId)) return false;

    const timeoutMs = this.torIntegration.getAdaptedTimeout(30000);
    let cancelWait = () => {};
    const response = new Promise<boolean>((resolve) => {
      let settled = false;
      let cleanup = () => {};
      let unregisterCancel = () => {};
      const finish = (value: boolean) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      };
      const handler = (message: any) => {
        if (message?.type !== SignalType.TOKEN_VALIDATION_RESPONSE) return;
        if (message?.requestId !== requestId) return;
        if (!isCurrent()) {
          finish(false);
          return;
        }
        if (!isTokenValidationResponse(message)) {
          this.unlinkedAuthorizationBlocked = true;
          finish(false);
          return;
        }
        let response: ResumeAuthorizationResponse;
        if (message.valid === true) {
          response = Object.freeze({
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            requestId: message.requestId,
            valid: true,
            serverEntryRequired: message.serverEntryRequired,
            serverEntryGranted: message.serverEntryGranted
          });
        } else {
          const rejection = message as Extract<ResumeAuthorizationResponse, { valid: false }>;
          response = Object.freeze({
            type: SignalType.TOKEN_VALIDATION_RESPONSE,
            requestId: rejection.requestId,
            valid: false,
            error: rejection.error
          });
        }
        this.unlinkedAuthorizationResponse = response;
        const authorized = response.valid === true && response.serverEntryRequired !== true;
        if (!authorized) {
          this.unlinkedAuthorizationBlocked = true;
        }
        finish(authorized);
      };
      const timeout = setTimeout(() => finish(false), timeoutMs);
      cleanup = () => {
        clearTimeout(timeout);
        this.messageHandler.unregisterHandler(SignalType.TOKEN_VALIDATION_RESPONSE, handler);
        unregisterCancel();
      };
      cancelWait = () => finish(false);
      this.messageHandler.registerHandler(SignalType.TOKEN_VALIDATION_RESPONSE, handler);
      unregisterCancel = this.registerConnectionWaiterCancel(cancelWait);
    });

    try {
      await this.sendSecureControlMessage({
        type: SignalType.TOKEN_VALIDATION,
        requestId,
        resumeRedemption
      }, { failIfQueued: true });
    } catch {
      cancelWait();
      return false;
    }

    const authorized = await response;
    if (!isCurrent()) return false;
    this.unlinkedAccountAuthorizationReady = authorized;
    return this.unlinkedAccountAuthorizationReady;
  }

  private async ensureUnlinkedDeliveryReady(): Promise<boolean> {
    if (this.unlinkedSessionReady) return true;
    if (this.unlinkedAuthorizationBlocked) return false;
    if (this.unlinkedDeliveryPromise) return this.unlinkedDeliveryPromise;
    const operation = this.performEnsureUnlinkedDeliveryReady();
    this.unlinkedDeliveryPromise = operation;
    try {
      return await operation;
    } finally {
      if (this.unlinkedDeliveryPromise === operation) {
        this.unlinkedDeliveryPromise = null;
      }
    }
  }

  private async performEnsureUnlinkedDeliveryReady(): Promise<boolean> {
    if (!this.isInUnlinkedMode) return false;
    if (this.lifecycleState !== 'connected' || !this.sessionKeyMaterial) return false;
    const connectionToken = this.nativeConnectionToken;
    if (!isNativeWsConnectionToken(connectionToken)) return false;
    const isCurrent = () => this.nativeConnectionToken === connectionToken;
    try {
      if (!await this.authorizeUnlinkedConnection()) {
        return false;
      }
      if (!isCurrent()) return false;
      if (!isCurrent()) return false;
      const bc = getBlindRoutingClient(this.lastAuthUsername);

      // Reset send function for the new PQ session
      const self = this;
      bc.setSendFunction(async (message: any) => {
        await self.sendSecureControlMessage(message);
      });

      const activationTimeoutMs = this.torIntegration.getAdaptedTimeout(30000);
      const activationRequestId = crypto.randomUUID();
      let cancelActivationWait = () => {};
      const waitForActivationResponse = new Promise<boolean>((resolve) => {
        let settled = false;
        let unregisterCancel = () => {};
        const cleanup = () => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.ACTIVATE_DELIVERY_RESPONSE, handler);
          unregisterCancel();
        };
        const finish = (success: boolean) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(success);
        };
        const handler = (detail: any) => {
          if (!isCurrent()) {
            finish(false);
            return;
          }
          if (detail?.requestId !== activationRequestId) return;
          finish(detail?.success === true);
        };
        const timeout = setTimeout(() => finish(false), activationTimeoutMs);
        cancelActivationWait = () => finish(false);
        this.messageHandler.registerHandler(SignalType.ACTIVATE_DELIVERY_RESPONSE, handler);
        unregisterCancel = this.registerConnectionWaiterCancel(cancelActivationWait);
      });

      let activationSent = false;
      try {
        activationSent = await bc.activateDelivery(activationRequestId);
        if (!isCurrent()) {
          cancelActivationWait();
          return false;
        }
      } catch (error) {
        cancelActivationWait();
        throw error;
      }
      if (!activationSent) {
        cancelActivationWait();
      }

      const activationSuccess = activationSent ? await waitForActivationResponse : false;
      if (!isCurrent()) return false;

      if (activationSuccess) {
        this.unlinkedSessionReady = true;
        this.startCoverTraffic();
        window.dispatchEvent(new CustomEvent(EventType.UNLINKED_SESSION_READY));
        return true;
      }

      this.unlinkedSessionReady = false;
      return false;
    } catch {
      if (!isCurrent()) return false;
      this.unlinkedSessionReady = false;
      console.warn('[WebSocket] Failed to activate anonymous delivery');
      return false;
    }
  }

  // Retry anonymous delivery activation.
  private scheduleDeliveryReadyRetry(): void {
    if (this.deliveryReadyRetryTimer) return;
    if (!this.isInUnlinkedMode) return;
    if (this.unlinkedAuthorizationBlocked) return;

    const attempt = this.deliveryReadyRetryAttempts++;
    const baseDelay = Math.min(3000 * Math.pow(1.6, attempt), 30000);
    const jitter = secureRandomIntInclusive(0, 999);

    this.deliveryReadyRetryTimer = setTimeout(async () => {
      this.deliveryReadyRetryTimer = null;

      if (this.lifecycleState !== 'connected' || !this.sessionKeyMaterial) {
        return;
      }
      if (this.unlinkedSessionReady) {
        this.deliveryReadyRetryAttempts = 0;
        return;
      }
      if (this.unlinkedAuthorizationBlocked) return;

      const ready = await this.ensureUnlinkedDeliveryReady().catch(() => false);
      if (ready) {
        this.deliveryReadyRetryAttempts = 0;
      } else if (!this.unlinkedAuthorizationBlocked) {
        this.scheduleDeliveryReadyRetry();
      }
    }, baseDelay + jitter);
  }

  private isNativeConnectionInProgress(error?: string): boolean {
    return typeof error === 'string' && error.toLowerCase().includes('connection in progress');
  }

  private async connectNativeTransport(operationGeneration: number): Promise<void> {
    let result = await websocket.connect();
    await this.rejectStaleConnectionOperation(operationGeneration, result?.connectionToken);
    if (result?.success === false && this.isNativeConnectionInProgress(result.error)) {
      await new Promise(resolve => setTimeout(resolve, 500));
      this.assertConnectionOperationCurrent(operationGeneration);
      const nativeState = await websocket.getState().catch(() => null);
      await this.rejectStaleConnectionOperation(
        operationGeneration,
        nativeState?.connected ? nativeState.connectionToken : undefined
      );
      if (nativeState?.connected) {
        if (!isNativeWsConnectionToken(nativeState.connectionToken)) {
          throw new Error('Native WebSocket connection token unavailable');
        }
        this.adoptNativeConnectionToken(nativeState.connectionToken);
        return;
      }
      if (nativeState?.connecting) {
        await websocket.disconnect().catch(() => { });
        this.assertConnectionOperationCurrent(operationGeneration);
        await new Promise(resolve => setTimeout(resolve, 250));
        this.assertConnectionOperationCurrent(operationGeneration);
      }
      result = await websocket.connect();
      await this.rejectStaleConnectionOperation(operationGeneration, result?.connectionToken);
    }

    if (result?.success === false) {
      if (typeof result.error === 'string' && /tor setup not complete/i.test(result.error)) {
        try { this.torIntegration.markTorNotReady(); } catch { }
      }
      throw new Error(result.error || 'Failed to establish WebSocket connection');
    }
    if (!isNativeWsConnectionToken(result?.connectionToken)) {
      throw new Error('Native WebSocket connection token unavailable');
    }
    this.adoptNativeConnectionToken(result.connectionToken);
    this.transportEventReceived = false;
  }

  // Register session error handler
  private registerSessionErrorHandler(): void {
    if (this.sessionErrorHandlersRegistered) return;
    this.sessionErrorHandlersRegistered = true;
    this.messageHandler.registerHandler(SignalType.ERROR, async (message: any) => {
      const errorMsg = message.message || '';
      if (message.code === 'ENVELOPE_TIMESTAMP_INVALID' || message.code === 'HANDSHAKE_TIMESTAMP_INVALID') {
        void this.recoverFromTimestampReject(message).catch(() => { });
        return;
      }
      if (errorMsg.includes('Unknown PQ session') || errorMsg.includes('PQ session')) {
        this.resetSessionKeys(true);
        void this.performHandshake(false)
          .then(() => this.queue.flush())
          .catch(() => { });
      }
    });

  }

  private async recoverFromTimestampReject(message: any): Promise<void> {
    if (this.timestampRecoveryInFlight) {
      return this.timestampRecoveryInFlight;
    }

    const now = Date.now();
    if (now - this.lastTimestampRecoveryAt < 3000) {
      return;
    }
    this.lastTimestampRecoveryAt = now;
    const recoveryGeneration = ++this.timestampRecoveryGeneration;
    const isCurrentRecovery = () =>
      this.timestampRecoveryGeneration === recoveryGeneration && !this.isManualClose;

    const recovery = (async () => {
      console.warn('[WebSocket] Server rejected a stale PQ envelope, reconnecting to drop queued ciphertext', {
        code: message?.code,
        replayWindowMs: message?.replayWindowMs
      });

      if (this.reconnectTimeout) {
        clearTimeout(this.reconnectTimeout);
        this.reconnectTimeout = null;
      }

      this.stopCoverTraffic();
      this.resetSessionKeys(true);
      this.handshake.reset();
      this.transportEventReceived = false;
      this.lifecycleState = 'disconnected';
      this.isManualClose = false;
      const connectionToken = this.nativeConnectionToken;
      if (connectionToken !== null) {
        this.retiredNativeConnectionToken = Math.max(this.retiredNativeConnectionToken, connectionToken);
      }
      this.nativeConnectionToken = null;
      this.clearCurrentConnectionClock();
      this.invalidateInboundMessages();

      try {
        await websocket.disconnect(connectionToken ?? undefined).catch(() => { });
      } catch { }
      if (!isCurrentRecovery()) return;

      await new Promise(resolve => setTimeout(resolve, 250));
      if (!isCurrentRecovery()) return;
      await this.connect();
      if (!isCurrentRecovery()) return;
      void this.queue.flush();
    })();
    this.timestampRecoveryInFlight = recovery;

    try {
      await recovery;
    } finally {
      if (this.timestampRecoveryInFlight === recovery) {
        this.timestampRecoveryInFlight = null;
      }
    }
  }

  // Start connectivity watchdog
  private startConnectivityWatchdog(): void {
    if (this.connectivityWatchdog) return;
    this.connectivityWatchdog = setInterval(() => {
      if (this.lifecycleState === 'connected') void this.queue.flush();
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
  handleConnectionError(options: { autoReconnect?: boolean } = {}): void {
    this.lifecycleState = SignalType.ERROR;
    this.resetSessionKeys(this.isManualClose);
    if (!this.isManualClose && options.autoReconnect !== false) this.attemptReconnect();
  }

  terminateCurrentConnection(): void {
    const connectionToken = this.nativeConnectionToken;
    if (!isNativeWsConnectionToken(connectionToken)) return;
    this.handleConnectionError();
    void websocket.disconnect(connectionToken).catch(() => { });
  }

  private ingestSecureChunk(chunk: any): any | null {
    if (
      !isPlainObject(chunk) ||
      hasPrototypePollutionKeys(chunk) ||
      !hasExactKeys(chunk, [
        'type',
        'messageId',
        'chunkIndex',
        'totalChunks',
        'totalLength',
        'payloadType',
        'data'
      ]) ||
      chunk.type !== SignalType.SECURE_CHUNK
    ) return null;

    const messageId = chunk?.messageId;
    const chunkIndex = chunk?.chunkIndex;
    const totalChunks = chunk?.totalChunks;
    const totalLength = chunk?.totalLength;
    const payloadType = chunk?.payloadType;
    const data = chunk?.data;

    if (typeof messageId !== 'string' || !SECURE_CHUNK_MESSAGE_ID_RE.test(messageId)) return null;
    if (typeof totalChunks !== 'number' || !Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > SECURE_CHUNK_MAX_TOTAL_CHUNKS) return null;
    if (typeof chunkIndex !== 'number' || !Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= totalChunks) return null;
    if (typeof totalLength !== 'number' || !Number.isInteger(totalLength) || totalLength < 1 || totalLength > SECURE_CHUNK_MAX_TOTAL_LENGTH) return null;
    if (payloadType !== SignalType.AUTH_OT_RESPONSE) return null;
    if (typeof data !== 'string' || data.length === 0 || data.length > SECURE_CHUNK_MAX_DATA_LENGTH) return null;

    let buf = this.secureChunkBuffers.get(messageId);
    if (!buf) {
      while (
        this.secureChunkBuffers.size >= SECURE_CHUNK_MAX_CONCURRENT ||
        this.secureChunkReservedLength + totalLength > SECURE_CHUNK_MAX_RESERVED_LENGTH
      ) {
        let oldestKey: string | null = null;
        let oldestAt = Infinity;
        for (const [k, v] of this.secureChunkBuffers) {
          if (v.createdAt < oldestAt) { oldestAt = v.createdAt; oldestKey = k; }
        }
        if (!oldestKey) return null;
        this.discardSecureChunkBuffer(oldestKey);
      }
      const timer = setTimeout(() => {
        this.discardSecureChunkBuffer(messageId);
        console.warn('[SECURE-CHUNK] Reassembly timed out', { payloadType });
      }, SECURE_CHUNK_TIMEOUT_MS);
      buf = {
        totalChunks, totalLength, payloadType,
        parts: new Array(totalChunks), receivedCount: 0, receivedLength: 0,
        createdAt: Date.now(), timer
      };
      this.secureChunkBuffers.set(messageId, buf);
      this.secureChunkReservedLength += totalLength;
    } else if (buf.totalChunks !== totalChunks || buf.totalLength !== totalLength || buf.payloadType !== payloadType) {
      this.discardSecureChunkBuffer(messageId);
      console.warn('[SECURE-CHUNK] Inconsistent chunk metadata', { payloadType });
      return null;
    }

    const existing = buf.parts[chunkIndex];
    if (existing === undefined) {
      if (buf.receivedLength + data.length > buf.totalLength) {
        this.discardSecureChunkBuffer(messageId);
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
      this.discardSecureChunkBuffer(messageId);
      console.warn('[SECURE-CHUNK] Conflicting duplicate chunk. discarded', { payloadType });
      return null;
    }

    if (buf.receivedCount < buf.totalChunks) return null;

    this.discardSecureChunkBuffer(messageId);

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

  private discardSecureChunkBuffer(messageId: string): void {
    const buffer = this.secureChunkBuffers.get(messageId);
    if (!buffer) return;
    clearTimeout(buffer.timer);
    this.secureChunkBuffers.delete(messageId);
    this.secureChunkReservedLength = Math.max(
      0,
      this.secureChunkReservedLength - buffer.totalLength
    );
  }

  // Drop all inflight reassemblies
  private clearSecureChunkBuffers(): void {
    for (const buf of this.secureChunkBuffers.values()) {
      try { clearTimeout(buf.timer); } catch { }
    }
    this.secureChunkBuffers.clear();
    this.secureChunkReservedLength = 0;
  }

  resetSessionKeys(preserveServerKeys: boolean = true): void {
    this.invalidateInboundMessages();
    this.cancelConnectionWaiters();
    this.heartbeat.reset();
    this.serverAuthGranted = false;
    this.applicationAuthReady = false;
    this.unlinkedSessionReady = false;
    this.unlinkedAccountAuthorizationReady = false;
    this.unlinkedAuthorizationResponse = null;
    this.unlinkedAuthorizationBlocked = false;
    this.unlinkedAuthorizationPromise = null;
    this.unlinkedDeliveryPromise = null;
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
    this.clearSecureChunkBuffers();
    this.encryption.resetCounters();
    if (!preserveServerKeys) this.handshake.clearServerKeyMaterial();
    this.handshake.reset();
  }

  // Attempt reconnect
  private attemptReconnect(): void {
    if (this.isManualClose) return;
    if (this.reconnectTimeout) return;

    this.reconnectDelayMs = Math.min(this.reconnectDelayMs * 2, MAX_RECONNECT_DELAY_MS);

    const jitterBytes = PostQuantumRandom.randomBytes(4);
    const jitterValue = ((jitterBytes[0]! << 24) >>> 0) ^ (jitterBytes[1]! << 16) ^ (jitterBytes[2]! << 8) ^ jitterBytes[3]!;
    const jitterMs = Math.floor((jitterValue / 0xffffffff) * 500);
    const delayWithJitter = this.reconnectDelayMs + jitterMs;

    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      void this.connect().catch(() => this.handleConnectionError());
    }, delayWithJitter);
  }

  // Send data
  send(data: unknown): void {
    void this.dispatchPayload(data, true).catch((err) => {
      console.error('[WebSocket] Send failed:', err);
    });
  }

  async sendReliable(
    data: unknown,
    options: { queueOnFailure?: boolean } = {},
  ): Promise<boolean> {
    const context = this.captureOutboundTransportContext();
    try {
      await this.dispatchPayload(data, false);
      return true;
    } catch {
      if (!this.isOutboundTransportContextCurrent(context)) return false;
      if (options.queueOnFailure !== false) {
        try { void this.dispatchPayload(data, true).catch(() => { }); } catch { }
      }
      return false;
    }
  }

  private runOnSecureSendLane<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.secureSendLane.then(operation, operation);
    this.secureSendLane = run.then(() => undefined, () => undefined);
    return run;
  }

  // Dispatch payload
  async dispatchPayload(
    data: unknown,
    allowQueue: boolean,
    options: DispatchOptions = {}
  ): Promise<string | null | undefined> {
    throwIfOperationAborted(options.signal);
    const msgObj = typeof data === 'string' ? ((): any => { try { return JSON.parse(data); } catch { return {}; } })() : (data as any);
    const payloadType = typeof msgObj?.type === 'string' ? msgObj.type : 'unknown';
    if (options.authBindingRequestId && allowQueue) {
      throw new Error('Channel-bound authentication requests cannot be queued');
    }

    if (!this.isInUnlinkedMode && LINKED_FORBIDDEN_ANONYMOUS_TYPES.has(msgObj.type)) {
      throw new Error('Anonymous-only message rejected on linked socket');
    }
    if (this.isInUnlinkedMode) {
      if (
        UNLINKED_FORBIDDEN_ACCOUNT_TYPES.has(msgObj.type) ||
        msgObj.username
      ) {
        throw new Error('Account-linked message rejected on unlinked socket');
      }
    }


    if (!this.rateLimiter.checkRateLimit()) {
      if (allowQueue) {
        if (!this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + RATE_LIMIT_BACKOFF_MS))) {
          throw new Error('WebSocket queue is full');
        }
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
        SignalType.AUTH_OT_REGISTER_CONFIRM,
        SignalType.AUTH_OT_REQUEST,
        SignalType.AUTH_OT_FINALIZE,
        SignalType.SERVER_ENTRY_REQUEST,
        SignalType.ACCOUNT_AUTH_TOKEN_REFRESH,
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
        if (!this.queue.enqueuePending(this.queue.createEntry(data, this.globalRateLimitUntil))) {
          throw new Error('WebSocket queue is full');
        }
      } else {
        throw new Error(`WebSocket globally rate limited for ${remainingSeconds}s`);
      }
      return;
    }

    if (this.lifecycleState !== 'connected' && !options.bypassStateCheck) {
      if (allowQueue) {
        if (!this.queue.enqueuePending(this.queue.createEntry(data, Date.now()))) {
          throw new Error('WebSocket queue is full');
        }
      }
      else throw new Error('WebSocket not connected');
      return;
    }

    if (!this.torIntegration.isCircuitHealthy()) {
      const circuitHealth = this.torIntegration.getCircuitHealth();
      if (allowQueue) {
        if (!this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + 5000))) {
          throw new Error('WebSocket queue is full');
        }
      } else {
        throw new Error(`Tor circuit is not healthy enough to send ${payloadType} (${circuitHealth})`);
      }
      return;
    }

    const outboundContext = this.captureOutboundTransportContext();
    if (!isNativeWsConnectionToken(outboundContext.connectionToken)) {
      throw new Error('Native WebSocket connection unavailable');
    }

    if (options.isCoverTraffic) {
      const state = await websocket.getState().catch(() => null);
      throwIfOperationAborted(options.signal);
      this.assertOutboundTransportContextCurrent(outboundContext);
      if (state && Number(state.queue_size || 0) > 0) {
        return;
      }
    }

    try {
      await this.ensureSessionKeys(false);
      throwIfOperationAborted(options.signal);
      this.assertOutboundTransportContextCurrent(outboundContext);
      return await this.runOnSecureSendLane(async () => {
        throwIfOperationAborted(options.signal);
        this.assertOutboundTransportContextCurrent(outboundContext);
        if (this.lifecycleState !== 'connected' && !options.bypassStateCheck) {
          throw new Error('WebSocket not connected');
        }

        if (!this.sessionKeyMaterial) {
          throw new Error('Post-quantum session not established');
        }

        let boundData = data;
        let authChannelBinding: string | null = null;
        if (options.authBindingRequestId) {
          const requestField = AUTH_CHANNEL_BOUND_REQUEST_FIELDS.get(payloadType);
          if (
            !requestField ||
            !isPlainObject(msgObj) ||
            hasPrototypePollutionKeys(msgObj) ||
            msgObj[requestField] !== options.authBindingRequestId ||
            !REQUEST_ID_RE.test(options.authBindingRequestId) ||
            Object.prototype.hasOwnProperty.call(msgObj, 'authChannelBinding')
          ) {
            throw new Error('Invalid channel-bound authentication request');
          }

          const bindingBytes = createAuthChannelBinding({
            sessionId: this.sessionKeyMaterial.sessionId,
            sessionFingerprint: this.sessionKeyMaterial.fingerprint,
            requestId: options.authBindingRequestId,
          });
          try {
            authChannelBinding = Base64.arrayBufferToBase64(bindingBytes);
          } finally {
            bindingBytes.fill(0);
          }
          boundData = {
            ...msgObj,
            authChannelBinding,
          };
        }

        const message = await this.encryption.prepareSecureEnvelope(boundData);
        throwIfOperationAborted(options.signal);
        this.assertOutboundTransportContextCurrent(outboundContext);
        await this.transmit(message);
        return authChannelBinding;
      });
    } catch (err: any) {
      const reason = err instanceof Error ? err.message : String(err);
      const isSessionNotReady =
        reason.includes('Post-quantum session not established') ||
        reason.includes('PQ session not established');
      const isSigningBindingMismatch = reason.includes('PQ session signing key binding mismatch');

      if ((isSessionNotReady || isSigningBindingMismatch) && allowQueue) {
        if (isSigningBindingMismatch) {
          this.resetSessionKeys();
        }
        if (!this.queue.enqueuePending(this.queue.createEntry(data, Date.now() + 500))) {
          throw new Error('WebSocket queue is full');
        }
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
    const sessionKeyMaterial = this.sessionKeyMaterial;
    if (!sessionKeyMaterial) {
      throw new Error('Post-quantum session not established');
    }
    await this.dispatchPayload({
      type: SignalType.PQ_HEARTBEAT_PING,
      timestamp: Date.now(),
      sessionId: sessionKeyMaterial.sessionId
    }, false);
  }

  markServerAuthGranted(): void {
    this.serverAuthGranted = true;
  }

  isServerAuthGranted(): boolean {
    return this.serverAuthGranted;
  }

  setServerEntryPromptPending(pending: boolean): void {
    this.serverEntryPromptPending = pending;
  }

  isServerEntryPromptPending(): boolean {
    return this.serverEntryPromptPending;
  }

  isServerPasswordRequired(): boolean {
    return this.serverPasswordRequired;
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

  async ensureDeliveryReadyForSend(): Promise<boolean> {
    if (!this.isInUnlinkedMode) return true;
    if (this.unlinkedSessionReady) return true;
    if (this.unlinkedAuthorizationBlocked) return false;
    if (this.lifecycleState !== 'connected') return false;
    return await this.ensureUnlinkedDeliveryReady().catch(() => false);
  }

  async transmit(message: string): Promise<void> {
    if (this.isManualClose) {
      console.warn('[WebSocket] Suppressing transmit during manual close to avoid write errors', { messageLength: message.length });
      throw new Error('WebSocket is manually closing');
    }
    const connectionToken = this.nativeConnectionToken;
    if (!isNativeWsConnectionToken(connectionToken)) {
      throw new Error('Native WebSocket connection unavailable');
    }
    try {
      const result = await websocket.send(message, connectionToken);
      if (this.nativeConnectionToken !== connectionToken) {
        throw new Error('WebSocket connection generation changed during send');
      }
      if (result?.success === false) {
        if (
          result.error?.includes('connection generation changed') &&
          this.nativeConnectionToken === connectionToken
        ) {
          this.retiredNativeConnectionToken = Math.max(this.retiredNativeConnectionToken, connectionToken);
          this.nativeConnectionToken = null;
          this.clearCurrentConnectionClock();
          this.resetSessionKeys(true);
        }
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
  }

  // Check if globally rate limited
  isGloballyRateLimited(): boolean { return Date.now() < this.globalRateLimitUntil; }

  // Register message handler
  registerMessageHandler(type: string, handler: MessageHandler): void { this.messageHandler.registerHandler(type, handler); }

  // Unregister message handler
  unregisterMessageHandler(type: string, handler?: MessageHandler): void { this.messageHandler.unregisterHandler(type, handler); }

  // Note heartbeat pong
  noteHeartbeatPong(message: any): void { this.heartbeat.handleResponse(message); }

  /**
   * Switch to unlinked mode
   */
  async switchToUnlinkedMode(abortSignal?: AbortSignal): Promise<ResumeAuthorizationResponse> {
    throwIfOperationAborted(abortSignal);
    if (this.serverEntryPromptPending) {
      throw operationAbortError('Server entry resolution is pending');
    }

    while (this.privacyBoundaryTransition) {
      const active = this.privacyBoundaryTransition;
      try {
        await active.promise;
      } catch (error) {
        if (active.targetMode === 'unlinked') throw error;
      }
      throwIfOperationAborted(abortSignal);
      if (this.serverEntryPromptPending) {
        throw operationAbortError('Server entry resolution is pending');
      }
      if (
        active.targetMode === 'unlinked' &&
        this.lifecycleState === 'connected' &&
        this.isInUnlinkedMode &&
        this.unlinkedSessionReady
      ) {
        const response = this.unlinkedAuthorizationResponse;
        if (!response || !response.valid || response.serverEntryRequired) {
          throw new Error('Verified anonymous authorization receipt unavailable');
        }
        return response;
      }
    }

    if (this.lifecycleState === 'connected' && this.unlinkedSessionReady) {
      throwIfOperationAborted(abortSignal);
      if (this.serverEntryPromptPending) {
        throw operationAbortError('Server entry resolution is pending');
      }
      const response = this.unlinkedAuthorizationResponse;
      if (!response || !response.valid || response.serverEntryRequired) {
        throw new Error('Verified anonymous authorization receipt unavailable');
      }
      return response;
    }

    const operation = this.isInUnlinkedMode
      ? this.resumeExistingUnlinkedMode(abortSignal)
      : this.performSwitchToUnlinkedMode(abortSignal);
    const transition: PrivacyBoundaryTransition = {
      targetMode: 'unlinked',
      promise: operation
    };
    this.privacyBoundaryTransition = transition;
    try {
      return await operation;
    } finally {
      if (this.privacyBoundaryTransition === transition) {
        this.privacyBoundaryTransition = null;
      }
    }
  }

  private async resumeExistingUnlinkedMode(
    abortSignal?: AbortSignal
  ): Promise<ResumeAuthorizationResponse> {
    await this.connectTransport({ autoReconnectOnFailure: false });
    throwIfOperationAborted(abortSignal);

    if (this.unlinkedAuthorizationBlocked && this.unlinkedAuthorizationResponse) {
      throw new UnlinkedAuthorizationError(this.unlinkedAuthorizationResponse);
    }
    if (!this.unlinkedSessionReady && this.lifecycleState === 'connected') {
      await this.ensureUnlinkedDeliveryReady();
      throwIfOperationAborted(abortSignal);
    }
    if (!this.unlinkedSessionReady) {
      if (this.unlinkedAuthorizationResponse) {
        throw new UnlinkedAuthorizationError(this.unlinkedAuthorizationResponse);
      }
      throw new Error('Unlinked session not ready after reconnect');
    }
    const response = this.unlinkedAuthorizationResponse;
    if (!response || !response.valid || response.serverEntryRequired) {
      throw new Error('Verified anonymous authorization receipt unavailable');
    }
    return response;
  }

  private async performSwitchToUnlinkedMode(
    abortSignal?: AbortSignal
  ): Promise<ResumeAuthorizationResponse> {
    if (this.serverEntryPromptPending) {
      throw operationAbortError('Server entry resolution is pending');
    }

    // Disconnect with reset
    await this.close();
    throwIfOperationAborted(abortSignal);
    if (this.serverEntryPromptPending) {
      throw operationAbortError('Server entry resolution is pending');
    }

    const jitter = secureRandomIntInclusive(500, 2000);
    await waitForAbortableDelay(jitter, abortSignal);
    if (this.serverEntryPromptPending) {
      throw operationAbortError('Server entry resolution is pending');
    }

    this.isInUnlinkedMode = true;
    await websocket.rotateSocksIdentity();
    throwIfOperationAborted(abortSignal);
    if (this.serverEntryPromptPending) {
      this.isInUnlinkedMode = false;
      throw operationAbortError('Server entry resolution is pending');
    }
    await this.connectTransport({ autoReconnectOnFailure: false });
    throwIfOperationAborted(abortSignal);
    if (!this.unlinkedSessionReady) {
      if (this.unlinkedAuthorizationResponse) {
        throw new UnlinkedAuthorizationError(this.unlinkedAuthorizationResponse);
      }
      throw new Error('Unlinked session not ready after switch');
    }
    const response = this.unlinkedAuthorizationResponse;
    if (!response || !response.valid || response.serverEntryRequired) {
      throw new Error('Verified anonymous authorization receipt unavailable');
    }
    return response;
  }

  async switchToLinkedAuthenticationMode(abortSignal?: AbortSignal): Promise<void> {
    throwIfOperationAborted(abortSignal);

    while (this.privacyBoundaryTransition) {
      const active = this.privacyBoundaryTransition;
      try {
        await active.promise;
      } catch (error) {
        if (active.targetMode === 'linked') throw error;
      }
      throwIfOperationAborted(abortSignal);
      if (
        active.targetMode === 'linked' &&
        this.lifecycleState === 'connected' &&
        !this.isInUnlinkedMode
      ) {
        return;
      }
    }

    const operation = this.performSwitchToLinkedAuthenticationMode(abortSignal);
    const transition: PrivacyBoundaryTransition = {
      targetMode: 'linked',
      promise: operation
    };
    this.privacyBoundaryTransition = transition;
    try {
      await operation;
    } finally {
      if (this.privacyBoundaryTransition === transition) {
        this.privacyBoundaryTransition = null;
      }
    }
  }

  async ensureLinkedAuthenticationMode(abortSignal?: AbortSignal): Promise<void> {
    throwIfOperationAborted(abortSignal);
    const transition = this.privacyBoundaryTransition;
    if (transition) {
      try {
        await transition.promise;
      } catch (error) {
        if (transition.targetMode === 'linked') throw error;
      }
      throwIfOperationAborted(abortSignal);
    }
    if (this.lifecycleState === 'connected' && !this.isInUnlinkedMode) {
      return;
    }
    await this.switchToLinkedAuthenticationMode(abortSignal);
  }

  private async performSwitchToLinkedAuthenticationMode(abortSignal?: AbortSignal): Promise<void> {
    await this.close();
    throwIfOperationAborted(abortSignal);
    this.isInUnlinkedMode = false;
    const jitter = secureRandomIntInclusive(500, 2000);
    await waitForAbortableDelay(jitter, abortSignal);
    
    await websocket.rotateSocksIdentity();
    await this.connectTransport({ autoReconnectOnFailure: false });
    throwIfOperationAborted(abortSignal);
  }

  resetConnectionPrivacyMode(): void {
    if (this.lifecycleState !== 'idle' && this.lifecycleState !== 'disconnected') {
      throw new Error('Connection privacy mode can only reset while disconnected');
    }
    this.isInUnlinkedMode = false;
    this.unlinkedAuthorizationBlocked = false;
  }

  /**
   * Start the server gatekeeper flow to get entry tokens
   */
  async startServerGatekeeperFlow(
    password: string,
    gatekeeperRequestId: string,
    onProgress?: (status: string) => void,
    abortSignal?: AbortSignal
  ): Promise<boolean> {
    if (this.isInUnlinkedMode) {
      throw new Error('Server-password authentication requires a linked socket');
    }
    if (this.isGatekeeperFlowActive) {
      console.warn('[WebSocket] Gatekeeper flow already active, ignoring request');
      return false;
    }
    this.isGatekeeperFlowActive = true;
    let operationGatekeeper: GatekeeperClient | null = null;
    let gatekeeperAuthChannelBinding: Uint8Array | null = null;
    const connectionToken = this.nativeConnectionToken;
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(gatekeeperRequestId)) {
      this.isGatekeeperFlowActive = false;
      throw new Error('Invalid server entry request identifier');
    }

    const abortError = () => {
      const error = new Error('Server entry operation was cancelled');
      error.name = 'AbortError';
      return error;
    };
    const throwIfAborted = () => {
      if (
        abortSignal?.aborted ||
        !isNativeWsConnectionToken(connectionToken) ||
        this.nativeConnectionToken !== connectionToken
      ) throw abortError();
    };

    try {
      throwIfAborted();
      if (onProgress) onProgress("Initializing gatekeeper...");
      const gk = await this.getGatekeeper();
      operationGatekeeper = gk;
      throwIfAborted();
      if (onProgress) onProgress("Preparing entry request...");
      const request = await gk.startEntryRequest(password);
      throwIfAborted();

      const challengeTimeoutMs = this.torIntegration.getAdaptedTimeout(10000);
      const waitForChallenge = (): { promise: Promise<any>; cancel: () => void } => {
        let cancel = () => {};
        const promise = new Promise<any>((resolve, reject) => {
        let timeout: ReturnType<typeof setTimeout>;
        let settled = false;
        let unregisterConnectionCancel = () => {};

        const cleanup = () => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_CHALLENGE, onChallenge);
          this.messageHandler.unregisterHandler(SignalType.AUTH_ERROR, onGatekeeperError);
          abortSignal?.removeEventListener('abort', onAbort);
          unregisterConnectionCancel();
        };

        const onGatekeeperError = async (msg: any) => {
          if (settled) return;
          if (msg?.requestId !== gatekeeperRequestId) return;
          settled = true;
          console.warn('[GK-FLOW] Error received during challenge wait:', msg.message || msg.code);
          cleanup();
          reject(new Error(msg.message || 'Authentication error'));
        };

        const onChallenge = async (msg: any) => {
          if (settled) return;
          if (msg?.requestId !== gatekeeperRequestId) return;
          settled = true;
          cleanup();
          resolve(msg);
        };

        const onAbort = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(abortError());
        };

        cancel = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(abortError());
        };

        timeout = setTimeout(() => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(new Error('Gatekeeper challenge timeout'));
        }, challengeTimeoutMs);

        this.messageHandler.registerHandler(SignalType.AUTH_ERROR, onGatekeeperError);
        this.messageHandler.registerHandler(SignalType.SERVER_ENTRY_CHALLENGE, onChallenge);
        unregisterConnectionCancel = this.registerConnectionWaiterCancel(onAbort);
        abortSignal?.addEventListener('abort', onAbort, { once: true });
        if (abortSignal?.aborted) onAbort();
        });
        return { promise, cancel };
      };

      let challenge: any = null;
      let preflightPowSolution: string | undefined;
      for (let round = 0; round < 3; round += 1) {
        const responseWaiter = waitForChallenge();
        let roundAuthChannelBinding: string | null = null;
        try {
          roundAuthChannelBinding = await this.sendSecureControlMessage({
            ...request,
            requestId: gatekeeperRequestId,
            preflightPowSolution
          }, {
            authBindingRequestId: gatekeeperRequestId,
            failIfQueued: true,
            signal: abortSignal
          });
        } catch (error) {
          responseWaiter.cancel();
          await responseWaiter.promise.catch(() => { });
          throw error;
        }
        const response = await responseWaiter.promise;
        throwIfAborted();
        if (!response?.preflightRequired) {
          if (!roundAuthChannelBinding) {
            throw new Error('Server entry channel binding was not transmitted');
          }
          gatekeeperAuthChannelBinding?.fill(0);
          gatekeeperAuthChannelBinding = decodeServerResponseBase64(roundAuthChannelBinding, 64);
          challenge = response;
          break;
        }
        if (onProgress) onProgress("Securing entry request...");
        preflightPowSolution = await solvePowChallenge(response.powChallenge, abortSignal);
        throwIfAborted();
      }
      if (!challenge) throw new Error('Gatekeeper preflight could not be completed');
      if (!gatekeeperAuthChannelBinding) {
        throw new Error('Server entry channel binding is unavailable');
      }
      if (onProgress) onProgress("Verifying challenge...");

      if (onProgress) onProgress("Requesting tokens...");
      let challengeEvaluated: Uint8Array | null = null;
      let challengeNonce: Uint8Array | null = null;
      let challengeEnvelope: Uint8Array | null = null;
      let challengeSalt: Uint8Array | null = null;
      let issuanceRequest: Record<string, any>;
      try {
        challengeEvaluated = decodeServerResponseBase64(challenge.evaluatedElement, 32);
        challengeNonce = decodeServerResponseBase64(challenge.serverNonce, 32);
        challengeEnvelope = decodeServerResponseBase64(challenge.envelope, 72);
        challengeSalt = decodeServerResponseBase64(challenge.salt, 32);
        issuanceRequest = await gk.prepareTokenIssuance({
          evaluatedElement: challengeEvaluated,
          serverNonce: challengeNonce,
          envelope: challengeEnvelope,
          salt: challengeSalt,
          powChallenge: challenge.powChallenge,
          authChannelBinding: gatekeeperAuthChannelBinding
        }, abortSignal);
        throwIfAborted();
      } finally {
        challengeEvaluated?.fill(0);
        challengeNonce?.fill(0);
        challengeEnvelope?.fill(0);
        challengeSalt?.fill(0);
      }
      const issuanceTimeoutMs = this.torIntegration.getAdaptedTimeout(15000);
      let cancelIssuanceWait = () => {};
      const issuancePromise = new Promise<any>((resolve, reject) => {
        let timeout: ReturnType<typeof setTimeout>;
        let settled = false;
        let unregisterConnectionCancel = () => {};

        const cleanup = () => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE, onIssuance);
          this.messageHandler.unregisterHandler(SignalType.AUTH_ERROR, onGatekeeperError);
          abortSignal?.removeEventListener('abort', onAbort);
          unregisterConnectionCancel();
        };

        const onGatekeeperError = async (msg: any) => {
          if (settled) return;
          if (msg?.requestId !== gatekeeperRequestId) return;
          settled = true;
          console.warn('[GK-FLOW] Error received during issuance wait:', msg.message || msg.code);
          cleanup();
          reject(new Error(msg.message || 'Authentication error'));
        };

        const onIssuance = async (msg: any) => {
          if (settled) return;
          if (msg?.requestId !== gatekeeperRequestId) return;
          settled = true;
          cleanup();
          resolve(msg);
        };

        const onAbort = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(abortError());
        };

        cancelIssuanceWait = () => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(abortError());
        };

        timeout = setTimeout(() => {
          if (settled) return;
          settled = true;
          console.error('[GK-FLOW] no issuance received before timeout');
          cleanup();
          reject(new Error('Token issuance timeout'));
        }, issuanceTimeoutMs);

        this.messageHandler.registerHandler(SignalType.AUTH_ERROR, onGatekeeperError);
        this.messageHandler.registerHandler(SignalType.SERVER_ENTRY_TOKEN_ISSUANCE, onIssuance);
        unregisterConnectionCancel = this.registerConnectionWaiterCancel(onAbort);
        abortSignal?.addEventListener('abort', onAbort, { once: true });
        if (abortSignal?.aborted) onAbort();
      });

      if (onProgress) onProgress("Issuing entry tokens...");
      try {
        await this.sendSecureControlMessage({
          ...issuanceRequest,
          requestId: gatekeeperRequestId
        }, { failIfQueued: true, signal: abortSignal });
      } catch (error) {
        cancelIssuanceWait();
        await issuancePromise.catch(() => { });
        throw error;
      }
      const tokenBatch = await issuancePromise;
      throwIfAborted();

      if (onProgress) onProgress("Finalizing entry...");
      // Step 3: Finalize
      let signedBlindedTokens: Uint8Array[] = [];
      let issuanceProof: Uint8Array | null = null;
      let issuerPublicKey: Uint8Array | null = null;
      try {
        if (!Array.isArray(tokenBatch.signedBlindedTokens) || tokenBatch.signedBlindedTokens.length !== 1000) {
          throw new Error('Invalid server-entry issuance batch size');
        }
        signedBlindedTokens = decodeCanonicalBase64List(tokenBatch.signedBlindedTokens, 32, 1000);
        issuanceProof = decodeServerResponseBase64(tokenBatch.proof, 64);
        issuerPublicKey = decodeServerResponseBase64(tokenBatch.publicKey, 32);
        if (!Number.isSafeInteger(tokenBatch.issuerEpoch)) {
          throw new Error('Invalid server-entry token issuer epoch');
        }
        await gk.finalizeEntry(
          signedBlindedTokens,
          issuanceProof,
          issuerPublicKey,
          tokenBatch.issuerEpoch
        );
        throwIfAborted();
      } finally {
        for (const token of signedBlindedTokens) token.fill(0);
        issuanceProof?.fill(0);
        issuerPublicKey?.fill(0);
      }
      // Auto-redeem to fully establish connection
      const redemption = await gk.getRedemptionPayload();
      throwIfAborted();
      if (!redemption) {
        throw new Error('Server entry token issuance produced no redeemable credential');
      }

      const redemptionRequestId = crypto.randomUUID();
      const grantWaiter = this.createServerEntryGrantWaiter(
        this.torIntegration.getAdaptedTimeout(SERVER_ENTRY_GRANT_BASE_TIMEOUT_MS),
        abortSignal,
        redemptionRequestId
      );
      try {
        await this.sendSecureControlMessage({
          ...redemption,
          requestId: redemptionRequestId
        }, { failIfQueued: true, signal: abortSignal });
      } catch (error) {
        grantWaiter.cancel();
        try { await gk.commitPendingTokenUsage(); } catch { }
        throw error;
      }
      const grantResult = await grantWaiter.promise;
      throwIfAborted();
      if (grantResult !== 'granted') {
        console.error('[GK-FLOW] server entry grant not received', { grantResult });
        try { await gk.commitPendingTokenUsage(); } catch { }
        return false;
      }
      await gk.commitPendingTokenUsage();
      this.serverAuthGranted = true;
      window.dispatchEvent(new CustomEvent(EventType.SERVER_ENTRY_GRANTED));

      return true;
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') throw error;
      console.error('[GK-FLOW] FLOW FAILED at:', error);
      const message = error instanceof Error ? error.message : String(error);
      if (/invalid server password|incorrect password|failed to derive server entry proof/i.test(message)) {
        return false;
      }
      throw error;
    } finally {
      if (operationGatekeeper) {
        try { await operationGatekeeper.cancelPendingEntry(); } catch { }
      }
      gatekeeperAuthChannelBinding?.fill(0);
      this.isGatekeeperFlowActive = false;
    }
  }

  // Replace exactly the account credential consumed by this native connection.
  async replaceConsumedAccountAuthorizationToken(): Promise<void> {
    if (
      !tokenVault.isVaultUnlocked() ||
      !this.isInUnlinkedMode ||
      !this.unlinkedSessionReady ||
      !this.unlinkedAccountAuthorizationReady ||
      this.lifecycleState !== 'connected'
    ) return;

    const connectionToken = this.nativeConnectionToken;
    const operationGeneration = this.connectionOperationGeneration;
    if (
      !isNativeWsConnectionToken(connectionToken) ||
      this.accountAuthReplacementConnectionToken === connectionToken
    ) return;

    this.accountAuthReplacementConnectionToken = connectionToken;
    const assertConnectionCurrent = () => {
      if (
        this.nativeConnectionToken !== connectionToken ||
        this.connectionOperationGeneration !== operationGeneration ||
        this.lifecycleState !== 'connected' ||
        !this.unlinkedSessionReady
      ) {
        throw operationAbortError();
      }
    };
    await this.issueAccountAuthorizationReplacement(assertConnectionCurrent);
  }

  private async issueAccountAuthorizationReplacement(
    assertConnectionCurrent: () => void
  ): Promise<void> {
    const requestId = crypto.randomUUID();
    let cancelResponseWait = () => {};
    let refreshPrepared = false;
    let finalized = false;
    try {
      const request = await tokenVault.prepareAuthorizedRefresh(ACCOUNT_AUTH_REPLACEMENT_BATCH_SIZE);
      refreshPrepared = true;
      assertConnectionCurrent();

      const timeoutMs = this.torIntegration.getAdaptedTimeout(
        AUTHORIZED_TOKEN_REFRESH_BASE_TIMEOUT_MS
      );
      const responsePromise = new Promise<any>((resolve, reject) => {
        let settled = false;
        let unregisterConnectionCancel = () => {};
        const cleanup = () => {
          clearTimeout(timeout);
          this.messageHandler.unregisterHandler(
            SignalType.ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE,
            onResponse
          );
          this.messageHandler.unregisterHandler(SignalType.AUTH_ERROR, onError);
          unregisterConnectionCancel();
        };
        const finish = (error: Error | null, value?: any) => {
          if (settled) return;
          settled = true;
          cleanup();
          if (error) reject(error);
          else resolve(value);
        };
        const onResponse = async (message: any) => {
          if (message?.requestId !== requestId) return;
          finish(null, message);
        };
        const onError = async (message: any) => {
          if (message?.requestId !== requestId) return;
          finish(new Error(message?.message || 'Account-auth refresh rejected'));
        };
        const timeout = setTimeout(
          () => finish(new Error('Account-auth refresh timeout')),
          timeoutMs
        );
        cancelResponseWait = () => finish(operationAbortError());
        this.messageHandler.registerHandler(
          SignalType.ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE,
          onResponse
        );
        this.messageHandler.registerHandler(SignalType.AUTH_ERROR, onError);
        unregisterConnectionCancel = this.registerConnectionWaiterCancel(
          cancelResponseWait
        );
      });

      try {
        await this.sendSecureControlMessage({
          type: SignalType.ACCOUNT_AUTH_TOKEN_REFRESH,
          blindedTokens: request.blindedTokens,
          tokenEpoch: request.tokenEpoch,
          requestId
        }, {
          bypassStateCheck: true,
          failIfQueued: true
        });
      } catch (error) {
        cancelResponseWait();
        await responsePromise.catch(() => { });
        throw error;
      }

      const response = await responsePromise;
      assertConnectionCurrent();
      if (
        !isPlainObject(response) ||
        hasPrototypePollutionKeys(response) ||
        !hasExactKeys(response, [
          'issuerEpoch',
          'proof',
          'publicKey',
          'requestId',
          'signedBlindedTokens',
          'type'
        ]) ||
        response.type !== SignalType.ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE ||
        response.requestId !== requestId ||
        !Array.isArray(response.signedBlindedTokens) ||
        response.signedBlindedTokens.length !== ACCOUNT_AUTH_REPLACEMENT_BATCH_SIZE ||
        !Number.isSafeInteger(response.issuerEpoch)
      ) {
        throw new Error('Invalid account-auth refresh response');
      }

      let signedBlindedTokens: Uint8Array[] = [];
      let issuanceProof: Uint8Array | null = null;
      let issuerPublicKey: Uint8Array | null = null;
      try {
        signedBlindedTokens = decodeCanonicalBase64List(
          response.signedBlindedTokens,
          32,
          ACCOUNT_AUTH_REPLACEMENT_BATCH_SIZE
        );
        issuanceProof = decodeServerResponseBase64(response.proof, 64);
        issuerPublicKey = decodeServerResponseBase64(response.publicKey, 32);
        await tokenVault.finalizeAuthorizedRefresh(
          signedBlindedTokens,
          issuanceProof,
          issuerPublicKey,
          Number(response.issuerEpoch)
        );
        finalized = true;
        assertConnectionCurrent();
        const account = this._username;
        if (typeof account !== 'string' || !account) {
          throw new Error('Account identity unavailable for resume-token replacement');
        }
        await replenishResumePool(account);
        assertConnectionCurrent();
      } finally {
        for (const token of signedBlindedTokens) token.fill(0);
        issuanceProof?.fill(0);
        issuerPublicKey?.fill(0);
      }
    } catch (error) {
      console.warn('[WebSocket] Account-auth credential replacement failed', {
        error: error instanceof Error ? error.message : String(error)
      });
    } finally {
      cancelResponseWait();
      if (refreshPrepared && !finalized) {
        try { await tokenVault.discardPendingTokens(); } catch { }
      }
    }
  }

  private createServerEntryGrantWaiter(
    timeoutMs: number = 5000,
    abortSignal?: AbortSignal,
    requestId?: string
  ): {
    promise: Promise<'granted' | 'rejected' | 'timeout' | 'aborted'>;
    cancel: () => void;
  } {
    const connectionToken = this.nativeConnectionToken;
    const isCurrent = () =>
      isNativeWsConnectionToken(connectionToken) && this.nativeConnectionToken === connectionToken;
    let cancel = () => {};
    const promise = new Promise<'granted' | 'rejected' | 'timeout' | 'aborted'>((resolve) => {
      let settled = false;
      let unregisterConnectionCancel = () => {};
      const cleanup = () => {
        clearTimeout(timeout);
        window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
        abortSignal?.removeEventListener('abort', onAbort);
        unregisterConnectionCancel();
      };

      const settle = (result: 'granted' | 'rejected' | 'timeout' | 'aborted') => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(result);
      };

      cancel = () => settle('timeout');

      const timeout = setTimeout(() => {
        settle('timeout');
      }, timeoutMs);

      const handler = (ev: Event) => {
        if (!isCurrent()) {
          settle('aborted');
          return;
        }
        const detail = (ev as CustomEvent).detail;
        if (requestId && detail?.requestId !== requestId) return;
        if (detail?.type === SignalType.OK) {
          settle('granted');
        } else if (detail?.type === SignalType.AUTH_ERROR || detail?.type === SignalType.ERROR) {
          console.warn('[WebSocket] Server entry grant rejected:', detail.message || detail.code || 'unknown');
          settle('rejected');
        }
      };

      const onAbort = () => settle('aborted');

      window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handler as any);
      unregisterConnectionCancel = this.registerConnectionWaiterCancel(() => settle('aborted'));
      abortSignal?.addEventListener('abort', onAbort, { once: true });
      if (abortSignal?.aborted || !isCurrent()) onAbort();
    });
    return { promise, cancel };
  }

  // Close connection
  async close(options: { killSession?: boolean } = {}): Promise<void> {
    this.isManualClose = true;
    this.connectionOperationGeneration += 1;
    this.timestampRecoveryGeneration += 1;
    this.timestampRecoveryInFlight = null;
    this.lastTimestampRecoveryAt = 0;
    this.lifecycleState = 'idle';
    const connectionToken = this.nativeConnectionToken;
    if (connectionToken !== null) {
      this.retiredNativeConnectionToken = Math.max(this.retiredNativeConnectionToken, connectionToken);
    }
    this.nativeConnectionToken = null;
    this.clearCurrentConnectionClock();
    this.invalidateInboundMessages();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    if (options.killSession) {
      this.messageHandler.clearHandlers();
      this.sessionErrorHandlersRegistered = false;
      this.hasOpenedTransport = false;
      this.transportEventReceived = false;
      this._username = undefined;
      this.lastAuthUsername = undefined;
    }
    this.globalRateLimitUntil = 0;
    this.queue.clear();
    
    if (options.killSession) {
      this.resetSessionKeys(false);
    } else {
      this.resetSessionKeys(true);
    }
    this.stopConnectivityWatchdog();
    this.heartbeat.stop();
    this.torIntegration.cleanup();
    this.rateLimiter.reset();
    this.handshake.reset();
    try {
      await websocket.disconnect(connectionToken ?? undefined).catch(() => { });
    } catch { }
  }

  // Check if connected to server
  isConnectedToServer(): boolean { return this.lifecycleState === 'connected'; }

  // Check if unlinked mode is active
  isUnlinkedMode(): boolean { return this.isInUnlinkedMode; }

  // Check if PQ session established
  isPQSessionEstablished(): boolean { return !!this.sessionKeyMaterial; }

  getAnonymousHttpServerKeyMaterial(): ServerKeyMaterial | null {
    const material = this.handshake.getServerKeyMaterial();
    if (
      this.lifecycleState !== 'connected' ||
      !this.sessionKeyMaterial ||
      !material ||
      !material.dilithiumPublicKey ||
      !material.x25519PublicKey ||
      material.fingerprint !== this.sessionKeyMaterial.fingerprint
    ) return null;

    return {
      kyberPublicKey: new Uint8Array(material.kyberPublicKey),
      dilithiumPublicKey: new Uint8Array(material.dilithiumPublicKey),
      x25519PublicKey: new Uint8Array(material.x25519PublicKey),
      fingerprint: material.fingerprint,
      serverId: material.serverId,
    };
  }

  getAuthenticatedServerNow(): number | null {
    return this.lifecycleState === 'connected' && this.sessionKeyMaterial
      ? this.getTrustedNow()
      : null;
  }

  // Bind caller work to one native socket without exposing account material.
  captureConnectionPrivacyEpoch(): number | null { return this.nativeConnectionToken; }

  isConnectionPrivacyEpochCurrent(epoch: number | null): boolean {
    return !this.isManualClose &&
      isNativeWsConnectionToken(epoch) &&
      epoch === this.nativeConnectionToken;
  }

  private isTransientlyUnavailable(): boolean {
    return (
      (this.lifecycleState === 'paused' || this.lifecycleState === 'handshaking' || this.lifecycleState === 'connecting') &&
      isNativeWsConnectionToken(this.nativeConnectionToken)
    );
  }

  private async waitForConnectedSettle(timeoutMs: number, signal?: AbortSignal): Promise<boolean> {
    if (this.lifecycleState === 'connected') return true;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (this.isManualClose || signal?.aborted) return false;
      if (this.lifecycleState === 'connected') return true;
      if (!this.isTransientlyUnavailable()) return false;
      try {
        await waitForAbortableDelay(50, signal);
      } catch {
        return false;
      }
    }
    return this.lifecycleState === 'connected';
  }

  // Wait until the socket is fully connected with an established PQ session
  async waitUntilReady(timeoutMs: number = 30000, signal?: AbortSignal): Promise<boolean> {
    const ready = () => this.isConnectedToServer() && this.isPQSessionEstablished();
    if (signal?.aborted) return false;
    if (ready()) return true;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        await waitForAbortableDelay(150, signal);
      } catch (error) {
        if (signal?.aborted) return false;
        throw error;
      }
      if (ready()) return true;
    }
    return ready();
  }

  // Send secure control message
  async sendSecureControlMessage(
    message: any,
    options: SecureControlSendOptions = {}
  ): Promise<string | null> {
    throwIfOperationAborted(options.signal);
    const entryContext = this.captureOutboundTransportContext();
    let messageType = typeof message?.type === 'string' ? message.type : '';
    if (!messageType && typeof message === 'string') {
      try {
        const parsed = JSON.parse(message);
        messageType = typeof parsed?.type === 'string' ? parsed.type : '';
      } catch { }
    }
    const failIfQueued = options.failIfQueued === true || NON_QUEUEABLE_CONTROL_TYPES.has(messageType);
    if (!this.isPQSessionEstablished()) {
      if (this.lifecycleState === 'connected' || options.bypassStateCheck) {
        try {
          await this.performHandshake(false);
        } catch { }
        throwIfOperationAborted(options.signal);
        this.assertOutboundTransportContextCurrent(entryContext);
      }
      if (this.lifecycleState !== 'connected' && !options.bypassStateCheck) {
        if (failIfQueued) {
          throw new Error('WebSocket not connected');
        }
        if (!this.queue.enqueuePending({ ...this.queue.createEntry(message, Date.now()), highPriority: true })) {
          throw new Error('WebSocket queue is full');
        }
        return null;
      }
      const maxWaitTime = 10000;
      const startTime = Date.now();
      while (!this.isPQSessionEstablished() && (Date.now() - startTime) < maxWaitTime) {
        await waitForAbortableDelay(100, options.signal);
      }
      if (!this.isPQSessionEstablished()) {
        if (failIfQueued) {
          throw new Error('PQ session not established');
        }
        if (!this.queue.enqueuePending({ ...this.queue.createEntry(message, Date.now() + 500), highPriority: true })) {
          throw new Error('WebSocket queue is full');
        }
        void this.performHandshake(false).catch(() => { });
        return null;
      }
    }
    throwIfOperationAborted(options.signal);
    
    if (
      this.lifecycleState !== 'connected' &&
      !options.bypassStateCheck &&
      this.isTransientlyUnavailable()
    ) {
      await this.waitForConnectedSettle(this.torIntegration.getAdaptedTimeout(15000), options.signal);
      throwIfOperationAborted(options.signal);
    }
    const authChannelBinding = await this.dispatchPayload(
      typeof message === 'string' ? message : JSON.stringify(message),
      !failIfQueued,
      options
    );
    if (options.authBindingRequestId && typeof authChannelBinding !== 'string') {
      throw new Error('Authentication request channel binding was not transmitted');
    }
    return typeof authChannelBinding === 'string' ? authChannelBinding : null;
  }

  // Set server key material
  setServerKeyMaterial(
    hybridKeys: { kyberPublicBase64: string; dilithiumPublicBase64?: string; x25519PublicBase64?: string },
    serverId?: string
  ): 'activated' | 'rejected' {
    try {
      if (!hybridKeys?.kyberPublicBase64 || !hybridKeys?.dilithiumPublicBase64 || !hybridKeys?.x25519PublicBase64) {
        throw new Error('Incomplete server key material for authenticated PQ transport');
      }
      
      const pinned = this.getPinnedServerPQKeys();
      if (!pinned) {
        return 'rejected';
      }
      if (
        pinned.kyber !== hybridKeys.kyberPublicBase64 ||
        pinned.dilithium !== hybridKeys.dilithiumPublicBase64 ||
        pinned.x25519 !== hybridKeys.x25519PublicBase64
      ) {
        return 'rejected';
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
      return 'activated';
    } catch {
      console.error('[WebSocket] setServerKeyMaterial failed');
      return 'rejected';
    }
  }

  private getPinnedServerPQKeys(): { kyber: string; dilithium: string; x25519: string } | null {
    const pinned = PinnedServer.get();
    return pinned ? {
      kyber: pinned.kyberPublicBase64,
      dilithium: pinned.dilithiumPublicBase64,
      x25519: pinned.x25519PublicBase64
    } : null;
  }

  async decryptIncomingEnvelope(envelope: any): Promise<any | null> { return this.encryption.decryptEnvelope(envelope); }
  async flushPendingQueue(): Promise<void> { return this.queue.flush(); }
  async reserveServerEntryAuthorization(): Promise<Record<string, any> | null> {
    const gatekeeper = await this.getGatekeeper();
    return gatekeeper.reserveRedemptionPayload();
  }
}

const websocketClient = new WebSocketConnection();
export default websocketClient;
