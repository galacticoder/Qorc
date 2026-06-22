import { SignalType } from "./signal-types";

export type IncomingGlobalSpoolCandidateCallback = (message: any) => void | Promise<void>;

export interface WebSocketMessageSchema {
  validate: (message: BaseMessage) => boolean;
}

export interface WebSocketHookOptions {
  schemas?: Record<string, WebSocketMessageSchema>;
  onAudit?: (event: { code: string; type: string }) => void;
}

export interface BaseMessage {
  type: string;
  [key: string]: unknown;
}

export const DEFAULT_ALLOWED_TYPES: Set<string> = new Set([
  SignalType.PQ_ENVELOPE,
  SignalType.PQ_HANDSHAKE_ACK,
  SignalType.PQ_HEARTBEAT_PONG,
  SignalType.SERVERMESSAGE,
  SignalType.AUTH_ERROR,
  SignalType.TOKEN_VALIDATION_RESPONSE,
  SignalType.ERROR,
  SignalType.BLOCK_LIST_UPDATE,
  SignalType.BLOCK_LIST_SYNC,
  SignalType.BLOCK_LIST_RESPONSE,
  SignalType.SESSION_ESTABLISHED,
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.AUTH_FULL_SUCCESS,
  SignalType.LIBSIGNAL_DELIVER_BUNDLE,
  SignalType.SESSION_RESET_REQUEST,
  SignalType.EDIT_MESSAGE,
  SignalType.DELETE_MESSAGE,
  SignalType.FILE_MESSAGE_CHUNK,
  SignalType.DELIVERY_RECEIPT,
  SignalType.READ_RECEIPT,
  SignalType.PUBLISH_DISCOVERY,
  SignalType.DISCOVERY_SNAPSHOT,
  SignalType.PIR_MANIFEST,
  SignalType.PIR_RESPONSE,
  SignalType.SEALED_ENVELOPE,
]);

export const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.PQ_ENVELOPE,
  SignalType.SEALED_ENVELOPE,
]);

export const DEFAULT_SCHEMAS: Record<string, WebSocketMessageSchema> = {
  [SignalType.ENCRYPTED_MESSAGE]: {
    validate: (message) => typeof message.encryptedPayload === 'object' && message.encryptedPayload !== null,
  },
  [SignalType.PQ_ENVELOPE]: {
    validate: (message) =>
      typeof (message as any).version === 'string' &&
      (message as any).version === 'pq-ws-1' &&
      typeof (message as any).sessionId === 'string' &&
      typeof (message as any).sessionFingerprint === 'string' &&
      typeof (message as any).messageId === 'string' &&
      typeof (message as any).counter === 'number' &&
      typeof (message as any).timestamp === 'number' &&
      typeof (message as any).nonce === 'string' &&
      typeof (message as any).ciphertext === 'string' &&
      typeof (message as any).tag === 'string' &&
      typeof (message as any).aad === 'string' &&
      typeof (message as any).signature === 'string',
  },
};

export type WebSocketLifecycleState =
  | 'idle'
  | 'tor-check'
  | 'connecting'
  | 'handshaking'
  | 'connected'
  | 'disconnected'
  | 'paused'
  | SignalType.ERROR;

export interface PendingSend {
  id: string;
  payload: unknown;
  createdAt: number;
  attempt: number;
  flushAfter: number;
  highPriority?: boolean;
}

export interface ServerKeyMaterial {
  kyberPublicKey: Uint8Array;
  dilithiumPublicKey?: Uint8Array;
  x25519PublicKey?: Uint8Array;
  fingerprint: string;
  serverId?: string;
}

export interface ConnectionMetrics {
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

export interface RateLimitState {
  messageTimestamps: number[];
  lastResetTime: number;
  violationCount: number;
}

export interface ConnectionHealth {
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

export interface MessageHandler {
  (message: unknown): void;
}

export interface SessionKeyMaterial {
  sessionId: string;
  sendKey: Uint8Array;
  recvKey: Uint8Array;
  establishedAt: number;
  fingerprint: string;
  clientSigningPublicKey?: Uint8Array;
}

export interface EncryptionContext {
  sessionKeyMaterial?: SessionKeyMaterial;
  previousSessionKeyMaterial?: SessionKeyMaterial;
  previousSessionFingerprint?: string;
  sessionTransitionTime?: number;
  serverSignatureKey?: Uint8Array;
  signingKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
}

export interface HandshakeCallbacks {
  transmit: (message: string) => Promise<void>;
  registerMessageHandler: (type: string, handler: MessageHandler) => void;
  unregisterMessageHandler: (type: string, handler?: MessageHandler) => void;
  getQueueLength: () => number;
  getTorAdaptedTimeout: (baseTimeout: number) => number;
  onSessionEstablished: (
    session: SessionKeyMaterial,
    serverSignatureKey?: Uint8Array,
    signingKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array }
  ) => void;
  onHandshakeError: (error: Error) => void;
  isConnected: () => boolean | Promise<boolean>;
  getTrustedNow?: () => number;
}

export interface HeartbeatCallbacks {
  onSendHeartbeat: () => Promise<void>;
  onConnectionLost: (error: Error) => void;
  onRehandshakeNeeded: () => void;
  getLifecycleState: () => string;
  getSessionId: () => string | undefined;
}

export interface MessageHandlerCallbacks {
  decryptEnvelope: (envelope: any) => Promise<any | null>;
  handleHeartbeatResponse: (message: any) => void;
}

// Offline messaging
export interface EncryptedPayload {
  content: string;
  nonce: string;
  tag: string;
  mac: string;
  aad?: string;
  kemCiphertext?: string;
  envelopeVersion?: string;
  sessionId?: string;
  type?: string;
}

export interface QueuedMessage {
  id: string;
  to: string;
  encryptedPayload: EncryptedPayload;
  timestamp: number;
  retryCount: number;
  maxRetries: number;
  expiresAt: number;
  nextAttempt: number;
  sizeBytes: number;
}

export interface GlobalSpoolCandidateItem {
  kind?: 'message' | 'pad';
  type?: string;
  envelope?: Record<string, unknown>;
  pad?: string;
}

export interface UserStatus {
  username: string;
  isOnline: boolean;
  lastSeen: number;
}

export interface QueueStats {
  totalQueuedMessages: number;
  usersWithQueuedMessages: number;
  onlineUsers: number;
  totalUsers: number;
}

export interface QueueMetrics {
  messagesQueued: number;
  messagesDelivered: number;
  messagesFailed: number;
  messagesExpired: number;
}
