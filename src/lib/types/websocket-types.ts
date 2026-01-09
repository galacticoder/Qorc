import { SignalType } from "./signal-types";
import { LongTermEnvelope } from '../cryptography/long-term-encryption';

export type IncomingOfflineMessageCallback = (message: any) => void | Promise<void>;

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
  SignalType.CLIENT_ERROR,
  SignalType.DEVICE_CHALLENGE,
  SignalType.DEVICE_ATTESTATION_ACK,
  SignalType.AVATAR_FETCH_RESPONSE,
  SignalType.AVATAR_UPLOAD_RESPONSE,
  SignalType.ENCRYPTED_MESSAGE,
  SignalType.DR_SEND,
  SignalType.SERVERMESSAGE,
  SignalType.SERVERLIMIT,
  SignalType.AUTH_ERROR,
  SignalType.NAMEEXISTSERROR,
  SignalType.INVALIDNAME,
  SignalType.INVALIDNAMELENGTH,
  SignalType.TOKEN_VALIDATION_RESPONSE,
  SignalType.ERROR,
  SignalType.BLOCK_LIST_UPDATE,
  SignalType.BLOCK_LIST_SYNC,
  SignalType.BLOCK_LIST_RESPONSE,
  SignalType.PASSPHRASE_HASH,
  SignalType.PASSPHRASE_SUCCESS,
  SignalType.PASSWORD_HASH_PARAMS,
  SignalType.CONNECTION_RESTORED,
  SignalType.SESSION_ESTABLISHED,
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.IN_ACCOUNT,
  SignalType.AUTH_SUCCESS,
  SignalType.USER_EXISTS_RESPONSE,
  SignalType.P2P_PEER_CERT,
  SignalType.LIBSIGNAL_DELIVER_BUNDLE,
  SignalType.LIBSIGNAL_PUBLISH_STATUS,
  SignalType.SESSION_RESET_REQUEST,
  SignalType.EDIT_MESSAGE,
  SignalType.DELETE_MESSAGE,
  SignalType.USER_DISCONNECT,
  SignalType.FILE_MESSAGE_CHUNK,
  SignalType.OFFLINE_MESSAGES_RESPONSE,
  SignalType.DELIVERY_RECEIPT,
  SignalType.READ_RECEIPT,
]);

export const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.PQ_ENVELOPE,
  SignalType.ENCRYPTED_MESSAGE,
  SignalType.DR_SEND,
]);

export const DEFAULT_SCHEMAS: Record<string, WebSocketMessageSchema> = {
  [SignalType.ENCRYPTED_MESSAGE]: {
    validate: (message) => typeof message.encryptedPayload === 'object' && message.encryptedPayload !== null,
  },
  [SignalType.DR_SEND]: {
    validate: (message) => typeof message.payload === 'object' && message.payload !== null,
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
      typeof (message as any).aad === 'string',
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
}

export interface EncryptionContext {
  sessionKeyMaterial?: SessionKeyMaterial;
  previousSessionFingerprint?: string;
  sessionTransitionTime?: number;
  serverSignatureKey?: Uint8Array;
  signingKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
}

export interface HandshakeCallbacks {
  transmit: (message: string) => Promise<void>;
  registerMessageHandler: (type: string, handler: MessageHandler) => void;
  unregisterMessageHandler: (type: string) => void;
  getQueueLength: () => number;
  getTorAdaptedTimeout: (baseTimeout: number) => number;
  onSessionEstablished: (session: SessionKeyMaterial, serverSignatureKey?: Uint8Array) => void;
  onHandshakeError: (error: Error) => void;
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

export interface OfflineMessage {
  encryptedPayload?: EncryptedPayload;
  longTermEnvelope?: LongTermEnvelope;
  version?: string;
  messageId?: string;
  to?: string;
  from?: string;
  expiresAt?: number;
  maxRetries?: number;
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