import { SignalType } from "./signal-types";

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
  SignalType.PQ_HANDSHAKE_ACK,
  SignalType.PQ_HANDSHAKE_CONFIRMED,
  SignalType.PQ_HEARTBEAT_PONG,
  SignalType.AUTH_ERROR,
  SignalType.TOKEN_VALIDATION_RESPONSE,
  SignalType.ERROR,
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.AUTH_FULL_SUCCESS,
  SignalType.SERVER_ENTRY_CREDENTIAL_ROTATED,
  SignalType.SEALED_ENVELOPE,
]);

export const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.SERVER_ENTRY_CREDENTIAL_ROTATED,
  SignalType.SEALED_ENVELOPE,
]);

export const DEFAULT_SCHEMAS: Record<string, WebSocketMessageSchema> = {};

export interface PendingSend {
  id: string;
  payload: unknown;
  createdAt: number;
  attempt: number;
  flushAfter: number;
  highPriority?: boolean;
  byteLength: number;
}

export interface ServerKeyMaterial {
  kyberPublicKey: Uint8Array;
  dilithiumPublicKey?: Uint8Array;
  x25519PublicKey?: Uint8Array;
  fingerprint: string;
  serverId?: string;
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
}

export interface HandshakeCallbacks {
  transmit: (message: string) => Promise<void>;
  transmitHandshake: (message: Record<string, unknown>) => Promise<void>;
  runOnSecureSendLane: <T>(operation: () => Promise<T>) => Promise<T>;
  registerMessageHandler: (type: string, handler: MessageHandler) => void;
  unregisterMessageHandler: (type: string, handler?: MessageHandler) => void;
  getTorAdaptedTimeout: (baseTimeout: number) => number;
  onSessionEstablished: (session: SessionKeyMaterial) => void;
  onHandshakeError: (error: Error) => void;
  onDiagnostic: (
    phase: string,
    details?: Record<string, unknown>,
    level?: 'info' | 'warn' | 'error'
  ) => void;
  onAuthenticatedServerTime: (serverTime: number) => void;
  isConnected: () => boolean | Promise<boolean>;
  getTrustedNow: () => number;
}

export interface HeartbeatCallbacks {
  onSendHeartbeat: () => Promise<void>;
  onConnectionLost: (error: Error) => void;
  onRehandshakeNeeded: () => void;
  getLifecycleState: () => string;
  getSessionId: () => string | undefined;
}
