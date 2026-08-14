import { SignalType } from "./signal-types";
import { PROTOCOL_KEYS } from "../config/protocol-keys";

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
  SignalType.PQ_HANDSHAKE_CONFIRMED,
  SignalType.PQ_HEARTBEAT_PONG,
  SignalType.AUTH_ERROR,
  SignalType.TOKEN_VALIDATION_RESPONSE,
  SignalType.ERROR,
  SignalType.SERVER_PUBLIC_KEY,
  SignalType.AUTH_FULL_SUCCESS,
  SignalType.SEALED_ENVELOPE,
]);

export const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.PQ_ENVELOPE,
  SignalType.SEALED_ENVELOPE,
]);

export const DEFAULT_SCHEMAS: Record<string, WebSocketMessageSchema> = {
  [SignalType.PQ_ENVELOPE]: {
    validate: (message) =>
      typeof (message as any).version === 'string' &&
      (message as any).version === PROTOCOL_KEYS.WS_PQ_PROTOCOL_VERSION &&
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
  onAuthenticatedServerTime: (serverTime: number) => void;
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
