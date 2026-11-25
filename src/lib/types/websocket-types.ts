
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

export { DEFAULT_ALLOWED_TYPES } from "../constants/interface";

export { DEFAULT_ENCRYPTED_TYPES } from "../constants/interface";

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
