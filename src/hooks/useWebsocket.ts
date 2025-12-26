import { useEffect, useMemo, useRef } from "react";
import { SignalType } from "@/lib/signal-types";
import { EventType } from "../lib/event-types";
import websocketClient from "@/lib/websocket";

type MessageHandler = (data: BaseMessage) => Promise<void>;

interface WebSocketMessageSchema {
  validate: (message: BaseMessage) => boolean;
}

interface WebSocketHookOptions {
  schemas?: Record<string, WebSocketMessageSchema>;
  onAudit?: (event: { code: string; type: string }) => void;
}

interface BaseMessage {
  type: string;
  [key: string]: unknown;
}

const DEFAULT_ALLOWED_TYPES: Set<string> = new Set([
  // Transport-level envelope
  SignalType.PQ_ENVELOPE,
  SignalType.PQ_HANDSHAKE_ACK,
  // Heartbeat messages
  SignalType.PQ_HEARTBEAT_PONG,
  // Client error reporting
  SignalType.CLIENT_ERROR,

  // Device attestation
  SignalType.DEVICE_CHALLENGE,
  SignalType.DEVICE_ATTESTATION_ACK,

  // Profile picture system
  SignalType.AVATAR_FETCH_RESPONSE,
  SignalType.AVATAR_UPLOAD_RESPONSE,

  // App-level messages
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

const RATE_LIMIT_WINDOW_MS = 1_000;
const RATE_LIMIT_MAX_MESSAGES = 500;

const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  SignalType.PQ_ENVELOPE,
  SignalType.ENCRYPTED_MESSAGE,
  SignalType.DR_SEND,
]);

const DEFAULT_SCHEMAS: Record<string, WebSocketMessageSchema> = {
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

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value == null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
};

const sanitizeIncomingMessage = (
  payload: unknown,
  allowedTypes: Set<string>,
  schemas: Record<string, WebSocketMessageSchema>,
): BaseMessage | null => {
  if (!payload || typeof payload !== 'object') return null;

  if (!isPlainObject(payload)) return null;
  if (hasPrototypePollutionKeys(payload)) return null;

  const type = (payload as BaseMessage).type;
  if (typeof type !== 'string' || type.length === 0 || type.length > 128) return null;
  if (/[\x00-\x1F\x7F]/.test(type)) return null;
  if (!allowedTypes.has(type)) return null;

  const schema = schemas[type];
  if (schema && !schema.validate(payload as BaseMessage)) {
    return null;
  }

  return payload as BaseMessage;
};

export const useWebSocket = (
  handleServerMessage: MessageHandler,
  handleEncryptedMessage: MessageHandler,
  setLoginError: (error: string) => void,
  options: WebSocketHookOptions = {},
) => {
  const { schemas: customSchemas, onAudit } = options;

  const { allowedTypes, encryptedTypes, schemas } = useMemo(() => {
    const mergedSchemas = { ...DEFAULT_SCHEMAS, ...(customSchemas ?? {}) };
    return {
      allowedTypes: new Set([...DEFAULT_ALLOWED_TYPES, ...(customSchemas ? Object.keys(customSchemas) : [])]),
      encryptedTypes: new Set([...DEFAULT_ENCRYPTED_TYPES]),
      schemas: mergedSchemas,
    };
  }, [customSchemas]);

  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  const routeMessage = useMemo(
    () =>
      async (data: BaseMessage) => {
        const isEncrypted = encryptedTypes.has(data.type);

        if (isEncrypted) {
          await handleEncryptedMessage(data);
        } else {
          await handleServerMessage(data);
        }
        onAudit?.({ code: 'ROUTE', type: data.type });
      },
    [encryptedTypes, handleEncryptedMessage, handleServerMessage, onAudit],
  );

  useEffect(() => {
    const handler = async (raw: unknown) => {
      try {
        // Rate limiting
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > RATE_LIMIT_MAX_MESSAGES) {
          return;
        }

        if (raw && typeof raw === 'object' && (raw as any)._decryptedInBackground === true) {
          const bgData = raw as BaseMessage;
          await handleEncryptedMessage(bgData);
          return;
        }

        const data = sanitizeIncomingMessage(raw, allowedTypes, schemas);
        if (!data) {
          return;
        }

        // Enforce encrypted-only mode after PQ session establishment
        const sessionEstablished = websocketClient.isPQSessionEstablished();
        const isHandshakeMessage = data.type === SignalType.SERVER_PUBLIC_KEY ||
          data.type === SignalType.SESSION_ESTABLISHED ||
          data.type === SignalType.PQ_HANDSHAKE_ACK;
        const isEncryptedTransport = data.type === SignalType.PQ_ENVELOPE || data.type === SignalType.PQ_HEARTBEAT_PONG;
        const isErrorMessage = data.type === SignalType.ERROR;
        const isSafeControl = data.type === SignalType.TOKEN_VALIDATION_RESPONSE ||
          data.type === SignalType.IN_ACCOUNT ||
          data.type === SignalType.AUTH_SUCCESS ||
          data.type === SignalType.AUTH_ERROR ||
          data.type === SignalType.PASSWORD_HASH_PARAMS ||
          data.type === SignalType.DEVICE_CHALLENGE ||
          data.type === SignalType.DEVICE_ATTESTATION_ACK;

        if (sessionEstablished && !isEncryptedTransport && !isHandshakeMessage && !isErrorMessage && !isSafeControl) {
          console.error('[useWebSocket] Security violation: plaintext after encryption established');
          setLoginError('Security violation: plaintext message after encryption established');
          return;
        }

        if (data.type === SignalType.USER_EXISTS_RESPONSE) {
          try {
            window.dispatchEvent(new CustomEvent(EventType.USER_EXISTS_RESPONSE, { detail: data }));
          } catch {
          }
        }
        if (data.type === SignalType.P2P_PEER_CERT) {
          try {
            window.dispatchEvent(new CustomEvent(EventType.P2P_PEER_CERT, { detail: data }));
          } catch { }
        }

        // Heartbeat pong from server
        if (data.type === SignalType.PQ_HEARTBEAT_PONG) {
          websocketClient.noteHeartbeatPong(data);
          return;
        }

        if (data.type === SignalType.DEVICE_CHALLENGE || data.type === SignalType.DEVICE_ATTESTATION_ACK) {
          return;
        }

        // Decrypt pq-envelope using the client's session keys
        if (data.type === SignalType.PQ_ENVELOPE) {
          const decrypted = await websocketClient.decryptIncomingEnvelope(data);
          if (!decrypted) {
            return;
          }

          const inner = sanitizeIncomingMessage(decrypted, allowedTypes, schemas);
          if (!inner) {
            return;
          }

          if (inner.type === SignalType.USER_EXISTS_RESPONSE) {
            try {
              window.dispatchEvent(new CustomEvent(EventType.USER_EXISTS_RESPONSE, { detail: inner }));
            } catch {
            }
          }
          if (inner.type === SignalType.P2P_PEER_CERT) {
            try {
              window.dispatchEvent(new CustomEvent(EventType.P2P_PEER_CERT, { detail: inner }));
            } catch { }
          }

          if (inner.type === SignalType.DEVICE_CHALLENGE || inner.type === SignalType.DEVICE_ATTESTATION_ACK) {
            try {
              websocketClient.handleEdgeServerMessage(inner);
            } catch {
            }
            return;
          }

          await routeMessage(inner);
          return;
        }

        await routeMessage(data);
      } catch (_error) {
        console.error('[useWebSocket] Message handler error:', _error instanceof Error ? _error.message : 'Unknown error');
        setLoginError('Secure transport error');
      }
    };

    const listener = (evt: Event) => {
      try {
        const detail = (evt as CustomEvent).detail;

        if (detail != null && typeof detail === 'object') {
          if (hasPrototypePollutionKeys(detail)) {
            return;
          }
        }

        let consumed = false;
        try {
          consumed = websocketClient.handleEdgeServerMessage(detail);
        } catch {
        }

        if (consumed) {
          return;
        }

        handler(detail ?? evt).catch((error) => {
          console.error('[useWebSocket] Handler error:', error instanceof Error ? error.message : 'Unknown error');
        });
      } catch (_error) {
        console.error('[useWebSocket] Listener exception:', _error instanceof Error ? _error.message : 'Unknown error');
      }
    };

    window.addEventListener('edge:server-message', listener as EventListener);
    return () => {
      window.removeEventListener('edge:server-message', listener as EventListener);
    };
  }, [allowedTypes, routeMessage, schemas, setLoginError]);
};