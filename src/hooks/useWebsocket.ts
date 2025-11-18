import { useEffect, useMemo, useRef } from "react";
import { SignalType } from "@/lib/signal-types";
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
  // Transport-level envelope (must be decrypted client-side)
  'pq-envelope',
  'pq-handshake-ack',
  // Heartbeat messages
  'pq-heartbeat-pong',
  // Client error reporting
  'client-error',
  
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
  'libsignal-publish-status',
  SignalType.SESSION_RESET_REQUEST,
  SignalType.EDIT_MESSAGE,
  SignalType.DELETE_MESSAGE,
  SignalType.USER_DISCONNECT,
  SignalType.FILE_MESSAGE_CHUNK,
  SignalType.MESSAGE_HISTORY_RESPONSE,
  SignalType.OFFLINE_MESSAGES_RESPONSE,
  'delivery-receipt',
  'read-receipt',
]);

const RATE_LIMIT_WINDOW_MS = 1_000;
const RATE_LIMIT_MAX_MESSAGES = 500;

const DEFAULT_ENCRYPTED_TYPES = new Set<string>([
  // Transport-level envelope treated specially (decrypted, then routed)
  'pq-envelope',
  
  // App-level encrypted payloads
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
  ['pq-envelope']: {
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

        const data = sanitizeIncomingMessage(raw, allowedTypes, schemas);
        if (!data) {
          return;
        }

        // Enforce encrypted-only mode after PQ session establishment
        const sessionEstablished = websocketClient.isPQSessionEstablished();
        const isHandshakeMessage = data.type === SignalType.SERVER_PUBLIC_KEY || 
                                   data.type === SignalType.SESSION_ESTABLISHED ||
                                   data.type === 'pq-handshake-ack';
        const isEncryptedTransport = data.type === 'pq-envelope' || data.type === 'pq-heartbeat-pong';
        const isErrorMessage = data.type === SignalType.ERROR;
        const isSafeControl = data.type === SignalType.TOKEN_VALIDATION_RESPONSE ||
                              data.type === SignalType.IN_ACCOUNT ||
                              data.type === SignalType.AUTH_SUCCESS ||
                              data.type === SignalType.AUTH_ERROR ||
                              data.type === SignalType.PASSWORD_HASH_PARAMS;
        
        if (sessionEstablished && !isEncryptedTransport && !isHandshakeMessage && !isErrorMessage && !isSafeControl) {
          console.error('[useWebSocket] Security violation: plaintext after encryption established');
          setLoginError('Security violation: plaintext message after encryption established');
          return;
        }

        if (data.type === SignalType.USER_EXISTS_RESPONSE) {
          try {
            window.dispatchEvent(new CustomEvent('user-exists-response', { detail: data }));
          } catch {
          }
        }
        if (data.type === SignalType.P2P_PEER_CERT) {
          try {
            window.dispatchEvent(new CustomEvent('p2p-peer-cert', { detail: data }));
          } catch {}
        }

        // Heartbeat pong from server
        if (data.type === 'pq-heartbeat-pong') {
          websocketClient.noteHeartbeatPong(data);
          return;
        }

        // Decrypt pq-envelope using the client's session keys
        if (data.type === 'pq-envelope') {
          await new Promise(resolve => setTimeout(resolve, 0));
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
              window.dispatchEvent(new CustomEvent('user-exists-response', { detail: inner }));
            } catch {
            }
          }
          if (inner.type === SignalType.P2P_PEER_CERT) {
            try {
              window.dispatchEvent(new CustomEvent('p2p-peer-cert', { detail: inner }));
            } catch {}
          }

          await new Promise(resolve => setTimeout(resolve, 0));
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