import { useEffect, useMemo, useRef } from "react";
import { SignalType } from "@/lib/types/signal-types";
import { EventType } from "../lib/types/event-types";
import websocketClient from "@/lib/websocket";
import { WEBSOCKET_RATE_LIMIT_MAX_MESSAGES, WEBSOCKET_RATE_LIMIT_WINDOW_MS } from "@/lib/constants";
import { isPlainObject, hasPrototypePollutionKeys } from "@/lib/sanitizers";
import { BaseMessage, WebSocketMessageSchema, DEFAULT_ALLOWED_TYPES, DEFAULT_ENCRYPTED_TYPES, DEFAULT_SCHEMAS, WebSocketHookOptions } from "@/lib/types/websocket-types";

type MessageHandler = (data: BaseMessage) => Promise<void>;

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
        if (now - bucket.windowStart > WEBSOCKET_RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > WEBSOCKET_RATE_LIMIT_MAX_MESSAGES) {
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

        // Enforce encrypted only mode after PQ session establishment
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

        // Decrypt pq-envelope
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
            try { window.dispatchEvent(new CustomEvent(EventType.USER_EXISTS_RESPONSE, { detail: inner })); } catch { }
          }
          if (inner.type === SignalType.P2P_PEER_CERT) {
            try { window.dispatchEvent(new CustomEvent(EventType.P2P_PEER_CERT, { detail: inner })); } catch { }
          }

          if (inner.type === SignalType.DEVICE_CHALLENGE || inner.type === SignalType.DEVICE_ATTESTATION_ACK) {
            try { websocketClient.handleEdgeServerMessage(inner); } catch { }
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
        try { consumed = websocketClient.handleEdgeServerMessage(detail); } catch { }
        if (consumed) { return; }

        handler(detail ?? evt).catch((error) => {
          console.error('[useWebSocket] Handler error:', error instanceof Error ? error.message : 'Unknown error');
        });
      } catch (_error) {
        console.error('[useWebSocket] Listener exception:', _error instanceof Error ? _error.message : 'Unknown error');
      }
    };

    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, listener as EventListener);
    return () => {
      window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, listener as EventListener);
    };
  }, [allowedTypes, routeMessage, schemas, setLoginError]);
};