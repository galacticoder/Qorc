import { useEffect, useLayoutEffect, useMemo, useRef, useCallback } from "react";
import { SignalType } from "@/lib/types/signal-types";
import { EventType } from "../lib/types/event-types";
import websocketClient from "@/lib/websocket/websocket";
import { WEBSOCKET_RATE_LIMIT_MAX_MESSAGES, WEBSOCKET_RATE_LIMIT_WINDOW_MS } from "@/lib/constants";
import { isPlainObject, hasPrototypePollutionKeys } from "@/lib/sanitizers";
import { BaseMessage, WebSocketMessageSchema, DEFAULT_ALLOWED_TYPES, DEFAULT_ENCRYPTED_TYPES, DEFAULT_SCHEMAS, WebSocketHookOptions } from "@/lib/types/websocket-types";

type MessageHandler = (data: BaseMessage) => Promise<boolean | void>;
const ROUTE_QUEUE_MAX_COUNT = 128;
const ROUTE_QUEUE_MAX_BYTES = 24 * 1024 * 1024;

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
  accountIdentity: string,
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
  const routeQueueRef = useRef<{
    items: Array<{ detail: unknown; isSecure: boolean; bytes: number; generation: number }>;
    bytes: number;
    draining: boolean;
    generation: number;
  }>({ items: [], bytes: 0, draining: false, generation: 0 });
  const routeAccountRef = useRef(accountIdentity);

  useLayoutEffect(() => {
    if (routeAccountRef.current === accountIdentity) return;
    routeAccountRef.current = accountIdentity;
    const queue = routeQueueRef.current;
    queue.generation += 1;
    queue.items = [];
    queue.bytes = 0;
    rateLimitRef.current = { windowStart: Date.now(), count: 0 };
  }, [accountIdentity]);

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

  const handler = useCallback(async (raw: unknown, isSecure: boolean = false) => {
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

      const data = sanitizeIncomingMessage(raw, allowedTypes, schemas);
      if (!data) {
        return;
      }

      // Enforce encrypted only mode after PQ session establishment
      const sessionEstablished = websocketClient.isPQSessionEstablished();
      const isHandshakeMessage = data.type === SignalType.SERVER_PUBLIC_KEY ||
        data.type === SignalType.PQ_HANDSHAKE_ACK;
      const isEncryptedTransport = data.type === SignalType.PQ_ENVELOPE || data.type === SignalType.PQ_HEARTBEAT_PONG;
      const isErrorMessage = data.type === SignalType.ERROR;
      const isSafeControl = false; // Hardened: all control messages should be encrypted once session exists

      if (sessionEstablished && !isSecure && !isEncryptedTransport && !isHandshakeMessage && !isErrorMessage && !isSafeControl) {
        console.error('[useWebSocket] Security violation: plaintext after encryption established', { type: data.type });
        setLoginError('Security violation: plaintext message after encryption established');
        return;
      }

      await routeMessage(data);
    } catch (_error) {
      console.error('[useWebSocket] Message handler error:', _error instanceof Error ? _error.message : 'Unknown error');
      setLoginError('Secure transport error');
    }
  }, [allowedTypes, encryptedTypes, routeMessage, schemas, setLoginError]);

  const handlerRef = useRef(handler);
  useLayoutEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  useEffect(() => {
    let mounted = true;
    const drain = async () => {
      const queue = routeQueueRef.current;
      if (queue.draining) return;
      queue.draining = true;
      try {
        while (mounted && queue.items.length > 0) {
          const item = queue.items.shift()!;
          queue.bytes = Math.max(0, queue.bytes - item.bytes);
          if (item.generation !== queue.generation) continue;
          await handlerRef.current(item.detail, item.isSecure);
        }
      } finally {
        queue.draining = false;
        if (mounted && queue.items.length > 0) void drain();
      }
    };

    const listener = (evt: Event) => {
      try {
        const detail = (evt as CustomEvent).detail;
        if (!detail) return;

        if (typeof detail === 'object' && detail !== null) {
          if (hasPrototypePollutionKeys(detail)) {
            return;
          }
        }

        const detailType = isPlainObject(detail) && typeof detail.type === 'string'
          ? detail.type
          : '';
        if (
          detailType === '__ws_connection_opened' ||
          detailType === '__ws_connection_closed' ||
          detailType === '__ws_connection_error'
        ) {
          const queue = routeQueueRef.current;
          queue.generation += 1;
          queue.items = [];
          queue.bytes = 0;
          rateLimitRef.current = { windowStart: Date.now(), count: 0 };
          return;
        }

        const isSecure = evt.type === EventType.SECURE_SERVER_MESSAGE;
        let bytes = 0;
        try {
          const serialized = JSON.stringify(detail);
          if (typeof serialized !== 'string') return;
          bytes = serialized.length;
        } catch {
          return;
        }
        const queue = routeQueueRef.current;
        if (
          queue.items.length + 1 > ROUTE_QUEUE_MAX_COUNT ||
          queue.bytes + bytes > ROUTE_QUEUE_MAX_BYTES
        ) {
          queue.generation += 1;
          queue.items = [];
          queue.bytes = 0;
          setLoginError('Secure transport overloaded; reconnecting.');
          websocketClient.terminateCurrentConnection();
          return;
        }
        queue.items.push({ detail, isSecure, bytes, generation: queue.generation });
        queue.bytes += bytes;
        void drain();
      } catch (_error) {
        console.error('[useWebSocket] Listener exception:', _error instanceof Error ? _error.message : 'Unknown error');
      }
    };

    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, listener as EventListener);
    window.addEventListener(EventType.SECURE_SERVER_MESSAGE, listener as EventListener);
    return () => {
      mounted = false;
      const queue = routeQueueRef.current;
      queue.generation += 1;
      queue.items = [];
      queue.bytes = 0;
      window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, listener as EventListener);
      window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, listener as EventListener);
    };
  }, [setLoginError]);
};
