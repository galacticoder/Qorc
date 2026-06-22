/**
 * WebSocket Message Handler
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import type { MessageHandler, MessageHandlerCallbacks } from '../types/websocket-types';
import { MAX_INCOMING_WS_STRING_CHARS } from '../constants';
import { SignalType } from '../types/signal-types';

export class WebSocketMessageHandler {
  private messageHandlers: Map<string, Set<MessageHandler>> = new Map();

  constructor(private callbacks: MessageHandlerCallbacks) {}

  registerHandler(type: string, handler: MessageHandler): void {
    const existing = this.messageHandlers.get(type);
    if (existing) {
      existing.add(handler);
      return;
    }
    this.messageHandlers.set(type, new Set([handler]));
  }

  unregisterHandler(type: string, handler?: MessageHandler): void {
    if (!handler) {
      this.messageHandlers.delete(type);
      return;
    }
    const handlers = this.messageHandlers.get(type);
    if (!handlers) return;
    handlers.delete(handler);
    if (handlers.size === 0) {
      this.messageHandlers.delete(type);
    }
  }

  hasHandler(type: string): boolean {
    const handlers = this.messageHandlers.get(type);
    const has = !!handlers && handlers.size > 0;
    return has;
  }

  clearHandlers(): void {
    this.messageHandlers.clear();
  }

  // Handle incoming WebSocket messages
  async handleMessage(data: unknown): Promise<void> {
    try {
      if (data === null || data === undefined) {
        return;
      }

      let message: any;

      if (typeof data === 'object' && data !== null) {
        message = data;
      } else {
        const dataString = String(data);
        if (dataString.length > MAX_INCOMING_WS_STRING_CHARS) {
          SecurityAuditLogger.log('warn', 'ws-message-data-string-too-long', {
            length: dataString.length,
            maxLength: MAX_INCOMING_WS_STRING_CHARS
          });
          return;
        }
        try {
          message = JSON.parse(dataString);
        } catch {
          message = { type: 'raw', data: dataString };
        }
      }

      if (!isPlainObject(message) || hasPrototypePollutionKeys(message)) {
        SecurityAuditLogger.log('warn', 'ws-message-invalid-object', {})
        return;
      }

      if (typeof message === 'object' && message?.type === SignalType.PQ_HEARTBEAT_PONG) {
        this.callbacks.handleHeartbeatResponse(message);
        return;
      }

      if (typeof message === 'object' && message?.type === SignalType.PQ_ENVELOPE) {
        const decrypted = await this.callbacks.decryptEnvelope(message);
        if (!decrypted) {
          SecurityAuditLogger.log('warn', 'ws-message-envelope-decryption-failed', {})
          return;
        }
        message = decrypted;
      }

      if (!isPlainObject(message) || hasPrototypePollutionKeys(message)) {
        SecurityAuditLogger.log('warn', 'ws-message-invalid-decrypted-object', {})
        return;
      }

      if (typeof message.type === 'string') {
        if (message.type.length > 100) {
          SecurityAuditLogger.log('warn', 'ws-message-type-too-long', {
            length: message.type.length,
            maxLength: 100
          });
          return;
        }

        const handlers = this.messageHandlers.get(message.type);
        if (handlers && handlers.size > 0) {
          for (const handler of Array.from(handlers)) {
            try {
              await handler(message);
            } catch (err) {
              console.error('[WS-MessageHandler] typed handler error', { type: message.type, error: (err as Error).message });
            }
          }
        }
      }

      const rawHandlers = this.messageHandlers.get('raw');
      if (rawHandlers && rawHandlers.size > 0) {
        for (const rawHandler of Array.from(rawHandlers)) {
          try {
            await rawHandler(message);
          } catch (err) {
            console.error('[WS-MessageHandler] raw handler error', { error: (err as Error).message });
          }
        }
      }
    } catch (err) {
      console.error('[WS-MessageHandler] handleMessage error', { error: (err as Error).message });
    }
  }
}
