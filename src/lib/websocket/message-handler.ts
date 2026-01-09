/**
 * WebSocket Message Handler
 */

import { SecurityAuditLogger } from '../cryptography/audit-logger';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import type { MessageHandler, MessageHandlerCallbacks } from '../types/websocket-types';
import { MAX_INCOMING_WS_STRING_CHARS } from '../constants';

export class WebSocketMessageHandler {
  private messageHandlers: Map<string, MessageHandler> = new Map();

  constructor(private callbacks: MessageHandlerCallbacks) {}

  registerHandler(type: string, handler: MessageHandler): void {
    this.messageHandlers.set(type, handler);
  }

  unregisterHandler(type: string): void {
    this.messageHandlers.delete(type);
  }

  hasHandler(type: string): boolean {
    const has = this.messageHandlers.has(type);
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

      if (typeof message === 'object' && message?.type === 'pq-heartbeat-pong') {
        this.callbacks.handleHeartbeatResponse(message);
        return;
      }

      if (typeof message === 'object' && message?.type === 'pq-envelope') {
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

        const handler = this.messageHandlers.get(message.type);
        if (handler) {
          handler(message);
        }
      }

      const rawHandler = this.messageHandlers.get('raw');
      if (rawHandler) {
        rawHandler(message);
      }
    } catch (err) {
      console.error('[WS-MessageHandler] handleMessage error', { error: (err as Error).message });
    }
  }
}
