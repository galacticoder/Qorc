/**
 * WebSocket Message Handler
 */

import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers';
import type { MessageHandler } from '../types/websocket-types';

export class WebSocketMessageHandler {
  private messageHandlers: Map<string, Set<MessageHandler>> = new Map();

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
      if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
        return;
      }
      const message = data;

      if (typeof message.type === 'string') {
        if (message.type.length > 100) {
          return;
        }

        const handlers = this.messageHandlers.get(message.type);
        if (handlers && handlers.size > 0) {
          for (const handler of Array.from(handlers)) {
            try {
              await handler(message);
            } catch {
              console.error('[WS-MessageHandler] typed handler failed');
            }
          }
        }
      }

    } catch {
      console.error('[WS-MessageHandler] message handling failed');
    }
  }
}
