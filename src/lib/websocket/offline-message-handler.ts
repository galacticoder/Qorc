/**
 * Offline Message Handler
 * Handles sending messages to offline users using server storage
 * and processing incoming offline messages from server
 */

import { decryptLongTerm, encryptLongTerm } from '../cryptography/long-term-encryption';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import type { EncryptedPayload, OfflineMessage, IncomingOfflineMessageCallback } from '../types/websocket-types';
import { sanitizeString } from '../utils/websocket-utils';

class OfflineMessageHandler {
  private ownKyberSecretKey: Uint8Array | null = null;
  private incomingCallback: IncomingOfflineMessageCallback | null = null;
  private lastRetrieveAt = 0;

  constructor() {
    this.setupEventListeners();
  }

  // Set the decryption key for the own user
  setDecryptionKey(kyberSecretKey: Uint8Array): void {
    this.ownKyberSecretKey = kyberSecretKey;
  }

  // Clear the decryption key for the own user
  clearDecryptionKey(): void {
    if (this.ownKyberSecretKey) {
      this.ownKyberSecretKey.fill(0);
      this.ownKyberSecretKey = null;
    }
  }

  // Set the callback for incoming offline encrypted messages
  setIncomingOfflineEncryptedMessageCallback(callback: IncomingOfflineMessageCallback): void {
    this.incomingCallback = callback;
  }

  // Setup event listeners for incoming offline messages
  private setupEventListeners(): void {
    if (typeof window === 'undefined') return;

    window.addEventListener(EventType.OFFLINE_MESSAGES_RESPONSE, async (event: Event) => {
      const customEvent = event as CustomEvent<{ messages?: OfflineMessage[] }>;
      const messages = customEvent.detail?.messages;
      if (Array.isArray(messages)) {
        await this.processIncomingOfflineMessages(messages);
      }
    });
  }

  // Store an offline message on the server
  private async storeOfflineMessageOnServer(
    to: string,
    messageId: string | undefined,
    encryptedPayload: EncryptedPayload,
    recipientKyberPublicKey: string
  ): Promise<void> {
    try {
      const { default: websocketClient } = await import('./websocket');
      if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
        return;
      }

      const messageData = JSON.stringify({
        messageId,
        encryptedPayload,
        timestamp: Date.now()
      });

      const longTermEnvelope = await encryptLongTerm(messageData, recipientKyberPublicKey);

      await websocketClient.sendSecureControlMessage({
        type: 'store-offline-message',
        messageId,
        to,
        longTermEnvelope,
        version: 'lt-v1'
      });
    } catch { }
  }

  // Retrieve offline messages from the server
  retrieveOfflineMessagesFromServer(): void {
    const now = Date.now();
    if (now - this.lastRetrieveAt < 1500) return;
    this.lastRetrieveAt = now;

    void import('./websocket')
      .then(async ({ default: websocketClient }) => {
        if (!websocketClient?.isConnectedToServer() || !websocketClient?.isPQSessionEstablished()) {
          return;
        }
        try {
          await websocketClient.sendSecureControlMessage({ type: 'retrieve-offline-messages' });
        } catch { }
      })
      .catch(() => {});
  }

  // Process incoming offline messages
  private async processIncomingOfflineMessages(messages: OfflineMessage[]): Promise<void> {
    if (!this.ownKyberSecretKey) {
      return;
    }

    for (const message of messages) {
      try {
        if (message.version !== 'lt-v1' || !message.longTermEnvelope) {
          continue;
        }

        const decrypted = await decryptLongTerm(message.longTermEnvelope, this.ownKyberSecretKey);
        if (!decrypted.json || typeof decrypted.json !== 'object') {
          continue;
        }

        const parsed = decrypted.json as { messageId?: string; encryptedPayload?: EncryptedPayload };
        const encryptedPayload = parsed.encryptedPayload;
        const to = sanitizeString(message.to) ?? '';

        if (!encryptedPayload || !to) {
          continue;
        }

        const from = sanitizeString(message.from) ?? '';
        const incoming = {
          type: SignalType.ENCRYPTED_MESSAGE,
          from,
          to,
          encryptedPayload,
          offline: true,
          messageId: sanitizeString(message.messageId ?? parsed.messageId)
        };

        if (this.incomingCallback) {
          await this.incomingCallback(incoming);
        }
      } catch { }
    }
  }

  // Queue a message for offline delivery
  async queueForOfflineDelivery(
    to: string,
    encryptedPayload: EncryptedPayload,
    recipientKyberPublicKey: string,
    messageId?: string
  ): Promise<void> {
    await this.storeOfflineMessageOnServer(to, messageId, encryptedPayload, recipientKyberPublicKey);
  }
}

export const offlineMessageHandler = new OfflineMessageHandler();
export const offlineMessageQueue = {
  setDecryptionKey: (key: Uint8Array) => offlineMessageHandler.setDecryptionKey(key),
  clearDecryptionKey: () => offlineMessageHandler.clearDecryptionKey(),
  setIncomingOfflineEncryptedMessageCallback: (cb: IncomingOfflineMessageCallback) => 
    offlineMessageHandler.setIncomingOfflineEncryptedMessageCallback(cb),
  retrieveOfflineMessagesFromServer: () => offlineMessageHandler.retrieveOfflineMessagesFromServer(),
  queueForOfflineDelivery: (to: string, payload: EncryptedPayload, kyberKey: string, msgId?: string) =>
    offlineMessageHandler.queueForOfflineDelivery(to, payload, kyberKey, msgId)
};

export function retrieveOfflineMessages(): void {
  offlineMessageHandler.retrieveOfflineMessagesFromServer();
}
