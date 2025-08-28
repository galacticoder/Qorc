import { v4 as uuidv4 } from 'uuid';
import { SignalType } from './signals';

interface MessageHandler {
  (message: unknown): void;
}

class WebSocketClient {
  private messageHandlers: Map<string, MessageHandler> = new Map();
  private setLoginError?: (error: string) => void;
  private globalRateLimitUntil: number = 0;
  private ws?: WebSocket;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectTimeout: number = 1000;

  public setLoginErrorCallback(fn: (error: string) => void) {
    this.setLoginError = fn;
  }

  public async login(username: string, password: string): Promise<void> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      await this.connect();
    }

    return new Promise((resolve, reject) => {
      const handleAuth = (msg: any) => {
        if (msg.type === SignalType.AUTH_SUCCESS) {
          this.unregisterMessageHandler(SignalType.AUTH_SUCCESS);
          this.unregisterMessageHandler(SignalType.AUTH_ERROR);
          this.send(username);
          resolve();
        } else if (msg.type === SignalType.AUTH_ERROR) {
          this.unregisterMessageHandler(SignalType.AUTH_SUCCESS);
          this.unregisterMessageHandler(SignalType.AUTH_ERROR);
          this.ws?.close(1008, "Auth failed");
          reject(new Error(msg.message || "Authentication failed"));
        }
      };

      this.registerMessageHandler(SignalType.AUTH_SUCCESS, handleAuth);
      this.registerMessageHandler(SignalType.AUTH_ERROR, handleAuth);

      this.send(password);
    });
  }

  public connect(): Promise<void> { return Promise.resolve(); }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      return;
    }

    this.reconnectAttempts++;

    setTimeout(() => {
      this.connect().catch(error => {
        this.setLoginError("Failed to connect to server")
      });
    }, this.reconnectTimeout * this.reconnectAttempts);
  }

  public send(data: unknown): void {
    // Forward to Electron edgeApi
    if (this.isGloballyRateLimited()) {
      // Drop to caller; caller can queue
      try { console.warn('[WS] send suppressed due to global rate limit'); } catch { }
      return;
    }

    try {
      // SECURITY: Validate input data
      if (data === null || data === undefined) {
        console.error('[WS] Cannot send null or undefined data');
        return;
      }

      // SECURITY: Limit message size to prevent DoS
      const message = typeof data === 'object' ? JSON.stringify(data) : String(data);
      if (message.length > 1048576) { // 1MB limit
        console.error('[WS] Message too large, dropping');
        return;
      }

      // SECURITY: Sanitize debug output to prevent information leakage
      try {
        const preview = (() => {
          try { 
            const parsed = typeof data === 'object' ? JSON.parse(message) : message.slice(0, 200);
            // SECURITY: Remove sensitive data from debug output
            if (typeof parsed === 'object' && parsed !== null) {
              const sanitized = { ...parsed };
              // Remove sensitive fields
              if (sanitized.passwordData) sanitized.passwordData = '[REDACTED]';
              if (sanitized.passphraseHash) sanitized.passphraseHash = '[REDACTED]';
              if (sanitized.encryptedMessage) sanitized.encryptedMessage = '[REDACTED]';
              if (sanitized.userData) sanitized.userData = '[REDACTED]';
              return sanitized;
            }
            return parsed;
          } catch { 
            return message.slice(0, 200); 
          }
        })();
        console.debug('[WS] send ->', preview);
      } catch { }

      // Type-safe access to edgeApi
      const edgeApi = (window as any).edgeApi as { wsSend?: (message: string) => void };
      if (edgeApi?.wsSend) {
        edgeApi.wsSend(message);
      } else {
        console.error('[WS] edgeApi.wsSend not available');
      }
    } catch (error) {
      console.error('Error sending message:', error);
    }
  }

  public setGlobalRateLimit(seconds: number) {
    const ms = Math.max(0, Math.floor(seconds * 1000));
    const until = Date.now() + ms;
    this.globalRateLimitUntil = Math.max(this.globalRateLimitUntil, until);
    try { console.warn('[WS] Global rate limit set for seconds:', seconds); } catch { }
  }

  public isGloballyRateLimited(): boolean {
    return Date.now() < this.globalRateLimitUntil;
  }

  public registerMessageHandler(type: string, handler: MessageHandler): void {
    this.messageHandlers.set(type, handler);
  }

  public unregisterMessageHandler(type: string): void {
    this.messageHandlers.delete(type);
  }

  private handleMessage(data: unknown): void {
    try {
      // SECURITY: Validate input data
      if (data === null || data === undefined) {
        console.error('[WS] Received null or undefined message');
        return;
      }

      // SECURITY: Limit message size to prevent DoS
      const dataString = String(data);
      if (dataString.length > 1048576) { // 1MB limit
        console.error('[WS] Received message too large, dropping');
        return;
      }

      let message;
      try {
        message = JSON.parse(dataString);
      } catch (parseError) {
        // SECURITY: Validate raw message format
        if (dataString.length > 10000) { // Limit raw message size
          console.error('[WS] Raw message too large, dropping');
          return;
        }
        message = { type: 'raw', data: dataString };
      }

      // SECURITY: Validate message structure
      if (typeof message !== 'object' || message === null) {
        console.error('[WS] Invalid message structure received');
        return;
      }

      // SECURITY: Sanitize debug output to prevent information leakage
      try {
        const sanitizedMessage = { ...message };
        // Remove sensitive fields from debug output
        if (sanitizedMessage.passwordData) sanitizedMessage.passwordData = '[REDACTED]';
        if (sanitizedMessage.passphraseHash) sanitizedMessage.passphraseHash = '[REDACTED]';
        if (sanitizedMessage.encryptedMessage) sanitizedMessage.encryptedMessage = '[REDACTED]';
        if (sanitizedMessage.userData) sanitizedMessage.userData = '[REDACTED]';
        if (sanitizedMessage.encryptedPayload) sanitizedMessage.encryptedPayload = '[REDACTED]';
        
        const dbg = typeof sanitizedMessage === 'object' ? 
          { type: sanitizedMessage.type, keys: Object.keys(sanitizedMessage) } : 
          { raw: String(sanitizedMessage).slice(0, 200) };
        console.debug('[WS] recv <-', dbg);
      } catch { }

      if (typeof message === 'object' && message.type) {
        // SECURITY: Validate message type
        if (typeof message.type !== 'string' || message.type.length > 100) {
          console.error('[WS] Invalid message type received');
          return;
        }

        const handler = this.messageHandlers.get(message.type);
        if (handler) {
          try {
            handler(message);
          } catch (handlerError) {
            console.error(`[WS] Handler error for message type ${message.type}:`, handlerError);
          }
        }
      } else {
        const rawHandler = this.messageHandlers.get('raw');
        if (rawHandler) {
          try {
            rawHandler(data);
          } catch (handlerError) {
            console.error('[WS] Raw handler error:', handlerError);
          }
        } else {
          const chatHandler = this.messageHandlers.get('chat');
          if (chatHandler) {
            try {
              chatHandler({
                id: uuidv4(),
                type: 'raw',
                content: dataString.slice(0, 1000), // SECURITY: Limit content size
                timestamp: new Date()
              });
            } catch (handlerError) {
              console.error('[WS] Chat handler error:', handlerError);
            }
          }
        }
      }
    } catch (error) {
      console.error('[WS] Error handling message:', error);
    }
  }

  public close(): void { this.messageHandlers.clear(); this.setLoginError = undefined; this.globalRateLimitUntil = 0; }

  public isConnectedToServer(): boolean { return true; }
}

const websocketClient = new WebSocketClient();
export default websocketClient;