import { v4 as uuidv4 } from 'uuid';
import { SignalType } from './signals';

interface MessageHandler {
  (message: unknown): void;
}

class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private isConnected: boolean = false;
  private reconnectAttempts: number = 0;
  private readonly maxReconnectAttempts: number = 5;
  private readonly reconnectTimeout: number = 2000;
  private messageHandlers: Map<string, MessageHandler> = new Map();
  private setLoginError?: (error: string) => void;

  constructor() {
    const isDev = import.meta.env.DEV;
    this.url = isDev ? "wss://localhost:8443/" : "wss://end2endchat.com";
  }

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

  public connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          this.isConnected = true;
          this.reconnectAttempts = 0;
          if (this.setLoginError) this.setLoginError("");
          resolve();
        };

        this.ws.onclose = (event) => {
          this.isConnected = false;

          if (event.code === 1008 || event.code === 1013) {
            return;
          }

          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          if (!this.isConnected) {
            reject(error);
          }
        };

        this.ws.onmessage = (event) => {
          this.handleMessage(event.data);
        };
      } catch (error) {
        reject(error);
      }
    });
  }

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
    if (!this.ws || !this.isConnected) {
      return;
    }

    try {
      const message = typeof data === 'object' ? JSON.stringify(data) : String(data);
      try {
        const preview = (() => {
          try { return typeof data === 'object' ? JSON.parse(message) : message.slice(0, 200); } catch { return message.slice(0, 200); }
        })();
        console.debug('[WS] send ->', preview);
      } catch { }
      this.ws.send(message);
    } catch (error) {
      console.error('Error sending message:', error);
    }
  }

  public registerMessageHandler(type: string, handler: MessageHandler): void {
    this.messageHandlers.set(type, handler);
  }

  public unregisterMessageHandler(type: string): void {
    this.messageHandlers.delete(type);
  }

  private handleMessage(data: unknown): void {
    try {
      let message;
      try {
        message = JSON.parse(data as string);
      } catch {
        message = { type: 'raw', data };
      }

      try {
        const dbg = typeof message === 'object' ? { type: message.type, keys: Object.keys(message || {}) } : { raw: String(message).slice(0, 200) };
        console.debug('[WS] recv <-', dbg);
      } catch { }

      if (typeof message === 'object' && message.type) {
        const handler = this.messageHandlers.get(message.type);
        if (handler) {
          handler(message);
        }
      } else {
        const rawHandler = this.messageHandlers.get('raw');
        if (rawHandler) {
          rawHandler(data);
        } else {
          const chatHandler = this.messageHandlers.get('chat');
          if (chatHandler) {
            chatHandler({
              id: uuidv4(),
              type: 'raw',
              content: data,
              timestamp: new Date()
            });
          }
        }
      }
    } catch (error) {
      console.error('Error handling message:', error);
    }
  }

  public close(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.isConnected = false;
    }
  }

  public isConnectedToServer(): boolean {
    return this.isConnected;
  }
}

const websocketClient = new WebSocketClient();
export default websocketClient;