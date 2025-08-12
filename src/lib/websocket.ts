import { v4 as uuidv4 } from 'uuid';

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

    this.url = isDev
      ? "wss://localhost:8443/"
      : "wss://end2endchat.com";

    console.log(`${isDev ? 'Development' : 'Production'} environment detected. Connecting to ${this.url}`);
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
        if (msg.type === 'AUTH_SUCCESS') {
          this.unregisterMessageHandler('AUTH_SUCCESS');
          this.unregisterMessageHandler('AUTH_ERROR');
          this.send(username);
          resolve();
        } else if (msg.type === 'AUTH_ERROR') {
          this.unregisterMessageHandler('AUTH_SUCCESS');
          this.unregisterMessageHandler('AUTH_ERROR');
          this.ws?.close(1008, "Auth failed");
          reject(new Error(msg.message || "Authentication failed"));
        }
      };

      this.registerMessageHandler('AUTH_SUCCESS', handleAuth);
      this.registerMessageHandler('AUTH_ERROR', handleAuth);

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
          console.log('WebSocket connection established');
          if (this.setLoginError) this.setLoginError("");
          resolve();
        };

        this.ws.onclose = (event) => {
          this.isConnected = false;
          console.warn(`WebSocket closed: ${event.reason} (code: ${event.code})`);

          if (event.code === 1008 || event.code === 1013) {
            console.warn('Connection rejected by server. Will not attempt to reconnect.');
            return;
          }

          this.attemptReconnect();
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          if (!this.isConnected) {
            reject(error);
          }
        };

        this.ws.onmessage = (event) => {
          this.handleMessage(event.data);
        };
      } catch (error) {
        console.error('WebSocket connection error:', error);
        reject(error);
      }
    });
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.warn('Max reconnection attempts reached. Giving up.');
      return;
    }

    this.reconnectAttempts++;
    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);

    setTimeout(() => {
      this.connect().catch(error => {
        console.warn('Reconnection failed:', error);
        this.setLoginError("Failed to connect to server")
      });
    }, this.reconnectTimeout * this.reconnectAttempts);
  }

  public send(data: unknown): void {
    if (!this.ws || !this.isConnected) {
      console.warn('Cannot send message: WebSocket is not connected');
      return;
    }

    try {
      const message = typeof data === 'object' ? JSON.stringify(data) : String(data);
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

      if (typeof message === 'object' && message.type) {
        const handler = this.messageHandlers.get(message.type);
        if (handler) {
          handler(message);
        } else {
          console.warn(`No handler registered for message type: ${message.type}`);
        }
      } else {
        const rawHandler = this.messageHandlers.get('raw');
        if (rawHandler) {
          rawHandler(data);
        } else {
          console.log('Received unhandled message:', data);

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
