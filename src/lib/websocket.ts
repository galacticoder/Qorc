import { v4 as uuidv4 } from 'uuid';

interface MessageHandler {
  (message: unknown): void;
}

class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private isConnected: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectTimeout: number = 2000;
  private messageHandlers: Map<string, MessageHandler> = new Map();
  
  constructor() {
    const isDev = import.meta.env.DEV;
    
    if (isDev) {
      console.log("Development environment detected, using local WebSocket server");
      this.url = 'ws://localhost:8080';
    } else {
      console.log("Production environment detected, using secure WebSocket server");
      this.url = 'wss://end2endchat.com';
    }
  }
  
  public connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);
        
        this.ws.onopen = () => {
          this.isConnected = true;
          this.reconnectAttempts = 0;
          console.log('WebSocket connection established');
          resolve();
        };
        
        this.ws.onclose = () => {
          this.isConnected = false;
          console.log('WebSocket connection closed');
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
      });
    }, this.reconnectTimeout * this.reconnectAttempts);
  }
  
  public send(data: unknown): void {
    if (!this.ws || !this.isConnected) {
      console.warn('Cannot send message: WebSocket is not connected');
      return;
    }
    
    try {
      if (typeof data === 'object') {
        this.ws.send(JSON.stringify(data));
      } else {
        this.ws.send(data);
      }
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
        message = JSON.parse(data);
      } catch (e) {
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
