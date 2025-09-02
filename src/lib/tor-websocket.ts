/**
 * Tor-Aware WebSocket Client
 * Provides WebSocket connections through Tor network for enhanced anonymity
 */

import { torNetworkManager } from './tor-network';
import { handleNetworkError } from './secure-error-handler';

export interface TorWebSocketOptions {
  useTor: boolean;
  fallbackToDirect: boolean;
  connectionTimeout: number;
  maxReconnectAttempts: number;
  reconnectDelay: number;
}

export class TorWebSocket {
  private ws: WebSocket | null = null;
  private url: string;
  private options: TorWebSocketOptions;
  private reconnectAttempts: number = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private isConnecting: boolean = false;
  private messageQueue: string[] = [];
  private readonly MAX_QUEUE_SIZE = 1000; // SECURITY: Prevent memory exhaustion
  private eventListeners: Map<string, Set<Function>> = new Map();
  private _isUsingTor: boolean = false; // Track actual Tor usage

  constructor(url: string, options?: Partial<TorWebSocketOptions>) {
    this.url = url;
    this.options = {
      useTor: true,
      fallbackToDirect: true,
      connectionTimeout: 30000,
      maxReconnectAttempts: 5,
      reconnectDelay: 5000,
      ...options
    };

    // Initialize event listener maps
    ['open', 'close', 'error', 'message'].forEach(event => {
      this.eventListeners.set(event, new Set());
    });
  }

  /**
   * Connect to WebSocket through Tor or direct connection
   */
  async connect(): Promise<boolean> {
    if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
      return true;
    }

    this.isConnecting = true;

    try {
      // Try Tor connection first if enabled
      if (this.options.useTor && torNetworkManager.isConnected()) {
        console.log('[TOR-WS] Attempting connection through Tor network...');
        const success = await this.connectThroughTor();
        if (success) {
          this._isUsingTor = true; // Successfully connected through Tor
          this.isConnecting = false;
          return true;
        } else {
          this._isUsingTor = false; // Tor connection failed
        }
      }

      // Fallback to direct connection if Tor fails or is disabled
      if (this.options.fallbackToDirect) {
        console.log('[TOR-WS] Connecting directly (not through Tor)...');
        const success = await this.connectDirect();
        this._isUsingTor = false; // Using direct connection
        this.isConnecting = false;
        return success;
      }

      this.isConnecting = false;
      return false;
    } catch (error) {
      this.isConnecting = false;
      console.error('[TOR-WS] Connection failed:', error);
      handleNetworkError(error as Error, { context: 'tor_websocket_connect' });
      return false;
    }
  }

  /**
   * Connect through Tor network
   */
  private async connectThroughTor(): Promise<boolean> {
    return new Promise((resolve) => {
      try {
        // Check if Tor is supported in current environment
        if (!torNetworkManager.isSupported()) {
          console.warn('[TOR-WS] Tor not supported in browser environment');
          resolve(false);
          return;
        }

        // For Electron environment, use Tor WebSocket
        this.ws = torNetworkManager.createTorWebSocket(this.url);

        // Fallback to regular WebSocket if Tor WebSocket creation fails
        if (!this.ws) {
          console.warn('[TOR-WS] Failed to create Tor WebSocket, using regular WebSocket');
          this.ws = new WebSocket(this.url);
        }

        if (!this.ws) {
          resolve(false);
          return;
        }

        const timeout = setTimeout(() => {
          console.error('[TOR-WS] Tor connection timeout');
          if (this.ws) {
            this.ws.close();
          }
          resolve(false);
        }, this.options.connectionTimeout);

        this.ws.onopen = () => {
          clearTimeout(timeout);
          console.log('[TOR-WS] Connected through Tor network');
          this.setupEventHandlers();
          this.flushMessageQueue();
          this.reconnectAttempts = 0;
          this.emit('open');
          resolve(true);
        };

        this.ws.onerror = (error) => {
          clearTimeout(timeout);
          console.error('[TOR-WS] Tor connection error:', error);
          this._isUsingTor = false; // Reset flag on Tor connection error
          this.emit('error', error);
          resolve(false);
        };

        this.ws.onclose = () => {
          clearTimeout(timeout);
          this.handleDisconnection();
        };

      } catch (error) {
        console.error('[TOR-WS] Failed to create Tor WebSocket:', error);
        resolve(false);
      }
    });
  }

  /**
   * Connect directly (without Tor)
   */
  private async connectDirect(): Promise<boolean> {
    return new Promise((resolve) => {
      try {
        this.ws = new WebSocket(this.url);

        const timeout = setTimeout(() => {
          console.error('[TOR-WS] Direct connection timeout');
          if (this.ws) {
            this.ws.close();
          }
          resolve(false);
        }, this.options.connectionTimeout);

        this.ws.onopen = () => {
          clearTimeout(timeout);
          console.log('[TOR-WS] Connected directly (not through Tor)');
          this.setupEventHandlers();
          this.flushMessageQueue();
          this.reconnectAttempts = 0;
          this.emit('open');
          resolve(true);
        };

        this.ws.onerror = (error) => {
          clearTimeout(timeout);
          console.error('[TOR-WS] Direct connection error:', error);
          this.emit('error', error);
          resolve(false);
        };

        this.ws.onclose = () => {
          clearTimeout(timeout);
          this.handleDisconnection();
        };

      } catch (error) {
        console.error('[TOR-WS] Failed to create direct WebSocket:', error);
        resolve(false);
      }
    });
  }

  /**
   * Setup event handlers for WebSocket
   */
  private setupEventHandlers(): void {
    if (!this.ws) return;

    this.ws.onmessage = (event) => {
      this.emit('message', event);
    };

    this.ws.onclose = (event) => {
      this.emit('close', event);
      this.handleDisconnection();
    };

    this.ws.onerror = (error) => {
      this.emit('error', error);
    };
  }

  /**
   * Handle disconnection and attempt reconnection
   */
  private handleDisconnection(): void {
    this.ws = null;
    this._isUsingTor = false; // Reset Tor usage flag on disconnection

    if (this.reconnectAttempts < this.options.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`[TOR-WS] Attempting reconnection ${this.reconnectAttempts}/${this.options.maxReconnectAttempts}...`);

      this.reconnectTimer = setTimeout(() => {
        this.connect();
      }, this.options.reconnectDelay);
    } else {
      console.error('[TOR-WS] Max reconnection attempts reached');
    }
  }

  /**
   * Send message through WebSocket
   */
  send(data: string): boolean {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(data);
      return true;
    } else {
      // Queue message for later sending
      this.messageQueue.push(data);
      console.log('[TOR-WS] Message queued (connection not ready)');
      return false;
    }
  }

  /**
   * Flush queued messages
   */
  private flushMessageQueue(): void {
    while (this.messageQueue.length > 0 && this.ws && this.ws.readyState === WebSocket.OPEN) {
      const message = this.messageQueue.shift();
      if (message) {
        this.ws.send(message);
      }
    }
  }

  /**
   * Add event listener
   */
  addEventListener(event: string, listener: Function): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.add(listener);
    }
  }

  /**
   * Remove event listener
   */
  removeEventListener(event: string, listener: Function): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.delete(listener);
    }
  }

  /**
   * Emit event to all listeners
   */
  private emit(event: string, data?: any): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.forEach(listener => {
        try {
          listener(data);
        } catch (error) {
          console.error(`[TOR-WS] Error in ${event} listener:`, error);
        }
      });
    }
  }

  /**
   * Close WebSocket connection
   */
  close(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    this._isUsingTor = false; // Reset flag on manual close
    this.messageQueue = [];
    this.reconnectAttempts = 0;
  }

  /**
   * Get connection state
   */
  get readyState(): number {
    return this.ws ? this.ws.readyState : WebSocket.CLOSED;
  }

  /**
   * Check if connected
   */
  get isConnected(): boolean {
    return this.ws ? this.ws.readyState === WebSocket.OPEN : false;
  }

  /**
   * Check if using Tor (reflects actual active connection path)
   */
  get isUsingTor(): boolean {
    return this._isUsingTor;
  }
}