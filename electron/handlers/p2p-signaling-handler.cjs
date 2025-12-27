/**
 * P2P Signaling WebSocket Handler
 * Manages the P2P signaling WebSocket connection in the main process
 * to keep it alive when the renderer is destroyed for background mode.
 */

const WebSocket = require('ws');
let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch (e) { }

class P2PSignalingHandler {
  constructor() {
    this.connection = null;
    this.serverUrl = null;
    this.isConnecting = false;
    this.torReady = false;
    this.torSocksPort = 9150;
    this.isBackgroundMode = false;
    this.localUsername = null;
    this.registrationPayload = null;
    this.onMessage = null;
    this.reconnectAttempts = 0;
    this.MAX_RECONNECT_ATTEMPTS = 10;
    this.RECONNECT_DELAY_BASE = 2000;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.heartbeatInterval = 30000;
  }

  // Set Tor ready state
  setTorReady(ready) {
    this.torReady = ready;
  }

  // Update Tor configuration
  updateTorConfig(config) {
    if (config && config.socksPort) {
      this.torSocksPort = config.socksPort;
    }
  }

  // Set background mode
  setBackgroundMode(enabled) {
    this.isBackgroundMode = enabled;
  }

  // Connect to P2P signaling server
  async connect(serverUrl, options = {}) {
    if (!serverUrl || typeof serverUrl !== 'string') {
      return { success: false, error: 'Invalid server URL' };
    }

    if (this.isConnecting) {
      return { success: false, error: 'Connection in progress' };
    }

    if (this.connection && this.connection.readyState === WebSocket.OPEN) {
      return { success: true, alreadyConnected: true };
    }

    if (!this.torReady) {
      return { success: false, error: 'Tor not ready' };
    }

    this.serverUrl = serverUrl;
    this.localUsername = options.username || null;
    this.registrationPayload = options.registrationPayload || null;
    this.isConnecting = true;

    try {
      await this.createConnection();
      return { success: true };
    } catch (error) {
      this.isConnecting = false;
      return { success: false, error: error.message || 'Connection failed' };
    }
  }

  async createConnection() {
    return new Promise((resolve, reject) => {
      try {
        const wsOptions = {
          handshakeTimeout: 15000,
          perMessageDeflate: false
        };

        if (this.torReady && SocksProxyAgent) {
          const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${this.torSocksPort}`);
          wsOptions.agent = agent;
        }

        this.connection = new WebSocket(this.serverUrl, undefined, wsOptions);

        this.connection.once('open', () => {
          this.isConnecting = false;
          this.reconnectAttempts = 0;

          if (this.localUsername && this.registrationPayload) {
            this.send({
              type: 'register',
              from: this.localUsername,
              payload: this.registrationPayload
            });
          }

          this.startHeartbeat();

          if (this.onMessage) {
            this.onMessage({ type: '__p2p_signaling_connected' });
          }

          resolve();
        });

        this.connection.once('error', (error) => {
          this.isConnecting = false;
          reject(error);
        });

        this.connection.on('message', (data) => {
          this.handleMessage(data);
        });

        this.connection.on('close', (code, reason) => {
          this.handleClose(code, reason);
        });

        this.connection.on('ping', () => {
          try {
            this.connection.pong();
          } catch (e) { }
        });

        const timeout = setTimeout(() => {
          if (this.connection && this.connection.readyState !== WebSocket.OPEN) {
            this.connection.terminate();
            reject(new Error('Connection timeout'));
          }
        }, 20000);

        this.connection.once('open', () => clearTimeout(timeout));
        this.connection.once('error', () => clearTimeout(timeout));

      } catch (error) {
        reject(error);
      }
    });
  }

  handleMessage(data) {
    try {
      let messageText;
      if (Buffer.isBuffer(data)) {
        messageText = data.toString('utf8');
      } else {
        messageText = data.toString();
      }

      const parsed = JSON.parse(messageText);
      if (this.onMessage) {
        this.onMessage(parsed);
      }
    } catch (_) {
    }
  }

  handleClose(code, reason) {
    this.stopHeartbeat();
    this.connection = null;
    this.isConnecting = false;

    if (this.onMessage) {
      this.onMessage({ type: '__p2p_signaling_closed', code, reason: reason?.toString() });
    }

    if ((this.isBackgroundMode || this.localUsername) && this.torReady && this.reconnectAttempts < this.MAX_RECONNECT_ATTEMPTS) {
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = Math.min(this.RECONNECT_DELAY_BASE * Math.pow(1.5, this.reconnectAttempts - 1), 30000);

    this.reconnectTimer = setTimeout(async () => {
      if (this.serverUrl && this.torReady) {
        try {
          await this.createConnection();
        } catch (error) { }
      }
    }, delay);
  }

  send(message) {
    if (!this.connection || this.connection.readyState !== WebSocket.OPEN) {
      return { success: false, error: 'Not connected' };
    }

    try {
      const payload = typeof message === 'string' ? message : JSON.stringify(message);
      this.connection.send(payload);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  startHeartbeat() {
    this.stopHeartbeat();

    this.heartbeatTimer = setInterval(() => {
      if (this.connection && this.connection.readyState === WebSocket.OPEN) {
        try {
          this.connection.ping();
        } catch (e) { }
      }
    }, this.heartbeatInterval);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.stopHeartbeat();

    if (this.connection) {
      try {
        this.connection.close(1000, 'Normal closure');
      } catch (e) { }
      this.connection = null;
    }

    this.isConnecting = false;
    this.reconnectAttempts = 0;

    return { success: true };
  }

  isConnected() {
    return this.connection && this.connection.readyState === WebSocket.OPEN;
  }
}

module.exports = { P2PSignalingHandler };
