/**
 * Secure WebSocket Handler
 */

const WebSocket = require('ws');
const crypto = require('crypto');
const tls = require('tls');
const { gunzipSync } = require('zlib');
let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch (e) {
  console.warn('[WS] socks-proxy-agent not found');
}

class WebSocketHandler {
  constructor(securityMiddleware, storageHandler = null) {
    this.securityMiddleware = securityMiddleware;
    this.storageHandler = storageHandler;

    // Connection state
    this.connection = null;
    this.isConnecting = false;
    this.serverUrl = null;
    this.torReady = false;
    this.torSocksPort = 9150;
    this.connectHostOverride = null;

    // Reconnection state
    this.reconnectAttempts = 0;
    this.MAX_RECONNECT_ATTEMPTS = 5;
    this.RECONNECT_DELAY_BASE = 2000;
    this.reconnectTimer = null;

    // Message queue
    this.messageQueue = [];
    this.MAX_QUEUE_SIZE = 100;

    // Chunk reassembly for large messages
    this.chunkBuffer = new Map(); // sessionId -> { chunks: [], totalChunks: 0, receivedChunks: 0 }

    // Connection metrics
    this.connectionEstablishedAt = null;
    this.heartbeatTimer = null;
    this.missedHeartbeats = 0;
    this.MAX_MISSED_HEARTBEATS = 8;

    // Certificate pinning
    this.pinnedFingerprints = new Set();

    // Extra headers to send on WS handshake (e.g., stable device id)
    this.extraHeaders = {};

    // Device proof material (Ed25519)
    this.deviceId = null;
    this.devicePublicKeyPem = null;
    this.devicePrivateKeyPem = null;
  }

  async initialize({ defaultUrl = 'wss://localhost:443', reconnectAttempts = 5, reconnectDelay = 2000 } = {}) {
    this.serverUrl = defaultUrl;
    this.MAX_RECONNECT_ATTEMPTS = reconnectAttempts;
    this.RECONNECT_DELAY_BASE = reconnectDelay;
    return { success: true };
  }

  async setServerUrl(url) {
    if (!url || typeof url !== 'string' || url.length > 2048) {
      return { success: false, error: 'Invalid server URL' };
    }

    try {
      const parsed = new URL(url);
      
      // Require wss:// only
      if (parsed.protocol !== 'wss:') {
        return { success: false, error: 'Only secure WebSocket (wss://) allowed' };
      }
      
      // Validate hostname
      if (!parsed.hostname || parsed.hostname.length > 253) {
        return { success: false, error: 'Invalid hostname' };
      }
      
      if (parsed.username || parsed.password) {
        return { success: false, error: 'Credentials in URL not allowed' };
      }
      
      const normalized = parsed.toString();
      this.serverUrl = normalized;
      
      if (this.storageHandler) {
        try {
          await this.storageHandler.persistServerUrl(normalized);
        } catch (e) {
          console.warn('[WS] Failed to persist server URL:', e.message);
        }
      }
      
      return { success: true };
    } catch (e) {
      return { success: false, error: 'Invalid URL format' };
    }
  }

  async loadStoredServerUrl() {
    if (!this.storageHandler) return null;
    try {
      const stored = await this.storageHandler.loadServerUrl();
      if (stored && typeof stored === 'string') {
        this.serverUrl = stored;
        return stored;
      }
    } catch (e) {
      console.warn('[WS] Failed to load stored server URL:', e.message);
    }
    return null;
  }

  setTorReady(ready) {
    this.torReady = Boolean(ready);
  }

  updateTorConfig(config) {
    if (config && config.socksPort) {
      this.torSocksPort = config.socksPort;
    }
  }

  setConnectHost(host) {
    if (typeof host === 'string' && host.length && (host === '127.0.0.1' || host === 'localhost' || host === '::1')) {
      this.connectHostOverride = host;
    }
  }

  buildConnectTarget(url) {
    try {
      const u = new URL(url);
      const tlsServername = u.hostname;
      let host = u.hostname;

      const isLocalUrl = (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1');
      if (this.connectHostOverride && isLocalUrl && (this.connectHostOverride === '127.0.0.1' || this.connectHostOverride === 'localhost' || this.connectHostOverride === '::1')) {
        host = this.connectHostOverride;
      }

      const address = `${u.protocol}//${host}${u.port ? ':' + u.port : ''}${u.pathname || ''}${u.search || ''}`;
      return { address, tlsServername };
    } catch {
      return { address: url, tlsServername: null };
    }
  }

  async connect() {
    if (!this.serverUrl) {
      return { success: false, error: 'Server URL not configured. Call setServerUrl() first.' };
    }

    if (this.isConnecting || (this.connection && this.connection.readyState === WebSocket.CONNECTING)) {
      return { success: false, error: 'Connection in progress' };
    }

    if (this.connection && this.connection.readyState === WebSocket.OPEN) {
      return { success: true, alreadyConnected: true };
    }

    if (!this.torReady) {
      return { success: false, error: 'Tor setup not complete' };
    }

    this.isConnecting = true;

    try {
      await this.createConnection();
      return { success: true, newConnection: true };
    } catch (error) {
      this.isConnecting = false;
      return { success: false, error: 'Connection failed' };
    }
  }

  async createConnection() {
    return new Promise((resolve, reject) => {
      try {
        const wsOptions = {
          handshakeTimeout: 10000,
          perMessageDeflate: false,
          headers: this.extraHeaders || {}
        };

        if (this.torReady && SocksProxyAgent) {
          const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${this.torSocksPort}`);
          wsOptions.agent = agent;
        }

        const target = this.buildConnectTarget(this.serverUrl);
        if (target.tlsServername) {
          wsOptions.servername = target.tlsServername;
        }

        if (this.pinnedFingerprints.size > 0) {
          wsOptions.checkServerIdentity = (hostname, cert) => this.validateServerCertificate(hostname, cert);
        }
        this.connection = new WebSocket(target.address, undefined, wsOptions);

        let reqSocketMonitored = false;
        const reqMonitor = setInterval(() => {
          try {
            const conn = this.connection;
            if (!conn) return;
            if (conn._req && !reqSocketMonitored) {
              const rsock = conn._req && conn._req.socket ? conn._req.socket : null;
              if (rsock) {
                reqSocketMonitored = true;
                const sock = rsock;
                try { sock.once && sock.once('secureConnect', () => { }); } catch { }
                try { sock.on && sock.on('error', () => { }); } catch { }
                try { sock.on && sock.on('close', () => { }); } catch { }
                try { sock.on && sock.on('timeout', () => { try { sock.destroy(new Error('Socket timeout')); } catch { } }); } catch { }
                try { sock.setTimeout && sock.setTimeout(30000); } catch { }
                setTimeout(() => {
                  try {
                    if (sock && !sock.authorized && sock.connecting) {
                    }
                  } catch { }
                }, 2000);
              }
            }
          } catch { }
        }, 5);

        setTimeout(() => {
          try { clearInterval(reqMonitor); } catch { }
        }, 500);

        const monitorSocket = (attempt = 1) => {
          try {
            const conn = this.connection;
            if (!conn) return; // connection torn down
            const socket = conn._socket || conn._stream;
            const reqSocket = conn._req && conn._req.socket ? conn._req.socket : null;

            if (reqSocket && attempt === 1) {
              try { reqSocket.once && reqSocket.once('secureConnect', () => { }); } catch { }
              try { reqSocket.on && reqSocket.on('error', () => { }); } catch { }
              try { reqSocket.on && reqSocket.on('timeout', () => { try { reqSocket.destroy(new Error('Request socket timeout')); } catch { } }); } catch { }
            }

            if (socket) {
              try { socket.once && socket.once('connect', () => { }); } catch { }
              try { socket.once && socket.once('secureConnect', () => { }); } catch { }
              try { socket.on && socket.on('error', () => { }); } catch { }
              try { socket.on && socket.on('close', () => { }); } catch { }
              try { socket.on && socket.on('end', () => { }); } catch { }
            } else if (attempt < 40) {
              setTimeout(() => monitorSocket(attempt + 1), 5);
            } else {
              const c2 = this.connection;
              if (c2 && c2._req && c2._req.socket) {
                const rs = c2._req.socket;
                try { rs.once && rs.once('secureConnect', () => { }); } catch { }
                try { rs.on && rs.on('error', () => { }); } catch { }
                try { rs.on && rs.on('timeout', () => { try { rs.destroy(new Error('TLS handshake timeout')); } catch { } }); } catch { }
                try { rs.on && rs.on('close', () => { }); } catch { }
              }
            }
          } catch { }
        };

        monitorSocket();

        this.connection.once('unexpected-response', (request, response) => {
          let body = '';
          response.on('data', (chunk) => {
            body += chunk.toString();
          });
          response.on('end', () => { });
        });

        this.connection.once('upgrade', () => { });

        // Set up event handlers
        this.connection.once('open', () => {
          this.handleConnectionOpen();
          resolve();
        });

        this.connection.once('error', (error) => {
          this.handleConnectionError(error);
          reject(error);
        });

        this.connection.on('message', (data) => {
          this.handleMessage(data);
        });

        this.connection.on('close', (code, reason) => {
          this.handleConnectionClose(code, reason);
        });

        this.connection.on('ping', () => {
          this.handlePing();
        });

        this.connection.on('pong', () => {
          const prevMissed = this.missedHeartbeats;
          this.missedHeartbeats = 0;
        });

        // Connection timeout
        const timeout = setTimeout(() => {
          if (this.connection.readyState !== WebSocket.OPEN) {
            this.connection.terminate();
            reject(new Error('Connection timeout'));
          }
        }, 30000);

        this.connection.once('open', () => clearTimeout(timeout));
        this.connection.once('error', () => clearTimeout(timeout));

      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Probe a server URL without touching the primary connection state.
   */
  async probeConnect(url, timeoutMs = 12000) {
    try {
      if (!url || typeof url !== 'string') {
        return { success: false, error: 'Invalid URL' };
      }
      if (!this.torReady) {
        return { success: false, error: 'Tor setup not complete' };
      }

      const wsOptions = {
        handshakeTimeout: Math.min(10000, timeoutMs),
        perMessageDeflate: false,
        headers: this.extraHeaders || {},
      };

      if (this.torReady && SocksProxyAgent) {
        const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${this.torSocksPort}`);
        wsOptions.agent = agent;
      }

      const target = this.buildConnectTarget(url);
      if (target.tlsServername) {
        wsOptions.servername = target.tlsServername;
      }

      const probe = new WebSocket(target.address, undefined, wsOptions);

      return await new Promise((resolve) => {
        let settled = false;
        const finish = (result) => { if (!settled) { settled = true; try { probe.close(); } catch { } resolve(result); } };
        const timer = setTimeout(() => finish({ success: false, error: 'Connection timeout' }), timeoutMs);

        probe.once('open', () => { clearTimeout(timer); finish({ success: true }); });
        probe.once('error', (err) => { clearTimeout(timer); finish({ success: false, error: err?.message || 'Connection failed' }); });
        probe.once('close', () => { });
      });
    } catch (e) {
      return { success: false, error: e?.message || 'Probe failed' };
    }
  }

  handleConnectionOpen() {
    this.isConnecting = false;
    this.reconnectAttempts = 0;
    this.connectionEstablishedAt = Date.now();
    this.missedHeartbeats = 0;

    if (this.onMessage) {
      this.onMessage({
        type: '__ws_connection_opened',
        timestamp: Date.now()
      });
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.processMessageQueue();
  }

  handleConnectionError(error) {
    if (this.onMessage) {
      this.onMessage({
        type: '__ws_connection_error',
        error: this.sanitizeError(error)
      });
    }

    this.isConnecting = false;
  }

  handleConnectionClose(code, reason) {
    const duration = this.connectionEstablishedAt
      ? Date.now() - this.connectionEstablishedAt
      : 0;



    if (this.onMessage) {
      this.onMessage({
        type: '__ws_connection_closed',
        code,
        reason,
        duration
      });
    }

    this.stopHeartbeat();
    this.connection = null;
    this.isConnecting = false;
    this.connectionEstablishedAt = null;

    if (this.torReady && this.reconnectAttempts < this.MAX_RECONNECT_ATTEMPTS) {
      this.scheduleReconnect();
    }
  }

  handleMessage(data) {
    try {
      let messageText;

      // Check if data is binary
      if (Buffer.isBuffer(data)) {
        try {
          const decompressed = gunzipSync(data);
          messageText = decompressed.toString('utf8');
        } catch (gzipError) {
          messageText = data.toString();
        }
      } else {
        messageText = data.toString();
      }

      const parsed = JSON.parse(messageText);

      // Handle chunked messages
      if (parsed.type === 'KEY_CHUNK') {
        this.handleKeyChunk(parsed);
        return;
      }

      // Device proof challenge -> sign and respond
      if (parsed.type === 'device-proof-challenge') {
        this.handleDeviceProofChallenge(parsed);
        return;
      }

      // Handle heartbeat responses
      if (parsed.type === 'pong' || parsed.type === 'heartbeat-response' || parsed.type === 'pq-heartbeat-pong') {
        this.missedHeartbeats = 0;
        return;
      }

      if (this.onMessage) {
        this.onMessage(parsed);
      }
    } catch (err) {
    }
  }

  handleKeyChunk(chunk) {
    try {
      const { chunkIndex, totalChunks, data } = chunk;

      // Initialize chunk buffer if this is the first chunk
      if (!this.chunkBuffer.has('key-exchange')) {
        this.chunkBuffer.set('key-exchange', {
          chunks: new Array(totalChunks),
          totalChunks,
          receivedChunks: 0
        });
      }

      const buffer = this.chunkBuffer.get('key-exchange');

      // Store this chunk
      buffer.chunks[chunkIndex] = Buffer.from(data, 'base64');
      buffer.receivedChunks++;

      if (buffer.receivedChunks === buffer.totalChunks) {
        const compressedData = Buffer.concat(buffer.chunks);
        const decompressed = gunzipSync(compressedData);
        const messageText = decompressed.toString('utf8');

        const parsed = JSON.parse(messageText);
        this.chunkBuffer.delete('key-exchange');

        // Deliver to message handler
        if (this.onMessage) {
          this.onMessage(parsed);
        }
      }
    } catch (err) {
      this.chunkBuffer.delete('key-exchange');
    }
  }

  handlePing() {
    if (this.connection?.readyState === WebSocket.OPEN) {
      this.connection.pong();
      this.missedHeartbeats = 0;
    }
  }

  async send(payload) {
    try {
      await this.securityMiddleware.validateRequest('edge:ws-send', [payload]);

      if (!this.connection || this.connection.readyState !== WebSocket.OPEN) {
        if (!this.torReady) {
          return { success: false, error: 'Tor not ready' };
        }

        if (this.messageQueue.length < this.MAX_QUEUE_SIZE) {
          this.messageQueue.push(this.prepareMessage(payload));
          return { success: true, queued: true };
        } else {
          return { success: false, error: 'Queue full' };
        }
      }

      this.connection.send(this.prepareMessage(payload));
      return { success: true };

    } catch (_) {
      return { success: false, error: 'Send failed' };
    }
  }

  prepareMessage(payload) {
    if (typeof payload === 'string') {
      try {
        JSON.parse(payload);
        return payload;
      } catch {
        return JSON.stringify({ type: 'raw', data: payload });
      }
    } else {
      return JSON.stringify(payload);
    }
  }

  processMessageQueue() {
    if (this.messageQueue.length === 0) return;

    const messages = [...this.messageQueue];
    this.messageQueue.length = 0;

    for (const message of messages) {
      try {
        if (this.connection?.readyState === WebSocket.OPEN) {
          this.connection.send(message);
        } else {
          if (this.messageQueue.length < this.MAX_QUEUE_SIZE) {
            this.messageQueue.push(message);
          }
          break;
        }
      } catch (error) {
        if (this.messageQueue.length < this.MAX_QUEUE_SIZE) {
          this.messageQueue.push(message);
        }
      }
    }
  }

  startHeartbeat() {
    this.stopHeartbeat();

    this.heartbeatTimer = setInterval(() => {
      if (!this.connection || this.connection.readyState !== WebSocket.OPEN) {
        this.stopHeartbeat();
        return;
      }

      this.missedHeartbeats++;

      if (this.missedHeartbeats >= this.MAX_MISSED_HEARTBEATS) {
        this.connection.terminate();
        this.stopHeartbeat();
        return;
      }

      try {
        this.connection.ping();
      } catch (error) {
      }
    }, 25000);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = this.RECONNECT_DELAY_BASE * this.reconnectAttempts;


    this.reconnectTimer = setTimeout(async () => {
      try {
        await this.connect();
      } catch (error) {
      }
    }, delay);
  }

  validateServerCertificate(hostname, cert) {
    // certificate pinning
    if (this.pinnedFingerprints.size === 0) {
      return tls.checkServerIdentity(hostname, cert);
    }

    // Calculate certificate fingerprint
    const fingerprint = crypto
      .createHash('sha256')
      .update(cert.raw)
      .digest('hex')
      .toUpperCase();

    if (!this.pinnedFingerprints.has(fingerprint)) {
      throw new Error('Certificate fingerprint mismatch');
    }

    return undefined;
  }

  addPinnedFingerprint(fingerprint) {
    if (typeof fingerprint === 'string' && fingerprint.length === 64) {
      this.pinnedFingerprints.add(fingerprint.toUpperCase());
    }
  }

  close() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.stopHeartbeat();

    // Close connection
    if (this.connection) {
      try {
        this.connection.close(1000, 'Normal closure');
      } catch (error) {
      }
      this.connection = null;
    }

    // Clear state
    this.messageQueue = [];
    this.isConnecting = false;
    this.connectionEstablishedAt = null;
    this.reconnectAttempts = 0;
  }

  async disconnect() {
    this.close();
    return { success: true };
  }

  async cleanup() {
    this.close();
    this.torReady = false;
    return { success: true };
  }

  isConnected() {
    return this.connection && this.connection.readyState === WebSocket.OPEN;
  }

  getState() {
    return {
      connected: this.isConnected(),
      connecting: this.isConnecting,
      reconnectAttempts: this.reconnectAttempts,
      queueSize: this.messageQueue.length,
      connectionDuration: this.connectionEstablishedAt
        ? Date.now() - this.connectionEstablishedAt
        : 0
    };
  }

  sanitizeError(err) {
    if (!err) return 'Unknown error';
    const message = err.message || String(err);
    return message.replace(/\/[^\s]+/g, '[PATH]').substring(0, 200);
  }

  setMessageHandler(handler) {
    this.onMessage = handler;
  }

  setExtraHeaders(headers) {
    try {
      if (headers && typeof headers === 'object') {
        const sanitized = {};
        for (const [k, v] of Object.entries(headers)) {
          if (typeof k === 'string' && typeof v === 'string' && v.length <= 256) {
            sanitized[k.toLowerCase()] = v;
          }
        }
        this.extraHeaders = { ...(this.extraHeaders || {}), ...sanitized };
        if (this.extraHeaders['x-device-id']) {
          this.deviceId = this.extraHeaders['x-device-id'];
        }
      }
      return { success: true, headers: { ...(this.extraHeaders || {}) } };
    } catch (_) {
      return { success: false };
    }
  }

  setDeviceKeys({ deviceId, publicKeyPem, privateKeyPem }) {
    try {
      if (typeof deviceId === 'string') this.deviceId = deviceId;
      if (typeof publicKeyPem === 'string') this.devicePublicKeyPem = publicKeyPem;
      if (typeof privateKeyPem === 'string') this.devicePrivateKeyPem = privateKeyPem;
      return { success: true };
    } catch (_) {
      return { success: false };
    }
  }

  getDeviceId() {
    return this.deviceId || null;
  }

  signRefreshProof({ nonce, jti }) {
    try {
      if (!this.devicePrivateKeyPem || !this.deviceId) return null;
      const crypto = require('crypto');
      const key = crypto.createPrivateKey({ key: this.devicePrivateKeyPem, format: 'pem', type: 'pkcs8' });
      const message = Buffer.from(`device-proof:refresh:v1|${nonce}|${jti}|${this.deviceId}`, 'utf8');
      const signature = crypto.sign(null, message, key);
      return signature.toString('base64');
    } catch (_) {
      return null;
    }
  }

  handleDeviceProofChallenge(ch) {
    try {
      if (!this.connection || this.connection.readyState !== WebSocket.OPEN) return;
      const nonce = ch?.nonce;
      if (!nonce || typeof nonce !== 'string') return;
      if (!this.devicePrivateKeyPem || !this.devicePublicKeyPem || !this.deviceId) return;
      const crypto = require('crypto');
      const key = crypto.createPrivateKey({ key: this.devicePrivateKeyPem, format: 'pem', type: 'pkcs8' });
      const message = Buffer.from(`device-proof:v1|${nonce}|${this.deviceId}`, 'utf8');
      const signature = crypto.sign(null, message, key);
      const response = {
        type: 'device-proof-response',
        deviceId: this.deviceId,
        publicKeyPem: this.devicePublicKeyPem,
        nonce,
        signatureBase64: signature.toString('base64')
      };
      this.connection.send(JSON.stringify(response));
    } catch (_) { }
  }
}

module.exports = { WebSocketHandler };
