const net = require('net');
const http = require('http');
const url = require('url');
const WebSocket = require('ws');
const crypto = require('crypto');

class OnionHandler {
  constructor({ torManager, onInboundMessage }) {
    if (!torManager) throw new Error('OnionHandler requires torManager');
    this.torManager = torManager;
    this.onInboundMessage = typeof onInboundMessage === 'function' ? onInboundMessage : (() => {});
    this.localServer = null;
    this.localPort = null;
    this.serviceId = null;
    this.expectedToken = null;
    this.peerSockets = new Map(); // peerUsername -> ws
    this.cleanupTimer = null;
  }

  async _findAvailablePort(start = 48888) {
    const tryPort = (port) => new Promise((resolve) => {
      const srv = http.createServer();
      srv.once('error', () => resolve(null));
      srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(port)));
    });
    for (let p = start; p < start + 200; p++) {
      const free = await tryPort(p);
      if (free) return free;
    }
    return null;
  }

  async _ensureLocalServer() {
    if (this.localServer && this.localPort) return { port: this.localPort };
    const port = await this._findAvailablePort();
    if (!port) throw new Error('No available port for onion WS');
    const server = http.createServer((req, res) => {
      res.statusCode = 426; // Upgrade Required
      res.end('WebSocket endpoint only');
    });
    const wss = new WebSocket.Server({ server, path: '/p2p' });

    wss.on('connection', (ws, req) => {
      try {
        const parsed = url.parse(req.url, true);
        const token = parsed.query && parsed.query.token ? String(parsed.query.token) : '';
        if (this.expectedToken && token !== this.expectedToken) {
          try { ws.close(1008, 'Invalid token'); } catch (_) {}
          return;
        }
      } catch (_) {}

      ws.on('message', (data) => {
        try {
          const text = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
          const msg = JSON.parse(text);
          // Track peer socket by username for outbound sends
          if (msg && typeof msg === 'object' && typeof msg.from === 'string') {
            this.peerSockets.set(msg.from, ws);
          }
          this.onInboundMessage(msg);
        } catch (_) {}
      });

      ws.on('close', () => {
        // Remove closed sockets from map
        for (const [peer, sock] of this.peerSockets.entries()) {
          if (sock === ws) this.peerSockets.delete(peer);
        }
      });
    });

    await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
    this.localServer = server;
    this.localPort = port;
    return { port };
  }

  async _torControlCommand(commands) {
    const port = this.torManager.effectiveControlPort || 9051;
    const password = this.torManager.controlPassword;
    return new Promise((resolve) => {
      let buf = '';
      const sock = net.createConnection(port, '127.0.0.1');
      const endOk = () => { try { sock.end(); } catch (_) {} };

      sock.on('connect', () => {
        sock.write(`AUTHENTICATE "${password}"\r\n`);
      });
      sock.on('data', (data) => {
        buf += data.toString();
        // Look for 250 OK after AUTH, then send commands
        if (/^250/.test(buf) && commands && commands.length) {
          const cmd = commands.shift();
          if (cmd) {
            sock.write(cmd);
          }
          buf = '';
        } else if (commands && commands.length === 0 && /^(250|5\d\d)/m.test(buf)) {
          const out = buf;
          endOk();
          resolve(out);
        }
      });
      sock.on('error', () => resolve(''));
      setTimeout(() => resolve(''), 5000);
    });
  }

  async createEndpoint({ ttlSeconds = 600 } = {}) {
    if (!this.torManager.isTorRunning()) {
      return { success: false, error: 'Tor not running' };
    }
    await this._ensureLocalServer();

    // Create new token for access control
    this.expectedToken = crypto.randomBytes(16).toString('hex');

    // Create onion service mapping 80 -> localPort
    const portLine = `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,MaxStreamsCloseCircuit Port=80,127.0.0.1:${this.localPort}\r\n`;
    const resp = await this._torControlCommand([portLine]);
    const sidMatch = resp.match(/250-ServiceID=([a-z0-9]+)/i);
    if (!sidMatch) {
      return { success: false, error: 'Failed to create onion service' };
    }
    this.serviceId = sidMatch[1];

    // Cleanup timer
    if (this.cleanupTimer) { try { clearTimeout(this.cleanupTimer); } catch (_) {} }
    this.cleanupTimer = setTimeout(() => { this.deleteEndpoint().catch(() => {}); }, Math.max(60, ttlSeconds) * 1000);

    const wsUrl = `ws://${this.serviceId}.onion/p2p?token=${this.expectedToken}`;
    return { success: true, wsUrl, token: this.expectedToken, serviceId: this.serviceId };
  }

  async deleteEndpoint() {
    if (!this.serviceId) return { success: true };
    const cmd = `DEL_ONION ${this.serviceId}\r\n`;
    await this._torControlCommand([cmd]);
    this.serviceId = null;
    this.expectedToken = null;
    try { if (this.localServer) this.localServer.close(); } catch (_) {}
    this.localServer = null;
    this.localPort = null;
    this.peerSockets.clear();
    return { success: true };
  }

  async send(toUsername, message) {
    try {
      const ws = this.peerSockets.get(toUsername);
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        return { success: false, error: 'No onion connection for peer' };
      }
      const text = typeof message === 'string' ? message : JSON.stringify(message);
      ws.send(text);
      return { success: true };
    } catch (e) {
      return { success: false, error: e?.message || String(e) };
    }
  }
}

module.exports = { OnionHandler };