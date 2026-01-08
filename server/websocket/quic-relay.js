import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

export function attachQuicRelay(wss, logger = cryptoLogger) {
  console.log('[QUIC Relay] Attaching relay service...');

  const peerConnections = new Map();
  const pendingDedicatedSockets = new Map();
  const activeLinkedSessions = new Map();

  const HEARTBEAT_INTERVAL_MS = 30_000;

  const heartbeatInterval = setInterval(() => {
    const allSockets = new Set();

    // Collect all unique sockets
    for (const connections of peerConnections.values()) {
      for (const ws of connections) allSockets.add(ws);
    }
    for (const entry of pendingDedicatedSockets.values()) allSockets.add(entry.ws);
    for (const ws of activeLinkedSessions.keys()) allSockets.add(ws);

    for (const ws of allSockets) {
      try {
        ws.ping();
      } catch (err) { }
    }
  }, HEARTBEAT_INTERVAL_MS);

  wss.on('close', () => {
    clearInterval(heartbeatInterval);
  });

  wss.on('connection', (ws, req) => {
    if (!req.url?.startsWith('/p2p-signaling/relay')) {
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const initiatorUsername = url.searchParams.get('username');
    const peerUsername = url.searchParams.get('peer');
    const isRegister = url.searchParams.get('register') === 'true';

    if (!initiatorUsername) {
      ws.close(1008, 'Missing username');
      return;
    }

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    // Registration
    if (isRegister) {
      if (!peerConnections.has(initiatorUsername)) {
        peerConnections.set(initiatorUsername, new Set());
      }
      const conns = peerConnections.get(initiatorUsername);
      conns.add(ws);

      ws.on('message', () => { ws.isAlive = true; });
      ws.on('close', () => {
        conns.delete(ws);
        if (conns.size === 0) {
          peerConnections.delete(initiatorUsername);
        }
      });

      return;
    }

    // Relay
    if (!peerUsername) {
      ws.close(1008, 'Missing peer parameter');
      return;
    }

    const myKey = `${initiatorUsername}:${peerUsername}`;
    const otherKey = `${peerUsername}:${initiatorUsername}`;

    // Matchmaking
    if (pendingDedicatedSockets.has(otherKey)) {
      const partnerEntry = pendingDedicatedSockets.get(otherKey);
      const partnerWs = partnerEntry.ws;

      if (partnerEntry.retryInterval) {
        clearInterval(partnerEntry.retryInterval);
      }

      pendingDedicatedSockets.delete(otherKey);

      if (partnerWs.readyState === 1) {        
        const link = (a, b, label) => {
          a.on('message', (data) => {
              if (b.readyState === 1) {
                b.send(data, () => { });
              }
          });
        };

        activeLinkedSessions.set(ws, partnerWs);
        activeLinkedSessions.set(partnerWs, ws);

        // Clear existing message listeners
        ws.removeAllListeners('message');
        partnerWs.removeAllListeners('message');

        // Restore links after clearing listeners
        link(ws, partnerWs, `[${initiatorUsername.slice(0, 4)}→${peerUsername.slice(0, 4)}]`);
        link(partnerWs, ws, `[${peerUsername.slice(0, 4)}→${initiatorUsername.slice(0, 4)}]`);

        // Replay buffered messages from partner if any
        if (partnerEntry.buffer && partnerEntry.buffer.length > 0) {
          for (const bufferedData of partnerEntry.buffer) {
            try {
              if (ws.readyState === 1) {
                ws.send(bufferedData);
              }
            } catch (err) {
              logger.error(`[QUIC Relay] Replay error:`, err.message);
            }
          }
          partnerEntry.buffer = [];
        }

        const cleanup = (closingWs, code, reason) => {
          const partner = activeLinkedSessions.get(closingWs);
          if (partner) {
            activeLinkedSessions.delete(closingWs);
            activeLinkedSessions.delete(partner);
            if (partner.readyState === 1) {
              partner.close(1000, 'Partner disconnected');
            }
          }
        };

        ws.on('close', (code, reason) => cleanup(ws, code, reason));
        partnerWs.on('close', (code, reason) => cleanup(partnerWs, code, reason));
      } else {
        pendingDedicatedSockets.set(myKey, { ws, buffer: [] });
      }
    } else {
      const entry = { ws, buffer: [], retryInterval: null };
      pendingDedicatedSockets.set(myKey, entry);

      // Temporary listener to buffer messages until linked
      const bufferHandler = (data) => {
        if (!activeLinkedSessions.has(ws)) {
          entry.buffer.push(data);
          if (entry.buffer.length > 100) entry.buffer.shift();
        }
      };
      ws.on('message', bufferHandler);

      const notifyTarget = () => {
        const targetConns = peerConnections.get(peerUsername);
        if (targetConns) {
          for (const targetWs of targetConns) {
            if (targetWs.readyState !== 1) {
              targetConns.delete(targetWs);
            }
          }
          if (targetConns.size === 0) {
            peerConnections.delete(peerUsername);
          }
        }

        const cleanedConns = peerConnections.get(peerUsername);
        if (cleanedConns && cleanedConns.size > 0) {
          const notifyMsg = JSON.stringify({
            type: 'relay-request',
            from: initiatorUsername,
            sessionId: `relay-${Date.now()}`
          });

          let sentCount = 0;
          for (const targetWs of cleanedConns) {
            if (targetWs.readyState === 1) {
              try {
                targetWs.send(notifyMsg, (err) => {
                  if (err) {
                    cleanedConns.delete(targetWs);
                  }
                });
                sentCount++;
              } catch (sendErr) {
                cleanedConns.delete(targetWs);
              }
            } else {
              cleanedConns.delete(targetWs);
            }
          }
        }
      };
      notifyTarget();

      let retryCount = 0;
      const MAX_RETRIES = 10;
      entry.retryInterval = setInterval(() => {
        retryCount++;
        if (ws.readyState !== 1) {
          clearInterval(entry.retryInterval);
          return;
        }
        if (retryCount > MAX_RETRIES) {
          clearInterval(entry.retryInterval);
          return;
        }
        notifyTarget();
      }, 1000);
    }

    ws.on('close', (code, reason) => {
      const currentEntry = pendingDedicatedSockets.get(myKey);
      if (currentEntry && currentEntry.ws === ws) {
        if (currentEntry.retryInterval) clearInterval(currentEntry.retryInterval);
        pendingDedicatedSockets.delete(myKey);
      }
    });

    ws.on('error', (err) => {
      logger.error(`[QUIC Relay] Socket error (${initiatorUsername.slice(0, 4)}):`, err.message, err.stack);
    });
  });
}

