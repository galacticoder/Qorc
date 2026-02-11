import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

// Relay IDs are provided by clients as opaque identifiers (e.g. inboxId)
function normalizeRelayId(id) {
  if (!id || typeof id !== 'string') return '';
  return id.trim().slice(0, 128);
}

function isSocketOpen(ws) {
  return ws && ws.readyState === 1;
}

export function attachQuicRelay(wss, logger = cryptoLogger) {
  console.log('[QUIC Relay] Attaching relay service...');

  const peerConnections = new Map();
  const pendingDedicatedSockets = new Map();
  const activeLinkedSessions = new Map();
  const socketMeta = new WeakMap();
  const linkedCloseBound = new WeakSet();

  const HEARTBEAT_INTERVAL_MS = 30_000;
  const RELAY_NOTIFY_RETRY_MS = 1_000;
  const RELAY_NOTIFY_MAX_RETRIES = 10;
  const MAX_BUFFERED_MESSAGES = 100;

  const clearRetry = (entry) => {
    if (entry?.retryInterval) {
      clearInterval(entry.retryInterval);
      entry.retryInterval = null;
    }
  };

  const cleanPeerConnectionSet = (relayId) => {
    const targetConns = peerConnections.get(relayId);
    if (!targetConns) return null;

    for (const targetWs of targetConns) {
      if (!isSocketOpen(targetWs)) {
        targetConns.delete(targetWs);
      }
    }

    if (targetConns.size === 0) {
      peerConnections.delete(relayId);
      return null;
    }

    return targetConns;
  };

  const notifyTarget = (fromRelayId, toRelayId) => {
    const cleanedConns = cleanPeerConnectionSet(toRelayId);
    if (!cleanedConns || cleanedConns.size === 0) return 0;

    const notifyMsg = JSON.stringify({
      type: 'relay-request',
      from: fromRelayId,
      sessionId: `relay-${Date.now()}`
    });

    let sentCount = 0;
    for (const targetWs of cleanedConns) {
      if (!isSocketOpen(targetWs)) {
        cleanedConns.delete(targetWs);
        continue;
      }

      try {
        targetWs.send(notifyMsg, (err) => {
          if (err) {
            cleanedConns.delete(targetWs);
          }
        });
        sentCount++;
      } catch {
        cleanedConns.delete(targetWs);
      }
    }

    if (cleanedConns.size === 0) {
      peerConnections.delete(toRelayId);
    }

    return sentCount;
  };

  const removePendingEntry = (key, expectedWs) => {
    const entry = pendingDedicatedSockets.get(key);
    if (!entry) return null;
    if (expectedWs && entry.ws !== expectedWs) return null;

    clearRetry(entry);
    pendingDedicatedSockets.delete(key);
    return entry;
  };

  const cleanupLinkedSocket = (closingWs) => {
    const partnerWs = activeLinkedSessions.get(closingWs);
    if (!partnerWs) return;

    activeLinkedSessions.delete(closingWs);
    activeLinkedSessions.delete(partnerWs);

    const partnerMeta = socketMeta.get(partnerWs);
    if (!partnerMeta || !isSocketOpen(partnerWs)) return;

    // Keep the surviving side alive and re-queue it so reconnecting peer can re-link.
    setPendingSocket(partnerMeta.initiatorId, partnerMeta.peerId, partnerWs);
  };

  const bindLinkedCloseHandler = (ws) => {
    if (linkedCloseBound.has(ws)) return;
    linkedCloseBound.add(ws);
    ws.on('close', () => {
      cleanupLinkedSocket(ws);
    });
  };

  const linkSockets = (wsA, wsB, replayToA = []) => {
    if (!isSocketOpen(wsA) || !isSocketOpen(wsB)) return false;

    wsA.removeAllListeners('message');
    wsB.removeAllListeners('message');

    const forward = (from, to) => {
      from.on('message', (data) => {
        from.isAlive = true;
        if (isSocketOpen(to)) {
          to.send(data, () => { });
        }
      });
    };

    activeLinkedSessions.set(wsA, wsB);
    activeLinkedSessions.set(wsB, wsA);
    bindLinkedCloseHandler(wsA);
    bindLinkedCloseHandler(wsB);

    forward(wsA, wsB);
    forward(wsB, wsA);

    if (Array.isArray(replayToA) && replayToA.length > 0) {
      for (const bufferedData of replayToA) {
        try {
          if (isSocketOpen(wsA)) {
            wsA.send(bufferedData);
          }
        } catch (err) {
          logger.error('[QUIC Relay] Replay error:', err?.message || String(err));
        }
      }
    }

    return true;
  };

  function setPendingSocket(initiatorId, peerId, ws) {
    if (!isSocketOpen(ws)) return null;

    const myKey = `${initiatorId}:${peerId}`;
    const existingEntry = pendingDedicatedSockets.get(myKey);
    if (existingEntry && existingEntry.ws !== ws) {
      clearRetry(existingEntry);
      pendingDedicatedSockets.delete(myKey);
      try {
        if (isSocketOpen(existingEntry.ws)) {
          existingEntry.ws.close(1000, 'Superseded by newer socket');
        }
      } catch { }
    }

    const entry = {
      ws,
      initiatorId,
      peerId,
      retryInterval: null,
      buffer: []
    };

    ws.removeAllListeners('message');
    ws.on('message', (data) => {
      ws.isAlive = true;
      if (!activeLinkedSessions.has(ws)) {
        entry.buffer.push(data);
        if (entry.buffer.length > MAX_BUFFERED_MESSAGES) {
          entry.buffer.shift();
        }
      }
    });

    pendingDedicatedSockets.set(myKey, entry);
    notifyTarget(initiatorId, peerId);

    let retryCount = 0;
    entry.retryInterval = setInterval(() => {
      if (!isSocketOpen(ws) || activeLinkedSessions.has(ws)) {
        clearRetry(entry);
        return;
      }

      retryCount += 1;
      if (retryCount > RELAY_NOTIFY_MAX_RETRIES) {
        clearRetry(entry);
        return;
      }

      notifyTarget(initiatorId, peerId);
    }, RELAY_NOTIFY_RETRY_MS);

    return entry;
  }

  const heartbeatInterval = setInterval(() => {
    const allSockets = new Set();

    for (const connections of peerConnections.values()) {
      for (const ws of connections) allSockets.add(ws);
    }
    for (const entry of pendingDedicatedSockets.values()) {
      allSockets.add(entry.ws);
    }
    for (const ws of activeLinkedSessions.keys()) {
      allSockets.add(ws);
    }

    for (const ws of allSockets) {
      try {
        ws.ping();
      } catch { }
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
    const rawInitiator = url.searchParams.get('relayId');
    const rawPeer = url.searchParams.get('peerRelayId') || url.searchParams.get('peer');
    const isRegister = url.searchParams.get('register') === 'true';

    if (!rawInitiator) {
      ws.close(1008, 'Missing relay ID');
      return;
    }

    const initiatorId = normalizeRelayId(rawInitiator);
    const peerId = rawPeer ? normalizeRelayId(rawPeer) : null;

    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });

    // Registration
    if (isRegister) {
      if (!peerConnections.has(initiatorId)) {
        peerConnections.set(initiatorId, new Set());
      }
      const conns = peerConnections.get(initiatorId);
      conns.add(ws);

      ws.on('message', () => {
        ws.isAlive = true;
      });
      ws.on('close', () => {
        conns.delete(ws);
        if (conns.size === 0) {
          peerConnections.delete(initiatorId);
        }
      });

      return;
    }

    if (!peerId) {
      ws.close(1008, 'Missing peer parameter');
      return;
    }

    const myKey = `${initiatorId}:${peerId}`;
    const otherKey = `${peerId}:${initiatorId}`;

    socketMeta.set(ws, { initiatorId, peerId });

    const partnerEntry = removePendingEntry(otherKey);
    if (partnerEntry && isSocketOpen(partnerEntry.ws)) {
      const linked = linkSockets(ws, partnerEntry.ws, partnerEntry.buffer);
      if (!linked) {
        setPendingSocket(initiatorId, peerId, ws);
      }
    } else {
      setPendingSocket(initiatorId, peerId, ws);
    }

    ws.on('close', () => {
      removePendingEntry(myKey, ws);
      cleanupLinkedSocket(ws);
    });

    ws.on('error', (err) => {
      logger.error(`[QUIC Relay] Socket error (${initiatorId.slice(0, 4)}):`, err.message, err.stack);
    });
  });
}
