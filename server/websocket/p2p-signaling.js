/**
 * P2P WebRTC Signaling Server
 * Signaling relay for WebRTC peer connections
 */
import { checkBlocking } from '../security/blocking.js';
import { SignalType } from '../signals.js';

export function attachP2PSignaling(wss, logger = console) {
  const peerConnections = new Map(); // username -> Set of ws connections

  wss.on('connection', (ws, req) => {
    if (!req.url?.startsWith('/p2p-signaling')) {
      return;
    }

    logger.info('[P2P Signaling] New connection established', { url: req.url });

    let currentUsername = null;

    ws.on('message', async (data) => {
      try {
        const message = JSON.parse(data.toString());
        const { type, from, to, payload } = message;

        // Register peer
        if (type === SignalType.REGISTER) {
          currentUsername = from;
          if (!peerConnections.has(from)) {
            peerConnections.set(from, new Set());
          }
          peerConnections.get(from).add(ws);

          logger.info('[P2P Signaling] User registered', { username: from?.slice(0, 8) + '...', totalPeers: peerConnections.size });

          ws.send(JSON.stringify({
            type: SignalType.REGISTER_ACK, // was 'registered'
            username: from,
          }));
          return;
        }

        // Relay signaling messages
        if (type === SignalType.OFFER || type === SignalType.ANSWER || type === SignalType.ICE_CANDIDATE) {
          try {
            const senderBlockedByRecipient = await checkBlocking(from, to);
            const recipientBlockedBySender = await checkBlocking(to, from);

            if (senderBlockedByRecipient || recipientBlockedBySender) {
              ws.send(JSON.stringify({ type: SignalType.ERROR, error: 'BLOCKED' }));
              logger.info('[P2P Signaling] Signaling blocked', {
                from: from?.slice(0, 8) + '...',
                to: to?.slice(0, 8) + '...',
                reason: senderBlockedByRecipient ? 'sender-blocked' : 'recipient-blocked'
              });
              return;
            }
          } catch (e) {
            logger.warn('[P2P Signaling] Blocking check error:', e?.message || String(e));
          }

          const targetSockets = peerConnections.get(to);

          if (targetSockets && targetSockets.size > 0) {
            const relayMessage = JSON.stringify({
              type,
              from,
              to,
              payload,
            });

            let delivered = false;
            for (const targetWs of targetSockets) {
              if (targetWs.readyState === 1) {
                targetWs.send(relayMessage);
                delivered = true;
              }
            }

            if (delivered) {
              ws.send(JSON.stringify({
                type: 'relayed',
                messageType: type,
              }));
            } else {
              ws.send(JSON.stringify({
                type: SignalType.ERROR,
                error: 'PEER_OFFLINE',
              }));
            }
          } else {
            ws.send(JSON.stringify({
              type: SignalType.ERROR,
              error: 'PEER_NOT_FOUND',
            }));
          }
          return;
        }

        ws.send(JSON.stringify({
          type: SignalType.ERROR,
          error: 'UNKNOWN_MESSAGE_TYPE',
        }));
      } catch (error) {
        logger.error('[P2P Signaling] Message error:', error.message);
        ws.send(JSON.stringify({
          type: SignalType.ERROR,
          error: 'INVALID_MESSAGE',
        }));
      }
    });

    ws.on('close', () => {
      logger.info('[P2P Signaling] Connection closed', { username: currentUsername?.slice(0, 8) + '...' || 'unknown' });
      if (currentUsername) {
        const sockets = peerConnections.get(currentUsername);
        if (sockets) {
          sockets.delete(ws);
          if (sockets.size === 0) {
            peerConnections.delete(currentUsername);
          }
        }
      }
    });

    ws.on('error', (error) => {
      logger.error('[P2P Signaling] WebSocket error:', error.message);
    });
  });

  logger.info('[P2P Signaling] Attached to WebSocket server at /p2p-signaling');

  return {
    getStats: () => ({
      connectedPeers: peerConnections.size,
      totalSockets: Array.from(peerConnections.values()).reduce((sum, set) => sum + set.size, 0),
    }),
  };
}