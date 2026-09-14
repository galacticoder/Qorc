import crypto from 'node:crypto';

const pendingBroadcasts = new WeakMap();

export function hasPendingBroadcast(ws) {
  return pendingBroadcasts.has(ws);
}

export async function sendFlowControlledBroadcast(ws, send) {
  if (ws.readyState !== 1 || ws._connectionAbortSignal?.aborted || pendingBroadcasts.has(ws)) {
    return false;
  }
  const acknowledgement = crypto.randomBytes(16);
  const release = () => {
    if (pendingBroadcasts.get(ws) !== acknowledgement) return;
    pendingBroadcasts.delete(ws);
    ws.off('pong', onPong);
    ws.off('close', release);
    ws.off('error', release);
  };
  const onPong = (payload) => {
    if (Buffer.isBuffer(payload) && payload.equals(acknowledgement)) release();
  };
  pendingBroadcasts.set(ws, acknowledgement);
  ws.on('pong', onPong);
  ws.once('close', release);
  ws.once('error', release);
  try {
    const delivered = await send();
    if (!delivered || ws.readyState !== 1 || pendingBroadcasts.get(ws) !== acknowledgement) {
      release();
      return false;
    }
    ws.ping(acknowledgement, (error) => {
      if (error) release();
    });
    return true;
  } catch (error) {
    release();
    throw error;
  }
}
