import { clearAccountAuthRefreshState } from '../authentication/account-auth-refresh-state.js';
import { unregisterLocalSocket } from '../routing/blind-router.js';

const SERVER_AUTHORIZATION_CHANGED_CLOSE_CODE = 4001;
const SERVER_AUTHORIZATION_CHANGED_REASON = 'Server authorization changed';

export function revokeAllWebSocketConnections(wss) {
  const sockets = Array.from(wss?.clients || []);
  for (const socket of sockets) {
    socket._hasServerAuth = false;
    socket._authenticated = false;
    socket._accountAuthViaAnonymousToken = false;
    delete socket._unlinkedSession;
    unregisterLocalSocket(socket);
    clearAccountAuthRefreshState(socket);
    socket._ingressQueueRejected = true;
    try {
      socket._connectionAbortController?.abort();
    } catch { }

    try {
      socket.close(
        SERVER_AUTHORIZATION_CHANGED_CLOSE_CODE,
        SERVER_AUTHORIZATION_CHANGED_REASON
      );
    } catch {
      try { socket.terminate?.(); } catch { }
      continue;
    }

    const termination = setTimeout(() => {
      try {
        if (socket.readyState !== 3) socket.terminate?.();
      } catch { }
    }, 1000);
    termination.unref?.();
  }
  return sockets.length;
}
