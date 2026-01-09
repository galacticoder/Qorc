/**
 * Session Signal Handlers
 * Handles LIBSIGNAL_DELIVER_BUNDLE, SESSION_RESET_REQUEST, SESSION_ESTABLISHED
 */

import websocketClient from '../websocket/websocket';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';

// Handle libsignal deliver bundle
export async function handleLibsignalDeliverBundle(data: any, loginUsernameRef: React.RefObject<string> | undefined): Promise<void> {
  try {
    const currentUser = loginUsernameRef?.current;
    const targetUser = data?.username;

    if (!data?.success || data?.error || !data?.bundle) {
      console.warn('[signals] libsignal bundle-request-failed');
      window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_BUNDLE_FAILED, {
        detail: { peer: targetUser, error: data?.error || 'Bundle not available' }
      }));
      return;
    }

    if (!currentUser || !targetUser) {
      console.warn('[signals] libsignal missing-fields');
      return;
    }

    // Check if session already exists
    await new Promise(resolve => setTimeout(resolve, 0));
    const sessionCheck = await (window as any).edgeApi?.hasSession?.({
      selfUsername: currentUser, peerUsername: targetUser, deviceId: 1
    });

    if (sessionCheck?.hasSession) return;

    // Process bundle if no existing session
    await new Promise(resolve => setTimeout(resolve, 0));
    const result = await (window as any).edgeApi?.processPreKeyBundle?.({
      selfUsername: currentUser, peerUsername: targetUser, bundle: data.bundle
    });

    if (!result?.success) throw new Error(result?.error || 'Failed to process pre-key bundle');

    await new Promise(resolve => setTimeout(resolve, 0));
    const confirm = await (window as any).edgeApi?.hasSession?.({
      selfUsername: currentUser, peerUsername: targetUser, deviceId: 1
    });

    if (confirm?.hasSession) {
      try { await (window as any).edgeApi?.trustPeerIdentity?.({ selfUsername: currentUser, peerUsername: targetUser, deviceId: 1 }); } catch { }
      window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_SESSION_READY, { detail: { peer: targetUser } }));
      await websocketClient.sendSecureControlMessage({
        type: SignalType.SESSION_ESTABLISHED,
        from: currentUser,
        username: targetUser,
        timestamp: Date.now()
      });
    } else {
      throw new Error('Session not present after bundle processing');
    }
  } catch (_error) {
    console.error('[signals] libsignal bundle-processing-failed', (_error as Error).message);
    const targetUser = data?.username;
    if (targetUser) {
      window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_BUNDLE_FAILED, {
        detail: { peer: targetUser, error: String(_error) }
      }));
    }
  }
}

// Handle session reset request
export async function handleSessionResetRequest(data: any, loginUsernameRef: React.RefObject<string> | undefined): Promise<void> {
  const peerUsername = data?.from || data?.username;
  const deviceId = data?.deviceId || 1;

  if (!peerUsername || !loginUsernameRef?.current) {
    console.warn('[signals] session-reset missing-peer');
    return;
  }

  try {
    await (window as any).edgeApi?.deleteSession?.({
      selfUsername: loginUsernameRef.current,
      peerUsername: peerUsername,
      deviceId: deviceId
    });

    window.dispatchEvent(new CustomEvent(EventType.SESSION_RESET_RECEIVED, {
      detail: { peerUsername, reason: data?.reason || 'peer-request' }
    }));
  } catch (_err) {
    console.error('[signals] session-reset delete-failed', _err instanceof Error ? _err.message : String(_err));
  }
}

// Handle session established
export function handleSessionEstablished(data: any): void {
  const peerUsername = data?.from || data?.username;
  if (!peerUsername) {
    console.warn('[signals] session-established missing-peer');
    return;
  }
  window.dispatchEvent(new CustomEvent(EventType.SESSION_ESTABLISHED_RECEIVED, {
    detail: { fromPeer: peerUsername }
  }));
}

// Handle error
export async function handleError(data: any, message: string | undefined, auth: any): Promise<void> {
  const errorMsg = message || '';
  try { auth.setIsSubmittingAuth?.(false); } catch { }

  if ((data as any)?.code === 'OFFLINE_LONGTERM_REQUIRED') {
    try { window.dispatchEvent(new CustomEvent(EventType.OFFLINE_LONGTERM_REQUIRED, { detail: data })); } catch { }
    return;
  }

  if (errorMsg.includes('Unknown PQ session') || errorMsg.includes('PQ session')) {
    console.warn('[signals] session-error unknown-session', errorMsg);
    try {
      websocketClient.resetSessionKeys();
      await websocketClient.performHandshake(false);
      void websocketClient.flushPendingQueue();
    } catch (_error) {
      console.error('[signals] session-error rehandshake-failed', _error instanceof Error ? _error.message : String(_error));
    }
  } else {
    console.warn('[signals] server-error received', errorMsg);
  }
}
