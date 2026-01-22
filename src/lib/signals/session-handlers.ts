/**
 * Session Signal Handlers
 * Handles LIBSIGNAL_DELIVER_BUNDLE, SESSION_RESET_REQUEST, SESSION_ESTABLISHED
 */

import websocketClient from '../websocket/websocket';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { signal } from '../tauri-bindings';

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
    const sessionCheck = await signal.hasSession(currentUser, targetUser, 1);

    if (sessionCheck) return;

    // Register Kyber/ML-KEM key if present in bundle
    if (data.bundle?.kyberPreKey?.publicKeyBase64 || data.bundle?.pqKyber?.publicKeyBase64) {
      try {
        const kyberKey = data.bundle.pqKyber?.publicKeyBase64 || data.bundle.kyberPreKey?.publicKeyBase64;
        if (kyberKey) {
          await signal.setPeerKyberKey(targetUser, kyberKey);
        }
      } catch (err) {
        console.warn('[signals] Failed to register peer Kyber key:', err);
      }
    }

    // Process bundle if no existing session
    await new Promise(resolve => setTimeout(resolve, 0));
    const result = await signal.processPreKeyBundle(currentUser, targetUser, data.bundle);

    if (!result) throw new Error('Failed to process pre-key bundle');

    await new Promise(resolve => setTimeout(resolve, 0));
    const confirm = await signal.hasSession(currentUser, targetUser, 1);

    if (confirm) {
      try { await signal.trustPeerIdentity(currentUser, targetUser, 1); } catch { }
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
    const targetUser = data?.username;
    const errorMessage = _error instanceof Error ? _error.message : String(_error);
    console.error('[signals] libsignal bundle-processing-failed', errorMessage);
    if (targetUser) {
      window.dispatchEvent(new CustomEvent(EventType.LIBSIGNAL_BUNDLE_FAILED, {
        detail: { peer: targetUser, error: errorMessage }
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
    await signal.deleteSession(loginUsernameRef.current, peerUsername, deviceId);

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
  try { auth.setTokenValidationInProgress?.(false); } catch { }
  try { auth.setAuthStatus?.(''); } catch { }

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
