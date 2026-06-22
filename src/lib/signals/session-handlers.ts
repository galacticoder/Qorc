/**
 * Session Signal Handlers
 * Handles LIBSIGNAL_DELIVER_BUNDLE, SESSION_RESET_REQUEST, SESSION_ESTABLISHED
 */

import { EventType } from '../types/event-types';
import { signal } from '../tauri-bindings';
import websocketClient from '../websocket/websocket';
import { validateSignalBundleForPeerIdentity, type PeerIdentityLike } from '../utils/signal-bundle-utils';

// Handle libsignal deliver bundle
export async function handleLibsignalDeliverBundle(
  data: any,
  loginUsernameRef: React.RefObject<string> | undefined,
  users?: PeerIdentityLike[] | null,
  findUser?: (handle: string, options?: { forceRefresh?: boolean }) => Promise<any>
): Promise<void> {
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

    const validation = await validateSignalBundleForPeerIdentity(targetUser, data.bundle, users, findUser);
    if (!validation.valid) {
      throw new Error(validation.reason || 'BUNDLE_IDENTITY_VALIDATION_FAILED');
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
  const requestId = typeof data?.requestId === 'string' ? data.requestId : '';
  const op = typeof data?.op === 'string' ? data.op : '';
  const code = typeof data?.code === 'string' ? data.code : '';
  const requestScoped = !!requestId || !!op || typeof data?.stage === 'string';
  const authenticationRequired =
    code === 'AUTHENTICATION_REQUIRED' ||
    data?.error === 'authentication_required' ||
    errorMsg.toLowerCase() === 'authentication required';
  const sessionError = errorMsg.includes('Unknown PQ session') || errorMsg.includes('PQ session');

  if (!requestScoped && !authenticationRequired && !sessionError) {
    try { auth.setIsSubmittingAuth?.(false); } catch { }
    try { auth.setTokenValidationInProgress?.(false); } catch { }
    try { auth.setAuthStatus?.(''); } catch { }
  }

  if (sessionError) {
    console.warn('[signals] session-error unknown-session', errorMsg);
    try {
      websocketClient.resetSessionKeys();
      await websocketClient.performHandshake(false);
      void websocketClient.flushPendingQueue();
    } catch (_error) {
      console.error('[signals] session-error rehandshake-failed', _error instanceof Error ? _error.message : String(_error));
    }
  } else if (requestScoped) {
    const detail = {
      requestId: requestId || undefined,
      op: op || undefined,
      code: code || undefined,
      message: errorMsg || undefined
    };
    if (authenticationRequired) {
      console.info('[signals] request-auth-required', detail);
    } else {
      console.warn('[signals] request-error received', detail);
    }
  } else {
    console.warn('[signals] server-error received', errorMsg);
  }
}
