import websocketClient from '../websocket/websocket';
import type { AuthRefs } from '../types/signal-handler-types';

// Handle error
export async function handleError(data: any, message: string | undefined, auth: AuthRefs): Promise<void> {
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
    auth.setIsSubmittingAuth(false);
    auth.setTokenValidationInProgress(false);
    auth.setAuthStatus('');
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
