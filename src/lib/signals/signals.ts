/**
 * Orchestrates Signal Message Handler
 */

import type { SignalHandlers } from '../types/signal-handler-types';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import {
  handleAuthError,
  handleAuthFullSuccess
} from './auth-handlers';
import { handleServerPublicKey } from './key-handlers';
import { handleError } from './session-handlers';
import { isStaleAuthOperation } from '../auth/auth-lifecycle';

export async function handleSignalMessages(data: any, handlers: SignalHandlers) {
  const { Authentication, handleEncryptedMessagePayload } = handlers;

  const type = data?.type;
  const message = data?.message ?? data?.data ?? data?.payload ?? '';

  if (!type) {
    console.warn('[signals] message missing type');
    return;
  }

  // Skip heartbeat signals
  if (type === SignalType.PQ_HEARTBEAT_PONG || type === SignalType.PQ_HEARTBEAT_PING) return;

  const auth = {
    setServerHybridPublic: Authentication?.setServerHybridPublic,
    handleAuthSuccess: Authentication?.handleAuthSuccess,
    loginUsernameRef: Authentication?.loginUsernameRef,
    originalUsernameRef: Authentication?.originalUsernameRef,
    setAccountAuthenticated: Authentication?.setAccountAuthenticated,
    setIsLoggedIn: Authentication?.setIsLoggedIn,
    setLoginError: Authentication?.setLoginError,
    passphrasePlaintextRef: Authentication?.passphrasePlaintextRef,
    setShowPassphrasePrompt: Authentication?.setShowPassphrasePrompt,
    setShowPasswordPrompt: Authentication?.setShowPasswordPrompt,
    passwordRef: Authentication?.passwordRef,
    setIsSubmittingAuth: Authentication?.setIsSubmittingAuth,
    setAuthStatus: Authentication?.setAuthStatus,
    setTokenValidationInProgress: Authentication?.setTokenValidationInProgress,
    keyManagerOwnerRef: Authentication?.keyManagerOwnerRef,
    setUsername: Authentication?.setUsername,
    setRecoveryActive: Authentication?.setRecoveryActive,
    setVaultReady: Authentication?.setVaultReady,
    getKeysOnDemand: Authentication?.getKeysOnDemand,
    hybridKeysRef: Authentication?.hybridKeysRef,
    serverHybridPublicRef: Authentication?.serverHybridPublicRef,
    authLifecycle: Authentication?.authLifecycle
  };

  try {
    switch (type) {
      case SignalType.PQ_HANDSHAKE_ACK:
        break;

      case SignalType.SERVER_PUBLIC_KEY:
        await handleServerPublicKey(data, auth);
        break;

      case SignalType.AUTH_FULL_SUCCESS:
        await handleAuthFullSuccess(data, auth);
        break;

      case SignalType.AUTH_OT_REGISTER_RESPONSE:
      case SignalType.AUTH_OT_REGISTER_READY:
      case SignalType.AUTH_OT_RESPONSE:
        // handled in handlers.ts
        break;

      case SignalType.SEALED_ENVELOPE:
        await handleEncryptedMessagePayload(data);
        break;

      case SignalType.AUTH_ERROR:
        handleAuthError(data, message, auth);
        break;

      case SignalType.ERROR:
        await handleError(data, message, auth);
        break;

      default:
        break;
    }
  } catch (_error) {
    if (isStaleAuthOperation(_error)) return;
    console.error('[signals] signal-processing-error', (_error as Error).message);
    auth.setLoginError?.('Error processing server message');
    if (type === SignalType.AUTH_FULL_SUCCESS && typeof data?.authRequestId === 'string') {
      window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
        detail: {
          type: 'AUTH_COMPLETION_FAILED',
          code: 'AUTH_COMPLETION_FAILED',
          authRequestId: data.authRequestId,
          message: 'Authentication completion failed'
        }
      }));
    }
  }
}
