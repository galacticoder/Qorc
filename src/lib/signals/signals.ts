/**
 * Orchestrates Signal Message Handler
 */

import type { SignalHandlers } from '../types/signal-handler-types';
import { SignalType } from '../types/signal-types';
import {
  handleTokenValidationResponse,
  handleAuthError,
  handleAuthFullSuccess,
  handleZKRefreshChallenge,
  handlePrivacyPassIssuance
} from './auth-handlers';
import {
  handleServerPublicKey, handleHybridKeys
} from './key-handlers';
import {
  handleLibsignalDeliverBundle, handleSessionResetRequest,
  handleSessionEstablished, handleError
} from './session-handlers';
import {
  handlePirManifest,
  handlePirResponse,
  handleBlockListSync, handleBlockListUpdate,
  handleBlockListResponse
} from './user-handlers';

export { clearAuthTokens, clearTokenEncryptionKey } from './token-storage';

export async function handleSignalMessages(data: any, handlers: SignalHandlers) {
  const { Authentication, Database, handleFileMessageChunk, handleEncryptedMessagePayload, findUser } = handlers;

  const type = data?.type;
  const message = data?.message ?? data?.data ?? data?.payload ?? '';

  if (!type) {
    console.warn('[signals] missing-type', data);
    return;
  }

  // Skip heartbeat signals
  if (type === SignalType.PQ_HEARTBEAT_PONG || type === SignalType.PQ_HEARTBEAT_PING) return;

  const auth = {
    setServerHybridPublic: Authentication?.setServerHybridPublic,
    serverHybridPublic: Authentication?.serverHybridPublic,
    handleAuthSuccess: Authentication?.handleAuthSuccess,
    loginUsernameRef: Authentication?.loginUsernameRef,
    originalUsernameRef: Authentication?.originalUsernameRef,
    aesKeyRef: Authentication?.aesKeyRef,
    setAccountAuthenticated: Authentication?.setAccountAuthenticated,
    setIsLoggedIn: Authentication?.setIsLoggedIn,
    setLoginError: Authentication?.setLoginError,
    setPassphraseHashParams: Authentication?.setPassphraseHashParams,
    passphrasePlaintextRef: Authentication?.passphrasePlaintextRef,
    passphraseRef: Authentication?.passphraseRef,
    setShowPassphrasePrompt: Authentication?.setShowPassphrasePrompt,
    setShowPasswordPrompt: Authentication?.setShowPasswordPrompt,
    passwordRef: Authentication?.passwordRef,
    setIsSubmittingAuth: Authentication?.setIsSubmittingAuth,
    setAuthStatus: Authentication?.setAuthStatus,
    setTokenValidationInProgress: Authentication?.setTokenValidationInProgress,
    setServerTrustRequest: Authentication?.setServerTrustRequest,
    keyManagerRef: Authentication?.keyManagerRef,
    setUsername: Authentication?.setUsername,
    setMaxStepReached: Authentication?.setMaxStepReached,
    setRecoveryActive: Authentication?.setRecoveryActive,
    setVaultReady: Authentication?.setVaultReady,
    getKeysOnDemand: Authentication?.getKeysOnDemand,
    hybridKeysRef: Authentication?.hybridKeysRef,
    accountAuthenticated: Authentication?.accountAuthenticated,
    isLoggedIn: Authentication?.isLoggedIn,
    isRegistrationMode: Authentication?.isRegistrationMode,
    blindCredentialRef: Authentication?.blindCredentialRef,
    serverHybridPublicRef: Authentication?.serverHybridPublicRef
  };

  const db = { setUsers: Database?.setUsers, users: Database?.users };

  try {
    switch (type) {
      case SignalType.PQ_HANDSHAKE_ACK:
        break;

      case SignalType.SERVER_PUBLIC_KEY:
        await handleServerPublicKey(data, auth);
        break;

      case SignalType.HYBRID_KEYS:
        handleHybridKeys(data, db);
        break;

      case SignalType.AUTH_FULL_SUCCESS:
        await handleAuthFullSuccess(data, auth);
        break;

      case SignalType.AUTH_OT_REGISTER_RESPONSE:
      case SignalType.AUTH_OT_RESPONSE:
        // handled in handlers.ts
        break;

      case SignalType.TOKEN_VALIDATION_RESPONSE:
        await handleTokenValidationResponse(data, auth);
        break;

      case SignalType.ZK_REFRESH_CHALLENGE:
        await handleZKRefreshChallenge(data, auth);
        break;
      case SignalType.ZK_DEVICE_REGISTER_RESPONSE:
        break;

      case SignalType.PRIVACY_PASS_ISSUANCE:
        await handlePrivacyPassIssuance(data, auth);
        break;

      case SignalType.ENCRYPTED_MESSAGE:
      case SignalType.EDIT_MESSAGE:
      case SignalType.DELETE_MESSAGE:
      case SignalType.SEALED_ENVELOPE:
        await handleEncryptedMessagePayload(data);
        break;

      case SignalType.LIBSIGNAL_DELIVER_BUNDLE:
        await handleLibsignalDeliverBundle(data, auth.loginUsernameRef, db.users, findUser);
        break;

      case SignalType.FILE_MESSAGE_CHUNK:
        await handleFileMessageChunk(data, { from: data?.from, to: data?.to });
        break;

      case SignalType.PIR_MANIFEST:
        handlePirManifest(data);
        break;

      case SignalType.PIR_RESPONSE:
        handlePirResponse(data);
        break;

      case SignalType.BLOCK_LIST_SYNC:
        handleBlockListSync(data);
        break;

      case SignalType.BLOCK_LIST_UPDATE:
        handleBlockListUpdate(data);
        break;

      case SignalType.BLOCK_LIST_RESPONSE:
        handleBlockListResponse(data);
        break;

      case SignalType.RATE_LIMIT_STATUS:
        break;

      case SignalType.AUTH_ERROR:
        handleAuthError(data, message, auth);
        break;

      case SignalType.SESSION_RESET_REQUEST:
        await handleSessionResetRequest(data, auth.loginUsernameRef);
        break;

      case SignalType.SESSION_ESTABLISHED:
        handleSessionEstablished(data);
        break;

      case SignalType.ERROR:
        await handleError(data, message, auth);
        break;

      default:
        break;
    }
  } catch (_error) {
    console.error('[signals] signal-processing-error', (_error as Error).message);
    auth.setLoginError?.('Error processing server message');
  }
}
