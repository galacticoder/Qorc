/**
 * Orchestrates Signal Message Handler
 */

import type { SignalHandlers } from '../types/signal-handler-types';
import { SignalType } from '../types/signal-types';
import {
  handleAuthSuccess, handleTokenValidationResponse, handleInAccount,
  handlePassphraseHash, handlePasswordHashParams, handlePassphraseSuccess,
  handleAuthError, handleLoginErrors, handleConnectionRestored
} from './auth-handlers';
import {
  handlePublicKeys, handleServerPublicKey, handleHybridKeys,
  handlePQSessionInit, handlePQSessionResponse
} from './key-handlers';
import {
  handleLibsignalDeliverBundle, handleSessionResetRequest,
  handleSessionEstablished, handleError
} from './session-handlers';
import {
  handleUserExistsResponse, handleOfflineMessagesResponse,
  handleBlockTokensUpdate, handleBlockListSync, handleBlockListUpdate,
  handleBlockListResponse, handleClientGeneratePrekeys, handlePrekeyStatus,
  handleLibsignalPublishStatus, handleAvatarFetchResponse, handleProfilePictureSignal
} from './user-handlers';

export { persistAuthTokens, retrieveAuthTokens, clearAuthTokens, clearTokenEncryptionKey } from './token-storage';

export async function handleSignalMessages(data: any, handlers: SignalHandlers) {
  const { Authentication, Database, handleFileMessageChunk, handleEncryptedMessagePayload } = handlers;
  const { type, message } = data ?? {};
  
  if (!type) {
    console.warn('[signals] missing-type');
    return;
  }

  // Skip heartbeat signals
  if (type === 'pq-heartbeat-pong' || type === 'pq-heartbeat-ping') return;

  const auth = {
    setServerHybridPublic: Authentication?.setServerHybridPublic,
    serverHybridPublic: Authentication?.serverHybridPublic,
    handleAuthSuccess: Authentication?.handleAuthSuccess,
    loginUsernameRef: Authentication?.loginUsernameRef,
    aesKeyRef: Authentication?.aesKeyRef,
    setAccountAuthenticated: Authentication?.setAccountAuthenticated,
    setIsLoggedIn: Authentication?.setIsLoggedIn,
    setLoginError: Authentication?.setLoginError,
    setPassphraseHashParams: Authentication?.setPassphraseHashParams,
    passphrasePlaintextRef: Authentication?.passphrasePlaintextRef,
    passphraseRef: Authentication?.passphraseRef,
    setShowPassphrasePrompt: Authentication?.setShowPassphrasePrompt,
    passwordRef: Authentication?.passwordRef,
    setIsSubmittingAuth: Authentication?.setIsSubmittingAuth,
    setAuthStatus: Authentication?.setAuthStatus,
    setTokenValidationInProgress: Authentication?.setTokenValidationInProgress,
    setServerTrustRequest: Authentication?.setServerTrustRequest,
    keyManagerRef: Authentication?.keyManagerRef,
    setUsername: Authentication?.setUsername,
    setMaxStepReached: Authentication?.setMaxStepReached,
    setRecoveryActive: Authentication?.setRecoveryActive,
    getKeysOnDemand: Authentication?.getKeysOnDemand,
    hybridKeysRef: Authentication?.hybridKeysRef,
    accountAuthenticated: Authentication?.accountAuthenticated,
    isLoggedIn: Authentication?.isLoggedIn,
    isRegistrationMode: Authentication?.isRegistrationMode
  };

  const db = { setUsers: Database?.setUsers };

  try {
    switch (type) {
      case 'pq-handshake-ack':
        break;

      case SignalType.PUBLICKEYS:
        handlePublicKeys(data, db);
        break;

      case SignalType.SERVER_PUBLIC_KEY:
        await handleServerPublicKey(data, auth);
        break;

      case SignalType.HYBRID_KEYS:
        handleHybridKeys(data, db);
        break;

      case SignalType.PQ_SESSION_INIT:
        await handlePQSessionInit(data);
        break;

      case SignalType.PQ_SESSION_RESPONSE:
        handlePQSessionResponse(data);
        break;

      case SignalType.AUTH_SUCCESS:
        await handleAuthSuccess(data, auth);
        break;

      case SignalType.TOKEN_VALIDATION_RESPONSE:
        await handleTokenValidationResponse(data, auth);
        break;

      case SignalType.IN_ACCOUNT:
        await handleInAccount(data, auth);
        break;

      case SignalType.PASSPHRASE_HASH:
        handlePassphraseHash(data, auth);
        break;

      case SignalType.PASSWORD_HASH_PARAMS:
        handlePasswordHashParams(data, auth);
        break;

      case SignalType.PASSPHRASE_SUCCESS:
        await handlePassphraseSuccess(auth);
        break;

      case SignalType.ENCRYPTED_MESSAGE:
      case SignalType.DR_SEND:
      case SignalType.USER_DISCONNECT:
      case SignalType.EDIT_MESSAGE:
      case SignalType.DELETE_MESSAGE:
        await handleEncryptedMessagePayload(data);
        break;

      case SignalType.LIBSIGNAL_DELIVER_BUNDLE:
        await handleLibsignalDeliverBundle(data, auth.loginUsernameRef);
        break;

      case SignalType.FILE_MESSAGE_CHUNK:
        await handleFileMessageChunk(data, { from: data?.from, to: data?.to });
        break;

      case SignalType.USER_EXISTS_RESPONSE:
        handleUserExistsResponse(data, db);
        break;

      case SignalType.OFFLINE_MESSAGES_RESPONSE:
        handleOfflineMessagesResponse(data);
        break;

      case SignalType.BLOCK_TOKENS_UPDATE:
        handleBlockTokensUpdate(data);
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

      case SignalType.CLIENT_GENERATE_PREKEYS:
        handleClientGeneratePrekeys(data);
        break;

      case SignalType.PREKEY_STATUS:
        handlePrekeyStatus(data);
        break;

      case 'libsignal-publish-status':
        handleLibsignalPublishStatus(data);
        break;

      case SignalType.RATE_LIMIT_STATUS:
        break;

      case SignalType.CONNECTION_RESTORED:
        handleConnectionRestored(data, auth);
        break;

      case SignalType.NAMEEXISTSERROR:
      case SignalType.INVALIDNAMELENGTH:
      case SignalType.INVALIDNAME:
      case SignalType.SERVERLIMIT:
        handleLoginErrors(type, message, auth);
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

      case 'avatar-fetch-response':
        handleAvatarFetchResponse(data);
        break;

      case 'profile-picture-request':
      case 'profile-picture-response':
        handleProfilePictureSignal(data, message);
        break;

      default:
        break;
    }
  } catch (_error) {
    console.error('[signals] signal-processing-error', (_error as Error).message);
    auth.setLoginError?.('Error processing server message');
  }
}
