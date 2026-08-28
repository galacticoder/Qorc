/**
 * Auth Signal Handlers
 */

import websocketClient from '../websocket/websocket';
import { EventType } from '../types/event-types';
import { account, storage } from '../tauri-bindings';
import type { AuthRefs } from '../types/signal-handler-types';
import { getBlindRoutingClient } from '../transport/blind-routing-client';
import { tokenVault } from '../database/token-vault';
import { PrivacyPassClient, PrivacyPassHelpers } from '../cryptography/privacy-pass-client';
import { clearStringRef, computePrivateAuthStorageId } from '../utils/auth-utils';
import {
  getCurrentLocalAccountScope,
  getCurrentServerScope,
  loadLastAuthenticatedAccount,
} from '../security/local-account-scope';
import { OPAQUE_CONFIG } from '../cryptography/opaque-client';
import {
  type AuthOperationSnapshot,
  StaleAuthOperationError,
  wipeStaleAuthResult,
} from '../auth/auth-lifecycle';
import { clearRegistrationAttempt } from '../auth/registration-attempt';
import { SignalType } from '../types/signal-types';
import { keyTransparencyClient } from '../key-transparency/client';
import { hasResumeToken, replenishResumePool } from './resume-tokens';
import { hasExactKeys } from '../sanitizers';
import { REQUEST_ID_RE } from '../../../shared/patterns.js';
import { STORAGE_PREFIXES } from '../database/storage-keys';

type AuthCompletionKind = 'failure' | 'login' | 'registration';

function hasValidIssuanceShape(value: unknown): value is Record<string, unknown> {
  return Boolean(
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype &&
    hasExactKeys(value as Record<string, unknown>, [
      'issuerEpoch',
      'proof',
      'publicKey',
      'signedBlindedTokens'
    ]) &&
    Array.isArray((value as any).signedBlindedTokens) &&
    (value as any).signedBlindedTokens.length === 250 &&
    (value as any).signedBlindedTokens.every((token: unknown) => typeof token === 'string') &&
    typeof (value as any).proof === 'string' &&
    typeof (value as any).publicKey === 'string' &&
    Number.isSafeInteger((value as any).issuerEpoch)
  );
}

function validateAuthCompletion(data: unknown): AuthCompletionKind {
  if (
    !data ||
    typeof data !== 'object' ||
    Array.isArray(data) ||
    Object.getPrototypeOf(data) !== Object.prototype
  ) {
    throw new Error('Server returned invalid authentication completion');
  }
  const payload = data as Record<string, any>;
  if (
    payload.type !== SignalType.AUTH_FULL_SUCCESS ||
    typeof payload.authRequestId !== 'string' ||
    !REQUEST_ID_RE.test(payload.authRequestId) ||
    typeof payload.authenticated !== 'boolean' ||
    typeof payload.serverEntryRequired !== 'boolean' ||
    typeof payload.serverEntryGranted !== 'boolean' ||
    payload.serverEntryRequired === payload.serverEntryGranted
  ) {
    throw new Error('Server returned invalid authentication completion');
  }

  if (!payload.authenticated) {
    if (!hasExactKeys(payload, [
      'authRequestId',
      'authenticated',
      'serverEntryGranted',
      'serverEntryRequired',
      'type'
    ])) {
      throw new Error('Server returned invalid authentication failure');
    }
    return 'failure';
  }

  if (payload.registrationConfirmed === true) {
    if (
      !hasExactKeys(payload, [
        'anonymitySetSize',
        'anonymousTokenBatch',
        'authRequestId',
        'authenticated',
        'credentialIndex',
        'registrationConfirmed',
        'serverEntryGranted',
        'serverEntryRequired',
        'type'
      ]) ||
      !Number.isInteger(payload.credentialIndex) ||
      payload.credentialIndex < 0 ||
      payload.credentialIndex >= OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE ||
      payload.anonymitySetSize !== OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE ||
      !hasValidIssuanceShape(payload.anonymousTokenBatch)
    ) {
      throw new Error('Server returned invalid registration completion');
    }
    return 'registration';
  }

  if (
    !hasExactKeys(payload, [
      'anonymousTokenBatch',
      'authRequestId',
      'authenticated',
      'serverEntryGranted',
      'serverEntryRequired',
      'type'
    ]) ||
    !hasValidIssuanceShape(payload.anonymousTokenBatch)
  ) {
    throw new Error('Server returned invalid login completion');
  }
  return 'login';
}

function captureAuthOperation(auth: AuthRefs): AuthOperationSnapshot | null {
  return auth.authLifecycle?.capture() ?? null;
}

function isAuthOperationCurrent(auth: AuthRefs, operation: AuthOperationSnapshot | null): boolean {
  return !operation || !auth.authLifecycle || auth.authLifecycle.isCurrent(operation);
}

function assertAuthOperationCurrent(auth: AuthRefs, operation: AuthOperationSnapshot | null): void {
  if (!isAuthOperationCurrent(auth, operation)) throw new StaleAuthOperationError();
}

function promptForServerEntry(
  auth: AuthRefs,
  message = 'This server requires an entry token. Please provide the server password.',
  authRequestId?: string
): void {
  websocketClient.setServerEntryPromptPending?.(true);
  auth.setShowPasswordPrompt?.(true);
  auth.setIsSubmittingAuth?.(false);
  auth.setTokenValidationInProgress?.(false);
  auth.setAuthStatus?.('');
  auth.setLoginError?.('');
  window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
    detail: {
      type: 'SERVER_ENTRY_REQUIRED',
      code: 'SERVER_ENTRY_REQUIRED',
      authRequestId,
      message
    }
  }));
}

const switchToUnlinkedModeOnce = async (
  assertCurrent: () => void,
  signal?: AbortSignal
): Promise<boolean> => {
  try {
    assertCurrent();
    console.log(`[AUTHFLOW-DIAG ${new Date().toISOString()}] login-completion: switching to unlinked mode`);
    await websocketClient.switchToUnlinkedMode(signal);
    assertCurrent();
    return !!(
      websocketClient.isUnlinkedMode?.()
      && websocketClient.isConnectedToServer?.()
      && websocketClient.isUnlinkedSessionReady?.()
    );
  } catch (err) {
    assertCurrent();
    console.error('[AuthHandlers] Unlinked privacy-boundary connection failed', {
      error: err instanceof Error ? err.message : String(err)
    });
    return false;
  }
};

/**
 * Handle Full Authentication Success
 */
export async function handleAuthFullSuccess(data: any, auth: AuthRefs): Promise<void> {
  const operation = captureAuthOperation(auth);
  const {
    setAuthStatus, loginUsernameRef, setIsLoggedIn,
    setAccountAuthenticated, setIsSubmittingAuth,
    setLoginError,
    setUsername, setRecoveryActive,
    handleAuthSuccess
  } = auth;

  const currentUsername = loginUsernameRef?.current || '';
  if (auth.authLifecycle && (!operation?.requestId || data?.authRequestId !== operation.requestId)) return;
  if (operation?.account && operation.account !== currentUsername) return;
  const awaitCurrent = async <T>(promise: Promise<T>): Promise<T> => {
    const result = await promise;
    try {
      assertAuthOperationCurrent(auth, operation);
    } catch (error) {
      wipeStaleAuthResult(result);
      throw error;
    }
    return result;
  };
  const completionKind = validateAuthCompletion(data);

  if (completionKind === 'failure') {
    const message = 'Incorrect username, password, or passphrase.';
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setLoginError?.(message);
    window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
      detail: { type: 'AUTH_FAILED', code: 'AUTH_FAILED', authRequestId: data?.authRequestId, message }
    }));
    return;
  }

  if (!currentUsername) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setLoginError?.('Local authentication identity is unavailable. Please sign in again.');
    try { await websocketClient.close(); } catch { }
    return;
  }

  if (completionKind === 'registration') {
    const storageId = computePrivateAuthStorageId(currentUsername, await awaitCurrent(getCurrentServerScope()));
    const slotKey = `${STORAGE_PREFIXES.PRIVATE_AUTH_SLOT}${storageId}`;
    const expectedSlotValue = JSON.stringify({
      credentialIndex: data.credentialIndex,
      anonymitySetSize: data.anonymitySetSize
    });
    if (await awaitCurrent(storage.get(slotKey)) !== expectedSlotValue) {
      throw new Error('Registration confirmation does not match the staged private-auth slot');
    }
  }

  await handlePrivacyPassIssuance(data.anonymousTokenBatch, auth, operation);
  assertAuthOperationCurrent(auth, operation);

  let resumeCredentialReady = false;
  try {
    await awaitCurrent(replenishResumePool(currentUsername, true));
    resumeCredentialReady = await awaitCurrent(hasResumeToken(currentUsername));
  } catch {
    assertAuthOperationCurrent(auth, operation);
  }

  if (!resumeCredentialReady) {
    const message = 'Anonymous session credentials could not be persisted. Please sign in again.';
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setLoginError?.(message);
    try { await websocketClient.close(); } catch { }
    window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
      detail: {
        type: 'ANONYMOUS_SESSION_UNAVAILABLE',
        code: 'ANONYMOUS_SESSION_UNAVAILABLE',
        authRequestId: data?.authRequestId,
        message
      }
    }));
    return;
  }

  try {
    await awaitCurrent(keyTransparencyClient.assertSecurityReady());
  } catch {
    const message = 'Key-transparency security incident detected. Messaging remains quarantined.';
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setLoginError?.(message);
    try { await websocketClient.close(); } catch { }
    window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
      detail: {
        type: 'KEY_TRANSPARENCY_SECURITY_INCIDENT',
        code: 'KEY_TRANSPARENCY_SECURITY_INCIDENT',
        authRequestId: data?.authRequestId,
        message
      }
    }));
    return;
  }

  if (completionKind === 'registration') {
    await awaitCurrent(clearRegistrationAttempt(currentUsername));
  }

  if (data?.serverEntryRequired) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setRecoveryActive?.(false);
    promptForServerEntry(auth, undefined, data.authRequestId);
    return;
  }

  websocketClient.markServerAuthGranted?.();

  try {
    const blindClient = getBlindRoutingClient(currentUsername);
    blindClient.setSendFunction(async (message: any) => {
      await websocketClient.sendSecureControlMessage(message);
    });
  } catch { }

  if (websocketClient.isServerEntryPromptPending?.()) {
    return;
  }

  if (!await awaitCurrent(switchToUnlinkedModeOnce(
    () => assertAuthOperationCurrent(auth, operation),
    operation?.signal
  ))) {
    const message = 'Anonymous delivery connection could not be established. Please sign in again.';
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setLoginError?.(message);
    try { await websocketClient.close(); } catch { }
    window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
      detail: {
        type: 'ANONYMOUS_SESSION_UNAVAILABLE',
        code: 'ANONYMOUS_SESSION_UNAVAILABLE',
        authRequestId: data?.authRequestId,
        message
      }
    }));
    return;
  }

  if (handleAuthSuccess) {
    await awaitCurrent(Promise.resolve(handleAuthSuccess(currentUsername)));
  } else {
    setAccountAuthenticated?.(true);
    setIsLoggedIn?.(true);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setRecoveryActive?.(false);
    if (currentUsername) setUsername?.(currentUsername);
  }

  auth.setShowPassphrasePrompt?.(false);
  auth.setShowPasswordPrompt?.(false);
  auth.setRecoveryActive?.(false);
  auth.setVaultReady?.(true);
  auth.setTokenValidationInProgress?.(false);

  assertAuthOperationCurrent(auth, operation);
  websocketClient.markApplicationAuthReady?.();
  window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS, {
    detail: {
      authenticated: true,
      authRequestId: data.authRequestId,
      serverEntryRequired: false,
      serverEntryGranted: true
    }
  }));
}

/**
 * Handle Privacy Pass Token Issuance
 */
export async function handlePrivacyPassIssuance(
  data: any,
  auth: AuthRefs,
  inheritedOperation?: AuthOperationSnapshot | null
): Promise<void> {
  const operation = inheritedOperation === undefined ? captureAuthOperation(auth) : inheritedOperation;
  let signedBlindedTokens: Uint8Array[] = [];
  let proof: Uint8Array | null = null;
  let serverPublicKey: Uint8Array | null = null;
  let pendingTokens: any[] = [];
  let completedTokens: any[] = [];
  try {
    assertAuthOperationCurrent(auth, operation);
    const ppClient = new PrivacyPassClient();
    const decoded = PrivacyPassHelpers.decodeResponse(data);
    signedBlindedTokens = decoded.signedBlindedTokens;
    proof = decoded.proof;
    serverPublicKey = decoded.serverPublicKey;

    pendingTokens = await tokenVault.getPendingTokens(signedBlindedTokens.length);
    if (pendingTokens.length !== signedBlindedTokens.length) {
      throw new Error('Privacy Pass issuance batch size mismatch');
    }
    completedTokens = await ppClient.unblindTokens(
      pendingTokens,
      signedBlindedTokens,
      proof,
      serverPublicKey,
      decoded.issuerEpoch
    );
    assertAuthOperationCurrent(auth, operation);

    await tokenVault.updateTokens(completedTokens);
    assertAuthOperationCurrent(auth, operation);
  } catch (err) {
    assertAuthOperationCurrent(auth, operation);
    console.error('[AuthHandlers] Privacy Pass issuance failed:', err);
    throw err;
  } finally {
    for (const token of signedBlindedTokens) token.fill(0);
    proof?.fill(0);
    serverPublicKey?.fill(0);
    for (const token of pendingTokens) {
      token.tokenSecret?.fill(0);
      token.blindingFactor?.fill(0);
      token.blindedElement?.fill(0);
      token.unblindedToken?.fill(0);
    }
    for (const token of completedTokens) {
      token.tokenSecret?.fill(0);
      token.blindingFactor?.fill(0);
      token.blindedElement?.fill(0);
      token.unblindedToken?.fill(0);
    }
  }
}

/**
 * Handle Token Validation Response
 */

export async function handleTokenValidationResponse(data: any, auth: AuthRefs): Promise<void> {
  if (
    !data ||
    typeof data !== 'object' ||
    Array.isArray(data) ||
    Object.getPrototypeOf(data) !== Object.prototype ||
    typeof data.requestId !== 'string' ||
    !REQUEST_ID_RE.test(data.requestId) ||
    typeof data.valid !== 'boolean' ||
    (data.valid
      ? !hasExactKeys(data, ['requestId', 'serverEntryGranted', 'serverEntryRequired', 'type', 'valid']) ||
        typeof data.serverEntryRequired !== 'boolean' ||
        typeof data.serverEntryGranted !== 'boolean' ||
        data.serverEntryRequired === data.serverEntryGranted
      : !hasExactKeys(data, ['error', 'requestId', 'type', 'valid']) ||
        typeof data.error !== 'string' ||
        data.error.length < 1 ||
        data.error.length > 128)
  ) {
    throw new Error('Server returned invalid session validation response');
  }
  const operation = captureAuthOperation(auth);
  const {
    loginUsernameRef,
    setAccountAuthenticated,
    setIsLoggedIn,
    setLoginError,
    setTokenValidationInProgress,
    setUsername,
    getKeysOnDemand,
    hybridKeysRef
  } = auth;
  const awaitCurrent = async <T>(promise: Promise<T>): Promise<T> => {
    const result = await promise;
    try {
      assertAuthOperationCurrent(auth, operation);
    } catch (error) {
      wipeStaleAuthResult(result);
      throw error;
    }
    return result;
  };

  if (!data?.valid) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setTokenValidationInProgress?.(false);
    if (data?.error || data?.message) {
      setLoginError?.(`Session expired or invalid: ${data.message || data.error}`);
    }
    try {
      await websocketClient.close();
      websocketClient.resetConnectionPrivacyMode();
    } catch { }
    return;
  }

  if (data?.serverEntryRequired) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    promptForServerEntry(auth);
    try {
      await websocketClient.validateLinkedAuthenticationMode();
    } catch {
      if (isAuthOperationCurrent(auth, operation)) {
        websocketClient.setServerEntryPromptPending?.(false);
        auth.setShowPasswordPrompt?.(false);
        setLoginError?.('Could not establish a private server-authentication connection.');
      }
      return;
    }
    return;
  }

  if (
    !websocketClient.isUnlinkedMode?.()
    || !websocketClient.isConnectedToServer?.()
    || !websocketClient.isUnlinkedSessionReady?.()
  ) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setTokenValidationInProgress?.(false);
    setLoginError?.('Anonymous delivery was not established. Please sign in again.');
    try { await websocketClient.close(); } catch { }
    return;
  }

  websocketClient.markServerAuthGranted?.();

  // Get username from storage or current ref
  const storedAccount = await awaitCurrent(loadLastAuthenticatedAccount());
  let username = storedAccount.username;
  const storedDisplayName = storedAccount.displayName;
  
  if (!username && loginUsernameRef?.current) {
    username = loginUsernameRef.current;
  }
  
  if (typeof username !== 'string' || !username) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setTokenValidationInProgress?.(false);
    setLoginError?.('Local authentication identity is unavailable. Please sign in again.');
    try { await websocketClient.close(); } catch { }
    return;
  }
  if (operation?.account && operation.account !== username) return;
  if (loginUsernameRef) loginUsernameRef.current = username;
  setUsername?.(typeof storedDisplayName === 'string' && storedDisplayName ? storedDisplayName : username);

  try {
    await awaitCurrent(keyTransparencyClient.assertSecurityReady());
  } catch {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setTokenValidationInProgress?.(false);
    setLoginError?.('Key-transparency security incident detected. Messaging remains quarantined.');
    try { await websocketClient.close(); } catch { }
    return;
  }

  let vaultUnlocked = false;
  if (username) {
    try {
      const accountScope = await awaitCurrent(getCurrentLocalAccountScope(username));
      vaultUnlocked = await awaitCurrent(account.isUnlocked(accountScope));
      if (auth.keyManagerOwnerRef) auth.keyManagerOwnerRef.current = accountScope;
      auth.setVaultReady?.(vaultUnlocked);
    } catch (err) {
      assertAuthOperationCurrent(auth, operation);
      console.warn('[Auth] Failed to auto-unlock vault:', err);
    }
  }

  if (getKeysOnDemand) {
    try {
      const keys = await getKeysOnDemand();
      assertAuthOperationCurrent(auth, operation);
      if (keys && hybridKeysRef) {
        hybridKeysRef.current = keys;
        try { window.dispatchEvent(new CustomEvent(EventType.HYBRID_KEYS_UPDATED)); } catch { }
      }
    } catch {
      assertAuthOperationCurrent(auth, operation);
    }
  }

  // Initialize blind routing
  if (username) {
    try {
      const blindClient = getBlindRoutingClient(username);
      blindClient.setSendFunction(async (message: any) => {
        await websocketClient.sendSecureControlMessage(message);
      });
    } catch (err) {
      console.warn('[Auth] Failed to initialize blind routing:', err);
    }
  }

  assertAuthOperationCurrent(auth, operation);
  setLoginError?.('');
  setAccountAuthenticated?.(true);
  setIsLoggedIn?.(true);
  setTokenValidationInProgress?.(false);
  
  if (vaultUnlocked) {
    if (auth.passwordRef) clearStringRef(auth.passwordRef);
    if (auth.passphrasePlaintextRef) clearStringRef(auth.passphrasePlaintextRef);
    auth.setShowPassphrasePrompt?.(false);
    auth.setRecoveryActive?.(false);
  } else {
    auth.setShowPassphrasePrompt?.(true);
    auth.setRecoveryActive?.(true);
  }

  websocketClient.markApplicationAuthReady?.();
  if (vaultUnlocked) {
    void websocketClient.replaceConsumedAccountAuthorizationToken().catch((error) => {
      console.warn('[Auth] Failed to replace consumed account credential:', error);
    });
  }
  window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS));
}

/**
 * Handle authentication error
 */
export function handleAuthError(data: any, message: string | undefined, auth: AuthRefs): void {
  const operation = captureAuthOperation(auth);
  if (
    typeof data?.authRequestId === 'string' &&
    auth.authLifecycle &&
    data.authRequestId !== operation?.requestId
  ) return;
  if (
    typeof data?.requestId === 'string' &&
    auth.authLifecycle &&
    data.requestId !== operation?.requestId
  ) return;
  const { setLoginError, setAuthStatus, setIsSubmittingAuth, setAccountAuthenticated, setIsLoggedIn } = auth;
  const locked = Boolean(data?.locked);
  const cooldownSeconds = typeof data?.cooldownSeconds === 'number' ? data.cooldownSeconds : undefined;

  let errorMessage = message ?? 'Authentication failed';
  if (locked && cooldownSeconds) {
    errorMessage = `Too many attempts. Try again in ${cooldownSeconds}s.`;
    websocketClient.setGlobalRateLimit?.(cooldownSeconds);
  }

  setLoginError?.(errorMessage);
  setAuthStatus?.('');
  setIsSubmittingAuth?.(false);
  auth.setTokenValidationInProgress?.(false);
  window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
    detail: {
      type: data?.code === 'SERVER_ENTRY_REQUIRED' ? 'SERVER_ENTRY_REQUIRED' : data?.type,
      category: data?.category,
      code: data?.code,
      authRequestId: data?.authRequestId,
      requestId: data?.requestId,
      message: errorMessage
    }
  }));

  if (locked) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
  }
}
