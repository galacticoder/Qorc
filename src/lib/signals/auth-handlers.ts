/**
 * Auth Signal Handlers
 */

import { CryptoUtils } from '../utils/crypto-utils';
import websocketClient from '../websocket/websocket';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { storage } from '../tauri-bindings';
import type { AuthRefs } from '../types/signal-handler-types';
import { clearAuthTokens, clearTokenEncryptionKey } from './token-storage';
import { PostQuantumUtils } from '../utils/pq-utils';
import { auth as authApi } from '../tauri-bindings';
import { getBlindRoutingClient, BlindRoutingCredentials } from '../transport/blind-routing-client';
import { tokenVault } from '../database/token-vault';
import { PrivacyPassClient, PrivacyPassHelpers } from '../cryptography/privacy-pass-client';
import { ZKDeviceProofGenerator, getOrCreateRingKeyPair } from '../cryptography/zk-device-proof';
import { unblindSignature } from '../crypto/blind-credentials';
import { computeBlindUserId } from '../utils/auth-utils';
import { loadVaultKeyRaw, loadWrappedMasterKey, ensureVaultKeyCryptoKey } from '../cryptography/vault-key';
import { SecureKeyManager } from '../database/secure-key-manager';
import { OPAQUE_CONFIG } from '../cryptography/opaque-client';

let unlinkedModeSwitchInFlight = false;
let unlinkedModeSwitchRetryCount = 0;
let unlinkedModeSwitchRetryTimer: ReturnType<typeof setTimeout> | null = null;
const MAX_UNLINKED_SWITCH_BACKOFF_MS = 10000;
const MAX_UNLINKED_SWITCH_RETRIES = 5;

function promptForServerEntry(auth: AuthRefs, message = 'This server requires an entry token. Please provide the server password.'): void {
  auth.setShowPasswordPrompt?.(true);
  auth.setIsSubmittingAuth?.(false);
  auth.setTokenValidationInProgress?.(false);
  auth.setAuthStatus?.('');
  auth.setLoginError?.('');
  window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
    detail: {
      type: 'SERVER_ENTRY_REQUIRED',
      code: 'SERVER_ENTRY_REQUIRED',
      message
    }
  }));
}

const scheduleUnlinkedModeSwitch = () => {
  if (unlinkedModeSwitchInFlight) return;
  try {
    if (
      websocketClient.isUnlinkedMode?.()
      && websocketClient.isConnectedToServer?.()
      && websocketClient.isUnlinkedSessionReady?.()
    ) {
      unlinkedModeSwitchRetryCount = 0;
      return;
    }
  } catch { }

  unlinkedModeSwitchInFlight = true;
  void Promise.resolve().then(async () => {
    try {
      await websocketClient.switchToUnlinkedMode();
      const ready = !!(
        websocketClient.isUnlinkedMode?.()
        && websocketClient.isConnectedToServer?.()
        && websocketClient.isUnlinkedSessionReady?.()
      );
      if (!ready) {
        throw new Error('Unlinked mode switch completed but session is not ready');
      }
      unlinkedModeSwitchRetryCount = 0;
    } catch (err) {
      const retryAttempt = ++unlinkedModeSwitchRetryCount;
      if (retryAttempt >= MAX_UNLINKED_SWITCH_RETRIES) {
        console.error('[AuthHandlers] Unlinked switch exhausted retries, giving up', { retryAttempt });
        unlinkedModeSwitchRetryCount = 0;
        unlinkedModeSwitchInFlight = false;
        return;
      }
      const delayMs = Math.min(MAX_UNLINKED_SWITCH_BACKOFF_MS, 1000 * Math.pow(2, Math.max(0, retryAttempt - 1)));
      console.warn('[AuthHandlers] Unlinked switch failed - scheduling retry', {
        retryAttempt,
        delayMs,
        error: err instanceof Error ? err.message : String(err)
      });
      if (unlinkedModeSwitchRetryTimer) {
        clearTimeout(unlinkedModeSwitchRetryTimer);
      }
      unlinkedModeSwitchRetryTimer = setTimeout(() => {
        unlinkedModeSwitchRetryTimer = null;
        unlinkedModeSwitchInFlight = false;
        scheduleUnlinkedModeSwitch();
      }, delayMs);
      return;
    } finally {
      if (!unlinkedModeSwitchRetryTimer) {
        unlinkedModeSwitchInFlight = false;
      }
    }
  });
};

/**
 * Handle Full Authentication Success
 */
export async function handleAuthFullSuccess(data: any, auth: AuthRefs): Promise<void> {
  const {
    setAuthStatus, loginUsernameRef, setIsLoggedIn,
    setAccountAuthenticated, setIsSubmittingAuth,
    setUsername, setMaxStepReached, setRecoveryActive,
    handleAuthSuccess
  } = auth;

  const currentUsername = loginUsernameRef?.current || '';

  // Process masked session result
  if (data.maskedResult) {
    setAuthStatus?.('Establishing secure context...');
  }

  // Handle Privacy Pass issuance
  if (data.anonymousTokenBatch) {
    await handlePrivacyPassIssuance(data.anonymousTokenBatch, auth);
  }

  try {
    const { replenishResumePool } = await import('./resume-tokens');
    await replenishResumePool();
  } catch { /* non-fatal */ }

  if (data.shardId !== undefined && data.credentialIndex !== undefined && (currentUsername || data.userId)) {
    const blindId = data.userId || (currentUsername ? computeBlindUserId(currentUsername) : null);
    if (blindId) {
      await storage.set(`shard_info_${blindId}`, JSON.stringify({
        shardId: data.shardId,
        credentialIndex: data.credentialIndex,
        shardSize: data.shardSize || OPAQUE_CONFIG.PRIVATE_AUTH_SHARD_SIZE
      }));
    }
  }

  if (data?.serverEntryRequired) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setMaxStepReached?.('login');
    setRecoveryActive?.(false);
    promptForServerEntry(auth);
    return;
  }

  websocketClient.markServerAuthGranted?.();

  // Initialize blind routing if provided
  if (data?.blindRouting) {
    await initializeAnonymousRouting(data, auth, currentUsername);
  } else if (currentUsername) {
    try {
      const blindClient = getBlindRoutingClient(currentUsername);
      const persistedCreds = await blindClient.loadPersistentCredentials();
      if (persistedCreds?.primaryInboxId && persistedCreds?.blindSignature) {
        blindClient.setSendFunction(async (message: any) => {
          await websocketClient.sendSecureControlMessage(message);
        });
        scheduleUnlinkedModeSwitch();
      }
    } catch { }
  }

  if (handleAuthSuccess) {
    await handleAuthSuccess(currentUsername, !!data.recovered);
  } else {
    setAccountAuthenticated?.(true);
    setIsLoggedIn?.(true);
    setIsSubmittingAuth?.(false);
    setAuthStatus?.('');
    setMaxStepReached?.('server');
    setRecoveryActive?.(false);
    if (currentUsername) setUsername?.(currentUsername);
  }

  websocketClient.markApplicationAuthReady?.();
  window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS));
}

/**
 * Handle Privacy Pass Token Issuance
 */
export async function handlePrivacyPassIssuance(data: any, _auth: AuthRefs): Promise<void> {
  try {
    const pendingTokens = tokenVault.getPendingTokens();
    if (pendingTokens.length === 0) return;

    const ppClient = new PrivacyPassClient();
    const { signedBlindedTokens, proof, serverPublicKey } = PrivacyPassHelpers.decodeResponse(data);

    const count = Math.min(pendingTokens.length, signedBlindedTokens.length);
    const completedTokens = await ppClient.unblindTokens(
      pendingTokens.slice(0, count),
      signedBlindedTokens.slice(0, count),
      proof,
      serverPublicKey
    );

    await tokenVault.updateTokens(completedTokens);
  } catch (err) {
    console.error('[AuthHandlers] Privacy Pass issuance failed:', err);
  }
}

/**
 * Handle ZK Refresh Challenge
 */
export async function handleZKRefreshChallenge(data: any, _auth: AuthRefs): Promise<void> {
  try {
    const { challengeId, challenge, commitments } = data;
    if (!challengeId || !challenge) return;
    const ppClient = new PrivacyPassClient();
    const { blindedTokens } = await ppClient.generateTokenBatch();

    const creds = await authApi.getDeviceCredentials();
    const deviceId = creds.device_id || 'default';
    const ringKeys = await getOrCreateRingKeyPair(deviceId);
    const ringPublicKeyBase64 = PostQuantumUtils.uint8ArrayToBase64(ringKeys.publicKey);

    const commitmentList = Array.isArray(commitments) ? commitments : [];
    const hasRingKey = commitmentList.some((c) => c?.ringPublicKey === ringPublicKeyBase64 && !c?.revoked);
    if (!hasRingKey) {
      await websocketClient.sendSecureControlMessage({
        type: SignalType.ZK_DEVICE_REGISTER,
        ringPublicKey: ringPublicKeyBase64
      });
      await websocketClient.sendSecureControlMessage({ type: SignalType.ZK_REFRESH_CHALLENGE });
      return;
    }

    const mappedCommitments = commitmentList
      .filter((c) => c && !c.revoked && typeof c.ringPublicKey === 'string')
      .map((c) => ({
        ringPublicKey: PostQuantumUtils.base64ToUint8Array(c.ringPublicKey),
        registeredAt: typeof c.registeredAt === 'number' ? c.registeredAt : 0,
        revoked: !!c.revoked,
        commitmentHash: c.commitmentHash
      }));

    const proof = await ZKDeviceProofGenerator.generateProof(
      ringKeys.secretKey,
      ringKeys.publicKey,
      mappedCommitments,
      PostQuantumUtils.base64ToUint8Array(challenge)
    );

    await websocketClient.sendSecureControlMessage({
      type: SignalType.ZK_REFRESH_RESPONSE,
      challengeId,
      proof: {
        version: proof.version,
        challenge: PostQuantumUtils.uint8ArrayToBase64(proof.challenge),
        c0: PostQuantumUtils.uint8ArrayToBase64(proof.c0),
        s: proof.s.map((resp) => PostQuantumUtils.uint8ArrayToBase64(resp)),
        keyImage: PostQuantumUtils.uint8ArrayToBase64(proof.keyImage)
      },
      blindedTokens: blindedTokens.map(t => PostQuantumUtils.uint8ArrayToBase64(t))
    });
  } catch (err) {
    console.error('[AuthHandlers] ZK Refresh failed:', err);
  }
}

/**
 * Handle Token Validation Response
 */

export async function handleTokenValidationResponse(data: any, auth: AuthRefs): Promise<void> {
  const {
    loginUsernameRef,
    setAccountAuthenticated,
    setIsLoggedIn,
    setLoginError,
    setTokenValidationInProgress,
    setUsername,
    setMaxStepReached,
    accountAuthenticated,
    isLoggedIn,
    getKeysOnDemand,
    hybridKeysRef
  } = auth;

  if (!data?.valid) {
    if (accountAuthenticated || isLoggedIn) return;

    await clearAuthTokens();
    await clearTokenEncryptionKey();
    try {
      const { clearResumePool } = await import('./resume-tokens');
      await clearResumePool();
    } catch { /* ignore */ }
    setAccountAuthenticated?.(false);
    setMaxStepReached?.('login');
    setTokenValidationInProgress?.(false);
    if (data?.error) setLoginError?.(`Session expired or invalid: ${data.message}`);
    return;
  }

  if (data?.serverEntryRequired) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setTokenValidationInProgress?.(false);
    setMaxStepReached?.('login');
    promptForServerEntry(auth);
    return;
  }

  websocketClient.markServerAuthGranted?.();

  // Get username from storage or current ref
  let username = await storage.get('last_authenticated_username');
  
  if (!username && loginUsernameRef?.current) {
    username = loginUsernameRef.current;
  }
  
  if (typeof username === 'string' && username) {
    if (loginUsernameRef) loginUsernameRef.current = username;
    setUsername?.(username);
  }

  // Try to auto-unlock vault with stored master key
  let vaultUnlocked = false;
  if (username) {
    try {
      const vaultKey = await (async () => {
        const rawVaultKey = await loadVaultKeyRaw(username);
        if (rawVaultKey && rawVaultKey.length === 32) {
          return await CryptoUtils.AES.importAesKey(rawVaultKey);
        }
        return await ensureVaultKeyCryptoKey(username);
      })();

      if (vaultKey) {
        const masterKeyBytes = await loadWrappedMasterKey(username, vaultKey);
        if (masterKeyBytes && masterKeyBytes.length === 32) {
          const masterKey = await CryptoUtils.AES.importAesKey(masterKeyBytes);
          
          if (auth.aesKeyRef) auth.aesKeyRef.current = masterKey;
          
          if (!auth.keyManagerRef?.current) {
            auth.keyManagerRef!.current = new SecureKeyManager(username);
          }
          try {
            await auth.keyManagerRef!.current!.initializeWithMasterKey(masterKeyBytes);
          } catch { }
          
          try { masterKeyBytes.fill(0); } catch { }
          
          auth.setVaultReady?.(true);
          vaultUnlocked = true;
        }
      }
    } catch (err) {
      console.warn('[Auth] Failed to auto-unlock vault:', err);
    }
  }

  if (getKeysOnDemand) {
    try {
      const keys = await getKeysOnDemand();
      if (keys && hybridKeysRef) {
        hybridKeysRef.current = keys;
        try { window.dispatchEvent(new CustomEvent(EventType.HYBRID_KEYS_UPDATED)); } catch { }
      }
    } catch { }
  }

  // Initialize blind routing
  if (username) {
    try {
      const blindClient = getBlindRoutingClient(username);
      
      if (data?.blindRouting) {
        // Server issued fresh blind routing credentials
        await initializeAnonymousRouting(data, auth, username);
      } else {
        // Fallback to saved credentials
        const persistedCreds = await blindClient.loadPersistentCredentials();
        if (persistedCreds) {
          blindClient.setSendFunction(async (message: any) => {
            await websocketClient.sendSecureControlMessage(message);
          });
          if (persistedCreds.primaryInboxId && persistedCreds.blindSignature) {
            scheduleUnlinkedModeSwitch();
          }
        }
      }
    } catch (err) {
      console.warn('[Auth] Failed to initialize blind routing:', err);
    }
  }

  setLoginError?.('');
  setAccountAuthenticated?.(true);
  setIsLoggedIn?.(true);
  setTokenValidationInProgress?.(false);
  
  if (vaultUnlocked) {
    setMaxStepReached?.('server');
    auth.setShowPassphrasePrompt?.(false);
  } else {
    setMaxStepReached?.('passphrase');
    auth.setShowPassphrasePrompt?.(true);
  }

  websocketClient.markApplicationAuthReady?.();
  window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS));
}

/**
 * Shared routing finalization
 */
async function initializeAnonymousRouting(data: any, auth: AuthRefs, recoveredUser: string): Promise<void> {
  if (!data?.blindRouting) return;

  try {
    const blindClient = getBlindRoutingClient(recoveredUser);
    const { blindCredentialRef } = auth;
    let finalCredentials = { ...data.blindRouting } as BlindRoutingCredentials;

    if (data.blindRouting.signedBlindedToken && blindCredentialRef?.current) {
      try {
        const { blindingFactor, n, modulusLength, kid } = blindCredentialRef.current;
        const signature = unblindSignature(
          data.blindRouting.signedBlindedToken,
          blindingFactor,
          n,
          modulusLength
        );
        finalCredentials.blindSignature = signature;
        finalCredentials.blindSignatureKid = data.blindRouting.blindSignatureKid || kid;
        finalCredentials.primaryInboxId = blindCredentialRef.current.inboxId || blindCredentialRef.current.message;
        finalCredentials.primaryRouteId = blindCredentialRef.current.routeId || blindCredentialRef.current.message;
        finalCredentials.blindSignatureSubject = 'route-v1';
        blindCredentialRef.current.used = true;
      } catch { }
    }

    if (!finalCredentials.primaryInboxId) {
      const existing = await blindClient.loadPersistentCredentials();
      if (existing?.primaryInboxId) {
        finalCredentials.primaryInboxId = existing.primaryInboxId;
      }
      if (!finalCredentials.blindSignature && existing?.blindSignature) {
        finalCredentials.blindSignature = existing.blindSignature;
        finalCredentials.blindSignatureKid = existing.blindSignatureKid;
      }
    }

    await blindClient.setCredentials(finalCredentials);
    blindClient.setSendFunction(async (message: any) => {
      await websocketClient.sendSecureControlMessage(message);
    });

    scheduleUnlinkedModeSwitch();
  } catch (err) {
    console.warn('[AuthHandlers] Failed to initialize blind routing:', err);
  }
}

/**
 * Handle authentication error
 */
export function handleAuthError(data: any, message: string | undefined, auth: AuthRefs): void {
  const { setLoginError, setAuthStatus, setIsSubmittingAuth, setAccountAuthenticated, setIsLoggedIn, setMaxStepReached } = auth;
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
      message: errorMessage
    }
  }));

  if (locked) {
    setAccountAuthenticated?.(false);
    setIsLoggedIn?.(false);
    setMaxStepReached?.('login');
  }
}
