/**
 * Auth Signal Handlers
 */

import { CryptoUtils, AES } from '../utils/crypto-utils';
import websocketClient from '../websocket/websocket';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';
import { syncEncryptedStorage } from '../database/encrypted-storage';
import { loadVaultKeyRaw, ensureVaultKeyCryptoKey, loadWrappedMasterKey, saveWrappedMasterKey } from '../cryptography/vault-key';
import { SecureKeyManager } from '../database/secure-key-manager';
import { AUTH_USERNAME_REGEX } from '../constants';
import type { AuthRefs } from '../types/signal-handler-types';
import { persistAuthTokens, retrieveAuthTokens, clearAuthTokens, clearTokenEncryptionKey } from './token-storage';

// Send hybrid keys update to server
async function sendHybridKeysUpdate(
  keyManagerRef: React.RefObject<any> | undefined,
  serverHybridPublic: any,
  getKeysOnDemand: (() => Promise<any>) | undefined
): Promise<void> {
  if (!keyManagerRef?.current || !serverHybridPublic) return;

  try {
    const maybeKeys = await keyManagerRef.current.getKeys().catch(() => null);
    if (!maybeKeys) {
      const pair = await CryptoUtils.Hybrid.generateHybridKeyPair();
      await keyManagerRef.current.storeKeys(pair);
    }

    const publicKeys = await keyManagerRef.current.getPublicKeys();
    if (!publicKeys) return;

    const keysToSend = {
      kyberPublicBase64: publicKeys.kyberPublicBase64 || '',
      dilithiumPublicBase64: publicKeys.dilithiumPublicBase64 || '',
      x25519PublicBase64: publicKeys.x25519PublicBase64 || ''
    };

    const payload = JSON.stringify(keysToSend);
    const keys = await getKeysOnDemand?.();
    const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(payload, serverHybridPublic, {
      senderDilithiumSecretKey: keys?.dilithium?.secretKey,
      senderDilithiumPublicKey: keys?.dilithium?.publicKey,
      metadata: { context: SignalType.HYBRID_KEYS_UPDATE }
    });

    websocketClient.send(JSON.stringify({ type: SignalType.HYBRID_KEYS_UPDATE, userData: encryptedHybridKeys }));
  } catch { }
}

// Configure Signal Storage Key for Edge API
async function configureSignalStorageKey(getKeysOnDemand: (() => Promise<any>) | undefined, hybridKeysRef: any): Promise<void> {
  if (!(window as any).edgeApi?.setSignalStorageKey) return;

  try {
    const label = new TextEncoder().encode('signal-storage-key-v1');
    const keys = await getKeysOnDemand?.();
    const kyberSecret: Uint8Array | undefined = keys?.kyber?.secretKey || hybridKeysRef?.current?.kyber?.secretKey;

    if (kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
      const derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
      if (derived) {
        const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);

        await (window as any).edgeApi.setSignalStorageKey({ keyBase64: keyB64 });
        try {
          derived.fill(0);
        } catch { }
      }
    }
  } catch { }
}

// Handle authentication success
export async function handleAuthSuccess(data: any, auth: AuthRefs): Promise<void> {
  const {
    loginUsernameRef,
    aesKeyRef,
    setAccountAuthenticated,
    setIsLoggedIn,
    setShowPassphrasePrompt,
    setIsSubmittingAuth,
    setAuthStatus,
    serverHybridPublic,
    keyManagerRef,
    setUsername,
    setMaxStepReached,
    setRecoveryActive,
    getKeysOnDemand,
    hybridKeysRef
  } = auth;

  const usernameFromServer = typeof data?.username === 'string' ? data.username.trim() : '';
  let recoveredUser = usernameFromServer;

  if (!recoveredUser) {
    let fallback = loginUsernameRef?.current;
    if (!fallback) {
      try {
        fallback = syncEncryptedStorage.getItem('last_authenticated_username') || '';
      } catch {
        fallback = '';
      }
    }

    if (typeof fallback === 'string') recoveredUser = fallback.trim();
  }

  if (recoveredUser && AUTH_USERNAME_REGEX.test(recoveredUser)) {
    if (loginUsernameRef) loginUsernameRef.current = recoveredUser;
    try {
      syncEncryptedStorage.setItem('last_authenticated_username', recoveredUser);
    } catch { }
  } else {
    recoveredUser = '';
  }

  if (data?.tokens?.accessToken && data?.tokens?.refreshToken) {
    clearTokenEncryptionKey();
    await persistAuthTokens({
      accessToken: String(data.tokens.accessToken),
      refreshToken: String(data.tokens.refreshToken)
    }).catch();

    setAccountAuthenticated?.(true);
    setIsSubmittingAuth?.(false);
    try {
      window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS));
    } catch { }
  }

  if (data?.recovered && recoveredUser) {
    let vaultKeyUnwrapSuccess = false;

    try {
      const raw = await loadVaultKeyRaw(recoveredUser);
      const vaultKey = raw?.length === 32 ? await AES.importAesKey(raw) : await ensureVaultKeyCryptoKey(recoveredUser);

      if (vaultKey) {
        const masterKeyBytes = await loadWrappedMasterKey(recoveredUser, vaultKey);
        if (masterKeyBytes?.length === 32) {
          const masterKey = await AES.importAesKey(masterKeyBytes);
          if (aesKeyRef) aesKeyRef.current = masterKey;

          if (!keyManagerRef?.current) {
            keyManagerRef!.current = new SecureKeyManager(recoveredUser);
          }

          try {
            await keyManagerRef!.current!.initializeWithMasterKey(masterKeyBytes);
            masterKeyBytes.fill(0);
          } catch { }

          await sendHybridKeysUpdate(keyManagerRef, serverHybridPublic, getKeysOnDemand);
          await configureSignalStorageKey(getKeysOnDemand, hybridKeysRef);

          setAccountAuthenticated?.(true);
          setIsLoggedIn?.(true);
          setShowPassphrasePrompt?.(false);
          setUsername?.(recoveredUser);
          setMaxStepReached?.('server');
          setRecoveryActive?.(false);
          try {
            window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS)); 
          } catch { }
          vaultKeyUnwrapSuccess = true;
        }
      }
    } catch { }

    if (vaultKeyUnwrapSuccess) return;
  }

  auth.handleAuthSuccess?.(recoveredUser || usernameFromServer || '', Boolean(data?.recovered));

  try { auth.setTokenValidationInProgress?.(false); } catch { }
  try { setAuthStatus?.(''); } catch { }
}

// Token validation response handler
export async function handleTokenValidationResponse(data: any, auth: AuthRefs): Promise<void> {
  const {
    loginUsernameRef,
    aesKeyRef,
    setAccountAuthenticated,
    setIsLoggedIn,
    setLoginError,
    setShowPassphrasePrompt,
    setAuthStatus,
    setTokenValidationInProgress,
    serverHybridPublic,
    keyManagerRef,
    setUsername,
    setMaxStepReached,
    passphrasePlaintextRef,
    getKeysOnDemand,
    accountAuthenticated,
    isLoggedIn,
    hybridKeysRef
  } = auth;

  if (!data || typeof data !== 'object') {
    console.warn('[signals] token-validation invalid-data');
    return;
  }

  if (data.valid) {
    if (typeof data.username === 'string' && data.username) {
      if (loginUsernameRef) loginUsernameRef.current = data.username;
      try { syncEncryptedStorage.setItem('last_authenticated_username', data.username); } catch { }
      setUsername?.(data.username);
    }
    try { setLoginError?.(''); } catch { }

    let vaultKey: CryptoKey | null = null;
    try {
      const raw = await loadVaultKeyRaw(loginUsernameRef?.current || data.username || '');
      vaultKey = raw?.length === 32 ? await AES.importAesKey(raw) : loginUsernameRef?.current ? await ensureVaultKeyCryptoKey(loginUsernameRef.current) : null;
    } catch { }

    let masterKeyBytes: Uint8Array | null = null;
    if (vaultKey && loginUsernameRef?.current) {
      try {
        masterKeyBytes = await loadWrappedMasterKey(loginUsernameRef.current, vaultKey); 
      } catch { }
    }

    if (masterKeyBytes?.length === 32) {
      try {
        const masterKey = await AES.importAesKey(masterKeyBytes);
        if (aesKeyRef) aesKeyRef.current = masterKey;

        if (!keyManagerRef?.current) {
          keyManagerRef!.current = new SecureKeyManager(loginUsernameRef!.current);
        }

        try { await keyManagerRef!.current!.initializeWithMasterKey(masterKeyBytes); } catch { }
        try {
          if (!await keyManagerRef!.current!.getKeys().catch(() => null)) {
            const pair = await CryptoUtils.Hybrid.generateHybridKeyPair();
            await keyManagerRef!.current!.storeKeys(pair);
          }
        } catch { }
      } finally {
        try { masterKeyBytes.fill(0); } catch { }
      }
    } else {
      try { setShowPassphrasePrompt?.(true); setAuthStatus?.('Passphrase required to unlock local keys'); } catch { }
    }

    await sendHybridKeysUpdate(keyManagerRef, serverHybridPublic, getKeysOnDemand);

    // Configure Signal storage key
    if (loginUsernameRef?.current && (window as any).edgeApi?.setSignalStorageKey) {
      try {
        const label = new TextEncoder().encode('signal-storage-key-v1');
        let derived: Uint8Array | null = null;

        const keys = await getKeysOnDemand?.();
        const kyberSecret = keys?.kyber?.secretKey || hybridKeysRef?.current?.kyber?.secretKey;

        if (kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
          derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
        } else if (passphrasePlaintextRef?.current) {
          derived = await (CryptoUtils as any).KDF.argon2id(passphrasePlaintextRef.current, {
            salt: label,
            time: 3,
            memoryCost: 1 << 17,
            parallelism: 2,
            hashLen: 32
          });
        }

        if (derived) {
          const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);

          try {
            await (window as any).edgeApi.setSignalStorageKey({ keyBase64: keyB64 });
          } catch { }

          try {
            const existing = await (window as any).edgeApi.getPreKeyBundle?.({ username: loginUsernameRef.current });

            if (!existing?.identityKeyBase64) {
              try { await (window as any).edgeApi.generateIdentity?.({ username: loginUsernameRef.current }); } catch { }
              try { await (window as any).edgeApi.generatePreKeys?.({ username: loginUsernameRef.current, startId: 1, count: 100 }); } catch { }
            }

            try { await (window as any).edgeApi.trustPeerIdentity?.({ selfUsername: loginUsernameRef.current, peerUsername: loginUsernameRef.current, deviceId: 1 }); } catch { }

            const bundle = await (window as any).edgeApi.getPreKeyBundle?.({ username: loginUsernameRef.current });

            if (bundle && !bundle.error) {
              await websocketClient.sendSecureControlMessage({ type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE, bundle });
            }
          } catch { }

          try { derived.fill(0); } catch { }
        }
      } catch { }
    }

    setAccountAuthenticated?.(true);
    try { window.dispatchEvent(new CustomEvent(EventType.SECURE_CHAT_AUTH_SUCCESS)); } catch { }
    setIsLoggedIn?.(true);
    setMaxStepReached?.('passphrase');
    try { setTokenValidationInProgress?.(false); } catch { }

    if (data.tokens?.accessToken && data.tokens.refreshToken) {
      clearTokenEncryptionKey();
      await persistAuthTokens({
        accessToken: data.tokens.accessToken,
        refreshToken: data.tokens.refreshToken
      }).catch(() => {});
    }
  } else {
    if (accountAuthenticated || isLoggedIn) return;

    try {
      setTokenValidationInProgress?.(true);
      setAuthStatus?.('Refreshing session...');

      const tokens = await retrieveAuthTokens();
      if (tokens?.refreshToken && (window as any).edgeApi?.refreshTokens) {
        const res = await (window as any).edgeApi.refreshTokens({ refreshToken: tokens.refreshToken });

        if (res?.success && res.tokens?.accessToken && res.tokens?.refreshToken) {
          await persistAuthTokens({ accessToken: res.tokens.accessToken, refreshToken: res.tokens.refreshToken });

          try { await websocketClient.attemptTokenValidationOnce?.('refresh'); } catch { }
          setAuthStatus?.('');
          setTokenValidationInProgress?.(false);

          return;
        }
      }
    } catch (e) {
      console.error('[auth] refresh failed', (e as Error)?.message || String(e));
    } finally {
      try {
        setAuthStatus?.('');
        setTokenValidationInProgress?.(false);
      } catch { }
    }

    await clearAuthTokens();
    clearTokenEncryptionKey();
    setAccountAuthenticated?.(false);
    setMaxStepReached?.('login');
    setShowPassphrasePrompt?.(false);

    try { setTokenValidationInProgress?.(false); } catch { }
    if (data.error) setLoginError?.(`Token validation failed: ${data.message}`);
  }
}

// Handle in-account response
export async function handleInAccount(data: any, auth: AuthRefs): Promise<void> {
  const { loginUsernameRef, setAccountAuthenticated, setShowPassphrasePrompt, setAuthStatus, setLoginError, passwordRef, setIsSubmittingAuth } = auth;

  setAccountAuthenticated?.(true);
  setShowPassphrasePrompt?.(false);
  setAuthStatus?.('Account authentication successful. Enter server password.');
  setLoginError?.('');

  if (passwordRef) passwordRef.current = '';

  const userCandidate = typeof data?.username === 'string' ? data.username.trim() : loginUsernameRef?.current;
  
  if (userCandidate) {
    if (loginUsernameRef) loginUsernameRef.current = userCandidate;
    try { syncEncryptedStorage.setItem('last_authenticated_username', userCandidate); } catch { }
  }

  if (data?.tokens?.accessToken && data.tokens.refreshToken) {
    clearTokenEncryptionKey();
    await persistAuthTokens({
      accessToken: data.tokens.accessToken,
      refreshToken: data.tokens.refreshToken
    }).catch(() => {});
  }
  setIsSubmittingAuth?.(false);
}

// Handle passphrase hash response
export function handlePassphraseHash(data: any, auth: AuthRefs): void {
  const {
    setPassphraseHashParams,
    setShowPassphrasePrompt,
    setAuthStatus,
    setLoginError,
    setIsSubmittingAuth,
    isRegistrationMode,
    accountAuthenticated,
    setRecoveryActive
  } = auth;

  const requiredFields = ['version', 'algorithm', 'salt', 'memoryCost', 'timeCost', 'parallelism'];
  const hasAllFields = requiredFields.every((f) => f in (data ?? {}));

  if (hasAllFields) {
    setPassphraseHashParams?.({
      version: data.version,
      algorithm: data.algorithm,
      salt: data.salt,
      memoryCost: data.memoryCost,
      timeCost: data.timeCost,
      parallelism: data.parallelism,
      message: data.message ?? ''
    });

    if (data.recovered && !isRegistrationMode && !accountAuthenticated) {
      setRecoveryActive?.(true);
    }
  } else {
    console.error('[Signals] PASSPHRASE_HASH missing required fields', {
      receivedKeys: Object.keys(data || {}),
      missing: requiredFields.filter((f) => !(f in (data ?? {})))
    });
    setPassphraseHashParams?.(null);
  }

  setShowPassphrasePrompt?.(true);
  setAuthStatus?.('Please enter your passphrase to continue...');
  setLoginError?.('');
  setIsSubmittingAuth?.(false);
}

// Handle password hash params response
export function handlePasswordHashParams(data: any, auth: AuthRefs): void {
  const {
    setIsSubmittingAuth,
    setAuthStatus,
    setAccountAuthenticated,
    setIsLoggedIn,
    setShowPassphrasePrompt,
    setMaxStepReached
  } = auth;
  try {
    window.dispatchEvent(new CustomEvent(EventType.PASSWORD_HASH_PARAMS, {
      detail: {
        salt: data.salt,
        timeCost: data.timeCost,
        memoryCost: data.memoryCost,
        parallelism: data.parallelism,
        algorithm: data.algorithm,
        version: data.version
      }
    }));
  } catch (_error) {
    try {
      setIsSubmittingAuth?.(false);
      setAuthStatus?.('');
      setMaxStepReached?.('login'); 
      setAccountAuthenticated?.(false); 
      setIsLoggedIn?.(false); 
      setShowPassphrasePrompt?.(false); 
    } catch { }
  }
}

// Handle passphrase success
export async function handlePassphraseSuccess(auth: AuthRefs): Promise<void> {
  const {
    loginUsernameRef,
    aesKeyRef,
    setShowPassphrasePrompt,
    setRecoveryActive,
    setAccountAuthenticated
  } = auth;
  try {
    const user = loginUsernameRef?.current || '';
    if (user && aesKeyRef?.current) {
      const vaultKey = await ensureVaultKeyCryptoKey(user);
      const raw = new Uint8Array(await (globalThis as any).crypto?.subtle?.exportKey('raw', aesKeyRef.current));

      await saveWrappedMasterKey(user, raw, vaultKey);
      raw.fill(0);
    }
  } catch (_error) { 
    console.error('[signals] passphrase-success derive-key-failed', (_error as Error).message); 
  }

  setShowPassphrasePrompt?.(false);
  setRecoveryActive?.(false);
  setAccountAuthenticated?.(true);
}

// Handle authentication error
export function handleAuthError(data: any, message: string | undefined, auth: AuthRefs): void {
  const { setLoginError, setAuthStatus, setIsSubmittingAuth, setAccountAuthenticated, setIsLoggedIn, setShowPassphrasePrompt, setMaxStepReached } = auth;
  const attemptsRemaining = typeof data?.attemptsRemaining === 'number' ? data.attemptsRemaining : undefined;
  const locked = Boolean(data?.locked);
  const cooldownSeconds = typeof data?.cooldownSeconds === 'number' ? data.cooldownSeconds : undefined;
  const category = typeof data?.category === 'string' ? data.category : undefined;

  let errorMessage = message ?? 'Authentication failed';
  if (locked && cooldownSeconds) {
    errorMessage = `Too many attempts. Try again in ${cooldownSeconds}s.`;
    try { websocketClient.setGlobalRateLimit?.(cooldownSeconds); } catch { }
    try { setAccountAuthenticated?.(false); setIsLoggedIn?.(false); setShowPassphrasePrompt?.(false); setMaxStepReached?.('login'); } catch { }
  } else if (typeof attemptsRemaining === 'number' && !locked) {
    errorMessage += ` (${attemptsRemaining} attempt${attemptsRemaining === 1 ? '' : 's'} remaining)`;
  }

  setLoginError?.(errorMessage);
  try { setAuthStatus?.(''); } catch { }
  try { setIsSubmittingAuth?.(false); } catch { }
  try { window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, { detail: { category, code: (data as any)?.code } })); } catch { }

  if (category === 'passphrase' && !locked) {
    setAccountAuthenticated?.(false); setIsLoggedIn?.(false); setShowPassphrasePrompt?.(false); setMaxStepReached?.('login');
  }
}

// Handle login errors
export function handleLoginErrors(type: string, message: string | undefined, auth: AuthRefs): void {
  auth.setLoginError?.(`Login error: ${message ?? type}`);
  try { auth.setAuthStatus?.(''); } catch { }
  try { auth.setIsSubmittingAuth?.(false); } catch { }
}

// Handle connection restored
export function handleConnectionRestored(data: any, auth: AuthRefs): void {
  if (data?.hasAuthenticated) { auth.setIsLoggedIn?.(true); auth.setAccountAuthenticated?.(true); }
}
