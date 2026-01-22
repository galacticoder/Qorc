import { useState, useRef, useCallback, useEffect } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import { retrieveAuthTokens } from "../../lib/signals/signals";
import websocketClient from "../../lib/websocket/websocket";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { SecureDB } from "../../lib/database/secureDB";
import { SecureKeyManager } from "../../lib/database/secure-key-manager";
import { encryptedStorage } from "../../lib/database/encrypted-storage";
import { secureWipeStringRef, PinnedServer } from "../../lib/utils/auth-utils";
import type { ServerHybridPublicKeys, HybridKeys, ServerTrustRequest, HashParams, MaxStepReached } from "../../lib/types/auth-types";
import { createDeriveEffectivePassphrase, createGetKeysOnDemand, createWaitForServerKeys, createInitializeKeys } from "./keyManagement";
import { createHandleAccountSubmit, createHandleServerPasswordSubmit } from "./handlers";
import { createHandlePassphraseSubmit } from "./passphrase";
import { createHandleAuthSuccess } from "./authSuccess";
import { createAttemptAuthRecovery, createStoreAuthenticationState, createClearAuthenticationState, createStoreUsernameMapping } from "./recovery";
import { createLogout, createGetLogout } from "./logout";
import { signal, storage } from "../../lib/tauri-bindings";

export const useAuth = (_secureDB?: SecureDB) => {
  const [username, setUsername] = useState("");
  const [pseudonym, setPseudonym] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [authStatus, setAuthStatus] = useState<string>("");
  const [loginError, setLoginError] = useState("");
  const [isSubmittingAuth, setIsSubmittingAuth] = useState(false);
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const [isRegistrationMode, setIsRegistrationMode] = useState(false);
  const [tokenValidationInProgress, setTokenValidationInProgress] = useState(false);

  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);
  const getKeysPromiseRef = useRef<Promise<any> | null>(null);
  const passphraseLimiterRef = useRef<{ tokens: number; last: number }>({ tokens: 5, last: Date.now() });

  const [serverHybridPublic, setServerHybridPublic] = useState<ServerHybridPublicKeys | null>(null);
  const serverHybridPublicRef = useRef<ServerHybridPublicKeys | null>(null);

  useEffect(() => {
    serverHybridPublicRef.current = serverHybridPublic;
  }, [serverHybridPublic]);

  useEffect(() => {
    let countdownInterval: NodeJS.Timeout | null = null;

    const onAuthError = () => {
      setIsSubmittingAuth(false);
      setTokenValidationInProgress(false);
      setAuthStatus('');
    };

    const onAuthRateLimited = (event: any) => {
      setIsSubmittingAuth(false);
      setTokenValidationInProgress(false);
      setAuthStatus('');
      setIsGeneratingKeys(false);

      const rateLimitUntil = event.detail?.rateLimitUntil;
      if (rateLimitUntil) {
        if (countdownInterval) {
          clearInterval(countdownInterval);
        }

        const updateCountdown = () => {
          const remaining = Math.max(0, Math.ceil((rateLimitUntil - Date.now()) / 1000));
          if (remaining > 0) {
            setLoginError(`Too many attempts. Try again in ${remaining}s.`);
            setTimeout(updateCountdown, 1000 - (Date.now() % 1000));
          } else {
            setLoginError('');
            if (countdownInterval) {
              clearInterval(countdownInterval);
              countdownInterval = null;
            }
          }
        };

        updateCountdown();
      }
    };

    try { window.addEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
    try { window.addEventListener(EventType.AUTH_RATE_LIMITED, onAuthRateLimited as any); } catch { }

    return () => {
      if (countdownInterval) {
        clearInterval(countdownInterval);
      }
      try { window.removeEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
      try { window.removeEventListener(EventType.AUTH_RATE_LIMITED, onAuthRateLimited as any); } catch { }
    };
  }, []);

  const [serverTrustRequest, setServerTrustRequest] = useState<ServerTrustRequest | null>(null);

  const acceptServerTrust = useCallback(() => {
    if (!serverTrustRequest) return;
    const { newKeys } = serverTrustRequest;
    try { PinnedServer.set(newKeys); } catch { }
    setServerHybridPublic(newKeys);
    setServerTrustRequest(null);
    setLoginError("");
  }, [serverTrustRequest]);

  const rejectServerTrust = useCallback(() => {
    setServerTrustRequest(null);
    setLoginError("Server key changed. Trust not granted.");
  }, []);

  const hybridKeysRef = useRef<HybridKeys | null>(null);
  const keyManagerRef = useRef<SecureKeyManager | null>(null);
  const keyManagerOwnerRef = useRef<string>("");
  const loginUsernameRef = useRef("");
  const originalUsernameRef = useRef<string>("");
  const passwordRef = useRef<string>("");
  const confirmPasswordRef = useRef<string>("");
  const passphraseConfirmRef = useRef<string>("");
  const lastPasswordParamsForRef = useRef<string>("");

  const [passphraseHashParams, setPassphraseHashParams] = useState<HashParams>(null);
  const [passwordHashParams, setPasswordHashParams] = useState<HashParams>(null);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [maxStepReached, setMaxStepReached] = useState<MaxStepReached>('login');
  const [recoveryActive, setRecoveryActive] = useState(false);

  // Create refs object for key management
  const keyManagementRefs = {
    loginUsernameRef,
    passwordRef,
    confirmPasswordRef,
    passphrasePlaintextRef,
    passphraseRef,
    aesKeyRef,
    hybridKeysRef,
    keyManagerRef,
    keyManagerOwnerRef,
    getKeysPromiseRef,
    serverHybridPublicRef,
  };

  const keyManagementSetters = {
    setIsGeneratingKeys,
    setAuthStatus: setAuthStatus as (v: string | ((prev: string) => string)) => void,
    setLoginError,
    setShowPassphrasePrompt,
  };

  // Create helper functions
  const deriveEffectivePassphrase = createDeriveEffectivePassphrase(keyManagementRefs);
  const getKeysOnDemand = useCallback(createGetKeysOnDemand(keyManagementRefs, deriveEffectivePassphrase), []);
  const waitForServerKeys = useCallback(createWaitForServerKeys(keyManagementRefs, keyManagementSetters), [setAuthStatus]);
  const initializeKeys = useCallback(createInitializeKeys(keyManagementRefs, keyManagementSetters, deriveEffectivePassphrase, recoveryActive), [recoveryActive]);

  // Recovery helpers
  const storeAuthenticationState = useCallback(createStoreAuthenticationState(), []);
  const clearAuthenticationState = useCallback(createClearAuthenticationState(), []);
  const storeUsernameMapping = useCallback(createStoreUsernameMapping({ loginUsernameRef, originalUsernameRef }), []);

  const attemptAuthRecovery = useCallback(
    createAttemptAuthRecovery(
      { loginUsernameRef, originalUsernameRef },
      { setUsername, setPseudonym, setAuthStatus, setTokenValidationInProgress },
      accountAuthenticated,
      isLoggedIn
    ),
    [accountAuthenticated, isLoggedIn]
  );

  // Clear secure DB helper
  const clearSecureDBForUser = async (pseudonym: string) => {
    try {
      const { SQLiteKV } = await import('../../lib/database/sqlite-kv');
      await (SQLiteKV as any).purgeUserDb(pseudonym);
    } catch { }
  };

  // Handler refs and setters
  const authRefs = {
    loginUsernameRef,
    originalUsernameRef,
    passwordRef,
    confirmPasswordRef,
    passphraseRef,
    passphrasePlaintextRef,
    hybridKeysRef,
    keyManagerRef,
    keyManagerOwnerRef,
    passphraseLimiterRef,
  };

  const authSetters = {
    setUsername,
    setPseudonym,
    setIsLoggedIn,
    setIsGeneratingKeys,
    setAuthStatus,
    setLoginError,
    setIsSubmittingAuth,
    setAccountAuthenticated,
    setIsRegistrationMode,
    setShowPassphrasePrompt,
    setRecoveryActive,
    setMaxStepReached,
  };

  const authState = {
    isLoggedIn,
    accountAuthenticated,
    recoveryActive,
    passphraseHashParams,
    serverHybridPublic,
    isSubmittingAuth,
  };

  // Create handlers
  const handleAccountSubmit = createHandleAccountSubmit(
    authRefs,
    authSetters,
    authState,
    { waitForServerKeys, initializeKeys, getKeysOnDemand, storeAuthenticationState, clearSecureDBForUser }
  );

  const handleServerPasswordSubmit = createHandleServerPasswordSubmit(
    authSetters,
    { waitForServerKeys, getKeysOnDemand }
  );

  const handlePassphraseSubmit = createHandlePassphraseSubmit(
    { loginUsernameRef, passphrasePlaintextRef, passphraseRef, passwordRef, passphraseLimiterRef, keyManagerRef },
    { setAuthStatus, setLoginError, setShowPassphrasePrompt, setRecoveryActive, setAccountAuthenticated, setIsLoggedIn, setMaxStepReached },
    { isLoggedIn, accountAuthenticated, recoveryActive, passphraseHashParams, serverHybridPublic },
    { initializeKeys, deriveEffectivePassphrase, getKeysOnDemand }
  );

  const handleAuthSuccess = createHandleAuthSuccess(
    { loginUsernameRef, originalUsernameRef, passphrasePlaintextRef, keyManagerRef },
    { setAuthStatus, setUsername, setPseudonym, setIsLoggedIn, setAccountAuthenticated, setRecoveryActive, setShowPassphrasePrompt, setIsRegistrationMode, setLoginError },
    { storeAuthenticationState, deriveEffectivePassphrase, getKeysOnDemand }
  );

  // Logout
  const logout = createLogout(
    { loginUsernameRef, passwordRef, passphraseRef, passphrasePlaintextRef, aesKeyRef, hybridKeysRef, keyManagerRef },
    { setIsLoggedIn, setLoginError, setAccountAuthenticated, setIsRegistrationMode, setIsSubmittingAuth, setUsername },
    clearAuthenticationState
  );

  const getLogout = createGetLogout(logout);

  // Effects
  useEffect(() => {
    if (showPassphrasePrompt) setMaxStepReached(prev => prev === 'server' ? 'server' : 'passphrase');
  }, [showPassphrasePrompt]);

  useEffect(() => {
    if (accountAuthenticated) setMaxStepReached('server');
  }, [accountAuthenticated]);

  useEffect(() => {
    const handleAuthUiBack = (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'login' | 'passphrase' | 'server' | undefined;
        setLoginError("");
        setAuthStatus("");
        if (to === 'login') {
          setShowPassphrasePrompt(false);
          setRecoveryActive(false);
          setAccountAuthenticated(false);
        } else if (to === 'passphrase') {
          setShowPassphrasePrompt(true);
        } else if (to === 'server') {
          setShowPassphrasePrompt(false);
          setRecoveryActive(false);
          setAccountAuthenticated(false);
          setIsLoggedIn(false);
          setMaxStepReached('login');
          secureWipeStringRef(passwordRef as any);
          secureWipeStringRef(passphraseRef as any);
          secureWipeStringRef(passphrasePlaintextRef as any);
          loginUsernameRef.current = "";
          originalUsernameRef.current = "";
          setUsername("");
          setPassphraseHashParams(null);
          setServerTrustRequest?.(null);
        }
      } catch { }
    };

    window.addEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
  }, []);

  useEffect(() => {
    const handleAuthUiInput = (event: CustomEvent) => {
      try {
        const { field, value } = (event as any).detail || {};
        if (typeof value !== 'string') return;
        switch (field) {
          case 'username': setTypedUsername(value); break;
          case 'password': setTypedPassword(value); break;
          case 'confirmPassword': setTypedConfirmPassword(value); break;
          case 'passphrase': setTypedPassphrase(value); break;
          case 'passphraseConfirm': passphraseConfirmRef.current = value; break;
        }
      } catch { }
    };
    window.addEventListener(EventType.AUTH_UI_INPUT, handleAuthUiInput as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_INPUT, handleAuthUiInput as EventListener);
  }, []);

  useEffect(() => {
    const handleAuthUiForward = async (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'login' | 'passphrase' | 'server_password' | undefined;
        setLoginError("");
        setAuthStatus("");

        if (to === 'passphrase') {
          setShowPassphrasePrompt(true);
          return;
        }
        if (to === 'server_password') {
          setShowPassphrasePrompt(false);
          return;
        }

        if (to === 'login' || (!showPassphrasePrompt && !accountAuthenticated)) {
          const orig = originalUsernameRef.current;
          const pwd = passwordRef.current;
          if (orig && pwd) {
            await handleAccountSubmit(isRegistrationMode ? 'register' : 'login', orig, pwd);
            return;
          }
        }

        if (showPassphrasePrompt) {
          setShowPassphrasePrompt(true);
          return;
        }

        if (accountAuthenticated) return;
      } catch { }
    };

    window.addEventListener(EventType.AUTH_UI_FORWARD, handleAuthUiForward as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_FORWARD, handleAuthUiForward as EventListener);
  }, [accountAuthenticated, showPassphrasePrompt, isRegistrationMode]);

  useEffect(() => {
    const handleBeforeUnload = () => {
      if (isLoggedIn && loginUsernameRef.current) {
        try {
          (async () => {
            try {
              const queueRaw = await encryptedStorage.getItem('cleanup_queue_pending');
              let queue: Array<{ username: string; timestamp: number }> = [];
              if (queueRaw && Array.isArray(queueRaw)) {
                queue = queueRaw;
              }
              queue.push({ username: loginUsernameRef.current, timestamp: Date.now() });
              await encryptedStorage.setItem('cleanup_queue_pending', queue.slice(-10));
            } catch { }
          })();
        } catch { }
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isLoggedIn]);

  useEffect(() => {
    const handleReconnection = async () => {
      if (isLoggedIn && loginUsernameRef.current) {
        try {
          await attemptAuthRecovery();
        } catch { }
      }
    };

    window.addEventListener(EventType.WS_RECONNECTED, handleReconnection);
    return () => window.removeEventListener(EventType.WS_RECONNECTED, handleReconnection);
  }, [isLoggedIn, attemptAuthRecovery]);

  useEffect(() => {
    (async () => {
      try {
        if (isLoggedIn && loginUsernameRef.current) {
          const keys = await getKeysOnDemand?.();
          const pub = keys?.kyber?.publicKeyBase64;
          const secB64 = keys?.kyber?.secretKey ? CryptoUtils.Base64.arrayBufferToBase64(keys.kyber.secretKey) : undefined;
          if (typeof pub === 'string' && typeof secB64 === 'string' && pub && secB64) {
            await signal.setStaticMlkemKeys(loginUsernameRef.current, pub, secB64);
          }
        }
      } catch { }
    })();
  }, [isLoggedIn, loginUsernameRef.current]);

  useEffect(() => {
    if (!isLoggedIn || !serverHybridPublic || !hybridKeysRef.current) return;

    const uploadKeys = async () => {
      try {
        let attempts = 0;
        while (attempts < 20 && !websocketClient.isPQSessionEstablished?.()) {
          await new Promise(resolve => setTimeout(resolve, 100));
          attempts++;
        }

        if (!websocketClient.isPQSessionEstablished?.()) {
          return;
        }

        const keys = hybridKeysRef.current;
        if (!keys?.dilithium?.publicKeyBase64 || !keys?.kyber?.publicKeyBase64 || !keys?.dilithium?.secretKey) {
          return;
        }

        const keysToSend = {
          kyberPublicBase64: keys.kyber.publicKeyBase64,
          dilithiumPublicBase64: keys.dilithium.publicKeyBase64,
          x25519PublicBase64: keys.x25519?.publicKeyBase64 || ''
        };

        const hybridKeysPayload = JSON.stringify(keysToSend);

        const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(
          hybridKeysPayload,
          serverHybridPublic,
          {
            senderDilithiumSecretKey: keys.dilithium.secretKey,
            metadata: {
              context: SignalType.HYBRID_KEYS_UPDATE,
              sender: { dilithiumPublicKey: keys.dilithium.publicKeyBase64 }
            }
          }
        );

        await websocketClient.sendSecureControlMessage({
          type: SignalType.HYBRID_KEYS_UPDATE,
          userData: encryptedHybridKeys,
        });

        try {
          window.dispatchEvent(new CustomEvent(EventType.HYBRID_KEYS_UPDATED));
        } catch { }
      } catch { }
    };

    uploadKeys();
  }, [isLoggedIn, serverHybridPublic, hybridKeysRef.current]);

  useEffect(() => {
    (async () => {
      try {
        const tokens = await retrieveAuthTokens();
        const storedUsername = await storage.get('last_authenticated_username');
        const storedDisplayName = await storage.get('last_authenticated_display_name');

        if ((tokens?.accessToken && tokens?.refreshToken) || storedUsername) {
          setTokenValidationInProgress(true);
          setAuthStatus('Verifying session...');

          if (storedUsername) {
            loginUsernameRef.current = storedUsername;
            const displayName = storedDisplayName || storedUsername;
            setUsername(displayName);
            originalUsernameRef.current = displayName;

          }
        } else {
          setTokenValidationInProgress(false);
          setAuthStatus('');
        }
      } catch (err) {
        console.error('[useAuth] Session restoration failed:', err);
        setTokenValidationInProgress(false);
        setAuthStatus('');
      }
    })();
  }, []);

  useEffect(() => {
    const onTokenValidationStart = (_ev: Event) => {
      try {
        setTokenValidationInProgress(true);
        setAuthStatus('Verifying session...');
      } catch { }
    };
    window.addEventListener(EventType.TOKEN_VALIDATION_START, onTokenValidationStart as EventListener);
    return () => window.removeEventListener(EventType.TOKEN_VALIDATION_START, onTokenValidationStart as EventListener);
  }, []);

  useEffect(() => {
    let timeout: NodeJS.Timeout;
    if (tokenValidationInProgress) {
      timeout = setTimeout(() => {
        setTokenValidationInProgress(false);
        setAuthStatus('');
      }, 10000);
    }
    return () => clearTimeout(timeout);
  }, [tokenValidationInProgress]);

  useEffect(() => {
    const onTokenValidationTimeout = (_ev: Event) => {
      try {
        setTokenValidationInProgress(false);
        setAuthStatus('');
        setLoginError('Session validation timed out. Please log in again.');
      } catch { }
    };
    window.addEventListener(EventType.TOKEN_VALIDATION_TIMEOUT, onTokenValidationTimeout as EventListener);
    return () => window.removeEventListener(EventType.TOKEN_VALIDATION_TIMEOUT, onTokenValidationTimeout as EventListener);
  }, []);

  useEffect(() => {
    const handlePasswordHashParams = (event: CustomEvent) => {
      const params = event.detail;
      if (!params || !params.salt || !params.memoryCost || !params.timeCost || !params.parallelism) {
        setLoginError("Server sent invalid password hash parameters");
        return;
      }

      setPasswordHashParams(params);

      try { lastPasswordParamsForRef.current = loginUsernameRef.current || ''; } catch { }

      const existingPassword = passwordRef.current || "";
      if (existingPassword) {
        (async () => {
          try {
            setAuthStatus("Computing hash...");
            const passwordHash = await CryptoUtils.Hash.hashDataUsingInfo(existingPassword, params);
            websocketClient.send(JSON.stringify({
              type: SignalType.PASSWORD_HASH_RESPONSE,
              passwordHash
            }));
            setShowPasswordPrompt(false);
            setAuthStatus("Verifying...");
          } catch {
            setShowPasswordPrompt(true);
            setAuthStatus("Password required");
          }
        })();
      } else {
        setShowPasswordPrompt(true);
        setAuthStatus("Password required");
      }
    };

    window.addEventListener(EventType.PASSWORD_HASH_PARAMS, handlePasswordHashParams as EventListener);
    return () => window.removeEventListener(EventType.PASSWORD_HASH_PARAMS, handlePasswordHashParams as EventListener);
  }, []);

  const setTypedUsername = (name: string) => { originalUsernameRef.current = name; };
  const setTypedPassword = (pwd: string) => { passwordRef.current = pwd; };
  const setTypedConfirmPassword = (pwd: string) => { confirmPasswordRef.current = pwd; };
  const setTypedPassphrase = (pp: string) => { passphrasePlaintextRef.current = pp; };

  useEffect(() => {
    try {
      const pinned = PinnedServer.get();
      if (pinned) {
        setServerHybridPublic(pinned);
      } else {
        setServerHybridPublic(null);
      }
    } catch {
      setServerHybridPublic(null);
    }
  }, []);

  return {
    username,
    setUsername,
    pseudonym,
    setPseudonym,
    tokenValidationInProgress,
    setTokenValidationInProgress,
    serverHybridPublic,
    setServerHybridPublic,
    serverTrustRequest,
    setServerTrustRequest,
    acceptServerTrust,
    rejectServerTrust,
    isLoggedIn,
    setIsLoggedIn,
    isGeneratingKeys,
    isSubmittingAuth,
    authStatus,
    setAuthStatus,
    loginError,
    accountAuthenticated,
    isRegistrationMode,
    setIsRegistrationMode,
    loginUsernameRef,
    originalUsernameRef,
    storeUsernameMapping,
    initializeKeys,
    handleAccountSubmit,
    handlePassphraseSubmit,
    handleServerPasswordSubmit,
    handleAuthSuccess,
    setAccountAuthenticated,
    passwordRef,
    setLoginError,
    passphraseHashParams,
    setPassphraseHashParams,
    passwordHashParams,
    setPasswordHashParams,
    passphrasePlaintextRef,
    passphraseRef,
    aesKeyRef,
    setShowPassphrasePrompt,
    showPassphrasePrompt,
    setShowPasswordPrompt,
    showPasswordPrompt,
    setMaxStepReached,
    handlePasswordHashSubmit: async (password: string) => {
      try {
        if (!passwordHashParams) throw new Error('Missing password params');
        const passwordHash = await CryptoUtils.Hash.hashDataUsingInfo(password, passwordHashParams);
        websocketClient.send(JSON.stringify({ type: SignalType.PASSWORD_HASH_RESPONSE, passwordHash }));
      } catch {
        setLoginError('Password processing failed');
      }
    },
    logout,
    getLogout,
    hybridKeysRef,
    keyManagerRef,
    getKeysOnDemand,
    attemptAuthRecovery,
    storeAuthenticationState,
    clearAuthenticationState,
    recoveryActive,
    setRecoveryActive,
    setTypedUsername,
    setTypedPassword,
    setTypedConfirmPassword,
    setTypedPassphrase,
    confirmPasswordRef,
    maxStepReached,
  };
};
