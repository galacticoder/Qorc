import { useState, useRef, useCallback, useEffect } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import { retrieveAuthTokens } from "../../lib/signals/signals";
import websocketClient from "../../lib/websocket/websocket";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { SecureDB } from "../../lib/database/secureDB";
import { SecureKeyManager } from "../../lib/database/secure-key-manager";
import { encryptedStorage } from "../../lib/database/encrypted-storage";
import { secureWipeStringRef, PinnedServer, generateBlindCredential } from "../../lib/utils/auth-utils";
import type { ServerHybridPublicKeys, HybridKeys, ServerTrustRequest, MaxStepReached } from "../../lib/types/auth-types";
import { createDeriveEffectivePassphrase, createGetKeysOnDemand, createWaitForServerKeys, createInitializeKeys } from "./keyManagement";
import { createHandleAccountSubmit } from "./handlers";
import { createHandleAuthSuccess } from "./authSuccess";
import { createAttemptAuthRecovery, createStoreAuthenticationState, createClearAuthenticationState } from "./recovery";
import { createLogout, createGetLogout } from "./logout";
import { signal, storage } from "../../lib/tauri-bindings";
import { toast } from "sonner";

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
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const [maxStepReached, setMaxStepReached] = useState<MaxStepReached>('login');
  const [recoveryActive, setRecoveryActive] = useState(false);
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [vaultReady, setVaultReady] = useState(false);

  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);
  const getKeysPromiseRef = useRef<Promise<any> | null>(null);
  const passphraseLimiterRef = useRef<{ tokens: number; last: number }>({ tokens: 5, last: Date.now() });
  const blindCredentialRef = useRef<{
    message: string;
    blindedMsg: string;
    blindingFactor: string;
    n: string;
    kid: string;
    modulusLength: number;
    hash: string;
    saltLength: number;
    scheme: string;
    used?: boolean;
  } | null>(null);

  const [serverHybridPublic, setServerHybridPublic] = useState<ServerHybridPublicKeys | null>(null);
  const serverHybridPublicRef = useRef<ServerHybridPublicKeys | null>(null);

  useEffect(() => {
    serverHybridPublicRef.current = serverHybridPublic;
  }, [serverHybridPublic]);

  useEffect(() => {
    let countdownInterval: NodeJS.Timeout | null = null;
    const onAuthError = () => { setIsSubmittingAuth(false); setTokenValidationInProgress(false); setAuthStatus(''); };
    const onAuthRateLimited = (event: any) => {
      setIsSubmittingAuth(false); setTokenValidationInProgress(false); setAuthStatus(''); setIsGeneratingKeys(false);
      const rateLimitUntil = event.detail?.rateLimitUntil;
      if (rateLimitUntil) {
        if (countdownInterval) clearInterval(countdownInterval);
        const updateCountdown = () => {
          const remaining = Math.max(0, Math.ceil((rateLimitUntil - Date.now()) / 1000));
          if (remaining > 0) {
            setLoginError(`Too many attempts. Try again in ${remaining}s.`);
            setTimeout(updateCountdown, 1000 - (Date.now() % 1000));
          } else {
            setLoginError('');
            if (countdownInterval) { clearInterval(countdownInterval); countdownInterval = null; }
          }
        };
        updateCountdown();
      }
    };
    try { window.addEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
    try { window.addEventListener(EventType.AUTH_RATE_LIMITED, onAuthRateLimited as any); } catch { }
    return () => {
      if (countdownInterval) clearInterval(countdownInterval);
      try { window.removeEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
      try { window.removeEventListener(EventType.AUTH_RATE_LIMITED, onAuthRateLimited as any); } catch { }
    };
  }, []);

  useEffect(() => {
    const handleAuthError = (event: any) => {
      const detail = event.detail;
      if (detail?.type === 'SERVER_ENTRY_REQUIRED') {
        setShowPasswordPrompt(true);
        setLoginError("");
        setAuthStatus("");
      }
    };
    window.addEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    return () => window.removeEventListener(EventType.AUTH_ERROR, handleAuthError as any);
  }, []);

  const [serverTrustRequest, setServerTrustRequest] = useState<ServerTrustRequest | null>(null);
  const acceptServerTrust = useCallback(() => {
    if (!serverTrustRequest) return;
    try { PinnedServer.set(serverTrustRequest.newKeys); } catch { }
    setServerHybridPublic(serverTrustRequest.newKeys);
    setServerTrustRequest(null);
    setLoginError("");
  }, [serverTrustRequest]);

  const rejectServerTrust = useCallback(() => { setServerTrustRequest(null); setLoginError("Server key changed. Trust not granted."); }, []);

  const hybridKeysRef = useRef<HybridKeys | null>(null);
  const keyManagerRef = useRef<SecureKeyManager | null>(null);
  const keyManagerOwnerRef = useRef<string>("");
  const loginUsernameRef = useRef("");
  const originalUsernameRef = useRef<string>("");
  const passwordRef = useRef<string>("");
  const confirmPasswordRef = useRef<string>("");

  const keyManagementRefs = {
    loginUsernameRef, passwordRef, confirmPasswordRef, passphrasePlaintextRef,
    passphraseRef, aesKeyRef, hybridKeysRef, keyManagerRef, keyManagerOwnerRef,
    getKeysPromiseRef, serverHybridPublicRef, blindCredentialRef,
  };

  const keyManagementSetters = {
    setIsGeneratingKeys,
    setAuthStatus: setAuthStatus as (v: string | ((prev: string) => string)) => void,
    setLoginError,
    setShowPassphrasePrompt,
  };

  const deriveEffectivePassphrase = createDeriveEffectivePassphrase(keyManagementRefs);
  const getKeysOnDemand = useCallback(createGetKeysOnDemand(keyManagementRefs, deriveEffectivePassphrase), []);
  const waitForServerKeys = useCallback(createWaitForServerKeys(keyManagementRefs, keyManagementSetters), []);
  const initializeKeys = useCallback(createInitializeKeys(keyManagementRefs, keyManagementSetters, deriveEffectivePassphrase, recoveryActive), [recoveryActive]);

  const storeAuthenticationState = useCallback(createStoreAuthenticationState(), []);
  const clearAuthenticationState = useCallback(createClearAuthenticationState(), []);

  const attemptAuthRecovery = useCallback(
    createAttemptAuthRecovery(
      { loginUsernameRef, originalUsernameRef },
      { setUsername, setPseudonym, setAuthStatus, setTokenValidationInProgress },
      accountAuthenticated, isLoggedIn
    ),
    [accountAuthenticated, isLoggedIn]
  );

  const clearSecureDBForUser = async (p: string) => {
    try {
      const { SQLiteKV } = await import('../../lib/database/sqlite-kv');
      await (SQLiteKV as any).purgeUserDb(p);
    } catch { }
  };

  const authRefs = {
    loginUsernameRef, originalUsernameRef, passwordRef, confirmPasswordRef,
    passphraseRef, passphrasePlaintextRef, hybridKeysRef, keyManagerRef,
    keyManagerOwnerRef, passphraseLimiterRef, aesKeyRef: keyManagementRefs.aesKeyRef,
    blindCredentialRef: keyManagementRefs.blindCredentialRef,
  };

  const authSetters = {
    setUsername, setPseudonym, setIsLoggedIn, setIsGeneratingKeys,
    setAuthStatus, setLoginError, setIsSubmittingAuth, setAccountAuthenticated,
    setIsRegistrationMode, setShowPassphrasePrompt, setRecoveryActive, setMaxStepReached,
    setVaultReady,
  };

  const authState = { isLoggedIn, accountAuthenticated, recoveryActive, serverHybridPublic, isSubmittingAuth };

  const handleAccountSubmit = createHandleAccountSubmit(
    authRefs, authSetters, authState,
    { waitForServerKeys, initializeKeys, getKeysOnDemand, storeAuthenticationState, clearSecureDBForUser }
  );

  const handleAuthSuccess = createHandleAuthSuccess(
    { loginUsernameRef, originalUsernameRef, passphrasePlaintextRef, keyManagerRef },
    { setAuthStatus, setUsername, setPseudonym, setIsLoggedIn, setAccountAuthenticated, setRecoveryActive, setShowPassphrasePrompt, setIsRegistrationMode, setLoginError },
    { storeAuthenticationState, deriveEffectivePassphrase, getKeysOnDemand }
  );

  const logout = createLogout(
    { loginUsernameRef, passwordRef, passphraseRef, passphrasePlaintextRef, aesKeyRef, hybridKeysRef, keyManagerRef },
    { setIsLoggedIn, setLoginError, setAccountAuthenticated, setIsRegistrationMode, setIsSubmittingAuth, setUsername, setTokenValidationInProgress },
    clearAuthenticationState
  );

  const getLogout = createGetLogout(logout);

  useEffect(() => { if (accountAuthenticated) setMaxStepReached('server'); }, [accountAuthenticated]);

  useEffect(() => {
    const handleAuthUiBack = (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'login' | 'server' | undefined;
        setLoginError(""); setAuthStatus("");
        if (to === 'login') {
          setShowPassphrasePrompt(false); setRecoveryActive(false); setAccountAuthenticated(false);
        } else if (to === 'server') {
          setShowPassphrasePrompt(false); setRecoveryActive(false); setAccountAuthenticated(false);
          setIsLoggedIn(false); setMaxStepReached('login');
          secureWipeStringRef(passwordRef as any); secureWipeStringRef(passphraseRef as any);
          secureWipeStringRef(passphrasePlaintextRef as any);
          loginUsernameRef.current = ""; originalUsernameRef.current = ""; setUsername("");
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
          case 'username': originalUsernameRef.current = value; break;
          case 'password': passwordRef.current = value; break;
          case 'confirmPassword': confirmPasswordRef.current = value; break;
          case 'passphrase': passphrasePlaintextRef.current = value; break;
        }
      } catch { }
    };
    window.addEventListener(EventType.AUTH_UI_INPUT, handleAuthUiInput as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_INPUT, handleAuthUiInput as EventListener);
  }, []);

  useEffect(() => {
    const handleAuthUiForward = async (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'login' | 'passphrase' | undefined;
        setLoginError(""); setAuthStatus("");
        if (to === 'login' || (!showPassphrasePrompt && !accountAuthenticated)) {
          const orig = originalUsernameRef.current; const pwd = passwordRef.current;
          const pps = passphrasePlaintextRef.current;
          if (orig && pwd) { await handleAccountSubmit(isRegistrationMode ? 'register' : 'login', orig, pwd, pps); }
        }
      } catch { }
    };
    window.addEventListener(EventType.AUTH_UI_FORWARD, handleAuthUiForward as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_FORWARD, handleAuthUiForward as EventListener);
  }, [accountAuthenticated, isRegistrationMode, showPassphrasePrompt, handleAccountSubmit]);

  useEffect(() => {
    const handleBeforeUnload = () => {
      if (isLoggedIn && loginUsernameRef.current) {
        try {
          (async () => {
            const qRaw = await encryptedStorage.getItem('cleanup_queue_pending');
            const q = Array.isArray(qRaw) ? qRaw : [];
            q.push({ username: loginUsernameRef.current, timestamp: Date.now() });
            await encryptedStorage.setItem('cleanup_queue_pending', q.slice(-10));
          })();
        } catch { }
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isLoggedIn]);

  useEffect(() => {
    const handleReconnection = async () => { if (isLoggedIn && loginUsernameRef.current) { try { await attemptAuthRecovery(); } catch { } } };
    window.addEventListener(EventType.WS_RECONNECTED, handleReconnection);
    return () => window.removeEventListener(EventType.WS_RECONNECTED, handleReconnection);
  }, [isLoggedIn, attemptAuthRecovery]);

  useEffect(() => {
    (async () => {
      try {
        if (isLoggedIn && loginUsernameRef.current) {
          const keys = await getKeysOnDemand?.();
          const pub = keys?.kyber?.publicKeyBase64;
          const sec = keys?.kyber?.secretKey ? CryptoUtils.Base64.arrayBufferToBase64(keys.kyber.secretKey) : undefined;
          if (pub && sec) await signal.setStaticMlkemKeys(loginUsernameRef.current, pub, sec);
        }
      } catch { }
    })();
  }, [isLoggedIn, getKeysOnDemand]);

  useEffect(() => {
    if (!isLoggedIn || !accountAuthenticated || !serverHybridPublic || !hybridKeysRef.current) return;
    if (websocketClient.isUnlinkedMode()) return;
    if (!websocketClient.isServerAuthGranted?.()) return;
    const uploadKeys = async () => {
      try {
        let attempts = 0;
        while (attempts < 20 && !websocketClient.isPQSessionEstablished?.()) { await new Promise(r => setTimeout(r, 100)); attempts++; }
        if (!websocketClient.isPQSessionEstablished?.()) return;
        const keys = hybridKeysRef.current;
        if (!keys?.dilithium?.publicKeyBase64 || !keys?.kyber?.publicKeyBase64 || !keys?.dilithium?.secretKey) return;
        const keysToSend: any = { kyberPublicBase64: keys.kyber.publicKeyBase64, dilithiumPublicBase64: keys.dilithium.publicKeyBase64, x25519PublicBase64: keys.x25519?.publicKeyBase64 || '' };

        if (blindCredentialRef.current?.blindedMsg) {
          keysToSend.blindedToken = blindCredentialRef.current.blindedMsg;
        }
        const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(JSON.stringify(keysToSend), serverHybridPublic, {
          senderDilithiumSecretKey: keys.dilithium.secretKey,
          senderDilithiumPublicKey: keys.dilithium.publicKeyBase64,
          metadata: { context: SignalType.HYBRID_KEYS_UPDATE }
        });
        await websocketClient.sendSecureControlMessage({ type: SignalType.HYBRID_KEYS_UPDATE, userData: encryptedHybridKeys });
        window.dispatchEvent(new CustomEvent(EventType.HYBRID_KEYS_UPDATED));
      } catch { }
    };
    uploadKeys();
  }, [isLoggedIn, accountAuthenticated, serverHybridPublic, hybridKeysRef]);

  useEffect(() => {
    (async () => {
      try {
        const token = await retrieveAuthTokens();
        const sU = await storage.get('last_authenticated_username');
        if (token || sU) {
          setTokenValidationInProgress(true); setAuthStatus('Verifying session...');
          if (sU) {
            const { computeBlindUserId } = await import('../../lib/utils/auth-utils');
            const pseudonymHash = computeBlindUserId(sU);
            loginUsernameRef.current = sU;
            setPseudonym(pseudonymHash);
            setUsername(sU);
            originalUsernameRef.current = sU;
          }
        } else {
          setTokenValidationInProgress(false); setAuthStatus('');
        }
      } catch { setTokenValidationInProgress(false); setAuthStatus(''); }
    })();
  }, []);

  useEffect(() => {
    const onStart = () => { setTokenValidationInProgress(true); setAuthStatus('Verifying session...'); };
    window.addEventListener(EventType.TOKEN_VALIDATION_START, onStart);
    return () => window.removeEventListener(EventType.TOKEN_VALIDATION_START, onStart);
  }, []);

  useEffect(() => {
    let timeout: NodeJS.Timeout;
    if (tokenValidationInProgress) timeout = setTimeout(() => { setTokenValidationInProgress(false); setAuthStatus(''); }, 10000);
    return () => clearTimeout(timeout);
  }, [tokenValidationInProgress]);

  useEffect(() => {
    const onTimeout = () => { setTokenValidationInProgress(false); setAuthStatus(''); setLoginError('Session validation timed out.'); };
    window.addEventListener(EventType.TOKEN_VALIDATION_TIMEOUT, onTimeout);
    return () => window.removeEventListener(EventType.TOKEN_VALIDATION_TIMEOUT, onTimeout);
  }, []);

  useEffect(() => {
    try {
      const pinned = PinnedServer.get();
      if (pinned) setServerHybridPublic(pinned); else setServerHybridPublic(null);
    } catch { setServerHybridPublic(null); }
  }, []);

  useEffect(() => {
    const onServerEntryGranted = async () => {
      try {
        if (websocketClient.isUnlinkedMode()) {
          return;
        }

        const savedUsername = await storage.get('last_authenticated_username');
        const token = await retrieveAuthTokens();

        if (token) {
          setTokenValidationInProgress(true);
          setAuthStatus('Resuming session...');

          if (savedUsername) {
            const { computeBlindUserId } = await import('../../lib/utils/auth-utils');
            const pseudonymHash = computeBlindUserId(savedUsername);
            loginUsernameRef.current = savedUsername;
            setPseudonym(pseudonymHash);
            setUsername(savedUsername);
          }

          // Generate blinded token for blind routing credential issuance
          let blindedToken: string | undefined;
          if (savedUsername && serverHybridPublicRef.current?.blindPublicKey) {
            const result = await generateBlindCredential(savedUsername, serverHybridPublicRef.current.blindPublicKey);
            if (result) {
              const existing = blindCredentialRef.current;
              if (!existing || existing.used) {
                blindCredentialRef.current = { ...result, used: false };
                blindedToken = result.blindedMsg;
              } else {
                blindedToken = existing.blindedMsg;
              }
            }
          }

          // Send token validation request
          const validationMessage: any = {
            type: SignalType.TOKEN_VALIDATION,
            accessToken: token
          };
          if (blindedToken) {
            validationMessage.blindedToken = blindedToken;
          }
          await websocketClient.sendSecureControlMessage(validationMessage);
        } else if (savedUsername) {
          // Have username but no token then show login with username pre-filled
          loginUsernameRef.current = savedUsername;
          setUsername(savedUsername);
          setTokenValidationInProgress(false);
        }
      } catch (err) {
        console.warn('[Auth] Auto-login after server entry failed:', err);
        setTokenValidationInProgress(false);
        setAuthStatus('');
      }
    };

    window.addEventListener(EventType.SERVER_ENTRY_GRANTED, onServerEntryGranted);
    return () => window.removeEventListener(EventType.SERVER_ENTRY_GRANTED, onServerEntryGranted);
  }, []);

  return {
    username, setUsername, pseudonym, setPseudonym, tokenValidationInProgress, setTokenValidationInProgress,
    serverHybridPublic, setServerHybridPublic, serverTrustRequest, setServerTrustRequest,
    acceptServerTrust, rejectServerTrust, isLoggedIn, setIsLoggedIn, isGeneratingKeys, isSubmittingAuth,
    authStatus, setAuthStatus, loginError, accountAuthenticated, isRegistrationMode, setIsRegistrationMode,
    loginUsernameRef, originalUsernameRef, initializeKeys,
    handleAccountSubmit, handleAuthSuccess, setAccountAuthenticated, passwordRef, setLoginError,
    setShowPassphrasePrompt, showPassphrasePrompt, setMaxStepReached, logout, getLogout,
    hybridKeysRef, keyManagerRef, getKeysOnDemand, attemptAuthRecovery, storeAuthenticationState,
    clearAuthenticationState, recoveryActive, setRecoveryActive,
    aesKeyRef, passphrasePlaintextRef, passphraseRef,
    vaultReady, setVaultReady,
    showPasswordPrompt,
    setShowPasswordPrompt,
    handlePasswordHashSubmit: async () => { },
    handleServerPasswordSubmit: async (password: string) => {
      if (!password) return;
      setIsSubmittingAuth(true);
      setAuthStatus("Verifying entry...");
      try {
        const success = await websocketClient.startServerGatekeeperFlow(password);
        if (success) {
          setShowPasswordPrompt(false);
          setAuthStatus("Entry granted");
          toast.success("Server access granted anonymously");
        } else {
          setLoginError("Invalid server password");
          setAuthStatus("");
        }
      } catch (err) {
        setLoginError("Entry verification failed");
        setAuthStatus("");
      } finally {
        setIsSubmittingAuth(false);
      }
    },
    handlePassphraseSubmit: async (passphrase: string) => {
      if (!passphrase) return;
      setIsSubmittingAuth(true);
      setAuthStatus("Initializing encryption...");
      try {
        passphrasePlaintextRef.current = passphrase;
        await initializeKeys(false);
        setVaultReady(true);
        setShowPassphrasePrompt(false);
      } catch (err) {
        setLoginError("Master key generation failed");
        console.error('[Auth] Passphrase submit error:', err);
      } finally {
        setIsSubmittingAuth(false);
        setAuthStatus("");
      }
    },
    setTypedUsername: (n: string) => { originalUsernameRef.current = n; },
    setTypedPassword: (p: string) => { passwordRef.current = p; },
    setTypedConfirmPassword: (p: string) => { confirmPasswordRef.current = p; },
    setTypedPassphrase: (p: string) => { passphrasePlaintextRef.current = p; },
    confirmPasswordRef, maxStepReached,
    blindCredentialRef: keyManagementRefs.blindCredentialRef,
    serverHybridPublicRef: keyManagementRefs.serverHybridPublicRef,
  };
};
