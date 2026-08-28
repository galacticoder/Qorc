import { useState, useRef, useCallback, useEffect, useLayoutEffect, useMemo } from "react";
import { EventType } from "../../lib/types/event-types";
import websocketClient from "../../lib/websocket/websocket";
import { clearStringRef, computeBlindUserId } from "../../lib/utils/auth-utils";
import type { ServerHybridPublicKeys, HybridKeys } from "../../lib/types/auth-types";
import { createDeriveEffectivePassphrase, createGetKeysOnDemand, createWaitForServerKeys, createInitializeKeys } from "./keyManagement";
import { createHandleAccountSubmit } from "./handlers";
import { createHandleAuthSuccess } from "./authSuccess";
import { createAttemptAuthRecovery, createStoreAuthenticationState, createClearAuthenticationState } from "./recovery";
import { createLogout, createGetLogout } from "./logout";
import { account } from "../../lib/tauri-bindings";
import { toast } from "sonner";
import { isExplicitlyLoggedOut } from "../../lib/auth/logout-marker";
import { loadLastAuthenticatedAccount } from "../../lib/security/local-account-scope";
import {
  type AuthLifecycle,
  type AuthOperationSnapshot,
  StaleAuthOperationError,
  isStaleAuthOperation,
} from "../../lib/auth/auth-lifecycle";
import { hasResumeToken, invalidateResumePoolOperations } from "../../lib/signals/resume-tokens";
import { handleTokenValidationResponse } from "../../lib/signals/auth-handlers";
import { tokenVault } from "../../lib/database/token-vault";
import { resetAvatarStoreClient } from "../../lib/avatar/avatar-store-client";
import { getBlindRoutingClient, resetBlindRoutingClient } from "../../lib/transport/blind-routing-client";
import { unifiedSignalTransport } from "../../lib/transport/unified-signal-transport";
import { p2pTransport } from "../../lib/transport/p2p-transport";
import { syncEncryptedStorage } from "../../lib/database/encrypted-storage";
import { receiptBatcher } from "../message-handling/receipt-batcher";
import { identityChangeStore } from "../../lib/security/identity-change-store";
import { blockingSystem } from "../../lib/blocking/blocking-system";
import { blockStatusCache } from "../../lib/blocking/block-status-cache";
import { profilePictureSystem } from "../../lib/avatar/profile-picture-system";
import { keyTransparencyClient } from "../../lib/key-transparency/client";
import { keyTransparencyWarningStore } from "../../lib/key-transparency/warning-store";
import { deliveryReceiptOutbox } from "../../lib/signals/delivery-receipt-outbox";

export const useAuth = () => {
  const [username, setUsername] = useState("");
  const [pseudonym, setPseudonym] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [authStatus, setAuthStatus] = useState<string>("");
  const [loginError, setLoginError] = useState("");
  const [isSubmittingAuth, setIsSubmittingAuth] = useState(false);
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const [isRegistrationMode, setIsRegistrationMode] = useState(false);
  const [tokenValidationInProgress, setTokenValidationInProgressState] = useState(false);
  const [tokenValidationGeneration, setTokenValidationGeneration] = useState(0);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const [recoveryActive, setRecoveryActive] = useState(false);
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [vaultReady, setVaultReady] = useState(false);
  const showPasswordPromptRef = useRef<boolean>(false);
  showPasswordPromptRef.current = showPasswordPrompt;

  useEffect(() => {
    websocketClient.setServerEntryPromptPending?.(showPasswordPrompt);
  }, [showPasswordPrompt]);

  const passphrasePlaintextRef = useRef<string>("");
  const getKeysPromiseRef = useRef<Promise<any> | null>(null);
  const accountSubmitInFlightRef = useRef<boolean>(false);
  const recoveryInFlightRef = useRef<Promise<boolean> | null>(null);
  const loginUsernameRef = useRef("");
  const originalUsernameRef = useRef<string>("");
  const passwordRef = useRef<string>("");
  const confirmPasswordRef = useRef<string>("");
  const hybridKeysRef = useRef<HybridKeys | null>(null);
  const keyManagerOwnerRef = useRef<string>("");
  const authLifecycleStateRef = useRef({
    generation: 0,
    account: '',
    requestId: '',
    controller: new AbortController(),
  });
  const [serverHybridPublic, setServerHybridPublic] = useState<ServerHybridPublicKeys | null>(null);
  const serverHybridPublicRef = useRef<ServerHybridPublicKeys | null>(null);

  const setTokenValidationInProgress = useCallback((value: boolean) => {
    if (value) setTokenValidationGeneration((generation) => generation + 1);
    setTokenValidationInProgressState(value);
  }, []);

  const rotateAuthLifecycle = useCallback((account = '', requestId = ''): AuthOperationSnapshot => {
    invalidateResumePoolOperations();
    const previous = authLifecycleStateRef.current;
    previous.controller.abort();

    const normalizedAccount = account.trim().toLowerCase();
    if (
      normalizedAccount &&
      loginUsernameRef.current &&
      loginUsernameRef.current !== normalizedAccount
    ) {
      keyTransparencyClient.destroy();
      hybridKeysRef.current = null;
      keyManagerOwnerRef.current = '';
    }

    const next = {
      generation: previous.generation + 1,
      account: normalizedAccount,
      requestId,
      controller: new AbortController(),
    };
    authLifecycleStateRef.current = next;
    accountSubmitInFlightRef.current = false;
    recoveryInFlightRef.current = null;
    getKeysPromiseRef.current = null;
    return {
      generation: next.generation,
      account: next.account,
      requestId: next.requestId,
      signal: next.controller.signal,
    };
  }, []);

  const captureAuthOperation = useCallback((): AuthOperationSnapshot => {
    const current = authLifecycleStateRef.current;
    return {
      generation: current.generation,
      account: current.account,
      requestId: current.requestId,
      signal: current.controller.signal,
    };
  }, []);

  const isAuthOperationCurrent = useCallback((operation: AuthOperationSnapshot): boolean => {
    const current = authLifecycleStateRef.current;
    return !operation.signal.aborted &&
      operation.generation === current.generation &&
      operation.signal === current.controller.signal;
  }, []);

  const assertAuthOperationCurrent = useCallback((operation: AuthOperationSnapshot): void => {
    if (!isAuthOperationCurrent(operation)) throw new StaleAuthOperationError();
  }, [isAuthOperationCurrent]);

  const authLifecycle = useMemo<AuthLifecycle>(() => ({
    begin: rotateAuthLifecycle,
    capture: captureAuthOperation,
    invalidate: () => { void rotateAuthLifecycle(''); },
    isCurrent: isAuthOperationCurrent,
    assertCurrent: assertAuthOperationCurrent,
  }), [assertAuthOperationCurrent, captureAuthOperation, isAuthOperationCurrent, rotateAuthLifecycle]);

  useEffect(() => {
    const mountedOperation = rotateAuthLifecycle(loginUsernameRef.current);
    return () => {
      if (isAuthOperationCurrent(mountedOperation)) {
        authLifecycleStateRef.current.controller.abort();
      }
    };
  }, [isAuthOperationCurrent, rotateAuthLifecycle]);

  useLayoutEffect(() => {
    serverHybridPublicRef.current = serverHybridPublic;
  }, [serverHybridPublic]);

  useEffect(() => {
    let countdownTimeout: ReturnType<typeof setTimeout> | null = null;
    let countdownGeneration = 0;
    const onAuthError = () => { setIsSubmittingAuth(false); setTokenValidationInProgress(false); setAuthStatus(''); };
    const onAuthRateLimited = (event: any) => {
      setIsSubmittingAuth(false); setTokenValidationInProgress(false); setAuthStatus(''); setIsGeneratingKeys(false);
      const rateLimitUntil = event.detail?.rateLimitUntil;
      if (rateLimitUntil) {
        countdownGeneration += 1;
        const generation = countdownGeneration;
        if (countdownTimeout) clearTimeout(countdownTimeout);
        const updateCountdown = () => {
          if (generation !== countdownGeneration) return;
          const remaining = Math.max(0, Math.ceil((rateLimitUntil - Date.now()) / 1000));
          if (remaining > 0) {
            setLoginError(`Too many attempts. Try again in ${remaining}s.`);
            countdownTimeout = setTimeout(updateCountdown, 1000 - (Date.now() % 1000));
          } else {
            setLoginError('');
            countdownTimeout = null;
          }
        };
        updateCountdown();
      }
    };
    try { window.addEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
    try { window.addEventListener(EventType.AUTH_RATE_LIMITED, onAuthRateLimited as any); } catch { }
    return () => {
      countdownGeneration += 1;
      if (countdownTimeout) clearTimeout(countdownTimeout);
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

  const keyManagementRefs = {
    loginUsernameRef, passwordRef, confirmPasswordRef, passphrasePlaintextRef,
    hybridKeysRef, keyManagerOwnerRef,
    getKeysPromiseRef, serverHybridPublicRef,
  };

  const keyManagementSetters = {
    setIsGeneratingKeys,
    setAuthStatus: setAuthStatus as (v: string | ((prev: string) => string)) => void,
    setLoginError,
    setShowPassphrasePrompt,
  };

  const deriveEffectivePassphrase = createDeriveEffectivePassphrase(keyManagementRefs);
  const getKeysOnDemand = useCallback(
    createGetKeysOnDemand(keyManagementRefs, deriveEffectivePassphrase, authLifecycle),
    [authLifecycle]
  );
  const waitForServerKeys = useCallback(createWaitForServerKeys(keyManagementRefs, keyManagementSetters), []);
  const initializeKeys = useCallback(
    createInitializeKeys(keyManagementRefs, keyManagementSetters, deriveEffectivePassphrase, recoveryActive, authLifecycle),
    [authLifecycle, recoveryActive]
  );

  const storeAuthenticationState = useCallback(createStoreAuthenticationState(), []);
  const clearAuthenticationState = useCallback(createClearAuthenticationState(), []);

  const completeRecoveredAuthorization = useCallback(
    async (response: import("../../lib/websocket/websocket").ResumeAuthorizationResponse) => {
      await handleTokenValidationResponse(response, {
        loginUsernameRef,
        setAccountAuthenticated,
        setIsLoggedIn,
        setLoginError,
        setTokenValidationInProgress,
        setUsername,
        setShowPassphrasePrompt,
        setShowPasswordPrompt,
        setIsSubmittingAuth,
        setAuthStatus,
        setVaultReady,
        keyManagerOwnerRef,
        getKeysOnDemand,
        hybridKeysRef,
        authLifecycle,
      });
    },
    [authLifecycle, getKeysOnDemand, setTokenValidationInProgress]
  );

  const attemptAuthRecovery = useCallback(
    createAttemptAuthRecovery(
      { loginUsernameRef, originalUsernameRef, recoveryInFlightRef },
      { setUsername, setPseudonym, setAuthStatus, setTokenValidationInProgress },
      accountAuthenticated, isLoggedIn, authLifecycle, completeRecoveredAuthorization
    ),
    [accountAuthenticated, authLifecycle, completeRecoveredAuthorization, isLoggedIn, setTokenValidationInProgress]
  );

  const authRefs = {
    loginUsernameRef, originalUsernameRef, passwordRef, confirmPasswordRef,
    passphrasePlaintextRef, hybridKeysRef,
    keyManagerOwnerRef, accountSubmitInFlightRef,
  };

  const authSetters = {
    setUsername, setPseudonym, setIsLoggedIn, setIsGeneratingKeys,
    setAuthStatus, setLoginError, setIsSubmittingAuth, setAccountAuthenticated,
    setIsRegistrationMode,
    setVaultReady, setShowPasswordPrompt, setShowPassphrasePrompt,
    setRecoveryActive, setTokenValidationInProgress,
  };

  const authState = { isSubmittingAuth };

  const handleAccountSubmit = createHandleAccountSubmit(
    authRefs, authSetters, authState,
    {
      waitForServerKeys,
      initializeKeys,
      attemptAuthRecovery,
      isLocalRecovery: () => recoveryActive,
      storeAuthenticationState,
      lifecycle: authLifecycle,
    }
  );

  const handleAuthSuccess = createHandleAuthSuccess(
    { loginUsernameRef, originalUsernameRef },
    { setAuthStatus, setUsername, setPseudonym, setIsLoggedIn, setAccountAuthenticated, setIsSubmittingAuth, setLoginError },
    { storeAuthenticationState, lifecycle: authLifecycle }
  );

  const logout = createLogout(
    {
      loginUsernameRef, passwordRef, passphrasePlaintextRef,
      hybridKeysRef, keyManagerOwnerRef, getKeysPromiseRef,
    },
    {
      setIsLoggedIn, setLoginError, setAccountAuthenticated, setIsRegistrationMode,
      setIsSubmittingAuth, setUsername, setTokenValidationInProgress, setVaultReady,
      setShowPassphrasePrompt, setShowPasswordPrompt,
    },
    clearAuthenticationState,
    authLifecycle
  );

  const getLogout = createGetLogout(logout);

  useEffect(() => {
    const handleAuthUiBack = (event: CustomEvent) => {
      try {
        const to = (event as any).detail?.to as 'server' | undefined;
        if (to !== 'server') return;
        authLifecycle.invalidate();
        setLoginError(""); setAuthStatus("");
        unifiedSignalTransport.resetForAccountTransition();
        deliveryReceiptOutbox.setPersistence(null, null);
        deliveryReceiptOutbox.setActiveAccount(null);
        receiptBatcher.setActiveAccount(null);
        identityChangeStore.clear();
        blockingSystem.setSecureDB(null);
        blockStatusCache.clear();
        profilePictureSystem.setSecureDB(null);
        syncEncryptedStorage.reset();
        void p2pTransport.shutdown().catch(() => { });
        setShowPassphrasePrompt(false); setRecoveryActive(false); setAccountAuthenticated(false);
        setIsLoggedIn(false); setVaultReady(false);
        tokenVault.lock();
        resetAvatarStoreClient();
        resetBlindRoutingClient();
        keyTransparencyClient.destroy();
        keyTransparencyWarningStore.clear();
        clearStringRef(passwordRef);
        clearStringRef(confirmPasswordRef);
        clearStringRef(passphrasePlaintextRef);
        const accountOwner = keyManagerOwnerRef.current;
        hybridKeysRef.current = null;
        keyManagerOwnerRef.current = '';
        getKeysPromiseRef.current = null;
        loginUsernameRef.current = ""; originalUsernameRef.current = ""; setUsername("");
        setPseudonym("");
        if (/^[a-f0-9]{64}$/.test(accountOwner)) {
          void account.lock(accountOwner).catch(() => false);
        }
        void websocketClient.close({ killSession: true }).catch(() => { });
      } catch { }
    };
    window.addEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
    return () => window.removeEventListener(EventType.AUTH_UI_BACK, handleAuthUiBack as EventListener);
  }, [authLifecycle]);

  useEffect(() => {
    const handleReconnection = async () => { if (isLoggedIn && loginUsernameRef.current) { try { await attemptAuthRecovery(); } catch { } } };
    window.addEventListener(EventType.WS_RECONNECTED, handleReconnection);
    return () => window.removeEventListener(EventType.WS_RECONNECTED, handleReconnection);
  }, [isLoggedIn, attemptAuthRecovery]);

  useEffect(() => {
    if (!isLoggedIn || !accountAuthenticated || !hybridKeysRef.current) return;
    window.dispatchEvent(new CustomEvent(EventType.HYBRID_KEYS_UPDATED));
  }, [isLoggedIn, accountAuthenticated, hybridKeysRef]);

  useEffect(() => {
    if (
      isLoggedIn &&
      accountAuthenticated &&
      !vaultReady &&
      !showPassphrasePrompt &&
      !showPasswordPrompt &&
      hybridKeysRef.current
    ) {
      setVaultReady(true);
    }
  }, [isLoggedIn, accountAuthenticated, vaultReady, showPassphrasePrompt, showPasswordPrompt]);

  useEffect(() => {
    const operation = authLifecycle.capture();
    (async () => {
      try {
        if (await isExplicitlyLoggedOut()) {
          if (!authLifecycle.isCurrent(operation)) return;
          setTokenValidationInProgress(false);
          setAuthStatus('');
          return;
        }
        authLifecycle.assertCurrent(operation);
        const sU = (await loadLastAuthenticatedAccount()).username;
        authLifecycle.assertCurrent(operation);
        authLifecycle.assertCurrent(operation);
        const canResume = sU ? await hasResumeToken(sU) : false;
        authLifecycle.assertCurrent(operation);
        if (canResume || sU) {
          setTokenValidationInProgress(true); setAuthStatus('Verifying session...');
          if (sU) {
            const pseudonymHash = computeBlindUserId(sU);
            loginUsernameRef.current = sU;
            setPseudonym(pseudonymHash);
            setUsername(sU);
            originalUsernameRef.current = sU;
          }
        } else {
          setTokenValidationInProgress(false); setAuthStatus('');
        }
      } catch (error) {
        if (!isStaleAuthOperation(error) && authLifecycle.isCurrent(operation)) {
          setTokenValidationInProgress(false); setAuthStatus('');
        }
      }
    })();
  }, [authLifecycle, setTokenValidationInProgress]);

  useEffect(() => {
    const onStart = () => { setTokenValidationInProgress(true); setAuthStatus('Verifying session...'); };
    window.addEventListener(EventType.TOKEN_VALIDATION_START, onStart);
    return () => window.removeEventListener(EventType.TOKEN_VALIDATION_START, onStart);
  }, []);

  useEffect(() => {
    const operation = authLifecycle.capture();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    if (tokenValidationInProgress) {
      timeout = setTimeout(() => {
        if (!authLifecycle.isCurrent(operation)) return;
        setTokenValidationInProgress(false);
        setAuthStatus('');
      }, 45000);
    }
    return () => clearTimeout(timeout);
  }, [authLifecycle, tokenValidationGeneration, tokenValidationInProgress, setTokenValidationInProgress]);

  useEffect(() => {
    const onTimeout = () => { setTokenValidationInProgress(false); setAuthStatus(''); setLoginError('Session validation timed out.'); };
    window.addEventListener(EventType.TOKEN_VALIDATION_TIMEOUT, onTimeout);
    return () => window.removeEventListener(EventType.TOKEN_VALIDATION_TIMEOUT, onTimeout);
  }, []);

  const resumeSavedAccountAfterServerEntry = useCallback(async (
    operation: AuthOperationSnapshot
  ): Promise<void> => {
    if (await isExplicitlyLoggedOut()) {
      authLifecycle.assertCurrent(operation);
      setTokenValidationInProgress(false);
      setAuthStatus('');
      return;
    }
    authLifecycle.assertCurrent(operation);
    if (websocketClient.isUnlinkedMode()) {
      return;
    }

    const savedAccount = await loadLastAuthenticatedAccount();
    authLifecycle.assertCurrent(operation);
    const savedUsername = savedAccount.username;
    if (operation.account && savedUsername && operation.account !== savedUsername) return;
    const canResume = savedUsername ? await hasResumeToken(savedUsername) : false;
    authLifecycle.assertCurrent(operation);

    if (canResume) {
      setTokenValidationInProgress(true);
      setAuthStatus('Resuming session...');

      if (savedUsername) {
        const pseudonymHash = computeBlindUserId(savedUsername);
        loginUsernameRef.current = savedUsername;
        originalUsernameRef.current = savedAccount.displayName || savedUsername;
        setPseudonym(pseudonymHash);
        setUsername(savedAccount.displayName || savedUsername);
        getBlindRoutingClient(savedUsername);
        websocketClient.setUsername(savedUsername);
      }

      const authorization = await websocketClient.switchToUnlinkedMode(operation.signal);
      authLifecycle.assertCurrent(operation);
      await completeRecoveredAuthorization(authorization);
      authLifecycle.assertCurrent(operation);
    } else if (savedUsername) {
      loginUsernameRef.current = savedUsername;
      originalUsernameRef.current = savedAccount.displayName || savedUsername;
      setUsername(savedAccount.displayName || savedUsername);
      setTokenValidationInProgress(false);
    }
  }, [authLifecycle, completeRecoveredAuthorization, setTokenValidationInProgress]);

  useEffect(() => {
    const onServerEntryGranted = async () => {
      if (
        websocketClient.isUnlinkedMode() ||
        accountSubmitInFlightRef.current ||
        showPasswordPromptRef.current
      ) {
        return;
      }

      const operation = authLifecycle.capture();
      try {
        await resumeSavedAccountAfterServerEntry(operation);
      } catch (err) {
        if (isStaleAuthOperation(err) || !authLifecycle.isCurrent(operation)) return;
        console.warn('[Auth] Auto-login after server entry failed:', err);
        setTokenValidationInProgress(false);
        setAuthStatus('');
      }
    };

    window.addEventListener(EventType.SERVER_ENTRY_GRANTED, onServerEntryGranted);
    return () => window.removeEventListener(EventType.SERVER_ENTRY_GRANTED, onServerEntryGranted);
  }, [authLifecycle, resumeSavedAccountAfterServerEntry, setTokenValidationInProgress]);

  return {
    username, setUsername, pseudonym, setPseudonym, tokenValidationInProgress, setTokenValidationInProgress,
    setServerHybridPublic, isLoggedIn, setIsLoggedIn, isGeneratingKeys, isSubmittingAuth,
    authStatus, setAuthStatus, loginError, accountAuthenticated, isRegistrationMode, setIsRegistrationMode,
    loginUsernameRef, originalUsernameRef, initializeKeys,
    handleAccountSubmit, handleAuthSuccess, setAccountAuthenticated, passwordRef, setLoginError,
    setShowPassphrasePrompt, showPassphrasePrompt, logout, getLogout,
    hybridKeysRef, getKeysOnDemand, attemptAuthRecovery, storeAuthenticationState,
    clearAuthenticationState, recoveryActive, setRecoveryActive,
    passphrasePlaintextRef,
    authLifecycle, keyManagerOwnerRef,
    vaultReady, setVaultReady,
    showPasswordPrompt,
    setShowPasswordPrompt,
    handleServerPasswordSubmit: async (password: string) => {
      if (!password) return;
      const requestId = crypto.randomUUID();
      const operation = authLifecycle.begin(loginUsernameRef.current, requestId);
      setLoginError("");
      setIsSubmittingAuth(true);
      setAuthStatus("Preparing private server-authentication connection...");
      try {
        await websocketClient.validateLinkedAuthenticationMode(operation.signal);
        authLifecycle.assertCurrent(operation);
        setAuthStatus("Verifying entry...");
        
        const success = websocketClient.isServerAuthGranted()
          ? true
          : await websocketClient.startServerGatekeeperFlow(
              password,
              requestId,
              (status) => {
                if (authLifecycle.isCurrent(operation)) setAuthStatus(status);
              },
              operation.signal
            );
        authLifecycle.assertCurrent(operation);
        if (success) {
          websocketClient.markServerAuthGranted?.();
          
          showPasswordPromptRef.current = false;
          websocketClient.setServerEntryPromptPending?.(false);
          setShowPasswordPrompt(false);
          setAuthStatus("Entry granted");
          toast.success("Server access granted anonymously");
          await resumeSavedAccountAfterServerEntry(operation);
          authLifecycle.assertCurrent(operation);
        } else {
          setLoginError("Invalid server password");
          setAuthStatus("");
        }
      } catch (err) {
        if (isStaleAuthOperation(err) || !authLifecycle.isCurrent(operation)) return;
        setLoginError(err instanceof Error && err.message ? err.message : "Entry verification failed");
        setAuthStatus("");
      } finally {
        if (authLifecycle.isCurrent(operation)) setIsSubmittingAuth(false);
      }
    },
    confirmPasswordRef,
    serverHybridPublicRef: keyManagementRefs.serverHybridPublicRef,
  };
};
