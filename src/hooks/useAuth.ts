import { useState, useRef, useCallback, useEffect, MutableRefObject } from "react";
import { SignalType } from "../lib/signal-types";
import { retrieveAuthTokens, clearTokenEncryptionKey } from "../lib/signals";
import websocketClient from "../lib/websocket";
import { CryptoUtils } from "../lib/unified-crypto";
import { SecureDB } from "../lib/secureDB";
import { SecureKeyManager } from "../lib/secure-key-manager";
import { ensureVaultKeyCryptoKey, saveWrappedMasterKey } from "../lib/vault-key";
import { encryptedStorage, syncEncryptedStorage } from "../lib/encrypted-storage";
import { pseudonymizeUsername } from "../lib/username-hash";
import { PostQuantumSignature, PostQuantumUtils } from "../lib/post-quantum-crypto";

const secureWipeStringRef = (ref: MutableRefObject<string>) => {
  try {
    const len = ref.current?.length || 0;
    if (len > 0) {
      for (let pass = 0; pass < 2; pass++) {
        const randomBytes = PostQuantumUtils.randomBytes(len);
        const filler = Array.from(randomBytes)
          .map((byte) => String.fromCharCode(32 + (byte % 95)))
          .join("");
        ref.current = filler;
      }
    }
    ref.current = "";
  } catch { }
};

const safeDecodeB64 = (b64?: string): Uint8Array | null => {
  try {
    if (!b64 || typeof b64 !== 'string' || b64.length > 10000) return null;
    return CryptoUtils.Base64.base64ToUint8Array(b64);
  } catch { return null; }
};

const validateServerKeys = (val: any): boolean => {
  if (!val || typeof val !== 'object') return false;
  if (!val.x25519PublicBase64 || !val.kyberPublicBase64 || !val.dilithiumPublicBase64) return false;
  if (typeof val.x25519PublicBase64 !== 'string' ||
    typeof val.kyberPublicBase64 !== 'string' ||
    typeof val.dilithiumPublicBase64 !== 'string') return false;
  const expB64Len = (n: number) => 4 * Math.ceil(n / 3);
  if (val.x25519PublicBase64.length > expB64Len(32) + 8) return false;
  if (val.kyberPublicBase64.length > expB64Len(1568) + 8) return false;
  if (val.dilithiumPublicBase64.length > expB64Len(2592) + 8) return false;

  const x = safeDecodeB64(val.x25519PublicBase64);
  const k = safeDecodeB64(val.kyberPublicBase64);
  const d = safeDecodeB64(val.dilithiumPublicBase64);
  if (!x || !k || !d) return false;
  if (x.length !== 32 || k.length !== 1568 || d.length !== 2592) return false;
  return true;
};

const PinnedServer = {
  get() {
    try {
      const storedStr = syncEncryptedStorage.getItem('securechat_server_pin_v2');
      if (!storedStr || storedStr.length > 4096) return null;

      const parsed = JSON.parse(storedStr);
      if (!validateServerKeys(parsed)) return null;
      return parsed;
    } catch { return null; }
  },
  set(val: any) {
    try {
      if (!validateServerKeys(val)) return;
      syncEncryptedStorage.setItem('securechat_server_pin_v2', JSON.stringify(val));
    } catch { }
  }
};

const deriveCombinedSecretInput = (username: string, password: string, passphrase: string): string => {
  const u = (username || "").trim();
  const p = password || "";
  const pp = passphrase || "";

  if (!u || !p || !pp) {
    throw new Error('[Auth] Missing username, password, or passphrase for key derivation');
  }

  return `${u}\u0000${p}\u0000${pp}`;
};

export const useAuth = (_secureDB?: SecureDB) => {
  const [username, setUsername] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [authStatus, setAuthStatus] = useState<string>("");
  const [loginError, setLoginError] = useState("");
  const [isSubmittingAuth, setIsSubmittingAuth] = useState(false);
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const [isRegistrationMode, setIsRegistrationMode] = useState(false);
  const [tokenValidationInProgress, setTokenValidationInProgress] = useState(() => {
    try {
      const storedUsername = syncEncryptedStorage.getItem('last_authenticated_username');
      return !!storedUsername;
    } catch {
      return false;
    }
  });
  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);
  const getKeysPromiseRef = useRef<Promise<any> | null>(null);
  const passphraseLimiterRef = useRef<{ tokens: number; last: number }>({ tokens: 5, last: Date.now() });

  const [serverHybridPublic, setServerHybridPublic] = useState<{
    x25519PublicBase64: string;
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
  } | null>(null);
  const serverHybridPublicRef = useRef<{
    x25519PublicBase64: string;
    kyberPublicBase64: string;
    dilithiumPublicBase64: string;
  } | null>(null);

  useEffect(() => {
    serverHybridPublicRef.current = serverHybridPublic;
  }, [serverHybridPublic]);

  useEffect(() => {
    let countdownInterval: NodeJS.Timeout | null = null;

    const onAuthError = () => {
      setIsSubmittingAuth(false);
    };

    const onAuthRateLimited = (event: any) => {
      setIsSubmittingAuth(false);
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

      console.log('[useAuth] States reset complete');
    };

    try { window.addEventListener('auth-error', onAuthError as any); } catch { }
    try { window.addEventListener('auth-rate-limited', onAuthRateLimited as any); } catch { }

    return () => {
      if (countdownInterval) {
        clearInterval(countdownInterval);
      }
      try { window.removeEventListener('auth-error', onAuthError as any); } catch { }
      try { window.removeEventListener('auth-rate-limited', onAuthRateLimited as any); } catch { }
    };
  }, []);

  const [serverTrustRequest, setServerTrustRequest] = useState<{
    newKeys: { x25519PublicBase64: string; kyberPublicBase64: string; dilithiumPublicBase64: string };
    pinned: { x25519PublicBase64: string; kyberPublicBase64: string; dilithiumPublicBase64: string } | null;
  } | null>(null);

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

  const hybridKeysRef = useRef<{
    x25519: { private: Uint8Array; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>(null);

  const keyManagerRef = useRef<SecureKeyManager | null>(null);
  const keyManagerOwnerRef = useRef<string>("");
  const loginUsernameRef = useRef("");
  const originalUsernameRef = useRef<string>("");

  const getKeysOnDemand = useCallback(async () => {
    if (!keyManagerRef.current) {
      return null;
    }

    try {
      if (hybridKeysRef.current) {
        return hybridKeysRef.current;
      }

      if (getKeysPromiseRef.current) {
        const cached = await getKeysPromiseRef.current.catch(() => null);
        if (cached) return cached;
      }

      const fetching = (async () => {
        try {
          let keys = await keyManagerRef.current!.getKeys().catch(() => null);

          if (!keys) {
            try {
              const effectivePassphrase = deriveEffectivePassphrase();
              const metadata = await keyManagerRef.current!.getKeyMetadata();
              if (metadata) {
                await keyManagerRef.current!.initialize(effectivePassphrase, metadata.salt);
              } else {
                await keyManagerRef.current!.initialize(effectivePassphrase);
              }
              keys = await keyManagerRef.current!.getKeys();
            } catch {
              return null;
            }
          }

          if (!keys || !keys.kyber || !keys.dilithium) {
            return null;
          }

          hybridKeysRef.current = keys;
          return keys;
        } finally {
          getKeysPromiseRef.current = null;
        }
      })();

      getKeysPromiseRef.current = fetching;
      const keys = await fetching;
      return keys;
    } catch {
      return null;
    }
  }, []);

  const waitForServerKeys = useCallback(
    async (timeoutMs: number = 15000) => {
      const start = Date.now();

      let current = serverHybridPublicRef.current;
      if (current && validateServerKeys(current)) {
        return current;
      }

      setAuthStatus((prev) => prev || 'Fetching server keys...');

      while (Date.now() - start < timeoutMs) {
        await new Promise((resolve) => setTimeout(resolve, 100));
        current = serverHybridPublicRef.current;
        if (current && validateServerKeys(current)) {
          return current;
        }
      }

      throw new Error('Failed to retrieve server keys from server');
    },
    [setAuthStatus],
  );

  const passwordRef = useRef<string>("");
  const confirmPasswordRef = useRef<string>("");
  const passphraseConfirmRef = useRef<string>("");
  const lastPasswordParamsForRef = useRef<string>("");

  type HashParams = { salt: string; memoryCost: number; timeCost: number; parallelism: number; version?: number; } | null;
  const [passphraseHashParams, setPassphraseHashParams] = useState<HashParams>(null);
  const [passwordHashParams, setPasswordHashParams] = useState<HashParams>(null);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [maxStepReached, setMaxStepReached] = useState<'login' | 'passphrase' | 'server'>('login');
  const [recoveryActive, setRecoveryActive] = useState(false);

  const deriveEffectivePassphrase = (): string => {
    const passphrase = passphrasePlaintextRef.current;
    const currentUsername = loginUsernameRef.current;
    let pwd = passwordRef.current;

    if (!passphrase) {
      throw new Error("Passphrase not available");
    }
    if (!currentUsername) {
      throw new Error("Username not available");
    }

    if (!pwd && confirmPasswordRef.current) {
      pwd = confirmPasswordRef.current;
    }
    if (!pwd) {
      throw new Error("Password not available");
    }

    return deriveCombinedSecretInput(currentUsername, pwd, passphrase);
  };

  const initializeKeys = useCallback(async (isRecoveryMode = false, providedSalt?: string, providedArgon2Params?: any) => {
    setIsGeneratingKeys(true);
    setAuthStatus("Initializing...");
    try {
      const effectivePassphrase = deriveEffectivePassphrase();

      const currentUsername = loginUsernameRef.current;
      if (!currentUsername) {
        throw new Error("Username not available");
      }

      await new Promise(resolve => setTimeout(resolve, 0));

      if (!keyManagerRef.current || keyManagerOwnerRef.current !== currentUsername) {
        try {
          if (keyManagerRef.current) {
            keyManagerRef.current.clearKeys();
            await keyManagerRef.current.deleteDatabase();
          }
        } catch { }

        try {
          keyManagerRef.current = new SecureKeyManager(currentUsername);
          keyManagerOwnerRef.current = currentUsername;
          hybridKeysRef.current = null;
        } catch (_e) {
          throw new Error('Key manager init failed: ' + ((_e as any)?.message || _e));
        }
      }

      await new Promise(resolve => setTimeout(resolve, 0));

      let hasExistingKeys = await keyManagerRef.current.hasKeys();

      if (hasExistingKeys) {
        setAuthStatus("Loading keys...");

        await new Promise(resolve => setTimeout(resolve, 0));

        let meta: { salt?: string; argon2Params?: any } | null = null;
        try {
          meta = await keyManagerRef.current.getKeyMetadata();
          if (meta?.salt) {
            await keyManagerRef.current.initialize(effectivePassphrase, meta.salt);
          } else {
            await keyManagerRef.current.initialize(effectivePassphrase);
          }
          const existingKeys = await keyManagerRef.current.getKeys();

          if (existingKeys) {
            setAuthStatus("Verifying...");
            hybridKeysRef.current = existingKeys;
            try {
              const pub = existingKeys.kyber.publicKeyBase64;
              const secB64 = CryptoUtils.Base64.arrayBufferToBase64(existingKeys.kyber.secretKey);
              if (typeof (window as any).edgeApi?.setStaticMlkemKeys === 'function' && pub && secB64) {
                await (window as any).edgeApi.setStaticMlkemKeys({ username: currentUsername, publicKeyBase64: pub, secretKeyBase64: secB64 });
              }
            } catch { }

            const masterKey = keyManagerRef.current.getMasterKey();
            if (masterKey) {
              aesKeyRef.current = masterKey;
              try {
                const vaultKey = await ensureVaultKeyCryptoKey(currentUsername);
                const raw = new Uint8Array(await CryptoUtils.Keys.exportAESKey(masterKey));
                await saveWrappedMasterKey(currentUsername, raw, vaultKey);
                raw.fill(0);
              } catch { }
            }

            const encodedHash = await keyManagerRef.current.getEncodedPassphraseHash(effectivePassphrase);
            if (encodedHash) {
              passphraseRef.current = encodedHash;
            }
          }
        } catch (_error) {
          const isDecryptionFailure = _error instanceof Error && (
            _error.message.includes('Decryption failed') ||
            _error.message.includes('Invalid authentication tag') ||
            _error.message.includes('X25519 key decryption failed') ||
            _error.message.includes('Key data corruption') ||
            _error.message.includes('Payload integrity verification failed') ||
            _error.message.includes('MAC verification failed')
          );

          if (isDecryptionFailure) {
            setLoginError('Incorrect passphrase. Please try again.');
            setShowPassphrasePrompt(true);
            throw new Error('Key decryption failed');
          } else {
            try {
              websocketClient.send({ type: 'client-error', error: _error instanceof Error ? _error.message : 'Unknown error' });
            } catch { }
            throw _error;
          }
        }
      }

      if (!hasExistingKeys) {
        if (isRecoveryMode || recoveryActive) {
          setLoginError('Recovery failed: stored keys not found.');
          throw new Error('Recovery mode: no existing keys');
        }
        setAuthStatus("Generating keys...");

        await new Promise(resolve => setTimeout(resolve, 0));

        const hybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPair();

        await new Promise(resolve => setTimeout(resolve, 0));

        setAuthStatus("Securing...");
        if (providedSalt && providedArgon2Params) {
          await keyManagerRef.current.initialize(effectivePassphrase, providedSalt, providedArgon2Params);
        } else {
          await keyManagerRef.current.initialize(effectivePassphrase);
        }
        setAuthStatus("Storing...");
        await keyManagerRef.current.storeKeys(hybridKeyPair);

        const masterKey = keyManagerRef.current.getMasterKey();
        if (masterKey) {
          aesKeyRef.current = masterKey;
          try {
            const vaultKey = await ensureVaultKeyCryptoKey(currentUsername);
            const raw = new Uint8Array(await CryptoUtils.Keys.exportAESKey(masterKey));
            await saveWrappedMasterKey(currentUsername, raw, vaultKey);
            raw.fill(0);
          } catch { }
        }

        const encodedHash = await keyManagerRef.current.getEncodedPassphraseHash(effectivePassphrase);
        if (encodedHash) {
          passphraseRef.current = encodedHash;
        }

        hybridKeysRef.current = hybridKeyPair;
        try {
          const pub = hybridKeyPair.kyber.publicKeyBase64;
          const secB64 = CryptoUtils.Base64.arrayBufferToBase64(hybridKeyPair.kyber.secretKey);
          if (typeof (window as any).edgeApi?.setStaticMlkemKeys === 'function' && pub && secB64) {
            await (window as any).edgeApi.setStaticMlkemKeys({ username: currentUsername, publicKeyBase64: pub, secretKeyBase64: secB64 });
          }
        } catch { }
      }
    } catch (_error) {
      const errorMessage = _error instanceof Error ? _error.message : String(_error);
      console.error('[Auth] Key initialization failed:', errorMessage, _error);
      setLoginError(`Key generation failed: ${errorMessage}`);
      throw _error;
    } finally {
      setIsGeneratingKeys(false);
      setAuthStatus("");
    }
  }, []);

  const clearSecureDBForUser = async (pseudonym: string) => {
    try {
      const { SQLiteKV } = await import('../lib/sqlite-kv');
      await (SQLiteKV as any).purgeUserDb(pseudonym);
    } catch {
    }
  };

  const handleAccountSubmit = async (
    mode: "login" | "register",
    userInput: string,
    password: string,
    passphrase?: string
  ) => {
    if (isSubmittingAuth) {
      return;
    }
    setIsSubmittingAuth(true);
    setLoginError("");
    setIsRegistrationMode(mode === "register");
    setAuthStatus(mode === "register" ? "Creating account..." : "Authenticating...");

    const trimmedUsername = userInput.trim();
    if (!trimmedUsername || trimmedUsername.length > 120 || /[^a-zA-Z0-9._-]/.test(trimmedUsername)) {
      setLoginError('Invalid username format');
      setIsSubmittingAuth(false);
      return;
    }
    if (password.length > 1024) {
      setLoginError('Password too long');
      setIsSubmittingAuth(false);
      return;
    }

    originalUsernameRef.current = trimmedUsername;
    const pseudonym = await pseudonymizeUsername(trimmedUsername);

    setIsSubmittingAuth(true);

    const prevUser = loginUsernameRef.current;
    if (prevUser && prevUser !== pseudonym) {
      await clearSecureDBForUser(prevUser);
      try {
        if (keyManagerRef.current) {
          keyManagerRef.current.clearKeys();
          await keyManagerRef.current.deleteDatabase();
          keyManagerRef.current = null;
          keyManagerOwnerRef.current = '' as any;
          hybridKeysRef.current = null;
        }
      } catch { }
    }

    loginUsernameRef.current = pseudonym;
    setUsername(pseudonym);
    websocketClient.setUsername(pseudonym);

    passwordRef.current = password;
    passphraseRef.current = passphrase || "";

    storeAuthenticationState(pseudonym);

    try {
      if (!websocketClient.isConnectedToServer()) {
        setAuthStatus("Connecting...");
        await websocketClient.connect();
      }

      const serverKeys = await waitForServerKeys();

      if (passphrase) {
        passphrasePlaintextRef.current = passphrase;
        await initializeKeys(false);
      }

      let localKeys = await getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
        setAuthStatus("Generating keys...");
        const ephemeralDilithium = await PostQuantumSignature.generateKeyPair();
        localKeys = {
          dilithium: {
            secretKey: ephemeralDilithium.secretKey,
            publicKeyBase64: PostQuantumUtils.uint8ArrayToBase64(ephemeralDilithium.publicKey)
          },
          kyber: { secretKey: new Uint8Array(0), publicKeyBase64: "" },
          x25519: { private: new Uint8Array(0), publicKeyBase64: "" }
        };
      }

      const userPayload = {
        usernameSent: pseudonym,
        hybridPublicKeys: {
          x25519PublicBase64: "",
          kyberPublicBase64: "",
          dilithiumPublicBase64: ""
        }
      };

      setAuthStatus("Encrypting...");

      const withTimeout = <T,>(p: Promise<T>, ms: number, label: string) => new Promise<T>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
        p.then((v) => { clearTimeout(t); resolve(v as T); }).catch((e) => { clearTimeout(t); reject(e); });
      });
      const encryptedPayload = await withTimeout(
        CryptoUtils.Hybrid.encryptForServer(
          userPayload,
          serverKeys,
          {
            senderDilithiumSecretKey: localKeys.dilithium.secretKey,
            metadata: {
              context: 'account-meta',
              sender: { dilithiumPublicKey: localKeys.dilithium.publicKeyBase64 }
            }
          }
        ),
        15000,
        'encrypt user payload'
      );

      let passwordToSend: string;
      if (mode === "register") {
        setAuthStatus("Attesting device...");

        // 1. Request challenge
        const challengePromise = new Promise<string>((resolve, reject) => {
          const timeout = setTimeout(() => {
            websocketClient.unregisterMessageHandler(SignalType.DEVICE_CHALLENGE);
            reject(new Error('Timeout waiting for device challenge'));
          }, 5000);

          websocketClient.registerMessageHandler(SignalType.DEVICE_CHALLENGE, (message: any) => {
            clearTimeout(timeout);
            websocketClient.unregisterMessageHandler(SignalType.DEVICE_CHALLENGE);
            resolve(message.challenge);
          });
        });

        websocketClient.send(JSON.stringify({ type: SignalType.DEVICE_CHALLENGE_REQUEST }));
        const challenge = await challengePromise;

        // 2. Sign challenge
        const { deviceCredentialManager } = await import('../lib/device-credential');
        const attestation = await deviceCredentialManager.signChallenge(challenge);

        // 3. Send attestation
        const ackPromise = new Promise<void>((resolve, reject) => {
          const timeout = setTimeout(() => {
            websocketClient.unregisterMessageHandler(SignalType.DEVICE_ATTESTATION_ACK);
            reject(new Error('Timeout waiting for attestation ack'));
          }, 5000);

          websocketClient.registerMessageHandler(SignalType.DEVICE_ATTESTATION_ACK, () => {
            clearTimeout(timeout);
            websocketClient.unregisterMessageHandler(SignalType.DEVICE_ATTESTATION_ACK);
            resolve();
          });
        });

        websocketClient.send(JSON.stringify({
          type: SignalType.DEVICE_ATTESTATION,
          attestation
        }));
        await ackPromise;

        setAuthStatus("Hashing...");
        passwordToSend = await CryptoUtils.Hash.hashData(password);
      } else {
        passwordToSend = 'REQUEST_PASSWORD_PARAMS';
      }

      setAuthStatus("Securing...");
      const encryptedPassword = await withTimeout(
        CryptoUtils.Hybrid.encryptForServer(
          { content: passwordToSend },
          serverKeys,
          {
            senderDilithiumSecretKey: localKeys.dilithium.secretKey,
            metadata: {
              context: 'account-password',
              sender: { dilithiumPublicKey: localKeys.dilithium.publicKeyBase64 }
            }
          }
        ),
        15000,
        'encrypt password payload'
      );

      const payload = {
        type: mode === "register" ? SignalType.ACCOUNT_SIGN_UP : SignalType.ACCOUNT_SIGN_IN,
        userData: encryptedPayload,
        passwordData: encryptedPassword
      };

      setAuthStatus("Sending...");
      websocketClient.send(JSON.stringify(payload));
    } catch (_error) {
      setAuthStatus('');
      setLoginError(_error instanceof Error ? _error.message : 'Authentication request failed');
      setIsSubmittingAuth(false);
    } finally {
      setIsGeneratingKeys(false);
    }
  };

  const handleServerPasswordSubmit = async (password: string) => {
    setLoginError("");
    setAuthStatus("Verifying...");

    try {
      if (!websocketClient.isConnectedToServer()) {
        try {
          await websocketClient.connect();
        } catch {
          setAuthStatus("");
          setLoginError('Failed to connect');
          return;
        }
      }

      const serverKeys = await waitForServerKeys();

      setAuthStatus("Encrypting...");
      const localKeys = await getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
        throw new Error('Keys required');
      }

      const encryptedPassword = await CryptoUtils.Hybrid.encryptForServer(
        { content: password },
        serverKeys,
        {
          senderDilithiumSecretKey: localKeys.dilithium.secretKey,
          metadata: {
            context: 'server-password',
            sender: { dilithiumPublicKey: localKeys.dilithium.publicKeyBase64 }
          }
        }
      );

      const loginInfo = {
        type: SignalType.SERVER_LOGIN,
        passwordData: encryptedPassword
      };

      setAuthStatus("Authenticating...");
      websocketClient.send(JSON.stringify(loginInfo));
    } catch (_error) {
      setAuthStatus('');
      setLoginError(_error instanceof Error ? _error.message : "Encryption failed");
    }
  };

  const handlePassphraseSubmit = async (passphrase: string, mode: "login" | "register") => {
    passphrasePlaintextRef.current = passphrase;
    setAuthStatus("Processing...");

    try {
      const limiter = passphraseLimiterRef.current;
      const now = Date.now();
      const elapsed = now - limiter.last;
      limiter.last = now;
      const refill = Math.floor(elapsed / 2000);
      limiter.tokens = Math.min(5, limiter.tokens + refill);
      if (limiter.tokens <= 0) {
        const wait = 2000 - (elapsed % 2000);
        await new Promise((resolve) => setTimeout(resolve, wait));
        limiter.tokens = Math.min(5, limiter.tokens + 1);
        limiter.last = Date.now();
      }
      limiter.tokens -= 1;

      const isInRecoveryMode = recoveryActive || (isLoggedIn && accountAuthenticated && !passphraseHashParams);
      if (mode === "login" && passphraseHashParams) {
        await initializeKeys(isInRecoveryMode, passphraseHashParams.salt, passphraseHashParams);
      } else {
        await initializeKeys(isInRecoveryMode);
      }

      const isRecoveryMode = isLoggedIn && accountAuthenticated && !passphraseHashParams;

      if (isRecoveryMode) {
        setShowPassphrasePrompt(false);
        setRecoveryActive(false);
        setAuthStatus("Verified");
        setTimeout(() => setAuthStatus(""), 2000);
        return;
      }

      let passphraseHash: string;
      const combinedSecret = deriveEffectivePassphrase();

      if (mode === "login") {
        if (!passphraseHashParams) {
          setAuthStatus("Retrieving parameters...");
          throw new Error("Missing parameters");
        }

        setAuthStatus("Hashing...");
        passphraseHash = await CryptoUtils.Hash.hashDataUsingInfo(
          combinedSecret,
          passphraseHashParams
        );
      } else {
        setAuthStatus("Generating hash...");
        passphraseHash = await CryptoUtils.Hash.hashData(combinedSecret);
      }

      passphraseRef.current = passphraseHash;

      setAuthStatus("Sending...");
      const messageToSend = {
        type: SignalType.PASSPHRASE_HASH,
        passphraseHash
      };

      websocketClient.send(JSON.stringify(messageToSend));

      if (keyManagerRef.current) {
        const waitForServerResponse = (timeoutMs = 20000) => new Promise<{ success: boolean; error?: string }>((resolve) => {
          let timeout: any;
          const onStatus = (ev: Event) => {
            try {
              const detail: any = (ev as CustomEvent).detail || {};
              if (typeof detail?.success === 'boolean') {
                cleanup();
                resolve({ success: detail.success, error: detail.error });
              }
            } catch { }
          };
          const onDisconnect = () => {
            cleanup();
            resolve({ success: false, error: 'Server disconnected due to missing or invalid bundle' });
          };
          const cleanup = () => {
            clearTimeout(timeout);
            window.removeEventListener('libsignal-publish-status', onStatus as EventListener);
            window.removeEventListener('beforeunload', onDisconnect);
          };
          window.addEventListener('libsignal-publish-status', onStatus as EventListener);
          window.addEventListener('beforeunload', onDisconnect);
          timeout = setTimeout(() => {
            cleanup();
            resolve({ success: false, error: 'Server did not respond to bundle publication' });
          }, timeoutMs);
        });

        try {
          setAuthStatus("Checking identity...");
          let identityExists = false;
          try {
            const existing = await (window as any).edgeApi.getPreKeyBundle?.({ username: loginUsernameRef.current });
            if (existing && existing.identityKeyBase64) {
              identityExists = true;
            }
          } catch {
            identityExists = false;
          }

          if (!identityExists) {
            setAuthStatus("Generating identity...");
            const identityResult = await (window as any).edgeApi.generateIdentity({ username: loginUsernameRef.current });

            if (!identityResult?.success) {
              const error = identityResult?.error || 'Failed to generate identity (native module may be missing)';

              websocketClient.send(JSON.stringify({
                type: 'signal-bundle-failure',
                error,
                stage: 'identity-generation',
                username: loginUsernameRef.current
              }));

              setAuthStatus('');
              setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
              try {
                setAccountAuthenticated(false);
                setIsLoggedIn(false);
                setShowPassphrasePrompt(false);
                setMaxStepReached('login');
              } catch { }
              return;
            }
          }

          setAuthStatus("Generating prekeys...");
          const prekeysResult = await (window as any).edgeApi.generatePreKeys({
            username: loginUsernameRef.current,
            startId: 1,
            count: 100
          });

          if (!prekeysResult?.success) {
            const error = prekeysResult?.error || 'Failed to generate prekeys';

            websocketClient.send(JSON.stringify({
              type: 'signal-bundle-failure',
              error,
              stage: 'prekey-generation',
              username: loginUsernameRef.current
            }));

            setAuthStatus('');
            setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
            try {
              setAccountAuthenticated(false);
              setIsLoggedIn(false);
              setShowPassphrasePrompt(false);
              setMaxStepReached('login');
            } catch { }
            return;
          }

          setAuthStatus("Publishing bundle...");
          const bundle = await (window as any).edgeApi.getPreKeyBundle({ username: loginUsernameRef.current });

          if (bundle?.success === false || bundle?.error) {
            const error = bundle.error || 'Failed to create pre-key bundle';

            websocketClient.send(JSON.stringify({
              type: 'signal-bundle-failure',
              error,
              stage: 'bundle-creation',
              username: loginUsernameRef.current
            }));

            setAuthStatus('');
            setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
            try {
              setAccountAuthenticated(false);
              setIsLoggedIn(false);
              setShowPassphrasePrompt(false);
              setMaxStepReached('login');
            } catch { }
            return;
          }

          if (!bundle.registrationId || !bundle.identityKeyBase64 || !bundle.signedPreKey) {
            const error = 'Invalid bundle structure returned from Signal handler';

            websocketClient.send(JSON.stringify({
              type: 'signal-bundle-failure',
              error,
              stage: 'bundle-validation',
              username: loginUsernameRef.current
            }));

            setAuthStatus('');
            setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
            try {
              setAccountAuthenticated(false);
              setIsLoggedIn(false);
              setShowPassphrasePrompt(false);
              setMaxStepReached('login');
            } catch { }
            return;
          }

          websocketClient.send(JSON.stringify({ type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE, bundle }));

          setAuthStatus("Verifying bundle...");
          const response = await waitForServerResponse();

          if (!response.success) {
            setAuthStatus('');
            setLoginError(response.error || 'Server did not accept Signal bundle');
            return;
          }

        } catch (_err) {
          const msg = _err instanceof Error ? _err.message : String(_err);

          try {
            websocketClient.send(JSON.stringify({
              type: 'signal-bundle-failure',
              error: msg,
              stage: 'unexpected-error',
              username: loginUsernameRef.current
            }));
          } catch { }

          setAuthStatus('');
          setLoginError(`Signal initialization error: ${msg}`);
          try {
            setAccountAuthenticated(false);
            setIsLoggedIn(false);
            setShowPassphrasePrompt(false);
            setMaxStepReached('login');
          } catch { }
          return;
        }

        if (keyManagerRef.current && serverHybridPublic) {
          const publicKeys = await keyManagerRef.current.getPublicKeys();
          if (publicKeys) {
            const keysToSend = {
              kyberPublicBase64: publicKeys.kyberPublicBase64 || '',
              dilithiumPublicBase64: publicKeys.dilithiumPublicBase64 || '',
              x25519PublicBase64: publicKeys.x25519PublicBase64 || ''
            };

            const hybridKeysPayload = JSON.stringify(keysToSend);

            const localKeys = await getKeysOnDemand();
            if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
              throw new Error('Dilithium keys required for hybrid key update');
            }

            const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(
              hybridKeysPayload,
              serverHybridPublic,
              {
                senderDilithiumSecretKey: localKeys.dilithium.secretKey,
                metadata: {
                  context: 'hybrid-keys-update',
                  sender: { dilithiumPublicKey: localKeys.dilithium.publicKeyBase64 }
                }
              }
            );

            websocketClient.send(JSON.stringify({
              type: SignalType.HYBRID_KEYS_UPDATE,
              userData: encryptedHybridKeys,
            }));
          }
        }
      }
    } catch (_error) {
      if (_error instanceof Error && _error.message.includes('Key decryption failed')) {
        return;
      }
      const message = _error instanceof Error ? _error.message : String(_error);
      try {
        console.error('[Auth] Passphrase processing failed:', message, _error);
      } catch { }
      setLoginError(`Passphrase processing failed: ${message}`);
      throw _error;
    }
  };


  const handleAuthSuccess = async (username: string, isRecovered = false) => {

    if (isRecovered && !passphrasePlaintextRef.current) {
      setAuthStatus("Passphrase required");
      setUsername(username);

      loginUsernameRef.current = username;

      setIsLoggedIn(true);
      setAccountAuthenticated(true);

      storeAuthenticationState(username);

      setRecoveryActive(true);
      setShowPassphrasePrompt(true);
      setIsRegistrationMode(false);
      setLoginError("");
      return;
    }

    setAuthStatus("Authenticated");
    setUsername(username);
    setIsLoggedIn(true);
    setAccountAuthenticated(true);

    storeAuthenticationState(username);

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    setTimeout(() => setAuthStatus(""), 1000);
    setLoginError("");

    try {
      if ((window as any).edgeApi?.setSignalStorageKey) {
        const label = new TextEncoder().encode('signal-storage-key-v1');
        let derived: Uint8Array | null = null;
        try {
          const keys = await getKeysOnDemand?.();
          const kyberSecret: Uint8Array | undefined = keys?.kyber?.secretKey;
          if (kyberSecret && kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
            derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
          } else {
            try {
              const composite = deriveEffectivePassphrase();
              const salt = new TextEncoder().encode('signal-storage-key-v1');
              derived = await (CryptoUtils as any).KDF.argon2id(composite, {
                salt,
                time: 3,
                memoryCost: 1 << 17,
                parallelism: 2,
                hashLen: 32
              });
            } catch { }
          }
          if (derived) {
            const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);
            await (window as any).edgeApi.setSignalStorageKey({ keyBase64: keyB64 });
            if ((derived as any)?.fill) (derived as any).fill(0);
          }
        } catch { }
      }
    } catch { }

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    if (keyManagerRef.current && passphrasePlaintextRef.current) {
      try {
        const effectivePassphrase = deriveEffectivePassphrase();
        keyManagerRef.current.initialize(effectivePassphrase).catch(_error => {
        });
      } catch { }
    }

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    try {
      const { retrieveOfflineMessages } = await import('../lib/offline-message-queue');
      retrieveOfflineMessages();
    } catch { }
  };

  const attemptAuthRecovery = useCallback(async () => {
    const storedUsername = loginUsernameRef.current || syncEncryptedStorage.getItem('last_authenticated_username');

    if (!storedUsername) {
      return false;
    }

    setAuthStatus("Recovering...");

    try {
      if (!websocketClient.isConnectedToServer()) {
        await websocketClient.connect();
      }

      loginUsernameRef.current = storedUsername;
      try { originalUsernameRef.current = storedUsername; } catch { }
      setUsername(storedUsername);

      websocketClient.send(JSON.stringify({
        type: SignalType.AUTH_RECOVERY,
        username: storedUsername
      }));

      return true;
    } catch (_error) {
      setAuthStatus('');
      return false;
    }
  }, []);

  const storeAuthenticationState = useCallback((username: string) => {
    try {
      syncEncryptedStorage.setItem('last_authenticated_username', username);
    } catch { }
  }, []);

  const clearAuthenticationState = useCallback(() => {
    try {
      syncEncryptedStorage.removeItem('last_authenticated_username');
    } catch { }
  }, []);

  const storeUsernameMapping = useCallback(async (secureDBInstance: SecureDB) => {
    if (originalUsernameRef.current && loginUsernameRef.current) {
      try {
        await secureDBInstance.storeUsernameMapping(loginUsernameRef.current, originalUsernameRef.current);
        try {
          window.dispatchEvent(new CustomEvent('username-mapping-updated', { detail: { username: loginUsernameRef.current } }));
        } catch { }
      } catch { }
    }
  }, []);

  const logout = async (secureDBRef?: MutableRefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    try {
      const user = loginUsernameRef.current || '';
      if (user && websocketClient.isConnectedToServer()) {
        try {
          if (websocketClient.isPQSessionEstablished?.()) {
            await websocketClient.sendSecureControlMessage({ type: SignalType.USER_DISCONNECT, username: user, timestamp: Date.now() });
            try { await new Promise(res => setTimeout(res, 25)); } catch { }
          }
        } catch { }
      }
      try { websocketClient.close(); } catch { }
      try { setTimeout(() => { try { void websocketClient.connect(); } catch { } }, 0); } catch { }
    } catch { }

    clearAuthenticationState();
    clearTokenEncryptionKey();

    try {
      secureWipeStringRef(passwordRef as any);
      secureWipeStringRef(passphraseRef as any);
      secureWipeStringRef(passphrasePlaintextRef as any);
      aesKeyRef.current = null;
      hybridKeysRef.current = null;

      if (typeof window !== 'undefined' && (window as any).gc) {
        (window as any).gc();
      }
    } catch { }

    if (secureDBRef?.current) {
      try {
        await secureDBRef.current.clearDatabase();
      } catch { }
      secureDBRef.current = null;
    }


    try {
      const pseudonym = loginUsernameRef.current || '';
      if (pseudonym && (window as any).electronAPI?.secureStore) {
        await (window as any).electronAPI.secureStore.init();
        try { await (window as any).electronAPI.secureStore.remove(`aes:${pseudonym}`); } catch { }
        try { await (window as any).electronAPI.secureStore.remove(`pph:${pseudonym}`); } catch { }
        try { await (window as any).electronAPI.secureStore.remove(`tok:${(window as any).electronAPI?.instanceId || '1'}`); } catch { }
      }
      try { const { removeVaultKey } = await import('../lib/vault-key'); if (pseudonym) await removeVaultKey(pseudonym); } catch { }
    } catch { }


    try {
      syncEncryptedStorage.removeItem('securechat_server_pin_v2');
    } catch { }

    if (keyManagerRef.current) {
      try {
        keyManagerRef.current.clearKeys();
        await keyManagerRef.current.deleteDatabase();
        keyManagerRef.current = null;
      } catch { }
    }

    loginUsernameRef.current = "";

    setIsLoggedIn(false);
    setLoginError(loginErrorMessage);
    setAccountAuthenticated(false);
    setIsRegistrationMode(false);
    setUsername("");

  };

  const useLogout = (Database: { secureDBRef: MutableRefObject<SecureDB | null> }) => {
    return async () => await logout(Database.secureDBRef, "Logged out");
  };

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

    window.addEventListener('auth-ui-back', handleAuthUiBack as EventListener);
    return () => window.removeEventListener('auth-ui-back', handleAuthUiBack as EventListener);
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
    window.addEventListener('auth-ui-input', handleAuthUiInput as EventListener);
    return () => window.removeEventListener('auth-ui-input', handleAuthUiInput as EventListener);
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

    window.addEventListener('auth-ui-forward', handleAuthUiForward as EventListener);
    return () => window.removeEventListener('auth-ui-forward', handleAuthUiForward as EventListener);
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

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isLoggedIn]);

  useEffect(() => {
    const handleReconnection = async () => {
      if (isLoggedIn && loginUsernameRef.current) {
        try {
          await attemptAuthRecovery();
        } catch { }
      }
    };

    window.addEventListener('ws-reconnected', handleReconnection);

    return () => {
      window.removeEventListener('ws-reconnected', handleReconnection);
    };
  }, [isLoggedIn, attemptAuthRecovery]);

  useEffect(() => {
    (async () => {
      try {
        if (isLoggedIn && loginUsernameRef.current && (window as any).edgeApi?.setStaticMlkemKeys) {
          const keys = await getKeysOnDemand?.();
          const pub = keys?.kyber?.publicKeyBase64;
          const secB64 = keys?.kyber?.secretKey ? CryptoUtils.Base64.arrayBufferToBase64(keys.kyber.secretKey) : undefined;
          if (typeof pub === 'string' && typeof secB64 === 'string' && pub && secB64) {
            await (window as any).edgeApi.setStaticMlkemKeys({ username: loginUsernameRef.current, publicKeyBase64: pub, secretKeyBase64: secB64 });
          }
        }
      } catch { }
    })();
  }, [isLoggedIn, loginUsernameRef.current]);

  // Upload hybrid public keys to server after login when keys become available
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
              context: 'hybrid-keys-update',
              sender: { dilithiumPublicKey: keys.dilithium.publicKeyBase64 }
            }
          }
        );

        await websocketClient.sendSecureControlMessage({
          type: SignalType.HYBRID_KEYS_UPDATE,
          userData: encryptedHybridKeys,
        });

        try {
          window.dispatchEvent(new CustomEvent('hybrid-keys-updated'));
        } catch { }
      } catch (_err) {
      }
    };

    uploadKeys();
  }, [isLoggedIn, serverHybridPublic, hybridKeysRef.current]);

  useEffect(() => {
    (async () => {
      try {
        const tokens = await retrieveAuthTokens();
        if (tokens?.accessToken && tokens?.refreshToken) {
          setTokenValidationInProgress(true);
          setAuthStatus('Verifying session...');
          const storedUsername = syncEncryptedStorage.getItem('last_authenticated_username');
          if (storedUsername) {
            loginUsernameRef.current = storedUsername;
            setUsername(storedUsername);
          }
        } else {
          setTokenValidationInProgress(false);
          setAuthStatus('');
        }
      } catch {
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
    window.addEventListener('token-validation-start', onTokenValidationStart as EventListener);
    return () => window.removeEventListener('token-validation-start', onTokenValidationStart as EventListener);
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
    window.addEventListener('token-validation-timeout', onTokenValidationTimeout as EventListener);
    return () => window.removeEventListener('token-validation-timeout', onTokenValidationTimeout as EventListener);
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

      if (accountAuthenticated && !showPassphrasePrompt) {
        setShowPassphrasePrompt(true);
      }

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
          } catch (_error) {
            setShowPasswordPrompt(true);
            setAuthStatus("Password required");
          }
        })();
      } else {
        setShowPasswordPrompt(true);
        setAuthStatus("Password required");
      }
    };

    window.addEventListener('password-hash-params', handlePasswordHashParams as EventListener);

    return () => {
      window.removeEventListener('password-hash-params', handlePasswordHashParams as EventListener);
    };
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
      } catch (_e) {
        setLoginError('Password processing failed');
      }
    },
    logout,
    useLogout,
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
