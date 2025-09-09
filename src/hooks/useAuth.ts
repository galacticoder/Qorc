import { useState, useRef, useCallback, useEffect, MutableRefObject } from "react";
import { SignalType } from "../lib/signals";
import websocketClient from "../lib/websocket";
import { CryptoUtils } from "../lib/unified-crypto";
import { SecureDB } from "../lib/secureDB";
import { SecureKeyManager } from "../lib/secure-key-manager";
import { pseudonymizeUsername, pseudonymizeUsernameWithCache } from "../lib/username-hash";
// Legacy pinned server removed; use simple in-memory pinning here
const PinnedServer = {
  get() {
    try {
      const stored = localStorage.getItem('securechat_server_pin_v1');
      if (!stored || stored.length > 10000) return null; // SECURITY: Prevent DoS via large JSON
      
      const parsed = JSON.parse(stored);
      // SECURITY: Validate parsed object structure
      if (!parsed || typeof parsed !== 'object') return null;
      if (!parsed.x25519PublicBase64 || !parsed.kyberPublicBase64) return null;
      if (typeof parsed.x25519PublicBase64 !== 'string' || typeof parsed.kyberPublicBase64 !== 'string') return null;
      
      return parsed;
    } catch { return null; }
  },
  set(val: any) {
    try { 
      // SECURITY: Validate input before storing
      if (!val || typeof val !== 'object') return;
      if (!val.x25519PublicBase64 || !val.kyberPublicBase64) return;
      if (typeof val.x25519PublicBase64 !== 'string' || typeof val.kyberPublicBase64 !== 'string') return;
      
      localStorage.setItem('securechat_server_pin_v1', JSON.stringify(val)); 
    } catch {}
  }
};

export const useAuth = (secureDB?: SecureDB) => {
  const [username, setUsername] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [authStatus, setAuthStatus] = useState<string>("");
  const [loginError, setLoginError] = useState("");
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const [isRegistrationMode, setIsRegistrationMode] = useState(false);
  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);

  const [serverHybridPublic, setServerHybridPublic] = useState<{
    x25519PublicBase64: string;
    kyberPublicBase64: string
  } | null>(null);

  //trust prompt for server key changes
  const [serverTrustRequest, setServerTrustRequest] = useState<{
    newKeys: { x25519PublicBase64: string; kyberPublicBase64: string };
    pinned: { x25519PublicBase64: string; kyberPublicBase64: string } | null;
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
    x25519: { private: any; publicKeyBase64: string };
    kyber: { publicKeyBase64: string; secretKey: Uint8Array };
    dilithium?: { publicKeyBase64: string; secretKey: Uint8Array };
  } | null>(null);

  const keyManagerRef = useRef<SecureKeyManager | null>(null);
  const loginUsernameRef = useRef("");
  // Keep original username only on client; never send to server
  const originalUsernameRef = useRef<string>("");

  const getKeysOnDemand = useCallback(async () => {
    console.log('[AUTH] Getting keys on demand');
    if (!keyManagerRef.current) {
      console.error("[AUTH] Key manager not initialized");
      return null;
    }

    if (!passphrasePlaintextRef.current) {
      console.error("[AUTH] Passphrase not available");
      return null;
    }

    try {
      // Check if we already have keys in memory first
      if (hybridKeysRef.current) {
        console.debug('[AUTH] Using cached keys from memory');
        return hybridKeysRef.current;
      }

      // Try to get keys without re-initializing first
      let keys = await keyManagerRef.current.getKeys().catch(() => null);

      if (!keys) {
        console.log('[AUTH] Keys not available, initializing key manager');
        const metadata = await keyManagerRef.current.getKeyMetadata();
        if (metadata) {
          await keyManagerRef.current.initialize(passphrasePlaintextRef.current, metadata.salt);
        } else {
          await keyManagerRef.current.initialize(passphrasePlaintextRef.current);
        }
        keys = await keyManagerRef.current.getKeys();
      }

      console.log('[AUTH] Keys retrieved successfully');

      if (!keys) {
        console.error('[AUTH] Keys are null after retrieval');
        return null;
      }

      // Validate key structure
      if (!keys.x25519 || !keys.kyber) {
        console.error('[AUTH] Invalid key structure:', { hasX25519: !!keys.x25519, hasKyber: !!keys.kyber });
        return null;
      }

      console.debug('[AUTH] Keys validation passed', {
        x25519PublicLen: keys.x25519.publicKeyBase64?.length,
        kyberPublicLen: keys.kyber.publicKeyBase64?.length,
        x25519PrivateLen: keys.x25519.private?.byteLength,
        kyberSecretLen: keys.kyber.secretKey?.byteLength,
        hasDilithium: !!keys.dilithium,
        dilithiumPublicLen: keys.dilithium?.publicKeyBase64?.length,
        dilithiumSecretLen: keys.dilithium?.secretKey?.byteLength
      });

      // Cache the keys for future use
      hybridKeysRef.current = keys;

      return keys;
    } catch (error) {
      console.error("[AUTH] Error loading keys on demand:", error);
      return null;
    }
  }, []);

  const passwordRef = useRef<string>("");
  const [passphraseHashParams, setPassphraseHashParams] = useState(null);
  const [passwordHashParams, setPasswordHashParams] = useState(null);
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);

  const initializeKeys = useCallback(async () => {
    console.log('[AUTH] Starting key initialization process');
    setIsGeneratingKeys(true);
    setAuthStatus("Initializing secure key manager...");
    try {
      const passphrase = passphrasePlaintextRef.current;
      if (!passphrase) {
        console.error("[AUTH] Passphrase not available for key generation");
        throw new Error("Passphrase not available for key generation");
      }

      const currentUsername = loginUsernameRef.current;
      if (!currentUsername) {
        console.error("[AUTH] Username not available for key generation");
        throw new Error("Username not available for key generation");
      }

      console.log(`[AUTH] Initializing key manager for user: ${currentUsername}`);
      if (!keyManagerRef.current) {
        keyManagerRef.current = new SecureKeyManager(currentUsername);
      }

      const hasExistingKeys = await keyManagerRef.current.hasKeys();

      if (hasExistingKeys) {
        console.log('[AUTH] Loading existing keys');
        setAuthStatus("Loading existing encryption keys...");
        await keyManagerRef.current.initialize(passphrase);
        const existingKeys = await keyManagerRef.current.getKeys();
        if (existingKeys) {
          console.log('[AUTH] Existing keys loaded successfully');
          setAuthStatus("Verifying key integrity...");
          try {
            console.debug('[AUTH] Existing keys summary', {
              x25519PublicBase64: existingKeys.x25519.publicKeyBase64?.slice(0, 28) + '...',
              kyberPublicBase64: existingKeys.kyber.publicKeyBase64?.slice(0, 28) + '...',
              x25519PrivateLen: existingKeys.x25519.private?.length,
              kyberSecretLen: existingKeys.kyber.secretKey?.length,
              hasDilithium: !!existingKeys.dilithium,
              dilithiumPublicBase64: existingKeys.dilithium?.publicKeyBase64?.slice(0, 28) + '...',
              dilithiumSecretLen: existingKeys.dilithium?.secretKey?.length,
            });
          } catch { }
          hybridKeysRef.current = existingKeys;
        }
      } else {
        console.log('[AUTH] Generating new hybrid key pair');
        setAuthStatus("Generating post-quantum encryption keys...");
        const seed = await CryptoUtils.Hash.hashData(passphrase + currentUsername);
        setAuthStatus("Creating hybrid cryptographic key pair...");
        const hybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPairFromSeed(seed);

        setAuthStatus("Securing keys with passphrase...");
        await keyManagerRef.current.initialize(passphrase);
        setAuthStatus("Storing encrypted keys securely...");
        await keyManagerRef.current.storeKeys(hybridKeyPair);

        console.log('[AUTH] New keys generated and stored successfully');
        try {
          console.debug('[AUTH] New keys summary', {
            x25519PublicBase64: hybridKeyPair.x25519.publicKeyBase64?.slice(0, 28) + '...',
            kyberPublicBase64: hybridKeyPair.kyber.publicKeyBase64?.slice(0, 28) + '...',
            x25519PrivateLen: hybridKeyPair.x25519.private?.length,
            kyberSecretLen: hybridKeyPair.kyber.secretKey?.length,
            hasDilithium: !!hybridKeyPair.dilithium,
            dilithiumPublicBase64: hybridKeyPair.dilithium?.publicKeyBase64?.slice(0, 28) + '...',
            dilithiumSecretLen: hybridKeyPair.dilithium?.secretKey?.length,
          });
        } catch { }
        hybridKeysRef.current = hybridKeyPair;
      }
    } catch (error) {
      console.error("[AUTH] Error generating keys: ", error);
      setLoginError("Key generation failed");
    } finally {
      setIsGeneratingKeys(false);
      setAuthStatus("");
    }
  }, []);

  const handleAccountSubmit = async (
    mode: "login" | "register",
    userInput: string,
    password: string,
    passphrase?: string
  ) => {
    console.log(`[AUTH] Starting ${mode} process for user (client-only original): ${userInput}`);
    setLoginError("");
    setIsRegistrationMode(mode === "register");
    setAuthStatus(mode === "register" ? "Creating new account..." : "Authenticating account...");

    // Store original username locally only; never send to server
    originalUsernameRef.current = userInput;

    // Compute pseudonym for all server-facing operations
    // Use non-cached version during login since SecureDB isn't initialized yet
    console.log(`[AUTH] Computing pseudonym for username: "${userInput}"`);
    const pseudonym = await pseudonymizeUsername(userInput);
    console.log(`[AUTH] Generated pseudonym: "${pseudonym}" (length: ${pseudonym.length})`);

    // Use pseudonym as canonical identity
    loginUsernameRef.current = pseudonym;
    setUsername(pseudonym);
    passwordRef.current = password;
    passphraseRef.current = passphrase || "";

    try {
      if (!serverHybridPublic) {
        console.error("[AUTH] Server public keys not available");
        throw new Error("Server public keys not available");
      }

      if (!websocketClient.isConnectedToServer()) {
        console.log('[AUTH] Connecting to WebSocket server');
        setAuthStatus("Connecting to secure server...");
        await websocketClient.connect();
      }

      if (passphrase) {
        console.log('[AUTH] Passphrase provided, initializing keys');
        passphrasePlaintextRef.current = passphrase;
        await initializeKeys();
      }

      const userPayload = {
        // Only send pseudonym to server
        usernameSent: pseudonym,
        hybridPublicKeys: {
          x25519PublicBase64: "",
          kyberPublicBase64: ""
        }
      };

      console.log(`[AUTH] Client userPayload before encryption:`, JSON.stringify(userPayload, null, 2));

      setAuthStatus("Encrypting user data with hybrid cryptography...");
      const encryptedPayload = await CryptoUtils.Hybrid.encryptHybridPayload(
        userPayload,
        serverHybridPublic
      );

      // For new registrations, hash password client-side with Argon2
      // For existing users, send plaintext to get proper Argon2 parameters from server
      let passwordToSend: string;
      if (mode === "register") {
        setAuthStatus("Hashing password with Argon2...");
        console.log('[AUTH] Hashing password client-side using Argon2 for new registration');
        passwordToSend = await CryptoUtils.Hash.hashData(password);
        console.log(`[AUTH] Password hashed client-side for registration, hash length: ${passwordToSend.length}`);
      } else {
        // For login, request Argon2 parameters without sending plaintext password
        console.log('[AUTH] Requesting password hash parameters (no plaintext password sent)');
        passwordToSend = 'REQUEST_PASSWORD_PARAMS';
      }
      
      setAuthStatus("Encrypting password with post-quantum security...");
      const encryptedPassword = await CryptoUtils.Hybrid.encryptHybridPayload(
        { content: passwordToSend },
        serverHybridPublic
      );

      const payload = {
        type: mode === "register" ? SignalType.ACCOUNT_SIGN_UP : SignalType.ACCOUNT_SIGN_IN,
        userData: encryptedPayload,
        passwordData: encryptedPassword
      };

      console.log(`[AUTH] Sending ${mode} request to server`);
      setAuthStatus(`Sending secure ${mode} request to server...`);
      websocketClient.send(JSON.stringify(payload));
    } catch (error) {
      console.error(`[AUTH] ${mode} submission failed:`, error);
      setAuthStatus('');
      setLoginError('Submission error: Authentication request failed');
    }
  };

  const handleServerPasswordSubmit = async (password: string) => {
    console.log('[AUTH] Submitting server password');
    setLoginError("");
    setAuthStatus("Verifying server access credentials...");
    if (!serverHybridPublic) {
      setLoginError("Server keys not available");
      return;
    }

    try {
      if (!websocketClient.isConnectedToServer()) {
        try {
          await websocketClient.connect();
        } catch (error) {
          setAuthStatus("");
          setLoginError('Failed to connect to server: Connection error');
          return;
        }
      }

      setAuthStatus("Encrypting server password with hybrid cryptography...");
      const encryptedPassword = await CryptoUtils.Hybrid.encryptHybridPayload(
        { content: password },
        serverHybridPublic
      );
      // SECURITY: Log only non-sensitive metadata
      try {
        console.debug('[AUTH] Password payload encrypted (hybrid-v1)', {
          hasEphemeralX25519Public: !!(encryptedPassword as any).ephemeralX25519Public,
          kyberCiphertextLen: ((encryptedPassword as any).kyberCiphertext || '').length,
          encryptedMessageLen: ((encryptedPassword as any).encryptedMessage || '').length,
          // SECURITY: No actual key material or content logged
        });
      } catch { }

      const loginInfo = {
        type: SignalType.SERVER_LOGIN,
        passwordData: encryptedPassword
      };

      console.log('[AUTH] Sending server password to server');
      setAuthStatus("Authenticating with server...");
      websocketClient.send(JSON.stringify(loginInfo));
      // Do not overwrite loginUsernameRef with any original string here
    } catch (error) {
      console.error("Login failed: ", error);
      setLoginError("Password encryption failed");
    }
  };

  const handlePassphraseSubmit = async (passphrase: string, mode: "login" | "register") => {
    console.log(`[AUTH] Submitting passphrase for ${mode} mode`);
    passphrasePlaintextRef.current = passphrase;
    setAuthStatus("Processing secure passphrase...");

    try {
      await initializeKeys();

      // Check if this is a recovery mode (already authenticated but need passphrase for functionality)
      const isRecoveryMode = isLoggedIn && accountAuthenticated && !passphraseHashParams;
      
      if (isRecoveryMode) {
        console.log('[AUTH] Passphrase provided for recovery mode - enabling full functionality');
        setShowPassphrasePrompt(false);
        setAuthStatus("Passphrase verified - full functionality enabled!");
        
        // Clear status after a brief delay
        setTimeout(() => setAuthStatus(""), 2000);
        return;
      }

      let passphraseHash: string;

      if (mode === "login") {
        if (!passphraseHashParams) {
          setAuthStatus("Retrieving secure hash parameters...");
          throw new Error("Missing passphrase parameters");
        }

        setAuthStatus("Computing secure passphrase hash with Argon2...");
        passphraseHash = await CryptoUtils.Hash.hashDataUsingInfo(
          passphrase,
          passphraseHashParams
        );
      } else {
        setAuthStatus("Generating secure passphrase hash...");
        passphraseHash = await CryptoUtils.Hash.hashData(passphrase);
      }

      passphraseRef.current = passphraseHash;

      console.log(`[AUTH] Sending passphrase hash to server`);
      setAuthStatus("Sending secure hash to server...");
      websocketClient.send(JSON.stringify({
        type: mode === "register"
          ? SignalType.PASSPHRASE_HASH_NEW
          : SignalType.PASSPHRASE_HASH,
        passphraseHash
      }));

      // publish official libsignal bundle via edge IPC and publish to server; keep legacy hybrid pub for DB
      if (keyManagerRef.current) {
        try {
          setAuthStatus("Generating Signal Protocol identity...");
          await (window as any).edgeApi.generateIdentity({ username: loginUsernameRef.current });
          setAuthStatus("Creating Signal Protocol prekeys...");
          await (window as any).edgeApi.generatePreKeys({ username: loginUsernameRef.current });
          setAuthStatus("Publishing Signal Protocol bundle...");
          const bundle = await (window as any).edgeApi.getPreKeyBundle({ username: loginUsernameRef.current });
          websocketClient.send(JSON.stringify({ type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE, bundle: { ...bundle } }));
        } catch (err) {
          console.error('[AUTH] Failed to publish libsignal bundle:', err);
        }

        // also publish legacy hybrid public keys so server can encrypt system messages immediately
        if (keyManagerRef.current && serverHybridPublic) {
          const publicKeys = await keyManagerRef.current.getPublicKeys();
          if (publicKeys) {
            const hybridKeysPayload = {
              usernameSent: loginUsernameRef.current,
              hybridPublicKeys: {
                x25519PublicBase64: publicKeys.x25519PublicBase64,
                kyberPublicBase64: publicKeys.kyberPublicBase64,
                dilithiumPublicBase64: publicKeys.dilithiumPublicBase64,
              },
            };

            const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptHybridPayload(
              hybridKeysPayload,
              serverHybridPublic
            );

            websocketClient.send(JSON.stringify({
              type: SignalType.HYBRID_KEYS_UPDATE,
              userData: encryptedHybridKeys,
            }));
          }
        }
      }
    } catch (error) {
      console.error("Passphrase hashing failed:", error);
      setLoginError("Passphrase processing failed");
    }
  };

  const handlePasswordHashSubmit = async (password: string) => {
    console.log(`[AUTH] Submitting password hash response`);
    setAuthStatus("Processing password hash...");

    try {
      if (!passwordHashParams) {
        setAuthStatus("Retrieving password hash parameters...");
        throw new Error("Missing password hash parameters");
      }

      setAuthStatus("Computing secure password hash with Argon2...");
      const passwordHash = await CryptoUtils.Hash.hashDataUsingInfo(
        password,
        passwordHashParams
      );

      console.log(`[AUTH] Sending password hash to server`);
      setAuthStatus("Sending secure password hash to server...");
      websocketClient.send(JSON.stringify({
        type: SignalType.PASSWORD_HASH_RESPONSE,
        passwordHash
      }));
      
      // Clear the password prompt after sending the response
      setShowPasswordPrompt(false);
      setAuthStatus("Password verification in progress...");
    } catch (error) {
      console.error("Password hashing failed:", error);
      setLoginError("Password processing failed");
      setAuthStatus("");
    }
  };

  const handleAuthSuccess = async (username: string, isRecovered = false) => {
    console.log(`[AUTH] Authentication success for user: ${username} (recovered: ${isRecovered})`);
    console.log(`[AUTH] Setting authentication flags - isLoggedIn: true, accountAuthenticated: true`);
    
    // For recovered authentication without passphrase, prompt for passphrase
    if (isRecovered && !passphrasePlaintextRef.current) {
      console.log('[AUTH] Authentication recovered but passphrase needed for full functionality');
      setAuthStatus("Authentication recovered - passphrase required for full functionality");
      setUsername(username);
      
      // CRITICAL: Set loginUsernameRef for recovered authentication
      loginUsernameRef.current = username;
      console.log(`[AUTH] Set loginUsernameRef.current to recovered username: ${username}`);
      
      setIsLoggedIn(true);
      setAccountAuthenticated(true);
      
      // Store authentication state for future recovery
      storeAuthenticationState(username);
      
      // Prompt for passphrase to enable full functionality
      setShowPassphrasePrompt(true);
      setIsRegistrationMode(false); // This is a login scenario
      setLoginError("");
      return;
    }
    
    setAuthStatus(isRecovered ? "Authentication recovered successfully!" : "Authentication successful! Logging in...");
    setUsername(username);
    console.log(`[AUTH] About to call setIsLoggedIn(true) - current value: ${isLoggedIn}`);
    setIsLoggedIn(true);
    setAccountAuthenticated(true);
    console.log(`[AUTH] Called setIsLoggedIn(true) and setAccountAuthenticated(true)`);
    
    // Store authentication state for future recovery
    storeAuthenticationState(username);
    
    // Clear status after a brief delay
    setTimeout(() => setAuthStatus(""), 1000);
    setLoginError("");

    if (keyManagerRef.current && passphrasePlaintextRef.current) {
      keyManagerRef.current.initialize(passphrasePlaintextRef.current).catch(error => {
        console.error("Failed to initialize key manager after auth success:", error);
      });
    }
  };

  // Authentication recovery function
  const attemptAuthRecovery = useCallback(async () => {
    const storedUsername = loginUsernameRef.current || localStorage.getItem('last_authenticated_username');
    
    if (!storedUsername) {
      console.log('[AUTH] No stored username found for auth recovery');
      return false;
    }

    console.log(`[AUTH] Attempting authentication recovery for user: ${storedUsername}`);
    setAuthStatus("Recovering authentication state...");
    
    try {
      if (!websocketClient.isConnectedToServer()) {
        console.log('[AUTH] Connecting to WebSocket server for auth recovery');
        await websocketClient.connect();
      }

      // Send auth recovery request
      websocketClient.send(JSON.stringify({
        type: SignalType.AUTH_RECOVERY,
        username: storedUsername
      }));

      return true;
    } catch (error) {
      console.error('[AUTH] Auth recovery attempt failed:', error);
      setAuthStatus('');
      return false;
    }
  }, []);

  // Store username for recovery on successful authentication
  const storeAuthenticationState = useCallback((username: string) => {
    try {
      localStorage.setItem('last_authenticated_username', username);
      console.log(`[AUTH] Stored authentication state for recovery: ${username}`);
    } catch (error) {
      console.error('[AUTH] Failed to store authentication state:', error);
    }
  }, []);

  // Clear stored authentication state
  const clearAuthenticationState = useCallback(() => {
    try {
      localStorage.removeItem('last_authenticated_username');
      console.log('[AUTH] Cleared stored authentication state');
    } catch (error) {
      console.error('[AUTH] Failed to clear authentication state:', error);
    }
  }, []);

  // Function to store username mapping (called from outside when SecureDB is ready)
  const storeUsernameMapping = useCallback(async (secureDBInstance: SecureDB) => {
    if (originalUsernameRef.current && loginUsernameRef.current) {
      try {
        console.log(`[AUTH] Storing username mapping: ${loginUsernameRef.current} -> ${originalUsernameRef.current}`);
        await secureDBInstance.storeUsernameMapping(loginUsernameRef.current, originalUsernameRef.current);
        console.log(`[AUTH] Username mapping stored successfully`);
      } catch (error) {
        console.error('[AUTH] Failed to store username mapping:', error);
      }
    }
  }, []);

  const handlePassphraseSuccess = () => {
    console.log(`[AUTH] Passphrase success - registration mode: ${isRegistrationMode}`);
    // Both registration and login should continue to server password prompt
    // The server password is a security feature required for both flows
  };

  const logout = async (secureDBRef?: MutableRefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    console.log('[AUTH] Logging out user');

    // Clear stored authentication state for recovery
    clearAuthenticationState();

    // SECURITY: Clear sensitive data from memory first
    try {
      // Clear sensitive references immediately
      passwordRef.current = "";
      passphraseRef.current = "";
      passphrasePlaintextRef.current = "";
      aesKeyRef.current = null;
      hybridKeysRef.current = null;

      // SECURITY: Force garbage collection of sensitive data if available
      if (typeof window !== 'undefined' && (window as any).gc) {
        (window as any).gc();
      }
    } catch (error) {
      console.error('[AUTH] Failed to clear sensitive data from memory:', error);
    }

    // Clear SecureDB database
    if (secureDBRef?.current) {
      try {
        console.log('[AUTH] Clearing SecureDB database');
        await secureDBRef.current.clearDatabase();
        console.log('[AUTH] SecureDB database cleared successfully');
      } catch (error) {
        console.error('[AUTH] Failed to clear SecureDB database:', error);
      }
      secureDBRef.current = null;
    }

    // SECURITY: Enhanced session data cleanup
    try { 
      if (typeof window !== 'undefined' && window.localStorage) {
        const keysToRemove: string[] = [];
        const currentUser = loginUsernameRef.current || '';
        
        // SECURITY: Safely iterate through localStorage
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          if (key && currentUser && (
            key.includes('session') && key.includes(currentUser) ||
            key.includes('securechat') && key.includes(currentUser) ||
            key.includes('keystore') && key.includes(currentUser) ||
            key.includes('identity') && key.includes(currentUser)
          )) {
            keysToRemove.push(key);
          }
        }
        
        // SECURITY: Remove keys in a separate loop to avoid iteration issues
        keysToRemove.forEach(key => {
          try {
            window.localStorage.removeItem(key);
          } catch (error) {
            console.error(`[AUTH] Failed to remove localStorage key ${key}:`, error);
          }
        });
        
        console.log(`[AUTH] Cleared ${keysToRemove.length} localStorage keys`);
      }
    } catch (error) {
      console.error('[AUTH] Failed to clear session data:', error);
    }

    // Clear localStorage data for the current user
    if (loginUsernameRef.current) {
      try {
        console.log('[AUTH] Clearing localStorage data for user');
        const userSpecificKeys = [
          `securechat_sessions_${loginUsernameRef.current}`,
          `securechat_pins_${loginUsernameRef.current}`,
          `sentReadReceipts_${loginUsernameRef.current}`,
          `keystore_${loginUsernameRef.current}`,
          `identity_${loginUsernameRef.current}`,
          `prekeys_${loginUsernameRef.current}`,
          `signedprekey_${loginUsernameRef.current}`,
          `registrationid_${loginUsernameRef.current}`
        ];
        
        userSpecificKeys.forEach(key => {
          try {
            localStorage.removeItem(key);
          } catch (error) {
            console.error(`[AUTH] Failed to remove key ${key}:`, error);
          }
        });
        
        console.log('[AUTH] localStorage data cleared successfully');
      } catch (error) {
        console.error('[AUTH] Failed to clear localStorage data:', error);
      }
    }

    // Clear server pinned keys (global)
    try {
      localStorage.removeItem('securechat_server_pin_v1');
    } catch (error) {
      console.error('[AUTH] Failed to clear server pin:', error);
    }

    // SECURITY: Clear key manager with proper cleanup
    if (keyManagerRef.current) {
      try {
        keyManagerRef.current.clearKeys();
        await keyManagerRef.current.deleteDatabase();
        keyManagerRef.current = null;
      } catch (error) {
        console.error("[AUTH] Failed to delete user database:", error);
      }
    }

    // SECURITY: Clear username reference last to ensure cleanup works
    const clearedUsername = loginUsernameRef.current;
    loginUsernameRef.current = "";

    setIsLoggedIn(false);
    setLoginError(loginErrorMessage);
    setAccountAuthenticated(false);
    setIsRegistrationMode(false);
    setUsername("");

    console.log(`[AUTH] Logout completed for user: ${clearedUsername}`);
  };

  const useLogout = (Database: any) => {
    return async () => await logout(Database.secureDBRef, "Logged out");
  };

  // Listen for password hash parameters from server
  useEffect(() => {
    const handlePasswordHashParams = (event: CustomEvent) => {
      console.log('[AUTH] Received password hash parameters event:', event.detail);
      
      // Validate that required parameters are present
      const params = event.detail;
      if (!params || !params.salt || !params.memoryCost || !params.timeCost || !params.parallelism) {
        console.error('[AUTH] Invalid password hash parameters received:', params);
        setLoginError("Server sent invalid password hash parameters");
        return;
      }
      
      // Persist for potential fallback prompt
      setPasswordHashParams(params);

      // If we still have the user's plaintext password in memory from the account form,
      // hash it immediately and respond without showing a second prompt
      const existingPassword = passwordRef.current || "";
      if (existingPassword) {
        (async () => {
          try {
            setAuthStatus("Computing secure password hash with Argon2...");
            const passwordHash = await CryptoUtils.Hash.hashDataUsingInfo(existingPassword, params);
            console.log('[AUTH] Auto-submitting password hash to server');
            websocketClient.send(JSON.stringify({
              type: SignalType.PASSWORD_HASH_RESPONSE,
              passwordHash
            }));
            // Do not show the prompt since we auto-submitted
            setShowPasswordPrompt(false);
            setAuthStatus("Password verification in progress...");
          } catch (error) {
            console.error('[AUTH] Auto password hashing failed:', error);
            // Fallback to manual prompt
            setShowPasswordPrompt(true);
            setAuthStatus("Server requires password for secure authentication...");
          }
        })();
      } else {
        // No password cached (e.g., recovery or resumed session) — prompt the user
        setShowPasswordPrompt(true);
        setAuthStatus("Server requires password for secure authentication...");
      }
    };

    window.addEventListener('password-hash-params', handlePasswordHashParams as EventListener);

    return () => {
      window.removeEventListener('password-hash-params', handlePasswordHashParams as EventListener);
    };
  }, []);

  // Add cleanup on page unload/refresh only
  useEffect(() => {

    const handleBeforeUnload = () => {
      // Only clear if user is logged in
      if (isLoggedIn && loginUsernameRef.current) {
        try {
          // Set a flag for cleanup on next app load
          localStorage.setItem('securechat_pending_cleanup', JSON.stringify({
            username: loginUsernameRef.current,
            timestamp: Date.now()
          }));

          // Clear localStorage data synchronously (async won't work in beforeunload)
          localStorage.removeItem(`securechat_sessions_${loginUsernameRef.current}`);
          localStorage.removeItem(`securechat_pins_${loginUsernameRef.current}`);
          localStorage.removeItem('securechat_server_pin_v1');
          console.log('[AUTH] Emergency cleanup on page unload completed');
        } catch (error) {
          console.error('[AUTH] Emergency cleanup failed:', error);
        }
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isLoggedIn]);

  return {
    username,
    serverHybridPublic,
    setServerHybridPublic,
    serverTrustRequest,
    setServerTrustRequest,
    acceptServerTrust,
    rejectServerTrust,
    isLoggedIn,
    setIsLoggedIn,
    isGeneratingKeys,
    authStatus,
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
    handlePassphraseSuccess,
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
    handlePasswordHashSubmit,
    logout,
    useLogout,
    hybridKeysRef,
    keyManagerRef,
    getKeysOnDemand,
    attemptAuthRecovery,
    storeAuthenticationState,
    clearAuthenticationState
  };
};