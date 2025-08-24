import { useState, useRef, useCallback, useEffect, MutableRefObject } from "react";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SecureDB } from "@/lib/secureDB";
import { SecureKeyManager } from "@/lib/secure-key-manager";
// Legacy pinned server removed; use simple in-memory pinning here
const PinnedServer = {
  get() {
    try { return JSON.parse(localStorage.getItem('securechat_server_pin_v1') || 'null'); } catch { return null; }
  },
  set(val: any) {
    try { localStorage.setItem('securechat_server_pin_v1', JSON.stringify(val)); } catch {}
  }
};

export const useAuth = () => {
  const [username, setUsername] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);
  const [initialCleanupDone, setInitialCleanupDone] = useState(false);

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
  } | null>(null);

  const keyManagerRef = useRef<SecureKeyManager | null>(null);
  const loginUsernameRef = useRef("");

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
        kyberSecretLen: keys.kyber.secretKey?.byteLength
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
  const [showPassphrasePrompt, setShowPassphrasePrompt] = useState(false);

  const initializeKeys = useCallback(async () => {
    console.log('[AUTH] Starting key initialization process');
    setIsGeneratingKeys(true);
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
        await keyManagerRef.current.initialize(passphrase);
        const existingKeys = await keyManagerRef.current.getKeys();
        if (existingKeys) {
          console.log('[AUTH] Existing keys loaded successfully');
          try {
            console.debug('[AUTH] Existing keys summary', {
              x25519PublicBase64: existingKeys.x25519.publicKeyBase64?.slice(0, 28) + '...',
              kyberPublicBase64: existingKeys.kyber.publicKeyBase64?.slice(0, 28) + '...',
              x25519PrivateLen: existingKeys.x25519.private?.length,
              kyberSecretLen: existingKeys.kyber.secretKey?.length,
            });
          } catch { }
          hybridKeysRef.current = existingKeys;
        }
      } else {
        console.log('[AUTH] Generating new hybrid key pair');
        const seed = await CryptoUtils.Hash.hashData(passphrase + currentUsername);
        const hybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPairFromSeed(seed);

        await keyManagerRef.current.initialize(passphrase);
        await keyManagerRef.current.storeKeys(hybridKeyPair);

        console.log('[AUTH] New keys generated and stored successfully');
        try {
          console.debug('[AUTH] New keys summary', {
            x25519PublicBase64: hybridKeyPair.x25519.publicKeyBase64?.slice(0, 28) + '...',
            kyberPublicBase64: hybridKeyPair.kyber.publicKeyBase64?.slice(0, 28) + '...',
            x25519PrivateLen: hybridKeyPair.x25519.private?.length,
            kyberSecretLen: hybridKeyPair.kyber.secretKey?.length,
          });
        } catch { }
        hybridKeysRef.current = hybridKeyPair;
      }
    } catch (error) {
      console.error("[AUTH] Error generating keys: ", error);
      setLoginError("Key generation failed");
    } finally {
      setIsGeneratingKeys(false);
    }
  }, []);

  const handleAccountSubmit = async (
    mode: "login" | "register",
    username: string,
    password: string,
    passphrase?: string
  ) => {
    console.log(`[AUTH] Starting ${mode} process for user: ${username}`);
    setLoginError("");

    // legacy ratchet sessions no longer used
    loginUsernameRef.current = username;
    setUsername(username);
    passwordRef.current = password;
    passphraseRef.current = passphrase || "";

    try {
      if (!serverHybridPublic) {
        console.error("[AUTH] Server public keys not available");
        throw new Error("Server public keys not available");
      }

      if (!websocketClient.isConnectedToServer()) {
        console.log('[AUTH] Connecting to WebSocket server');
        await websocketClient.connect();
      }

      if (passphrase) {
        console.log('[AUTH] Passphrase provided, initializing keys');
        passphrasePlaintextRef.current = passphrase;
        await initializeKeys();
      }

      const userPayload = {
        usernameSent: username,
        hybridPublicKeys: {
          x25519PublicBase64: "",
          kyberPublicBase64: ""
        }
      };

      const encryptedPayload = await CryptoUtils.Hybrid.encryptHybridPayload(
        userPayload,
        serverHybridPublic
      );

      const encryptedPassword = await CryptoUtils.Hybrid.encryptHybridPayload(
        { content: password },
        serverHybridPublic
      );

      const payload = {
        type: mode === "register" ? SignalType.ACCOUNT_SIGN_UP : SignalType.ACCOUNT_SIGN_IN,
        userData: encryptedPayload,
        passwordData: encryptedPassword
      };

      console.log(`[AUTH] Sending ${mode} request to server`);
      websocketClient.send(JSON.stringify(payload));
    } catch (error) {
      console.error(`[AUTH] ${mode} submission failed:`, error);
      setLoginError(`Submission error: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  };

  const handleServerPasswordSubmit = async (password: string) => {
    console.log('[AUTH] Submitting server password');
    setLoginError("");
    if (!serverHybridPublic) {
      setLoginError("Server keys not available");
      return;
    }

    try {
      if (!websocketClient.isConnectedToServer()) {
        try {
          await websocketClient.connect();
        } catch (error) {
          setLoginError(`Failed to connect to server: ${error}`);
          return;
        }
      }

      const encryptedPassword = await CryptoUtils.Hybrid.encryptHybridPayload(
        { content: password },
        serverHybridPublic
      );
      try {
        console.debug('[AUTH] Password payload encrypted (hybrid-v1)', {
          hasEphemeralX25519Public: !!(encryptedPassword as any).ephemeralX25519Public,
          kyberCiphertextLen: ((encryptedPassword as any).kyberCiphertext || '').length,
          encryptedMessageLen: ((encryptedPassword as any).encryptedMessage || '').length,
        });
      } catch { }

      const loginInfo = {
        type: SignalType.SERVER_LOGIN,
        passwordData: encryptedPassword
      };

      console.log('[AUTH] Sending server password to server');
      websocketClient.send(JSON.stringify(loginInfo));
      loginUsernameRef.current = username;
    } catch (error) {
      console.error("Login failed: ", error);
      setLoginError("Password encryption failed");
    }
  };

  const handlePassphraseSubmit = async (passphrase: string, mode: "login" | "register") => {
    console.log(`[AUTH] Submitting passphrase for ${mode} mode`);
    passphrasePlaintextRef.current = passphrase;

    try {
      await initializeKeys();

      let passphraseHash: string;

      if (mode === "login") {
        if (!passphraseHashParams) {
          throw new Error("Missing passphrase parameters");
        }

        passphraseHash = await CryptoUtils.Hash.hashDataUsingInfo(
          passphrase,
          passphraseHashParams
        );
      } else {
        passphraseHash = await CryptoUtils.Hash.hashData(passphrase);
      }

      passphraseRef.current = passphraseHash;

      console.log(`[AUTH] Sending passphrase hash to server`);
      websocketClient.send(JSON.stringify({
        type: mode === "register"
          ? SignalType.PASSPHRASE_HASH_NEW
          : SignalType.PASSPHRASE_HASH,
        passphraseHash
      }));

      // publish official libsignal bundle via edge IPC and publish to server; keep legacy hybrid pub for DB
      if (keyManagerRef.current) {
        try {
          const idOut = await (window as any).edgeApi.generateIdentity({ username: loginUsernameRef.current });
          const prekeys = await (window as any).edgeApi.generatePreKeys({ username: loginUsernameRef.current });
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

  const handleAuthSuccess = (username: string) => {
    console.log(`[AUTH] Authentication success for user: ${username}`);
    if (!accountAuthenticated) return;

    setUsername(username);
    setIsLoggedIn(true);
    setLoginError("");

    if (keyManagerRef.current && passphrasePlaintextRef.current) {
      keyManagerRef.current.initialize(passphrasePlaintextRef.current).catch(error => {
        console.error("Failed to initialize key manager after auth success:", error);
      });
    }
  };

  const logout = async (secureDBRef?: MutableRefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    console.log('[AUTH] Logging out user');

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

    //drop all ratchet sessions for this user to avoid annoying chain drift on next login
    try { SessionStore.clearAllForCurrentUser(); } catch { }

    // Clear localStorage data for the current user
    if (loginUsernameRef.current) {
      try {
        console.log('[AUTH] Clearing localStorage data for user');
        // Clear session store data
        localStorage.removeItem(`securechat_sessions_${loginUsernameRef.current}`);
        // Clear pinned identities
        localStorage.removeItem(`securechat_pins_${loginUsernameRef.current}`);
        // Clear read receipt tracking data
        localStorage.removeItem(`sentReadReceipts_${loginUsernameRef.current}`);
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

    passwordRef.current = "";
    passphraseRef.current = "";
    passphrasePlaintextRef.current = "";
    aesKeyRef.current = null;
    hybridKeysRef.current = null;

    if (keyManagerRef.current) {
      keyManagerRef.current.clearKeys();
      keyManagerRef.current.deleteDatabase().catch(error => {
        console.error("Failed to delete user database:", error);
      });
    }

    setIsLoggedIn(false);
    setLoginError(loginErrorMessage);
    setAccountAuthenticated(false);
  };

  const useLogout = (Database: any) => {
    return async () => await logout(Database.secureDBRef, "Logged out");
  };

  // Add cleanup on page unload/refresh and check for pending cleanup on mount
  useEffect(() => {
    // Comprehensive cleanup on app initialization
    const performInitialCleanup = async () => {
      if (initialCleanupDone) return;

      try {
        console.log('[AUTH] Performing initial cleanup check');

        // Check for pending cleanup flag
        const pendingCleanup = localStorage.getItem('securechat_pending_cleanup');
        if (pendingCleanup) {
          try {
            const { username } = JSON.parse(pendingCleanup);
            console.log('[AUTH] Found pending cleanup for user:', username);

            // Clear SecureKeyManager database
            const tempKeyManager = new SecureKeyManager(username);
            await tempKeyManager.deleteDatabase();
            console.log('[AUTH] Cleared SecureKeyManager database for:', username);

            // Remove the pending cleanup flag
            localStorage.removeItem('securechat_pending_cleanup');
            console.log('[AUTH] Pending cleanup completed');
          } catch (error) {
            console.error('[AUTH] Failed to complete pending cleanup:', error);
            // Remove the flag anyway to prevent infinite attempts
            localStorage.removeItem('securechat_pending_cleanup');
          }
        }

        // Also clear any SecureDB databases that might be lingering
        try {
          // Get all databases and clear any that look like SecureDB databases
          if ('indexedDB' in window) {
            // Clear any databases that start with 'SecureKeyDB_'
            const databases = await indexedDB.databases?.() || [];
            for (const db of databases) {
              if (db.name && (db.name.startsWith('SecureKeyDB_'))) {
                console.log('[AUTH] Clearing orphaned database:', db.name);
                const deleteRequest = indexedDB.deleteDatabase(db.name);
                await new Promise((resolve, reject) => {
                  deleteRequest.onsuccess = () => resolve(undefined);
                  deleteRequest.onerror = () => reject(deleteRequest.error);
                });
              }
            }
          }
        } catch (error) {
          console.warn('[AUTH] Could not clear orphaned databases:', error);
        }

        setInitialCleanupDone(true);
        console.log('[AUTH] Initial cleanup completed');
      } catch (error) {
        console.error('[AUTH] Initial cleanup failed:', error);
        setInitialCleanupDone(true); // Set anyway to prevent infinite retries
      }
    };

    performInitialCleanup();

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
    loginError,
    accountAuthenticated,
    loginUsernameRef,
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
    passphrasePlaintextRef,
    passphraseRef,
    aesKeyRef,
    setShowPassphrasePrompt,
    showPassphrasePrompt,
    logout,
    useLogout,
    hybridKeysRef,
    keyManagerRef,
    getKeysOnDemand
  };
};