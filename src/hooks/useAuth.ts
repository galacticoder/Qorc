import { useState, useRef, useCallback, MutableRefObject } from "react";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SecureDB } from "@/lib/secureDB";
import { SecureKeyManager } from "@/lib/secure-key-manager";

export const useAuth = () => {
  const [username, setUsername] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [accountAuthenticated, setAccountAuthenticated] = useState(false);
  const passphraseRef = useRef<string>("");
  const passphrasePlaintextRef = useRef<string>("");
  const aesKeyRef = useRef<CryptoKey | null>(null);

  const [serverHybridPublic, setServerHybridPublic] = useState<{
    x25519PublicBase64: string;
    kyberPublicBase64: string
  } | null>(null);

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
      const metadata = await keyManagerRef.current.getKeyMetadata();
      if (metadata) {
        await keyManagerRef.current.initialize(passphrasePlaintextRef.current, metadata.salt);
      } else {
        await keyManagerRef.current.initialize(passphrasePlaintextRef.current);
      }

      const keys = await keyManagerRef.current.getKeys();
      console.log('[AUTH] Keys retrieved successfully');
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
          hybridKeysRef.current = existingKeys;
        }
      } else {
        console.log('[AUTH] Generating new hybrid key pair');
        const seed = await CryptoUtils.Hash.hashData(passphrase + currentUsername);
        const hybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPairFromSeed(seed);

        await keyManagerRef.current.initialize(passphrase);
        await keyManagerRef.current.storeKeys(hybridKeyPair);

        console.log('[AUTH] New keys generated and stored successfully');
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

      let passphraseHash;

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

      if (keyManagerRef.current && serverHybridPublic) {
        const publicKeys = await keyManagerRef.current.getPublicKeys();
        if (publicKeys) {
          const hybridKeysPayload = {
            usernameSent: loginUsernameRef.current,
            hybridPublicKeys: {
              x25519PublicBase64: publicKeys.x25519PublicBase64,
              kyberPublicBase64: publicKeys.kyberPublicBase64
            }
          };

          const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptHybridPayload(
            hybridKeysPayload,
            serverHybridPublic
          );

          console.log('[AUTH] Sending hybrid keys update to server');
          websocketClient.send(JSON.stringify({
            type: SignalType.HYBRID_KEYS_UPDATE,
            userData: encryptedHybridKeys
          }));
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

  const logout = (secureDBRef?: MutableRefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    console.log('[AUTH] Logging out user');
    if (secureDBRef?.current) secureDBRef.current = null;

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
    return () => logout(Database.secureDBRef, "Logged out");
  };

  return {
    username,
    serverHybridPublic,
    setServerHybridPublic,
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