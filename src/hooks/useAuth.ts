import { useState, useRef, useCallback, MutableRefObject } from "react";
import { SignalType } from "@/lib/signals";
import websocketClient from "@/lib/websocket";
import { CryptoUtils } from "@/lib/unified-crypto";
import { SecureDB } from "@/lib/secureDB";
import { SecureKeyManager } from "@/lib/secure-key-manager";
import { X3DH } from "@/lib/ratchet/x3dh";
import { SessionStore } from "@/lib/ratchet/session-store";
import { PinnedServer } from "@/lib/ratchet/pinned-server";

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

    try { SessionStore.clearAllForCurrentUser(); } catch { } //clear any stale ratchet sessions before starting a fresh auth flow
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

      //publish prekey bundle for X3DH
      if (keyManagerRef.current) {
        let ratchetId = await keyManagerRef.current.getRatchetIdentity();
        if (!ratchetId) {
          const id = await X3DH.generateIdentityKeyPair();
          console.log('[AUTH] Generated new ratchet identity:', {
            ed25519PrivateLen: id.ed25519Private.length,
            dilithiumPrivateLen: id.dilithiumPrivate.length,
            x25519PrivateLen: id.x25519Private.length
          });
          await keyManagerRef.current.storeRatchetIdentity({
            ed25519Private: id.ed25519Private,
            ed25519PublicBase64: CryptoUtils.Base64.arrayBufferToBase64(id.ed25519Public),
            dilithiumPrivate: id.dilithiumPrivate,
            dilithiumPublicBase64: CryptoUtils.Base64.arrayBufferToBase64(id.dilithiumPublic),
            x25519Private: id.x25519Private,
            x25519PublicBase64: CryptoUtils.Base64.arrayBufferToBase64(id.x25519Public),
          });
          ratchetId = await keyManagerRef.current.getRatchetIdentity();
        }

        console.log('[AUTH] Retrieved ratchet identity:', {
          ed25519PrivateLen: ratchetId?.ed25519Private?.length,
          dilithiumPrivateLen: ratchetId?.dilithiumPrivate?.length,
          x25519PrivateLen: ratchetId?.x25519Private?.length
        });

        //reuse existing prekeys if available and if not then generate new
        let existing = await keyManagerRef.current.getRatchetPrekeys();
        let signedPreKey = existing?.signedPreKey ?? null;
        let oneTimePreKeys = existing?.oneTimePreKeys ?? [];
        let generatedSignedPreKey = null;
        if (!signedPreKey) {
          console.log('[AUTH] Generating signed prekey with keys:', {
            ed25519PrivateLen: ratchetId!.ed25519Private.length,
            dilithiumPrivateLen: ratchetId!.dilithiumPrivate?.length,
            hasDilithium: !!ratchetId!.dilithiumPrivate
          });
          const gen = await X3DH.generateSignedPreKey(ratchetId!.ed25519Private, ratchetId!.dilithiumPrivate || undefined);
          generatedSignedPreKey = gen;
          signedPreKey = {
            id: gen.id,
            private: gen.privateKey!,
            publicBase64: CryptoUtils.Base64.arrayBufferToBase64(gen.publicKey),
            signatureBase64: CryptoUtils.Base64.arrayBufferToBase64(gen.ed25519Signature),
          };
        }
        if (!oneTimePreKeys || oneTimePreKeys.length === 0) {
          const genOtks = await X3DH.generateOneTimePreKeys(25);
          oneTimePreKeys = genOtks.map(k => ({ id: k.id, private: k.privateKey!, publicBase64: CryptoUtils.Base64.arrayBufferToBase64(k.publicKey) }));
        }

        //store merged prekeys back and preserve any existing
        await keyManagerRef.current.storeRatchetPrekeys({ signedPreKey, oneTimePreKeys });

        //publish bundle (no secrets) to server using base64 strings
        websocketClient.send(JSON.stringify({
          type: SignalType.X3DH_PUBLISH_BUNDLE,
          bundle: {
            username: loginUsernameRef.current,
            identityEd25519PublicBase64: ratchetId!.ed25519PublicBase64,
            identityDilithiumPublicBase64: ratchetId!.dilithiumPublicBase64,
            identityX25519PublicBase64: ratchetId!.x25519PublicBase64,
            ratchetPublicBase64: signedPreKey.publicBase64,
            signedPreKey: {
              id: signedPreKey.id,
              publicKeyBase64: signedPreKey.publicBase64,
              ed25519SignatureBase64: signedPreKey.signatureBase64,
              dilithiumSignatureBase64: generatedSignedPreKey ? CryptoUtils.Base64.arrayBufferToBase64(generatedSignedPreKey.dilithiumSignature!) : undefined,
            },
            oneTimePreKeys: oneTimePreKeys.map(k => ({ id: k.id, publicKeyBase64: k.publicBase64 })),
          }
        }));

        //and alsi publish legacy hybrid public keys so server can encrypt system messages immediately
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

  const logout = (secureDBRef?: MutableRefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    console.log('[AUTH] Logging out user');
    //drop all ratchet sessions for this user to avoid annoying chain drift on next login
    try { SessionStore.clearAllForCurrentUser(); } catch { }
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