import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import websocketClient from "../../lib/websocket";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { pseudonymizeUsername } from "../../lib/username-hash";
import { PostQuantumSignature } from "../../lib/cryptography/signature";
import { PostQuantumUtils } from "../../lib/utils/pq-utils";
import type { ServerHybridPublicKeys, HybridKeys, HashParams } from "../../lib/types/auth-types";

export interface AuthRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
  passwordRef: RefObject<string>;
  confirmPasswordRef: RefObject<string>;
  passphraseRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  hybridKeysRef: RefObject<HybridKeys | null>;
  keyManagerRef: RefObject<any>;
  keyManagerOwnerRef: RefObject<string>;
  passphraseLimiterRef: RefObject<{ tokens: number; last: number }>;
}

export interface AuthSetters {
  setUsername: (v: string) => void;
  setIsLoggedIn: (v: boolean) => void;
  setIsGeneratingKeys: (v: boolean) => void;
  setAuthStatus: (v: string) => void;
  setLoginError: (v: string) => void;
  setIsSubmittingAuth: (v: boolean) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setIsRegistrationMode: (v: boolean) => void;
  setShowPassphrasePrompt: (v: boolean) => void;
  setRecoveryActive: (v: boolean) => void;
  setMaxStepReached: (v: 'login' | 'passphrase' | 'server') => void;
}

export interface AuthState {
  isLoggedIn: boolean;
  accountAuthenticated: boolean;
  recoveryActive: boolean;
  passphraseHashParams: HashParams;
  serverHybridPublic: ServerHybridPublicKeys | null;
  isSubmittingAuth: boolean;
}

export const createHandleAccountSubmit = (
  refs: AuthRefs,
  setters: AuthSetters,
  state: AuthState,
  helpers: {
    waitForServerKeys: () => Promise<ServerHybridPublicKeys>;
    initializeKeys: (isRecoveryMode?: boolean, providedSalt?: string, providedArgon2Params?: any) => Promise<void>;
    getKeysOnDemand: () => Promise<HybridKeys | null>;
    storeAuthenticationState: (username: string) => void;
    clearSecureDBForUser: (pseudonym: string) => Promise<void>;
  }
) => {
  return async (
    mode: "login" | "register",
    userInput: string,
    password: string,
    passphrase?: string
  ) => {
    if (state.isSubmittingAuth) {
      return;
    }
    setters.setIsSubmittingAuth(true);
    setters.setLoginError("");
    setters.setIsRegistrationMode(mode === "register");
    setters.setAuthStatus(mode === "register" ? "Creating account..." : "Authenticating...");

    const trimmedUsername = userInput.trim();
    if (!trimmedUsername || trimmedUsername.length > 120 || /[^a-zA-Z0-9._-]/.test(trimmedUsername)) {
      setters.setLoginError('Invalid username format');
      setters.setIsSubmittingAuth(false);
      return;
    }
    if (password.length > 1024) {
      setters.setLoginError('Password too long');
      setters.setIsSubmittingAuth(false);
      return;
    }

    refs.originalUsernameRef.current = trimmedUsername;
    const pseudonym = await pseudonymizeUsername(trimmedUsername);

    const prevUser = refs.loginUsernameRef.current;
    if (prevUser && prevUser !== pseudonym) {
      await helpers.clearSecureDBForUser(prevUser);
      try {
        if (refs.keyManagerRef.current) {
          refs.keyManagerRef.current.clearKeys();
          await refs.keyManagerRef.current.deleteDatabase();
          refs.keyManagerRef.current = null;
          refs.keyManagerOwnerRef.current = '' as any;
          refs.hybridKeysRef.current = null;
        }
      } catch { }
    }

    refs.loginUsernameRef.current = pseudonym;
    setters.setUsername(pseudonym);
    websocketClient.setUsername(pseudonym);

    refs.passwordRef.current = password;
    refs.passphraseRef.current = passphrase || "";

    helpers.storeAuthenticationState(pseudonym);

    try {
      if (!websocketClient.isConnectedToServer()) {
        setters.setAuthStatus("Connecting...");
        await websocketClient.connect();
      }

      const serverKeys = await helpers.waitForServerKeys();

      if (passphrase) {
        refs.passphrasePlaintextRef.current = passphrase;
        await helpers.initializeKeys(false);
      }

      let localKeys = await helpers.getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
        setters.setAuthStatus("Generating keys...");
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

      setters.setAuthStatus("Encrypting...");

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
              context: SignalType.ACCOUNT_META,
              sender: { dilithiumPublicKey: localKeys.dilithium.publicKeyBase64 }
            }
          }
        ),
        15000,
        'encrypt user payload'
      );

      let passwordToSend: string;
      if (mode === "register") {
        setters.setAuthStatus("Attesting device...");

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

        const { deviceCredentialManager } = await import('../../lib/device-credential');
        const attestation = await deviceCredentialManager.signChallenge(challenge);

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

        setters.setAuthStatus("Hashing...");
        passwordToSend = await CryptoUtils.Hash.hashData(password);
      } else {
        passwordToSend = SignalType.REQUEST_SERVER_PASSWORD_PARAMS;
      }

      setters.setAuthStatus("Securing...");
      const encryptedPassword = await withTimeout(
        CryptoUtils.Hybrid.encryptForServer(
          { content: passwordToSend },
          serverKeys,
          {
            senderDilithiumSecretKey: localKeys.dilithium.secretKey,
            metadata: {
              context: SignalType.ACCOUNT_PASSWORD,
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

      setters.setAuthStatus("Sending...");
      websocketClient.send(JSON.stringify(payload));
    } catch (_error) {
      setters.setAuthStatus('');
      setters.setLoginError(_error instanceof Error ? _error.message : 'Authentication request failed');
      setters.setIsSubmittingAuth(false);
    } finally {
      setters.setIsGeneratingKeys(false);
    }
  };
};

export const createHandleServerPasswordSubmit = (
  setters: AuthSetters,
  helpers: {
    waitForServerKeys: () => Promise<ServerHybridPublicKeys>;
    getKeysOnDemand: () => Promise<HybridKeys | null>;
  }
) => {
  return async (password: string) => {
    setters.setLoginError("");
    setters.setAuthStatus("Verifying...");

    try {
      if (!websocketClient.isConnectedToServer()) {
        try {
          await websocketClient.connect();
        } catch {
          setters.setAuthStatus("");
          setters.setLoginError('Failed to connect');
          return;
        }
      }

      const serverKeys = await helpers.waitForServerKeys();

      setters.setAuthStatus("Encrypting...");
      const localKeys = await helpers.getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
        throw new Error('Keys required');
      }

      const encryptedPassword = await CryptoUtils.Hybrid.encryptForServer(
        { content: password },
        serverKeys,
        {
          senderDilithiumSecretKey: localKeys.dilithium.secretKey,
          metadata: {
            context: SignalType.SERVER_PASSWORD,
            sender: { dilithiumPublicKey: localKeys.dilithium.publicKeyBase64 }
          }
        }
      );

      const loginInfo = {
        type: SignalType.SERVER_LOGIN,
        passwordData: encryptedPassword
      };

      setters.setAuthStatus("Authenticating...");
      websocketClient.send(JSON.stringify(loginInfo));
    } catch (_error) {
      setters.setAuthStatus('');
      setters.setLoginError(_error instanceof Error ? _error.message : "Encryption failed");
    }
  };
};
