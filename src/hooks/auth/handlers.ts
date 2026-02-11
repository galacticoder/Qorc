import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import websocketClient from "../../lib/websocket/websocket";
import { PostQuantumSignature } from "../../lib/cryptography/signature";
import { PostQuantumUtils } from "../../lib/utils/pq-utils";
import type { ServerHybridPublicKeys, HybridKeys, HashParams, MaxStepReached } from "../../lib/types/auth-types";
import { OPAQUEClient, OPAQUEClientHelpers } from "../../lib/cryptography/opaque-client";
import { computeBlindUserId, generateBlindCredential } from "../../lib/utils/auth-utils";
import { PrivacyPassClient, PrivacyPassHelpers } from "../../lib/cryptography/privacy-pass-client";
import { tokenVault } from "../../lib/database/token-vault";
import { blake3 } from '@noble/hashes/blake3.js';
import { storage } from "../../lib/tauri-bindings";

/**
 * Derive a composite secret from username, password, and passphrase
 */
function deriveCompositeSecret(username: string, password: string, passphrase?: string): Uint8Array {
  const u = (username || "").trim().toLowerCase();
  const p = password || "";
  const pp = passphrase || "";

  const encoder = new TextEncoder();
  const data = new Uint8Array([
    ...encoder.encode(`u:${u}`),
    0x00,
    ...encoder.encode(`p:${p}`),
    0x00,
    ...encoder.encode(`s:${pp}`)
  ]);

  const hash = blake3(data, { dkLen: 32 });
  return hash;
}

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
  aesKeyRef: RefObject<CryptoKey | null>;
  blindCredentialRef?: RefObject<{
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
  } | null>;
}

const waitForAuthFinalize = (timeoutMs: number): Promise<void> => {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      window.removeEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, handleSuccess as any);
      window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handleServerMessage as any);
      window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handleServerMessage as any);
      window.removeEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    };

    const handleSuccess = () => {
      cleanup();
      resolve();
    };

    const handleServerMessage = (evt: Event) => {
      const detail = (evt as CustomEvent).detail as any;
      if (!detail || typeof detail !== 'object') return;
      const type = detail.type;
      if (type === SignalType.AUTH_FULL_SUCCESS) {
        cleanup();
        resolve();
        return;
      }
      if (type === SignalType.AUTH_ERROR) {
        cleanup();
        reject(new Error(detail?.message || 'Registration failed'));
      }
    };

    const handleAuthError = (evt: Event) => {
      const detail = (evt as CustomEvent).detail as any;
      cleanup();
      reject(new Error(detail?.message || 'Registration failed'));
    };

    window.addEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, handleSuccess as any);
    window.addEventListener(EventType.SECURE_SERVER_MESSAGE, handleServerMessage as any);
    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handleServerMessage as any);
    window.addEventListener(EventType.AUTH_ERROR, handleAuthError as any);

    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Registration finalization timeout'));
    }, timeoutMs);
  });
};

const waitForSignalResponse = <T = any>(
  signalType: SignalType,
  timeoutMs: number,
  timeoutMessage: string
): Promise<T> => {
  return new Promise((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      try { websocketClient.unregisterMessageHandler(signalType); } catch { }
      try { window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, onEdgeMessage as any); } catch { }
      try { window.removeEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
    };

    const fail = (reason: string) => {
      cleanup();
      reject(new Error(reason));
    };

    const onEdgeMessage = (event: Event) => {
      const detail = (event as CustomEvent).detail as any;
      if (!detail || typeof detail !== 'object') return;
      if (detail.type === '__ws_connection_closed') {
        fail('Connection closed while waiting for server response');
      } else if (detail.type === '__ws_connection_error') {
        fail(detail.error ? `Connection error: ${detail.error}` : 'Connection error while waiting for server response');
      }
    };

    const onAuthError = (event: Event) => {
      const detail = (event as CustomEvent).detail as any;
      fail(detail?.message || 'Authentication failed');
    };

    const timeout = setTimeout(() => {
      fail(timeoutMessage);
    }, timeoutMs);

    websocketClient.registerMessageHandler(signalType, (msg: any) => {
      cleanup();
      resolve(msg as T);
    });

    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, onEdgeMessage as any);
    window.addEventListener(EventType.AUTH_ERROR, onAuthError as any);
  });
};

export interface AuthSetters {
  setUsername: (v: string) => void;
  setPseudonym: (v: string) => void;
  setIsLoggedIn: (v: boolean) => void;
  setIsGeneratingKeys: (v: boolean) => void;
  setAuthStatus: (v: string) => void;
  setLoginError: (v: string) => void;
  setIsSubmittingAuth: (v: boolean) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setIsRegistrationMode: (v: boolean) => void;
  setShowPassphrasePrompt: (v: boolean) => void;
  setRecoveryActive: (v: boolean) => void;
  setMaxStepReached: (v: MaxStepReached | ((prev: MaxStepReached) => MaxStepReached)) => void;
  setVaultReady: (v: boolean) => void;
}

export interface AuthState {
  isLoggedIn: boolean;
  accountAuthenticated: boolean;
  recoveryActive: boolean;
  passphraseHashParams?: HashParams;
  serverHybridPublic: ServerHybridPublicKeys | null;
  isSubmittingAuth: boolean;
  inboxId?: string;
  blindSignature?: string;
}

export const createHandleAccountSubmit = (
  refs: AuthRefs,
  setters: AuthSetters,
  state: AuthState,
  helpers: {
    waitForServerKeys: () => Promise<ServerHybridPublicKeys>;
    initializeKeys: (isRecoveryMode?: boolean, providedSalt?: string, providedArgon2Params?: any) => Promise<void>;
    getKeysOnDemand: () => Promise<HybridKeys | null>;
    storeAuthenticationState: (username: string, originalUsername?: string) => void;
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
    const blindUserId = computeBlindUserId(trimmedUsername);

    const prevUser = refs.loginUsernameRef.current;
    if (prevUser && prevUser !== blindUserId) {
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

    refs.loginUsernameRef.current = trimmedUsername;
    setters.setUsername(trimmedUsername);
    setters.setPseudonym(blindUserId);
    websocketClient.setUsername(blindUserId);

    refs.passwordRef.current = password;
    refs.confirmPasswordRef.current = passphrase || "";

    await helpers.storeAuthenticationState(trimmedUsername, trimmedUsername);

    try {
      if (!websocketClient.isConnectedToServer()) {
        setters.setAuthStatus("Connecting...");
        await websocketClient.connect();
      }

      await helpers.waitForServerKeys();

      if (passphrase) {
        refs.passphrasePlaintextRef.current = passphrase;
        await helpers.initializeKeys(false);
      }

      let localKeys = await helpers.getKeysOnDemand();
      if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
        setters.setAuthStatus("Generating keys...");
        await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 100)));
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

      // OPAQUE Flow
      try {
        setters.setAuthStatus("Initializing OPAQUE...");
        await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));
        const compositeSecret = deriveCompositeSecret(trimmedUsername, password, passphrase);

        const opaqueClient = new OPAQUEClient();
        const ppClient = new PrivacyPassClient();

        if (mode === "register") {
          setters.setAuthStatus("Blinding credentials...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          const { blindedElement, clientPublicKey, blindingFactor, clientSecretKey } =
            await opaqueClient.startOTRegistration(compositeSecret);

          setters.setAuthStatus("Generating anonymous tokens...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));
          const { blindedTokens, tokenSecrets } = await ppClient.generateTokenBatch(250);

          // Request a slot
          const responsePromise = waitForSignalResponse<any>(
            SignalType.AUTH_OT_REGISTER_RESPONSE,
            30000,
            'Registration response timeout'
          );

          setters.setAuthStatus("Requesting registration slot...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          await websocketClient.sendSecureControlMessage({
            type: SignalType.AUTH_OT_REGISTER_REQUEST,
            blindedElement: PostQuantumUtils.uint8ArrayToBase64(blindedElement),
            clientPublicKey: PostQuantumUtils.uint8ArrayToBase64(clientPublicKey),
            blindedTokens: blindedTokens.map(t => PostQuantumUtils.uint8ArrayToBase64(t))
          });

          const serverResponse = await responsePromise;
          setters.setAuthStatus("Creating envelope...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          // Finish OT registration
          const registrationFinalize = await opaqueClient.finishOTRegistration(
            compositeSecret,
            blindingFactor,
            clientSecretKey,
            OPAQUEClientHelpers.decodeResponse(serverResponse, ['evaluatedElement', 'serverPublicKey', 'serverNonce'])
          );

          // Store export key for vault
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));
          await tokenVault.initialize(registrationFinalize.exportKey);

          // Store generated tokens in the vault
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));
          await tokenVault.storeTokens(tokenSecrets);

          // Generate blind credential for blind routing
          let blindedToken: string | undefined;
          let blindParams: { message: string; blindedMsg: string; blindingFactor: string; n: string; kid: string; modulusLength: number; hash: string; saltLength: number; scheme: string } | undefined;
          if (state.serverHybridPublic?.blindPublicKey) {
            try {
              const { CryptoUtils } = await import('../../lib/utils/crypto-utils');
              const { deriveInboxId } = await import('../../lib/cryptography/vault-key');
              const { blindMessage } = await import('../../lib/crypto/blind-credentials');

              const vaultKey = await CryptoUtils.AES.importAesKey(registrationFinalize.exportKey);
              const inboxId = await deriveInboxId(vaultKey);

              // Blind the inbox ID for server signing
              const blindResult = await blindMessage(inboxId, state.serverHybridPublic.blindPublicKey);
              blindedToken = blindResult.blindedMsg;
              blindParams = {
                message: inboxId,
                blindedMsg: blindResult.blindedMsg,
                blindingFactor: blindResult.blindingFactor,
                n: blindResult.n,
                kid: blindResult.kid,
                modulusLength: blindResult.modulusLength,
                hash: blindResult.hash,
                saltLength: blindResult.saltLength,
                scheme: blindResult.scheme,
                used: false
              };
              
              if (refs.blindCredentialRef) {
                const existing = refs.blindCredentialRef.current;
                if (!existing || existing.used) {
                  refs.blindCredentialRef.current = blindParams;
                }
              }
            } catch (err) {
              console.warn('[Auth] Failed to generate blind credential for registration:', err);
            }
          }

          // Send credentialId
          await websocketClient.sendSecureControlMessage({
            type: SignalType.AUTH_OT_REGISTER_FINALIZE,
            credentialId: PostQuantumUtils.uint8ArrayToBase64(registrationFinalize.credentialId),
            blindedToken,
            ...OPAQUEClientHelpers.encodeRequest({
              envelope: registrationFinalize.envelope,
              maskedResponse: registrationFinalize.maskedResponse
            })
          });

          await waitForAuthFinalize(10000);

          if (passphrase) {
            refs.passphrasePlaintextRef.current = passphrase;
            await helpers.initializeKeys(false);

            if (state.serverHybridPublic?.blindPublicKey) {
              const blindParams = await generateBlindCredential(trimmedUsername, state.serverHybridPublic.blindPublicKey);
              if (blindParams && refs.blindCredentialRef) {
                const existing = refs.blindCredentialRef.current;
                if (!existing || existing.used) {
                  refs.blindCredentialRef.current = { ...blindParams, used: false };
                }
              }
            }

            setters.setVaultReady(true);
          } else {
            setters.setShowPassphrasePrompt(true);
          }

          setters.setAccountAuthenticated(true);
          setters.setIsLoggedIn(true);
          setters.setIsSubmittingAuth(false);
          setters.setIsRegistrationMode(false);
        } else {
          setters.setAuthStatus("Preparing anonymous lookup...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          // Retrieve shard info
          const shardInfoRaw = await storage.get(`shard_info_${blindUserId}`);
          let shardId = 0;
          let myIndex = 0;

          if (shardInfoRaw && typeof shardInfoRaw === 'string') {
            try {
              const parsed = JSON.parse(shardInfoRaw);
              shardId = parsed.shardId;
              myIndex = parsed.credentialIndex;
            } catch {
              console.warn('[Auth] Failed to parse shard info, using deterministic fallback');
            }
          }


          const opaqueClient = new OPAQUEClient();
          const ppClient = new PrivacyPassClient();

          // Prepare anonymous token
          let token = await tokenVault.getToken();
          let redemptionToken: any = null;

          if (token) {
            redemptionToken = await ppClient.prepareRedemption(token);
          }

          setters.setAuthStatus("Generating OT keys...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          const compositeSecret = deriveCompositeSecret(trimmedUsername, password, passphrase);
          const shardSize = 100;
          const { pubKeys, blindedElement } = await opaqueClient.startOTLogin(compositeSecret, shardSize, myIndex);

          // Send OT Request
          const otResponsePromise = waitForSignalResponse<any>(
            SignalType.AUTH_OT_RESPONSE,
            45000,
            'OT response timeout'
          );

          setters.setAuthStatus("Retrieving blind record...");
          await websocketClient.sendSecureControlMessage({
            type: SignalType.AUTH_OT_REQUEST,
            shardId,
            clientPubKeys: pubKeys.map(pk => PostQuantumUtils.uint8ArrayToBase64(pk)),
            blindedElement: PostQuantumUtils.uint8ArrayToBase64(blindedElement),
            anonymousTokenData: redemptionToken ? PrivacyPassHelpers.formatResponse(redemptionToken) : null
          });

          const otResponse = await otResponsePromise;

          setters.setAuthStatus("Decrypting record...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          const loginFinalize = await opaqueClient.finishOTLogin(
            compositeSecret,
            otResponse.otRecords,
            PostQuantumUtils.base64ToUint8Array(otResponse.evaluatedElement),
            PostQuantumUtils.base64ToUint8Array(otResponse.serverNonce)
          );

          if (!loginFinalize.success || !loginFinalize.authMessage || !loginFinalize.exportKey) {
            throw new Error('OT authentication failed - incorrect password or record');
          }

          // Initialize vault and send final auth message
          await tokenVault.initialize(loginFinalize.exportKey);

          // Store username for auto-login on reconnect
          await storage.set('last_authenticated_username', trimmedUsername);
          refs.loginUsernameRef.current = trimmedUsername;
          setters.setUsername(trimmedUsername);

          if (passphrase) {
            refs.passphrasePlaintextRef.current = passphrase;
            await helpers.initializeKeys(false);

            if (state.serverHybridPublic?.blindPublicKey) {
              const blindParams = await generateBlindCredential(trimmedUsername, state.serverHybridPublic.blindPublicKey);
              if (blindParams && refs.blindCredentialRef) {
                const existing = refs.blindCredentialRef.current;
                if (!existing || existing.used) {
                  refs.blindCredentialRef.current = { ...blindParams, used: false };
                }
              }
            }

            setters.setVaultReady(true);
          }

          await websocketClient.sendSecureControlMessage({
            type: SignalType.AUTH_OT_FINALIZE,
            authProof: PostQuantumUtils.uint8ArrayToBase64(loginFinalize.authMessage),
            serverNonce: PostQuantumUtils.uint8ArrayToBase64(loginFinalize.serverNonce),
            credentialId: loginFinalize.credentialId,
            blindedToken: refs.blindCredentialRef?.current?.blindedMsg
          });
        }
      } catch (_error) {
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        console.error('[Auth] Error during account submit:', errorMessage);
        setters.setLoginError(errorMessage || 'Authentication request failed');
        setters.setIsSubmittingAuth(false);
      } finally {
        setters.setIsGeneratingKeys(false);
      }
    } catch (err) {
      console.error('[Auth] Connection or key error:', err);
      setters.setLoginError(String(err));
      setters.setIsSubmittingAuth(false);
    } finally {
      setters.setAuthStatus('');
    }
  };
};
