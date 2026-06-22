import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import websocketClient from "../../lib/websocket/websocket";
import { PostQuantumUtils } from "../../lib/utils/pq-utils";
import type { ServerHybridPublicKeys, HybridKeys, HashParams, MaxStepReached } from "../../lib/types/auth-types";
import { OPAQUEClient, OPAQUEClientHelpers, OPAQUE_CONFIG } from "../../lib/cryptography/opaque-client";
import { computeBlindUserId } from "../../lib/utils/auth-utils";
import { PrivacyPassClient, PrivacyPassHelpers } from "../../lib/cryptography/privacy-pass-client";
import { tokenVault } from "../../lib/database/token-vault";
import { blake3 } from '@noble/hashes/blake3.js';
import { storage } from "../../lib/tauri-bindings";
import { deriveRendezvousRouteId } from "../../lib/transport/rendezvous-routing";

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
  accountSubmitInFlightRef: RefObject<boolean>;
  aesKeyRef: RefObject<CryptoKey | null>;
  blindCredentialRef?: RefObject<{
    message: string;
    inboxId?: string;
    routeId?: string;
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

const createAuthFinalizeWaiter = (timeoutMs: number): { promise: Promise<any>; cancel: () => void } => {
  let cancelWait = () => {};
  let capturedSuccess: any = null;
  const promise = new Promise<any>((resolve, reject) => {
    let settled = false;
    const startedAt = Date.now();
    let timeout: ReturnType<typeof setTimeout>;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      window.removeEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, handleSuccess as any);
      window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, handleServerMessage as any);
      window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handleServerMessage as any);
      window.removeEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    };
    cancelWait = cleanup;

    const handleSuccess = () => {
      console.log('[AUTH-FLOW] Finalization success event received', {
        elapsedMs: Date.now() - startedAt
      });
      cleanup();
      resolve(capturedSuccess);
    };

    const handleServerMessage = (evt: Event) => {
      const detail = (evt as CustomEvent).detail as any;
      if (!detail || typeof detail !== 'object') return;
      const type = detail.type;
      if (type === SignalType.AUTH_FULL_SUCCESS) {
        console.log('[AUTH-FLOW] AUTH_FULL_SUCCESS received while waiting for finalization', {
          elapsedMs: Date.now() - startedAt,
          serverEntryRequired: !!detail?.serverEntryRequired
        });
        capturedSuccess = detail;
        if (detail?.serverEntryRequired) {
          cleanup();
          resolve(detail);
        }
        return;
      }
      if (type === SignalType.AUTH_ERROR) {
        console.warn('[AUTH-FLOW] Auth error while waiting for finalization', {
          elapsedMs: Date.now() - startedAt,
          code: detail?.code
        });
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

    timeout = setTimeout(() => {
      console.error('[AUTH-FLOW] Registration finalization wait timed out', {
        timeoutMs,
        elapsedMs: Date.now() - startedAt
      });
      cleanup();
      reject(new Error('Registration finalization timeout'));
    }, timeoutMs);
  });
  return { promise, cancel: cancelWait };
};

const createSignalResponseWaiter = <T = any>(
  signalType: SignalType,
  timeoutMs: number,
  timeoutMessage: string
): { promise: Promise<T>; cancel: () => void } => {
  let cancelWait = () => {};
  const promise = new Promise<T>((resolve, reject) => {
    let settled = false;
    let onSignalMessage: (msg: any) => void = () => {};
    const startedAt = Date.now();

    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      try { websocketClient.unregisterMessageHandler(signalType, onSignalMessage); } catch { }
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

    cancelWait = cleanup;

    const onAuthError = (event: Event) => {
      const detail = (event as CustomEvent).detail as any;
      fail(detail?.message || 'Authentication failed');
    };

    onSignalMessage = (msg: any) => {
      console.log('[AUTH-FLOW] Response received', {
        type: signalType,
        elapsedMs: Date.now() - startedAt
      });
      cleanup();
      resolve(msg as T);
    };

    const timeout = setTimeout(() => {
      console.error('[AUTH-FLOW] Response wait timed out', {
        type: signalType,
        timeoutMs,
        elapsedMs: Date.now() - startedAt,
        connected: websocketClient.isConnectedToServer?.(),
        pqSessionEstablished: websocketClient.isPQSessionEstablished?.()
      });
      fail(timeoutMessage);
    }, timeoutMs);

    websocketClient.registerMessageHandler(signalType, onSignalMessage);
    console.log('[AUTH-FLOW] Waiting for response', {
      type: signalType,
      timeoutMs,
      connected: websocketClient.isConnectedToServer?.(),
      pqSessionEstablished: websocketClient.isPQSessionEstablished?.()
    });

    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, onEdgeMessage as any);
    window.addEventListener(EventType.AUTH_ERROR, onAuthError as any);
  });
  return { promise, cancel: cancelWait };
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
  setTokenValidationInProgress: (v: boolean) => void;
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
    if (state.isSubmittingAuth || refs.accountSubmitInFlightRef.current) {
      return;
    }
    refs.accountSubmitInFlightRef.current = true;
    setters.setIsSubmittingAuth(true);
    setters.setLoginError("");
    setters.setIsRegistrationMode(mode === "register");
    setters.setAuthStatus(mode === "register" ? "Creating account..." : "Authenticating...");

    const trimmedUsername = userInput.trim();
    if (!trimmedUsername || trimmedUsername.length > 120 || /[^a-zA-Z0-9._-]/.test(trimmedUsername)) {
      setters.setLoginError('Invalid username format');
      setters.setIsSubmittingAuth(false);
      refs.accountSubmitInFlightRef.current = false;
      return;
    }
    if (password.length > 1024) {
      setters.setLoginError('Password too long');
      setters.setIsSubmittingAuth(false);
      refs.accountSubmitInFlightRef.current = false;
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

      // Ensure on-demand identity keys are initialized for later use (messaging prekey bundle,
      // etc.). The OPAQUE flow below derives everything it needs from the password directly and
      // does not consume this result, so we don't build a placeholder key object here (the old
      // ephemeral fallback was dead code and constructed an invalid, accountRoot-less HybridKeys).
      await helpers.getKeysOnDemand();

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
          const responseWaiter = createSignalResponseWaiter<any>(
            SignalType.AUTH_OT_REGISTER_RESPONSE,
            60000,
            'Registration response timeout'
          );

          setters.setAuthStatus("Requesting registration slot...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          console.log('[AUTH-FLOW] Sending registration slot request', {
            connected: websocketClient.isConnectedToServer?.(),
            pqSessionEstablished: websocketClient.isPQSessionEstablished?.()
          });
          try {
            await websocketClient.sendSecureControlMessage({
              type: SignalType.AUTH_OT_REGISTER_REQUEST,
              blindedElement: PostQuantumUtils.uint8ArrayToBase64(blindedElement),
              clientPublicKey: PostQuantumUtils.uint8ArrayToBase64(clientPublicKey)
            }, { failIfQueued: true });
            console.log('[AUTH-FLOW] Registration slot request sent');
          } catch (sendError) {
            responseWaiter.cancel();
            throw sendError;
          }

          const serverResponse = await responseWaiter.promise;
          setters.setAuthStatus("Creating envelope...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          // Finish OT registration
          const registrationFinalize = await opaqueClient.finishOTRegistration(
            compositeSecret,
            blindingFactor,
            clientSecretKey,
            OPAQUEClientHelpers.decodeResponse(serverResponse, ['evaluatedElement', 'serverPublicKey', 'serverNonce'])
          );

          // wipe composite secret
          compositeSecret.fill(0);

          // Store export key for vault
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));
          await tokenVault.initialize(registrationFinalize.exportKey);

          // Persist vault key
          try {
            const { saveVaultKeyRaw } = await import('../../lib/cryptography/vault-key');
            await saveVaultKeyRaw(trimmedUsername, registrationFinalize.exportKey);
          } catch (err) {
            console.warn('[Auth] Failed to persist vault key during registration:', err);
          }

          // Re wrap master key with export key that persisted as vault key
          try {
            const { saveWrappedMasterKey } = await import('../../lib/cryptography/vault-key');
            const { CryptoUtils } = await import('../../lib/utils/crypto-utils');
            const masterKey = refs.keyManagerRef.current?.getMasterKey?.();
            if (masterKey) {
              const exportVaultKey = await CryptoUtils.AES.importAesKey(registrationFinalize.exportKey);
              const rawMaster = new Uint8Array(await CryptoUtils.Keys.exportAESKey(masterKey));
              await saveWrappedMasterKey(trimmedUsername, rawMaster, exportVaultKey);
              rawMaster.fill(0);
            }
          } catch (err) {
            console.warn('[Auth] Failed to re-wrap master key with export vault key:', err);
          }

          // Store generated tokens in the vault
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));
          await tokenVault.storeTokens(tokenSecrets);

          // Generate blind credential for blind routing
          let blindedToken: string | undefined;
          let blindParams: { message: string; inboxId?: string; routeId?: string; blindedMsg: string; blindingFactor: string; n: string; kid: string; modulusLength: number; hash: string; saltLength: number; scheme: string; used?: boolean } | undefined;
          if (state.serverHybridPublic?.blindPublicKey) {
            try {
              const { CryptoUtils } = await import('../../lib/utils/crypto-utils');
              const { deriveInboxId, currentInboxEpoch } = await import('../../lib/cryptography/vault-key');
              const { blindMessage } = await import('../../lib/crypto/blind-credentials');

              const vaultKey = await CryptoUtils.AES.importAesKey(registrationFinalize.exportKey);
              const inboxId = await deriveInboxId(vaultKey, currentInboxEpoch());

              const routeId = deriveRendezvousRouteId(inboxId);
              const blindResult = await blindMessage(routeId, state.serverHybridPublic.blindPublicKey);
              blindedToken = blindResult.blindedMsg;
              blindParams = {
                message: routeId,
                inboxId,
                routeId,
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

          const finalizationWaiter = createAuthFinalizeWaiter(120000);
          try {
            await websocketClient.sendSecureControlMessage({
              type: SignalType.AUTH_OT_REGISTER_FINALIZE,
              credentialId: PostQuantumUtils.uint8ArrayToBase64(registrationFinalize.credentialId),
              blindedToken,
              blindedTokens: blindedTokens.map(t => PostQuantumUtils.uint8ArrayToBase64(t)),
              ...OPAQUEClientHelpers.encodeRequest({
                envelope: registrationFinalize.envelope,
                maskedResponse: registrationFinalize.maskedResponse
              })
            }, { failIfQueued: true });
          } catch (sendError) {
            finalizationWaiter.cancel();
            throw sendError;
          }

          const finalizeSuccess = await finalizationWaiter.promise;

          // Persist assigned shard slot
          try {
            const sId = Number.isInteger(finalizeSuccess?.shardId) ? finalizeSuccess.shardId : null;
            const cIndex = Number.isInteger(finalizeSuccess?.credentialIndex) ? finalizeSuccess.credentialIndex : null;
            if (sId !== null && cIndex !== null) {
              await storage.set(`shard_info_${blindUserId}`, JSON.stringify({
                shardId: sId,
                credentialIndex: cIndex,
                shardSize: Number.isInteger(finalizeSuccess?.shardSize)
                  ? finalizeSuccess.shardSize
                  : OPAQUE_CONFIG.PRIVATE_AUTH_SHARD_SIZE
              }));
            } else {
              console.warn('[Auth] Registration finished without shard slot metadata. re login may require recovery');
            }
          } catch (err) {
            console.warn('[Auth] Failed to persist shard info during registration:', err);
          }

          if (passphrase) {
            refs.passphrasePlaintextRef.current = passphrase;
            if (!refs.hybridKeysRef.current || !refs.aesKeyRef.current) {
              await helpers.initializeKeys(false);
            }
            setters.setVaultReady(true);
          } else {
            setters.setShowPassphrasePrompt(true);
          }

          registrationFinalize.exportKey.fill(0);

          setters.setAccountAuthenticated(true);
          setters.setIsLoggedIn(true);
          setters.setIsRegistrationMode(false);
          setters.setIsSubmittingAuth(false);
        } else {
          setters.setAuthStatus("Preparing anonymous lookup...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          // Retrieve shard info
          const shardInfoRaw = await storage.get(`shard_info_${blindUserId}`);
          let shardId: number | null = null;
          let myIndex: number | null = null;

          if (shardInfoRaw && typeof shardInfoRaw === 'string') {
            try {
              const parsed = JSON.parse(shardInfoRaw);
              shardId = Number.isInteger(parsed.shardId) ? parsed.shardId : null;
              myIndex = Number.isInteger(parsed.credentialIndex) ? parsed.credentialIndex : null;
              if (parsed.shardSize !== OPAQUE_CONFIG.PRIVATE_AUTH_SHARD_SIZE) {
                throw new Error('Shard anonymity set size mismatch');
              }
            } catch {
              console.warn('[Auth] Failed to load private auth shard metadata');
            }
          }
          if (shardId === null || myIndex === null) {
            throw new Error('Private auth shard metadata unavailable. recovery flow is required');
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
          const shardSize = OPAQUE_CONFIG.PRIVATE_AUTH_SHARD_SIZE;
          const { pubKeys, blindedElement } = await opaqueClient.startOTLogin(compositeSecret, shardSize, myIndex);

          // Send OT Request
          const otResponseWaiter = createSignalResponseWaiter<any>(
            SignalType.AUTH_OT_RESPONSE,
            240000,
            'OT response timeout'
          );

          setters.setAuthStatus("Retrieving blind record...");

          const onOtChunkProgress = (ev: Event) => {
            const detail = (ev as CustomEvent).detail;
            if (
              detail?.payloadType === SignalType.AUTH_OT_RESPONSE &&
              Number.isFinite(detail?.total) && detail.total > 0
            ) {
              const pct = Math.max(0, Math.min(100, Math.round((detail.received / detail.total) * 100)));
              setters.setAuthStatus(`Retrieving blind record... (${pct}%)`);
            }
          };
          window.addEventListener(EventType.SECURE_CHUNK_PROGRESS, onOtChunkProgress as EventListener);

          let otResponse: any;
          try {
            let sent = false;
            let lastSendError: unknown = null;
            for (let attempt = 0; attempt < 3 && !sent; attempt++) {
              const ready = await websocketClient.waitUntilReady(45000);
              if (!ready) {
                lastSendError = new Error('Connection not ready. Please try again.');
                break;
              }
              try {
                await websocketClient.sendSecureControlMessage({
                  type: SignalType.AUTH_OT_REQUEST,
                  shardId,
                  clientPubKeys: pubKeys.map(pk => PostQuantumUtils.uint8ArrayToBase64(pk)),
                  blindedElement: PostQuantumUtils.uint8ArrayToBase64(blindedElement),
                  anonymousTokenData: redemptionToken ? PrivacyPassHelpers.formatResponse(redemptionToken) : null
                }, { failIfQueued: true });
                sent = true;
              } catch (sendError) {
                lastSendError = sendError;
                await new Promise(resolve => setTimeout(resolve, 500));
              }
            }
            if (!sent) {
              otResponseWaiter.cancel();
              throw lastSendError instanceof Error ? lastSendError : new Error('WebSocket not connected');
            }

            otResponse = await otResponseWaiter.promise;
          } finally {
            window.removeEventListener(EventType.SECURE_CHUNK_PROGRESS, onOtChunkProgress as EventListener);
          }

          setters.setAuthStatus("Decrypting record...");
          await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 50)));

          const loginFinalize = await opaqueClient.finishOTLogin(
            compositeSecret,
            otResponse.otRecords,
            PostQuantumUtils.base64ToUint8Array(otResponse.evaluatedElement),
            PostQuantumUtils.base64ToUint8Array(otResponse.serverNonce)
          );

          // Wipe composite secret
          compositeSecret.fill(0);

          if (!loginFinalize.success || !loginFinalize.authMessage || !loginFinalize.exportKey) {
            throw new Error('Incorrect username, password, or passphrase.');
          }

          // Initialize vault and send final auth message
          await tokenVault.initialize(loginFinalize.exportKey);

          // Store username for auto-login on reconnect
          await storage.set('last_authenticated_username', trimmedUsername);
          refs.loginUsernameRef.current = trimmedUsername;
          setters.setUsername(trimmedUsername);

          // Generate blind credential from export key
          let blindedToken: string | undefined;
          if (state.serverHybridPublic?.blindPublicKey) {
            try {
              const { CryptoUtils } = await import('../../lib/utils/crypto-utils');
              const { deriveInboxId, currentInboxEpoch, saveVaultKeyRaw } = await import('../../lib/cryptography/vault-key');
              const { blindMessage } = await import('../../lib/crypto/blind-credentials');

              // Persist vault key
              await saveVaultKeyRaw(trimmedUsername, loginFinalize.exportKey);

              const vaultKey = await CryptoUtils.AES.importAesKey(loginFinalize.exportKey);
              const inboxId = await deriveInboxId(vaultKey, currentInboxEpoch());

              const routeId = deriveRendezvousRouteId(inboxId);
              const blindResult = await blindMessage(routeId, state.serverHybridPublic.blindPublicKey);
              blindedToken = blindResult.blindedMsg;
              const blindParams = {
                message: routeId,
                inboxId,
                routeId,
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
              console.warn('[Auth] Failed to generate blind credential for login:', err);
            }
          }

          if (passphrase) {
            refs.passphrasePlaintextRef.current = passphrase;
            await helpers.initializeKeys(false);
            setters.setVaultReady(true);
          }

          loginFinalize.exportKey.fill(0);
          await websocketClient.sendSecureControlMessage({
            type: SignalType.AUTH_OT_FINALIZE,
            authProof: PostQuantumUtils.uint8ArrayToBase64(loginFinalize.authMessage),
            serverNonce: PostQuantumUtils.uint8ArrayToBase64(loginFinalize.serverNonce),
            shardId,
            blindedToken
          }, { failIfQueued: true });
        }
      } catch (_error) {
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        console.error('[Auth] Error during account submit:', errorMessage);
        const friendlyMessage = /invalid tag|invalid mac|decrypt|tag mismatch/i.test(errorMessage)
          ? 'Incorrect username, password, or passphrase.'
          : (errorMessage || 'Authentication request failed');
        setters.setLoginError(friendlyMessage);
        setters.setIsSubmittingAuth(false);
        
        try { setters.setTokenValidationInProgress(false); } catch { }
      } finally {
        setters.setIsGeneratingKeys(false);
      }
    } catch (err) {
      console.error('[Auth] Connection or key error:', err);
      setters.setLoginError(err instanceof Error && err.message ? err.message : 'Connection failed. Please try again.');
      setters.setIsSubmittingAuth(false);
    } finally {
      refs.accountSubmitInFlightRef.current = false;
      setters.setAuthStatus('');
    }
  };
};
