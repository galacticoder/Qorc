import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import websocketClient from "../../lib/websocket/websocket";
import { PostQuantumUtils } from "../../lib/utils/pq-utils";
import type { HybridKeys, ServerHybridPublicKeys } from "../../lib/types/auth-types";
import { OPAQUEClient, OPAQUEClientHelpers, OPAQUE_CONFIG } from "../../lib/cryptography/opaque-client";
import { computeBlindUserId, computePrivateAuthStorageId } from "../../lib/utils/auth-utils";
import { PrivacyPassClient, getPrivacyPassBatchEpoch } from "../../lib/cryptography/privacy-pass-client";
import { solvePowChallenge } from "../../lib/cryptography/proof-of-work";
import { tokenVault } from "../../lib/database/token-vault";
import { blake3 } from '@noble/hashes/blake3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { account, storage } from "../../lib/tauri-bindings";
import { PostQuantumWorker } from "../../lib/cryptography/worker-bridge";
import { getCurrentServerScope } from "../../lib/security/local-account-scope";
import {
  clearRegistrationAttempt,
  getOrCreateRegistrationAttempt,
} from "../../lib/auth/registration-attempt";
import {
  type AuthLifecycle,
  StaleAuthOperationError,
  isStaleAuthOperation,
  wipeStaleAuthResult,
} from "../../lib/auth/auth-lifecycle";
import { keyTransparencyClient } from "../../lib/key-transparency/client";
import {
  PASSPHRASE_MAX_LENGTH,
  PASSPHRASE_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
} from "../../lib/constants";
import { REQUEST_ID_RE } from '../../../shared/patterns.js';
import { PROTOCOL_KEYS } from '../../lib/config/protocol-keys';
import { STORAGE_PREFIXES } from '../../lib/database/storage-keys';

const yieldToEventLoop = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

function privateAuthRequestCommitment(
  blindedElement: Uint8Array,
  publicKeys: Uint8Array[]
): string {
  const hash = sha256.create();
  hash.update(new TextEncoder().encode(PROTOCOL_KEYS.PRIVATE_AUTH_REQUEST));
  hash.update(blindedElement);
  for (const publicKey of publicKeys) hash.update(publicKey);
  const digest = hash.digest();
  try {
    return PostQuantumUtils.uint8ArrayToBase64(digest);
  } finally {
    digest.fill(0);
  }
}

/**
 * Derive a composite secret from username, password, and passphrase
 */
async function deriveCompositeSecret(username: string, password: string, passphrase?: string): Promise<Uint8Array> {
  const u = (username || "").trim().toLowerCase();
  const p = password || "";
  const pp = passphrase || "";

  if (!u || u.length > 128 || !p || p.length > 1024 || pp.length > 1024) {
    throw new Error('Invalid authentication secret');
  }

  const encoder = new TextEncoder();
  const usernameBytes = encoder.encode(`${PROTOCOL_KEYS.ACCOUNT_AUTH_USERNAME_PREFIX}${u}`);
  const passwordBytes = encoder.encode(`${PROTOCOL_KEYS.ACCOUNT_AUTH_PASSWORD_PREFIX}${p}`);
  const passphraseBytes = encoder.encode(`${PROTOCOL_KEYS.ACCOUNT_AUTH_PASSPHRASE_PREFIX}${pp}`);
  const data = new Uint8Array(usernameBytes.length + passwordBytes.length + passphraseBytes.length + 2);
  let offset = 0;
  data.set(usernameBytes, offset);
  offset += usernameBytes.length + 1;
  data.set(passwordBytes, offset);
  offset += passwordBytes.length + 1;
  data.set(passphraseBytes, offset);
  const saltInput = encoder.encode(`${PROTOCOL_KEYS.ACCOUNT_AUTH_KDF}${u}`);
  let salt: Uint8Array | null = null;
  let workerHash: Uint8Array | null = null;
  try {
    salt = blake3(saltInput, { dkLen: 32 });
    const result = await PostQuantumWorker.argon2Hash({
      pass: data,
      salt,
      time: 3,
      mem: 64 * 1024,
      parallelism: 1,
      type: 2,
      version: 0x13,
      hashLen: 32
    });
    workerHash = result.hash instanceof Uint8Array ? result.hash : null;
    if (!workerHash || workerHash.length !== 32) {
      throw new Error('Authentication KDF returned an invalid result');
    }
    return new Uint8Array(workerHash);
  } finally {
    usernameBytes.fill(0);
    passwordBytes.fill(0);
    passphraseBytes.fill(0);
    data.fill(0);
    saltInput.fill(0);
    salt?.fill(0);
    workerHash?.fill(0);
  }
}

export interface AuthRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
  passwordRef: RefObject<string>;
  confirmPasswordRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  hybridKeysRef: RefObject<HybridKeys | null>;
  keyManagerOwnerRef: RefObject<string>;
  accountSubmitInFlightRef: RefObject<boolean>;
}

const createAuthFinalizeWaiter = (
  timeoutMs: number,
  abortSignal: AbortSignal,
  authRequestId: string
): { promise: Promise<any>; cancel: () => void } => {
  let cancelWait = () => {};
  const promise = new Promise<any>((resolve, reject) => {
    let settled = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      if (timeout) clearTimeout(timeout);
      window.removeEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, handleSuccess as any);
      window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, handleEdgeMessage as any);
      window.removeEventListener(EventType.AUTH_ERROR, handleAuthError as any);
      abortSignal.removeEventListener('abort', handleAbort);
    };
    cancelWait = cleanup;

    const handleSuccess = (evt: Event) => {
      const detail = (evt as CustomEvent).detail as any;
      if (detail?.authRequestId !== authRequestId || detail?.authenticated !== true) return;
      cleanup();
      resolve(detail);
    };

    const handleAuthError = (evt: Event) => {
      const detail = (evt as CustomEvent).detail as any;
      if (detail?.authRequestId !== authRequestId) return;
      if (detail?.code === 'SERVER_ENTRY_REQUIRED') {
        cleanup();
        resolve({
          authenticated: true,
          authRequestId,
          serverEntryRequired: true,
          serverEntryGranted: false
        });
        return;
      }
      cleanup();
      reject(new Error(detail?.message || 'Registration failed'));
    };

    const handleEdgeMessage = (evt: Event) => {
      const detail = (evt as CustomEvent).detail as any;
      if (detail?.type !== '__ws_connection_closed' && detail?.type !== '__ws_connection_error') return;
      cleanup();
      reject(new Error('Connection closed while finalizing authentication'));
    };

    const handleAbort = () => {
      cleanup();
      reject(new StaleAuthOperationError());
    };

    window.addEventListener(EventType.SECURE_CHAT_AUTH_SUCCESS, handleSuccess as any);
    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, handleEdgeMessage as any);
    window.addEventListener(EventType.AUTH_ERROR, handleAuthError as any);
    abortSignal.addEventListener('abort', handleAbort, { once: true });

    timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Authentication completion timeout'));
    }, timeoutMs);
    if (abortSignal.aborted) handleAbort();
  });
  return { promise, cancel: cancelWait };
};

const createSignalResponseWaiter = <T = any>(
  signalType: SignalType,
  timeoutMs: number,
  timeoutMessage: string,
  abortSignal: AbortSignal,
  authRequestId: string
): { promise: Promise<T>; cancel: () => void } => {
  let cancelWait = () => {};
  const promise = new Promise<T>((resolve, reject) => {
    let settled = false;
    let onSignalMessage: (msg: any) => void = () => {};
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      try { websocketClient.unregisterMessageHandler(signalType, onSignalMessage); } catch { }
      try { window.removeEventListener(EventType.EDGE_SERVER_MESSAGE, onServerEvent as any); } catch { }
      try { window.removeEventListener(EventType.SECURE_SERVER_MESSAGE, onServerEvent as any); } catch { }
      try { window.removeEventListener(EventType.AUTH_ERROR, onAuthError as any); } catch { }
      abortSignal.removeEventListener('abort', onAbort);
    };

    const fail = (reason: string, code?: unknown) => {
      cleanup();
      const error = new Error(reason) as Error & { code?: string };
      if (typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code)) {
        error.code = code;
      }
      reject(error);
    };

    const onServerEvent = (event: Event) => {
      const detail = (event as CustomEvent).detail as any;
      if (!detail || typeof detail !== 'object') return;
      if (detail.type === '__ws_connection_closed') {
        fail('Connection closed while waiting for server response');
      } else if (detail.type === '__ws_connection_error') {
        fail(detail.error ? `Connection error: ${detail.error}` : 'Connection error while waiting for server response');
      } else if (detail.type === SignalType.ERROR || detail.type === SignalType.AUTH_ERROR) {
        const responseAuthRequestId = typeof detail.authRequestId === 'string'
          ? detail.authRequestId
          : '';
        if (responseAuthRequestId && responseAuthRequestId !== authRequestId) return;
        const belongsToAnotherRequest = !responseAuthRequestId && (
          typeof detail.requestId === 'string' ||
          typeof detail.op === 'string' ||
          typeof detail.stage === 'string'
        );
        if (belongsToAnotherRequest) return;
        fail(detail.message || 'Authentication request failed', detail.code);
      }
    };

    cancelWait = cleanup;

    const onAuthError = (event: Event) => {
      const detail = (event as CustomEvent).detail as any;
      if (detail?.authRequestId !== authRequestId) return;
      fail(detail?.message || 'Authentication failed', detail?.code);
    };

    const onAbort = () => {
      cleanup();
      reject(new StaleAuthOperationError());
    };

    onSignalMessage = (msg: any) => {
      if (msg?.authRequestId !== authRequestId) return;
      cleanup();
      resolve(msg as T);
    };

    const timeout = setTimeout(() => {
      fail(timeoutMessage);
    }, timeoutMs);

    websocketClient.registerMessageHandler(signalType, onSignalMessage);
    window.addEventListener(EventType.EDGE_SERVER_MESSAGE, onServerEvent as any);
    window.addEventListener(EventType.SECURE_SERVER_MESSAGE, onServerEvent as any);
    window.addEventListener(EventType.AUTH_ERROR, onAuthError as any);
    abortSignal.addEventListener('abort', onAbort, { once: true });
    if (abortSignal.aborted) onAbort();
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
  setVaultReady: (v: boolean) => void;
  setTokenValidationInProgress: (v: boolean) => void;
  setShowPasswordPrompt: (v: boolean) => void;
  setShowPassphrasePrompt: (v: boolean) => void;
  setRecoveryActive: (v: boolean) => void;
}

export interface AuthState {
  isSubmittingAuth: boolean;
}

export const createHandleAccountSubmit = (
  refs: AuthRefs,
  setters: AuthSetters,
  state: AuthState,
  helpers: {
    waitForServerKeys: (signal?: AbortSignal) => Promise<ServerHybridPublicKeys>;
    initializeKeys: () => Promise<void>;
    attemptAuthRecovery: () => Promise<boolean>;
    isLocalRecovery: () => boolean;
    storeAuthenticationState: (username: string, originalUsername?: string) => Promise<void>;
    lifecycle: AuthLifecycle;
  }
) => {
  return async (
    mode: "login" | "register",
    userInput: string,
    password: string,
    passphrase: string
  ) => {
    if (state.isSubmittingAuth || refs.accountSubmitInFlightRef.current) {
      return;
    }
    const displayUsername = userInput.trim();
    const trimmedUsername = displayUsername.toLowerCase();
    if (!/^[a-zA-Z0-9._-]{3,100}$/.test(displayUsername)) {
      setters.setLoginError('Invalid username format');
      return;
    }
    if (mode === 'register') {
      if (
        password.length < PASSWORD_MIN_LENGTH ||
        password.length > PASSWORD_MAX_LENGTH ||
        passphrase.length < PASSPHRASE_MIN_LENGTH ||
        passphrase.length > PASSPHRASE_MAX_LENGTH ||
        password === passphrase
      ) {
        setters.setLoginError('Password or passphrase does not meet the account security policy');
        return;
      }
    } else {
      if (
        password.length === 0 ||
        password.length > PASSWORD_MAX_LENGTH ||
        passphrase.length === 0 ||
        passphrase.length > PASSPHRASE_MAX_LENGTH
      ) {
        setters.setLoginError('Enter your password and passphrase');
        return;
      }
    }

    const authRequestId = crypto.randomUUID();
    if (!REQUEST_ID_RE.test(authRequestId)) {
      setters.setLoginError('Authentication request could not be initialized');
      return;
    }
    const operation = helpers.lifecycle.begin(trimmedUsername, authRequestId);
    tokenVault.lock();
    const assertCurrent = () => {
      helpers.lifecycle.assertCurrent(operation);
      if (refs.loginUsernameRef.current && refs.loginUsernameRef.current !== trimmedUsername) {
        throw new StaleAuthOperationError();
      }
    };
    const awaitCurrent = async <T>(promise: Promise<T>): Promise<T> => {
      const result = await promise;
      try {
        assertCurrent();
      } catch (error) {
        wipeStaleAuthResult(result);
        throw error;
      }
      return result;
    };

    refs.accountSubmitInFlightRef.current = true;
    setters.setIsSubmittingAuth(true);
    setters.setLoginError("");
    setters.setIsRegistrationMode(mode === "register");
    setters.setAuthStatus(mode === "register" ? "Creating account..." : "Authenticating...");

    refs.originalUsernameRef.current = displayUsername;
    const blindUserId = computeBlindUserId(trimmedUsername);

    refs.loginUsernameRef.current = trimmedUsername;
    setters.setUsername(displayUsername);
    setters.setPseudonym(blindUserId);
    websocketClient.setUsername(trimmedUsername);

    refs.passwordRef.current = password;
    refs.confirmPasswordRef.current = "";
    refs.passphrasePlaintextRef.current = "";

    let nativeUnlockedForAttempt = false;
    let retainNativeSession = false;

    const unlockNativeAccountForTokens = async (): Promise<void> => {
      if (!nativeUnlockedForAttempt) {
        refs.passwordRef.current = password;
        refs.passphrasePlaintextRef.current = passphrase;
        await awaitCurrent(helpers.initializeKeys());
        nativeUnlockedForAttempt = true;
      }
      if (!tokenVault.isVaultUnlocked()) {
        await awaitCurrent(tokenVault.initialize());
      }
    };

    const releaseFailedNativeAccount = async (): Promise<void> => {
      if (!nativeUnlockedForAttempt || retainNativeSession) return;
      tokenVault.lock();
      setters.setVaultReady(false);
      const accountOwner = refs.keyManagerOwnerRef.current;
      refs.hybridKeysRef.current = null;
      refs.keyManagerOwnerRef.current = '';
      nativeUnlockedForAttempt = false;
      if (/^[a-f0-9]{64}$/.test(accountOwner)) {
        await account.lock(accountOwner).catch(() => false);
      }
    };

    try {
      if (mode === 'login' && helpers.isLocalRecovery()) {
        refs.passphrasePlaintextRef.current = passphrase;
        setters.setAuthStatus('Unlocking local account...');
        await awaitCurrent(helpers.initializeKeys());
        nativeUnlockedForAttempt = true;
        await awaitCurrent(tokenVault.initialize());
        setters.setVaultReady(true);
        try { window.dispatchEvent(new CustomEvent(EventType.HYBRID_KEYS_UPDATED)); } catch { }

        const resumed = await awaitCurrent(helpers.attemptAuthRecovery());
        if (resumed) {
          retainNativeSession = true;
          setters.setShowPassphrasePrompt(false);
          setters.setRecoveryActive(false);
          setters.setIsSubmittingAuth(false);
          return;
        }

        // native vault is unlocked but no resume credential remains
        refs.passwordRef.current = password;
        refs.passphrasePlaintextRef.current = passphrase;
        setters.setAuthStatus('No restart credential remains; signing in...');
      }

      setters.setAuthStatus("Preparing private authentication connection...");
      await awaitCurrent(websocketClient.switchToLinkedAuthenticationMode(operation.signal));

      await awaitCurrent(helpers.waitForServerKeys(operation.signal));
      if (
        websocketClient.isServerPasswordRequired()
        && !websocketClient.isServerAuthGranted()
      ) {
        setters.setIsSubmittingAuth(false);
        setters.setAuthStatus('');
        setters.setShowPasswordPrompt(true);
        window.dispatchEvent(new CustomEvent(EventType.AUTH_ERROR, {
          detail: {
            type: 'SERVER_ENTRY_REQUIRED',
            code: 'SERVER_ENTRY_REQUIRED',
            authRequestId,
            message: 'Enter the server password before signing in to the account.'
          }
        }));
        return;
      }

      // OPAQUE Flow
      let compositeSecret: Uint8Array | null = null;
      const opaqueClient = new OPAQUEClient();
      const ppClient = new PrivacyPassClient();
      try {
        setters.setAuthStatus("Initializing OPAQUE...");
        await awaitCurrent(yieldToEventLoop());
        compositeSecret = await awaitCurrent(deriveCompositeSecret(trimmedUsername, password, passphrase));

        if (mode === "register") {
          let registrationBlindedElement: Uint8Array | null = null;
          let registrationBlindingFactor: Uint8Array | null = null;
          let registrationBlindedTokens: Uint8Array[] = [];
          let registrationTokenSecrets: any[] = [];
          let pendingRegistrationTokens: any[] = [];
          let decodedRegistrationResponse: any = null;
          let registrationFinalize: any = null;
          try {
          setters.setAuthStatus("Blinding credentials...");
          await awaitCurrent(yieldToEventLoop());

          const registrationStart = await awaitCurrent(opaqueClient.startOTRegistration(compositeSecret));
          registrationBlindedElement = registrationStart.blindedElement;
          registrationBlindingFactor = registrationStart.blindingFactor;

          setters.setAuthStatus("Requesting registration proof...");
          await awaitCurrent(yieldToEventLoop());

          let registrationPreflightSolution: string | undefined;
          let serverResponse: any = null;
          for (let round = 0; round < 3; round += 1) {
            const responseWaiter = createSignalResponseWaiter<any>(
              SignalType.AUTH_OT_REGISTER_RESPONSE,
              60000,
              'Registration response timeout',
              operation.signal,
              authRequestId
            );
            try {
              await awaitCurrent(websocketClient.sendSecureControlMessage({
                type: SignalType.AUTH_OT_REGISTER_REQUEST,
                authRequestId,
                blindedElement: PostQuantumUtils.uint8ArrayToBase64(registrationBlindedElement),
                preflightPowSolution: registrationPreflightSolution
              }, { failIfQueued: true, signal: operation.signal }));
            } catch (sendError) {
              responseWaiter.cancel();
              throw sendError;
            }

            const response = await awaitCurrent(responseWaiter.promise);
            if (!response?.preflightRequired) {
              serverResponse = response;
              break;
            }
            setters.setAuthStatus("Securing registration request...");
            registrationPreflightSolution = await awaitCurrent(solvePowChallenge(
              response.powChallenge,
              operation.signal
            ));
          }
          if (!serverResponse) {
            throw new Error('Registration preflight could not be completed');
          }
          setters.setAuthStatus("Creating envelope...");
          await awaitCurrent(yieldToEventLoop());

          // Finish OT registration
          decodedRegistrationResponse = OPAQUEClientHelpers.decodeResponse(serverResponse, {
            evaluatedElement: 32,
            serverNonce: 32
          });
          registrationFinalize = await awaitCurrent(opaqueClient.finishOTRegistration(
            compositeSecret,
            registrationBlindingFactor,
            decodedRegistrationResponse
          ));

          const registrationAttemptId = await awaitCurrent(
            getOrCreateRegistrationAttempt(trimmedUsername)
          );
          const readyWaiter = createSignalResponseWaiter<any>(
            SignalType.AUTH_OT_REGISTER_READY,
            120000,
            'Registration staging timeout',
            operation.signal,
            authRequestId
          );
          try {
            await awaitCurrent(websocketClient.sendSecureControlMessage({
              type: SignalType.AUTH_OT_REGISTER_FINALIZE,
              authRequestId,
              registrationAttemptId,
              ...OPAQUEClientHelpers.encodeRequest({
                envelope: registrationFinalize.envelope,
                authPublicKey: registrationFinalize.authPublicKey
              })
            }, { failIfQueued: true, signal: operation.signal }));
          } catch (sendError) {
            readyWaiter.cancel();
            throw sendError;
          }

          const ready = await awaitCurrent(readyWaiter.promise);
          if (
            !ready ||
            typeof ready !== 'object' ||
            Array.isArray(ready) ||
            Object.keys(ready).sort().join(',') !== 'anonymitySetSize,authRequestId,credentialIndex,registrationAlreadyCommitted,staged,type' ||
            typeof ready.staged !== 'boolean' ||
            typeof ready.registrationAlreadyCommitted !== 'boolean' ||
            ready.staged === ready.registrationAlreadyCommitted ||
            !Number.isInteger(ready.credentialIndex) ||
            ready.credentialIndex < 0 ||
            ready.credentialIndex >= OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE ||
            ready.anonymitySetSize !== OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE
          ) {
            throw new Error('Server returned invalid registration staging state');
          }

          if (ready.registrationAlreadyCommitted === true) {
            await awaitCurrent(clearRegistrationAttempt(trimmedUsername));
            setters.setIsRegistrationMode(false);
            throw new Error('Account creation was already committed. Sign in to continue.');
          }

          await unlockNativeAccountForTokens();

          pendingRegistrationTokens = await awaitCurrent(tokenVault.getPendingTokens(250));
          if (pendingRegistrationTokens.length > 0 && pendingRegistrationTokens.length !== 250) {
            for (const token of pendingRegistrationTokens) {
              token.tokenSecret?.fill(0);
              token.blindingFactor?.fill(0);
              token.blindedElement?.fill(0);
              token.unblindedToken?.fill(0);
            }
            pendingRegistrationTokens = [];
            await awaitCurrent(tokenVault.discardPendingTokens());
          }
          if (pendingRegistrationTokens.length === 0) {
            setters.setAuthStatus("Generating anonymous tokens...");
            await awaitCurrent(yieldToEventLoop());
            const generatedTokens = await awaitCurrent(ppClient.generateTokenBatch(250));
            registrationBlindedTokens = generatedTokens.blindedTokens;
            registrationTokenSecrets = generatedTokens.tokenSecrets;
            await awaitCurrent(tokenVault.replaceTokens(registrationTokenSecrets));
            pendingRegistrationTokens = await awaitCurrent(tokenVault.getPendingTokens(250));
          }
          if (
            pendingRegistrationTokens.length !== 250 ||
            pendingRegistrationTokens.some((candidate) => candidate.blindedElement?.length !== 32)
          ) {
            throw new Error('Anonymous token issuance state unavailable');
          }

          const privateAuthStorageId = computePrivateAuthStorageId(
            trimmedUsername,
            await awaitCurrent(getCurrentServerScope())
          );
          const privateAuthSlotKey = `${STORAGE_PREFIXES.PRIVATE_AUTH_SLOT}${privateAuthStorageId}`;
          const privateAuthSlotValue = JSON.stringify({
            credentialIndex: ready.credentialIndex,
            anonymitySetSize: ready.anonymitySetSize
          });
          if (!await awaitCurrent(storage.set(
            privateAuthSlotKey,
            privateAuthSlotValue
          ))) {
            throw new Error('Private authentication slot could not be persisted');
          }
          if (await awaitCurrent(storage.get(privateAuthSlotKey)) !== privateAuthSlotValue) {
            throw new Error('Private authentication slot could not be verified');
          }

          const finalizationWaiter = createAuthFinalizeWaiter(120000, operation.signal, authRequestId);
          try {
            await awaitCurrent(websocketClient.sendSecureControlMessage({
              type: SignalType.AUTH_OT_REGISTER_CONFIRM,
              authRequestId,
              registrationAttemptId,
              blindedTokens: pendingRegistrationTokens.map((candidate) =>
                PostQuantumUtils.uint8ArrayToBase64(candidate.blindedElement!)
              ),
              tokenEpoch: getPrivacyPassBatchEpoch(pendingRegistrationTokens)
            }, { failIfQueued: true, signal: operation.signal }));
          } catch (sendError) {
            finalizationWaiter.cancel();
            throw sendError;
          }

          const authResult = await awaitCurrent(finalizationWaiter.promise);

          if (authResult?.serverEntryRequired) {
            await awaitCurrent(helpers.storeAuthenticationState(trimmedUsername, displayUsername));
            return;
          }

          retainNativeSession = true;
          setters.setVaultReady(true);

          setters.setAccountAuthenticated(true);
          setters.setIsLoggedIn(true);
          setters.setIsRegistrationMode(false);
          setters.setIsSubmittingAuth(false);
          } finally {
            registrationBlindedElement?.fill(0);
            registrationBlindingFactor?.fill(0);
            for (const token of registrationBlindedTokens) token.fill(0);
            for (const token of registrationTokenSecrets) {
              token.tokenSecret?.fill(0);
              token.blindingFactor?.fill(0);
              token.blindedElement?.fill(0);
              token.unblindedToken?.fill(0);
            }
            for (const token of pendingRegistrationTokens) {
              token.tokenSecret?.fill(0);
              token.blindingFactor?.fill(0);
              token.blindedElement?.fill(0);
              token.unblindedToken?.fill(0);
            }
            decodedRegistrationResponse?.evaluatedElement?.fill(0);
            decodedRegistrationResponse?.serverNonce?.fill(0);
            registrationFinalize?.envelope?.fill(0);
            registrationFinalize?.exportKey?.fill(0);
            registrationFinalize?.authPublicKey?.fill(0);
          }
        } else {
          let loginBlindedElement: Uint8Array | null = null;
          let loginPublicKeys: Uint8Array[] = [];
          let evaluatedElement: Uint8Array | null = null;
          let loginServerNonce: Uint8Array | null = null;
          let loginAuthChannelBinding: Uint8Array | null = null;
          let loginFinalize: any = null;
          let otResponse: any = null;
          let pendingAccountTokens: any[] = [];
          try {
            setters.setAuthStatus("Preparing anonymous lookup...");
            await awaitCurrent(yieldToEventLoop());

            const privateAuthStorageId = computePrivateAuthStorageId(
              trimmedUsername,
              await awaitCurrent(getCurrentServerScope())
            );
            const privateAuthSlotRaw = await awaitCurrent(storage.get(`${STORAGE_PREFIXES.PRIVATE_AUTH_SLOT}${privateAuthStorageId}`));
            let myIndex: number | null = null;
            if (privateAuthSlotRaw && typeof privateAuthSlotRaw === 'string') {
              try {
                const parsed = JSON.parse(privateAuthSlotRaw);
                if (
                  !parsed ||
                  Array.isArray(parsed) ||
                  Object.getPrototypeOf(parsed) !== Object.prototype ||
                  Object.keys(parsed).sort().join(',') !== 'anonymitySetSize,credentialIndex' ||
                  !Number.isInteger(parsed.credentialIndex) ||
                  parsed.credentialIndex < 0 ||
                  parsed.credentialIndex >= OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE ||
                  parsed.anonymitySetSize !== OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE
                ) {
                  throw new Error('Private authentication slot metadata is invalid');
                }
                myIndex = parsed.credentialIndex;
              } catch {
                console.warn('[Auth] Failed to load private auth slot metadata');
              }
            }
            if (myIndex === null) {
              throw new Error('Private auth slot unavailable. Account recovery is required.');
            }

            setters.setAuthStatus("Generating OT keys...");
            await awaitCurrent(yieldToEventLoop());

            const anonymitySetSize = OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE;
            const loginStart = await awaitCurrent(opaqueClient.startOTLogin(compositeSecret, anonymitySetSize, myIndex));
            loginPublicKeys = loginStart.pubKeys;
            loginBlindedElement = loginStart.blindedElement;
            let encodedPubKeys = loginPublicKeys.map((publicKey) =>
              PostQuantumUtils.uint8ArrayToBase64(publicKey)
            );
            const requestCommitment = privateAuthRequestCommitment(loginBlindedElement, loginPublicKeys);
            for (const publicKey of loginPublicKeys) publicKey.fill(0);
            loginPublicKeys = [];

            setters.setAuthStatus("Retrieving blind record...");
            const onOtChunkProgress = (ev: Event) => {
              if (!helpers.lifecycle.isCurrent(operation)) return;
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

            try {
              let preflightPowSolution: string | undefined;
              for (let round = 0; round < 3; round += 1) {
                const otResponseWaiter = createSignalResponseWaiter<any>(
                  SignalType.AUTH_OT_RESPONSE,
                  240000,
                  'OT response timeout',
                  operation.signal,
                  authRequestId
                );
                let sent = false;
                let lastSendError: unknown = null;
                let roundAuthChannelBinding: string | null = null;
                for (let attempt = 0; attempt < 3 && !sent; attempt++) {
                  const ready = await awaitCurrent(websocketClient.waitUntilReady(45000, operation.signal));
                  if (!ready) {
                    lastSendError = new Error('Connection not ready. Please try again.');
                    break;
                  }
                  try {
                    roundAuthChannelBinding = await awaitCurrent(websocketClient.sendSecureControlMessage({
                      type: SignalType.AUTH_OT_REQUEST,
                      authRequestId,
                      clientPubKeys: preflightPowSolution ? encodedPubKeys : undefined,
                      blindedElement: PostQuantumUtils.uint8ArrayToBase64(loginBlindedElement),
                      requestCommitment,
                      preflightPowSolution
                    }, {
                      authBindingRequestId: authRequestId,
                      failIfQueued: true,
                      signal: operation.signal
                    }));
                    sent = true;
                  } catch (sendError) {
                    if (isStaleAuthOperation(sendError)) throw sendError;
                    lastSendError = sendError;
                    await awaitCurrent(new Promise(resolve => setTimeout(resolve, 500)));
                  }
                }
                if (!sent) {
                  otResponseWaiter.cancel();
                  throw lastSendError instanceof Error ? lastSendError : new Error('WebSocket not connected');
                }

                const response = await awaitCurrent(otResponseWaiter.promise);
                if (!response?.preflightRequired) {
                  if (!roundAuthChannelBinding) {
                    throw new Error('Private authentication channel binding was not transmitted');
                  }
                  const decodedBinding = OPAQUEClientHelpers.decodeResponse<{
                    authChannelBinding: Uint8Array;
                  }>({ authChannelBinding: roundAuthChannelBinding }, {
                    authChannelBinding: 64
                  });
                  loginAuthChannelBinding?.fill(0);
                  loginAuthChannelBinding = decodedBinding.authChannelBinding;
                  otResponse = response;
                  break;
                }

                setters.setAuthStatus("Securing anonymous lookup...");
                preflightPowSolution = await awaitCurrent(solvePowChallenge(
                  response.powChallenge,
                  operation.signal
                ));
              }
              if (!otResponse) {
                throw new Error('Authentication preflight could not be completed');
              }
            } finally {
              encodedPubKeys = [];
              window.removeEventListener(EventType.SECURE_CHUNK_PROGRESS, onOtChunkProgress as EventListener);
            }

            if (!Array.isArray(otResponse.otRecords) || otResponse.otRecords.length !== anonymitySetSize) {
              throw new Error('Invalid private-auth response');
            }
            const decodedResponse = OPAQUEClientHelpers.decodeResponse<any>(otResponse, {
              evaluatedElement: 32,
              serverNonce: 32
            });
            evaluatedElement = decodedResponse.evaluatedElement;
            loginServerNonce = decodedResponse.serverNonce;

            setters.setAuthStatus("Decrypting record...");
            await awaitCurrent(yieldToEventLoop());

            if (!loginAuthChannelBinding) {
              throw new Error('Private authentication channel binding is unavailable');
            }
            loginFinalize = await awaitCurrent(opaqueClient.finishOTLogin(
              compositeSecret,
              otResponse.otRecords,
              evaluatedElement,
              loginServerNonce,
              loginAuthChannelBinding
            ));
            otResponse.otRecords = [];

            if (!loginFinalize.success || !loginFinalize.authMessage || !loginFinalize.exportKey) {
              throw new Error('Incorrect username, password, or passphrase.');
            }

            // Unlock local native account before loading or replacing token pool
            await unlockNativeAccountForTokens();

            pendingAccountTokens = await awaitCurrent(tokenVault.getPendingTokens(250));
            if (pendingAccountTokens.length > 0 && pendingAccountTokens.length !== 250) {
              for (const token of pendingAccountTokens) {
                token.tokenSecret?.fill(0);
                token.blindingFactor?.fill(0);
                token.blindedElement?.fill(0);
                token.unblindedToken?.fill(0);
              }
              pendingAccountTokens = [];
              await awaitCurrent(tokenVault.discardPendingTokens());
            }
            if (pendingAccountTokens.length === 0) {
              const generated = await awaitCurrent(ppClient.generateTokenBatch(250));
              try {
                await awaitCurrent(tokenVault.replaceTokens(generated.tokenSecrets));
              } finally {
                for (const token of generated.blindedTokens) token.fill(0);
                for (const token of generated.tokenSecrets) {
                  token.tokenSecret.fill(0);
                  token.blindingFactor?.fill(0);
                  token.blindedElement?.fill(0);
                  token.unblindedToken?.fill(0);
                }
              }
              pendingAccountTokens = await awaitCurrent(tokenVault.getPendingTokens(250));
            }
            if (
              pendingAccountTokens.length !== 250 ||
              pendingAccountTokens.some((candidate) => candidate.blindedElement?.length !== 32)
            ) {
              throw new Error('Anonymous token issuance state unavailable');
            }

            const powSolution = await awaitCurrent(solvePowChallenge(
              otResponse.powChallenge,
              operation.signal
            ));
            const finalizationWaiter = createAuthFinalizeWaiter(120000, operation.signal, authRequestId);
            try {
              await awaitCurrent(websocketClient.sendSecureControlMessage({
                type: SignalType.AUTH_OT_FINALIZE,
                authRequestId,
                authProof: PostQuantumUtils.uint8ArrayToBase64(loginFinalize.authMessage),
                blindedTokens: pendingAccountTokens.map((candidate) =>
                  PostQuantumUtils.uint8ArrayToBase64(candidate.blindedElement!)
                ),
                tokenEpoch: getPrivacyPassBatchEpoch(pendingAccountTokens),
                powSolution
              }, { failIfQueued: true, signal: operation.signal }));
            } catch (sendError) {
              finalizationWaiter.cancel();
              throw sendError;
            }

            const authResult = await awaitCurrent(finalizationWaiter.promise);
            refs.loginUsernameRef.current = trimmedUsername;
            setters.setUsername(displayUsername);

            if (authResult?.serverEntryRequired) {
              await awaitCurrent(helpers.storeAuthenticationState(trimmedUsername, displayUsername));
              return;
            }

            retainNativeSession = true;
            setters.setVaultReady(true);
            setters.setIsSubmittingAuth(false);
          } finally {
            loginBlindedElement?.fill(0);
            for (const publicKey of loginPublicKeys) publicKey.fill(0);
            evaluatedElement?.fill(0);
            loginServerNonce?.fill(0);
            loginAuthChannelBinding?.fill(0);
            loginFinalize?.exportKey?.fill(0);
            loginFinalize?.authMessage?.fill(0);
            for (const token of pendingAccountTokens) {
              token.tokenSecret?.fill(0);
              token.blindingFactor?.fill(0);
              token.blindedElement?.fill(0);
              token.unblindedToken?.fill(0);
            }
            if (Array.isArray(otResponse?.otRecords)) otResponse.otRecords = [];
          }
        }
      } catch (_error) {
        if (isStaleAuthOperation(_error) || !helpers.lifecycle.isCurrent(operation)) return;
        keyTransparencyClient.destroy();
        tokenVault.lock();
        if ((_error as { code?: unknown })?.code === 'REGISTRATION_ATTEMPT_MISMATCH') {
          await awaitCurrent(clearRegistrationAttempt(trimmedUsername));
        }
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        console.error('[Auth] Error during account submit:', errorMessage);
        const friendlyMessage = /invalid tag|invalid mac|decrypt|tag mismatch/i.test(errorMessage)
          ? 'Incorrect username, password, or passphrase.'
          : (errorMessage || 'Authentication request failed');
        setters.setLoginError(friendlyMessage);
        setters.setIsSubmittingAuth(false);
        
        try { setters.setTokenValidationInProgress(false); } catch { }
      } finally {
        compositeSecret?.fill(0);
        opaqueClient.clear();
        if (helpers.lifecycle.isCurrent(operation)) setters.setIsGeneratingKeys(false);
      }
    } catch (err) {
      if (isStaleAuthOperation(err) || !helpers.lifecycle.isCurrent(operation)) return;
      tokenVault.lock();
      console.error('[Auth] Connection or key error:', err);
      setters.setLoginError(err instanceof Error && err.message ? err.message : 'Connection failed. Please try again.');
      setters.setIsSubmittingAuth(false);
    } finally {
      if (helpers.lifecycle.isCurrent(operation)) {
        await releaseFailedNativeAccount();
        refs.passwordRef.current = '';
        refs.confirmPasswordRef.current = '';
        refs.passphrasePlaintextRef.current = '';
        refs.accountSubmitInFlightRef.current = false;
        setters.setAuthStatus('');
      }
    }
  };
};
