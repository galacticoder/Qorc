import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import websocketClient from "../../lib/websocket/websocket";
import { signal, database } from "../../lib/tauri-bindings";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import type { ServerHybridPublicKeys, HybridKeys, HashParams } from "../../lib/types/auth-types";
import { EventType } from "../../lib/types/event-types";
import { ErrorType } from "../../lib/types/error-types";

export interface PassphraseRefs {
  loginUsernameRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  passphraseRef: RefObject<string>;
  passwordRef: RefObject<string>;
  passphraseLimiterRef: RefObject<{ tokens: number; last: number }>;
  keyManagerRef: RefObject<any>;
}

export interface PassphraseSetters {
  setAuthStatus: (v: string) => void;
  setLoginError: (v: string) => void;
  setShowPassphrasePrompt: (v: boolean) => void;
  setRecoveryActive: (v: boolean) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setIsLoggedIn: (v: boolean) => void;
  setMaxStepReached: (v: 'login' | 'passphrase' | 'server') => void;
}

export interface PassphraseState {
  isLoggedIn: boolean;
  accountAuthenticated: boolean;
  recoveryActive: boolean;
  passphraseHashParams: HashParams;
  serverHybridPublic: ServerHybridPublicKeys | null;
}

export const createHandlePassphraseSubmit = (
  refs: PassphraseRefs,
  setters: PassphraseSetters,
  state: PassphraseState,
  helpers: {
    initializeKeys: (isRecoveryMode?: boolean, providedSalt?: string, providedArgon2Params?: any) => Promise<void>;
    deriveEffectivePassphrase: () => string;
    getKeysOnDemand: () => Promise<HybridKeys | null>;
  }
) => {
  return async (passphrase: string, mode: "login" | "register") => {
    refs.passphrasePlaintextRef.current = passphrase;
    setters.setAuthStatus("Processing...");

    try {
      const limiter = refs.passphraseLimiterRef.current;
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

      const isInRecoveryMode = state.recoveryActive || (state.isLoggedIn && state.accountAuthenticated && !state.passphraseHashParams);
      if (mode === "login" && state.passphraseHashParams) {
        await helpers.initializeKeys(isInRecoveryMode, state.passphraseHashParams.salt, state.passphraseHashParams);
      } else {
        await helpers.initializeKeys(isInRecoveryMode);
      }

      const isRecoveryMode = state.isLoggedIn && state.accountAuthenticated && !state.passphraseHashParams;

      if (isRecoveryMode) {
        setters.setShowPassphrasePrompt(false);
        setters.setRecoveryActive(false);
        setters.setAuthStatus("Verified");
        setTimeout(() => setters.setAuthStatus(""), 2000);
        return;
      }

      let passphraseHash: string;
      const combinedSecret = helpers.deriveEffectivePassphrase();

      if (mode === "login") {
        if (!state.passphraseHashParams) {
          setters.setAuthStatus("Retrieving parameters...");
          throw new Error("Missing parameters");
        }

        setters.setAuthStatus("Hashing...");
        passphraseHash = await CryptoUtils.Hash.hashDataUsingInfo(
          combinedSecret,
          state.passphraseHashParams
        );
      } else {
        setters.setAuthStatus("Generating hash...");
        passphraseHash = await CryptoUtils.Hash.hashData(combinedSecret);
      }

      refs.passphraseRef.current = passphraseHash;

      setters.setAuthStatus("Sending...");
      const messageToSend = {
        type: SignalType.PASSPHRASE_HASH,
        passphraseHash
      };

      websocketClient.send(JSON.stringify(messageToSend));

      if (refs.keyManagerRef.current) {
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
            window.removeEventListener(EventType.LIBSIGNAL_PUBLISH_STATUS, onStatus as EventListener);
            window.removeEventListener('beforeunload', onDisconnect);
          };
          window.addEventListener(EventType.LIBSIGNAL_PUBLISH_STATUS, onStatus as EventListener);
          window.addEventListener('beforeunload', onDisconnect);
          timeout = setTimeout(() => {
            cleanup();
            resolve({ success: false, error: 'Server did not respond to bundle publication' });
          }, timeoutMs);
        });

        try {
          setters.setAuthStatus("Checking identity...");
          let identityExists = false;
          try {
            const existing = await signal.createPreKeyBundle(refs.loginUsernameRef.current!);
            if (existing && existing.identityKeyBase64) {
              identityExists = true;
            }
          } catch {
            identityExists = false;
          }

          if (!identityExists) {
            setters.setAuthStatus("Generating identity...");
            try {
              await signal.generateIdentity(refs.loginUsernameRef.current!);
            } catch (err) {
              const error = err instanceof Error ? err.message : 'Failed to generate identity';

              websocketClient.send(JSON.stringify({
                type: ErrorType.SIGNAL_BUNDLE_FAILURE,
                error,
                stage: 'identity-generation',
                username: refs.loginUsernameRef.current
              }));

              setters.setAuthStatus('');
              setters.setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
              try {
                setters.setAccountAuthenticated(false);
                setters.setIsLoggedIn(false);
                setters.setShowPassphrasePrompt(false);
                setters.setMaxStepReached('login');
              } catch { }
              return;
            }
          }

          setters.setAuthStatus("Generating prekeys...");
          try {
            await signal.generatePreKeys(refs.loginUsernameRef.current!, 1, 100);
          } catch (err) {
            const error = err instanceof Error ? err.message : 'Failed to generate prekeys';

            websocketClient.send(JSON.stringify({
              type: ErrorType.SIGNAL_BUNDLE_FAILURE,
              error,
              stage: 'prekey-generation',
              username: refs.loginUsernameRef.current
            }));

            setters.setAuthStatus('');
            setters.setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
            try {
              setters.setAccountAuthenticated(false);
              setters.setIsLoggedIn(false);
              setters.setShowPassphrasePrompt(false);
              setters.setMaxStepReached('login');
            } catch { }
            return;
          }

          setters.setAuthStatus("Publishing bundle...");
          let bundle;
          try {
            bundle = await signal.createPreKeyBundle(refs.loginUsernameRef.current!);
          } catch (err) {
            const error = err instanceof Error ? err.message : 'Failed to create pre-key bundle';

            websocketClient.send(JSON.stringify({
              type: ErrorType.SIGNAL_BUNDLE_FAILURE,
              error,
              stage: 'bundle-creation',
              username: refs.loginUsernameRef.current
            }));

            setters.setAuthStatus('');
            setters.setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
            try {
              setters.setAccountAuthenticated(false);
              setters.setIsLoggedIn(false);
              setters.setShowPassphrasePrompt(false);
              setters.setMaxStepReached('login');
            } catch { }
            return;
          }

          if (!bundle || !bundle.registrationId || !bundle.identityKeyBase64 || !bundle.signedPreKey) {
            const error = 'Invalid bundle structure returned from Signal handler';

            websocketClient.send(JSON.stringify({
              type: ErrorType.SIGNAL_BUNDLE_FAILURE,
              error,
              stage: 'bundle-validation',
              username: refs.loginUsernameRef.current
            }));

            setters.setAuthStatus('');
            setters.setLoginError(`Signal initialization failed: ${error}. Server will disconnect for safety.`);
            try {
              setters.setAccountAuthenticated(false);
              setters.setIsLoggedIn(false);
              setters.setShowPassphrasePrompt(false);
              setters.setMaxStepReached('login');
            } catch { }
            return;
          }

          websocketClient.send(JSON.stringify({ type: SignalType.LIBSIGNAL_PUBLISH_BUNDLE, bundle }));

          setters.setAuthStatus("Verifying bundle...");
          const response = await waitForServerResponse();

          if (!response.success) {
            setters.setAuthStatus('');
            setters.setLoginError(response.error || 'Server did not accept Signal bundle');
            return;
          }

        } catch (_err) {
          const msg = _err instanceof Error ? _err.message : String(_err);

          try {
            websocketClient.send(JSON.stringify({
              type: ErrorType.SIGNAL_BUNDLE_FAILURE,
              error: msg,
              stage: 'unexpected-error',
              username: refs.loginUsernameRef.current
            }));
          } catch { }

          setters.setAuthStatus('');
          setters.setLoginError(`Signal initialization error: ${msg}`);
          try {
            setters.setAccountAuthenticated(false);
            setters.setIsLoggedIn(false);
            setters.setShowPassphrasePrompt(false);
            setters.setMaxStepReached('login');
          } catch { }
          return;
        }

        if (refs.keyManagerRef.current && state.serverHybridPublic) {
          const publicKeys = await refs.keyManagerRef.current.getPublicKeys();
          if (publicKeys) {
            const keysToSend = {
              kyberPublicBase64: publicKeys.kyberPublicBase64 || '',
              dilithiumPublicBase64: publicKeys.dilithiumPublicBase64 || '',
              x25519PublicBase64: publicKeys.x25519PublicBase64 || ''
            };

            const hybridKeysPayload = JSON.stringify(keysToSend);

            const localKeys = await helpers.getKeysOnDemand();
            if (!localKeys?.dilithium?.secretKey || !localKeys.dilithium.publicKeyBase64) {
              throw new Error('Dilithium keys required for hybrid key update');
            }

            const encryptedHybridKeys = await CryptoUtils.Hybrid.encryptForServer(
              hybridKeysPayload,
              state.serverHybridPublic,
              {
                senderDilithiumSecretKey: localKeys.dilithium.secretKey,
                metadata: {
                  context: SignalType.HYBRID_KEYS_UPDATE,
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

      if (refs.passwordRef) refs.passwordRef.current = '';

    } catch (_error) {
      if (_error instanceof Error && _error.message.includes('Key decryption failed')) {
        return;
      }
      const message = _error instanceof Error ? _error.message : String(_error);
      setters.setLoginError(`Passphrase processing failed: ${message}`);
      throw _error;
    }
  };
};
