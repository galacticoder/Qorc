import { RefObject } from "react";
import websocketClient from "../../lib/websocket";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { SecureKeyManager } from "../../lib/database/secure-key-manager";
import { ensureVaultKeyCryptoKey, saveWrappedMasterKey } from "../../lib/cryptography/vault-key";
import { validateServerKeys, deriveCombinedSecretInput } from "../../lib/utils/auth-utils";
import type { ServerHybridPublicKeys, HybridKeys } from "../../lib/types/auth-types";

export interface KeyManagementRefs {
  loginUsernameRef: RefObject<string>;
  passwordRef: RefObject<string>;
  confirmPasswordRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  passphraseRef: RefObject<string>;
  aesKeyRef: RefObject<CryptoKey | null>;
  hybridKeysRef: RefObject<HybridKeys | null>;
  keyManagerRef: RefObject<SecureKeyManager | null>;
  keyManagerOwnerRef: RefObject<string>;
  getKeysPromiseRef: RefObject<Promise<any> | null>;
  serverHybridPublicRef: RefObject<ServerHybridPublicKeys | null>;
}

export interface KeyManagementSetters {
  setIsGeneratingKeys: (v: boolean) => void;
  setAuthStatus: (v: string | ((prev: string) => string)) => void;
  setLoginError: (v: string) => void;
  setShowPassphrasePrompt: (v: boolean) => void;
}

export const createDeriveEffectivePassphrase = (refs: KeyManagementRefs) => {
  return (): string => {
    const passphrase = refs.passphrasePlaintextRef.current;
    const currentUsername = refs.loginUsernameRef.current;
    let pwd = refs.passwordRef.current;

    if (!passphrase) {
      throw new Error("Passphrase not available");
    }
    if (!currentUsername) {
      throw new Error("Username not available");
    }

    if (!pwd && refs.confirmPasswordRef.current) {
      pwd = refs.confirmPasswordRef.current;
    }
    if (!pwd) {
      throw new Error("Password not available");
    }

    return deriveCombinedSecretInput(currentUsername, pwd, passphrase);
  };
};

export const createGetKeysOnDemand = (
  refs: KeyManagementRefs,
  deriveEffectivePassphrase: () => string
) => {
  return async (): Promise<HybridKeys | null> => {
    if (!refs.keyManagerRef.current) {
      return null;
    }

    try {
      if (refs.hybridKeysRef.current) {
        return refs.hybridKeysRef.current;
      }

      if (refs.getKeysPromiseRef.current) {
        const cached = await refs.getKeysPromiseRef.current.catch(() => null);
        if (cached) return cached;
      }

      const fetching = (async () => {
        try {
          let keys = await refs.keyManagerRef.current!.getKeys().catch(() => null);

          if (!keys) {
            try {
              const effectivePassphrase = deriveEffectivePassphrase();
              const metadata = await refs.keyManagerRef.current!.getKeyMetadata();
              if (metadata) {
                await refs.keyManagerRef.current!.initialize(effectivePassphrase, metadata.salt);
              } else {
                await refs.keyManagerRef.current!.initialize(effectivePassphrase);
              }
              keys = await refs.keyManagerRef.current!.getKeys();
            } catch {
              return null;
            }
          }

          if (!keys || !keys.kyber || !keys.dilithium) {
            return null;
          }

          refs.hybridKeysRef.current = keys;
          return keys;
        } finally {
          refs.getKeysPromiseRef.current = null;
        }
      })();

      refs.getKeysPromiseRef.current = fetching;
      const keys = await fetching;
      return keys;
    } catch {
      return null;
    }
  };
};

export const createWaitForServerKeys = (
  refs: KeyManagementRefs,
  setters: KeyManagementSetters
) => {
  return async (timeoutMs: number = 15000): Promise<ServerHybridPublicKeys> => {
    const start = Date.now();

    let current = refs.serverHybridPublicRef.current;
    if (current && validateServerKeys(current)) {
      return current;
    }

    setters.setAuthStatus((prev: string) => prev || 'Fetching server keys...');

    while (Date.now() - start < timeoutMs) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      current = refs.serverHybridPublicRef.current;
      if (current && validateServerKeys(current)) {
        return current;
      }
    }

    throw new Error('Failed to retrieve server keys from server');
  };
};

export const createInitializeKeys = (
  refs: KeyManagementRefs,
  setters: KeyManagementSetters,
  deriveEffectivePassphrase: () => string,
  recoveryActive: boolean
) => {
  return async (isRecoveryMode = false, providedSalt?: string, providedArgon2Params?: any) => {
    setters.setIsGeneratingKeys(true);
    setters.setAuthStatus("Initializing...");
    try {
      const effectivePassphrase = deriveEffectivePassphrase();

      const currentUsername = refs.loginUsernameRef.current;
      if (!currentUsername) {
        throw new Error("Username not available");
      }

      await new Promise(resolve => setTimeout(resolve, 0));

      if (!refs.keyManagerRef.current || refs.keyManagerOwnerRef.current !== currentUsername) {
        try {
          if (refs.keyManagerRef.current) {
            refs.keyManagerRef.current.clearKeys();
            await refs.keyManagerRef.current.deleteDatabase();
          }
        } catch { }

        try {
          refs.keyManagerRef.current = new SecureKeyManager(currentUsername);
          refs.keyManagerOwnerRef.current = currentUsername;
          refs.hybridKeysRef.current = null;
        } catch (_e) {
          throw new Error('Key manager init failed: ' + ((_e as any)?.message || _e));
        }
      }

      await new Promise(resolve => setTimeout(resolve, 0));

      let hasExistingKeys = await refs.keyManagerRef.current.hasKeys();

      if (hasExistingKeys) {
        setters.setAuthStatus("Loading keys...");

        await new Promise(resolve => setTimeout(resolve, 0));

        let meta: { salt?: string; argon2Params?: any } | null = null;
        try {
          meta = await refs.keyManagerRef.current.getKeyMetadata();
          if (meta?.salt) {
            await refs.keyManagerRef.current.initialize(effectivePassphrase, meta.salt);
          } else {
            await refs.keyManagerRef.current.initialize(effectivePassphrase);
          }
          const existingKeys = await refs.keyManagerRef.current.getKeys();

          if (existingKeys) {
            setters.setAuthStatus("Verifying...");
            refs.hybridKeysRef.current = existingKeys;
            try {
              const pub = existingKeys.kyber.publicKeyBase64;
              const secB64 = CryptoUtils.Base64.arrayBufferToBase64(existingKeys.kyber.secretKey);
              if (typeof (window as any).edgeApi?.setStaticMlkemKeys === 'function' && pub && secB64) {
                await (window as any).edgeApi.setStaticMlkemKeys({ username: currentUsername, publicKeyBase64: pub, secretKeyBase64: secB64 });
              }
            } catch { }

            const masterKey = refs.keyManagerRef.current.getMasterKey();
            if (masterKey) {
              refs.aesKeyRef.current = masterKey;
              try {
                const vaultKey = await ensureVaultKeyCryptoKey(currentUsername);
                const raw = new Uint8Array(await CryptoUtils.Keys.exportAESKey(masterKey));
                await saveWrappedMasterKey(currentUsername, raw, vaultKey);
                raw.fill(0);
              } catch { }
            }

            const encodedHash = await refs.keyManagerRef.current.getEncodedPassphraseHash(effectivePassphrase);
            if (encodedHash) {
              refs.passphraseRef.current = encodedHash;
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
            setters.setLoginError('Incorrect passphrase. Please try again.');
            setters.setShowPassphrasePrompt(true);
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
          setters.setLoginError('Recovery failed: stored keys not found.');
          throw new Error('Recovery mode: no existing keys');
        }

        setters.setAuthStatus("Generating keys...");
        const hybridKeyPair = await CryptoUtils.Hybrid.generateHybridKeyPair();

        setters.setAuthStatus("Securing...");
        if (providedSalt && providedArgon2Params) {
          await refs.keyManagerRef.current.initialize(effectivePassphrase, providedSalt, providedArgon2Params);
        } else {
          await refs.keyManagerRef.current.initialize(effectivePassphrase);
        }
        setters.setAuthStatus("Storing...");
        await refs.keyManagerRef.current.storeKeys(hybridKeyPair);

        const masterKey = refs.keyManagerRef.current.getMasterKey();
        if (masterKey) {
          refs.aesKeyRef.current = masterKey;
          try {
            const vaultKey = await ensureVaultKeyCryptoKey(currentUsername);
            const raw = new Uint8Array(await CryptoUtils.Keys.exportAESKey(masterKey));
            await saveWrappedMasterKey(currentUsername, raw, vaultKey);
            raw.fill(0);
          } catch { }
        }

        const encodedHash = await refs.keyManagerRef.current.getEncodedPassphraseHash(effectivePassphrase);
        if (encodedHash) {
          refs.passphraseRef.current = encodedHash;
        }

        refs.hybridKeysRef.current = hybridKeyPair;
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
      setters.setLoginError(`Key generation failed: ${errorMessage}`);
      throw _error;
    } finally {
      setters.setIsGeneratingKeys(false);
      setters.setAuthStatus("");
    }
  };
};
