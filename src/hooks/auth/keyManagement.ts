import { RefObject } from "react";
import { validateServerKeys } from "../../lib/utils/auth-utils";
import type { ServerHybridPublicKeys, HybridKeys } from "../../lib/types/auth-types";
import { getCurrentLocalAccountScope } from "../../lib/security/local-account-scope";
import { account, type NativeAccountPublicKeys } from "../../lib/tauri-bindings";
import {
  type AuthLifecycle,
  StaleAuthOperationError,
  isStaleAuthOperation,
} from "../../lib/auth/auth-lifecycle";

export interface KeyManagementRefs {
  loginUsernameRef: RefObject<string>;
  passwordRef: RefObject<string>;
  confirmPasswordRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  hybridKeysRef: RefObject<HybridKeys | null>;
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

const toPublicHybridKeys = (keys: NativeAccountPublicKeys): HybridKeys => ({
  native: true,
  kyber: { publicKeyBase64: keys.kyberPublicBase64 },
  dilithium: { publicKeyBase64: keys.dilithiumPublicBase64 },
  x25519: { publicKeyBase64: keys.x25519PublicBase64 },
  accountRoot: { publicKeyBase64: keys.accountRootPublicBase64 },
});

export const createDeriveEffectivePassphrase = (refs: KeyManagementRefs) => {
  return (): string => {
    const passphrase = refs.passphrasePlaintextRef.current;
    const currentUsername = refs.loginUsernameRef.current;
    const pwd = refs.passwordRef.current;

    if (!passphrase) {
      throw new Error("Passphrase not available");
    }
    if (!currentUsername) {
      throw new Error("Username not available");
    }

    if (!pwd) {
      throw new Error("Password not available");
    }

    return passphrase;
  };
};

export const createGetKeysOnDemand = (
  refs: KeyManagementRefs,
  _deriveEffectivePassphrase: () => string,
  lifecycle: AuthLifecycle
) => {
  return async (): Promise<HybridKeys | null> => {
    const operation = lifecycle.capture();
    const currentUsername = refs.loginUsernameRef.current;
    if (!currentUsername) {
      return null;
    }

    const accountScope = await getCurrentLocalAccountScope(currentUsername);
    const assertOwner = () => {
      lifecycle.assertCurrent(operation);
      if (
        refs.loginUsernameRef.current !== currentUsername ||
        refs.keyManagerOwnerRef.current !== accountScope
      ) {
        throw new StaleAuthOperationError();
      }
    };
    assertOwner();

    if (refs.hybridKeysRef.current) {
      return refs.hybridKeysRef.current;
    }

    if (refs.getKeysPromiseRef.current) {
      const existing = refs.getKeysPromiseRef.current;
      const cached = await existing;
      assertOwner();
      if (refs.getKeysPromiseRef.current === existing) return cached;
      throw new StaleAuthOperationError();
    }

    const fetching = (async () => {
      assertOwner();
      if (!await account.isUnlocked(accountScope)) return null;
      assertOwner();
      const keys = toPublicHybridKeys(await account.publicKeys());
      assertOwner();
      refs.hybridKeysRef.current = keys;
      return keys;
    })();

    refs.getKeysPromiseRef.current = fetching;
    try {
      return await fetching;
    } finally {
      if (refs.getKeysPromiseRef.current === fetching) {
        refs.getKeysPromiseRef.current = null;
      }
    }
  };
};

export const createWaitForServerKeys = (
  refs: KeyManagementRefs,
  setters: KeyManagementSetters
) => {
  return async (
    signal?: AbortSignal,
    timeoutMs: number = 15000
  ): Promise<ServerHybridPublicKeys> => {
    const start = Date.now();

    let current = refs.serverHybridPublicRef.current;
    if (current && validateServerKeys(current)) {
      return current;
    }

    setters.setAuthStatus((prev: string) => prev || 'Fetching server keys...');

    while (Date.now() - start < timeoutMs) {
      if (signal?.aborted) throw new StaleAuthOperationError();
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        let timer: ReturnType<typeof setTimeout>;
        const finish = (error?: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal?.removeEventListener('abort', onAbort);
          if (error) reject(error);
          else resolve();
        };
        const onAbort = () => finish(new StaleAuthOperationError());
        timer = setTimeout(() => finish(), 100);
        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) onAbort();
      });
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
  _deriveEffectivePassphrase: () => string,
  recoveryActive: boolean,
  lifecycle: AuthLifecycle
) => {
  return async () => {
    const operation = lifecycle.capture();
    const currentUsername = refs.loginUsernameRef.current;
    if (!currentUsername) {
      throw new Error("Username not available");
    }
    setters.setIsGeneratingKeys(true);
    setters.setAuthStatus("Initializing...");
    let operationAccountScope = '';
    try {
      const accountScope = await getCurrentLocalAccountScope(currentUsername);
      const assertAccount = () => {
        lifecycle.assertCurrent(operation);
        if (refs.loginUsernameRef.current !== currentUsername) {
          throw new StaleAuthOperationError();
        }
      };
      assertAccount();

      refs.keyManagerOwnerRef.current = accountScope;
      refs.hybridKeysRef.current = null;
      operationAccountScope = accountScope;
      const assertOwner = () => {
        assertAccount();
        if (refs.keyManagerOwnerRef.current !== accountScope) {
          throw new StaleAuthOperationError();
        }
      };

      const password = refs.passwordRef.current;
      const passphrase = refs.passphrasePlaintextRef.current;
      if (!password || !passphrase) throw new Error('Account credentials are unavailable');
      setters.setAuthStatus(recoveryActive ? "Unlocking native vault..." : "Securing native account...");
      const opened = await account.open(
        accountScope,
        currentUsername,
        password,
        passphrase,
      );
      assertOwner();
      refs.hybridKeysRef.current = toPublicHybridKeys(opened.publicKeys);
    } catch (_error) {
      if (
        refs.keyManagerOwnerRef.current === operationAccountScope
      ) {
        refs.hybridKeysRef.current = null;
      }
      if (!isStaleAuthOperation(_error) && lifecycle.isCurrent(operation)) {
        const errorMessage = _error instanceof Error ? _error.message : String(_error);
        setters.setLoginError(
          `${recoveryActive ? 'Local account unlock' : 'Native account setup'} failed: ${errorMessage}`,
        );
      }
      throw _error;
    } finally {
      if (lifecycle.isCurrent(operation) && refs.loginUsernameRef.current === currentUsername) {
        refs.passwordRef.current = '';
        refs.confirmPasswordRef.current = '';
        refs.passphrasePlaintextRef.current = '';
        setters.setIsGeneratingKeys(false);
        setters.setAuthStatus("");
      }
    }
  };
};
