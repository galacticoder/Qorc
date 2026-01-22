import { RefObject } from "react";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import { retrieveOfflineMessages } from '../../lib/websocket/offline-message-handler';
import type { HybridKeys } from "../../lib/types/auth-types";
import { signal } from "../../lib/tauri-bindings";

export interface AuthSuccessRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  keyManagerRef: RefObject<any>;
}

export interface AuthSuccessSetters {
  setAuthStatus: (v: string) => void;
  setUsername: (v: string) => void;
  setPseudonym: (v: string) => void;
  setIsLoggedIn: (v: boolean) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setRecoveryActive: (v: boolean) => void;
  setShowPassphrasePrompt: (v: boolean) => void;
  setIsRegistrationMode: (v: boolean) => void;
  setLoginError: (v: string) => void;
}

export const createHandleAuthSuccess = (
  refs: AuthSuccessRefs,
  setters: AuthSuccessSetters,
  helpers: {
    storeAuthenticationState: (username: string, originalUsername?: string) => void;
    deriveEffectivePassphrase: () => string;
    getKeysOnDemand: () => Promise<HybridKeys | null>;
  }
) => {
  return async (username: string, isRecovered = false) => {
    const displayName = refs.originalUsernameRef.current || username;

    if (isRecovered && !refs.passphrasePlaintextRef.current) {
      setters.setAuthStatus("Passphrase required");
      setters.setUsername(displayName);
      setters.setPseudonym(username);

      refs.loginUsernameRef.current = username;

      setters.setIsLoggedIn(true);
      setters.setAccountAuthenticated(true);

      await helpers.storeAuthenticationState(username, displayName);

      setters.setRecoveryActive(true);
      setters.setShowPassphrasePrompt(true);
      setters.setIsRegistrationMode(false);
      setters.setLoginError("");
      return;
    }

    setters.setAuthStatus("Authenticated");
    setters.setUsername(displayName);
    setters.setPseudonym(username);
    setters.setIsLoggedIn(true);
    setters.setAccountAuthenticated(true);

    await helpers.storeAuthenticationState(username, displayName);

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    setTimeout(() => setters.setAuthStatus(""), 1000);
    setters.setLoginError("");

    try {
      const label = new TextEncoder().encode('signal-storage-key-v1');
      let derived: Uint8Array | null = null;
      try {
        const keys = await helpers.getKeysOnDemand?.();
        const kyberSecret: Uint8Array | undefined = keys?.kyber?.secretKey;
        if (kyberSecret && kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
          derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
        } else {
          try {
            const composite = helpers.deriveEffectivePassphrase();
            const salt = new TextEncoder().encode('signal-storage-key-v1');
            derived = await (CryptoUtils as any).KDF.argon2id(composite, {
              salt,
              time: 3,
              memoryCost: 1 << 17,
              parallelism: 2,
              hashLen: 32
            });
          } catch { }
        }
        if (derived) {
          const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);
          await signal.setStorageKey(keyB64);
          if ((derived as any)?.fill) (derived as any).fill(0);
        }
      } catch { }
    } catch { }

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    if (refs.keyManagerRef.current && refs.passphrasePlaintextRef.current) {
      try {
        const effectivePassphrase = helpers.deriveEffectivePassphrase();
        refs.keyManagerRef.current.initialize(effectivePassphrase).catch((_error: any) => {
        });
      } catch { }
    }

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    try {
      retrieveOfflineMessages();
    } catch { }
  };
};
