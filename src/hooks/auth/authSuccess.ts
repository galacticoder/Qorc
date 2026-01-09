import { RefObject } from "react";
import { CryptoUtils } from "../../lib/utils/crypto-utils";
import type { HybridKeys } from "../../lib/types/auth-types";

export interface AuthSuccessRefs {
  loginUsernameRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  keyManagerRef: RefObject<any>;
}

export interface AuthSuccessSetters {
  setAuthStatus: (v: string) => void;
  setUsername: (v: string) => void;
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
    storeAuthenticationState: (username: string) => void;
    deriveEffectivePassphrase: () => string;
    getKeysOnDemand: () => Promise<HybridKeys | null>;
  }
) => {
  return async (username: string, isRecovered = false) => {
    if (isRecovered && !refs.passphrasePlaintextRef.current) {
      setters.setAuthStatus("Passphrase required");
      setters.setUsername(username);

      refs.loginUsernameRef.current = username;

      setters.setIsLoggedIn(true);
      setters.setAccountAuthenticated(true);

      helpers.storeAuthenticationState(username);

      setters.setRecoveryActive(true);
      setters.setShowPassphrasePrompt(true);
      setters.setIsRegistrationMode(false);
      setters.setLoginError("");
      return;
    }

    setters.setAuthStatus("Authenticated");
    setters.setUsername(username);
    setters.setIsLoggedIn(true);
    setters.setAccountAuthenticated(true);

    helpers.storeAuthenticationState(username);

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }

    setTimeout(() => setters.setAuthStatus(""), 1000);
    setters.setLoginError("");

    try {
      if ((window as any).edgeApi?.setSignalStorageKey) {
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
            await (window as any).edgeApi.setSignalStorageKey({ keyBase64: keyB64 });
            if ((derived as any)?.fill) (derived as any).fill(0);
          }
        } catch { }
      }
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
      const { retrieveOfflineMessages } = await import('../../lib/websocket/offline-message-handler');
      retrieveOfflineMessages();
    } catch { }
  };
};
