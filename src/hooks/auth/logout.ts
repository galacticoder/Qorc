import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { clearTokenEncryptionKey } from "../../lib/signals";
import websocketClient from "../../lib/websocket/websocket";
import { syncEncryptedStorage } from "../../lib/database/encrypted-storage";
import { SecureDB } from "../../lib/database/secureDB";
import { SecureKeyManager } from "../../lib/database/secure-key-manager";
import { secureWipeStringRef } from "../../lib/utils/auth-utils";
import type { HybridKeys } from "../../lib/types/auth-types";

export interface LogoutRefs {
  loginUsernameRef: RefObject<string>;
  passwordRef: RefObject<string>;
  passphraseRef: RefObject<string>;
  passphrasePlaintextRef: RefObject<string>;
  aesKeyRef: RefObject<CryptoKey | null>;
  hybridKeysRef: RefObject<HybridKeys | null>;
  keyManagerRef: RefObject<SecureKeyManager | null>;
}

export interface LogoutSetters {
  setIsLoggedIn: (v: boolean) => void;
  setLoginError: (v: string) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setIsRegistrationMode: (v: boolean) => void;
  setIsSubmittingAuth: (v: boolean) => void;
  setUsername: (v: string) => void;
}

export const createLogout = (
  refs: LogoutRefs,
  setters: LogoutSetters,
  clearAuthenticationState: () => void
) => {
  return async (secureDBRef?: RefObject<SecureDB | null>, loginErrorMessage: string = "") => {
    try {
      const user = refs.loginUsernameRef.current || '';
      if (user && websocketClient.isConnectedToServer()) {
        try {
          if (websocketClient.isPQSessionEstablished?.()) {
            await websocketClient.sendSecureControlMessage({ type: SignalType.USER_DISCONNECT, username: user, timestamp: Date.now() });
            try { await new Promise(res => setTimeout(res, 25)); } catch { }
          }
        } catch { }
      }
      try { websocketClient.close(); } catch { }
    } catch { }

    clearAuthenticationState();
    clearTokenEncryptionKey();

    try {
      secureWipeStringRef(refs.passwordRef as any);
      secureWipeStringRef(refs.passphraseRef as any);
      secureWipeStringRef(refs.passphrasePlaintextRef as any);
      refs.aesKeyRef.current = null;
      refs.hybridKeysRef.current = null;

      if (typeof window !== 'undefined' && (window as any).gc) {
        (window as any).gc();
      }
    } catch { }

    if (secureDBRef?.current) {
      secureDBRef.current = null;
    }

    try {
      const pseudonym = refs.loginUsernameRef.current || '';
      if (pseudonym && (window as any).electronAPI?.secureStore) {
        await (window as any).electronAPI.secureStore.init();
        try { await (window as any).electronAPI.secureStore.remove(`aes:${pseudonym}`); } catch { }
        try { await (window as any).electronAPI.secureStore.remove(`pph:${pseudonym}`); } catch { }
        try { await (window as any).electronAPI.secureStore.remove(`tok:${(window as any).electronAPI?.instanceId || '1'}`); } catch { }
      }
    } catch { }

    try {
      syncEncryptedStorage.removeItem('qorchat_server_pin_v2');
    } catch { }

    if (refs.keyManagerRef.current) {
      try {
        refs.keyManagerRef.current.clearKeys();
        refs.keyManagerRef.current = null;
      } catch { }
    }

    refs.loginUsernameRef.current = "";

    setters.setIsLoggedIn(false);
    setters.setLoginError(loginErrorMessage);
    setters.setAccountAuthenticated(false);
    setters.setIsRegistrationMode(false);
    setters.setIsSubmittingAuth(false);
    setters.setUsername("");
  };
};

export const createGetLogout = (logout: (secureDBRef?: RefObject<SecureDB | null>, loginErrorMessage?: string) => Promise<void>) => {
  return (Database: { secureDBRef: RefObject<SecureDB | null> }) => {
    return async () => await logout(Database.secureDBRef, "Logged out");
  };
};
