import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { clearTokenEncryptionKey } from "../../lib/signals/signals";
import websocketClient from "../../lib/websocket/websocket";
import { syncEncryptedStorage } from "../../lib/database/encrypted-storage";
import { SecureDB } from "../../lib/database/secureDB";
import { SecureKeyManager } from "../../lib/database/secure-key-manager";
import { secureWipeStringRef } from "../../lib/utils/auth-utils";
import type { HybridKeys } from "../../lib/types/auth-types";
import { storage, session } from "../../lib/tauri-bindings";
import { messageVault } from "../../lib/security/message-vault";
import { removeVaultKey, removeWrappedMasterKey } from "../../lib/cryptography/vault-key";

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
  setTokenValidationInProgress: (v: boolean) => void;
}

export const createLogout = (
  refs: LogoutRefs,
  setters: LogoutSetters,
  clearAuthenticationState: () => Promise<void>
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
      try { await websocketClient.close(); } catch { }
    } catch { }

    try {
      setters.setTokenValidationInProgress(false);
    } catch { }

    // Clear background state definitively to prevent automatic resume on next launch
    try {
      await session.setBackgroundState(false);
    } catch { }

    await clearAuthenticationState();
    await clearTokenEncryptionKey();
    messageVault.clear();

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
      if (pseudonym) {
        // Detailed cleanup of user-specific cryptographic material and tokens
        await storage.init();
        await Promise.allSettled([
          removeVaultKey(pseudonym),
          removeWrappedMasterKey(pseudonym),
          refs.keyManagerRef.current?.deleteDatabase() || Promise.resolve(),
          storage.remove(`key_meta:${pseudonym}`),
          storage.remove(`key_bundle:${pseudonym}`),
          storage.remove('tok:1'), // Final redundant safety purge
          storage.remove('last_authenticated_username'),
          storage.remove('last_authenticated_display_name'),
          storage.remove('bg_session_active'),
          storage.remove('bg_session_last_activity'),
          storage.remove('bg_session_pending')
        ]);
      }
    } catch { }

    try {
      await syncEncryptedStorage.removeItem('qorchat_server_pin_v2');
      await syncEncryptedStorage.removeItem('last_authenticated_username');
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
