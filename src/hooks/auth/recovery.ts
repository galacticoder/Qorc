import { RefObject } from "react";
import { SignalType } from "../../lib/types/signal-types";
import { EventType } from "../../lib/types/event-types";
import websocketClient from "../../lib/websocket/websocket";
import { syncEncryptedStorage } from "../../lib/database/encrypted-storage";
import { SecureDB } from "../../lib/database/secureDB";

export interface RecoveryRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
}

export interface RecoverySetters {
  setUsername: (v: string) => void;
  setAuthStatus: (v: string) => void;
  setTokenValidationInProgress: (v: boolean) => void;
}

export const createAttemptAuthRecovery = (
  refs: RecoveryRefs,
  setters: RecoverySetters,
  accountAuthenticated: boolean,
  isLoggedIn: boolean
) => {
  return async (): Promise<boolean> => {
    const storedUsername = refs.loginUsernameRef.current || syncEncryptedStorage.getItem('last_authenticated_username');

    if (!storedUsername) {
      return false;
    }

    const alreadyAuthenticated = accountAuthenticated && isLoggedIn;
    if (!alreadyAuthenticated) {
      try { setters.setTokenValidationInProgress(true); } catch { }
      setters.setAuthStatus("Recovering...");
    }

    try {
      if (!websocketClient.isConnectedToServer()) {
        await websocketClient.connect();
      }

      refs.loginUsernameRef.current = storedUsername;
      try { refs.originalUsernameRef.current = storedUsername; } catch { }
      setters.setUsername(storedUsername);

      websocketClient.send(JSON.stringify({
        type: SignalType.AUTH_RECOVERY,
        username: storedUsername
      }));

      return true;
    } catch {
      if (!alreadyAuthenticated) {
        setters.setAuthStatus('');
        try { setters.setTokenValidationInProgress(false); } catch { }
      }
      return false;
    }
  };
};

export const createStoreAuthenticationState = () => {
  return (username: string) => {
    try {
      syncEncryptedStorage.setItem('last_authenticated_username', username);
    } catch { }
  };
};

export const createClearAuthenticationState = () => {
  return () => {
    try {
      syncEncryptedStorage.removeItem('last_authenticated_username');
    } catch { }
  };
};

export const createStoreUsernameMapping = (refs: RecoveryRefs) => {
  return async (secureDBInstance: SecureDB) => {
    if (refs.originalUsernameRef.current && refs.loginUsernameRef.current) {
      try {
        await secureDBInstance.storeUsernameMapping(refs.loginUsernameRef.current, refs.originalUsernameRef.current);
        try {
          window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, { detail: { username: refs.loginUsernameRef.current } }));
        } catch { }
      } catch { }
    }
  };
};
