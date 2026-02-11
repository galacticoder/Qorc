import { RefObject } from "react";
import websocketClient from "../../lib/websocket/websocket";
import { storage } from "../../lib/tauri-bindings";

export interface RecoveryRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
}

export interface RecoverySetters {
  setUsername: (v: string) => void;
  setPseudonym: (v: string) => void;
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
    // Attempt to recover username from global storage
    let storedUsername = refs.loginUsernameRef.current;
    let storedDisplayName = refs.originalUsernameRef.current;

    if (!storedUsername || !storedDisplayName) {
      try {
        const recoveringUsername = await storage.get('last_authenticated_username');
        const recoveringDisplayName = await storage.get('last_authenticated_display_name');

        if (!storedUsername) storedUsername = recoveringUsername;
        if (!storedDisplayName) storedDisplayName = recoveringDisplayName || storedUsername;
      } catch (err) { }
    }

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

      const { computeBlindUserId } = await import('../../lib/utils/auth-utils');
      const pseudonymHash = computeBlindUserId(storedUsername);
      refs.loginUsernameRef.current = storedUsername;

      if (storedDisplayName) {
        refs.originalUsernameRef.current = storedDisplayName;
        setters.setUsername(storedDisplayName);
        setters.setPseudonym(pseudonymHash);
      } else {
        setters.setUsername(storedUsername);
        setters.setPseudonym(pseudonymHash);
      }

      await websocketClient.attemptTokenValidationOnce('recovery');

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
  return async (username: string, originalUsername?: string) => {
    try {
      await storage.init();
      await storage.set('last_authenticated_username', username);
      if (originalUsername) {
        await storage.set('last_authenticated_display_name', originalUsername);
      }
    } catch (err) {
      console.error('[Recovery] Failed to store authentication state:', err);
    }
  };
};

export const createClearAuthenticationState = () => {
  return async () => {
    try {
      await storage.init();
      await Promise.allSettled([
        storage.remove('last_authenticated_username'),
        storage.remove('last_authenticated_display_name'),
        storage.remove('tok:1'),
        storage.remove('bg_session_active'),
        storage.remove('bg_session_last_activity'),
        storage.remove('bg_session_pending')
      ]);
    } catch (err) {
      console.error('[Recovery] Failed to clear authentication state:', err);
    }
  };
};
