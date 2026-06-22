import { RefObject } from "react";
import websocketClient from "../../lib/websocket/websocket";
import { storage } from "../../lib/tauri-bindings";
import { PinnedServer, generateBlindCredential } from "../../lib/utils/auth-utils";
import { isExplicitlyLoggedOut } from "../../lib/auth/logout-marker";

interface BlindCredentialRefValue {
  message: string;
  inboxId?: string;
  routeId?: string;
  blindedMsg: string;
  blindingFactor: string;
  n: string;
  kid: string;
  modulusLength: number;
  hash: string;
  saltLength: number;
  scheme: string;
  used?: boolean;
}

export interface RecoveryRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
  blindCredentialRef?: RefObject<BlindCredentialRefValue | null>;
  serverHybridPublicRef?: RefObject<{ blindPublicKey?: any } | null>;
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
    if (await isExplicitlyLoggedOut()) {
      setters.setAuthStatus('');
      try { setters.setTokenValidationInProgress(false); } catch { }
      return false;
    }

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

      let blindedToken: string | undefined;
      try {
        const blindPublicKey =
          refs.serverHybridPublicRef?.current?.blindPublicKey ||
          PinnedServer.get()?.blindPublicKey;

        if (blindPublicKey && refs.blindCredentialRef) {
          const existing = refs.blindCredentialRef.current;
          if (!existing || existing.used) {
            const generated = await generateBlindCredential(storedUsername, blindPublicKey);
            if (generated) {
              refs.blindCredentialRef.current = { ...generated, used: false };
              blindedToken = generated.blindedMsg;
            }
          } else {
            blindedToken = existing.blindedMsg;
          }
        }
      } catch { }

      await websocketClient.attemptTokenValidationOnce(
        'recovery',
        false,
        blindedToken ? { blindedToken } : {}
      );

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
