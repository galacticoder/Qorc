import { RefObject } from "react";
import websocketClient, {
  type ResumeAuthorizationResponse,
  UnlinkedAuthorizationError,
} from "../../lib/websocket/websocket";
import { isExplicitlyLoggedOut } from "../../lib/auth/logout-marker";
import {
  clearLastAuthenticatedAccount,
  loadLastAuthenticatedAccount,
  storeLastAuthenticatedAccount,
} from "../../lib/security/local-account-scope";
import {
  type AuthLifecycle,
  isStaleAuthOperation,
  wipeStaleAuthResult,
} from "../../lib/auth/auth-lifecycle";
import { hasResumeToken } from "../../lib/signals/resume-tokens";
import { computeBlindUserId } from "../../lib/utils/auth-utils";
import { getBlindRoutingClient } from "../../lib/transport/blind-routing-client";

export interface RecoveryRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
  recoveryInFlightRef: RefObject<Promise<boolean> | null>;
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
  isLoggedIn: boolean,
  lifecycle: AuthLifecycle,
  completeAuthorization: (response: ResumeAuthorizationResponse) => Promise<void>
) => {
  return async (): Promise<boolean> => {
    if (refs.recoveryInFlightRef.current) return refs.recoveryInFlightRef.current;
    const operation = lifecycle.capture();
    const awaitCurrent = async <T>(promise: Promise<T>): Promise<T> => {
      const result = await promise;
      try {
        lifecycle.assertCurrent(operation);
      } catch (error) {
        wipeStaleAuthResult(result);
        throw error;
      }
      return result;
    };

    const recovery = (async (): Promise<boolean> => {
      if (await awaitCurrent(isExplicitlyLoggedOut())) {
        setters.setAuthStatus('');
        try { setters.setTokenValidationInProgress(false); } catch { }
        return false;
      }

      let storedUsername = refs.loginUsernameRef.current;
      let storedDisplayName = refs.originalUsernameRef.current;

      if (!storedUsername || !storedDisplayName) {
        try {
          const recovered = await awaitCurrent(loadLastAuthenticatedAccount());
          const recoveringUsername = recovered.username;
          const recoveringDisplayName = recovered.displayName;

          if (!storedUsername) storedUsername = recoveringUsername;
          if (!storedDisplayName) storedDisplayName = recoveringDisplayName || storedUsername;
        } catch (error) {
          if (isStaleAuthOperation(error)) return false;
        }
      }

      if (!storedUsername || (operation.account && operation.account !== storedUsername)) {
        return false;
      }

      if (!await awaitCurrent(hasResumeToken(storedUsername))) {
        if (!accountAuthenticated || !isLoggedIn) {
          setters.setAuthStatus('');
          try { setters.setTokenValidationInProgress(false); } catch { }
        }
        return false;
      }

      const alreadyAuthenticated = accountAuthenticated && isLoggedIn;
      if (!alreadyAuthenticated) {
        try { setters.setTokenValidationInProgress(true); } catch { }
        setters.setAuthStatus("Recovering...");
      }

      try {
        lifecycle.assertCurrent(operation);
        const pseudonymHash = computeBlindUserId(storedUsername);
        refs.loginUsernameRef.current = storedUsername;
        websocketClient.setUsername(storedUsername);

        if (storedDisplayName) {
          refs.originalUsernameRef.current = storedDisplayName;
          setters.setUsername(storedDisplayName);
          setters.setPseudonym(pseudonymHash);
        } else {
          setters.setUsername(storedUsername);
          setters.setPseudonym(pseudonymHash);
        }

        try {
          lifecycle.assertCurrent(operation);
          getBlindRoutingClient(storedUsername);
        } catch (error) {
          if (isStaleAuthOperation(error)) return false;
        }

        const response = await awaitCurrent(websocketClient.switchToUnlinkedMode(operation.signal));
        const ready = websocketClient.isUnlinkedSessionReady();
        if (ready && !alreadyAuthenticated) {
          await awaitCurrent(completeAuthorization(response));
        }
        return ready;
      } catch (error) {
        if (isStaleAuthOperation(error) || !lifecycle.isCurrent(operation)) return false;
        if (error instanceof UnlinkedAuthorizationError) {
          try {
            await awaitCurrent(completeAuthorization(error.response));
          } catch (completionError) {
            if (isStaleAuthOperation(completionError) || !lifecycle.isCurrent(operation)) return false;
          }
        }
        if (!alreadyAuthenticated) {
          setters.setAuthStatus('');
          try { setters.setTokenValidationInProgress(false); } catch { }
        }
        return false;
      }
    })().catch((error): boolean => {
      if (!isStaleAuthOperation(error) && lifecycle.isCurrent(operation)) {
        setters.setAuthStatus('');
        try { setters.setTokenValidationInProgress(false); } catch { }
      }
      return false;
    });

    refs.recoveryInFlightRef.current = recovery;
    try {
      return await recovery;
    } finally {
      if (refs.recoveryInFlightRef.current === recovery) {
        refs.recoveryInFlightRef.current = null;
      }
    }
  };
};

export const createStoreAuthenticationState = () => {
  return async (username: string, originalUsername?: string) => {
    await storeLastAuthenticatedAccount(username, originalUsername);
  };
};

export const createClearAuthenticationState = () => {
  return async () => {
    await clearLastAuthenticatedAccount();
  };
};
