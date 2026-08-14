import { RefObject } from "react";
import { clearExplicitLogout } from "../../lib/auth/logout-marker";
import { computeBlindUserId } from "../../lib/utils/auth-utils";
import { type AuthLifecycle, isStaleAuthOperation } from "../../lib/auth/auth-lifecycle";

export interface AuthSuccessRefs {
  loginUsernameRef: RefObject<string>;
  originalUsernameRef: RefObject<string>;
}

export interface AuthSuccessSetters {
  setAuthStatus: (v: string) => void;
  setUsername: (v: string) => void;
  setPseudonym: (v: string) => void;
  setIsLoggedIn: (v: boolean) => void;
  setAccountAuthenticated: (v: boolean) => void;
  setIsSubmittingAuth: (v: boolean) => void;
  setLoginError: (v: string) => void;
}

export const createHandleAuthSuccess = (
  refs: AuthSuccessRefs,
  setters: AuthSuccessSetters,
  helpers: {
    storeAuthenticationState: (username: string, originalUsername?: string) => Promise<void>;
    lifecycle: AuthLifecycle;
  }
) => {
  return async (username: string) => {
    const operation = helpers.lifecycle.capture();
    if (operation.account && operation.account !== username) return;
    const displayName = refs.originalUsernameRef.current || username;
    const pseudonym = computeBlindUserId(username);

    try {
      await clearExplicitLogout();
      helpers.lifecycle.assertCurrent(operation);
    } catch (error) {
      if (isStaleAuthOperation(error)) return;
      throw error;
    }

    refs.loginUsernameRef.current = username;
    await helpers.storeAuthenticationState(username, displayName);
    if (!helpers.lifecycle.isCurrent(operation)) return;

    setters.setAuthStatus("Authenticated");
    setters.setUsername(displayName);
    setters.setPseudonym(pseudonym);
    setters.setIsLoggedIn(true);
    setters.setAccountAuthenticated(true);
    setters.setIsSubmittingAuth(false);

    try { await new Promise(resolve => setTimeout(resolve, 0)); } catch { }
    if (!helpers.lifecycle.isCurrent(operation)) return;

    setTimeout(() => {
      if (helpers.lifecycle.isCurrent(operation)) setters.setAuthStatus("");
    }, 1000);
    setters.setLoginError("");
  };
};
