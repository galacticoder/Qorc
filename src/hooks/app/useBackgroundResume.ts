import { useEffect, useState } from 'react';
import { account, websocket, session } from '../../lib/tauri-bindings';
import { startupConnection } from '../../lib/transport/startup-connection';
import { isExplicitlyLoggedOut } from '../../lib/auth/logout-marker';
import {
  getCurrentLocalAccountScope,
  loadLastAuthenticatedAccount,
} from '../../lib/security/local-account-scope';
import { computeBlindUserId } from '../../lib/utils/auth-utils';
import {
  type AuthLifecycle,
  type AuthOperationSnapshot,
  isStaleAuthOperation,
} from '../../lib/auth/auth-lifecycle';

interface BackgroundResumeResult {
  isResumingFromBackground: boolean;
  backgroundCheckComplete: boolean;
  serverUrl: string;
  setupComplete: boolean;
}

interface AuthenticationContext {
  loginUsernameRef: React.RefObject<string | null>;
  keyManagerOwnerRef: React.RefObject<string>;
  originalUsernameRef: React.RefObject<string | null>;
  setUsername: (username: string) => void;
  setPseudonym: (pseudonym: string) => void;
  setShowPassphrasePrompt: (value: boolean) => void;
  setRecoveryActive: (value: boolean) => void;
  setTokenValidationInProgress: (value: boolean) => void;
  setAuthStatus: (status: string) => void;
  setVaultReady: (value: boolean) => void;
  attemptAuthRecovery: () => Promise<boolean>;
  authLifecycle: AuthLifecycle;
}

export function useBackgroundResume(
  Authentication: AuthenticationContext
): BackgroundResumeResult {
  const [isResumingFromBackground, setIsResumingFromBackground] = useState(false);
  const [backgroundCheckComplete, setBackgroundCheckComplete] = useState(false);
  const [serverUrl, setServerUrl] = useState('');
  const [setupComplete, setSetupComplete] = useState(false);

  useEffect(() => {
    let operation: AuthOperationSnapshot = Authentication.authLifecycle.capture();
    const awaitCurrent = async <T>(promise: Promise<T>): Promise<T> => {
      const result = await promise;
      Authentication.authLifecycle.assertCurrent(operation);
      return result;
    };
    const checkBackgroundState = async () => {
      try {
        const state = await awaitCurrent(session.getBackgroundState());
        const isBackgroundResume = !!(state && state.active);
        if (isBackgroundResume) setIsResumingFromBackground(true);
        const explicitLogout = await awaitCurrent(isExplicitlyLoggedOut());
        const configuredServerUrl = await awaitCurrent(websocket.getServerUrl());

        if (isBackgroundResume) {
          const torReady = await awaitCurrent(startupConnection.validateTor());

          if (configuredServerUrl) {
            setServerUrl(configuredServerUrl);
            setSetupComplete(torReady);
          }
        }

        const storedAccount = explicitLogout || !configuredServerUrl
          ? null
          : await awaitCurrent(loadLastAuthenticatedAccount());
        const storedUsername = explicitLogout
          ? ''
          : Authentication.loginUsernameRef.current || storedAccount?.username;

        if (storedUsername && !explicitLogout) {
          operation = Authentication.authLifecycle.begin(storedUsername);
          const storedDisplayName = storedAccount?.displayName;
          const accountScope = await awaitCurrent(getCurrentLocalAccountScope(storedUsername));
          const unlocked = await awaitCurrent(account.isUnlocked(accountScope));
          if (unlocked) {
            Authentication.keyManagerOwnerRef.current = accountScope;
            Authentication.loginUsernameRef.current = storedUsername;
            Authentication.originalUsernameRef.current = storedDisplayName || storedUsername;
            Authentication.setUsername(storedDisplayName || storedUsername);
            Authentication.setPseudonym(computeBlindUserId(storedUsername));
            Authentication.setShowPassphrasePrompt(false);
            Authentication.setRecoveryActive(false);
            Authentication.setVaultReady(true);
          } else {
            Authentication.keyManagerOwnerRef.current = accountScope;
            Authentication.setVaultReady(false);
            Authentication.setRecoveryActive(true);
            Authentication.setShowPassphrasePrompt(true);
          }
        }

        if (isBackgroundResume && !explicitLogout) {
          Authentication.setTokenValidationInProgress(true);
          await awaitCurrent(Authentication.attemptAuthRecovery());

          await awaitCurrent(session.setBackgroundState(false));
        } else if (explicitLogout) {
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
          await session.setBackgroundState(false);
        }
      } catch (e) {
        if (isStaleAuthOperation(e)) return;
        console.error('[Resume] Error checking background state:', e);
      } finally {
        setIsResumingFromBackground(false);
        setBackgroundCheckComplete(true);
      }
    };
    checkBackgroundState();
  }, []);

  return { isResumingFromBackground, backgroundCheckComplete, serverUrl, setupComplete };
}
