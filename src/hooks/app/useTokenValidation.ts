import { useCallback, useEffect, useRef, useState } from 'react';
import websocketClient from '../../lib/websocket/websocket';
import {
  humanizeConnectionError,
  startupConnection,
  type StartupFailureTarget,
} from '../../lib/transport/startup-connection';
import type { AuthRecoveryResult } from '../auth/recovery';

export interface RecoveryConnectionIssue {
  readonly error: string;
  readonly target: Exclude<StartupFailureTarget, null>;
  readonly serverUrl: string;
}

interface TokenValidationProps {
  Authentication: {
    tokenValidationInProgress: boolean;
    isLoggedIn: boolean;
    accountAuthenticated: boolean;
    showPasswordPrompt: boolean;
    attemptAuthRecovery: () => Promise<boolean>;
    attemptAuthRecoveryDetailed: () => Promise<AuthRecoveryResult>;
    setTokenValidationInProgress: (value: boolean) => void;
    setAuthStatus: (status: string) => void;
    setLoginError: (error: string) => void;
    setShowPasswordPrompt: (value: boolean) => void;
  };
  setupComplete: boolean;
  selectedServerUrl: string;
}

export function useTokenValidation({
  Authentication,
  setupComplete,
  selectedServerUrl,
}: TokenValidationProps) {

  const validationGenerationRef = useRef(0);
  const [connectionIssue, setConnectionIssue] = useState<RecoveryConnectionIssue | null>(null);

  useEffect(() => {
    setConnectionIssue((current) => (
      current && current.serverUrl !== selectedServerUrl ? null : current
    ));
  }, [selectedServerUrl]);

  const retryRecovery = useCallback(() => {
    setConnectionIssue(null);
    Authentication.setLoginError('');
    Authentication.setAuthStatus('Reconnecting...');
    Authentication.setTokenValidationInProgress(true);
  }, [
    Authentication.setAuthStatus,
    Authentication.setLoginError,
    Authentication.setTokenValidationInProgress,
  ]);
  const clearConnectionIssue = useCallback(() => setConnectionIssue(null), []);

  useEffect(() => {
    const generation = ++validationGenerationRef.current;
    let inFlight = false;
    let cancelled = false;
    const isCurrent = () => !cancelled && validationGenerationRef.current === generation;

    if (
      !Authentication.tokenValidationInProgress
      || Authentication.isLoggedIn
      || Authentication.accountAuthenticated
      || Authentication.showPasswordPrompt
    ) {
      return () => { cancelled = true; };
    }
    if (!setupComplete || !selectedServerUrl) return () => { cancelled = true; };

    const tryRecover = async () => {
      if (!isCurrent() || inFlight) return;
      inFlight = true;
      try {
        try {
          await startupConnection.prepareRecoveryTransport();
        } catch (error) {
          if (!isCurrent()) return;
          const startupState = startupConnection.getState();
          setConnectionIssue({
            target: 'tor',
            error: startupState.step || humanizeConnectionError(error),
            serverUrl: selectedServerUrl,
          });
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
          return;
        }
        if (!isCurrent()) return;
        const result = await Authentication.attemptAuthRecoveryDetailed();
        if (!isCurrent()) return;
        if (result.outcome === 'recovered') {
          setConnectionIssue(null);
          return;
        }
        if (result.outcome === 'cancelled') return;
        if (result.outcome === 'transport-unavailable') {
          setConnectionIssue({
            target: 'server',
            error: humanizeConnectionError(result.error),
            serverUrl: selectedServerUrl,
          });
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
          return;
        }
        setConnectionIssue(null);
        if (result.outcome === 'server-entry-required') {
          if (
            websocketClient.isServerPasswordRequired()
            && !websocketClient.isServerAuthGranted()
          ) {
            websocketClient.setServerEntryPromptPending(true);
            Authentication.setLoginError('');
            Authentication.setShowPasswordPrompt(true);
          }
          return;
        }
        Authentication.setTokenValidationInProgress(false);
        Authentication.setAuthStatus('');
      } catch (error) {
        if (!isCurrent()) return;
        setConnectionIssue({
          target: 'server',
          error: humanizeConnectionError(error),
          serverUrl: selectedServerUrl,
        });
        Authentication.setTokenValidationInProgress(false);
        Authentication.setAuthStatus('');
      } finally {
        if (isCurrent()) inFlight = false;
      }
    };

    void tryRecover();

    return () => {
      cancelled = true;
    };
  }, [
    Authentication.tokenValidationInProgress,
    Authentication.isLoggedIn,
    Authentication.accountAuthenticated,
    Authentication.showPasswordPrompt,
    Authentication.attemptAuthRecoveryDetailed,
    Authentication.setAuthStatus,
    Authentication.setLoginError,
    Authentication.setShowPasswordPrompt,
    Authentication.setTokenValidationInProgress,
    setupComplete,
    selectedServerUrl,
  ]);

  return { connectionIssue, retryRecovery, clearConnectionIssue };
}
