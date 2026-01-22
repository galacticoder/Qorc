import { useEffect, useRef } from 'react';
import websocketClient from '../../lib/websocket/websocket';

interface TokenValidationProps {
  Authentication: {
    tokenValidationInProgress: boolean;
    isLoggedIn: boolean;
    accountAuthenticated: boolean;
    attemptAuthRecovery: () => Promise<boolean>;
    setTokenValidationInProgress: (value: boolean) => void;
    setAuthStatus: (status: string) => void;
  };
  setupComplete: boolean;
  selectedServerUrl: string;
}

export function useTokenValidation({
  Authentication,
  setupComplete,
  selectedServerUrl,
}: TokenValidationProps) {

  const tokenRecoveryAttemptedRef = useRef(false);
  useEffect(() => {
    if (!Authentication.tokenValidationInProgress) {
      tokenRecoveryAttemptedRef.current = false;
      return;
    }
    if (Authentication.isLoggedIn || Authentication.accountAuthenticated) return;
    if (!setupComplete || !selectedServerUrl) return;
    if (tokenRecoveryAttemptedRef.current) return;

    tokenRecoveryAttemptedRef.current = true;
    (async () => {
      try {
        const recovered = await Authentication.attemptAuthRecovery();
        if (!recovered) {
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
        }
      } catch {
        Authentication.setTokenValidationInProgress(false);
        Authentication.setAuthStatus('');
      }
    })();
  }, [Authentication.tokenValidationInProgress, Authentication.isLoggedIn, Authentication.accountAuthenticated, setupComplete, selectedServerUrl]);

  const tokenValidationEnsureRef = useRef<{ attempts: number; retryTimer: NodeJS.Timeout | null }>({ attempts: 0, retryTimer: null });
  useEffect(() => {
    const state = tokenValidationEnsureRef.current;
    if (!Authentication.tokenValidationInProgress || Authentication.isLoggedIn || Authentication.accountAuthenticated) {
      state.attempts = 0;
      if (state.retryTimer) {
        clearTimeout(state.retryTimer);
        state.retryTimer = null;
      }
      return;
    }
    if (!setupComplete || !selectedServerUrl) return;

    const trySend = async (reason: string, resetFirst: boolean) => {
      try {
        await websocketClient.connect();
      } catch { }
      try {
        if (resetFirst && (websocketClient as any)?.resetSessionKeys) {
          (websocketClient as any).resetSessionKeys(false);
        }
      } catch { }
      try {
        await websocketClient.attemptTokenValidationOnce?.(`ensure-${reason}`, resetFirst);
      } catch { }
    };

    if (state.attempts === 0) {
      state.attempts = 1;
      void trySend('initial', false);
      state.retryTimer = setTimeout(() => {
        state.retryTimer = null;
        if (Authentication.tokenValidationInProgress && !Authentication.isLoggedIn && !Authentication.accountAuthenticated && state.attempts === 1) {
          state.attempts = 2;
          void trySend('retry', true);
        }
      }, 8000);
    }

    return () => {
      if (state.retryTimer) {
        clearTimeout(state.retryTimer);
        state.retryTimer = null;
      }
    };
  }, [Authentication.tokenValidationInProgress, Authentication.isLoggedIn, Authentication.accountAuthenticated, setupComplete, selectedServerUrl]);
}
