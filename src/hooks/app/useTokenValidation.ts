import { useEffect, useRef } from 'react';

interface TokenValidationProps {
  Authentication: {
    tokenValidationInProgress: boolean;
    isLoggedIn: boolean;
    accountAuthenticated: boolean;
    showPasswordPrompt: boolean;
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

  const validationGenerationRef = useRef(0);
  useEffect(() => {
    const generation = ++validationGenerationRef.current;
    let attempts = 0;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
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
      attempts += 1;
      const attempt = attempts;
      try {
        const recovered = await Authentication.attemptAuthRecovery();
        if (!isCurrent()) return;
        if (recovered) return;
        if (attempt >= 2) {
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
        } else {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            void tryRecover();
          }, 15000);
        }
      } catch {
        if (!isCurrent()) return;
        if (attempt >= 2) {
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
        } else {
          retryTimer = setTimeout(() => {
            retryTimer = null;
            void tryRecover();
          }, 15000);
        }
      } finally {
        if (isCurrent()) inFlight = false;
      }
    };

    void tryRecover();

    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [
    Authentication.tokenValidationInProgress,
    Authentication.isLoggedIn,
    Authentication.accountAuthenticated,
    Authentication.showPasswordPrompt,
    setupComplete,
    selectedServerUrl,
  ]);
}
