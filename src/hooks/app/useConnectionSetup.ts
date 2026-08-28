import { useEffect, useRef } from 'react';
import { startupConnection } from '../../lib/transport/startup-connection';

interface ConnectionSetupProps {
  setupComplete: boolean;
  selectedServerUrl: string;
  Authentication: {
    isLoggedIn: boolean;
    isRegistrationMode: boolean;
    showPassphrasePrompt: boolean;
    showPasswordPrompt: boolean;
    isSubmittingAuth: boolean;
    accountAuthenticated: boolean;
    recoveryActive: boolean;
    tokenValidationInProgress: boolean;
  };
  Database: {
    secureDBRef: React.RefObject<any>;
    dbInitialized: boolean;
  };
}

export function useConnectionSetup({
  setupComplete,
  selectedServerUrl,
  Authentication,
  Database,
}: ConnectionSetupProps) {
  const connectionGenerationRef = useRef(0);

  useEffect(() => {
    const generation = ++connectionGenerationRef.current;
    let cancelled = false;
    const isCurrent = () => !cancelled && connectionGenerationRef.current === generation;
    if (!selectedServerUrl || !setupComplete) {
      return () => { cancelled = true; };
    }

    if (
      Authentication.isSubmittingAuth ||
      Authentication.recoveryActive ||
      Authentication.tokenValidationInProgress ||
      Authentication.showPasswordPrompt
    ) {
      return () => { cancelled = true; };
    }
    const initializeConnection = async () => {
      try {
        await startupConnection.checkConnected();
        if (!isCurrent()) return;
      } catch {
        if (!isCurrent()) return;
      }
    };

    void initializeConnection();
    return () => { cancelled = true; };
  }, [setupComplete, selectedServerUrl, Authentication.isSubmittingAuth, Authentication.recoveryActive, Authentication.tokenValidationInProgress, Authentication.showPasswordPrompt, Database.dbInitialized]);
}
