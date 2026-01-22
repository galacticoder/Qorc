import { useEffect, useRef } from 'react';
import { SecurityAuditLogger } from '../../lib/cryptography/audit-logger';
import { SignalType } from '../../lib/types/signal-types';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { retrieveAuthTokens } from '../../lib/signals/signals';
import websocketClient from '../../lib/websocket/websocket';
import { storage } from '../../lib/tauri-bindings';

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
    attemptAuthRecovery: () => Promise<boolean>;
    setTokenValidationInProgress: (value: boolean) => void;
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
  const attemptedRecoveryRef = useRef(false);

  useEffect(() => {
    if (!selectedServerUrl || !setupComplete) return;

    const initializeConnection = async () => {
      try {
        await websocketClient.connect();

        const hasEncryptedAuth = Database.secureDBRef.current !== null;
        let storedUsername: string | null = null;
        let hasStoredTokens = false;
        try {
          storedUsername = await storage.get('last_authenticated_username');
        } catch { }
        try {
          const tokens = await retrieveAuthTokens();
          hasStoredTokens = !!(tokens?.accessToken && tokens?.refreshToken);
        } catch { }

        const canRecover = (
          (hasEncryptedAuth || !!storedUsername || hasStoredTokens) &&
          !Authentication.isLoggedIn &&
          !Authentication.isRegistrationMode &&
          !Authentication.showPassphrasePrompt &&
          !Authentication.showPasswordPrompt &&
          !Authentication.isSubmittingAuth &&
          !Authentication.accountAuthenticated &&
          !Authentication.recoveryActive
        );

        if (canRecover && !attemptedRecoveryRef.current) {
          attemptedRecoveryRef.current = true;
          try {
            const recovered = await Authentication.attemptAuthRecovery();
            if (!recovered) {
              Authentication.setTokenValidationInProgress(false);
            }
          } catch (_e) {
            SecurityAuditLogger.log('warn', 'auth-recovery-failed', { error: (_e as any)?.message || 'unknown' });
            Authentication.setTokenValidationInProgress(false);
          }
        } else if (!canRecover && Authentication.tokenValidationInProgress && !Authentication.isLoggedIn) {
          if (!storedUsername && !hasStoredTokens && !hasEncryptedAuth) {
            Authentication.setTokenValidationInProgress(false);
          }
        }
      } catch (_error) {
        SecurityAuditLogger.log(SignalType.ERROR, 'connection-init-failed', { error: _error instanceof Error ? _error.message : 'unknown' });
      }
    };

    void initializeConnection();
  }, [setupComplete, selectedServerUrl, Authentication.isLoggedIn, Authentication.isRegistrationMode, Authentication.showPassphrasePrompt, Authentication.showPasswordPrompt, Authentication.isSubmittingAuth, Authentication.accountAuthenticated, Authentication.recoveryActive, Authentication.tokenValidationInProgress, Database.dbInitialized]);
}
