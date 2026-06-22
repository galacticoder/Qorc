import { useEffect, useState } from 'react';
import websocketClient from '../../lib/websocket/websocket';
import { torNetworkManager } from '../../lib/transport/tor-network';
import { websocket, session, tor, storage, signal, database } from '../../lib/tauri-bindings';
import { loadVaultKeyRaw, loadWrappedMasterKey, ensureVaultKeyCryptoKey } from '../../lib/cryptography/vault-key';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import { SecureKeyManager } from '../../lib/database/secure-key-manager';
import { isExplicitlyLoggedOut } from '../../lib/auth/logout-marker';

interface BackgroundResumeResult {
  isResumingFromBackground: boolean;
  serverUrl: string;
  setupComplete: boolean;
}

interface AuthenticationContext {
  loginUsernameRef: React.RefObject<string | null>;
  aesKeyRef: React.RefObject<CryptoKey | null>;
  keyManagerRef: React.RefObject<any>;
  originalUsernameRef: React.RefObject<string | null>;
  setUsername: (username: string) => void;
  setIsLoggedIn: (value: boolean) => void;
  setAccountAuthenticated: (value: boolean) => void;
  setShowPassphrasePrompt: (value: boolean) => void;
  setRecoveryActive: (value: boolean) => void;
  setMaxStepReached: (step: any) => void;
  setTokenValidationInProgress: (value: boolean) => void;
  setAuthStatus: (status: string) => void;
  attemptAuthRecovery: () => Promise<boolean>;
  getKeysOnDemand?: () => Promise<any>;
}

export function useBackgroundResume(
  Authentication: AuthenticationContext
): BackgroundResumeResult {
  const [isResumingFromBackground, setIsResumingFromBackground] = useState(true);
  const [serverUrl, setServerUrl] = useState('');
  const [setupComplete, setSetupComplete] = useState(false);

  useEffect(() => {
    const checkBackgroundState = async () => {
      try {
        const state = await session.getBackgroundState();
        const isBackgroundResume = !!(state && state.active);
        const explicitLogout = await isExplicitlyLoggedOut();

        if (isBackgroundResume) {
          let torReady = false;
          try {
            const torStatus = await tor.status();
            if (torStatus?.is_running || torStatus?.bootstrapped) {
              torNetworkManager.updateConfig({
                enabled: true,
                socksPort: torStatus.socks_port || 9150,
                controlPort: torStatus.control_port || 9151,
                host: '127.0.0.1'
              });
              torReady = await torNetworkManager.syncWithDaemon() || await torNetworkManager.initialize();
            }
          } catch (torErr) {
            console.error('[Resume] Failed to re-sync Tor:', torErr);
          }

          const serverUrlResult = await websocket.getServerUrl();
          if (serverUrlResult) {
            setServerUrl(serverUrlResult);
            setSetupComplete(torReady);
          }
        }

        const storedUsername = explicitLogout
          ? ''
          : Authentication.loginUsernameRef.current || (await storage.get('last_authenticated_username'));

        let localAuthRestored = false;
        console.log('[AUTOLOGIN] local-restore start', {
          isBackgroundResume, hasStoredUsername: !!storedUsername
        });

        if (storedUsername && !explicitLogout) {
          try {
            const storedDisplayName = await storage.get('last_authenticated_display_name');
            const rawVaultKey = await loadVaultKeyRaw(storedUsername);
            const vaultKey = (rawVaultKey && rawVaultKey.length === 32)
              ? await CryptoUtils.AES.importAesKey(rawVaultKey)
              : await ensureVaultKeyCryptoKey(storedUsername);
            console.log('[AUTOLOGIN] local-restore vaultKey', {
              rawVaultKeyLen: rawVaultKey?.length ?? null, gotVaultKey: !!vaultKey
            });

            if (vaultKey) {
              const masterKeyBytes = await loadWrappedMasterKey(storedUsername, vaultKey);
              console.log('[AUTOLOGIN] local-restore wrappedMasterKey', {
                masterKeyLen: masterKeyBytes?.length ?? null
              });

              if (masterKeyBytes && masterKeyBytes.length === 32) {
                const masterKey = await CryptoUtils.AES.importAesKey(masterKeyBytes);

                Authentication.aesKeyRef.current = masterKey;
                Authentication.loginUsernameRef.current = storedUsername;

                if (Authentication.originalUsernameRef) {
                  Authentication.originalUsernameRef.current = storedDisplayName || storedUsername;
                }

                if (!Authentication.keyManagerRef.current) {
                  Authentication.keyManagerRef.current = new SecureKeyManager(storedUsername);
                }
                try {
                  await Authentication.keyManagerRef.current.initializeWithMasterKey(masterKeyBytes);
                } catch { }

                // Initialize Rust DatabaseManager
                try {
                  const masterKeyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(masterKeyBytes);
                  await database.init(storedUsername, masterKeyB64);
                } catch (dbErr) {
                  console.error('[Resume] Rust DB init before signal restore failed:', dbErr);
                }

                try { masterKeyBytes.fill(0); } catch { }

                // restore persisted libsignal session state into Rust signal stores
                try {
                  const keys = await Authentication.getKeysOnDemand?.();
                  const kyberSecret: Uint8Array | undefined = keys?.kyber?.secretKey;
                  if (kyberSecret instanceof Uint8Array && kyberSecret.length > 0) {
                    const label = new TextEncoder().encode('signal-storage-key-v1');
                    const derived = await (CryptoUtils as any).Hash.generateBlake3Mac(label, kyberSecret);
                    const keyB64 = (CryptoUtils as any).Base64.arrayBufferToBase64(derived);
                    await signal.setStorageKey(keyB64);
                    if ((derived as any)?.fill) (derived as any).fill(0);
                  }
                  await signal.initStorage(storedUsername);
                } catch (sigErr) {
                  console.error('[Resume] Signal storage restore failed:', sigErr);
                }

                Authentication.setUsername(storedDisplayName || storedUsername);
                Authentication.setIsLoggedIn(true);
                Authentication.setAccountAuthenticated(true);
                Authentication.setShowPassphrasePrompt(false);
                Authentication.setRecoveryActive(false);
                Authentication.setMaxStepReached('server');
                Authentication.setTokenValidationInProgress(false);
                Authentication.setAuthStatus('');

                localAuthRestored = true;
                console.log('[AUTOLOGIN] local-restore SUCCESS (logged in from device-bound vault)');
              }
            }
          } catch (vaultErr) {
            console.error('[Resume] Vault key restoration failed:', vaultErr);
          }
        }
        console.log('[AUTOLOGIN] local-restore done', { localAuthRestored });

        if (isBackgroundResume && !explicitLogout) {
          if (!localAuthRestored) {
            try {
              Authentication.setTokenValidationInProgress(true);
              await websocketClient.attemptTokenValidationOnce?.('background-resume');
            } catch (tvErr) {
              console.error('[Resume] Token validation on resume failed:', tvErr);
            }

            try {
              await Authentication.attemptAuthRecovery();
            } catch (authErr) {
              console.error('[Resume] Auth recovery failed:', authErr);
            }
          }

          await session.setBackgroundState(false);
        } else if (explicitLogout) {
          Authentication.setTokenValidationInProgress(false);
          Authentication.setAuthStatus('');
          await session.setBackgroundState(false).catch(() => { });
        }
      } catch (e) {
        console.error('[Resume] Error checking background state:', e);
      } finally {
        setIsResumingFromBackground(false);
      }
    };
    checkBackgroundState();
  }, []);

  return { isResumingFromBackground, serverUrl, setupComplete };
}
