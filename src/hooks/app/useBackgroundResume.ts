import { useEffect, useState } from 'react';
import websocketClient from '../../lib/websocket/websocket';
import { torNetworkManager } from '../../lib/transport/tor-network';

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
        const api = (window as any).edgeApi;
        const electronApi = (window as any).electronAPI;
        if (api?.getBackgroundSessionState) {
          const state = await api.getBackgroundSessionState();

          if (state && state.isBackgroundMode) {
            try {
              const pqKeysResult = await api.getPQSessionKeys?.();
              if (pqKeysResult?.success && pqKeysResult.keys) {
                const restored = websocketClient.importSessionKeys(pqKeysResult.keys);
                if (restored) {
                  await api.clearPQSessionKeys?.();
                }
              }
            } catch (pqErr) {
              console.error('[Resume] Failed to restore PQ session keys:', pqErr);
            }

            try {
              const torStatus = await electronApi?.getTorStatus?.();
              if (torStatus?.isRunning || torStatus?.bootstrapped) {
                torNetworkManager.updateConfig({
                  enabled: true,
                  socksPort: torStatus.socksPort || 9150,
                  controlPort: torStatus.controlPort || 9151,
                  host: '127.0.0.1'
                });
                await torNetworkManager.initialize();
              }
            } catch (torErr) {
              console.error('[Resume] Failed to re-sync Tor:', torErr);
            }

            const serverResult = await api.getServerUrl?.();
            if (serverResult?.serverUrl) {
              setServerUrl(serverResult.serverUrl);
              setSetupComplete(true);

              const storedUsername = state.username ||
                Authentication.loginUsernameRef.current ||
                (await import('../../lib/database/encrypted-storage')).syncEncryptedStorage.getItem('last_authenticated_username');

              let localAuthRestored = false;

              if (storedUsername) {
                try {
                  const { loadVaultKeyRaw, loadWrappedMasterKey, ensureVaultKeyCryptoKey } = await import('../../lib/cryptography/vault-key');
                  const { AES } = await import('../../lib/utils/crypto-utils');

                  let vaultKey: CryptoKey | null = null;
                  const rawVaultKey = await loadVaultKeyRaw(storedUsername);
                  if (rawVaultKey && rawVaultKey.length === 32) {
                    vaultKey = await AES.importAesKey(rawVaultKey);
                  } else {
                    vaultKey = await ensureVaultKeyCryptoKey(storedUsername);
                  }

                  if (vaultKey) {
                    const masterKeyBytes = await loadWrappedMasterKey(storedUsername, vaultKey);

                    if (masterKeyBytes && masterKeyBytes.length === 32) {
                      const masterKey = await AES.importAesKey(masterKeyBytes);

                      Authentication.aesKeyRef.current = masterKey;
                      Authentication.loginUsernameRef.current = storedUsername;

                      if (!Authentication.keyManagerRef.current) {
                        const { SecureKeyManager } = await import('../../lib/database/secure-key-manager');
                        Authentication.keyManagerRef.current = new SecureKeyManager(storedUsername);
                      }
                      try {
                        await Authentication.keyManagerRef.current.initializeWithMasterKey(masterKeyBytes);
                      } catch { }

                      try { masterKeyBytes.fill(0); } catch { }

                      Authentication.setUsername(storedUsername);
                      Authentication.setIsLoggedIn(true);
                      Authentication.setAccountAuthenticated(true);
                      Authentication.setShowPassphrasePrompt(false);
                      Authentication.setRecoveryActive(false);
                      Authentication.setMaxStepReached('server');
                      Authentication.setTokenValidationInProgress(false);
                      Authentication.setAuthStatus('');

                      localAuthRestored = true;
                    }
                  }
                } catch (vaultErr) {
                  console.error('[Resume] Vault key restoration failed:', vaultErr);
                }
              }

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
              setTimeout(async () => {
                try {
                  await api.requestPendingMessages?.();
                } catch (e) {
                  console.error('[Resume] Failed to request pending messages:', e);
                }
              }, 2000);

              await api.clearBackgroundSessionState?.();
            }
          }
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
