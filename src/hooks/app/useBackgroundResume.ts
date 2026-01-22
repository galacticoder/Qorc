import { useEffect, useState } from 'react';
import websocketClient from '../../lib/websocket/websocket';
import { torNetworkManager } from '../../lib/transport/tor-network';
import { websocket, session, tor, storage } from '../../lib/tauri-bindings';
import { loadVaultKeyRaw, loadWrappedMasterKey, ensureVaultKeyCryptoKey } from '../../lib/cryptography/vault-key';
import { CryptoUtils } from '../../lib/utils/crypto-utils';
import { SecureKeyManager } from '../../lib/database/secure-key-manager';

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
        const state = await session.getBackgroundState();

        if (state && state.active) {
          try {
            const pqKeysResult = await session.getPQKeys('current');
            if (pqKeysResult) {
              const keys = {
                sessionId: pqKeysResult.session_id,
                sendKey: pqKeysResult.aes_key,
                recvKey: pqKeysResult.mac_key,
                fingerprint: '',
                establishedAt: pqKeysResult.created_at
              };
              const restored = websocketClient.importSessionKeys(keys);
              if (restored) {
                await session.deletePQKeys(pqKeysResult.session_id);
              }
            }
          } catch (pqErr) {
            console.error('[Resume] Failed to restore PQ session keys:', pqErr);
          }

          try {
            const torStatus = await tor.status();
            if (torStatus?.is_running || torStatus?.bootstrapped) {
              torNetworkManager.updateConfig({
                enabled: true,
                socksPort: torStatus.socks_port || 9150,
                controlPort: torStatus.control_port || 9151,
                host: '127.0.0.1'
              });
              await torNetworkManager.initialize();
            }
          } catch (torErr) {
            console.error('[Resume] Failed to re-sync Tor:', torErr);
          }

          const serverUrlResult = await websocket.getServerUrl();
          if (serverUrlResult) {
            setServerUrl(serverUrlResult);
            setSetupComplete(true);

            const storedUsername = Authentication.loginUsernameRef.current ||
              (await storage.get('last_authenticated_username'));

            let localAuthRestored = false;

            if (storedUsername) {
              try {
                const storedDisplayName = await storage.get('last_authenticated_display_name');
                const vaultKey = await (async () => {
                  const rawVaultKey = await loadVaultKeyRaw(storedUsername);
                  if (rawVaultKey && rawVaultKey.length === 32) {
                    return await CryptoUtils.AES.importAesKey(rawVaultKey);
                  } else {
                    return await ensureVaultKeyCryptoKey(storedUsername);
                  }
                })();

                if (vaultKey) {
                  const masterKeyBytes = await loadWrappedMasterKey(storedUsername, vaultKey);

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

                    try { masterKeyBytes.fill(0); } catch { }

                    Authentication.setUsername(storedDisplayName || storedUsername);
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

            await session.setBackgroundState(false);
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
