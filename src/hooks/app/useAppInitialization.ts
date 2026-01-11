import { useEffect, useRef } from 'react';
import { EventType } from '../../lib/types/event-types';
import { SignalType } from '../../lib/types/signal-types';
import { SecurityAuditLogger } from '../../lib/cryptography/audit-logger';
import { secureMessageQueue } from '../../lib/database/secure-message-queue';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { offlineMessageQueue } from '../../lib/websocket/offline-message-handler';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import websocketClient from '../../lib/websocket/websocket';
import { torNetworkManager } from '../../lib/transport/tor-network';

interface AppInitializationProps {
  Authentication: {
    isLoggedIn: boolean;
    accountAuthenticated: boolean;
    loginUsernameRef: React.RefObject<string | null>;
    originalUsernameRef: React.RefObject<string | null>;
    hybridKeysRef: React.RefObject<any>;
    passphrasePlaintextRef: React.RefObject<string | null>;
    aesKeyRef: React.RefObject<CryptoKey | null>;
    storeUsernameMapping: (db: any) => Promise<void>;
  };
  Database: {
    secureDBRef: React.RefObject<any>;
    dbInitialized: boolean;
  };
  fileHandler: {
    handleFileMessageChunk: (payload: any, context: { from: string; to: string }) => void;
  };
  encryptedHandlerRef: React.RefObject<(msg: any) => Promise<void>>;
  flushPendingSaves: () => Promise<void>;
  setShowSettings: (show: boolean) => void;
}

export function useAppInitialization({
  Authentication,
  Database,
  fileHandler,
  encryptedHandlerRef,
  flushPendingSaves,
  setShowSettings,
}: AppInitializationProps) {
  // Set offline message callback once
  const offlineCallbackSetRef = useRef(false);
  useEffect(() => {
    if (offlineCallbackSetRef.current) return;
    offlineCallbackSetRef.current = true;

    try {
      offlineMessageQueue.setIncomingOfflineEncryptedMessageCallback(async (msg: any) => {
        await encryptedHandlerRef.current(msg);
      });
    } catch { }
  }, []);

  // Apply decryption key for offline messages
  useEffect(() => {
    const applyKey = () => {
      const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey;
      if (kyberSecret && kyberSecret instanceof Uint8Array) {
        try {
          offlineMessageQueue.setDecryptionKey(kyberSecret);
        } catch { }
      } else {
        try {
          offlineMessageQueue.clearDecryptionKey();
        } catch { }
      }
    };

    applyKey();

    const onKeysUpdated = () => applyKey();
    try {
      window.addEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
    } catch { }
    return () => {
      try {
        window.removeEventListener(EventType.HYBRID_KEYS_UPDATED, onKeysUpdated as EventListener);
      } catch { }
    };
  }, [Authentication.hybridKeysRef.current]);

  // Store username mapping for current user
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.originalUsernameRef.current) {
      const storeCurrentUserMapping = async () => {
        try {
          await Authentication.storeUsernameMapping(Database.secureDBRef.current!);
        } catch {
          SecurityAuditLogger.log(SignalType.ERROR, 'user-mapping-store-failed', { error: 'unknown' });
        }
      };
      storeCurrentUserMapping();
    }
  }, [Database.secureDBRef.current, Authentication.originalUsernameRef.current]);

  // Restore original username from SecureDB
  useEffect(() => {
    const restoreOriginalUsername = async () => {
      const db = Database.secureDBRef.current;
      const hashedUsername = Authentication.loginUsernameRef.current;
      const currentOriginal = Authentication.originalUsernameRef.current;

      if (!db || !hashedUsername || !Authentication.isLoggedIn) return;
      if (currentOriginal && currentOriginal !== hashedUsername) return;

      try {
        const original = await db.getOriginalUsername(hashedUsername);
        if (original && original !== hashedUsername) {
          Authentication.originalUsernameRef.current = original;
          window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, {
            detail: { username: hashedUsername, original }
          }));
        }
      } catch {
        SecurityAuditLogger.log('warn', 'original-username-restore-failed', {});
      }
    };

    restoreOriginalUsername();
  }, [Database.secureDBRef.current, Authentication.isLoggedIn, Authentication.loginUsernameRef.current]);

  // Initialize message queue
  useEffect(() => {
    if (Database.secureDBRef.current && Authentication.loginUsernameRef.current) {
      const initMessageQueue = async () => {
        try {
          await secureMessageQueue.initialize(
            Authentication.loginUsernameRef.current!,
            Database.secureDBRef.current!
          );
        } catch {
          SecurityAuditLogger.log(SignalType.ERROR, 'message-queue-init-failed', { error: 'unknown' });
        }
      };
      initMessageQueue();
    }
  }, [Database.secureDBRef.current, Authentication.loginUsernameRef.current]);

  // Initialize profile picture system
  useEffect(() => {
    if (Database.secureDBRef.current) {
      Promise.all([
        import('../../lib/avatar/profile-picture-system'),
        import('../../lib/websocket/websocket')
      ]).then(([{ profilePictureSystem }, { default: _websocketClient }]) => {
        profilePictureSystem.setSecureDB(Database.secureDBRef.current);
        profilePictureSystem.initialize().catch(() => { });
      }).catch(() => { });
    }
  }, [Database.secureDBRef.current]);

  // Set keys for profile picture system
  useEffect(() => {
    if (Authentication.hybridKeysRef.current?.kyber?.publicKeyBase64 && Authentication.hybridKeysRef.current?.kyber?.secretKey) {
      import('../../lib/avatar/profile-picture-system').then(({ profilePictureSystem }) => {
        profilePictureSystem.setKeys(
          Authentication.hybridKeysRef.current!.kyber!.publicKeyBase64,
          Authentication.hybridKeysRef.current!.kyber!.secretKey
        );
      });
    }
  }, [Authentication.hybridKeysRef.current]);

  // Bridge P2P file chunks into file handler
  useEffect(() => {
    const onP2PChunk = (e: Event) => {
      try {
        const d: any = (e as CustomEvent).detail || {};
        if (d && d.payload) {
          fileHandler.handleFileMessageChunk(d.payload, { from: d.from, to: d.to });
        }
      } catch { }
    };
    window.addEventListener(EventType.P2P_FILE_CHUNK, onP2PChunk as EventListener);
    return () => window.removeEventListener(EventType.P2P_FILE_CHUNK, onP2PChunk as EventListener);
  }, [fileHandler]);

  // Restore encrypted block list
  useEffect(() => {
    const tryRestoreBlockList = async () => {
      const passphrase = Authentication.passphrasePlaintextRef?.current || '';
      const kyberSecret = Authentication.hybridKeysRef?.current?.kyber?.secretKey || null;
      const key = passphrase ? passphrase : (kyberSecret ? { kyberSecret } : null);
      if (!Authentication.isLoggedIn || !Authentication.accountAuthenticated || !key || !Database.dbInitialized) return;
      try {
        await blockingSystem.downloadFromServer(key as any);
      } catch { }
    };
    tryRestoreBlockList();
  }, [Authentication.isLoggedIn, Authentication.accountAuthenticated, Authentication.passphrasePlaintextRef?.current, Authentication.aesKeyRef?.current]);

  // Handle settings open/close events
  useEffect(() => {
    const handleOpenSettings = () => setShowSettings(true);
    const handleCloseSettings = () => setShowSettings(false);
    window.addEventListener(EventType.OPEN_SETTINGS, handleOpenSettings);
    window.addEventListener(EventType.CLOSE_SETTINGS, handleCloseSettings);
    return () => {
      window.removeEventListener(EventType.OPEN_SETTINGS, handleOpenSettings);
      window.removeEventListener(EventType.CLOSE_SETTINGS, handleCloseSettings);
    };
  }, [setShowSettings]);

  // Load notification settings
  useEffect(() => {
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.notifications) {
          (window as any).edgeApi?.setNotificationsEnabled?.(parsed.notifications.desktop !== false).catch(() => { });
        }
      }
    } catch { }
  }, []);

  // Handle entering background
  const isEnteringBackgroundRef = useRef(false);
  useEffect(() => {
    const handleEnteringBackground = async () => {
      isEnteringBackgroundRef.current = true;

      try {
        await flushPendingSaves();
      } catch (e) {
        console.error('[App] Failed to flush pending saves:', e);
      }

      const currentUsername = Authentication.loginUsernameRef.current ||
        syncEncryptedStorage.getItem('last_authenticated_username');
      if (currentUsername) {
        try {
          await (window as any).edgeApi?.setBackgroundUsername?.(currentUsername);
        } catch (e) {
          console.error('[App] Failed to store background username:', e);
        }
      }

      try {
        const sessionKeys = websocketClient.exportSessionKeys();
        if (sessionKeys) {
          await (window as any).edgeApi?.storePQSessionKeys?.(sessionKeys);
        }
      } catch (e) {
        console.error('[App] Failed to store PQ session keys:', e);
      }
    };
    window.addEventListener(EventType.APP_ENTERING_BACKGROUND, handleEnteringBackground);

    return () => {
      window.removeEventListener(EventType.APP_ENTERING_BACKGROUND, handleEnteringBackground);
      if (!isEnteringBackgroundRef.current && torNetworkManager.isSupported()) {
        torNetworkManager.shutdown();
      }
    };
  }, [flushPendingSaves]);
}
