import { useEffect, useRef } from 'react';
import { EventType } from '../../lib/types/event-types';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { torNetworkManager } from '../../lib/transport/tor-network';
import { notifications, session } from '../../lib/tauri-bindings';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { STORAGE_KEYS } from '../../lib/database/storage-keys';

interface AppInitializationProps {
  Authentication: {
    isLoggedIn: boolean;
    accountAuthenticated: boolean;
    loginUsernameRef: React.RefObject<string | null>;
    hybridKeysRef: React.RefObject<any>;
    passphrasePlaintextRef: React.RefObject<string | null>;
  };
  Database: {
    secureDBRef: React.RefObject<any>;
    dbInitialized: boolean;
  };
  flushPendingSaves: () => Promise<void>;
  setShowSettings: (show: boolean) => void;
}

export function useAppInitialization({
  Authentication,
  Database,
  flushPendingSaves,
  setShowSettings,
}: AppInitializationProps) {

  // Initialize profile picture system
  useEffect(() => {
    if (Database.secureDBRef.current) {
      profilePictureSystem.setSecureDB(Database.secureDBRef.current);
      profilePictureSystem.initialize().catch(() => { });
    }
  }, [Database.secureDBRef.current]);

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
    const applyNotificationSettings = () => {
      try {
        const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.notifications) {
            notifications.setEnabled(parsed.notifications.desktop !== false).catch(() => { });
          }
        }
      } catch { }
    };
    applyNotificationSettings();
    return syncEncryptedStorage.subscribe(applyNotificationSettings);
  }, []);

  // Handle entering background
  const isEnteringBackgroundRef = useRef(false);
  
  const flushPendingSavesRef = useRef(flushPendingSaves);
  flushPendingSavesRef.current = flushPendingSaves;
  useEffect(() => {
    const handleEnteringBackground = async () => {
      isEnteringBackgroundRef.current = true;

      try {
        await flushPendingSavesRef.current();
      } catch (e) {
        console.error('[App] Failed to flush pending saves:', e);
      }

      const currentUsername = Authentication.loginUsernameRef.current;
      if (currentUsername) {
        try {
          await session.setBackgroundState(true);
        } catch (e) {
          console.error('[App] Failed to store background state:', e);
        }
      }

    };
    window.addEventListener(EventType.APP_ENTERING_BACKGROUND, handleEnteringBackground);

    return () => {
      window.removeEventListener(EventType.APP_ENTERING_BACKGROUND, handleEnteringBackground);
      if (!isEnteringBackgroundRef.current && torNetworkManager.isSupported()) {
        console.log('[TOR-DIAG] useAppInitialization unmount cleanup: shutting down Tor manager');
        torNetworkManager.shutdown();
      }
    };
  }, []);
}
