import { useEffect, useRef, useState } from 'react';
import { EventType } from '../../lib/types/event-types';
import { torNetworkManager } from '../../lib/transport/tor-network';
import { notifications, session } from '../../lib/tauri-bindings';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { readAppSettings } from '../../lib/ui/app-settings';
import { readNotificationPreferences, subscribeNotificationPreferences } from '../../lib/ui/notification-preferences';

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
  const [avatarDataLoaded, setAvatarDataLoaded] = useState(false);

  // Initialize profile picture system
  useEffect(() => {
    const db = Database.secureDBRef.current;
    if (!db || !Database.dbInitialized) {
      setAvatarDataLoaded(false);
      return;
    }
    let cancelled = false;
    setAvatarDataLoaded(false);
    profilePictureSystem.setSecureDB(db);
    void profilePictureSystem.initialize().then(() => {
      if (!cancelled && Database.secureDBRef.current === db) setAvatarDataLoaded(true);
    }).catch((error) => {
      console.error('[App] Failed to initialize profile pictures', error);
    });
    return () => { cancelled = true; };
  }, [Database.dbInitialized, Database.secureDBRef.current]);

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
      const settings = readAppSettings();
      const { doNotDisturb } = readNotificationPreferences();
      void notifications.setEnabled((settings.notifications?.desktop ?? true) && !(doNotDisturb.messages && doNotDisturb.calls)).catch((error) => {
        console.error('[App] Failed to apply notification setting', error);
      });
    };
    applyNotificationSettings();
    return subscribeNotificationPreferences(applyNotificationSettings);
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
      if (!isEnteringBackgroundRef.current) {
        torNetworkManager.shutdown();
      }
    };
  }, []);

  return { avatarDataLoaded };
}
