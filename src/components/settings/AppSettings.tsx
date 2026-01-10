import React, { useState, useEffect } from 'react';
import { useTheme } from 'next-themes';
import { syncEncryptedStorage } from '../../lib/database/encrypted-storage';
import { BlockedUsersSettings } from './BlockedUsersSettings';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { screenSharingSettings } from '../../lib/screen-sharing-settings';
import { toast } from 'sonner';
import { User, Palette, Bell, Volume2, Monitor, Download, Shield, Trash2 } from 'lucide-react';

import { AppSettingsStyles } from './sections/AppSettingsStyles';
import { AccountSettings } from './sections/AccountSettings';
import { AppearanceSettings } from './sections/AppearanceSettings';
import { NotificationSettings } from './sections/NotificationSettings';
import { AudioSettings } from './sections/AudioSettings';
import { VoiceVideoSettings } from './sections/VoiceVideoSettings';
import { DownloadSettings } from './sections/DownloadSettings';
import { DataManagementSettings } from './sections/DataManagementSettings';

interface AppSettingsProps {
  passphraseRef?: React.RefObject<string>;
  kyberSecretRef?: React.RefObject<Uint8Array | null>;
  getDisplayUsername?: (username: string) => Promise<string>;
  currentUsername?: string;
  currentDisplayName?: string;
}

interface NotificationSettings {
  desktop: boolean;
  sound: boolean;
}

interface AudioSettings {
  noiseSuppression: boolean;
  echoCancellation: boolean;
}

type SectionId = 'account' | 'appearance' | 'notifications' | 'audio' | 'voice-video' | 'downloads' | 'privacy' | 'data';

export const AppSettings = React.memo(function AppSettings({
  passphraseRef,
  kyberSecretRef,
  getDisplayUsername,
  currentUsername = '',
  currentDisplayName = ''
}: AppSettingsProps) {
  // App theme settings
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Download settings
  const [downloadSettings, setDownloadSettings] = useState<{ downloadPath: string; autoSave: boolean } | null>(null);
  const [isChoosingPath, setIsChoosingPath] = useState(false);
  const [isClearingData, setIsClearingData] = useState(false);

  // Notification & audio preferences
  const [notifications, setNotifications] = useState<NotificationSettings>({ desktop: true, sound: true });
  const [audioSettings, setAudioSettings] = useState<AudioSettings>({ noiseSuppression: true, echoCancellation: true });

  // Currently selected settings section
  const [activeSection, setActiveSection] = useState<SectionId>('account');

  // Screen sharing configuration
  const [screenSettings, setScreenSettings] = useState<any>(null);

  // Profile picture state
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const [shareWithOthers, setShareWithOthers] = useState(false);

  // Device selection state
  const [micDevices, setMicDevices] = useState<MediaDeviceInfo[]>([]);
  const [speakerDevices, setSpeakerDevices] = useState<MediaDeviceInfo[]>([]);
  const [cameraDevices, setCameraDevices] = useState<MediaDeviceInfo[]>([]);
  const [preferredMicId, setPreferredMicId] = useState<string>('');
  const [preferredSpeakerId, setPreferredSpeakerId] = useState<string>('');
  const [preferredCameraId, setPreferredCameraId] = useState<string>('');

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const initDownloadSettings = async () => {
      const api = (window as any).electronAPI;
      if (!api) return;
      try {
        const settings = await api.getDownloadSettings();
        setDownloadSettings(settings);
      } catch { }
    };
    initDownloadSettings();

    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.notifications) {
          setNotifications(parsed.notifications);
          (window as any).edgeApi?.setNotificationsEnabled?.(parsed.notifications.desktop !== false).catch(() => { });
        }
        if (parsed.audioSettings) setAudioSettings(parsed.audioSettings);
        if (parsed.preferredMicId) setPreferredMicId(parsed.preferredMicId);
        if (parsed.preferredSpeakerId) setPreferredSpeakerId(parsed.preferredSpeakerId);
        if (parsed.preferredCameraId) setPreferredCameraId(parsed.preferredCameraId);
      }
    } catch { }

    const loadDevices = async () => {
      try {
        try {
          const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: true });
          stream.getTracks().forEach(t => t.stop());
        } catch { }

        const devices = await navigator.mediaDevices.enumerateDevices();
        setMicDevices(devices.filter(d => d.kind === 'audioinput'));
        setSpeakerDevices(devices.filter(d => d.kind === 'audiooutput'));
        setCameraDevices(devices.filter(d => d.kind === 'videoinput'));
      } catch (e) {
        console.error('[AppSettings] Failed to enumerate devices:', e);
      }
    };
    loadDevices();

    // Initialize profile picture system
    const initProfilePicture = async () => {
      try {
        await profilePictureSystem.initialize();
        const ownAvatar = profilePictureSystem.getOwnAvatar();
        setAvatarUrl(ownAvatar);
        setShareWithOthers(profilePictureSystem.getShareWithOthers());
      } catch (e) {
        console.error('[AppSettings] Failed to init profile picture:', e);
      }
    };
    initProfilePicture();
  }, []);

  useEffect(() => {
    let isMountedLocal = true;
    const loadScreenSettings = async () => {
      try {
        const current = await screenSharingSettings.getSettings();
        if (isMountedLocal) setScreenSettings(current);
      } catch { }
    };
    loadScreenSettings();
    const unsubscribe = screenSharingSettings.subscribe((newSettings) => {
      if (isMountedLocal) setScreenSettings(newSettings);
    });
    return () => {
      isMountedLocal = false;
      unsubscribe();
    };
  }, []);

  const handleChooseDownloadPath = async () => {
    const api = (window as any).electronAPI;
    if (!api || isChoosingPath) return;
    setIsChoosingPath(true);
    try {
      const result = await api.chooseDownloadPath();
      if (result.success && result.path) {
        const updateResult = await api.setDownloadPath(result.path);
        if (updateResult.success) {
          setDownloadSettings(prev => prev ? { ...prev, downloadPath: result.path! } : null);
          toast.success('Download path updated');
        } else {
          toast.error(updateResult.error || 'Failed to update download path');
        }
      }
    } catch {
      toast.error('Failed to change download path');
    } finally {
      setIsChoosingPath(false);
    }
  };

  const handleAutoSaveToggle = async (autoSave: boolean) => {
    const api = (window as any).electronAPI;
    if (!api) return;
    try {
      const result = await api.setAutoSave(autoSave);
      if (result.success) {
        setDownloadSettings(prev => prev ? { ...prev, autoSave } : null);
        toast.success(autoSave ? 'Auto-save enabled' : 'Auto-save disabled');
      } else {
        toast.error(result.error || 'Failed to update auto-save setting');
      }
    } catch {
      toast.error('Failed to change auto-save setting');
    }
  };

  const saveSettings = (updates: Partial<{ notifications: NotificationSettings; audioSettings: AudioSettings; avatarUrl: string | null; preferredMicId: string; preferredSpeakerId: string; preferredCameraId: string }>) => {
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({ ...parsed, ...updates }));
    } catch { }
  };

  const handleClearData = async () => {
    if (isClearingData) return;
    if (confirm('Clear all local data? This will log you out and remove all stored messages.')) {
      setIsClearingData(true);
      try {
        const { encryptedStorage } = await import('../../lib/database/encrypted-storage');
        await encryptedStorage.setItem('app_settings_v1', '');
        window.location.reload();
      } catch {
        toast.error('Failed to clear data');
        setIsClearingData(false);
      }
    }
  };

  const sections: { category: string; items: { id: SectionId; label: string; icon: React.ElementType }[] }[] = [
    {
      category: 'USER SETTINGS',
      items: [
        { id: 'account', label: 'My Account', icon: User },
      ]
    },
    {
      category: 'APP SETTINGS',
      items: [
        { id: 'appearance', label: 'Appearance', icon: Palette },
        { id: 'notifications', label: 'Notifications', icon: Bell },
      ]
    },
    {
      category: 'CALLING',
      items: [
        { id: 'audio', label: 'Audio', icon: Volume2 },
        { id: 'voice-video', label: 'Voice & Video', icon: Monitor },
      ]
    },
    {
      category: 'DATA',
      items: [
        { id: 'downloads', label: 'Downloads', icon: Download },
        { id: 'privacy', label: 'Privacy & Safety', icon: Shield },
        { id: 'data', label: 'Data Management', icon: Trash2 },
      ]
    }
  ];

  if (!mounted) return null;

  return (
    <>
      <AppSettingsStyles />

      <div className="settings-layout select-none">
        <div className="settings-sidebar">
          <div style={{ padding: '8px 0' }}>
            {sections.map((section, idx) => (
              <div key={idx}>
                <div className="settings-category">{section.category}</div>
                {section.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.id}
                      onClick={() => setActiveSection(item.id)}
                      className={`settings-nav-item ${activeSection === item.id ? 'active' : ''}`}
                      style={{ width: 'calc(100% - 16px)' }}
                    >
                      <Icon size={18} />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
                {idx < sections.length - 1 && (
                  <div style={{ margin: '8px 20px', borderBottom: '1px solid hsl(var(--border) / 0.3)' }} />
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="settings-content">
          {activeSection === 'account' && (
            <AccountSettings
              currentUsername={currentUsername}
              currentDisplayName={currentDisplayName}
              avatarUrl={avatarUrl}
              setAvatarUrl={setAvatarUrl}
              shareWithOthers={shareWithOthers}
              setShareWithOthers={setShareWithOthers}
            />
          )}

          {activeSection === 'appearance' && (
            <AppearanceSettings
              theme={theme}
              setTheme={setTheme}
            />
          )}

          {activeSection === 'notifications' && (
            <NotificationSettings
              notifications={notifications}
              setNotifications={setNotifications}
              saveSettings={saveSettings}
            />
          )}

          {activeSection === 'audio' && (
            <AudioSettings
              audioSettings={audioSettings}
              setAudioSettings={setAudioSettings}
              saveSettings={saveSettings}
              preferredMicId={preferredMicId}
              setPreferredMicId={setPreferredMicId}
              preferredSpeakerId={preferredSpeakerId}
              setPreferredSpeakerId={setPreferredSpeakerId}
              preferredCameraId={preferredCameraId}
              setPreferredCameraId={setPreferredCameraId}
              micDevices={micDevices}
              speakerDevices={speakerDevices}
              cameraDevices={cameraDevices}
            />
          )}

          {activeSection === 'voice-video' && screenSettings && (
            <VoiceVideoSettings
              screenSettings={screenSettings}
            />
          )}

          {activeSection === 'downloads' && downloadSettings && (
            <DownloadSettings
              downloadSettings={downloadSettings}
              isChoosingPath={isChoosingPath}
              handleChooseDownloadPath={handleChooseDownloadPath}
              handleAutoSaveToggle={handleAutoSaveToggle}
            />
          )}

          {activeSection === 'privacy' && (
            <div>
              <h2 className="settings-section-title">Privacy & Safety</h2>
              <div className="settings-group">
                <BlockedUsersSettings
                  passphraseRef={passphraseRef}
                  kyberSecretRef={kyberSecretRef}
                  getDisplayUsername={getDisplayUsername}
                />
              </div>
            </div>
          )}

          {activeSection === 'data' && (
            <DataManagementSettings
              handleClearData={handleClearData}
              isClearingData={isClearingData}
            />
          )}
        </div>
      </div>
    </>
  );
});
