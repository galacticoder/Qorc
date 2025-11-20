import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Label } from '../ui/label';
import { AnimatedSwitch } from '../ui/AnimatedSwitch';
import { Button } from '../ui/button';
import { Separator } from '../ui/separator';
import { useTheme } from 'next-themes';
import { ScreenSharingSettings } from './ScreenSharingSettings';
import { syncEncryptedStorage } from '../../lib/encrypted-storage';
import { BlockedUsersSettings } from './BlockedUsersSettings';
import { Bell, Monitor, Volume2, Download, Shield, Database } from 'lucide-react';
import ThemeToggle from './ThemeToggle';
import { ScrollArea } from '../ui/scroll-area';

interface AppSettingsProps {
  passphraseRef?: React.MutableRefObject<string>;
  kyberSecretRef?: React.MutableRefObject<Uint8Array | null>;
  getDisplayUsername?: (username: string) => Promise<string>;
}

interface NotificationSettings {
  desktop: boolean;
  sound: boolean;
}

interface AudioSettings {
  noiseSuppression: boolean;
  echoCancellation: boolean;
}

export const AppSettings = React.memo(function AppSettings({ passphraseRef, kyberSecretRef, getDisplayUsername }: AppSettingsProps = {}) {

  const { theme, setTheme } = useTheme();
  const [downloadSettings, setDownloadSettings] = useState<{ downloadPath: string; autoSave: boolean } | null>(null);
  const [isChoosingPath, setIsChoosingPath] = useState(false);
  const [isClearingData, setIsClearingData] = useState(false);
  const [notifications, setNotifications] = useState<NotificationSettings>({ desktop: true, sound: true });
  const [audioSettings, setAudioSettings] = useState<AudioSettings>({ noiseSuppression: true, echoCancellation: true });

  useEffect(() => {
    const initDownloadSettings = async () => {
      const api = (window as any).electronAPI;
      if (!api) return;
      try {
        const settings = await api.getDownloadSettings();
        setDownloadSettings(settings);
      } catch (_error) {
        console.error('Failed to get download settings:', _error);
      }
    };
    initDownloadSettings();

    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.notifications) setNotifications(parsed.notifications);
        if (parsed.audioSettings) setAudioSettings(parsed.audioSettings);
      }
    } catch { }
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
        } else {
          alert(`Failed to set download path: ${updateResult.error || 'Unknown error'}`);
        }
      } else if (!result.canceled) {
        alert(`Failed to choose download path: ${result.error || 'Unknown error'}`);
      }
    } catch (_error) {
      console.error('Failed to choose download path:', _error);
      alert('Failed to choose download path. Please try again.');
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
      } else {
        alert(`Failed to update auto-save setting: ${result.error || 'Unknown error'}`);
      }
    } catch (_error) {
      console.error('Failed to update auto-save setting:', _error);
      alert('Failed to update auto-save setting. Please try again.');
    }
  };

  const handleNotificationChange = (key: keyof NotificationSettings, value: boolean) => {
    const updated = { ...notifications, [key]: value };
    setNotifications(updated);
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({ ...parsed, notifications: updated }));
      window.dispatchEvent(new CustomEvent('settings-changed', { detail: { notifications: updated } }));
    } catch { }
  };

  const handleAudioSettingChange = (key: keyof AudioSettings, value: boolean) => {
    const updated = { ...audioSettings, [key]: value };
    setAudioSettings(updated);
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({ ...parsed, audioSettings: updated }));
      window.dispatchEvent(new CustomEvent('settings-changed', { detail: { audioSettings: updated } }));
    } catch { }
  };

  const handleClearData = async () => {
    if (isClearingData) return;
    if (confirm('Clear all local data? This will log you out and remove all stored messages.')) {
      setIsClearingData(true);
      try { const { encryptedStorage } = await import('../../lib/encrypted-storage'); await encryptedStorage.setItem('app_settings_v1', ''); } catch { }
      window.location.reload();
    }
  };

  return (
    <>
      <style>{`
        .settings-scroll-container {
          scrollbar-width: thin;
          scrollbar-color: transparent transparent;
          transition: scrollbar-color 0.3s ease;
        }
        
        .settings-scroll-container:hover {
          scrollbar-color: hsl(var(--muted-foreground) / 0.3) transparent;
        }
        
        .settings-scroll-container::-webkit-scrollbar {
          width: 8px;
        }
        
        .settings-scroll-container::-webkit-scrollbar-track {
          background: transparent;
        }
        
        .settings-scroll-container::-webkit-scrollbar-thumb {
          background-color: transparent;
          border-radius: 4px;
          transition: background-color 0.3s ease;
        }
        
        .settings-scroll-container:hover::-webkit-scrollbar-thumb {
          background-color: hsl(var(--muted-foreground) / 0.3);
        }
        
        .settings-scroll-container::-webkit-scrollbar-thumb:hover {
          background-color: hsl(var(--muted-foreground) / 0.5);
        }
      `}</style>
      <div className="flex flex-col h-full max-h-[85vh]">
        <div className="p-6 border-b border-border flex-shrink-0">
          <h1 className="text-2xl font-semibold">Settings</h1>
          <p className="text-sm text-muted-foreground mt-1">Manage your application preferences</p>
        </div>

        <div className="settings-scroll-container flex-1 overflow-y-auto p-6 space-y-6">
          {/* Appearance Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Monitor className="h-5 w-5" />
                Appearance
              </CardTitle>
              <CardDescription>Customize how the app looks</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Theme</Label>
                <ThemeToggle />
              </div>
            </CardContent>
          </Card>

          {/* Notifications Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bell className="h-5 w-5" />
                Notifications
              </CardTitle>
              <CardDescription>Configure notification preferences</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="desktop-notifications">Desktop Notifications</Label>
                  <p className="text-sm text-muted-foreground">Show notifications on your desktop</p>
                </div>
                <AnimatedSwitch
                  checked={notifications.desktop}
                  onCheckedChange={(checked) => {
                    setNotifications(prev => ({ ...prev, desktop: checked }));
                    try {
                      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({
                        notifications: { ...notifications, desktop: checked },
                        audioSettings
                      }));
                    } catch { }
                  }}
                />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="sound-notifications">Sound Notifications</Label>
                  <p className="text-sm text-muted-foreground">Play sound for new messages</p>
                </div>
                <AnimatedSwitch
                  checked={notifications.sound}
                  onCheckedChange={(checked) => {
                    setNotifications(prev => ({ ...prev, sound: checked }));
                    try {
                      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({
                        notifications: { ...notifications, sound: checked },
                        audioSettings
                      }));
                    } catch { }
                  }}
                />
              </div>
            </CardContent>
          </Card>

          {/* Audio Settings Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Volume2 className="h-5 w-5" />
                Audio
              </CardTitle>
              <CardDescription>Configure audio call settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="noise-suppression">Noise Suppression</Label>
                  <p className="text-sm text-muted-foreground">Filter out background noise during calls</p>
                </div>
                <AnimatedSwitch
                  checked={audioSettings.noiseSuppression}
                  onCheckedChange={(checked) => {
                    setAudioSettings(prev => ({ ...prev, noiseSuppression: checked }));
                    try {
                      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({
                        notifications,
                        audioSettings: { ...audioSettings, noiseSuppression: checked }
                      }));
                    } catch { }
                  }}
                />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label htmlFor="echo-cancellation">Echo Cancellation</Label>
                  <p className="text-sm text-muted-foreground">Reduce echo during calls</p>
                </div>
                <AnimatedSwitch
                  checked={audioSettings.echoCancellation}
                  onCheckedChange={(checked) => {
                    setAudioSettings(prev => ({ ...prev, echoCancellation: checked }));
                    try {
                      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({
                        notifications,
                        audioSettings: { ...audioSettings, echoCancellation: checked }
                      }));
                    } catch { }
                  }}
                />
              </div>
            </CardContent>
          </Card>

          {/* Screen Sharing Settings */}
          <ScreenSharingSettings />

          {/* Downloads Section */}
          {downloadSettings && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Download className="h-5 w-5" />
                  Downloads
                </CardTitle>
                <CardDescription>Manage download preferences</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="download-path">Download Location</Label>
                  <div className="flex gap-2">
                    <input
                      id="download-path"
                      type="text"
                      readOnly
                      value={downloadSettings.downloadPath || ''}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                    />
                    <Button
                      onClick={handleChooseDownloadPath}
                      variant="outline"
                      disabled={isChoosingPath}
                    >
                      {isChoosingPath ? 'Choosing...' : 'Browse'}
                    </Button>
                  </div>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label htmlFor="auto-save">Auto-save Files</Label>
                    <p className="text-sm text-muted-foreground">Automatically save files to download location</p>
                  </div>
                  <AnimatedSwitch
                    checked={downloadSettings.autoSave || false}
                    onCheckedChange={handleAutoSaveToggle}
                  />
                </div>
              </CardContent>
            </Card>
          )}

          {/* Privacy Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Privacy
              </CardTitle>
              <CardDescription>Manage your privacy settings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <BlockedUsersSettings
                passphraseRef={passphraseRef}
                kyberSecretRef={kyberSecretRef}
                getDisplayUsername={getDisplayUsername}
              />
            </CardContent>
          </Card>

          {/* Data Management Section */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Data Management
              </CardTitle>
              <CardDescription>Manage your app data</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Label>Clear All Data</Label>
                <p className="text-sm text-muted-foreground mb-2">
                  This will delete all your messages, conversations, and settings. This action cannot be undone.
                </p>
                <Button
                  variant="destructive"
                  onClick={handleClearData}
                  disabled={isClearingData}
                >
                  {isClearingData ? 'Clearing...' : 'Clear All Data'}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
});
