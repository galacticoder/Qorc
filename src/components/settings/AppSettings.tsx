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
import { Bell, Monitor, Volume2, Download, Shield, Database, Moon, Sun, Laptop } from 'lucide-react';
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
    <div className="flex flex-col h-full bg-background">
      <div className="p-6 border-b border-border bg-background sticky top-0 z-10 select-none">
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground text-sm">Manage your application preferences</p>
      </div>

      <ScrollArea className="flex-1 p-6">
        <div className="max-w-4xl mx-auto space-y-8 pb-10 select-none">

          {/* Appearance */}
          <section className="space-y-4">
            <div className="flex items-center gap-2 text-primary dark:text-primary-foreground">
              <Monitor className="w-5 h-5" />
              <h2 className="text-lg font-semibold text-foreground">Appearance</h2>
            </div>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-base">Theme</Label>
                    <p className="text-sm text-muted-foreground">Select your preferred interface theme</p>
                  </div>
                  <div className="flex gap-2 bg-secondary/50 p-1 rounded-lg">
                    <Button
                      variant={theme === 'light' ? 'default' : 'ghost'}
                      size="sm"
                      onClick={() => setTheme('light')}
                      className="gap-2"
                    >
                      <Sun className="w-4 h-4" /> Light
                    </Button>
                    <Button
                      variant={theme === 'dark' ? 'default' : 'ghost'}
                      size="sm"
                      onClick={() => setTheme('dark')}
                      className="gap-2"
                    >
                      <Moon className="w-4 h-4" /> Dark
                    </Button>
                    <Button
                      variant={theme === 'system' ? 'default' : 'ghost'}
                      size="sm"
                      onClick={() => setTheme('system')}
                      className="gap-2"
                    >
                      <Laptop className="w-4 h-4" /> System
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          {/* Notifications */}
          <section className="space-y-4">
            <div className="flex items-center gap-2 text-primary dark:text-primary-foreground">
              <Bell className="w-5 h-5" />
              <h2 className="text-lg font-semibold text-foreground">Notifications</h2>
            </div>
            <Card>
              <CardContent className="pt-6 space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-base">Desktop Notifications</Label>
                    <p className="text-sm text-muted-foreground">Show notifications when app is in background</p>
                  </div>
                  <AnimatedSwitch checked={notifications.desktop} onCheckedChange={(v) => handleNotificationChange('desktop', v)} />
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-base">Sound Notifications</Label>
                    <p className="text-sm text-muted-foreground">Play sound on new messages</p>
                  </div>
                  <AnimatedSwitch checked={notifications.sound} onCheckedChange={(v) => handleNotificationChange('sound', v)} />
                </div>
              </CardContent>
            </Card>
          </section>

          {/* Audio & Video */}
          <section className="space-y-4">
            <div className="flex items-center gap-2 text-primary dark:text-primary-foreground">
              <Volume2 className="w-5 h-5" />
              <h2 className="text-lg font-semibold text-foreground">Audio & Video</h2>
            </div>
            <Card>
              <CardContent className="pt-6 space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-base">Noise Suppression</Label>
                    <p className="text-sm text-muted-foreground">Reduce background noise during calls</p>
                  </div>
                  <AnimatedSwitch checked={audioSettings.noiseSuppression} onCheckedChange={(v) => handleAudioSettingChange('noiseSuppression', v)} />
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label className="text-base">Echo Cancellation</Label>
                    <p className="text-sm text-muted-foreground">Prevent audio feedback during calls</p>
                  </div>
                  <AnimatedSwitch checked={audioSettings.echoCancellation} onCheckedChange={(v) => handleAudioSettingChange('echoCancellation', v)} />
                </div>
              </CardContent>
            </Card>
          </section>

          {/* Downloads */}
          {downloadSettings && (
            <section className="space-y-4">
              <div className="flex items-center gap-2 text-primary dark:text-primary-foreground">
                <Download className="w-5 h-5" />
                <h2 className="text-lg font-semibold text-foreground">File Downloads</h2>
              </div>
              <Card>
                <CardContent className="pt-6 space-y-6">
                  <div className="space-y-3">
                    <Label className="text-base">Download Location</Label>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 p-3 bg-secondary/50 rounded-lg text-sm font-mono truncate border border-border/50" title={downloadSettings.downloadPath}>
                        {downloadSettings.downloadPath}
                      </div>
                      <Button variant="outline" onClick={handleChooseDownloadPath} disabled={isChoosingPath}>
                        {isChoosingPath ? 'Browsing…' : 'Browse'}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </section>
          )}

          {/* Privacy & Security */}
          <section className="space-y-4">
            <div className="flex items-center gap-2 text-primary dark:text-primary-foreground">
              <Shield className="w-5 h-5" />
              <h2 className="text-lg font-semibold text-foreground">Privacy & Security</h2>
            </div>
            <ScreenSharingSettings />
            <BlockedUsersSettings passphraseRef={passphraseRef} kyberSecretRef={kyberSecretRef} getDisplayUsername={getDisplayUsername} />
          </section>

          {/* Data Management */}
          <section className="space-y-4">
            <div className="flex items-center gap-2 text-destructive">
              <Database className="w-5 h-5" />
              <h2 className="text-lg font-semibold text-destructive">Data Management</h2>
            </div>
            <Card className="border-destructive/20">
              <CardHeader>
                <CardTitle className="text-destructive">Danger Zone</CardTitle>
                <CardDescription>Irreversible actions regarding your data</CardDescription>
              </CardHeader>
              <CardContent>
                <Button variant="destructive" onClick={handleClearData} disabled={isClearingData} className="w-full sm:w-auto">
                  {isClearingData ? 'Clearing Data…' : 'Clear All Local Data'}
                </Button>
              </CardContent>
            </Card>
          </section>

        </div>
      </ScrollArea>
    </div>
  );
});
