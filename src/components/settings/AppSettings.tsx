import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Label } from '../../components/ui/label';
import { Switch } from '../../components/ui/switch';
import { Button } from '../../components/ui/button';
import { Separator } from '../../components/ui/separator';
import { useTheme } from 'next-themes';
import { ScreenSharingSettings } from './ScreenSharingSettings';
import { syncEncryptedStorage } from '../../lib/encrypted-storage';
import { BlockedUsersSettings } from './BlockedUsersSettings';

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
  
  const { theme, setTheme: rawSetTheme } = useTheme();
  const setTheme = React.useCallback((newTheme: string) => {
    rawSetTheme(newTheme);
  }, [rawSetTheme]);
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
    } catch {}
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
    } catch {}
  };

  const handleAudioSettingChange = (key: keyof AudioSettings, value: boolean) => {
    const updated = { ...audioSettings, [key]: value };
    setAudioSettings(updated);
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({ ...parsed, audioSettings: updated }));
      window.dispatchEvent(new CustomEvent('settings-changed', { detail: { audioSettings: updated } }));
    } catch {}
  };

  const handleClearData = async () => {
    if (isClearingData) return;
    if (confirm('Clear all local data? This will log you out and remove all stored messages.')) {
      setIsClearingData(true);
      try { const { encryptedStorage } = await import('../../lib/encrypted-storage'); await encryptedStorage.setItem('app_settings_v1', ''); } catch {}
      window.location.reload();
    }
  };

  const handleClose = () => {
    window.dispatchEvent(new CustomEvent('closeSettings'));
  };

  return (
    <div className="flex flex-col h-full" style={{ backgroundColor: 'var(--color-background)' }}>
      <div className="p-4 border-b flex items-center justify-between" style={{ backgroundColor: 'var(--color-surface)', borderColor: 'var(--color-border)' }}>
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--color-text-primary)' }}>Settings</h2>
        </div>
        <Button variant="ghost" size="sm" onClick={handleClose} className="h-8 w-8 p-0" style={{ color: 'var(--color-text-secondary)' }}>
          Close
        </Button>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="space-y-6 max-w-2xl">
          <p style={{ color: 'var(--color-text-secondary)' }}>Manage preferences.</p>

          <Card>
            <CardHeader>
              <CardTitle>Appearance</CardTitle>
              <CardDescription>Choose theme.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <Label className="text-sm font-medium">Theme</Label>
                <div className="flex gap-2">
                  <Button variant={theme === 'light' ? 'default' : 'outline'} size="sm" onClick={() => setTheme('light')}>Light</Button>
                  <Button variant={theme === 'dark' ? 'default' : 'outline'} size="sm" onClick={() => setTheme('dark')}>Dark</Button>
                  <Button variant={theme === 'system' ? 'default' : 'outline'} size="sm" onClick={() => setTheme('system')}>System</Button>
                </div>
              </div>
            </CardContent>
          </Card>


          <Card>
            <CardHeader>
              <CardTitle>Notifications</CardTitle>
              <CardDescription>Configure notifications.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Desktop Notifications</Label>
                  <div className="text-sm text-muted-foreground">Show notifications when app is in background.</div>
                </div>
                <Switch checked={notifications.desktop} onCheckedChange={(v) => handleNotificationChange('desktop', v)} />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Sound Notifications</Label>
                  <div className="text-sm text-muted-foreground">Play sound on new messages.</div>
                </div>
                <Switch checked={notifications.sound} onCheckedChange={(v) => handleNotificationChange('sound', v)} />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Audio & Video</CardTitle>
              <CardDescription>Configure call settings.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Noise Suppression</Label>
                  <div className="text-sm text-muted-foreground">Reduce background noise during calls.</div>
                </div>
                <Switch checked={audioSettings.noiseSuppression} onCheckedChange={(v) => handleAudioSettingChange('noiseSuppression', v)} />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Echo Cancellation</Label>
                  <div className="text-sm text-muted-foreground">Prevent audio feedback during calls.</div>
                </div>
                <Switch checked={audioSettings.echoCancellation} onCheckedChange={(v) => handleAudioSettingChange('echoCancellation', v)} />
              </div>
            </CardContent>
          </Card>

          {downloadSettings && (
            <Card>
              <CardHeader>
                <CardTitle>File Downloads</CardTitle>
                <CardDescription>Configure file saving.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-3">
                  <Label className="text-sm font-medium">Download Location</Label>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 p-2 bg-muted rounded-md text-sm font-mono truncate" title={downloadSettings.downloadPath}>{downloadSettings.downloadPath}</div>
                    <Button variant="outline" size="sm" onClick={handleChooseDownloadPath} disabled={isChoosingPath}>{isChoosingPath ? 'Browsing…' : 'Browse'}</Button>
                  </div>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5"><Label>Auto-save Files</Label><div className="text-sm text-muted-foreground">Automatically save files without asking.</div></div>
                  <Switch checked={downloadSettings.autoSave} onCheckedChange={handleAutoSaveToggle} />
                </div>
              </CardContent>
            </Card>
          )}

          <ScreenSharingSettings />
          <BlockedUsersSettings passphraseRef={passphraseRef} kyberSecretRef={kyberSecretRef} getDisplayUsername={getDisplayUsername} />

          <Card>
            <CardHeader>
              <CardTitle>Data Management</CardTitle>
              <CardDescription>Manage local data and storage.</CardDescription>
            </CardHeader>
            <CardContent>
              <Button variant="destructive" onClick={handleClearData} disabled={isClearingData} className="w-full">{isClearingData ? 'Clearing Data…' : 'Clear All Data'}</Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
});
