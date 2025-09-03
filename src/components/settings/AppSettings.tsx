import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { useTheme } from 'next-themes';
import { Moon, Sun, Monitor, Palette, Shield, Bell, Volume2, Trash2, Download, FolderOpen, X } from 'lucide-react';
import { ScreenSharingSettings } from './ScreenSharingSettings';

export function AppSettings() {
  const { theme, setTheme } = useTheme();
  const [downloadSettings, setDownloadSettings] = useState<{ downloadPath: string; autoSave: boolean } | null>(null);
  const [isElectron, setIsElectron] = useState(false);

  useEffect(() => {
    const checkElectron = async () => {
      if (window.electronAPI?.isElectron) {
        setIsElectron(true);
        try {
          const settings = await window.electronAPI.getDownloadSettings();
          setDownloadSettings(settings);
        } catch (error) {
          console.error('Failed to get download settings:', error);
        }
      }
    };
    checkElectron();
  }, []);

  const handleChooseDownloadPath = async () => {
    if (!window.electronAPI) return;
    
    try {
      const result = await window.electronAPI.chooseDownloadPath();
      if (result.success && result.path) {
        const updateResult = await window.electronAPI.setDownloadPath(result.path);
        if (updateResult.success) {
          setDownloadSettings(prev => prev ? { ...prev, downloadPath: result.path! } : null);
        } else {
          // Show user-facing error for failed path update
          alert(`Failed to set download path: ${updateResult.error || 'Unknown error'}`);
        }
      } else {
        // Show user-facing error for failed path selection
        if (!result.canceled) {
          alert(`Failed to choose download path: ${result.error || 'Unknown error'}`);
        }
      }
    } catch (error) {
      console.error('Failed to choose download path:', error);
      alert('Failed to choose download path. Please try again.');
    }
  };

  const handleAutoSaveToggle = async (autoSave: boolean) => {
    if (!window.electronAPI) return;
    
    try {
      const result = await window.electronAPI.setAutoSave(autoSave);
      if (result.success) {
        setDownloadSettings(prev => prev ? { ...prev, autoSave } : null);
      } else {
        // Show user-facing error for failed auto-save update
        alert(`Failed to update auto-save setting: ${result.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Failed to update auto-save setting:', error);
      alert('Failed to update auto-save setting. Please try again.');
    }
  };

  const handleClearData = () => {
    if (confirm('Are you sure you want to clear all local data? This will log you out and remove all stored messages.')) {
      // Clear localStorage
      localStorage.clear();
      // Clear sessionStorage
      sessionStorage.clear();
      // Reload the page to reset the app state
      window.location.reload();
    }
  };

  const handleClose = () => {
    window.dispatchEvent(new CustomEvent('closeSettings'));
  };

  return (
    <div 
      className="flex flex-col h-full"
      style={{ backgroundColor: 'var(--color-background)' }}
    >
      {/* Header with close button */}
      <div 
        className="p-4 border-b flex items-center justify-between"
        style={{
          backgroundColor: 'var(--color-surface)',
          borderColor: 'var(--color-border)'
        }}
      >
        <div>
          <h2 
            className="text-lg font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Settings
          </h2>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleClose}
          className="h-8 w-8 p-0"
          style={{
            color: 'var(--color-text-secondary)'
          }}
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="space-y-6 max-w-2xl">
          <p style={{ color: 'var(--color-text-secondary)' }}>
            Manage your application preferences and privacy settings.
          </p>

      {/* Appearance Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Palette className="h-5 w-5" />
            <CardTitle>Appearance</CardTitle>
          </div>
          <CardDescription>
            Customize the look and feel of the application
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <Label className="text-sm font-medium">Theme</Label>
            <div className="flex gap-2">
              <Button
                variant={theme === 'light' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setTheme('light')}
                className="flex items-center gap-2"
              >
                <Sun className="h-4 w-4" />
                Light
              </Button>
              <Button
                variant={theme === 'dark' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setTheme('dark')}
                className="flex items-center gap-2"
              >
                <Moon className="h-4 w-4" />
                Dark
              </Button>
              <Button
                variant={theme === 'system' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setTheme('system')}
                className="flex items-center gap-2"
              >
                <Monitor className="h-4 w-4" />
                System
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Choose your preferred theme or follow your system setting
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Privacy & Security Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            <CardTitle>Privacy & Security</CardTitle>
          </div>
          <CardDescription>
            Control your privacy and security preferences
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>End-to-End Encryption</Label>
              <div className="text-sm text-muted-foreground">
                All messages are encrypted using X25519 + Kyber768 hybrid encryption
              </div>
            </div>
            <Switch checked={true} disabled />
          </div>
          
          <Separator />
          
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Message Persistence</Label>
              <div className="text-sm text-muted-foreground">
                Store encrypted messages locally for offline access
              </div>
            </div>
            <Switch checked={true} />
          </div>
        </CardContent>
      </Card>

      {/* Notifications Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            <CardTitle>Notifications</CardTitle>
          </div>
          <CardDescription>
            Configure how you receive notifications
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Desktop Notifications</Label>
              <div className="text-sm text-muted-foreground">
                Show notifications when the app is in the background
              </div>
            </div>
            <Switch defaultChecked />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Sound Notifications</Label>
              <div className="text-sm text-muted-foreground">
                Play sound when receiving new messages
              </div>
            </div>
            <Switch defaultChecked />
          </div>
        </CardContent>
      </Card>

      {/* Audio Settings */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Volume2 className="h-5 w-5" />
            <CardTitle>Audio & Video</CardTitle>
          </div>
          <CardDescription>
            Configure audio and video call settings
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Noise Suppression</Label>
              <div className="text-sm text-muted-foreground">
                Reduce background noise during calls
              </div>
            </div>
            <Switch defaultChecked />
          </div>
          
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Echo Cancellation</Label>
              <div className="text-sm text-muted-foreground">
                Prevent audio feedback during calls
              </div>
            </div>
            <Switch defaultChecked />
          </div>
        </CardContent>
      </Card>

      {/* Download Settings - Only show in Electron */}
      {isElectron && downloadSettings && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Download className="h-5 w-5" />
              <CardTitle>File Downloads</CardTitle>
            </div>
            <CardDescription>
              Configure how files are saved when downloaded
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <Label className="text-sm font-medium">Download Location</Label>
              <div className="flex items-center gap-2">
                <div className="flex-1 p-2 bg-muted rounded-md text-sm font-mono truncate" title={downloadSettings.downloadPath}>
                  {downloadSettings.downloadPath}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleChooseDownloadPath}
                  className="flex items-center gap-2"
                >
                  <FolderOpen className="h-4 w-4" />
                  Browse
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Choose where downloaded files will be saved
              </p>
            </div>
            
            <Separator />
            
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>Auto-save Files</Label>
                <div className="text-sm text-muted-foreground">
                  Automatically save files to download folder without asking
                </div>
              </div>
              <Switch 
                checked={downloadSettings.autoSave} 
                onCheckedChange={handleAutoSaveToggle}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Screen Sharing Settings */}
      <ScreenSharingSettings />


      {/* Data Management */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Trash2 className="h-5 w-5" />
            <CardTitle>Data Management</CardTitle>
          </div>
          <CardDescription>
            Manage your local data and storage
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button 
            variant="destructive" 
            onClick={handleClearData}
            className="w-full"
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Clear All Data
          </Button>
        </CardContent>
      </Card>
        </div>
      </div>
    </div>
  );
}