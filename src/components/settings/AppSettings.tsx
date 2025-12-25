import React, { useState, useEffect, useRef } from 'react';
import { AnimatedSwitch } from '../ui/AnimatedSwitch';
import { Button } from '../ui/button';
import { useTheme } from 'next-themes';
import { syncEncryptedStorage } from '../../lib/encrypted-storage';
import { blockingSystem, BlockedUser } from '../../lib/blocking-system';
import { profilePictureSystem } from '../../lib/profile-picture-system';
import {
  ScreenSharingSettings as ScreenSharingSettingsType,
  SCREEN_SHARING_RESOLUTIONS,
  SCREEN_SHARING_FRAMERATES
} from '../../lib/screen-sharing-consts';
import { screenSharingSettings } from '../../lib/screen-sharing-settings';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { User, Palette, Bell, Volume2, Monitor, Download, Shield, Trash2, Camera, X } from 'lucide-react';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';

const PROFILE_PICTURE_EVENT_RATE_WINDOW_MS = 10_000;
const PROFILE_PICTURE_EVENT_RATE_MAX = 200;
const MAX_PROFILE_PICTURE_EVENT_TYPE_LENGTH = 32;

const sanitizeEventText = (value: unknown, maxLen: number): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
  if (!cleaned) return null;
  return cleaned.slice(0, maxLen);
};

interface AppSettingsProps {
  passphraseRef?: React.MutableRefObject<string>;
  kyberSecretRef?: React.MutableRefObject<Uint8Array | null>;
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

const QUALITY_OPTIONS = ['low', 'medium', 'high'] as const;
const QUALITY_LABELS: Record<string, string> = { low: 'Low', medium: 'Medium', high: 'High' };

export const AppSettings = React.memo(function AppSettings({
  passphraseRef,
  kyberSecretRef,
  getDisplayUsername,
  currentUsername = '',
  currentDisplayName = ''
}: AppSettingsProps) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [downloadSettings, setDownloadSettings] = useState<{ downloadPath: string; autoSave: boolean } | null>(null);
  const [isChoosingPath, setIsChoosingPath] = useState(false);
  const [isClearingData, setIsClearingData] = useState(false);
  const [notifications, setNotifications] = useState<NotificationSettings>({ desktop: true, sound: true });
  const [audioSettings, setAudioSettings] = useState<AudioSettings>({ noiseSuppression: true, echoCancellation: true });
  const [activeSection, setActiveSection] = useState<SectionId>('account');

  const [blockedUsers, setBlockedUsers] = useState<BlockedUser[]>([]);
  const [blockedLoading, setBlockedLoading] = useState(false);
  const [displayMap, setDisplayMap] = useState<Record<string, string>>({});

  const [screenSettings, setScreenSettings] = useState<ScreenSharingSettingsType | null>(null);

  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const [shareWithOthers, setShareWithOthers] = useState(false);
  const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);
  const avatarInputRef = useRef<HTMLInputElement>(null);

  // Device selection state
  const [micDevices, setMicDevices] = useState<MediaDeviceInfo[]>([]);
  const [speakerDevices, setSpeakerDevices] = useState<MediaDeviceInfo[]>([]);
  const [cameraDevices, setCameraDevices] = useState<MediaDeviceInfo[]>([]);
  const [preferredMicId, setPreferredMicId] = useState<string>('');
  const [preferredSpeakerId, setPreferredSpeakerId] = useState<string>('');
  const [preferredCameraId, setPreferredCameraId] = useState<string>('');

  const profilePictureEventRateRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

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

    const handleAvatarUpdate = (event: Event) => {
      try {
        const now = Date.now();
        const bucket = profilePictureEventRateRef.current;
        if (now - bucket.windowStart > PROFILE_PICTURE_EVENT_RATE_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > PROFILE_PICTURE_EVENT_RATE_MAX) {
          return;
        }

        if (!(event instanceof CustomEvent)) return;
        const detail = event.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;

        const type = sanitizeEventText((detail as any).type, MAX_PROFILE_PICTURE_EVENT_TYPE_LENGTH);
        if (type !== 'own') return;

        setAvatarUrl(profilePictureSystem.getOwnAvatar());
      } catch { }
    };

    window.addEventListener('profile-picture-updated', handleAvatarUpdate as EventListener);
    return () => window.removeEventListener('profile-picture-updated', handleAvatarUpdate as EventListener);
  }, []);

  useEffect(() => {
    const loadBlockedUsers = async () => {
      const passphrase = passphraseRef?.current;
      const kyberSecret = kyberSecretRef?.current || null;
      if (!passphrase && !kyberSecret) return;

      setBlockedLoading(true);
      try {
        const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
        const users = await blockingSystem.getBlockedUsers(key);
        setBlockedUsers(users);
      } catch {
        setBlockedUsers([]);
      } finally {
        setBlockedLoading(false);
      }
    };
    loadBlockedUsers();
  }, [passphraseRef, kyberSecretRef]);

  useEffect(() => {
    let canceled = false;
    (async () => {
      if (!blockedUsers.length || !getDisplayUsername) {
        setDisplayMap({});
        return;
      }
      const entries = await Promise.all(
        blockedUsers.map(async (u) => {
          try {
            const dn = await getDisplayUsername(u.username);
            return [u.username, dn] as const;
          } catch {
            return [u.username, u.username] as const;
          }
        })
      );
      if (!canceled) {
        const next: Record<string, string> = {};
        for (const [k, v] of entries) next[k] = v;
        setDisplayMap(next);
      }
    })();
    return () => { canceled = true; };
  }, [blockedUsers, getDisplayUsername]);

  useEffect(() => {
    let mounted = true;
    const loadScreenSettings = async () => {
      try {
        const current = await screenSharingSettings.getSettings();
        if (mounted) setScreenSettings(current);
      } catch { }
    };
    loadScreenSettings();
    const unsubscribe = screenSharingSettings.subscribe((newSettings) => {
      if (mounted) setScreenSettings(newSettings);
    });
    return () => { mounted = false; unsubscribe(); };
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
        }
      }
    } catch { } finally {
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
      }
    } catch { }
  };

  const saveSettings = (updates: Partial<{ notifications: NotificationSettings; audioSettings: AudioSettings; avatarUrl: string | null; preferredMicId: string; preferredSpeakerId: string; preferredCameraId: string }>) => {
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({ ...parsed, ...updates }));
    } catch { }
  };

  const handleUnblockUser = async (username: string) => {
    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;
    if (!passphrase && !kyberSecret) return;

    setBlockedLoading(true);
    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      await blockingSystem.unblockUser(username, key);
      setBlockedUsers(prev => prev.filter(u => u.username !== username));
    } catch { } finally {
      setBlockedLoading(false);
    }
  };

  const handleClearData = async () => {
    if (isClearingData) return;
    if (confirm('Clear all local data? This will log you out and remove all stored messages.')) {
      setIsClearingData(true);
      try {
        const { encryptedStorage } = await import('../../lib/encrypted-storage');
        await encryptedStorage.setItem('app_settings_v1', '');
      } catch { }
      window.location.reload();
    }
  };

  const handleAvatarChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || isUploadingAvatar) return;

    e.target.value = '';

    if (file.size > 5 * 1024 * 1024) {
      toast.error('Image too large (max 5MB)');
      return;
    }

    setIsUploadingAvatar(true);

    const reader = new FileReader();
    reader.onloadend = async () => {
      try {
        const result = reader.result as string;
        const uploadResult = await profilePictureSystem.setOwnAvatar(result);

        if (uploadResult.success) {
          setAvatarUrl(profilePictureSystem.getOwnAvatar());
          toast.success('Profile picture updated');
        } else {
          toast.error(uploadResult.error || 'Failed to upload avatar');
        }
      } catch {
        toast.error('Failed to process image');
      } finally {
        setIsUploadingAvatar(false);
      }
    };
    reader.onerror = () => {
      toast.error('Failed to read image file');
      setIsUploadingAvatar(false);
    };
    reader.readAsDataURL(file);
  };

  const handleRemoveAvatar = async () => {
    await profilePictureSystem.removeOwnAvatar(currentUsername);
    toast.success('Profile picture removed');
  };

  const handleShareToggle = async (share: boolean) => {
    await profilePictureSystem.setShareWithOthers(share);
    setShareWithOthers(share);
  };

  const displayUsername = currentDisplayName || currentUsername || 'User';
  const truncatedHash = currentUsername?.length > 20 ? `${currentUsername.slice(0, 8)}...${currentUsername.slice(-8)}` : currentUsername;

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
      <style>{`
        .settings-layout {
          display: flex;
          height: 80vh;
          width: 100%;
          overflow: hidden;
        }
        .settings-sidebar {
          width: 220px;
          flex-shrink: 0;
          background: hsl(var(--secondary) / 0.3);
          overflow-y: auto;
          scrollbar-width: thin;
          scrollbar-color: hsl(var(--muted-foreground) / 0.2) transparent;
        }
        .settings-sidebar::-webkit-scrollbar { width: 4px; }
        .settings-sidebar::-webkit-scrollbar-track { background: transparent; }
        .settings-sidebar::-webkit-scrollbar-thumb { 
          background: hsl(var(--muted-foreground) / 0.2); 
          border-radius: 2px;
        }
        .settings-content {
          flex: 1;
          overflow-y: auto;
          padding: 40px;
          scrollbar-width: thin;
          scrollbar-color: hsl(var(--muted-foreground) / 0.2) transparent;
        }
        .settings-content::-webkit-scrollbar { width: 8px; }
        .settings-content::-webkit-scrollbar-track { background: transparent; }
        .settings-content::-webkit-scrollbar-thumb { 
          background: hsl(var(--muted-foreground) / 0.2); 
          border-radius: 4px;
        }
        .settings-nav-item {
          display: flex;
          align-items: center;
          gap: 10px;
          width: 100%;
          padding: 8px 12px;
          margin: 2px 8px;
          border-radius: 4px;
          font-size: 14px;
          font-weight: 500;
          color: hsl(var(--muted-foreground));
          background: transparent;
          border: none;
          cursor: pointer;
          transition: all 0.1s ease;
          text-align: left;
        }
        .settings-nav-item:hover {
          background: hsl(var(--secondary) / 0.8);
          color: hsl(var(--foreground));
        }
        .settings-nav-item.active {
          background: hsl(var(--secondary));
          color: hsl(var(--foreground));
        }
        .settings-category {
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.02em;
          text-transform: uppercase;
          color: hsl(var(--muted-foreground));
          padding: 16px 20px 8px;
        }
        .settings-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 16px 0;
          border-bottom: 1px solid hsl(var(--border) / 0.5);
        }
        .settings-row:last-child {
          border-bottom: none;
        }
        .settings-label {
          font-size: 15px;
          font-weight: 500;
          color: hsl(var(--foreground));
          margin-bottom: 4px;
        }
        .settings-description {
          font-size: 13px;
          color: hsl(var(--muted-foreground));
          line-height: 1.4;
        }
        .settings-section-title {
          font-size: 20px;
          font-weight: 600;
          color: hsl(var(--foreground));
          margin-bottom: 20px;
        }
        .settings-group {
          margin-bottom: 32px;
        }
        .settings-group-title {
          font-size: 12px;
          font-weight: 600;
          letter-spacing: 0.02em;
          text-transform: uppercase;
          color: hsl(var(--muted-foreground));
          margin-bottom: 12px;
        }
        .avatar-container {
          position: relative;
          width: 80px;
          height: 80px;
          border-radius: 50%;
          overflow: hidden;
          cursor: pointer;
          background: linear-gradient(135deg, #5865F2 0%, #4752C4 100%);
        }
        .avatar-container:hover .avatar-overlay {
          opacity: 1;
        }
        .avatar-overlay {
          position: absolute;
          inset: 0;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          background: rgba(0, 0, 0, 0.6);
          opacity: 0;
          transition: opacity 0.2s ease;
        }
        .avatar-image {
          width: 100%;
          height: 100%;
          object-fit: cover;
        }
        .avatar-placeholder {
          width: 100%;
          height: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 32px;
          font-weight: 600;
          color: white;
        }
        .account-card {
          background: hsl(var(--secondary) / 0.5);
          border-radius: 8px;
          padding: 20px;
          margin-bottom: 24px;
        }
        .theme-option {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 16px;
          border-radius: 8px;
          border: 2px solid transparent;
          cursor: pointer;
          transition: all 0.2s ease;
          background: hsl(var(--secondary) / 0.3);
          min-width: 80px;
        }
        .theme-option:hover {
          background: hsl(var(--secondary) / 0.6);
        }
        .theme-option.active {
          border-color: #5865F2;
          background: hsl(var(--secondary) / 0.8);
        }
        .theme-icon {
          width: 40px;
          height: 40px;
          margin-bottom: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .custom-select {
          width: 100%;
          padding: 10px 12px;
          border-radius: 4px;
          border: 1px solid hsl(var(--border));
          background: hsl(var(--background));
          color: hsl(var(--foreground));
          font-size: 14px;
          cursor: pointer;
          outline: none;
          transition: border-color 0.2s ease;
        }
        .custom-select:hover {
          border-color: rgba(88, 101, 242, 0.5);
        }
        .custom-select:focus {
          border-color: #5865F2;
        }
        .blocked-user-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 12px 16px;
          background: hsl(var(--secondary) / 0.3);
          border-radius: 6px;
          margin-bottom: 8px;
        }
        .danger-zone {
          background: hsl(0 70% 50% / 0.1);
          border: 1px solid hsl(0 70% 50% / 0.3);
          border-radius: 8px;
          padding: 20px;
        }
      `}</style>

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
            <div>
              <h2 className="settings-section-title">My Account</h2>

              <div className="account-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                  <div
                    className="avatar-container"
                    onClick={() => avatarInputRef.current?.click()}
                  >
                    {avatarUrl ? (
                      <img src={avatarUrl} alt="Avatar" className="avatar-image" />
                    ) : (
                      <div className="avatar-placeholder animate-pulse" style={{ backgroundColor: 'var(--color-secondary)' }} />
                    )}
                    <div className="avatar-overlay">
                      <Camera size={20} color="white" />
                      <span style={{ fontSize: '10px', color: 'white', marginTop: '4px' }}>CHANGE</span>
                    </div>
                  </div>
                  <input
                    ref={avatarInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleAvatarChange}
                    style={{ display: 'none' }}
                  />
                  <div>
                    <div style={{ fontSize: '20px', fontWeight: 600, color: 'hsl(var(--foreground))' }}>
                      {displayUsername}
                    </div>
                    {currentUsername && currentUsername !== displayUsername && (
                      <div style={{ fontSize: '13px', color: 'hsl(var(--muted-foreground))', marginTop: '4px' }}>
                        {truncatedHash}
                      </div>
                    )}
                  </div>
                </div>

                {avatarUrl && !profilePictureSystem.isOwnAvatarDefault() && (
                  <button
                    onClick={handleRemoveAvatar}
                    style={{
                      marginTop: '16px',
                      padding: '8px 16px',
                      fontSize: '13px',
                      color: 'hsl(var(--muted-foreground))',
                      background: 'transparent',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '6px'
                    }}
                  >
                    <X size={14} />
                    Remove Avatar
                  </button>
                )}
              </div>

              <div className="settings-group">
                <div className="settings-group-title">Profile Picture</div>
                <div className="settings-row">
                  <div>
                    <div className="settings-label">Share with Others</div>
                    <div className="settings-description">
                      Allow other users to see your profile picture. When disabled, they'll see a default avatar.
                    </div>
                  </div>
                  <AnimatedSwitch
                    checked={shareWithOthers}
                    onCheckedChange={handleShareToggle}
                  />
                </div>
              </div>

              <div className="settings-group">
                <div className="settings-group-title">Security</div>
                <div style={{ background: 'hsl(var(--secondary) / 0.3)', borderRadius: '8px', padding: '16px' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                    <Shield size={24} style={{ color: '#5865F2', flexShrink: 0, marginTop: '2px' }} />
                    <div>
                      <div className="settings-label">End-to-End Encrypted</div>
                      <div className="settings-description">
                        Your messages are guaranteed protected with hybrid post-quantum cryptography.
                        Only you and your recipients can ever read them.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'appearance' && (
            <div>
              <h2 className="settings-section-title">Appearance</h2>

              <div className="settings-group">
                <div className="settings-group-title">Theme</div>
                <div className="settings-description" style={{ marginBottom: '16px' }}>
                  Choose how the app looks to you. Select a theme or sync with your system settings.
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                  <button
                    className={`theme-option ${theme === 'light' ? 'active' : ''}`}
                    onClick={() => setTheme('light')}
                  >
                    <div className="theme-icon">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="5" />
                        <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
                      </svg>
                    </div>
                    <span style={{ fontSize: '13px', fontWeight: 500 }}>Light</span>
                  </button>
                  <button
                    className={`theme-option ${theme === 'dark' ? 'active' : ''}`}
                    onClick={() => setTheme('dark')}
                  >
                    <div className="theme-icon">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                      </svg>
                    </div>
                    <span style={{ fontSize: '13px', fontWeight: 500 }}>Dark</span>
                  </button>
                  <button
                    className={`theme-option ${theme === 'system' ? 'active' : ''}`}
                    onClick={() => setTheme('system')}
                  >
                    <div className="theme-icon">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                        <path d="M8 21h8M12 17v4" />
                      </svg>
                    </div>
                    <span style={{ fontSize: '13px', fontWeight: 500 }}>System</span>
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'notifications' && (
            <div>
              <h2 className="settings-section-title">Notifications</h2>

              <div className="settings-group">
                <div className="settings-row">
                  <div>
                    <div className="settings-label">Desktop Notifications</div>
                    <div className="settings-description">
                      Show a notification popup when you receive a new message
                    </div>
                  </div>
                  <AnimatedSwitch
                    checked={notifications.desktop}
                    onCheckedChange={(checked) => {
                      setNotifications(prev => ({ ...prev, desktop: checked }));
                      saveSettings({ notifications: { ...notifications, desktop: checked } });
                      (window as any).edgeApi?.setNotificationsEnabled?.(checked).catch(() => { });
                    }}
                  />
                </div>

                <div className="settings-row">
                  <div>
                    <div className="settings-label">Sound Notifications</div>
                    <div className="settings-description">
                      Play a sound when you receive a new message
                    </div>
                  </div>
                  <AnimatedSwitch
                    checked={notifications.sound}
                    onCheckedChange={(checked) => {
                      setNotifications(prev => ({ ...prev, sound: checked }));
                      saveSettings({ notifications: { ...notifications, sound: checked } });
                    }}
                  />
                </div>
              </div>
            </div>
          )}

          {activeSection === 'audio' && (
            <div>
              <h2 className="settings-section-title">Audio</h2>

              <div className="settings-group">
                <div className="settings-group-title">Voice Processing</div>

                <div className="settings-row">
                  <div>
                    <div className="settings-label">Noise Suppression</div>
                    <div className="settings-description">
                      Filter out background noise during calls for clearer audio
                    </div>
                  </div>
                  <AnimatedSwitch
                    checked={audioSettings.noiseSuppression}
                    onCheckedChange={(checked) => {
                      setAudioSettings(prev => ({ ...prev, noiseSuppression: checked }));
                      saveSettings({ audioSettings: { ...audioSettings, noiseSuppression: checked } });
                    }}
                  />
                </div>

                <div className="settings-row">
                  <div>
                    <div className="settings-label">Echo Cancellation</div>
                    <div className="settings-description">
                      Reduce echo and feedback during voice calls
                    </div>
                  </div>
                  <AnimatedSwitch
                    checked={audioSettings.echoCancellation}
                    onCheckedChange={(checked) => {
                      setAudioSettings(prev => ({ ...prev, echoCancellation: checked }));
                      saveSettings({ audioSettings: { ...audioSettings, echoCancellation: checked } });
                    }}
                  />
                </div>
              </div>

              <div className="settings-group">
                <div className="settings-group-title">Device Selection</div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                  <div>
                    <div className="settings-label">Microphone</div>
                    <div className="settings-description">Default microphone for calls and voice messages</div>
                  </div>
                  <select
                    value={preferredMicId}
                    onChange={(e) => {
                      setPreferredMicId(e.target.value);
                      saveSettings({ preferredMicId: e.target.value });
                    }}
                    className="settings-select"
                  >
                    <option value="">System Default</option>
                    {micDevices.map(d => (
                      <option key={d.deviceId} value={d.deviceId}>
                        {d.label || `Microphone ${d.deviceId.slice(0, 8)}`}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                  <div>
                    <div className="settings-label">Speaker</div>
                    <div className="settings-description">Default speaker for call audio output</div>
                  </div>
                  <select
                    value={preferredSpeakerId}
                    onChange={(e) => {
                      setPreferredSpeakerId(e.target.value);
                      saveSettings({ preferredSpeakerId: e.target.value });
                    }}
                    className="settings-select"
                  >
                    <option value="">System Default</option>
                    {speakerDevices.map(d => (
                      <option key={d.deviceId} value={d.deviceId}>
                        {d.label || `Speaker ${d.deviceId.slice(0, 8)}`}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                  <div>
                    <div className="settings-label">Camera</div>
                    <div className="settings-description">Default camera for video calls</div>
                  </div>
                  <select
                    value={preferredCameraId}
                    onChange={(e) => {
                      setPreferredCameraId(e.target.value);
                      saveSettings({ preferredCameraId: e.target.value });
                    }}
                    className="settings-select"
                  >
                    <option value="">System Default</option>
                    {cameraDevices.map(d => (
                      <option key={d.deviceId} value={d.deviceId}>
                        {d.label || `Camera ${d.deviceId.slice(0, 8)}`}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'voice-video' && screenSettings && (
            <div>
              <h2 className="settings-section-title">Voice & Video</h2>

              <div className="settings-group">
                <div className="settings-group-title">Screen Sharing</div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                  <div>
                    <div className="settings-label">Resolution</div>
                    <div className="settings-description">
                      {screenSettings.resolution.isNative
                        ? 'Uses your display\'s native resolution'
                        : `Fixed resolution: ${screenSettings.resolution.width} × ${screenSettings.resolution.height}`}
                    </div>
                  </div>
                  <select
                    className="custom-select"
                    value={screenSettings.resolution.id}
                    onChange={(e) => {
                      const resolution = SCREEN_SHARING_RESOLUTIONS.find(r => r.id === e.target.value);
                      if (resolution) screenSharingSettings.setResolution(resolution);
                    }}
                  >
                    {SCREEN_SHARING_RESOLUTIONS.map((res) => (
                      <option key={res.id} value={res.id}>{res.name}</option>
                    ))}
                  </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                  <div>
                    <div className="settings-label">Frame Rate</div>
                    <div className="settings-description">
                      Higher frame rates provide smoother video but use more bandwidth
                    </div>
                  </div>
                  <select
                    className="custom-select"
                    value={screenSettings.frameRate.toString()}
                    onChange={(e) => {
                      const frameRate = Number.parseInt(e.target.value, 10);
                      if (SCREEN_SHARING_FRAMERATES.includes(frameRate as any)) {
                        screenSharingSettings.setFrameRate(frameRate);
                      }
                    }}
                  >
                    {SCREEN_SHARING_FRAMERATES.map((fps) => (
                      <option key={fps} value={fps.toString()}>{fps} FPS</option>
                    ))}
                  </select>
                </div>

                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                  <div>
                    <div className="settings-label">Quality</div>
                    <div className="settings-description">
                      Balance between video quality and bandwidth usage
                    </div>
                  </div>
                  <select
                    className="custom-select"
                    value={screenSettings.quality}
                    onChange={(e) => {
                      const quality = e.target.value as 'low' | 'medium' | 'high';
                      screenSharingSettings.setQuality(quality);
                    }}
                  >
                    {QUALITY_OPTIONS.map((q) => (
                      <option key={q} value={q}>{QUALITY_LABELS[q]}</option>
                    ))}
                  </select>
                </div>

                <div style={{ paddingTop: '16px' }}>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => screenSharingSettings.resetToDefaults()}
                  >
                    Reset to Defaults
                  </Button>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'downloads' && downloadSettings && (
            <div>
              <h2 className="settings-section-title">Downloads</h2>

              <div className="settings-group">
                <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
                  <div>
                    <div className="settings-label">Download Location</div>
                    <div className="settings-description">
                      Choose where files are saved when you download them
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '12px', width: '100%' }}>
                    <input
                      type="text"
                      readOnly
                      value={downloadSettings.downloadPath || ''}
                      className="custom-select"
                      style={{ flex: 1 }}
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

                <div className="settings-row">
                  <div>
                    <div className="settings-label">Auto-save Files</div>
                    <div className="settings-description">
                      Automatically save received files to your download location
                    </div>
                  </div>
                  <AnimatedSwitch
                    checked={downloadSettings.autoSave || false}
                    onCheckedChange={handleAutoSaveToggle}
                  />
                </div>
              </div>
            </div>
          )}

          {activeSection === 'privacy' && (
            <div>
              <h2 className="settings-section-title">Privacy & Safety</h2>

              <div className="settings-group">
                <div className="settings-group-title">Blocked Users</div>
                <div className="settings-description" style={{ marginBottom: '16px' }}>
                  Users you've blocked can't send you messages or call you.
                </div>

                {blockedLoading ? (
                  <div style={{ color: 'hsl(var(--muted-foreground))', padding: '16px 0' }}>
                    Loading...
                  </div>
                ) : blockedUsers.length === 0 ? (
                  <div style={{
                    color: 'hsl(var(--muted-foreground))',
                    padding: '24px',
                    textAlign: 'center',
                    background: 'hsl(var(--secondary) / 0.3)',
                    borderRadius: '8px'
                  }}>
                    <div style={{ marginBottom: '4px' }}>No blocked users</div>
                    <div style={{ fontSize: '13px' }}>Users you block will appear here</div>
                  </div>
                ) : (
                  <div>
                    {blockedUsers.map((user) => {
                      const dn = displayMap[user.username] || user.username;
                      return (
                        <div key={user.username} className="blocked-user-item">
                          <div>
                            <div style={{ fontWeight: 500, color: 'hsl(var(--foreground))' }}>{dn}</div>
                            <div style={{ fontSize: '12px', color: 'hsl(var(--muted-foreground))' }}>
                              Blocked {format(new Date(user.blockedAt), "MMM d, yyyy")}
                            </div>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleUnblockUser(user.username)}
                            disabled={blockedLoading}
                          >
                            Unblock
                          </Button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeSection === 'data' && (
            <div>
              <h2 className="settings-section-title">Data Management</h2>

              <div className="settings-group">
                <div className="danger-zone">
                  <div className="settings-label" style={{ color: 'hsl(0 70% 50%)' }}>
                    Clear All Data
                  </div>
                  <div className="settings-description" style={{ marginBottom: '16px' }}>
                    This will permanently delete all your messages, conversations, and settings.
                    You will be logged out and this action cannot be undone.
                  </div>
                  <Button
                    variant="destructive"
                    onClick={handleClearData}
                    disabled={isClearingData}
                  >
                    {isClearingData ? 'Clearing...' : 'Clear All Data'}
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
});
