import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from 'next-themes';
import { format } from 'date-fns';
import { toast } from 'sonner';
import { syncEncryptedStorage, encryptedStorage } from '../../lib/database/encrypted-storage';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { screenSharingSettings } from '../../lib/database/screen-sharing-settings';
import { blockingSystem, type BlockedUser } from '../../lib/blocking/blocking-system';
import { file, notifications as tauriNotifications, database, tray } from '../../lib/tauri-bindings';
import {
  hasPrototypePollutionKeys,
  isPlainObject,
  isValidUsername,
  sanitizeEventText,
  sanitizeEventUsername,
} from '../../lib/sanitizers';
import { EventType } from '../../lib/types/event-types';
import {
  SCREEN_SHARING_FRAMERATES,
  SCREEN_SHARING_RESOLUTIONS,
  type ScreenSharingSettings,
} from '../../lib/types/screen-sharing-types';
import {
  DEFAULT_EVENT_RATE_MAX,
  DEFAULT_EVENT_RATE_WINDOW_MS,
  MAX_EVENT_TYPE_LENGTH,
  MAX_EVENT_USERNAME_LENGTH,
  MAX_PROFILE_IMAGE_SIZE,
  QUALITY_LABELS,
  QUALITY_OPTIONS,
  type QualityOption,
} from '../../lib/constants';
import { useDisplayUsername } from '../../hooks/database/useDisplayUsername';
import { AppSettingsStyles } from './sections/AppSettingsStyles';

interface AppSettingsProps {
  passphraseRef?: React.RefObject<string>;
  kyberSecretRef?: React.RefObject<Uint8Array | null>;
  currentUsername?: string;
  currentDisplayName?: string;
  onLogout?: () => void | Promise<void>;
}

interface NotificationSettings {
  desktop: boolean;
  sound: boolean;
}

interface AudioSettings {
  noiseSuppression: boolean;
  echoCancellation: boolean;
}

type SectionId = 'account' | 'general' | 'audio' | 'voice-video' | 'privacy';

const sectionGroups: Array<{
  category: string;
  items: Array<{ id: SectionId; label: string; icon: string }>;
}> = [
  {
    category: 'User',
    items: [{ id: 'account', label: 'My Account', icon: 'icon-user' }],
  },
  {
    category: 'App',
    items: [{ id: 'general', label: 'General', icon: 'icon-settings' }],
  },
  {
    category: 'Calling',
    items: [
      { id: 'audio', label: 'Audio', icon: 'icon-volume' },
      { id: 'voice-video', label: 'Voice & Video', icon: 'icon-monitor' },
    ],
  },
  {
    category: 'Data',
    items: [{ id: 'privacy', label: 'Privacy & Safety', icon: 'icon-shield' }],
  },
];

const visibleResolutionIds = ['native', '1080p', '720p'] as const;
const qualityButtonLabels: Record<QualityOption, string> = {
  low: 'Low',
  medium: 'Balanced',
  high: 'High',
};

function IconUse({ id, filled = false }: { id: string; filled?: boolean }) {
  return (
    <svg aria-hidden="true">
      <use href={`#${filled ? `${id}-filled` : id}`} />
    </svg>
  );
}

function SwitchButton({
  checked,
  label,
  disabled,
  onChange,
}: {
  checked: boolean;
  label: string;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <button
      className={`switch ${checked ? 'on' : ''}`}
      type="button"
      disabled={disabled}
      aria-label={`${label} ${checked ? 'enabled' : 'disabled'}`}
      onClick={() => onChange(!checked)}
    />
  );
}

const BlockedUserRow = React.memo(function BlockedUserRow({
  user,
  loading,
  onUnblock,
}: {
  user: BlockedUser;
  loading: boolean;
  onUnblock: (username: string) => void;
}) {
  const displayName = useDisplayUsername({ username: user.username });

  return (
    <div className="setting-row blocked-user-row">
      <div className="min-w-0">
        <div className="blocked-user-name" title={displayName}>{displayName}</div>
        <div className="setting-description">
          Blocked {format(new Date(user.blockedAt), "MMM d, yyyy 'at' h:mm a")}
        </div>
      </div>
      <button className="action" type="button" disabled={loading} onClick={() => onUnblock(user.username)}>
        Unblock
      </button>
    </div>
  );
});

export const AppSettings = React.memo(function AppSettings({
  passphraseRef,
  kyberSecretRef,
  currentUsername = '',
  currentDisplayName = '',
  onLogout,
}: AppSettingsProps) {
  const { theme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [activeSection, setActiveSection] = useState<SectionId>('account');
  const [downloadSettings, setDownloadSettings] = useState({ downloadPath: '', autoSave: false });
  const [isChoosingPath, setIsChoosingPath] = useState(false);
  const [isClearingData, setIsClearingData] = useState(false);
  const [isCompactingDatabase, setIsCompactingDatabase] = useState(false);
  const [notifications, setNotifications] = useState<NotificationSettings>({ desktop: true, sound: true });
  const [audioSettings, setAudioSettings] = useState<AudioSettings>({ noiseSuppression: true, echoCancellation: true });
  const [closeToTray, setCloseToTray] = useState(true);
  const [isTrayLoading, setIsTrayLoading] = useState(true);
  const [screenSettings, setScreenSettings] = useState<ScreenSharingSettings | null>(null);
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const [shareWithOthers, setShareWithOthers] = useState(false);
  const [copiedUsername, setCopiedUsername] = useState(false);
  const [micDevices, setMicDevices] = useState<MediaDeviceInfo[]>([]);
  const [speakerDevices, setSpeakerDevices] = useState<MediaDeviceInfo[]>([]);
  const [cameraDevices, setCameraDevices] = useState<MediaDeviceInfo[]>([]);
  const [preferredMicId, setPreferredMicId] = useState('');
  const [preferredSpeakerId, setPreferredSpeakerId] = useState('');
  const [preferredCameraId, setPreferredCameraId] = useState('');
  const [blockedUsers, setBlockedUsers] = useState<BlockedUser[]>([]);
  const [blockedUsersLoading, setBlockedUsersLoading] = useState(false);
  const [blockedUsersError, setBlockedUsersError] = useState<string | null>(null);
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const profilePictureEventRateRef = useRef({ windowStart: Date.now(), count: 0 });
  const blockStatusEventRateRef = useRef({ windowStart: Date.now(), count: 0 });

  const activeTheme = theme === 'system' ? resolvedTheme : theme;
  const themeClass = activeTheme === 'light' ? 'light' : 'dark';
  const displayUsername = currentDisplayName || currentUsername || 'User';
  const copyUsername = currentDisplayName || currentUsername || '';
  const blockingKeyAvailable = Boolean(passphraseRef?.current || kyberSecretRef?.current);

  const visibleResolutions = useMemo(
    () => visibleResolutionIds
      .map((id) => SCREEN_SHARING_RESOLUTIONS.find((resolution) => resolution.id === id))
      .filter((resolution): resolution is NonNullable<typeof resolution> => Boolean(resolution)),
    []
  );

  const saveSettings = useCallback((updates: Partial<{
    notifications: NotificationSettings;
    audioSettings: AudioSettings;
    preferredMicId: string;
    preferredSpeakerId: string;
    preferredCameraId: string;
  }>) => {
    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem('app_settings_v1', JSON.stringify({ ...parsed, ...updates }));
    } catch { }
  }, []);

  const loadBlockedUsers = useCallback(async () => {
    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;

    if (!passphrase && !kyberSecret) {
      setBlockedUsersError('Please log in.');
      setBlockedUsers([]);
      return;
    }

    setBlockedUsersLoading(true);
    setBlockedUsersError(null);

    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      const users = await blockingSystem.getBlockedUsers(key);
      setBlockedUsers(users);
    } catch (error) {
      console.error('Error loading blocked users:', error);
      setBlockedUsersError('Failed to load blocked users.');
      setBlockedUsers([]);
    } finally {
      setBlockedUsersLoading(false);
    }
  }, [passphraseRef, kyberSecretRef]);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    const initDownloadSettings = async () => {
      try {
        const settings = await file.getDownloadSettings();
        setDownloadSettings({
          downloadPath: settings.download_path || '',
          autoSave: !settings.ask_where_to_save,
        });
      } catch { }
    };

    const initTraySettings = async () => {
      try {
        setCloseToTray(await tray.getCloseToTray());
      } catch { }
      setIsTrayLoading(false);
    };

    const loadDevices = async () => {
      try {
        const devices = await navigator.mediaDevices?.enumerateDevices?.() ?? [];
        setMicDevices(devices.filter((device) => device.kind === 'audioinput'));
        setSpeakerDevices(devices.filter((device) => device.kind === 'audiooutput'));
        setCameraDevices(devices.filter((device) => device.kind === 'videoinput'));
      } catch (error) {
        console.error('[AppSettings] Failed to enumerate devices:', error);
      }
    };

    const initProfilePicture = async () => {
      try {
        await profilePictureSystem.initialize();
        setAvatarUrl(profilePictureSystem.getOwnAvatar());
        setShareWithOthers(profilePictureSystem.getShareWithOthers());
      } catch (error) {
        console.error('[AppSettings] Failed to init profile picture:', error);
      }
    };

    initDownloadSettings();
    initTraySettings();
    loadDevices();
    initProfilePicture();

    try {
      const stored = syncEncryptedStorage.getItem('app_settings_v1');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.notifications) {
          setNotifications(parsed.notifications);
          tauriNotifications.setEnabled(parsed.notifications.desktop !== false).catch(() => { });
        }
        if (parsed.audioSettings) setAudioSettings(parsed.audioSettings);
        if (parsed.preferredMicId) setPreferredMicId(parsed.preferredMicId);
        if (parsed.preferredSpeakerId) setPreferredSpeakerId(parsed.preferredSpeakerId);
        if (parsed.preferredCameraId) setPreferredCameraId(parsed.preferredCameraId);
      }
    } catch { }
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

  useEffect(() => {
    const handleAvatarUpdate = (event: Event) => {
      try {
        const now = Date.now();
        const bucket = profilePictureEventRateRef.current;
        if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > DEFAULT_EVENT_RATE_MAX) return;

        if (event.type === EventType.PROFILE_PICTURE_UPDATED && event instanceof CustomEvent) {
          const detail = event.detail;
          if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
          const type = sanitizeEventText((detail as any).type, MAX_EVENT_TYPE_LENGTH);
          if (type && type !== 'own') return;
        }

        setAvatarUrl(profilePictureSystem.getOwnAvatar());
        setShareWithOthers(profilePictureSystem.getShareWithOthers());
      } catch { }
    };

    window.addEventListener(EventType.PROFILE_PICTURE_UPDATED, handleAvatarUpdate as EventListener);
    window.addEventListener(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED, handleAvatarUpdate as EventListener);
    window.addEventListener(EventType.PROFILE_SETTINGS_UPDATED, handleAvatarUpdate as EventListener);

    return () => {
      window.removeEventListener(EventType.PROFILE_PICTURE_UPDATED, handleAvatarUpdate as EventListener);
      window.removeEventListener(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED, handleAvatarUpdate as EventListener);
      window.removeEventListener(EventType.PROFILE_SETTINGS_UPDATED, handleAvatarUpdate as EventListener);
    };
  }, []);

  useEffect(() => {
    if (blockingKeyAvailable) {
      loadBlockedUsers();
    }
  }, [blockingKeyAvailable, loadBlockedUsers]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && blockingKeyAvailable) {
        loadBlockedUsers();
      }
    };

    const handleBlockStatusChange = (event: Event) => {
      try {
        const now = Date.now();
        const bucket = blockStatusEventRateRef.current;
        if (now - bucket.windowStart > DEFAULT_EVENT_RATE_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > DEFAULT_EVENT_RATE_MAX) return;

        if (!(event instanceof CustomEvent)) return;
        const detail = event.detail;
        if (!isPlainObject(detail) || hasPrototypePollutionKeys(detail)) return;
        if (!sanitizeEventUsername((detail as any).username, MAX_EVENT_USERNAME_LENGTH)) return;

        if (blockingKeyAvailable) {
          loadBlockedUsers();
        }
      } catch { }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange as EventListener);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange as EventListener);
    };
  }, [blockingKeyAvailable, loadBlockedUsers]);

  const handleCopyUsername = async () => {
    if (!copyUsername) return;

    try {
      await navigator.clipboard?.writeText(copyUsername);
    } catch {
      const input = document.createElement('input');
      input.value = copyUsername;
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      input.remove();
    }

    setCopiedUsername(true);
    window.setTimeout(() => setCopiedUsername(false), 900);
  };

  const handleAvatarChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (!selectedFile) return;
    event.target.value = '';

    if (selectedFile.size > MAX_PROFILE_IMAGE_SIZE) {
      toast.error(`Image too large (max ${MAX_PROFILE_IMAGE_SIZE / 1024 / 1024}MB)`);
      return;
    }

    const reader = new FileReader();
    reader.onloadend = async () => {
      try {
        const uploadResult = await profilePictureSystem.setOwnAvatar(reader.result as string);
        if (uploadResult.success) {
          setAvatarUrl(profilePictureSystem.getOwnAvatar());
          toast.success('Profile picture updated');
        } else {
          toast.error(uploadResult.error || 'Failed to upload avatar');
        }
      } catch {
        toast.error('Failed to process image');
      }
    };
    reader.onerror = () => toast.error('Failed to read image file');
    reader.readAsDataURL(selectedFile);
  };

  const handleShareToggle = async (share: boolean) => {
    try {
      await profilePictureSystem.setShareWithOthers(share);
      setShareWithOthers(share);
    } catch {
      toast.error('Failed to update profile sharing');
    }
  };

  const handleCloseToTrayChange = async (enabled: boolean) => {
    const previous = closeToTray;
    setCloseToTray(enabled);
    try {
      await tray.setCloseToTray(enabled);
    } catch {
      setCloseToTray(previous);
      toast.error('Failed to update tray setting');
    }
  };

  const handleNotificationToggle = (key: keyof NotificationSettings, checked: boolean) => {
    const updated = { ...notifications, [key]: checked };
    setNotifications(updated);
    saveSettings({ notifications: updated });
    if (key === 'desktop') {
      tauriNotifications.setEnabled(checked).catch(() => { });
    }
  };

  const handleAudioToggle = (key: keyof AudioSettings, checked: boolean) => {
    const updated = { ...audioSettings, [key]: checked };
    setAudioSettings(updated);
    saveSettings({ audioSettings: updated });
  };

  const handleChooseDownloadPath = async () => {
    if (isChoosingPath) return;
    setIsChoosingPath(true);
    try {
      const newPath = await file.chooseDownloadPath();
      if (newPath) {
        const ok = await file.setDownloadPath(newPath);
        if (ok) {
          setDownloadSettings((prev) => ({ ...prev, downloadPath: newPath }));
          toast.success('Download path updated');
        } else {
          toast.error('Failed to update download path');
        }
      }
    } catch {
      toast.error('Failed to change download path');
    } finally {
      setIsChoosingPath(false);
    }
  };

  const handleDevicePreference = (
    key: 'preferredMicId' | 'preferredSpeakerId' | 'preferredCameraId',
    value: string
  ) => {
    if (key === 'preferredMicId') setPreferredMicId(value);
    if (key === 'preferredSpeakerId') setPreferredSpeakerId(value);
    if (key === 'preferredCameraId') setPreferredCameraId(value);
    saveSettings({ [key]: value });
  };

  const handleResolutionChange = (resolutionId: string) => {
    const resolution = SCREEN_SHARING_RESOLUTIONS.find((item) => item.id === resolutionId);
    if (!resolution) return;
    screenSharingSettings.setResolution(resolution).catch(() => toast.error('Failed to update resolution'));
  };

  const handleFrameRateChange = (frameRate: number) => {
    screenSharingSettings.setFrameRate(frameRate).catch(() => toast.error('Failed to update frame rate'));
  };

  const handleQualityChange = (quality: QualityOption) => {
    screenSharingSettings.setQuality(quality).catch(() => toast.error('Failed to update quality'));
  };

  const handleCompactDatabase = async () => {
    if (isCompactingDatabase) return;
    setIsCompactingDatabase(true);
    try {
      await database.compact();
      toast.success('Database compacted successfully');
    } catch (error) {
      toast.error('Failed to compact database');
      console.error(error);
    } finally {
      setIsCompactingDatabase(false);
    }
  };

  const handleClearData = async () => {
    if (isClearingData) return;
    if (!confirm('Clear all local data? This will log you out and remove all stored messages.')) return;

    setIsClearingData(true);
    try {
      await encryptedStorage.setItem('app_settings_v1', '');
      window.location.reload();
    } catch {
      toast.error('Failed to clear data');
      setIsClearingData(false);
    }
  };

  const handleBlockUser = async () => {
    const username = window.prompt('Username to block')?.trim() || '';
    if (!username) return;

    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;
    if (!passphrase && !kyberSecret) {
      setBlockedUsersError('Please log in.');
      return;
    }

    if (!isValidUsername(username)) {
      setBlockedUsersError('Invalid username format');
      return;
    }

    setBlockedUsersLoading(true);
    setBlockedUsersError(null);
    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      await blockingSystem.blockUser(username, key);
      await loadBlockedUsers();
    } catch (error) {
      console.error('Error blocking user:', error);
      setBlockedUsersError('Failed to block user. Please try again.');
    } finally {
      setBlockedUsersLoading(false);
    }
  };

  const handleUnblockUser = async (username: string) => {
    const passphrase = passphraseRef?.current;
    const kyberSecret = kyberSecretRef?.current || null;
    if (!passphrase && !kyberSecret) {
      setBlockedUsersError('Please log in.');
      return;
    }

    if (!confirm(`Unblock ${username}?`)) return;

    setBlockedUsersLoading(true);
    setBlockedUsersError(null);
    try {
      const key = passphrase ? passphrase : { kyberSecret: kyberSecret! } as any;
      await blockingSystem.unblockUser(username, key);
      await loadBlockedUsers();
    } catch (error) {
      console.error('Error unblocking user:', error);
      setBlockedUsersError('Failed to unblock user. Please try again.');
    } finally {
      setBlockedUsersLoading(false);
    }
  };

  if (!mounted) return null;

  return (
    <>
      <AppSettingsStyles />
      <div className={`qor-settings-host ${themeClass}`}>
        <svg className="hidden-symbols" aria-hidden="true">
          <symbol id="icon-user" viewBox="0 0 24 24"><path d="M20 21a8 8 0 0 0-16 0M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></symbol>
          <symbol id="icon-user-filled" viewBox="0 0 24 24"><path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM4 22a8 8 0 0 1 16 0z" fill="currentColor" /></symbol>
          <symbol id="icon-settings" viewBox="0 0 24 24"><path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z" fill="none" stroke="currentColor" strokeWidth="1.8" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2a2 2 0 1 1-4 0V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1A2 2 0 1 1 4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H2.8a2 2 0 1 1 0-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7A2 2 0 1 1 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2a2 2 0 1 1 4 0V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1A2 2 0 1 1 19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2a2 2 0 1 1 0 4H21a1.7 1.7 0 0 0-1.6 1z" fill="none" stroke="currentColor" strokeWidth="1.4" /></symbol>
          <symbol id="icon-settings-filled" viewBox="0 0 24 24"><path fillRule="evenodd" clipRule="evenodd" d="M10.4 2h3.2a2 2 0 0 1 2 2v.24c0 .61.67.99 1.19.69l.21-.12a2 2 0 0 1 2.73.73l1.6 2.77a2 2 0 0 1-.73 2.73l-.21.12a.79.79 0 0 0 0 1.37l.21.12a2 2 0 0 1 .73 2.73l-1.6 2.77a2 2 0 0 1-2.73.73l-.21-.12a.79.79 0 0 0-1.19.69V20a2 2 0 0 1-2 2h-3.2a2 2 0 0 1-2-2v-.24a.79.79 0 0 0-1.19-.69l-.21.12a2 2 0 0 1-2.73-.73l-1.6-2.77a2 2 0 0 1 .73-2.73l.21-.12a.79.79 0 0 0 0-1.37l-.21-.12a2 2 0 0 1-.73-2.73l1.6-2.77A2 2 0 0 1 7 5.12l.21.12a.79.79 0 0 0 1.19-.69V4a2 2 0 0 1 2-2ZM12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z" fill="currentColor" /></symbol>
          <symbol id="icon-volume" viewBox="0 0 24 24"><path d="M11 5 6 9H2v6h4l5 4zM15 9a4 4 0 0 1 0 6M18 6a8 8 0 0 1 0 12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></symbol>
          <symbol id="icon-volume-filled" viewBox="0 0 24 24"><path d="M11.6 4.3a1 1 0 0 1 .4.8v13.8a1 1 0 0 1-1.64.77L5.65 15.8H3a1 1 0 0 1-1-1V9.2a1 1 0 0 1 1-1h2.65l4.71-3.87a1 1 0 0 1 1.24-.03z" fill="currentColor" /><path d="M15 9a4 4 0 0 1 0 6M18 6a8 8 0 0 1 0 12" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" /></symbol>
          <symbol id="icon-monitor" viewBox="0 0 24 24"><path d="M3 5h18v12H3zM8 21h8M12 17v4" fill="none" stroke="currentColor" strokeWidth="1.8" /></symbol>
          <symbol id="icon-monitor-filled" viewBox="0 0 24 24"><path d="M4 5h16a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1zM11 17h2v3h3a1 1 0 1 1 0 2H8a1 1 0 1 1 0-2h3z" fill="currentColor" /></symbol>
          <symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4 3 8 7 10 4-2 7-6 7-10V6z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" /></symbol>
          <symbol id="icon-shield-filled" viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4 3 8 7 10 4-2 7-6 7-10V6z" fill="currentColor" /></symbol>
          <symbol id="icon-copy" viewBox="0 0 24 24"><path d="M8 8h10v12H8zM6 16H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" /></symbol>
          <symbol id="icon-camera" viewBox="0 0 24 24"><path d="M9 5 7.5 7H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-2.5L15 5z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" /><circle cx="12" cy="13" r="3.5" fill="none" stroke="currentColor" strokeWidth="1.8" /></symbol>
        </svg>

        <main className="settings-screen">
          <aside className="settings-nav" aria-label="Settings sections">
            <h1 className="settings-brand"><span>Qor Chat</span><strong>Settings</strong></h1>

            {sectionGroups.map((group) => (
              <div className="nav-block" key={group.category}>
                <div className="nav-label">{group.category}</div>
                {group.items.map((item) => (
                  <button
                    key={item.id}
                    className={`settings-tab ${activeSection === item.id ? 'active' : ''}`}
                    data-settings-section={item.id}
                    type="button"
                    onClick={() => setActiveSection(item.id)}
                  >
                    <IconUse id={item.icon} filled={activeSection === item.id} />
                    <span>{item.label}</span>
                  </button>
                ))}
              </div>
            ))}
          </aside>

          <section className="settings-content">
            <section className={`pane account-pane ${activeSection === 'account' ? 'active' : ''}`} data-settings-pane="account">
              <header className="pane-head">
                <div>
                  <span className="pane-kicker">User</span>
                  <h2 className="pane-title">My Account</h2>
                </div>
              </header>

              <div className="settings-section">
                <div className="account-editor">
                  <div className="account-preview">
                    <button
                      className="avatar-preview-button"
                      type="button"
                      aria-label="Change profile picture"
                      onClick={() => avatarInputRef.current?.click()}
                    >
                      <div className={`avatar-preview ${avatarUrl ? 'has-image' : ''}`} aria-hidden="true">
                        {avatarUrl && <img src={avatarUrl} alt="" />}
                        <span className="avatar-hover-overlay">
                          <IconUse id="icon-camera" />
                        </span>
                      </div>
                    </button>
                    <input
                      ref={avatarInputRef}
                      className="avatar-upload-input"
                      type="file"
                      accept="image/*"
                      onChange={handleAvatarChange}
                    />
                    <div className="account-name-row">
                      <div className="account-username">{displayUsername}</div>
                      <button
                        className={`copy-username ${copiedUsername ? 'copied' : ''}`}
                        type="button"
                        aria-label={copiedUsername ? 'Username copied' : 'Copy username'}
                        data-copy-username={copyUsername}
                        onClick={handleCopyUsername}
                      >
                        <IconUse id="icon-copy" />
                      </button>
                    </div>
                  </div>

                  <div className="account-share-row">
                    <div>
                      <div className="setting-label">Share with Others</div>
                      <div className="setting-description">Allow other users to see your profile picture. When disabled, they see a default avatar.</div>
                    </div>
                    <SwitchButton checked={shareWithOthers} label="Share with Others" onChange={handleShareToggle} />
                  </div>

                  <div className="account-actions">
                    <div className="account-action-row">
                      <div>
                        <div className="setting-label">Compact Database</div>
                        <div className="setting-description">Optimize storage by removing deleted data and defragmenting the local database.</div>
                      </div>
                      <button className="action" type="button" disabled={isCompactingDatabase} onClick={handleCompactDatabase}>
                        {isCompactingDatabase ? 'Compacting' : 'Compact'}
                      </button>
                    </div>
                    <div className="account-action-row account-danger-row">
                      <div>
                        <div className="setting-label" style={{ color: 'var(--danger)' }}>Clear All Data</div>
                        <div className="setting-description">Permanently delete messages, conversations, and settings. You will be logged out.</div>
                      </div>
                      <button className="danger-action" type="button" disabled={isClearingData} onClick={handleClearData}>
                        {isClearingData ? 'Clearing' : 'Clear All Data'}
                      </button>
                    </div>
                  </div>

                  <div className="logout-row">
                    <button className="danger-action" type="button" onClick={() => void onLogout?.()}>
                      Log Out
                    </button>
                  </div>
                </div>
              </div>
            </section>

            <section className={`pane ${activeSection === 'general' ? 'active' : ''}`} data-settings-pane="general">
              <header className="pane-head">
                <div>
                  <span className="pane-kicker">App</span>
                  <h2 className="pane-title">General</h2>
                  <p className="pane-subtitle">Basic app behavior.</p>
                </div>
              </header>

              <div className="settings-section">
                <h3 className="section-title">Behavior</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Minimize to system tray on close</div>
                      <div className="setting-description">Closing the window keeps Qor running in the background.</div>
                    </div>
                    <SwitchButton checked={closeToTray} disabled={isTrayLoading} label="Minimize to system tray" onChange={handleCloseToTrayChange} />
                  </div>
                </div>
              </div>

              <div className="settings-section">
                <h3 className="section-title">Notifications</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Desktop Notifications</div>
                      <div className="setting-description">Show a notification popup when a new message arrives.</div>
                    </div>
                    <SwitchButton checked={notifications.desktop} label="Desktop Notifications" onChange={(checked) => handleNotificationToggle('desktop', checked)} />
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Sound Notifications</div>
                      <div className="setting-description">Play a sound when a new message arrives.</div>
                    </div>
                    <SwitchButton checked={notifications.sound} label="Sound Notifications" onChange={(checked) => handleNotificationToggle('sound', checked)} />
                  </div>
                </div>
              </div>

              <div className="settings-section">
                <h3 className="section-title">Files</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Download Location</div>
                      <div className="setting-description">Choose where downloaded files are saved.</div>
                    </div>
                    <div className="input-line">
                      <input className="text-input" value={downloadSettings.downloadPath || '~/Downloads/Qor'} readOnly aria-label="Download location" />
                      <button className="action" type="button" disabled={isChoosingPath} onClick={handleChooseDownloadPath}>
                        {isChoosingPath ? 'Choosing' : 'Browse'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className={`pane ${activeSection === 'audio' ? 'active' : ''}`} data-settings-pane="audio">
              <header className="pane-head">
                <div>
                  <span className="pane-kicker">Calling</span>
                  <h2 className="pane-title">Audio</h2>
                  <p className="pane-subtitle">Voice processing and device selection.</p>
                </div>
              </header>

              <div className="settings-section">
                <h3 className="section-title">Voice Processing</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Noise Suppression</div>
                      <div className="setting-description">Filter background noise during calls.</div>
                    </div>
                    <SwitchButton checked={audioSettings.noiseSuppression} label="Noise Suppression" onChange={(checked) => handleAudioToggle('noiseSuppression', checked)} />
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Echo Cancellation</div>
                      <div className="setting-description">Reduce echo and feedback during voice calls.</div>
                    </div>
                    <SwitchButton checked={audioSettings.echoCancellation} label="Echo Cancellation" onChange={(checked) => handleAudioToggle('echoCancellation', checked)} />
                  </div>
                </div>
              </div>

              <div className="settings-section">
                <h3 className="section-title">Device Selection</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Microphone</div>
                      <div className="setting-description">Default microphone for calls and voice messages.</div>
                    </div>
                    <select className="select" value={preferredMicId} onChange={(event) => handleDevicePreference('preferredMicId', event.target.value)}>
                      <option value="">System Default</option>
                      {micDevices.map((device) => <option key={device.deviceId} value={device.deviceId}>{device.label || `Microphone ${device.deviceId.slice(0, 8)}`}</option>)}
                    </select>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Speaker</div>
                      <div className="setting-description">Default speaker for call audio output.</div>
                    </div>
                    <select className="select" value={preferredSpeakerId} onChange={(event) => handleDevicePreference('preferredSpeakerId', event.target.value)}>
                      <option value="">System Default</option>
                      {speakerDevices.map((device) => <option key={device.deviceId} value={device.deviceId}>{device.label || `Speaker ${device.deviceId.slice(0, 8)}`}</option>)}
                    </select>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Camera</div>
                      <div className="setting-description">Default camera for video calls.</div>
                    </div>
                    <select className="select" value={preferredCameraId} onChange={(event) => handleDevicePreference('preferredCameraId', event.target.value)}>
                      <option value="">System Default</option>
                      {cameraDevices.map((device) => <option key={device.deviceId} value={device.deviceId}>{device.label || `Camera ${device.deviceId.slice(0, 8)}`}</option>)}
                    </select>
                  </div>
                </div>
              </div>
            </section>

            <section className={`pane ${activeSection === 'voice-video' ? 'active' : ''}`} data-settings-pane="voice-video">
              <header className="pane-head">
                <div>
                  <span className="pane-kicker">Calling</span>
                  <h2 className="pane-title">Voice & Video</h2>
                  <p className="pane-subtitle">Screen sharing behavior.</p>
                </div>
              </header>

              <div className="settings-section">
                <h3 className="section-title">Screen Sharing</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Resolution</div>
                      <div className="setting-description">Choose the capture resolution for screen sharing.</div>
                    </div>
                    <div className="segmented" role="group" aria-label="Resolution">
                      {visibleResolutions.map((resolution) => (
                        <button
                          key={resolution.id}
                          className={screenSettings?.resolution.id === resolution.id ? 'active' : ''}
                          type="button"
                          onClick={() => handleResolutionChange(resolution.id)}
                        >
                          {resolution.id === 'native' ? 'Native' : resolution.id}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Frame Rate</div>
                      <div className="setting-description">Higher frame rates use more bandwidth.</div>
                    </div>
                    <div className="segmented" role="group" aria-label="Frame Rate">
                      {SCREEN_SHARING_FRAMERATES.map((fps) => (
                        <button
                          key={fps}
                          className={screenSettings?.frameRate === fps ? 'active' : ''}
                          type="button"
                          onClick={() => handleFrameRateChange(fps)}
                        >
                          {fps} FPS
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Quality</div>
                      <div className="setting-description">Balance video quality and bandwidth usage.</div>
                    </div>
                    <div className="segmented" role="group" aria-label="Quality">
                      {QUALITY_OPTIONS.map((quality) => (
                        <button
                          key={quality}
                          className={screenSettings?.quality === quality ? 'active' : ''}
                          type="button"
                          title={QUALITY_LABELS[quality]}
                          onClick={() => handleQualityChange(quality)}
                        >
                          {qualityButtonLabels[quality]}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Reset settings</div>
                      <div className="setting-description">Restore screen sharing defaults.</div>
                    </div>
                    <button className="action" type="button" onClick={() => screenSharingSettings.resetToDefaults().catch(() => toast.error('Failed to reset settings'))}>
                      Reset to Defaults
                    </button>
                  </div>
                </div>
              </div>
            </section>

            <section className={`pane ${activeSection === 'privacy' ? 'active' : ''}`} data-settings-pane="privacy">
              <header className="pane-head">
                <div>
                  <span className="pane-kicker">Data</span>
                  <h2 className="pane-title">Privacy & Safety</h2>
                  <p className="pane-subtitle">Blocked user management.</p>
                </div>
              </header>

              <div className="settings-section">
                <h3 className="section-title">Blocks</h3>
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Blocked Users</div>
                      <div className="setting-description">Manage users you have blocked.</div>
                    </div>
                    <button className="action" type="button" disabled={blockedUsersLoading || !blockingKeyAvailable} onClick={handleBlockUser}>
                      Block user
                    </button>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Blocked Users ({blockedUsers.length})</div>
                      <div className="setting-description">Refresh the blocked user list.</div>
                    </div>
                    <button className="action" type="button" disabled={blockedUsersLoading || !blockingKeyAvailable} onClick={loadBlockedUsers}>
                      {blockedUsersLoading ? 'Loading' : 'Refresh'}
                    </button>
                  </div>
                </div>

                {blockedUsersError && <div className="settings-error">{blockedUsersError}</div>}

                {blockedUsers.length === 0 ? (
                  <div className="blocked-empty">
                    <div><strong>No blocked users</strong><span>Users you block will appear here.</span></div>
                  </div>
                ) : (
                  <div className="blocked-user-list">
                    {blockedUsers.map((user) => (
                      <BlockedUserRow
                        key={user.username}
                        user={user}
                        loading={blockedUsersLoading}
                        onUnblock={handleUnblockUser}
                      />
                    ))}
                  </div>
                )}
              </div>
            </section>
          </section>
        </main>
      </div>
    </>
  );
});
