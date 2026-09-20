import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTheme } from '../../contexts/ThemeContext';
import { toast } from 'sonner';
import {
  Ban,
  Bell,
  Camera,
  Check,
  ChevronDown,
  Copy,
  Headphones,
  LoaderCircle,
  LogOut,
  RefreshCw,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  UserRound,
  X,
} from 'lucide-react';
import { encryptedStorage } from '../../lib/database/encrypted-storage';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { nativeCamera, nativeMicrophone, notifications as tauriNotifications, system, tray } from '../../lib/tauri-bindings';
import { copyTextToClipboard } from '../../lib/clipboard';
import {
  hasPrototypePollutionKeys,
  isPlainObject,
  sanitizeEventText,
  sanitizeEventUsername,
} from '../../lib/sanitizers';
import { EventType } from '../../lib/types/event-types';
import {
  DEFAULT_EVENT_RATE_MAX,
  DEFAULT_EVENT_RATE_WINDOW_MS,
  MAX_EVENT_TYPE_LENGTH,
  MAX_EVENT_USERNAME_LENGTH,
  MAX_PROFILE_IMAGE_SIZE,
} from '../../lib/constants';
import { useDisplayUsername } from '../../hooks/database/useDisplayUsername';
import { UserAvatar } from '../ui/UserAvatar';
import { installAppSettingsStyles } from './sections/AppSettingsStyles';
import {
  readAppSettings,
  updateAppSettings,
  type AppSettingsState,
} from '../../lib/ui/app-settings';
import { STORAGE_KEYS } from '../../lib/database/storage-keys';
import {
  readNavigationLayout,
  writeNavigationLayout,
  type NavigationLayout,
} from '../../lib/ui/navigation-layout';
import { SettingsSkeleton } from '../ui/ViewSkeletons';
import { SettingsIcon } from '../chat/assets/icons';
import { type BlockedUser } from '../../lib/types/blocking-types';
import { useNotificationPreferences } from '../../hooks/useNotificationPreferences';
import { setDoNotDisturb, type NotificationMutes } from '../../lib/ui/notification-preferences';

installAppSettingsStyles();

interface AppSettingsProps {
  currentUsername: string;
  currentDisplayName: string;
  onLogout: () => void | Promise<void>;
  onOpenBlockConversationChooser: () => void;
}

interface NotificationSettings {
  desktop: boolean;
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
      role="switch"
      aria-checked={checked}
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
      <div className="blocked-user-identity">
        <UserAvatar username={user.username} size="sm" />
        <div className="min-w-0">
          <div className="blocked-user-name" title={displayName}>{displayName}</div>
        </div>
      </div>
      <button className="action" type="button" disabled={loading} onClick={() => onUnblock(user.username)}>
        Unblock
      </button>
    </div>
  );
});

const UnblockConfirmModal = React.memo(function UnblockConfirmModal({
  username,
  busy,
  themeClass,
  onCancel,
  onConfirm,
}: {
  username: string;
  busy: boolean;
  themeClass: 'light' | 'dark';
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const displayName = useDisplayUsername({ username });
  const showUsername = displayName.trim().toLowerCase() !== username.trim().toLowerCase();

  return createPortal(
    <div className={`qorc-settings-host ${themeClass} qorc-unblock-overlay`} onClick={onCancel}>
      <div
        className="qorc-unblock-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="unblock-modal-title"
        aria-describedby="unblock-modal-description"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="qorc-unblock-head">
          <div className="qorc-unblock-head-copy">
            <h3 id="unblock-modal-title">Unblock user</h3>
            <p id="unblock-modal-description">They will be able to message and call you again.</p>
          </div>
          <button
            className="qorc-unblock-close"
            type="button"
            onClick={onCancel}
            disabled={busy}
            aria-label="Close unblock user dialog"
            title="Close"
          >
            <X aria-hidden="true" />
          </button>
        </div>

        <div className="qorc-unblock-target">
          <UserAvatar username={username} size="md" className="qorc-unblock-avatar" />
          <div className="qorc-unblock-user-copy">
            <span className="qorc-unblock-name" title={displayName}>{displayName}</span>
            {showUsername && <span className="qorc-unblock-username" title={username}>@{username}</span>}
          </div>
          <button className="qorc-unblock-confirm" type="button" onClick={onConfirm} disabled={busy}>
            {busy && <LoaderCircle className="qorc-unblock-spinner" aria-hidden="true" />}
            <span>{busy ? 'Unblocking…' : 'Unblock'}</span>
          </button>
        </div>
      </div>
    </div>,
    document.body,
  );
});

export const AppSettings = React.memo(function AppSettings({
  currentUsername,
  currentDisplayName,
  onLogout,
  onOpenBlockConversationChooser,
}: AppSettingsProps) {
  const { theme, resolvedTheme } = useTheme();
  const [isClearingData, setIsClearingData] = useState(false);
  const [clearArmed, setClearArmed] = useState(false);
  const clearArmTimerRef = useRef<number | null>(null);
  const [logoutArmed, setLogoutArmed] = useState(false);
  const logoutTimerRef = useRef<number | null>(null);
  const [notifications, setNotifications] = useState<NotificationSettings>({ desktop: true });
  const { doNotDisturb } = useNotificationPreferences();
  const [navigationLayout, setNavigationLayout] = useState<NavigationLayout>(readNavigationLayout);
  const [closeToTray, setCloseToTray] = useState(true);
  const [isTrayLoading, setIsTrayLoading] = useState(true);
  const [avatarUrl, setAvatarUrl] = useState<string | null>(null);
  const [copiedUsername, setCopiedUsername] = useState(false);
  const [micDevices, setMicDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [speakerDevices, setSpeakerDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [cameraDevices, setCameraDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const devicesLoadingRef = useRef(false);
  const [preferredMicId, setPreferredMicId] = useState('');
  const [preferredSpeakerId, setPreferredSpeakerId] = useState('');
  const [preferredCameraId, setPreferredCameraId] = useState('');
  const [blockedUsers, setBlockedUsers] = useState<BlockedUser[]>([]);
  const [blockedUsersLoading, setBlockedUsersLoading] = useState(false);
  const [blockedUsersError, setBlockedUsersError] = useState<string | null>(null);
  const [unblockTarget, setUnblockTarget] = useState<string | null>(null);
  const [unblocking, setUnblocking] = useState(false);
  const [initialSettingsReady, setInitialSettingsReady] = useState(false);
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const profilePictureEventRateRef = useRef({ windowStart: Date.now(), count: 0 });
  const blockStatusEventRateRef = useRef({ windowStart: Date.now(), count: 0 });

  const activeTheme = theme === 'system' ? resolvedTheme : theme;
  const themeClass = activeTheme === 'light' ? 'light' : 'dark';
  const displayUsername = currentDisplayName || currentUsername;
  const copyUsername = currentDisplayName || currentUsername;

  const saveSettings = useCallback((updates: Partial<AppSettingsState>) => {
    updateAppSettings(updates);
  }, []);

  const loadBlockedUsers = useCallback(async () => {
    setBlockedUsersLoading(true);
    setBlockedUsersError(null);

    try {
      const users = await blockingSystem.getBlockedUsers();
      setBlockedUsers(users);
    } catch (error) {
      console.error('Error loading blocked users:', error);
      setBlockedUsersError('Failed to load blocked users.');
      setBlockedUsers([]);
    } finally {
      setBlockedUsersLoading(false);
    }
  }, []);

  const refreshMediaDevices = useCallback(async () => {
    if (devicesLoadingRef.current) return;
    devicesLoadingRef.current = true;
    setDevicesLoading(true);
    try {
      if (!await system.requestMediaAccess('enumerate')) return;
      const [microphones, speakers, cameras] = await Promise.all([
        nativeMicrophone.devices(),
        nativeMicrophone.outputDevices(),
        nativeCamera.devices(),
      ]);
      if (microphones.length > 64 || speakers.length > 64 || cameras.length > 32) {
        throw new Error('Invalid media device list');
      }
      setMicDevices(microphones.map(device => ({ deviceId: device.device_id, label: device.label })));
      setSpeakerDevices(speakers.map(device => ({ deviceId: device.device_id, label: device.label })));
      setCameraDevices(cameras.map(device => ({ deviceId: device.device_id, label: device.label })));
    } catch {
      toast.error('Could not load media devices');
    } finally {
      devicesLoadingRef.current = false;
      setDevicesLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    const initTraySettings = async () => {
      setCloseToTray(await tray.getCloseToTray());
      setIsTrayLoading(false);
    };

    const initProfilePicture = async () => {
      await profilePictureSystem.initialize();
      setAvatarUrl(profilePictureSystem.getOwnAvatar());
    };

    const storedSettings = readAppSettings();
    if (storedSettings.notifications) {
      setNotifications(storedSettings.notifications);
    }
    if (storedSettings.preferredCallMicId !== undefined) setPreferredMicId(storedSettings.preferredCallMicId);
    if (storedSettings.preferredSpeakerId !== undefined) setPreferredSpeakerId(storedSettings.preferredSpeakerId);
    if (storedSettings.preferredCameraId !== undefined) setPreferredCameraId(storedSettings.preferredCameraId);

    const initialize = async () => {
      try {
        await Promise.all([
          initTraySettings(),
          initProfilePicture(),
          loadBlockedUsers(),
        ]);
        if (!cancelled) setInitialSettingsReady(true);
      } catch (error) {
        if (!cancelled) console.error('[AppSettings] Failed to initialize settings', error);
      }
    };

    void initialize();
    return () => { cancelled = true; };
  }, [loadBlockedUsers]);

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
      } catch { }
    };

    window.addEventListener(EventType.PROFILE_PICTURE_UPDATED, handleAvatarUpdate as EventListener);
    window.addEventListener(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED, handleAvatarUpdate as EventListener);

    return () => {
      window.removeEventListener(EventType.PROFILE_PICTURE_UPDATED, handleAvatarUpdate as EventListener);
      window.removeEventListener(EventType.PROFILE_PICTURE_SYSTEM_INITIALIZED, handleAvatarUpdate as EventListener);
    };
  }, []);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
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

        loadBlockedUsers();
      } catch { }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange as EventListener);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener(EventType.BLOCK_STATUS_CHANGED, handleBlockStatusChange as EventListener);
    };
  }, [loadBlockedUsers]);

  const handleCopyUsername = async () => {
    if (!copyUsername) return;

    try {
      await copyTextToClipboard(copyUsername);
      setCopiedUsername(true);
      window.setTimeout(() => setCopiedUsername(false), 900);
    } catch {
      toast.error('Could not copy username');
    }
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

  const handleDesktopNotificationsToggle = (checked: boolean) => {
    const updated = { ...notifications, desktop: checked };
    setNotifications(updated);
    saveSettings({ notifications: updated });
    tauriNotifications.setEnabled(checked && !(doNotDisturb.messages && doNotDisturb.calls)).catch(() => { });
  };

  const handleDoNotDisturb = (type: keyof NotificationMutes, checked: boolean) => {
    try {
      setDoNotDisturb(type, checked);
    } catch {
      toast.error('Failed to update do not disturb');
    }
  };

  const handleNavigationLayoutChange = (layout: NavigationLayout) => {
    if (layout === navigationLayout) return;
    try {
      writeNavigationLayout(layout);
      setNavigationLayout(layout);
    } catch {
      toast.error('Failed to update navigation layout');
    }
  };

  const handleDevicePreference = (
    key: 'preferredMicId' | 'preferredSpeakerId' | 'preferredCameraId',
    value: string
  ) => {
    if (key === 'preferredMicId') setPreferredMicId(value);
    if (key === 'preferredSpeakerId') setPreferredSpeakerId(value);
    if (key === 'preferredCameraId') setPreferredCameraId(value);
    saveSettings(key === 'preferredMicId' ? { preferredCallMicId: value } : { [key]: value });
  };

  const armClearData = useCallback(() => {
    setLogoutArmed(false);
    if (logoutTimerRef.current) {
      clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
    }
    setClearArmed(true);
    if (clearArmTimerRef.current) clearTimeout(clearArmTimerRef.current);
    clearArmTimerRef.current = window.setTimeout(() => setClearArmed(false), 5000);
  }, []);

  const cancelClearData = useCallback(() => {
    setClearArmed(false);
    if (clearArmTimerRef.current) {
      clearTimeout(clearArmTimerRef.current);
      clearArmTimerRef.current = null;
    }
  }, []);

  const handleClearData = useCallback(async () => {
    if (isClearingData) return;
    if (clearArmTimerRef.current) {
      clearTimeout(clearArmTimerRef.current);
      clearArmTimerRef.current = null;
    }

    setIsClearingData(true);
    try {
      await encryptedStorage.removeItem(STORAGE_KEYS.APP_SETTINGS);
      window.location.reload();
    } catch {
      toast.error('Failed to clear data');
      setIsClearingData(false);
      setClearArmed(false);
    }
  }, [isClearingData]);

  const armLogout = useCallback(() => {
    setClearArmed(false);
    if (clearArmTimerRef.current) {
      clearTimeout(clearArmTimerRef.current);
      clearArmTimerRef.current = null;
    }
    setLogoutArmed(true);
    if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
    logoutTimerRef.current = window.setTimeout(() => setLogoutArmed(false), 5000);
  }, []);

  const cancelLogout = useCallback(() => {
    setLogoutArmed(false);
    if (logoutTimerRef.current) {
      clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
    }
  }, []);

  const handleLogout = useCallback(() => {
    if (logoutTimerRef.current) {
      clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
    }
    void onLogout();
  }, [onLogout]);

  useEffect(() => () => {
    if (clearArmTimerRef.current) clearTimeout(clearArmTimerRef.current);
    if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
  }, []);

  const openUnblockModal = useCallback((username: string) => {
    setUnblockTarget(username);
  }, []);

  const closeUnblockModal = useCallback(() => {
    if (unblocking) return;
    setUnblockTarget(null);
  }, [unblocking]);

  const confirmUnblock = useCallback(async () => {
    if (!unblockTarget || unblocking) return;
    setUnblocking(true);
    setBlockedUsersError(null);
    try {
      await blockingSystem.unblockUser(unblockTarget);
      await loadBlockedUsers();
      setUnblockTarget(null);
    } catch (error) {
      console.error('Error unblocking user:', error);
      setBlockedUsersError('Failed to unblock user. Please try again.');
    } finally {
      setUnblocking(false);
    }
  }, [unblockTarget, unblocking, loadBlockedUsers]);

  if (!initialSettingsReady) {
    return (
      <div className={`qorc-settings-host ${themeClass}`}>
        <main className="settings-screen">
          <SettingsSkeleton />
        </main>
      </div>
    );
  }

  return (
    <>
      <div className={`qorc-settings-host ${themeClass}`}>
        <main className="settings-screen">
          <h1 className="settings-brand">
            <SettingsIcon className="settings-brand-icon" aria-hidden="true" />
            <strong>Settings</strong>
          </h1>
          <section className="settings-content">
            <section className="pane account-pane" data-settings-pane="account" aria-label="Account">
              <header className="pane-head">
                <div className="pane-heading">
                  <div className="pane-title-row">
                    <UserRound className="pane-title-icon" aria-hidden="true" />
                    <h2 className="pane-title">My Account</h2>
                  </div>
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
                        {avatarUrl
                          ? <img src={avatarUrl} alt="" />
                          : <span className="avatar-preview-placeholder">{displayUsername.slice(0, 1).toUpperCase()}</span>}
                        <span className="avatar-hover-overlay">
                          <Camera aria-hidden="true" />
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
                        {copiedUsername ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                      </button>
                    </div>

                    <section className="account-actions" aria-label="Account actions">
                      {clearArmed ? (
                        <div className="confirm-inline">
                          <button className="action" type="button" onClick={cancelClearData} disabled={isClearingData}>
                            Cancel
                          </button>
                          <button className="danger-action is-armed" type="button" onClick={handleClearData} disabled={isClearingData}>
                            {isClearingData ? 'Clearing…' : 'Are you sure?'}
                          </button>
                        </div>
                      ) : logoutArmed ? (
                        <div className="confirm-inline">
                          <button className="action" type="button" onClick={cancelLogout}>
                            Cancel
                          </button>
                          <button className="danger-action is-armed" type="button" onClick={handleLogout}>
                            Are you sure?
                          </button>
                        </div>
                      ) : (
                        <div className="account-action-controls">
                          <button className="danger-action" type="button" onClick={armLogout}>
                            <LogOut aria-hidden="true" />
                            <span>Log Out</span>
                          </button>
                          <button className="danger-action" type="button" disabled={isClearingData} onClick={armClearData}>
                            <Trash2 aria-hidden="true" />
                            <span>Clear Data</span>
                          </button>
                        </div>
                      )}
                    </section>
                  </div>
                </div>
              </div>
            </section>

            <section className="pane" data-settings-pane="general">
              <header className="pane-head">
                <div className="pane-heading">
                  <div className="pane-title-row">
                    <SlidersHorizontal className="pane-title-icon" aria-hidden="true" />
                    <h2 className="pane-title">General</h2>
                  </div>
                  <p className="pane-subtitle">Basic app behavior.</p>
                </div>
              </header>

              <div className="settings-section">
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Navigation layout</div>
                      <div className="setting-description">Choose the collapsible sidebar or compact navigation at the top.</div>
                    </div>
                    <div className="navigation-layout-picker" role="group" aria-label="Navigation layout">
                      <button
                        type="button"
                        className={navigationLayout === 'sidebar' ? 'is-active' : ''}
                        aria-pressed={navigationLayout === 'sidebar'}
                        onClick={() => handleNavigationLayoutChange('sidebar')}
                      >
                        Sidebar
                      </button>
                      <button
                        type="button"
                        className={navigationLayout === 'top' ? 'is-active' : ''}
                        aria-pressed={navigationLayout === 'top'}
                        onClick={() => handleNavigationLayoutChange('top')}
                      >
                        Top
                      </button>
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Minimize to system tray on close</div>
                      <div className="setting-description">Closing the window keeps Qorc running in the background.</div>
                    </div>
                    <SwitchButton checked={closeToTray} disabled={isTrayLoading} label="Minimize to system tray" onChange={handleCloseToTrayChange} />
                  </div>
                </div>
              </div>
            </section>

            <section className="pane" data-settings-pane="notifications">
              <header className="pane-head">
                <div className="pane-heading">
                  <div className="pane-title-row">
                    <Bell className="pane-title-icon" aria-hidden="true" />
                    <h2 className="pane-title">Notifications</h2>
                  </div>
                </div>
              </header>
              <div className="settings-section">
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Desktop Notifications</div>
                      <div className="setting-description">Show desktop alerts for unmuted messages and calls.</div>
                    </div>
                    <SwitchButton checked={notifications.desktop && !(doNotDisturb.messages && doNotDisturb.calls)} disabled={doNotDisturb.messages && doNotDisturb.calls} label="Desktop Notifications" onChange={handleDesktopNotificationsToggle} />
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Mute message alerts</div>
                      <div className="setting-description">Mute all notification alerts for messages.</div>
                    </div>
                    <SwitchButton checked={doNotDisturb.messages} label="Mute message alerts" onChange={checked => handleDoNotDisturb('messages', checked)} />
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Mute call alerts</div>
                      <div className="setting-description">Mute all notification alerts for calls.</div>
                    </div>
                    <SwitchButton checked={doNotDisturb.calls} label="Mute call alerts" onChange={checked => handleDoNotDisturb('calls', checked)} />
                  </div>
                </div>
              </div>
            </section>

            <section className="pane" data-settings-pane="devices">
              <header className="pane-head">
                <div className="pane-heading">
                  <div className="pane-title-row">
                    <Headphones className="pane-title-icon" aria-hidden="true" />
                    <h2 className="pane-title">Devices</h2>
                  </div>
                  <p className="pane-subtitle">Hardware used for calls.</p>
                </div>
                <button
                  className="settings-icon-action"
                  type="button"
                  disabled={devicesLoading}
                  aria-label="Refresh media devices"
                  title="Refresh media devices"
                  onClick={() => { void refreshMediaDevices(); }}
                >
                  <RefreshCw className={devicesLoading ? 'animate-spin' : ''} aria-hidden="true" />
                </button>
              </header>

              <div className="settings-section">
                <div className="settings-list">
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Microphone</div>
                      <div className="setting-description">Default microphone for calls.</div>
                    </div>
                    <div className="device-select">
                      <select className="select" value={preferredMicId} onChange={(event) => handleDevicePreference('preferredMicId', event.target.value)}>
                        <option value="">System Default</option>
                        {micDevices.map((device) => <option key={device.deviceId} value={device.deviceId}>{device.label || `Microphone ${device.deviceId.slice(0, 8)}`}</option>)}
                      </select>
                      <ChevronDown aria-hidden="true" />
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Speaker</div>
                      <div className="setting-description">Default speaker for call audio output.</div>
                    </div>
                    <div className="device-select">
                      <select className="select" value={preferredSpeakerId} onChange={(event) => handleDevicePreference('preferredSpeakerId', event.target.value)}>
                        <option value="">System Default</option>
                        {speakerDevices.map((device) => <option key={device.deviceId} value={device.deviceId}>{device.label || `Speaker ${device.deviceId.slice(0, 8)}`}</option>)}
                      </select>
                      <ChevronDown aria-hidden="true" />
                    </div>
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Camera</div>
                      <div className="setting-description">Default camera for video calls.</div>
                    </div>
                    <div className="device-select">
                      <select className="select" value={preferredCameraId} onChange={(event) => handleDevicePreference('preferredCameraId', event.target.value)}>
                        <option value="">System Default</option>
                        {cameraDevices.map((device) => <option key={device.deviceId} value={device.deviceId}>{device.label || `Camera ${device.deviceId.slice(0, 8)}`}</option>)}
                      </select>
                      <ChevronDown aria-hidden="true" />
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className="pane" data-settings-pane="privacy">
              <header className="pane-head">
                <div className="pane-heading">
                  <div className="pane-title-row">
                    <ShieldCheck className="pane-title-icon" aria-hidden="true" />
                    <h2 className="pane-title">Privacy & Safety</h2>
                  </div>
                  <p className="pane-subtitle">Manage who can reach you.</p>
                </div>
                <button
                  className="settings-head-action"
                  type="button"
                  onClick={onOpenBlockConversationChooser}
                >
                  <Ban aria-hidden="true" />
                  <span>Block user</span>
                </button>
              </header>

              <div className="settings-section">
                {blockedUsersError && <div className="settings-error">{blockedUsersError}</div>}

                {blockedUsersLoading && blockedUsers.length === 0 ? (
                  <div className="blocked-empty" role="status" aria-label="Loading blocked users">
                    <LoaderCircle className="blocked-spinner" size={20} aria-hidden="true" />
                  </div>
                ) : blockedUsers.length === 0 ? (
                  <div className="blocked-empty">
                    <div><strong>No blocked users</strong><span>Users you block will appear here.</span></div>
                  </div>
                ) : (
                  <div className="blocked-user-list">
                    {blockedUsers.map((user) => (
                      <BlockedUserRow
                        key={user.username}
                        user={user}
                        loading={unblocking}
                        onUnblock={openUnblockModal}
                      />
                    ))}
                  </div>
                )}
              </div>
            </section>
          </section>
        </main>

        {unblockTarget && (
          <UnblockConfirmModal
            username={unblockTarget}
            busy={unblocking}
            themeClass={themeClass}
            onCancel={closeUnblockModal}
            onConfirm={confirmUnblock}
          />
        )}
      </div>
    </>
  );
});
