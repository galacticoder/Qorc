import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTheme } from '../../contexts/ThemeContext';
import { toast } from 'sonner';
import { Ban, Camera, Check, Copy, LoaderCircle, LogOut, RefreshCw, Trash2 } from 'lucide-react';
import { syncEncryptedStorage, encryptedStorage } from '../../lib/database/encrypted-storage';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { blockingSystem, type BlockedUser } from '../../lib/blocking/blocking-system';
import { nativeCamera, nativeMicrophone, notifications as tauriNotifications, system, tray } from '../../lib/tauri-bindings';
import { copyTextToClipboard } from '../../lib/clipboard';
import {
  hasPrototypePollutionKeys,
  isPlainObject,
  isValidUsername,
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
import { STORAGE_KEYS } from '../../lib/database/storage-keys';
import {
  readNavigationLayout,
  writeNavigationLayout,
  type NavigationLayout,
} from '../../lib/ui/navigation-layout';

installAppSettingsStyles();

interface AppSettingsProps {
  currentUsername?: string;
  currentDisplayName?: string;
  onLogout?: () => void | Promise<void>;
  findUser?: (handle: string, opts?: { forceRefresh?: boolean; monitorContact?: boolean }) => Promise<unknown>;
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
  onCancel,
  onConfirm,
}: {
  username: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const displayName = useDisplayUsername({ username });

  return (
    <div className="qorc-modal-overlay" onClick={onCancel}>
      <div
        className="qorc-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="unblock-modal-title"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="qorc-modal-head">
          <h3 id="unblock-modal-title">Unblock user?</h3>
          <p><strong>{displayName}</strong> will be able to message and call you again.</p>
        </div>
        <div className="qorc-modal-actions">
          <button className="qorc-modal-btn" type="button" onClick={onCancel} disabled={busy}>Cancel</button>
          <button className="qorc-modal-btn primary" type="button" onClick={onConfirm} disabled={busy}>
            {busy ? 'Unblocking…' : 'Unblock'}
          </button>
        </div>
      </div>
    </div>
  );
});

export const AppSettings = React.memo(function AppSettings({
  currentUsername = '',
  currentDisplayName = '',
  onLogout,
  findUser,
}: AppSettingsProps) {
  const { theme, resolvedTheme } = useTheme();
  const [isClearingData, setIsClearingData] = useState(false);
  const [clearArmed, setClearArmed] = useState(false);
  const clearArmTimerRef = useRef<number | null>(null);
  const [logoutArmed, setLogoutArmed] = useState(false);
  const logoutTimerRef = useRef<number | null>(null);
  const [notifications, setNotifications] = useState<NotificationSettings>({ desktop: true });
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
  const [blockModalOpen, setBlockModalOpen] = useState(false);
  const [blockInput, setBlockInput] = useState('');
  const [blockChecking, setBlockChecking] = useState(false);
  const [blockModalError, setBlockModalError] = useState<string | null>(null);
  const [unblockTarget, setUnblockTarget] = useState<string | null>(null);
  const [unblocking, setUnblocking] = useState(false);
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const profilePictureEventRateRef = useRef({ windowStart: Date.now(), count: 0 });
  const blockStatusEventRateRef = useRef({ windowStart: Date.now(), count: 0 });

  const activeTheme = theme === 'system' ? resolvedTheme : theme;
  const themeClass = activeTheme === 'light' ? 'light' : 'dark';
  const displayUsername = currentDisplayName || currentUsername || 'User';
  const copyUsername = currentDisplayName || currentUsername || '';
  const blockingAvailable = Boolean(currentUsername);

  const saveSettings = useCallback((updates: Partial<{
    notifications: NotificationSettings;
    preferredCallMicId: string;
    preferredSpeakerId: string;
    preferredCameraId: string;
  }>) => {
    try {
      const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
      const parsed = stored ? JSON.parse(stored) : {};
      syncEncryptedStorage.setItem(STORAGE_KEYS.APP_SETTINGS, JSON.stringify({ ...parsed, ...updates }));
    } catch { }
  }, []);

  const loadBlockedUsers = useCallback(async () => {
    if (!blockingAvailable) {
      setBlockedUsersError('Please log in.');
      setBlockedUsers([]);
      return;
    }

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
  }, [blockingAvailable]);

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
    const initTraySettings = async () => {
      try {
        setCloseToTray(await tray.getCloseToTray());
      } catch { }
      setIsTrayLoading(false);
    };

    const initProfilePicture = async () => {
      try {
        await profilePictureSystem.initialize();
        setAvatarUrl(profilePictureSystem.getOwnAvatar());
      } catch (error) {
        console.error('[AppSettings] Failed to init profile picture:', error);
      }
    };

    initTraySettings();
    initProfilePicture();

    try {
      const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.notifications) {
          setNotifications(parsed.notifications);
          tauriNotifications.setEnabled(parsed.notifications.desktop !== false).catch(() => { });
        }
        if (parsed.preferredCallMicId) setPreferredMicId(parsed.preferredCallMicId);
        if (parsed.preferredSpeakerId) setPreferredSpeakerId(parsed.preferredSpeakerId);
        if (parsed.preferredCameraId) setPreferredCameraId(parsed.preferredCameraId);
      }
    } catch { }
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
    if (blockingAvailable) {
      loadBlockedUsers();
    }
  }, [blockingAvailable, loadBlockedUsers]);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && blockingAvailable) {
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

        if (blockingAvailable) {
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
  }, [blockingAvailable, loadBlockedUsers]);

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
    tauriNotifications.setEnabled(checked).catch(() => { });
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
      await encryptedStorage.setItem(STORAGE_KEYS.APP_SETTINGS, '');
      window.location.reload();
    } catch {
      toast.error('Failed to clear data');
      setIsClearingData(false);
      setClearArmed(false);
    }
  }, [isClearingData]);

  const armLogout = useCallback(() => {
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
    void onLogout?.();
  }, [onLogout]);

  useEffect(() => () => {
    if (clearArmTimerRef.current) clearTimeout(clearArmTimerRef.current);
    if (logoutTimerRef.current) clearTimeout(logoutTimerRef.current);
  }, []);

  const openBlockModal = useCallback(() => {
    setBlockInput('');
    setBlockModalError(null);
    setBlockChecking(false);
    setBlockModalOpen(true);
  }, []);

  const closeBlockModal = useCallback(() => {
    if (blockChecking) return;
    setBlockModalOpen(false);
  }, [blockChecking]);

  const confirmBlock = useCallback(async () => {
    const username = blockInput.trim();
    if (!username || blockChecking) return;

    if (!blockingAvailable) {
      setBlockModalError('Please log in.');
      return;
    }

    if (!isValidUsername(username)) {
      setBlockModalError('That username format is invalid.');
      return;
    }

    if (username === currentUsername) {
      setBlockModalError("You can't block yourself.");
      return;
    }

    if (blockedUsers.some((u) => u.username === username)) {
      setBlockModalError('That user is already blocked.');
      return;
    }

    setBlockChecking(true);
    setBlockModalError(null);
    try {
      // Verify the user actually exists in discovery before blocking
      if (findUser) {
        let exists = false;
        try {
          exists = Boolean(await findUser(username, { monitorContact: false }));
        } catch {
          setBlockModalError("Couldn't verify that username right now. Check your connection and try again.");
          setBlockChecking(false);
          return;
        }
        if (!exists) {
          setBlockModalError('No user found with that username.');
          setBlockChecking(false);
          return;
        }
      }

      await blockingSystem.blockUser(username);
      await loadBlockedUsers();
      setBlockModalOpen(false);
    } catch (error) {
      console.error('Error blocking user:', error);
      setBlockModalError('Failed to block user. Please try again.');
    } finally {
      setBlockChecking(false);
    }
  }, [blockInput, blockChecking, blockingAvailable, currentUsername, blockedUsers, findUser, loadBlockedUsers]);

  const openUnblockModal = useCallback((username: string) => {
    setUnblockTarget(username);
  }, []);

  const closeUnblockModal = useCallback(() => {
    if (unblocking) return;
    setUnblockTarget(null);
  }, [unblocking]);

  const confirmUnblock = useCallback(async () => {
    if (!unblockTarget || unblocking) return;
    if (!blockingAvailable) {
      setBlockedUsersError('Please log in.');
      setUnblockTarget(null);
      return;
    }

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
  }, [unblockTarget, unblocking, blockingAvailable, loadBlockedUsers]);

  return (
    <>
      <div className={`qorc-settings-host ${themeClass}`}>
        <main className="settings-screen">
          <section className="settings-content">
            <h1 className="settings-brand"><strong>Settings</strong></h1>

            <section className="pane account-pane" data-settings-pane="account">
              <header className="pane-head">
                <div>
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
                        {avatarUrl
                          ? <img src={avatarUrl} alt="" />
                          : <span className="avatar-preview-fallback">{displayUsername.slice(0, 1).toUpperCase()}</span>}
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
                  </div>

                  <div className="account-actions">
                    <div className="account-action-row account-danger-row">
                      <div>
                        <div className="setting-label" style={{ color: 'var(--danger)' }}>Clear All Data</div>
                        <div className="setting-description">Permanently delete all your local account stored data. You will be logged out.</div>
                      </div>
                      {clearArmed ? (
                        <div className="confirm-inline">
                          <button className="action" type="button" onClick={cancelClearData} disabled={isClearingData}>
                            Cancel
                          </button>
                          <button className="danger-action is-armed" type="button" onClick={handleClearData} disabled={isClearingData}>
                            {isClearingData ? 'Clearing…' : 'Are you sure?'}
                          </button>
                        </div>
                      ) : (
                        <button className="danger-action" type="button" disabled={isClearingData} onClick={armClearData}>
                          <Trash2 aria-hidden="true" />
                          <span>Clear Data</span>
                        </button>
                      )}
                    </div>
                    <div className="account-action-row account-danger-row">
                      <div>
                        <div className="setting-label" style={{ color: 'var(--danger)' }}>Log Out</div>
                        <div className="setting-description">Sign out of your account on this device.</div>
                      </div>
                      {logoutArmed ? (
                        <div className="confirm-inline">
                          <button className="action" type="button" onClick={cancelLogout}>
                            Cancel
                          </button>
                          <button className="danger-action is-armed" type="button" onClick={handleLogout}>
                            Are you sure?
                          </button>
                        </div>
                      ) : (
                        <button className="danger-action" type="button" onClick={armLogout}>
                          <LogOut aria-hidden="true" />
                          <span>Log Out</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </section>

            <section className="pane" data-settings-pane="general">
              <header className="pane-head">
                <div>
                  <h2 className="pane-title">General</h2>
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
                      <div className="setting-description">Closing the window keeps qorc running in the background.</div>
                    </div>
                    <SwitchButton checked={closeToTray} disabled={isTrayLoading} label="Minimize to system tray" onChange={handleCloseToTrayChange} />
                  </div>
                  <div className="setting-row">
                    <div>
                      <div className="setting-label">Desktop Notifications</div>
                      <div className="setting-description">Show a notification popup when a new message arrives.</div>
                    </div>
                    <SwitchButton checked={notifications.desktop} label="Desktop Notifications" onChange={handleDesktopNotificationsToggle} />
                  </div>
                </div>
              </div>
            </section>

            <section className="pane" data-settings-pane="devices">
              <header className="pane-head">
                <div>
                  <h2 className="pane-title">Devices</h2>
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

            <section className="pane" data-settings-pane="privacy">
              <header className="pane-head">
                <div>
                  <h2 className="pane-title">Privacy & Safety</h2>
                  <p className="pane-subtitle">Manage who can reach you.</p>
                </div>
                <button
                  className="settings-head-action"
                  type="button"
                  disabled={!blockingAvailable}
                  onClick={openBlockModal}
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

        {blockModalOpen && (
          <div className="qorc-modal-overlay" onClick={closeBlockModal}>
            <div
              className="qorc-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="block-modal-title"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="qorc-modal-head">
                <h3 id="block-modal-title">Block a user</h3>
                <p>Enter the username of the person you want to block.</p>
              </div>
              <div className="qorc-modal-body">
                <label className="qorc-modal-field">
                  <span className="field-label">Username</span>
                  <input
                    className="text-input"
                    type="text"
                    value={blockInput}
                    placeholder="Enter a username"
                    autoFocus
                    spellCheck={false}
                    autoComplete="off"
                    disabled={blockChecking}
                    onChange={(e) => { setBlockInput(e.target.value); if (blockModalError) setBlockModalError(null); }}
                    onKeyDown={(e) => { if (e.key === 'Enter') confirmBlock(); }}
                  />
                </label>
                {blockModalError && <div className="qorc-modal-error">{blockModalError}</div>}
              </div>
              <div className="qorc-modal-actions">
                <button className="qorc-modal-btn" type="button" onClick={closeBlockModal} disabled={blockChecking}>Cancel</button>
                <button className="qorc-modal-btn danger" type="button" onClick={confirmBlock} disabled={blockChecking || !blockInput.trim()}>
                  {blockChecking ? 'Checking…' : 'Block user'}
                </button>
              </div>
            </div>
          </div>
        )}

        {unblockTarget && (
          <UnblockConfirmModal
            username={unblockTarget}
            busy={unblocking}
            onCancel={closeUnblockModal}
            onConfirm={confirmUnblock}
          />
        )}
      </div>
    </>
  );
});
