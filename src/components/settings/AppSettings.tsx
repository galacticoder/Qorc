import React, { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTheme } from '../../contexts/ThemeContext';
import { toast } from 'sonner';
import {
  Ban,
  ArrowLeft,
  Bell,
  Camera,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  FileText,
  Headphones,
  LoaderCircle,
  LogOut,
  ShieldCheck,
  Server,
  SlidersHorizontal,
  Trash2,
  X,
} from 'lucide-react';
import { profilePictureSystem } from '../../lib/avatar/profile-picture-system';
import { blockingSystem } from '../../lib/blocking/blocking-system';
import { nativeCamera, nativeMicrophone, notifications as tauriNotifications, system, tray } from '../../lib/tauri-bindings';
import { copyTextToClipboard } from '../../lib/clipboard';
import { isAndroidPlatform } from '../../lib/runtime/platform';
import { useMobileLayout } from '../../hooks/useMobileLayout';
import { useAppBack } from '../../hooks/useAppBack';
import { useSettingFeedback, type SettingFeedbackState } from '../../hooks/useSettingFeedback';
import { animateView } from '../../lib/ui/motion';
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
import { SavedServersScreen } from '../servers/SavedServersScreen';
import { AppSelect } from '../ui/AppSelect';
import { StandaloneScreen } from '../ui/StandaloneScreen';
import { installAppSettingsStyles } from './sections/AppSettingsStyles';
import {
  readAppSettings,
  updateAppSettingsConfirmed,
  type AppSettingsState,
} from '../../lib/ui/app-settings';
import {
  readNavigationLayout,
  writeNavigationLayoutConfirmed,
  type NavigationLayout,
} from '../../lib/ui/navigation-layout';
import { SettingsIcon } from '../chat/assets/icons';
import { type BlockedUser } from '../../lib/types/blocking-types';
import { useNotificationPreferences } from '../../hooks/useNotificationPreferences';
import { setDoNotDisturbConfirmed, type NotificationMutes } from '../../lib/ui/notification-preferences';
import { uniqueMediaDevices } from '../../lib/ui/media-device-options';
import { TERMS_URL, PRIVACY_URL } from '../../lib/ui/legal-links';

installAppSettingsStyles();

interface AppSettingsProps {
  currentUsername: string;
  currentDisplayName: string;
  onLogout: () => void | Promise<void>;
  onClearLocalData: () => Promise<void>;
  onResetAllLocalData: () => Promise<void>;
  onOpenBlockConversationChooser: () => void;
}

interface NotificationSettings {
  desktop: boolean;
}

const SETTINGS_SECTIONS = [
  { id: 'general', label: 'General', description: 'Theme and app appearance', icon: SlidersHorizontal },
  { id: 'servers', label: 'Servers', description: 'Manage saved servers', icon: Server },
  { id: 'notifications', label: 'Notifications', description: 'Message and call alerts', icon: Bell },
  { id: 'devices', label: 'Devices', description: 'Microphone, speaker and camera', icon: Headphones },
  { id: 'privacy', label: 'Privacy & Safety', description: 'Blocked users, privacy and local account data', icon: ShieldCheck },
] as const;
type SettingsSection = typeof SETTINGS_SECTIONS[number]['id'];
type SettingsAction = 'logout' | 'clear' | 'reset';

function SettingCopy({ children }: { children: React.ReactNode }) {
  return <div className="setting-copy">
    <div className="setting-copy-text">{children}</div>
  </div>;
}

function SettingsActionDialog({ title, description, confirmLabel, busyLabel, busy, error, themeClass, onCancel, onConfirm }: {
  title: string; description: string; confirmLabel: string; busyLabel: string;
  busy: boolean; error: string | null; themeClass: 'light' | 'dark';
  onCancel: () => void; onConfirm: () => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId(), descriptionId = useId();
  useAppBack(true, () => { if (!busy) onCancel(); }, 100);
  useLayoutEffect(() => {
    const previousFocus = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialogRef.current?.querySelector<HTMLButtonElement>('button')?.focus();
    return () => {
      document.body.style.overflow = previousOverflow;
      queueMicrotask(() => {
        if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
      });
    };
  }, []);
  useEffect(() => {
    if (busy) dialogRef.current?.focus({ preventScroll: true });
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault(); event.stopPropagation();
        if (!busy) onCancel();
      } else if (event.key === 'Tab') {
        const buttons = Array.from(dialogRef.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
        const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
        if (index < 0 || (event.shiftKey ? index === 0 : index === buttons.length - 1)) {
          event.preventDefault();
          if (buttons.length) buttons[event.shiftKey ? buttons.length - 1 : 0].focus();
          else dialogRef.current?.focus();
        }
      }
    };
    document.addEventListener('keydown', keydown, true);
    return () => document.removeEventListener('keydown', keydown, true);
  }, [busy, onCancel]);
  return createPortal(<div className={`qorc-settings-host ${themeClass} qorc-unblock-overlay qorc-screen-overlay settings-action-overlay`}
    data-state="open" onClick={() => { if (!busy) onCancel(); }}>
    <div ref={dialogRef} tabIndex={-1} className="qorc-unblock-dialog settings-action-dialog" role="alertdialog" aria-modal="true"
      aria-labelledby={titleId} aria-describedby={descriptionId} aria-busy={busy} onClick={event => event.stopPropagation()}>
      <div className="settings-action-dialog-copy"><h2 id={titleId}>{title}</h2><p id={descriptionId}>{description}</p>
        {error && <p className="settings-action-dialog-error" role="alert">{error}</p>}
        {busy && <p className="settings-action-dialog-status" role="status">{busyLabel}</p>}
      </div>
      <div className="settings-action-dialog-buttons">
        <button className="action" type="button" disabled={busy} onClick={onCancel}>Cancel</button>
        <button className="danger-action" type="button" disabled={busy} onClick={onConfirm}>{busy ? busyLabel : confirmLabel}</button>
      </div>
    </div>
  </div>, document.body);
}

function SettingFeedback({ state }: { state?: SettingFeedbackState }) {
  if (!state) return null;
  return <span className="setting-feedback is-error" role="alert">
    <X size={13} aria-hidden="true" />
    <span>{state.message}</span>
  </span>;
}

function mediaOptions(devices: Array<{ deviceId: string; label: string }>, selected: string, name: string) {
  const unique = uniqueMediaDevices(devices, name);
  return [
    { value: '', label: 'Default' },
    ...(selected && !unique.some(device => device.deviceId === selected)
      ? [{ value: selected, label: `Saved ${name.toLowerCase()}` }] : []),
    ...unique.map(device => ({ value: device.deviceId, label: device.label })),
  ];
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
  error,
  onCancel,
  onConfirm,
}: {
  username: string;
  busy: boolean;
  themeClass: 'light' | 'dark';
  error?: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const displayName = useDisplayUsername({ username });
  const showUsername = displayName.trim().toLowerCase() !== username.trim().toLowerCase();
  const dialogRef = useRef<HTMLDivElement>(null);
  useAppBack(true, () => { if (!busy) onCancel(); }, 100);

  useLayoutEffect(() => {
    const previousFocus = document.activeElement;
    dialogRef.current?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
    return () => {
      queueMicrotask(() => {
        if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
      });
    };
  }, []);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        if (!busy) onCancel();
      } else if (event.key === 'Tab') {
        const buttons = Array.from(dialogRef.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
        const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
        if (!buttons.length || index < 0 || (event.shiftKey ? index === 0 : index === buttons.length - 1)) {
          event.preventDefault();
          if (buttons.length) buttons[event.shiftKey ? buttons.length - 1 : 0].focus();
          else dialogRef.current?.focus();
        }
      }
    };
    document.addEventListener('keydown', keydown, true);
    return () => document.removeEventListener('keydown', keydown, true);
  }, [busy, onCancel]);

  return createPortal(
    <div className={`qorc-settings-host ${themeClass} qorc-unblock-overlay qorc-screen-overlay`} data-state="open" onClick={onCancel}>
      <div
        ref={dialogRef}
        tabIndex={-1}
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
        {error && <div className="settings-error" role="alert">{error}</div>}
      </div>
    </div>,
    document.body,
  );
});

export const AppSettings = React.memo(function AppSettings({
  currentUsername,
  currentDisplayName,
  onLogout,
  onClearLocalData,
  onResetAllLocalData,
  onOpenBlockConversationChooser,
}: AppSettingsProps) {
  const { theme, resolvedTheme, setTheme } = useTheme();
  const mobile = useMobileLayout();
  const android = isAndroidPlatform();
  const [sectionId, setSectionId] = useState<SettingsSection | null>(null);
  const settingsContentRef = useRef<HTMLElement>(null);
  const overviewScrollRef = useRef(0);
  const settingsHeadingRef = useRef<HTMLHeadingElement>(null);
  const sectionNavigationRef = useRef(false);
  const previousSectionRef = useRef(sectionId);
  const feedback = useSettingFeedback();
  const [confirmationAction, setConfirmationAction] = useState<SettingsAction | null>(null);
  const [pendingAction, setPendingAction] = useState<SettingsAction | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const actionBusyRef = useRef(false);
  const actionBusy = pendingAction !== null;
  const [storedSettings] = useState(readAppSettings);
  const [notifications, setNotifications] = useState<NotificationSettings>(() => storedSettings.notifications ?? { desktop: true });
  const { doNotDisturb } = useNotificationPreferences();
  const [navigationLayout, setNavigationLayout] = useState<NavigationLayout>(readNavigationLayout);
  const [closeToTray, setCloseToTray] = useState(true);
  const [isTrayLoading, setIsTrayLoading] = useState(true);
  const [avatarUrl, setAvatarUrl] = useState<string | null>(() => profilePictureSystem.getOwnAvatar());
  const [copiedUsername, setCopiedUsername] = useState(false);
  const [micDevices, setMicDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [speakerDevices, setSpeakerDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [cameraDevices, setCameraDevices] = useState<Array<{ deviceId: string; label: string }>>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const devicesLoadingRef = useRef(false);
  const [preferredMicId, setPreferredMicId] = useState(storedSettings.preferredCallMicId ?? '');
  const [preferredSpeakerId, setPreferredSpeakerId] = useState(storedSettings.preferredSpeakerId ?? '');
  const [preferredCameraId, setPreferredCameraId] = useState(storedSettings.preferredCameraId ?? '');
  const [blockedUsers, setBlockedUsers] = useState<BlockedUser[]>([]);
  const [blockedUsersLoading, setBlockedUsersLoading] = useState(false);
  const [blockedUsersError, setBlockedUsersError] = useState<string | null>(null);
  const [unblockTarget, setUnblockTarget] = useState<string | null>(null);
  const [unblocking, setUnblocking] = useState(false);
  const [savedServersOpen, setSavedServersOpen] = useState(false);
  const [blockedUsersOpen, setBlockedUsersOpen] = useState(false);
  const blockedUsersTitleId = useId();
  const avatarInputRef = useRef<HTMLInputElement>(null);
  const profilePictureEventRateRef = useRef({ windowStart: Date.now(), count: 0 });
  const blockStatusEventRateRef = useRef({ windowStart: Date.now(), count: 0 });
  const selectedSection = SETTINGS_SECTIONS.find(section => section.id === sectionId);

  useLayoutEffect(() => {
    if (settingsContentRef.current) settingsContentRef.current.scrollTop = sectionId ? 0 : overviewScrollRef.current;
    if (sectionNavigationRef.current) {
      settingsHeadingRef.current?.focus({ preventScroll: true });
      sectionNavigationRef.current = false;
    }
    if (previousSectionRef.current === sectionId) return;
    previousSectionRef.current = sectionId;
    if (!mobile) return;
    const animation = animateView(settingsContentRef.current, sectionId ? 'forward' : 'back');
    return () => animation?.cancel();
  }, [mobile, sectionId]);

  const activeTheme = theme === 'system' ? resolvedTheme : theme;
  const themeClass = activeTheme === 'light' ? 'light' : 'dark';
  const displayUsername = currentDisplayName || currentUsername;
  const copyUsername = currentDisplayName || currentUsername;

  const handleOpenLegalLink = useCallback(async (url: string) => {
    try {
      await system.openExternal(url);
    } catch {
      toast.error('Could not open the document. Please try again.');
    }
  }, []);

  const saveSettings = useCallback(async (updates: Partial<AppSettingsState>) => {
    await updateAppSettingsConfirmed(updates);
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
      await feedback.run('devices', async () => {
        if (!await system.requestMediaAccess('enumerate')) return false;
        const [microphones, speakers, cameras] = await Promise.all([
          nativeMicrophone.devices(), nativeMicrophone.outputDevices(), nativeCamera.devices(),
        ]);
        if (microphones.length > 64 || speakers.length > 64 || cameras.length > 32) throw new Error('Invalid media device list');
        setMicDevices(microphones.map(device => ({ deviceId: device.device_id, label: device.label })));
        setSpeakerDevices(speakers.map(device => ({ deviceId: device.device_id, label: device.label })));
        setCameraDevices(cameras.map(device => ({ deviceId: device.device_id, label: device.label })));
      }, 'Could not load media devices. Please try again.');
    } finally {
      devicesLoadingRef.current = false;
      setDevicesLoading(false);
    }
  }, [feedback.run]);

  useEffect(() => {
    let cancelled = false;

    const initTraySettings = async () => {
      try {
        const enabled = await tray.getCloseToTray();
        if (!cancelled) setCloseToTray(enabled);
      }
      catch {
        if (!cancelled) {
          setCloseToTray(false);
          toast.error(android ? 'Android could not start background mode' : 'Failed to read tray setting');
        }
      } finally { if (!cancelled) setIsTrayLoading(false); }
    };

    const initProfilePicture = async () => {
      await profilePictureSystem.initialize();
      if (!cancelled) setAvatarUrl(profilePictureSystem.getOwnAvatar());
    };

    const initialize = async () => {
      try {
        await Promise.all([
          initTraySettings(),
          initProfilePicture(),
          loadBlockedUsers(),
        ]);
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
      feedback.fail('avatar', `Image too large (max ${MAX_PROFILE_IMAGE_SIZE / 1024 / 1024}MB)`);
      return;
    }

    await feedback.run('avatar', async isCurrent => {
      const data = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => typeof reader.result === 'string' ? resolve(reader.result) : reject(new Error('Invalid image'));
        reader.onerror = () => reject(new Error('Image could not be read'));
        reader.onabort = () => reject(new Error('Image read was cancelled'));
        reader.readAsDataURL(selectedFile);
      });
      if (!isCurrent()) return false;
      const result = await profilePictureSystem.setOwnAvatar(data);
      if (!result.success) throw new Error('Avatar upload failed');
      setAvatarUrl(profilePictureSystem.getOwnAvatar());
    }, 'Could not update your picture. Please try again.');
  };

  const handleCloseToTrayChange = async (enabled: boolean) => {
    const previous = closeToTray;
    await feedback.run('background', async () => {
      setCloseToTray(enabled);
      try { if (!await tray.setCloseToTray(enabled)) throw new Error('Background setting was rejected'); }
      catch (error) { setCloseToTray(previous); throw error; }
    }, android ? 'Failed to update background setting' : 'Failed to update tray setting');
  };

  const handleDesktopNotificationsToggle = async (checked: boolean) => {
    const previous = notifications;
    const updated = { ...notifications, desktop: checked };
    await feedback.run('notifications', async isCurrent => {
      setNotifications(updated);
      try {
        await tauriNotifications.setEnabled(checked && !(doNotDisturb.messages && doNotDisturb.calls));
        if (!isCurrent()) return false;
        await saveSettings({ notifications: updated });
      } catch (error) {
        setNotifications(previous);
        if (isCurrent()) await tauriNotifications.setEnabled(previous.desktop && !(doNotDisturb.messages && doNotDisturb.calls)).catch(() => { });
        throw error;
      }
    }, 'Could not save notification settings. Please try again.');
  };

  const handleDoNotDisturb = async (type: keyof NotificationMutes, checked: boolean) => {
    await feedback.run(`mute-${type}`, () => setDoNotDisturbConfirmed(type, checked), 'Could not save mute settings. Please try again.');
  };

  const handleNavigationLayoutChange = async (layout: NavigationLayout) => {
    if (layout === navigationLayout) return;
    const previous = navigationLayout;
    await feedback.run('navigation', async () => {
      setNavigationLayout(layout);
      try { await writeNavigationLayoutConfirmed(layout); }
      catch (error) { setNavigationLayout(previous); throw error; }
    }, 'Failed to update navigation layout');
  };

  const handleDevicePreference = async (
    key: 'preferredMicId' | 'preferredSpeakerId' | 'preferredCameraId',
    value: string
  ) => {
    const setValue = key === 'preferredMicId' ? setPreferredMicId : key === 'preferredSpeakerId' ? setPreferredSpeakerId : setPreferredCameraId;
    const previous = key === 'preferredMicId' ? preferredMicId : key === 'preferredSpeakerId' ? preferredSpeakerId : preferredCameraId;
    await feedback.run(key, async () => {
      setValue(value);
      try { await saveSettings(key === 'preferredMicId' ? { preferredCallMicId: value } : { [key]: value }); }
      catch (error) { setValue(previous); throw error; }
    }, 'Could not save this device. Please try again.');
  };

  const handleThemeChange = async (value: string) => {
    if (value !== 'light' && value !== 'dark' && value !== 'system') return;
    await feedback.run('theme', () => setTheme(value), 'Could not save your theme. Please try again.');
  };

  const openActionConfirmation = useCallback((action: SettingsAction) => {
    if (actionBusyRef.current || confirmationAction) return;
    setActionError(null);
    setConfirmationAction(action);
  }, [confirmationAction]);

  const closeActionConfirmation = useCallback(() => {
    if (actionBusyRef.current) return;
    setConfirmationAction(null);
    setActionError(null);
  }, []);

  const confirmAction = useCallback(async () => {
    if (actionBusyRef.current || !confirmationAction) return;
    const action = confirmationAction;
    actionBusyRef.current = true;
    setPendingAction(action);
    setActionError(null);
    try {
      if (action === 'clear') { await onClearLocalData(); window.location.reload(); }
      else if (action === 'reset') await onResetAllLocalData();
      else {
        await onLogout();
        actionBusyRef.current = false;
        setPendingAction(null);
        setConfirmationAction(null);
      }
    } catch {
      actionBusyRef.current = false;
      setPendingAction(null);
      setActionError(action === 'clear' ? 'Could not finish deleting local account data. Please try again.'
        : action === 'reset' ? 'Could not finish resetting local app data. Restart Qorc to retry.'
        : 'Could not log out. Please try again.');
    }
  }, [confirmationAction, onClearLocalData, onResetAllLocalData, onLogout]);

  const openUnblockModal = useCallback((username: string) => {
    setBlockedUsersError(null);
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

  const closeBlockedUsers = useCallback(() => {
    if (unblockTarget || unblocking) return;
    setBlockedUsersOpen(false);
  }, [unblockTarget, unblocking]);

  const navigateSection = (section: SettingsSection | null) => {
    if (actionBusyRef.current || confirmationAction) return;
    if (section && !sectionId) overviewScrollRef.current = settingsContentRef.current?.scrollTop || 0;
    sectionNavigationRef.current = true;
    setSectionId(section);
  };
  useAppBack(!!sectionId, () => navigateSection(null), 20);

  return (
    <>
      <div className={`qorc-settings-host ${themeClass}${mobile ? ' is-mobile' : ''}`}>
        <main className="settings-screen" inert={!!confirmationAction || actionBusy}>
          <header className="settings-header">
            {selectedSection && <button className="settings-back" type="button" disabled={actionBusy} aria-label="Back to Settings" onClick={() => navigateSection(null)}>
              <ArrowLeft size={22} aria-hidden="true" />
            </button>}
            <h1 className="settings-brand" ref={settingsHeadingRef} tabIndex={-1}>
              {!selectedSection && <SettingsIcon className="settings-brand-icon" aria-hidden="true" />}
              <strong>{selectedSection?.label || 'Settings'}</strong>
            </h1>
          </header>
          <section ref={settingsContentRef} className={`settings-content${selectedSection ? ' is-section' : ''}`} inert={!!confirmationAction || actionBusy} aria-busy={actionBusy} aria-label={selectedSection ? `${selectedSection.label} settings` : 'Application settings'}>
            {!sectionId && <section className="pane account-pane" data-settings-pane="account" aria-label="Account">
              <div className="settings-section">
                <div className="account-editor">
                  <div className="account-preview">
                    <button
                      className="avatar-preview-button"
                      type="button"
                      aria-label="Change profile picture"
                      disabled={feedback.busy}
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
                      disabled={feedback.busy}
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
                      <SettingFeedback state={feedback.states.avatar} />
                    </div>


                  </div>
                </div>
              </div>
            </section>}

            {!sectionId && <nav className="settings-section-menu" aria-label="Settings sections">
              {SETTINGS_SECTIONS.map(section => <button key={section.id} type="button" className="settings-section-link" onClick={() => navigateSection(section.id)}>
                <section.icon className="settings-section-icon" size={22} aria-hidden="true" />
                <span className="settings-section-copy"><strong>{section.label}</strong><span>{section.description}</span></span>
                <ChevronRight size={20} aria-hidden="true" />
              </button>)}
            </nav>}

            {sectionId === 'general' && <section className="pane" data-settings-pane="general">

              <div className="settings-section">
                <div className="settings-list">
                  <h3 className="settings-subsection-title">Appearance</h3>
                  {!mobile && <div className="setting-row">
                    <div>
                      <div className="setting-label">Navigation layout<SettingFeedback state={feedback.states['navigation']} /></div>
                      <div className="setting-description">Choose the collapsible sidebar or compact navigation at the top.</div>
                    </div>
                    <div className="navigation-layout-picker" role="group" aria-label="Navigation layout">
                      <button
                        type="button"
                        className={navigationLayout === 'sidebar' ? 'is-active' : ''}
                        aria-pressed={navigationLayout === 'sidebar'} disabled={feedback.busy}
                        onClick={() => handleNavigationLayoutChange('sidebar')}
                      >
                        Sidebar
                      </button>
                      <button
                        type="button"
                        className={navigationLayout === 'top' ? 'is-active' : ''}
                        aria-pressed={navigationLayout === 'top'} disabled={feedback.busy}
                        onClick={() => handleNavigationLayoutChange('top')}
                      >
                        Top
                      </button>
                    </div>
                  </div>}
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">Theme<SettingFeedback state={feedback.states['theme']} /></div>
                      <div className="setting-description">Choose a light or dark appearance, or follow your device.</div>
                    </SettingCopy>
                    <AppSelect className="theme-select" label="Theme" value={theme}
                      onValueChange={handleThemeChange} disabled={feedback.busy}
                      options={[{ value: 'system', label: 'System' }, { value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }]} />
                  </div>
                  {(!mobile || android) && <h3 className="settings-subsection-title">Background activity</h3>}
                  {(!mobile || android) && <div className="setting-row">
                    <div>
                      <div className="setting-label">{android ? 'Keep running in background' : 'Minimize to system tray on close'}<SettingFeedback state={feedback.states.background} /></div>
                      <div className="setting-description">{android ? 'Keep messages and calls connected after closing the app.' : 'Closing the window keeps Qorc running in the background.'}</div>
                    </div>
                    <SwitchButton checked={closeToTray} disabled={isTrayLoading || feedback.busy} label={android ? 'Keep running in background' : 'Minimize to system tray'} onChange={handleCloseToTrayChange} />
                  </div>}
                  {android && <div className="setting-row">
                    <div>
                      <div className="setting-label">Background connection notice<SettingFeedback state={feedback.states['background-notice']} /></div>
                      <div className="setting-description">Open Android notification settings to manage the connection notice. Hiding it keeps Qorc running.</div>
                    </div>
                    <button className="action" type="button" onClick={() => {
                      void tray.openBackgroundNoticeSettings().catch(() => feedback.fail('background-notice', 'Could not open Android notification settings. Please try again.'));
                    }}>Manage</button>
                  </div>}
                </div>
              </div>
            </section>}

            {sectionId === 'servers' && <section className="pane" data-settings-pane="servers">
              <div className="settings-section"><div className="settings-list"><h3 className="settings-subsection-title">Connections</h3><div className="setting-row">
                <SettingCopy><div className="setting-label">Saved servers</div><div className="setting-description">Add or remove server addresses available on the sign-in screen.</div></SettingCopy>
                <button type="button" className="action" onClick={() => setSavedServersOpen(true)}>Manage servers</button>
              </div></div></div>
            </section>}

            {sectionId === 'notifications' && <section className="pane" data-settings-pane="notifications">
              <div className="settings-section">
                <div className="settings-list">
                  <h3 className="settings-subsection-title">Alerts</h3>
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">{mobile ? 'Notifications' : 'Desktop Notifications'}<SettingFeedback state={feedback.states.notifications} /></div>
                      <div className="setting-description">Show alerts for unmuted messages and calls.</div>
                    </SettingCopy>
                    <SwitchButton checked={notifications.desktop && !(doNotDisturb.messages && doNotDisturb.calls)} disabled={feedback.busy || (doNotDisturb.messages && doNotDisturb.calls)} label={mobile ? 'Notifications' : 'Desktop Notifications'} onChange={handleDesktopNotificationsToggle} />
                  </div>
                  <h3 className="settings-subsection-title">Do Not Disturb</h3>
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">Mute message alerts<SettingFeedback state={feedback.states['mute-messages']} /></div>
                      <div className="setting-description">Silence message alerts while keeping messages available in your chats.</div>
                    </SettingCopy>
                    <SwitchButton checked={doNotDisturb.messages} disabled={feedback.busy} label="Mute message alerts" onChange={checked => handleDoNotDisturb('messages', checked)} />
                  </div>
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">Mute call alerts<SettingFeedback state={feedback.states['mute-calls']} /></div>
                      <div className="setting-description">Silence incoming call alerts without changing your message alerts.</div>
                    </SettingCopy>
                    <SwitchButton checked={doNotDisturb.calls} disabled={feedback.busy} label="Mute call alerts" onChange={checked => handleDoNotDisturb('calls', checked)} />
                  </div>
                </div>
              </div>
            </section>}

            {sectionId === 'devices' && <section className="pane" data-settings-pane="devices">

              <div className="settings-section">
                <div className="settings-list">
                  <div className="setting-row settings-refresh-row">
                    <div>
                      <div className="setting-label">Available devices<SettingFeedback state={feedback.states.devices} /></div>
                      <div className="setting-description" id="settings-refresh-description">Find connected microphones, speakers and cameras. May request device access.</div>
                    </div>
                    <button className="action settings-refresh-button" type="button"
                      disabled={devicesLoading || feedback.busy} aria-busy={devicesLoading}
                      aria-label="Refresh media devices" aria-describedby="settings-refresh-description"
                      onClick={() => { void refreshMediaDevices(); }}>
                      {devicesLoading ? 'Loading…' : 'Refresh devices'}
                    </button>
                  </div>
                  <h3 className="settings-subsection-title">Audio</h3>
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">Microphone<SettingFeedback state={feedback.states['preferredMicId']} /></div>
                      <div className="setting-description">Default microphone for calls.</div>
                    </SettingCopy>
                    <AppSelect className="device-select" disabled={feedback.busy} label="Microphone" value={preferredMicId} onValueChange={(value) => handleDevicePreference('preferredMicId', value)} options={mediaOptions(micDevices, preferredMicId, 'Microphone')} />
                  </div>
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">Speaker<SettingFeedback state={feedback.states['preferredSpeakerId']} /></div>
                      <div className="setting-description">Default speaker for call audio output.</div>
                    </SettingCopy>
                    <AppSelect className="device-select" disabled={feedback.busy} label="Speaker" value={preferredSpeakerId} onValueChange={(value) => handleDevicePreference('preferredSpeakerId', value)} options={mediaOptions(speakerDevices, preferredSpeakerId, 'Speaker')} />
                  </div>
                  <h3 className="settings-subsection-title">Video</h3>
                  <div className="setting-row">
                    <SettingCopy>
                      <div className="setting-label">Camera<SettingFeedback state={feedback.states['preferredCameraId']} /></div>
                      <div className="setting-description">Default camera for video calls.</div>
                    </SettingCopy>
                    <AppSelect className="device-select" disabled={feedback.busy} label="Camera" value={preferredCameraId} onValueChange={(value) => handleDevicePreference('preferredCameraId', value)} options={mediaOptions(cameraDevices, preferredCameraId, 'Camera')} />
                  </div>
                </div>
              </div>
            </section>}

            {sectionId === 'privacy' && <section className="pane" data-settings-pane="privacy">

              <div className="settings-section">
                <h3 className="settings-subsection-title">Contacts</h3>
                <button className="settings-section-link" type="button" aria-label="Blocked users" onClick={() => setBlockedUsersOpen(true)}>
                  <Ban size={22} aria-hidden="true" />
                  <span className="settings-section-copy"><strong>Blocked users</strong><span>View blocked people and choose who to unblock.</span></span>
                  <ChevronRight size={20} aria-hidden="true" />
                </button>
              </div>
              <div className="settings-legal-links" role="group" aria-label="Legal documents">
                <h3 className="settings-subsection-title">Terms and privacy</h3>
                <button className="settings-section-link" type="button" onClick={() => handleOpenLegalLink(TERMS_URL)}>
                  <FileText size={22} aria-hidden="true" />
                  <span className="settings-section-copy"><strong>Terms and Conditions</strong></span>
                  <ExternalLink size={20} aria-hidden="true" />
                </button>
                <button className="settings-section-link" type="button" onClick={() => handleOpenLegalLink(PRIVACY_URL)}>
                  <ShieldCheck size={22} aria-hidden="true" />
                  <span className="settings-section-copy"><strong>Privacy Policy</strong></span>
                  <ExternalLink size={20} aria-hidden="true" />
                </button>
              </div>
              <div className="settings-local-data" role="group" aria-labelledby="settings-local-data-title">
                <h3 id="settings-local-data-title" className="settings-subsection-title">Local account data</h3>
                <div className="setting-row setting-row-destructive">
                  <div>
                    <div className="setting-label">Remove this account from this device</div>
                    <div className="setting-description">Delete this account’s local messages, files and keys, then sign out. Other accounts, shared settings and exported copies are kept. Your server account remains.</div>
                  </div>
                  <div className="settings-clear-controls">
                    <button className="danger-action" type="button" disabled={actionBusy || feedback.busy} onClick={() => openActionConfirmation('clear')}><Trash2 aria-hidden="true" /><span>Clear Data</span></button>
                  </div>
                </div>
              </div>
              <div className="settings-local-data" role="group" aria-labelledby="settings-app-reset-title">
                <h3 id="settings-app-reset-title" className="settings-subsection-title">All local Qorc data</h3>
                <div className="setting-row setting-row-destructive">
                  <div><div className="setting-label">Reset this Qorc installation</div><div className="setting-description">Delete every local account, message, attachment, encryption key, saved server and app setting. Accounts on the server and exported copies remain.</div></div>
                  <div className="settings-clear-controls">
                    <button className="danger-action" type="button" disabled={actionBusy || feedback.busy} onClick={() => openActionConfirmation('reset')}><Trash2 aria-hidden="true" /><span>Reset All Local Qorc Data</span></button>
                  </div>
                </div>
              </div>
            </section>}
            {!sectionId && <section className="account-actions settings-account-footer" aria-label="Account actions">
              <div className="settings-account-action-copy">
                <div className="account-action-controls">
                  <button className="danger-action" type="button" disabled={actionBusy || feedback.busy} onClick={() => openActionConfirmation('logout')}><LogOut aria-hidden="true" /><span>Log Out</span></button>
                </div>
              </div>
            </section>}
          </section>
        </main>

        {confirmationAction && <SettingsActionDialog
          themeClass={themeClass} busy={actionBusy} error={actionError}
          title={confirmationAction === 'logout' ? 'Log out?' : confirmationAction === 'clear' ? 'Clear this account’s local data?' : 'Reset all local Qorc data?'}
          description={confirmationAction === 'logout' ? 'Sign out of Qorc on this device. Your local messages and files will be kept.'
            : confirmationAction === 'clear' ? `Permanently delete local messages, attachments, encryption keys, saved sign-in and settings for ${displayUsername}, then sign out. Other local accounts and your account on the server remain. This cannot be undone.`
            : `Permanently delete every local account, message, attachment, encryption key, saved server and app setting. Server accounts and exported copies remain. ${android ? 'Qorc will close; reopen it to start from setup.' : 'Qorc will restart and return to setup.'} This cannot be undone.`}
          confirmLabel={confirmationAction === 'logout' ? 'Log Out' : confirmationAction === 'clear' ? 'Delete local data' : 'Reset all local data'}
          busyLabel={confirmationAction === 'logout' ? 'Logging out…' : confirmationAction === 'clear' ? 'Deleting…' : 'Resetting…'}
          onCancel={closeActionConfirmation} onConfirm={confirmAction}
        />}
        <SavedServersScreen open={savedServersOpen} onOpenChange={setSavedServersOpen} />
        {blockedUsersOpen && <StandaloneScreen open onBack={closeBlockedUsers} className="qorc-blocked-users-screen" labelledBy={blockedUsersTitleId}>
          <div className={`qorc-settings-host ${themeClass}${mobile ? ' is-mobile' : ''}`}>
            <main className="settings-screen blocked-users-screen" inert={!!unblockTarget}>
              <header className="settings-header blocked-users-header">
                <button className="settings-back" type="button" data-screen-back="" aria-label="Back to Privacy & Safety" onClick={closeBlockedUsers}>
                  <ArrowLeft size={22} aria-hidden="true" />
                </button>
                <h1 className="settings-brand" id={blockedUsersTitleId}><strong>Blocked users</strong></h1>
              </header>
              <section className="settings-content" aria-label="Blocked users list">
                <button className="settings-section-link" type="button" aria-label="Block a user" onClick={() => { setBlockedUsersOpen(false); onOpenBlockConversationChooser(); }}>
                  <Ban size={22} aria-hidden="true" />
                  <span className="settings-section-copy"><strong>Block a user</strong></span>
                  <ChevronRight size={20} aria-hidden="true" />
                </button>
                {blockedUsersError && <div className="settings-error" role="alert">{blockedUsersError}</div>}
                {blockedUsersLoading && blockedUsers.length === 0 ? (
                  <div className="blocked-empty" role="status" aria-label="Loading blocked users">
                    <LoaderCircle className="blocked-spinner" size={20} aria-hidden="true" />
                  </div>
                ) : blockedUsers.length === 0 ? (
                  !blockedUsersError && <div className="blocked-empty">
                    <div><strong>No blocked users</strong><span>Users you block will appear here.</span></div>
                  </div>
                ) : (
                  <div className="blocked-user-list">
                    {blockedUsers.map((user) => <BlockedUserRow key={user.username} user={user} loading={unblocking} onUnblock={openUnblockModal} />)}
                  </div>
                )}
              </section>
            </main>
          </div>
        </StandaloneScreen>}
        {unblockTarget && (
          <UnblockConfirmModal
            username={unblockTarget}
            busy={unblocking}
            themeClass={themeClass}
            error={blockedUsersError}
            onCancel={closeUnblockModal}
            onConfirm={confirmUnblock}
          />
        )}
      </div>
    </>
  );
});
