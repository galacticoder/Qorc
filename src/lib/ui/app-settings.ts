import { encryptedStorage, syncEncryptedStorage } from '../database/encrypted-storage';
import { STORAGE_KEYS } from '../database/storage-keys';
import { hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import { isValidMediaDeviceId } from '../utils/calling-utils';

export type NavigationLayout = 'sidebar' | 'top';

export interface AppSettingsState {
  navigationLayout?: NavigationLayout;
  notifications?: {
    desktop: boolean;
  };
  preferredCallMicId?: string;
  preferredSpeakerId?: string;
  preferredCameraId?: string;
}

const APP_SETTINGS_KEYS = new Set([
  'navigationLayout',
  'notifications',
  'preferredCallMicId',
  'preferredSpeakerId',
  'preferredCameraId',
]);
const MAX_APP_SETTINGS_CHARS = 32 * 1024;

function validDevicePreference(value: unknown): value is string {
  return value === '' || isValidMediaDeviceId(value);
}

export function parseAppSettings(raw: unknown): AppSettingsState {
  if (raw === null) return {};
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_APP_SETTINGS_CHARS) {
    throw new Error('Invalid application settings');
  }
  const parsed: unknown = JSON.parse(raw);
  if (
    !isPlainObject(parsed) ||
    hasPrototypePollutionKeys(parsed) ||
    Object.keys(parsed).some((key) => !APP_SETTINGS_KEYS.has(key))
  ) {
    throw new Error('Invalid application settings');
  }
  if (
    parsed.navigationLayout !== undefined &&
    parsed.navigationLayout !== 'sidebar' &&
    parsed.navigationLayout !== 'top'
  ) {
    throw new Error('Invalid navigation layout setting');
  }
  if (parsed.notifications !== undefined) {
    if (
      !isPlainObject(parsed.notifications) ||
      hasPrototypePollutionKeys(parsed.notifications) ||
      Object.keys(parsed.notifications).length !== 1 ||
      typeof parsed.notifications.desktop !== 'boolean'
    ) {
      throw new Error('Invalid notification setting');
    }
  }
  for (const key of ['preferredCallMicId', 'preferredSpeakerId', 'preferredCameraId'] as const) {
    if (parsed[key] !== undefined && !validDevicePreference(parsed[key])) {
      throw new Error('Invalid media device setting');
    }
  }
  return { ...parsed } as AppSettingsState;
}

export function readAppSettings(): AppSettingsState {
  return parseAppSettings(syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS));
}

export function updateAppSettings(updates: Partial<AppSettingsState>): AppSettingsState {
  const next = { ...readAppSettings(), ...updates };
  const serialized = JSON.stringify(next);
  parseAppSettings(serialized);
  syncEncryptedStorage.setItem(STORAGE_KEYS.APP_SETTINGS, serialized);
  return next;
}

export async function readAppSettingsAsync(): Promise<AppSettingsState> {
  return parseAppSettings(await encryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS));
}

export async function updateAppSettingsAsync(updates: Partial<AppSettingsState>): Promise<AppSettingsState> {
  const next = { ...await readAppSettingsAsync(), ...updates };
  const serialized = JSON.stringify(next);
  parseAppSettings(serialized);
  await encryptedStorage.setItem(STORAGE_KEYS.APP_SETTINGS, serialized);
  return next;
}
