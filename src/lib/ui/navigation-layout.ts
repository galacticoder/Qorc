import { syncEncryptedStorage } from '../database/encrypted-storage';
import { STORAGE_KEYS } from '../database/storage-keys';
import { hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import { EventType } from '../types/event-types';

export type NavigationLayout = 'sidebar' | 'top';

export const readNavigationLayout = (): NavigationLayout => {
  try {
    const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
    if (!stored) return 'sidebar';
    const parsed = JSON.parse(stored);
    if (!isPlainObject(parsed) || hasPrototypePollutionKeys(parsed)) return 'sidebar';
    return parsed.navigationLayout === 'top' ? 'top' : 'sidebar';
  } catch {
    return 'sidebar';
  }
};

export const writeNavigationLayout = (layout: NavigationLayout): void => {
  const stored = syncEncryptedStorage.getItem(STORAGE_KEYS.APP_SETTINGS);
  let settings: Record<string, unknown> = {};
  if (stored) {
    const parsed = JSON.parse(stored);
    if (isPlainObject(parsed) && !hasPrototypePollutionKeys(parsed)) settings = parsed;
  }
  syncEncryptedStorage.setItem(
    STORAGE_KEYS.APP_SETTINGS,
    JSON.stringify({ ...settings, navigationLayout: layout }),
  );
  window.dispatchEvent(new CustomEvent(EventType.NAVIGATION_LAYOUT_CHANGED, { detail: { layout } }));
};
