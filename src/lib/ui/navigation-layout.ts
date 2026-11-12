import { EventType } from '../types/event-types';
import { readAppSettings, updateAppSettings, updateAppSettingsConfirmed } from './app-settings';
import { isAndroidPlatform } from '../runtime/platform';

export type NavigationLayout = 'sidebar' | 'top';

export const readNavigationLayout = (): NavigationLayout => {
  return readAppSettings().navigationLayout ?? (isAndroidPlatform() ? 'top' : 'sidebar');
};

export const writeNavigationLayout = (layout: NavigationLayout): void => {
  updateAppSettings({ navigationLayout: layout });
  window.dispatchEvent(new CustomEvent(EventType.NAVIGATION_LAYOUT_CHANGED, { detail: { layout } }));
};

export const writeNavigationLayoutConfirmed = async (layout: NavigationLayout): Promise<void> => {
  await updateAppSettingsConfirmed({ navigationLayout: layout });
  window.dispatchEvent(new CustomEvent(EventType.NAVIGATION_LAYOUT_CHANGED, { detail: { layout } }));
};
