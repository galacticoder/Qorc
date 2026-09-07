import { EventType } from '../types/event-types';
import { readAppSettings, updateAppSettings } from './app-settings';

export type NavigationLayout = 'sidebar' | 'top';

export const readNavigationLayout = (): NavigationLayout => {
  return readAppSettings().navigationLayout ?? 'sidebar';
};

export const writeNavigationLayout = (layout: NavigationLayout): void => {
  updateAppSettings({ navigationLayout: layout });
  window.dispatchEvent(new CustomEvent(EventType.NAVIGATION_LAYOUT_CHANGED, { detail: { layout } }));
};
