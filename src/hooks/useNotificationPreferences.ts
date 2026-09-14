import { useMemo, useSyncExternalStore } from 'react';
import {
  notificationPreferencesSnapshot,
  parseNotificationPreferences,
  subscribeNotificationPreferences,
} from '../lib/ui/notification-preferences';

export function useNotificationPreferences() {
  const raw = useSyncExternalStore(subscribeNotificationPreferences, notificationPreferencesSnapshot, () => null);
  return useMemo(() => parseNotificationPreferences(raw), [raw]);
}
