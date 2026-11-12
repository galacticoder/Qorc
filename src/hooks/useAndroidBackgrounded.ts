import { useSyncExternalStore } from 'react';
import { isAndroidPlatform } from '../lib/runtime/platform';

const snapshot = () => isAndroidPlatform() && (document.visibilityState === 'hidden' || !document.hasFocus());
const subscribe = (notify: () => void) => {
  document.addEventListener('visibilitychange', notify);
  window.addEventListener('focus', notify);
  window.addEventListener('blur', notify);
  return () => {
    document.removeEventListener('visibilitychange', notify);
    window.removeEventListener('focus', notify);
    window.removeEventListener('blur', notify);
  };
};

export const useAndroidBackgrounded = () => useSyncExternalStore(subscribe, snapshot, () => false);
