import { useSyncExternalStore } from 'react';
import { isAndroidPlatform } from '../lib/runtime/platform';

const query = '(max-width: 760px)';
const getSnapshot = () => isAndroidPlatform() || window.matchMedia(query).matches;
const subscribe = (onChange: () => void) => {
  const media = window.matchMedia(query);
  media.addEventListener('change', onChange);
  return () => media.removeEventListener('change', onChange);
};

export const useMobileLayout = () => useSyncExternalStore(subscribe, getSnapshot, () => false);
