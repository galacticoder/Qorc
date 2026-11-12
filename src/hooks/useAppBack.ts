import { useEffect, useLayoutEffect, useRef } from 'react';
import { registerAndroidBackHandler } from '../lib/runtime/android-back';
import { isAndroidPlatform } from '../lib/runtime/platform';

export function useAppBack(enabled: boolean, onBack: () => boolean | void, priority = 0): void {
  const callback = useRef(onBack);
  useLayoutEffect(() => { callback.current = onBack; });
  useEffect(() => {
    if (!enabled || !isAndroidPlatform()) return;
    return registerAndroidBackHandler(() => callback.current() !== false, priority);
  }, [enabled, priority]);
}
