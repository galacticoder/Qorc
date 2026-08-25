import { useEffect, useRef, useState } from 'react';

type IdleCallback = (callback: () => void, options?: { timeout: number }) => number;
type CancelIdleCallback = (handle: number) => void;

export function usePrefetchedComponent<T>(load: () => Promise<T>, enabled: boolean = true): T | null {
  const [component, setComponent] = useState<T | null>(null);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    if (!enabled || component) return;
    let cancelled = false;

    const run = () => {
      void loadRef.current()
        .then((loaded) => {
          if (!cancelled) setComponent(() => loaded);
        })
        .catch(() => { });
    };

    const requestIdle = (window as unknown as { requestIdleCallback?: IdleCallback }).requestIdleCallback;
    const cancelIdle = (window as unknown as { cancelIdleCallback?: CancelIdleCallback }).cancelIdleCallback;
    const handle = requestIdle ? requestIdle(run, { timeout: 1500 }) : window.setTimeout(run, 200);

    return () => {
      cancelled = true;
      if (requestIdle && cancelIdle) cancelIdle(handle);
      else window.clearTimeout(handle);
    };
  }, [enabled, component]);

  return component;
}
