import { useSyncExternalStore } from 'react';

const listeners = new Set<() => void>();
let media: MediaQueryList | undefined;

const getSnapshot = () => Math.min(4, Math.max(0.5, window.devicePixelRatio || 1));

function watchResolution(): void {
  media?.removeEventListener('change', update);
  media = window.matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`);
  media.addEventListener('change', update);
}

function update(): void {
  watchResolution();
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  if (listeners.size === 1) {
    watchResolution();
    window.addEventListener('resize', update);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      media?.removeEventListener('change', update);
      media = undefined;
      window.removeEventListener('resize', update);
    }
  };
}

export function useDevicePixelRatio(): number {
  return useSyncExternalStore(subscribe, getSnapshot, () => 1);
}
