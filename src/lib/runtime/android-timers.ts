import { invoke } from '@tauri-apps/api/core';
import { isAndroidPlatform } from './platform';
import { installBackgroundTimers } from './background-timers';

if (isAndroidPlatform() && '__TAURI_INTERNALS__' in window) {
  installBackgroundTimers(window, document, {
    open: async () => (await invoke<{ clockId: number }>('android_runtime_wait', {
      clockId: null, sequence: 0, delayMs: 0,
    })).clockId,
    wait: async (clockId, sequence, delayMs) => (await invoke<{ fired: boolean }>('android_runtime_wait', {
      clockId, sequence, delayMs,
    })).fired,
  }, undefined, error => {
    if (typeof window.reportError === 'function') window.reportError(error);
    else void Promise.reject(error);
  });
}
