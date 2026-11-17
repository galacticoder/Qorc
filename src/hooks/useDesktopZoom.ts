import { useEffect } from 'react';
import { isTauri } from '@tauri-apps/api/core';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { isAndroidPlatform } from '../lib/runtime/platform';

export function useDesktopZoom(mainScreenVisible: boolean): void {
  useEffect(() => {
    if (isAndroidPlatform() || !isTauri()) return;
    void getCurrentWebview().setZoom(mainScreenVisible ? 1.75 : 1.3).catch(error => {
      console.error('[Display] Could not update desktop zoom', error);
    });
  }, [mainScreenVisible]);
}
