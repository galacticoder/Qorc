import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { STORAGE_KEYS } from '../../lib/database/storage-keys';
import { getInstanceLocalStorageItem, setInstanceLocalStorageItem } from '../../lib/runtime/instance-storage';
import { websocket } from '../../lib/tauri-bindings';
import { FullscreenSpinner } from '../ui/FullscreenSpinner';
import { AppIntroduction } from './AppIntroduction';

export function FirstRunGate({ children }: { readonly children: ReactNode }) {
  const [state, setState] = useState<'checking' | 'introduction' | 'ready'>('checking');

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const completed = await getInstanceLocalStorageItem(STORAGE_KEYS.INTRO_COMPLETED);
      if (cancelled) return;
      if (completed === 'true') {
        setState('ready');
        return;
      }

      const serverUrl = await websocket.getServerUrl();
      if (cancelled) return;
      if (serverUrl) {
        setState('ready');
        await setInstanceLocalStorageItem(STORAGE_KEYS.INTRO_COMPLETED, 'true');
      } else {
        setState('introduction');
      }
    })().catch(() => {
      
      console.warn('[Introduction] Could not read the local introduction preference');
      if (!cancelled) setState('ready');
    });
    return () => { cancelled = true; };
  }, []);

  const completeIntroduction = useCallback(async () => {
    try {
      await setInstanceLocalStorageItem(STORAGE_KEYS.INTRO_COMPLETED, 'true');
    } catch {
      console.warn('[Introduction] Could not save the local introduction preference');
    }
    setState('ready');
  }, []);

  if (state === 'checking') return <FullscreenSpinner />;
  if (state === 'introduction') return <AppIntroduction onComplete={completeIntroduction} />;
  return children;
}
