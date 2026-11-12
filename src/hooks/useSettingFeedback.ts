import { useCallback, useEffect, useRef, useState } from 'react';

export interface SettingFeedbackState {
  status: 'error';
  message: string;
}

export function useSettingFeedback() {
  const [states, setStates] = useState<Record<string, SettingFeedbackState>>({});
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const clear = useCallback((id: string) => {
    if (mounted.current) setStates(previous => {
      const next = { ...previous };
      delete next[id];
      return next;
    });
  }, []);

  const fail = useCallback((id: string, message: string) => {
    clear(id);
    if (mounted.current) setStates(previous => ({ ...previous, [id]: { status: 'error', message } }));
  }, [clear]);

  const run = useCallback(async (
    id: string,
    operation: (isCurrent: () => boolean) => void | boolean | Promise<void | boolean>,
    errorMessage = 'Could not save. Please try again.',
  ): Promise<boolean> => {
    
    if (pending.current || !mounted.current) return false;
    pending.current = true;
    clear(id);
    setBusy(true);
    try {
      const result = await operation(() => mounted.current);
      return result !== false;
    } catch {
      fail(id, errorMessage);
      return false;
    } finally {
      pending.current = false;
      if (mounted.current) setBusy(false);
    }
  }, [clear, fail]);

  return { states, busy, run, fail };
}
