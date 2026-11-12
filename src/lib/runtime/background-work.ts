import { invoke } from '@tauri-apps/api/core';
import { isAndroidPlatform } from './platform';

type NativeWork = {
  begin: () => Promise<string>;
  end: (id: string) => Promise<unknown>;
};

export async function acquireBackgroundWork(native: NativeWork, signal?: AbortSignal): Promise<() => Promise<void>> {
  let id = '';
  let released = false;
  const end = async () => {
    const current = id;
    id = '';
    if (current) await native.end(current).catch(error => console.warn('[Background work] Release failed', error));
  };
  const release = async () => {
    released = true;
    signal?.removeEventListener('abort', onAbort);
    await end();
  };
  const onAbort = () => { void release(); };
  if (signal?.aborted) return release;
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    id = await native.begin();
    if (released || signal?.aborted) await release();
  } catch (error) {
    await release();
    console.warn('[Background work] Android could not protect this operation', error);
  }
  return release;
}

export function beginBackgroundWork(signal?: AbortSignal): Promise<() => Promise<void>> {
  if (!isAndroidPlatform()) return Promise.resolve(async () => {});
  return acquireBackgroundWork({
    begin: () => invoke<string>('android_runtime_work_begin'),
    end: id => invoke('android_runtime_work_end', { id }),
  }, signal);
}
