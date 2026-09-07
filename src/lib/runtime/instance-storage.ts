import { system } from '@/lib/tauri-bindings';
import { STORAGE_PREFIXES } from '@/lib/database/storage-keys';

let cachedInstanceId: string | null = null;
let instanceIdPromise: Promise<string> | null = null;

function validateInstanceId(value: unknown): string {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!/^[a-zA-Z0-9_.-]{1,80}$/.test(raw)) {
    throw new Error('Native application instance identifier is invalid');
  }
  return raw;
}

function cacheInstanceId(value: string): string {
  const instanceId = validateInstanceId(value);
  cachedInstanceId = instanceId;
  return instanceId;
}

export async function getAppInstanceId(): Promise<string> {
  if (cachedInstanceId) return cachedInstanceId;
  if (!instanceIdPromise) {
    instanceIdPromise = system.getInstanceId().then(cacheInstanceId).finally(() => {
      instanceIdPromise = null;
    });
  }
  return instanceIdPromise;
}

export async function instanceLocalStorageKey(key: string): Promise<string> {
  return `${STORAGE_PREFIXES.INSTANCE}:instance:${await getAppInstanceId()}:${key}`;
}

export async function getInstanceLocalStorageItem(key: string): Promise<string | null> {
  return localStorage.getItem(await instanceLocalStorageKey(key));
}

export async function setInstanceLocalStorageItem(key: string, value: string): Promise<void> {
  localStorage.setItem(await instanceLocalStorageKey(key), value);
}
