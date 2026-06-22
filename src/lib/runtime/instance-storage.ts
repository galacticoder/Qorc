import { isTauri, system } from '@/lib/tauri-bindings';

const STORAGE_PREFIX = 'qor:v1';
const FALLBACK_INSTANCE_ID = 'browser';

let cachedInstanceId: string | null = null;
let instanceIdPromise: Promise<string> | null = null;

function sanitizeInstanceId(value: unknown): string {
  const raw = typeof value === 'string' ? value.trim() : '';
  if (!raw) return FALLBACK_INSTANCE_ID;
  return raw.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 80) || FALLBACK_INSTANCE_ID;
}

function readInstanceIdFromWindow(): string | null {
  try {
    const value = (globalThis as any).__QOR_INSTANCE_ID;
    return typeof value === 'string' && value.trim() ? sanitizeInstanceId(value) : null;
  } catch {
    return null;
  }
}

function readInstanceIdFromUrl(): string | null {
  try {
    const params = new URLSearchParams(globalThis.location?.search || '');
    const value = params.get('qorInstanceId') || params.get('instanceId');
    return value ? sanitizeInstanceId(value) : null;
  } catch {
    return null;
  }
}

function cacheInstanceId(value: string): string {
  const sanitized = sanitizeInstanceId(value);
  cachedInstanceId = sanitized;
  try {
    (globalThis as any).__QOR_INSTANCE_ID = sanitized;
  } catch { }
  return sanitized;
}

export function getCachedInstanceId(): string {
  if (cachedInstanceId) return cachedInstanceId;
  return cacheInstanceId(readInstanceIdFromWindow() || readInstanceIdFromUrl() || FALLBACK_INSTANCE_ID);
}

export async function getAppInstanceId(): Promise<string> {
  if (cachedInstanceId) return cachedInstanceId;
  if (!instanceIdPromise) {
    instanceIdPromise = (async () => {
      const urlInstanceId = readInstanceIdFromUrl();
      if (urlInstanceId) return cacheInstanceId(urlInstanceId);

      if (isTauri()) {
        try {
          return cacheInstanceId(await system.getInstanceId());
        } catch { }
      }

      return cacheInstanceId(readInstanceIdFromWindow() || FALLBACK_INSTANCE_ID);
    })().finally(() => {
      instanceIdPromise = null;
    });
  }
  return instanceIdPromise;
}

export async function instanceLocalStorageKey(key: string): Promise<string> {
  return `${STORAGE_PREFIX}:instance:${await getAppInstanceId()}:${key}`;
}

export function instanceLocalStorageKeySync(key: string): string {
  return `${STORAGE_PREFIX}:instance:${getCachedInstanceId()}:${key}`;
}

export async function getInstanceLocalStorageItem(key: string): Promise<string | null> {
  return localStorage.getItem(await instanceLocalStorageKey(key));
}

export async function setInstanceLocalStorageItem(key: string, value: string): Promise<void> {
  localStorage.setItem(await instanceLocalStorageKey(key), value);
}

export async function removeInstanceLocalStorageItem(key: string): Promise<void> {
  localStorage.removeItem(await instanceLocalStorageKey(key));
}

