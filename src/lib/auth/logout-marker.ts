import { storage } from '../tauri-bindings';
import { STORAGE_KEYS } from '../database/storage-keys';

export async function markExplicitLogout(): Promise<void> {
  const marker = String(Date.now());
  try {
    if (
      await storage.set(STORAGE_KEYS.EXPLICIT_LOGOUT, marker) !== true ||
      await storage.get(STORAGE_KEYS.EXPLICIT_LOGOUT) !== marker
    ) throw new Error('Logout marker verification failed');
  } catch {
    throw new Error('Explicit logout marker could not be persisted');
  }
}

export async function clearExplicitLogout(): Promise<void> {
  try {
    if (!await storage.remove(STORAGE_KEYS.EXPLICIT_LOGOUT)) {
      throw new Error('Logout marker removal failed');
    }
    if (await storage.get(STORAGE_KEYS.EXPLICIT_LOGOUT) !== null) {
      throw new Error('Logout marker verification failed');
    }
  } catch {
    throw new Error('Explicit logout marker could not be cleared');
  }
}

export async function isExplicitlyLoggedOut(): Promise<boolean> {
  const value = await storage.get(STORAGE_KEYS.EXPLICIT_LOGOUT);
  if (value === null) return false;
  if (!/^[1-9][0-9]{0,15}$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new Error('Explicit logout marker is invalid');
  }
  return true;
}
