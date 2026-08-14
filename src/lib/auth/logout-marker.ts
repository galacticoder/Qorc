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
    await storage.remove(STORAGE_KEYS.EXPLICIT_LOGOUT);
    if (await storage.get(STORAGE_KEYS.EXPLICIT_LOGOUT) !== null) {
      throw new Error('Logout marker verification failed');
    }
  } catch {
    throw new Error('Explicit logout marker could not be cleared');
  }
}

export async function isExplicitlyLoggedOut(): Promise<boolean> {
  try {
    const value = await storage.get(STORAGE_KEYS.EXPLICIT_LOGOUT);
    if (typeof value === 'string' && value.length > 0) {
      return true;
    }
  } catch {
    return true;
  }

  return false;
}
