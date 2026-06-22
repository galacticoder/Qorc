import { storage } from '../tauri-bindings';

const EXPLICIT_LOGOUT_KEY = 'qor_explicit_logout_v1';

export async function markExplicitLogout(): Promise<void> {
  try {
    await storage.init();
    await storage.set(EXPLICIT_LOGOUT_KEY, String(Date.now()));
  } catch {
    try {
      localStorage.setItem(EXPLICIT_LOGOUT_KEY, String(Date.now()));
    } catch { }
  }
}

export async function clearExplicitLogout(): Promise<void> {
  try {
    await storage.init();
    await storage.remove(EXPLICIT_LOGOUT_KEY);
  } catch { }

  try {
    localStorage.removeItem(EXPLICIT_LOGOUT_KEY);
  } catch { }
}

export async function isExplicitlyLoggedOut(): Promise<boolean> {
  try {
    await storage.init();
    const value = await storage.get(EXPLICIT_LOGOUT_KEY);
    if (typeof value === 'string' && value.length > 0) {
      return true;
    }
  } catch { }

  try {
    return !!localStorage.getItem(EXPLICIT_LOGOUT_KEY);
  } catch {
    return false;
  }
}
