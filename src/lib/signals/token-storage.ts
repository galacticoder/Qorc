/**
 * Secure Token Storage
 * Handles secure storage and retrieval of auth tokens
 */

import { JWT_LIKE_REGEX, TOKEN_STORAGE_KEY_BASE } from '../constants';

class SecureTokenStorage {
  // Generate a unique key for each instance
  private static keyForInstance(): string {
    try {
      const id = (window as any).electronAPI?.instanceId;
      const suffix = typeof id === 'string' || typeof id === 'number' ? String(id) : '1';
      return `${TOKEN_STORAGE_KEY_BASE}:${suffix}`;
    } catch {
      return `${TOKEN_STORAGE_KEY_BASE}:1`;
    }
  }

  // Store tokens
  static async store(tokens: { accessToken: string; refreshToken: string }): Promise<boolean> {
    try {
      const access = typeof tokens.accessToken === 'string' ? tokens.accessToken.trim() : '';
      const refresh = typeof tokens.refreshToken === 'string' ? tokens.refreshToken.trim() : '';

      if (!access || !refresh) return false;

      if (!JWT_LIKE_REGEX.test(access) || !JWT_LIKE_REGEX.test(refresh)) {
        return false;
      }

      const api = (window as any).electronAPI;
      if (!api?.secureStore?.set) return false;

      await api.secureStore.init?.();
      const ok = await api.secureStore.set(
        this.keyForInstance(),
        JSON.stringify({ a: access, r: refresh, t: Date.now() })
      );
      return !!ok;
    } catch (_error) {
      console.error('[tokens] store-failed', (_error as Error).message);
      return false;
    }
  }

  // Retrieve tokens
  static async retrieve(): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
      const api = (window as any).electronAPI;
      if (!api?.secureStore?.get) return null;

      await api.secureStore.init?.();

      const raw = await api.secureStore.get(this.keyForInstance());
      if (!raw || typeof raw !== 'string') return null;

      const parsed = JSON.parse(raw);
      const access = typeof parsed?.a === 'string' ? parsed.a.trim() : '';
      const refresh = typeof parsed?.r === 'string' ? parsed.r.trim() : '';

      if (!access || !refresh) return null;

      return { accessToken: access, refreshToken: refresh };
    } catch (_error) {
      console.error('[tokens] retrieve-failed', (_error as Error).message);
      return null;
    }
  }

  // Clear tokens
  static clear(): void {
    try {
      (window as any).electronAPI?.secureStore?.remove?.(this.keyForInstance());
    } catch { }
  }
}

// Persist tokens
export async function persistAuthTokens(tokens: {
  accessToken: string;
  refreshToken: string;
}): Promise<boolean> {
  return await SecureTokenStorage.store(tokens);
}

// Retrieve tokens
export async function retrieveAuthTokens(): Promise<{ accessToken: string; refreshToken: string } | null> {
  return await SecureTokenStorage.retrieve();
}

// Clear tokens
export function clearAuthTokens(): void {
  SecureTokenStorage.clear();
}

// Clear token encryption key
export function clearTokenEncryptionKey(): void {
  SecureTokenStorage.clear();
}
