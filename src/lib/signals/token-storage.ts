/**
 * Secure Token Storage
 * Handles secure storage and retrieval of auth tokens
 */

import { JWT_LIKE_REGEX, TOKEN_STORAGE_KEY_BASE } from '../constants';
import { storage } from '../tauri-bindings';

class SecureTokenStorage {
  // Generate a unique key for each instance
  private static keyForInstance(): string {
    return `${TOKEN_STORAGE_KEY_BASE}:1`;
  }

  // Store tokens
  static async store(tokens: { accessToken: string; refreshToken: string }): Promise<boolean> {
    try {
      const access = typeof tokens.accessToken === 'string' ? tokens.accessToken.trim() : '';
      const refresh = typeof tokens.refreshToken === 'string' ? tokens.refreshToken.trim() : '';

      if (!access || !refresh) {
        return false;
      }

      if (!JWT_LIKE_REGEX.test(access) || !JWT_LIKE_REGEX.test(refresh)) {
        console.warn('[tokens] Attempted to store malformed tokens');
        return false;
      }

      await storage.init();
      const key = this.keyForInstance();
      const payload = JSON.stringify({ a: access, r: refresh, t: Date.now() });

      const ok = await storage.set(key, payload);
      return !!ok;
    } catch (_error) {
      console.error('[tokens] store-failed', (_error as Error).message);
      return false;
    }
  }

  // Retrieve tokens
  static async retrieve(): Promise<{ accessToken: string; refreshToken: string } | null> {
    try {
      await storage.init();
      const key = this.keyForInstance();
      const raw = await storage.get(key);

      if (!raw || typeof raw !== 'string') {
        return null;
      }

      const parsed = JSON.parse(raw);
      const access = typeof parsed?.a === 'string' ? parsed.a.trim() : '';
      const refresh = typeof parsed?.r === 'string' ? parsed.r.trim() : '';

      if (!access || !refresh) {
        return null;
      }

      return { accessToken: access, refreshToken: refresh };
    } catch (_error) {
      console.error('[tokens] retrieve-failed', (_error as Error).message);
      return null;
    }
  }

  // Clear tokens
  static async clear(): Promise<boolean> {
    try {
      await storage.init();
      const ok = await storage.remove(this.keyForInstance());
      return !!ok;
    } catch (_error) {
      console.error('[tokens] clear-failed', (_error as Error).message);
      return false;
    }
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
export async function clearAuthTokens(): Promise<void> {
  await SecureTokenStorage.clear();
}

// Clear token encryption key
export async function clearTokenEncryptionKey(): Promise<void> {
  await SecureTokenStorage.clear();
}
