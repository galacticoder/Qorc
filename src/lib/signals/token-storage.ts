/**
 * Secure Token Storage
 * Handles secure storage and retrieval of auth tokens
 */

import { BASE64_URLSAFE_REGEX, TOKEN_STORAGE_KEY_BASE } from '../constants';
import { storage } from '../tauri-bindings';

class SecureTokenStorage {
  // Generate a unique key for each instance
  private static keyForInstance(): string {
    return `${TOKEN_STORAGE_KEY_BASE}:v3`;
  }

  // Store anonymous session token
  static async store(token: string): Promise<boolean> {
    try {
      const trimmedToken = typeof token === 'string' ? token.trim() : '';

      if (!trimmedToken) {
        return false;
      }

      if (!BASE64_URLSAFE_REGEX.test(trimmedToken)) {
        return false;
      }

      await storage.init();
      const key = this.keyForInstance();
      const payload = JSON.stringify({ a: trimmedToken, t: Date.now() });

      const ok = await storage.set(key, payload);
      return !!ok;
    } catch (_error) {
      console.error('[tokens] store-failed', (_error as Error).message);
      return false;
    }
  }

  // Retrieve anonymous session token
  static async retrieve(): Promise<string | null> {
    try {
      await storage.init();
      const key = this.keyForInstance();
      const raw = await storage.get(key);

      if (!raw || typeof raw !== 'string') {
        return null;
      }

      const parsed = JSON.parse(raw);
      const token = typeof parsed?.a === 'string' ? parsed.a.trim() : '';

      if (!token) {
        return null;
      }

      return token;
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

/**
 * Persist anonymous session token
 */
export async function persistAuthTokens(token: any): Promise<boolean> {
  const tokenString = typeof token === 'string' ? token : null;
  if (!tokenString) return false;
  return await SecureTokenStorage.store(tokenString);
}

/**
 * Retrieve anonymous session token
 */
export async function retrieveAuthTokens(): Promise<string | null> {
  const token = await SecureTokenStorage.retrieve();
  if (!token) return null;
  return token;
}

/**
 * Clear stored auth tokens
 */
export async function clearAuthTokens(): Promise<void> {
  await SecureTokenStorage.clear();
}

/**
 * Clear token encryption key
 */
export async function clearTokenEncryptionKey(): Promise<void> {
  await SecureTokenStorage.clear();
}
