/**
 * Secure Token Storage
 *
 * Purges the legacy stable session-token store. A single long-lived session token, replayed on every
 * reconnect, let the server link all of a client's reconnects — so it is gone. Autologin now uses a
 * pool of one-time anonymous (Privacy Pass) tokens redeemed unlinkably instead (see ./resume-tokens).
 * These helpers only clear any lingering legacy token so a plaintext token never persists.
 */

import { TOKEN_STORAGE_KEY_BASE } from '../constants';
import { storage } from '../tauri-bindings';

class SecureTokenStorage {
  private static keyForInstance(): string {
    return `${TOKEN_STORAGE_KEY_BASE}:v3`;
  }

  // Clear any stored (legacy) token
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
