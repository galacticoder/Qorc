import { SecureDB } from './secureDB';
import { pseudonymizeUsernameWithCache } from './username-hash';

/**
 * Store a username mapping if we know the original username
 */
export async function storeUsernameMapping(
  originalUsername: string,
  secureDB: SecureDB
): Promise<void> {
  try {
    const pseudonym = await pseudonymizeUsernameWithCache(originalUsername);
    await secureDB.storeUsernameMapping(pseudonym, originalUsername);
    console.log(`[storeUsernameMapping] Stored mapping: ${pseudonym} -> ${originalUsername}`);
  } catch (error) {
    console.error('[storeUsernameMapping] Failed to store mapping:', error);
  }
}

/**
 * Get the display name for a username (original if available, hash as fallback)
 */
export async function getDisplayUsername(
  username: string,
  secureDB: SecureDB,
  currentUserOriginal?: string
): Promise<string> {
  console.log('[getDisplayUsername] Looking up:', username, 'currentUserOriginal:', currentUserOriginal);

  // If this is the current user and we have their original username, use it
  if (currentUserOriginal) {
    try {
      const cachedHash = await secureDB.getCachedUsernameHash(currentUserOriginal);
      console.log('[getDisplayUsername] Current user hash check:', username, 'vs', cachedHash);
      if (username === cachedHash) {
        console.log('[getDisplayUsername] Matched current user, returning:', currentUserOriginal);
        return currentUserOriginal;
      }
    } catch (error) {
      console.error('[getDisplayUsername] Failed to get cached username hash:', error);
      // Continue with normal lookup
    }
  }

  // Try to get the original username from the mapping
  console.log('[getDisplayUsername] Checking mapping for:', username);
  const originalUsername = await secureDB.getOriginalUsername(username);
  console.log('[getDisplayUsername] Mapping result:', username, '->', originalUsername);
  if (originalUsername) {
    return originalUsername;
  }

  // Fallback to the hash if no mapping exists
  console.log('[getDisplayUsername] No mapping found, returning hash:', username);
  return username;
}

/**
 * Create a username display context for efficient batch lookups
 */
export class UsernameDisplayContext {
  private cache = new Map<string, string>();
  
  constructor(
    private secureDB: SecureDB,
    private currentUserOriginal?: string
  ) {}
  
  async getDisplayUsername(username: string): Promise<string> {
    // Check cache first
    if (this.cache.has(username)) {
      console.log('[UsernameDisplayContext] Cache hit for:', username, '->', this.cache.get(username));
      return this.cache.get(username)!;
    }

    console.log('[UsernameDisplayContext] Cache miss, resolving:', username);
    // Get display name and cache it
    const displayName = await getDisplayUsername(username, this.secureDB, this.currentUserOriginal);
    console.log('[UsernameDisplayContext] Resolved:', username, '->', displayName);
    this.cache.set(username, displayName);
    return displayName;
  }
  
  clearCache(): void {
    this.cache.clear();
  }
}
