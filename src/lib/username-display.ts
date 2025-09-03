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
  // If this is the current user and we have their original username, use it
  if (currentUserOriginal) {
    try {
      const cachedHash = await secureDB.getCachedUsernameHash(currentUserOriginal);
      if (username === cachedHash) {
        return currentUserOriginal;
      }
    } catch (error) {
      console.error('Failed to get cached username hash:', error);
      // Continue with normal lookup
    }
  }
  
  // Try to get the original username from the mapping
  const originalUsername = await secureDB.getOriginalUsername(username);
  if (originalUsername) {
    return originalUsername;
  }
  
  // Fallback to the hash if no mapping exists
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
      return this.cache.get(username)!;
    }
    
    // Get display name and cache it
    const displayName = await getDisplayUsername(username, this.secureDB, this.currentUserOriginal);
    this.cache.set(username, displayName);
    return displayName;
  }
  
  clearCache(): void {
    this.cache.clear();
  }
}
