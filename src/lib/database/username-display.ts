import { SecureDB } from './secureDB';
import { pseudonymizeUsernameWithCache } from './username-hash';
import { UsernameDisplayConfiguration } from './unified-username-display';
import { sanitizeUsernameInput } from '../utils/username-utils';

// Store a mapping from pseudonym to original username
export async function storeUsernameMapping(
  originalUsername: string,
  secureDB: SecureDB
): Promise<void> {
  const sanitizedOriginal = sanitizeUsernameInput(originalUsername);

  if (!sanitizedOriginal) {
    return;
  }

  try {
    const pseudonym = await pseudonymizeUsernameWithCache(sanitizedOriginal, secureDB);
    await secureDB.storeUsernameMapping(pseudonym, sanitizedOriginal);
  } catch { }
}

// Resolve a username for display preferring original names over pseudonyms
export async function getDisplayUsername(
  username: string,
  secureDB: SecureDB,
  currentUserOriginal?: string
): Promise<string> {
  const sanitized = sanitizeUsernameInput(username);
  const config = UsernameDisplayConfiguration.get();
  let result = sanitized;

  if (!sanitized || sanitized.length > config.maxUsernameLength) {
    return 'Unknown User';
  }

  try {
    if (currentUserOriginal) {
      const cachedHash = await secureDB.getCachedUsernameHash(currentUserOriginal);
      if (cachedHash && sanitized === cachedHash) {
        result = currentUserOriginal;
        return result;
      }
    }

    // Try to get the original username from the mapping
    const originalUsername = await secureDB.getOriginalUsername(sanitized);
    if (originalUsername && typeof originalUsername === 'string') {
      result = originalUsername;
      return result;
    }

    return result;
  } catch { return result; }
}

// Username display helper
export class UsernameDisplayContext {
  private readonly cache = new Map<string, { value: string; timestamp: number }>();
  private readonly pendingRequests = new Map<string, Promise<string>>();
  
  constructor(
    private secureDB: SecureDB,
    private currentUserOriginal?: string
  ) {}

  // Get display username
  async getDisplayUsername(username: string): Promise<string> {
    const sanitized = sanitizeUsernameInput(username);
    const config = UsernameDisplayConfiguration.get();

    if (!sanitized || sanitized.length > config.maxUsernameLength) {
      return 'Unknown User';
    }

    const cached = this.cache.get(sanitized);
    const now = Date.now();
    if (cached && now - cached.timestamp < config.cacheTTL) {
      return cached.value;
    }

    if (cached) {
      this.cache.delete(sanitized);
    }

    if (this.pendingRequests.has(sanitized)) {
      return this.pendingRequests.get(sanitized)!;
    }

    const request = (async () => {
      try {
        const result = await getDisplayUsername(sanitized, this.secureDB, this.currentUserOriginal);
        this.cache.set(sanitized, { value: result, timestamp: Date.now() });
        this.evictIfNeeded();
        return result;
      } catch {
        const fallback = sanitized;
        this.cache.set(sanitized, { value: fallback, timestamp: Date.now() });
        this.evictIfNeeded();
        return fallback;
      } finally {
        this.pendingRequests.delete(sanitized);
      }
    })();

    this.pendingRequests.set(sanitized, request);
    return request;
  }

  // Get display usernames
  async getDisplayUsernames(usernames: string[]): Promise<Map<string, string>> {
    const results = new Map<string, string>();

    if (!Array.isArray(usernames) || usernames.length === 0) {
      return results;
    }

    const config = UsernameDisplayConfiguration.get();
    const limit = Math.max(1, config.concurrentResolutionLimit);

    for (let i = 0; i < usernames.length; i += limit) {
      const chunk = usernames.slice(i, i + limit);
      await Promise.allSettled(
        chunk.map(async (username) => {
          try {
            results.set(username, await this.getDisplayUsername(username));
          } catch {
            results.set(username, 'Unknown User');
          }
        })
      );
    }

    return results;
  }

  // Preload usernames
  async preloadUsernames(usernames: string[]): Promise<void> {
    if (Array.isArray(usernames) && usernames.length > 0) {
      try {
        await this.getDisplayUsernames(usernames);
      } catch {
      }
    }
  }
  
  // Clear cache
  clearCache(): void {
    this.cache.clear();
    this.pendingRequests.clear();
  }

  // Evict oldest entries if cache exceeds size limit
  private evictIfNeeded(): void {
    const { cacheSize } = UsernameDisplayConfiguration.get();
    while (this.cache.size > cacheSize) {
      const oldestKey = this.cache.keys().next().value;
      if (!oldestKey) break;
      this.cache.delete(oldestKey);
    }
  }
}
