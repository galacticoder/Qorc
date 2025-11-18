import { SecureDB } from './secureDB';
import { pseudonymizeUsernameWithCache } from './username-hash';
import {
  UsernameDisplayConfiguration,
  recordUsernameResolutionEvent,
  sanitizeUsernameInput
} from './unified-username-display';

/**
 * Persist a mapping from pseudonym to original username when available.
 */
export async function storeUsernameMapping(
  originalUsername: string,
  secureDB: SecureDB
): Promise<void> {
  const startTime = Date.now();
  const sanitizedOriginal = sanitizeUsernameInput(originalUsername);
  let success = false;

  if (!sanitizedOriginal) {
    recordUsernameResolutionEvent('ensure-mapping', originalUsername, 'Unknown User', Date.now() - startTime, false);
    return;
  }

  try {
    const pseudonym = await pseudonymizeUsernameWithCache(sanitizedOriginal, secureDB);
    await secureDB.storeUsernameMapping(pseudonym, sanitizedOriginal);
    success = true;
  } catch {
  } finally {
    recordUsernameResolutionEvent('ensure-mapping', sanitizedOriginal, sanitizedOriginal, Date.now() - startTime, success);
  }
}

/**
 * Resolve a username for display, preferring original names over pseudonyms.
 */
export async function getDisplayUsername(
  username: string,
  secureDB: SecureDB,
  currentUserOriginal?: string
): Promise<string> {
  const startTime = Date.now();
  const sanitized = sanitizeUsernameInput(username);
  const config = UsernameDisplayConfiguration.get();
  let result = sanitized;
  let success = false;

  if (!sanitized || sanitized.length > config.maxUsernameLength) {
    recordUsernameResolutionEvent('context-resolve', username, 'Unknown User', Date.now() - startTime, false);
    return 'Unknown User';
  }

  try {
    // If this is the current user and we have their original username, use it
    if (currentUserOriginal) {
      const cachedHash = await secureDB.getCachedUsernameHash(currentUserOriginal);
      if (cachedHash && sanitized === cachedHash) {
        result = currentUserOriginal;
        success = true;
        return result;
      }
    }

    // Try to get the original username from the mapping
    const originalUsername = await secureDB.getOriginalUsername(sanitized);
    if (originalUsername && typeof originalUsername === 'string') {
      result = originalUsername;
      success = true;
      return result;
    }

    success = true;
    return result;
  } catch {
    return result;
  } finally {
    recordUsernameResolutionEvent('context-resolve', sanitized, result, Date.now() - startTime, success);
  }
}

/**
 * Username display helper with caching and bounded concurrency.
 */
export class UsernameDisplayContext {
  private readonly cache = new Map<string, { value: string; timestamp: number }>();
  private readonly pendingRequests = new Map<string, Promise<string>>();
  
  constructor(
    private secureDB: SecureDB,
    private currentUserOriginal?: string
  ) {}
  
  async getDisplayUsername(username: string): Promise<string> {
    const sanitized = sanitizeUsernameInput(username);
    const config = UsernameDisplayConfiguration.get();

    if (!sanitized || sanitized.length > config.maxUsernameLength) {
      return 'Unknown User';
    }

    // Check cache
    const cached = this.cache.get(sanitized);
    const now = Date.now();
    if (cached && now - cached.timestamp < config.cacheTTL) {
      return cached.value;
    }

    if (cached) {
      this.cache.delete(sanitized);
    }

    // Deduplicate concurrent requests
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

  async preloadUsernames(usernames: string[]): Promise<void> {
    if (Array.isArray(usernames) && usernames.length > 0) {
      try {
        await this.getDisplayUsernames(usernames);
      } catch {
      }
    }
  }
  
  clearCache(): void {
    this.cache.clear();
    this.pendingRequests.clear();
  }

  private evictIfNeeded(): void {
    const { cacheSize } = UsernameDisplayConfiguration.get();
    while (this.cache.size > cacheSize) {
      const oldestKey = this.cache.keys().next().value;
      if (!oldestKey) break;
      this.cache.delete(oldestKey);
    }
  }
}
