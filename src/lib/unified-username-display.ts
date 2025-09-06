/**
 * Unified Username Display Utilities
 * 
 * This module provides simple, consistent utilities for displaying usernames
 * throughout the application with proper error handling and fallback mechanisms.
 */

/**
 * Simple utility to resolve a username with proper error handling
 * This is the recommended way to resolve usernames in most components
 */
export async function resolveDisplayUsername(
  username: string,
  getDisplayUsername?: (username: string) => Promise<string>
): Promise<string> {
  if (!username) {
    return '';
  }

  if (!getDisplayUsername) {
    return isHashedUsername(username) ? formatUsernameForDisplay(username, 16, true) : username;
  }

  try {
    const resolved = await getDisplayUsername(username);
    return isHashedUsername(resolved) ? formatUsernameForDisplay(resolved, 16, true) : resolved;
  } catch (error) {
    console.error(`[resolveDisplayUsername] Failed to resolve username "${username}":`, error);
    return isHashedUsername(username) ? formatUsernameForDisplay(username, 16, true) : username; // Show formatted pseudonym on fallback
  }
}

/**
 * Batch resolve multiple usernames efficiently
 * Returns a map of original username -> display username
 */
export async function batchResolveUsernames(
  usernames: string[],
  getDisplayUsername?: (username: string) => Promise<string>
): Promise<Map<string, string>> {
  const results = new Map<string, string>();

  if (!getDisplayUsername) {
    usernames.forEach(username => results.set(username, username));
    return results;
  }

  // Process all usernames in parallel
  const promises = usernames.map(async (username) => {
    try {
      const resolved = await getDisplayUsername(username);
      results.set(username, resolved);
    } catch (error) {
      console.error(`[batchResolveUsernames] Failed to resolve username "${username}":`, error);
      results.set(username, username); // Fallback to original
    }
  });

  await Promise.allSettled(promises);
  return results;
}

/**
 * Create a username resolver function with caching
 * This is useful for components that need to resolve many usernames
 */
export function createUsernameResolver(
  getDisplayUsername?: (username: string) => Promise<string>
) {
  const cache = new Map<string, string>();
  const pendingRequests = new Map<string, Promise<string>>();

  return async function resolveUsername(username: string): Promise<string> {
    if (!username) {
      return '';
    }

    if (!getDisplayUsername) {
      return username;
    }

    // Check cache first
    if (cache.has(username)) {
      return cache.get(username)!;
    }

    // Check if there's already a pending request for this username
    if (pendingRequests.has(username)) {
      return pendingRequests.get(username)!;
    }

    // Create new request
    const request = (async () => {
      try {
        const resolved = await getDisplayUsername(username);
        cache.set(username, resolved);
        return resolved;
      } catch (error) {
        console.error(`[createUsernameResolver] Failed to resolve username "${username}":`, error);
        const fallback = username;
        cache.set(username, fallback);
        return fallback;
      } finally {
        pendingRequests.delete(username);
      }
    })();

    pendingRequests.set(username, request);
    return request;
  };
}

/**
 * Utility to check if a username looks like a hash
 * This can be useful for UI decisions (e.g., showing different styling for unresolved usernames)
 */
export function isHashedUsername(username: string): boolean {
  if (!username) return false;
  
  // Check if it's a long hex string (typical hash format)
  const hexPattern = /^[a-f0-9]{32,}$/i;
  return hexPattern.test(username);
}

/**
 * Get the first letter of a username for avatar display
 * Handles both original usernames and hashed usernames appropriately
 */
export function getUsernameInitial(username: string): string {
  if (!username) return 'U';
  
  // For hashed usernames, use 'U' for "User"
  if (isHashedUsername(username)) {
    return 'U';
  }
  
  return username.charAt(0).toUpperCase();
}

/**
 * Format a username for display with optional truncation
 */
export function formatUsernameForDisplay(
  username: string,
  maxLength?: number,
  showHashIndicator = false
): string {
  if (!username) return 'Unknown User';
  
  let displayName = username;
  
  // If it's a hashed username and we want to show an indicator
  if (showHashIndicator && isHashedUsername(username)) {
    displayName = `User (${username.slice(0, 8)}...)`;
  }
  
  // Truncate if needed
  if (maxLength && displayName.length > maxLength) {
    displayName = displayName.slice(0, maxLength - 3) + '...';
  }
  
  return displayName;
}

/**
 * Validate that a username resolution function is working properly
 * Useful for debugging username display issues
 */
export async function validateUsernameResolver(
  testUsername: string,
  getDisplayUsername?: (username: string) => Promise<string>
): Promise<{
  success: boolean;
  originalUsername: string;
  resolvedUsername: string;
  error?: string;
}> {
  try {
    const resolved = await resolveDisplayUsername(testUsername, getDisplayUsername);
    return {
      success: true,
      originalUsername: testUsername,
      resolvedUsername: resolved
    };
  } catch (error) {
    return {
      success: false,
      originalUsername: testUsername,
      resolvedUsername: testUsername,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

/**
 * Ensure username mapping exists for a given original username
 * This can be called proactively to store mappings when we know the original username
 */
export async function ensureUsernameMapping(
  originalUsername: string,
  secureDB?: any,
  pseudonymizeFunction?: (username: string) => Promise<string>
): Promise<boolean> {
  if (!originalUsername || !secureDB || !pseudonymizeFunction) {
    return false;
  }

  try {
    // Generate the pseudonym for this username
    const pseudonym = await pseudonymizeFunction(originalUsername);

    // Check if mapping already exists
    const existingMapping = await secureDB.getOriginalUsername(pseudonym);
    if (existingMapping === originalUsername) {
      return true; // Mapping already exists and is correct
    }

    // Store the mapping
    await secureDB.storeUsernameMapping(pseudonym, originalUsername);
    console.log(`[ensureUsernameMapping] Stored mapping: ${pseudonym} -> ${originalUsername}`);
    return true;
  } catch (error) {
    console.error('[ensureUsernameMapping] Failed to ensure username mapping:', error);
    return false;
  }
}
