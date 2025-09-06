import { useState, useEffect, useCallback } from 'react';

/**
 * Unified Username Display Hook
 * 
 * This hook provides a simple, consistent way to display usernames throughout the application.
 * It automatically resolves hashed usernames to original usernames when possible,
 * with proper error handling and fallback mechanisms.
 */

interface UseUnifiedUsernameDisplayProps {
  username: string;
  getDisplayUsername?: (username: string) => Promise<string>;
  fallbackToOriginal?: boolean; // If true, falls back to original username on error
}

interface UseUnifiedUsernameDisplayReturn {
  displayName: string;
  isLoading: boolean;
  error: string | null;
  retry: () => void;
}

export function useUnifiedUsernameDisplay({
  username,
  getDisplayUsername,
  fallbackToOriginal = true
}: UseUnifiedUsernameDisplayProps): UseUnifiedUsernameDisplayReturn {
  const [displayName, setDisplayName] = useState(username);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resolveUsername = useCallback(async () => {
    if (!username) {
      setDisplayName('');
      return;
    }

    if (!getDisplayUsername) {
      // Show formatted pseudonym when no resolver is available
      try {
        const hexPattern = /^[a-f0-9]{32,}$/i;
        setDisplayName(hexPattern.test(username) ? `${username.slice(0, 8)}...` : username);
      } catch {
        setDisplayName(username);
      }
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const resolved = await getDisplayUsername(username);
      try {
        const hexPattern = /^[a-f0-9]{32,}$/i;
        setDisplayName(hexPattern.test(resolved) ? `${resolved.slice(0, 8)}...` : resolved);
      } catch {
        setDisplayName(resolved);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to resolve username';
      setError(errorMessage);
      
      if (fallbackToOriginal) {
        try {
          const hexPattern = /^[a-f0-9]{32,}$/i;
          setDisplayName(hexPattern.test(username) ? `${username.slice(0, 8)}...` : username);
        } catch {
          setDisplayName(username);
        }
      } else {
        setDisplayName('Unknown User');
      }
    } finally {
      setIsLoading(false);
    }
  }, [username, getDisplayUsername, fallbackToOriginal]);

  const retry = useCallback(() => {
    resolveUsername();
  }, [resolveUsername]);

  useEffect(() => {
    resolveUsername();
  }, [resolveUsername]);

  // Re-resolve when a username mapping is updated for this username
  useEffect(() => {
    const handler = (e: any) => {
      try {
        const updated = e.detail?.username || e.detail?.hashed;
        if (updated && typeof updated === 'string' && updated === username) {
          resolveUsername();
        }
      } catch {}
    };
    window.addEventListener('username-mapping-updated', handler as EventListener);
    window.addEventListener('username-mapping-received', handler as EventListener);
    return () => {
      window.removeEventListener('username-mapping-updated', handler as EventListener);
      window.removeEventListener('username-mapping-received', handler as EventListener);
    };
  }, [username, resolveUsername]);

  return {
    displayName,
    isLoading,
    error,
    retry
  };
}

/**
 * Utility function for synchronous username display
 * Use this when you need to display a username immediately without waiting for resolution
 */
export function getImmediateDisplayName(
  username: string,
  getDisplayUsername?: (username: string) => Promise<string>
): string {
  if (!username) return '';
  
  // For immediate display, we return the original username
  // The component should use useUnifiedUsernameDisplay for proper resolution
  return username;
}

/**
 * Utility function to resolve multiple usernames at once
 * Useful for batch operations like conversation lists
 */
export async function resolveMultipleUsernames(
  usernames: string[],
  getDisplayUsername?: (username: string) => Promise<string>
): Promise<Record<string, string>> {
  if (!getDisplayUsername) {
    return usernames.reduce((acc, username) => {
      acc[username] = username;
      return acc;
    }, {} as Record<string, string>);
  }

  const results: Record<string, string> = {};
  
  await Promise.allSettled(
    usernames.map(async (username) => {
      try {
        const resolved = await getDisplayUsername(username);
        results[username] = resolved;
      } catch (error) {
        console.error(`Failed to resolve username ${username}:`, error);
        results[username] = username; // Fallback to original
      }
    })
  );

  return results;
}

/**
 * Props interface for the UsernameDisplay component
 * This component should be implemented in a separate .tsx file if needed
 */
export interface UsernameDisplayProps {
  username: string;
  getDisplayUsername?: (username: string) => Promise<string>;
  fallbackToOriginal?: boolean;
  className?: string;
  loadingText?: string;
  errorText?: string;
  showRetry?: boolean;
  onRetry?: () => void;
}
