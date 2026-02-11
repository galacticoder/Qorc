import { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  sanitizeDbUsername, 
  anonymizeUsername, 
  getCachedDisplayName 
} from '../../lib/utils/database-utils';

export interface UseDisplayUsernameProps {
  username: string;
  fallbackToOriginal?: boolean;
}

/**
 * Hook for resolving display names
 */
export function useDisplayUsername({
  username,
  fallbackToOriginal = true,
}: UseDisplayUsernameProps): string {
  const sanitizedUsername = useMemo(() => sanitizeDbUsername(username) ?? '', [username]);
  
  const getDisplayName = useCallback(() => {
    if (!sanitizedUsername) return '';
    
    // Check global resolution cache
    const cached = getCachedDisplayName(sanitizedUsername);
    if (cached) return cached;
    
    // Fallback
    return fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
  }, [sanitizedUsername, fallbackToOriginal]);

  const [displayName, setDisplayName] = useState(getDisplayName);

  // Update when username changes
  useEffect(() => {
    setDisplayName(getDisplayName());
  }, [getDisplayName]);

  return displayName;
}
