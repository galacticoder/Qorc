import { useState, useEffect, useCallback } from 'react';
import { SecureDB } from '../lib/secureDB';
import { UsernameDisplayContext } from '../lib/username-display';

export const useUsernameDisplay = (secureDB: SecureDB | undefined, currentUserOriginal?: string) => {
  const [displayContext, setDisplayContext] = useState<UsernameDisplayContext | null>(null);

  useEffect(() => {
    if (secureDB) {
      setDisplayContext(new UsernameDisplayContext(secureDB, currentUserOriginal));
    } else {
      setDisplayContext(null);
    }
  }, [secureDB, currentUserOriginal]);

  const getDisplayUsername = useCallback(async (username: string): Promise<string> => {
    if (!displayContext) {
      return username; // Fallback to hash if context not ready
    }
    return await displayContext.getDisplayUsername(username);
  }, [displayContext]);

  const clearCache = useCallback(() => {
    if (displayContext) {
      displayContext.clearCache();
    }
  }, [displayContext]);

  return {
    getDisplayUsername,
    clearCache,
    isReady: !!displayContext
  };
};
