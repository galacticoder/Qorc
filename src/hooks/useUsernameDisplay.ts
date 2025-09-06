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

  // Invalidate cache when mappings are updated/received so re-resolutions reflect immediately
  useEffect(() => {
    const handler = () => clearCache();
    window.addEventListener('username-mapping-updated', handler as EventListener);
    window.addEventListener('username-mapping-received', handler as EventListener);
    return () => {
      window.removeEventListener('username-mapping-updated', handler as EventListener);
      window.removeEventListener('username-mapping-received', handler as EventListener);
    };
  }, [clearCache]);

  return {
    getDisplayUsername,
    clearCache,
    isReady: !!displayContext
  };
};
