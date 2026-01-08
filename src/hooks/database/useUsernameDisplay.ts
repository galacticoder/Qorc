import { useState, useEffect, useCallback, useRef } from 'react';
import { SecureDB } from '../../lib/database/secureDB';
import { UsernameDisplayContext } from '../../lib/database/username-display';
import { EventType } from '../../lib/types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';
import { sanitizeDbUsername, anonymizeUsername } from '../../lib/utils/database-utils';
import { USERNAME_DISPLAY_RATE_LIMIT_WINDOW_MS, USERNAME_DISPLAY_RATE_LIMIT_MAX_EVENTS } from '../../lib/constants';
import type { RateLimitBucket } from '../../lib/types/database-types';

// Hook for username display context
export const useUsernameDisplay = (secureDB: SecureDB | undefined, currentUserOriginal?: string) => {
  const [displayContext, setDisplayContext] = useState<UsernameDisplayContext | null>(null);
  const rateLimitRef = useRef<RateLimitBucket>({ windowStart: Date.now(), count: 0 });

  // Initialize display context when secureDB is available
  useEffect(() => {
    if (secureDB) {
      try {
        setDisplayContext(new UsernameDisplayContext(secureDB, currentUserOriginal));
      } catch (error) {
        console.error('[useUsernameDisplay] Failed to initialize context:', error);
        setDisplayContext(null);
      }
    } else {
      setDisplayContext(null);
    }
  }, [secureDB, currentUserOriginal]);

  // Gets display name
  const getDisplayUsername = useCallback(
    async (username: string): Promise<string> => {
      const sanitized = sanitizeDbUsername(username);
      if (!sanitized) {
        return anonymizeUsername('invalid');
      }

      if (!displayContext) {
        return anonymizeUsername(sanitized);
      }

      try {
        return await displayContext.getDisplayUsername(sanitized);
      } catch (error) {
        console.error('[useUsernameDisplay] Failed to resolve username:', error);
        return anonymizeUsername(sanitized);
      }
    },
    [displayContext],
  );

  // Clears cached usernames
  const clearCache = useCallback(() => {
    try {
      displayContext?.clearCache();
    } catch (error) {
      console.error('[useUsernameDisplay] Failed to clear cache:', error);
    }
  }, [displayContext]);

  // Handles username mapping update events
  useEffect(() => {
    const handler = (event: Event) => {
      try {
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart > USERNAME_DISPLAY_RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > USERNAME_DISPLAY_RATE_LIMIT_MAX_EVENTS) {
          return;
        }

        const detail = (event as CustomEvent).detail;

        if (!isPlainObject(detail)) return;
        if (hasPrototypePollutionKeys(detail)) {
          console.error('[useUsernameDisplay] Prototype pollution attempt detected');
          return;
        }

        const username = sanitizeDbUsername(detail?.username ?? detail?.hashed);
        if (!username) return;

        clearCache();
      } catch (error) {
        console.error('[useUsernameDisplay] Event handler error:', error);
      }
    };

    window.addEventListener(EventType.USERNAME_MAPPING_UPDATED, handler as EventListener);
    window.addEventListener(EventType.USERNAME_MAPPING_RECEIVED, handler as EventListener);
    return () => {
      window.removeEventListener(EventType.USERNAME_MAPPING_UPDATED, handler as EventListener);
      window.removeEventListener(EventType.USERNAME_MAPPING_RECEIVED, handler as EventListener);
    };
  }, [clearCache]);

  return {
    getDisplayUsername,
    clearCache,
    isReady: !!displayContext,
  };
};
