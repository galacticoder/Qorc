import { useState, useEffect, useCallback, useRef } from 'react';
import { SecureDB } from '../lib/secureDB';
import { UsernameDisplayContext } from '../lib/username-display';

const MAX_USERNAME_LENGTH = 256;
const RATE_LIMIT_WINDOW_MS = 5_000;
const RATE_LIMIT_MAX_EVENTS = 50;

const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value == null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
};

const sanitizeUsername = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_USERNAME_LENGTH) return null;
  if (/[\x00-\x1F\x7F]/.test(trimmed)) return null;
  return trimmed;
};

const anonymizeUsername = (username: string) => {
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(username);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `anon:${hex.slice(0, 12)}`;
  } catch {
    return 'anon:unknown';
  }
};

export const useUsernameDisplay = (secureDB: SecureDB | undefined, currentUserOriginal?: string) => {
  const [displayContext, setDisplayContext] = useState<UsernameDisplayContext | null>(null);
  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

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

  const getDisplayUsername = useCallback(
    async (username: string): Promise<string> => {
      const sanitized = sanitizeUsername(username);
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

  const clearCache = useCallback(() => {
    try {
      displayContext?.clearCache();
    } catch (error) {
      console.error('[useUsernameDisplay] Failed to clear cache:', error);
    }
  }, [displayContext]);

  useEffect(() => {
    const handler = (event: Event) => {
      try {
        const now = Date.now();
        const bucket = rateLimitRef.current;
        if (now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
          bucket.windowStart = now;
          bucket.count = 0;
        }
        bucket.count += 1;
        if (bucket.count > RATE_LIMIT_MAX_EVENTS) {
          return;
        }

        const detail = (event as CustomEvent).detail;

        if (!isPlainObject(detail)) return;
        if (hasPrototypePollutionKeys(detail)) {
          console.error('[useUsernameDisplay] Prototype pollution attempt detected');
          return;
        }

        const username = sanitizeUsername(detail?.username ?? detail?.hashed);
        if (!username) return;

        clearCache();
      } catch (error) {
        console.error('[useUsernameDisplay] Event handler error:', error);
      }
    };

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
    isReady: !!displayContext,
  };
};
