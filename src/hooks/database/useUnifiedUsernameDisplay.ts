import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { EventType } from '../../lib/types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';
import {
  sanitizeDbUsername,
  anonymizeUsername,
  getCachedDisplayName,
  setCachedDisplayName,
  getInflightRequest,
  setInflightRequest,
  deleteInflightRequest,
  withTimeout,
} from '../../lib/utils/database-utils';
import {
  USERNAME_HEX_PATTERN,
  USERNAME_ANON_PREFIX,
  USERNAME_OBFUSCATED_LENGTH,
  USERNAME_DISPLAY_RESOLVE_TIMEOUT_MS,
  USERNAME_DISPLAY_RATE_LIMIT_WINDOW_MS,
  USERNAME_DISPLAY_RATE_LIMIT_MAX_EVENTS,
} from '../../lib/constants';
import type {
  UseUnifiedUsernameDisplayProps,
  UseUnifiedUsernameDisplayReturn,
  UsernameDisplayProps,
  RateLimitBucket,
} from '../../lib/types/database-types';

export function useUnifiedUsernameDisplay({
  username,
  getDisplayUsername,
  fallbackToOriginal = true,
  originalUsername,
  resolveTimeoutMs = USERNAME_DISPLAY_RESOLVE_TIMEOUT_MS,
}: UseUnifiedUsernameDisplayProps): UseUnifiedUsernameDisplayReturn {
  const sanitizedUsername = useMemo(() => sanitizeDbUsername(username) ?? '', [username]);
  const [displayName, setDisplayName] = useState(() => {
    if (!sanitizedUsername) return '';
    if (originalUsername && !USERNAME_HEX_PATTERN.test(originalUsername)) {
      setCachedDisplayName(sanitizedUsername, originalUsername);
      return originalUsername;
    }
    return fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rateLimitRef = useRef<RateLimitBucket>({ windowStart: Date.now(), count: 0 });

  const resolveUsername = useCallback(async () => {
    if (!sanitizedUsername) {
      setDisplayName('');
      setError(null);
      return;
    }

    if (originalUsername && !USERNAME_HEX_PATTERN.test(originalUsername)) {
      setDisplayName(originalUsername);
      setCachedDisplayName(sanitizedUsername, originalUsername);
      setError(null);
      return;
    }

    const cached = getCachedDisplayName(sanitizedUsername);
    if (cached) {
      setDisplayName(cached);
      setError(null);
      return;
    }

    if (!getDisplayUsername) {
      const anonymized = anonymizeUsername(sanitizedUsername);
      setDisplayName(anonymized);
      setCachedDisplayName(sanitizedUsername, anonymized);
      setError(null);
      return;
    }

    const existingRequest = getInflightRequest(sanitizedUsername);
    if (existingRequest) {
      try {
        const resolved = await existingRequest;
        setDisplayName(resolved);
        setError(null);
      } catch {
        const fallbackName = fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
        setDisplayName(fallbackName);
        setCachedDisplayName(sanitizedUsername, fallbackName);
        setError('Failed to resolve username');
      }
      return;
    }

    setIsLoading(true);
    setError(null);

    const requestPromise = (async () => {
      try {
        const resolvedRaw = await withTimeout(getDisplayUsername(sanitizedUsername), resolveTimeoutMs);
        const resolved = sanitizeDbUsername(resolvedRaw) ?? sanitizedUsername;

        let finalName: string;
        if (USERNAME_HEX_PATTERN.test(resolved) && resolved === sanitizedUsername) {
          finalName = fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
        } else if (USERNAME_HEX_PATTERN.test(resolved)) {
          finalName = `${USERNAME_ANON_PREFIX}${resolved.slice(0, USERNAME_OBFUSCATED_LENGTH)}`;
        } else {
          finalName = resolved;
        }

        setCachedDisplayName(sanitizedUsername, finalName);
        return finalName;
      } finally {
        deleteInflightRequest(sanitizedUsername);
      }
    })();

    setInflightRequest(sanitizedUsername, requestPromise);

    try {
      const resolved = await requestPromise;
      setDisplayName(resolved);
    } catch {
      const fallbackName = fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
      setDisplayName(fallbackName);
      setCachedDisplayName(sanitizedUsername, fallbackName);
      setError('Failed to resolve username');
    } finally {
      setIsLoading(false);
    }
  }, [fallbackToOriginal, getDisplayUsername, sanitizedUsername, originalUsername, resolveTimeoutMs]);

  const retry = useCallback(() => {
    resolveUsername();
  }, [resolveUsername]);

  useEffect(() => {
    resolveUsername();
  }, [resolveUsername]);

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
          console.error('[useUnifiedUsernameDisplay] Prototype pollution attempt detected');
          return;
        }

        const mapping = sanitizeDbUsername(detail?.username ?? detail?.hashed);
        if (mapping && mapping === sanitizedUsername) {
          const original = sanitizeDbUsername(detail?.original);
          if (original && !USERNAME_HEX_PATTERN.test(original)) {
            setDisplayName(original);
            setCachedDisplayName(sanitizedUsername, original);
            setError(null);
            return;
          }
          resolveUsername();
        }
      } catch (error) {
        console.error('[useUnifiedUsernameDisplay] Event handler error:', error);
      }
    };

    window.addEventListener(EventType.USERNAME_MAPPING_UPDATED, handler as EventListener);
    window.addEventListener(EventType.USERNAME_MAPPING_RECEIVED, handler as EventListener);
    return () => {
      window.removeEventListener(EventType.USERNAME_MAPPING_UPDATED, handler as EventListener);
      window.removeEventListener(EventType.USERNAME_MAPPING_RECEIVED, handler as EventListener);
    };
  }, [resolveUsername, sanitizedUsername]);

  return {
    displayName,
    isLoading,
    error,
    retry,
  };
}

// Gets display name
export function getImmediateDisplayName(
  username: string,
  getDisplayUsername?: (username: string) => Promise<string>,
): string {
  const sanitized = sanitizeDbUsername(username);
  if (!sanitized) return '';
  if (!getDisplayUsername) return anonymizeUsername(sanitized);
  return anonymizeUsername(sanitized);
}

// Bulk resolves multiple usernames
export async function resolveMultipleUsernames(
  usernames: string[],
  getDisplayUsername?: (username: string) => Promise<string>,
): Promise<Record<string, string>> {
  const results: Record<string, string> = {};

  await Promise.allSettled(
    usernames.map(async (raw) => {
      const sanitized = sanitizeDbUsername(raw);
      if (!sanitized) {
        return;
      }

      if (!getDisplayUsername) {
        results[sanitized] = anonymizeUsername(sanitized);
        return;
      }

      try {
        const resolvedRaw = await getDisplayUsername(sanitized);
        const resolved = sanitizeDbUsername(resolvedRaw) ?? sanitized;

        if (USERNAME_HEX_PATTERN.test(resolved) && resolved === sanitized) {
          results[sanitized] = sanitized;
        } else if (USERNAME_HEX_PATTERN.test(resolved)) {
          results[sanitized] = `${USERNAME_ANON_PREFIX}${resolved.slice(0, USERNAME_OBFUSCATED_LENGTH)}`;
        } else {
          results[sanitized] = resolved;
        }
      } catch (error) {
        console.error('[resolveMultipleUsernames] Failed to resolve username:', error);
        results[sanitized] = anonymizeUsername(sanitized);
      }
    }),
  );

  return results;
}

export type { UsernameDisplayProps };
