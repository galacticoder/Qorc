import { useState, useEffect, useCallback, useMemo, useRef } from 'react';

interface UseUnifiedUsernameDisplayProps {
  username: string;
  getDisplayUsername?: (username: string) => Promise<string>;
  fallbackToOriginal?: boolean;
  resolveTimeoutMs?: number;
}

interface UseUnifiedUsernameDisplayReturn {
  displayName: string;
  isLoading: boolean;
  error: string | null;
  retry: () => void;
}

const ANON_PREFIX = 'anon:';
const HEX_PATTERN = /^[a-f0-9]{32}$/i;
const OBFUSCATED_LENGTH = 12;
const MAX_USERNAME_LENGTH = 256;
const DEFAULT_RESOLVE_TIMEOUT_MS = 10_000;
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE_SIZE = 512;
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
  // Check for null bytes and control characters
  if (/[\x00-\x1F\x7F]/.test(trimmed)) return null;
  return trimmed;
};

const anonymizeUsername = (username: string) => {
  let hexCandidate: string;
  if (HEX_PATTERN.test(username)) {
    hexCandidate = username;
  } else {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(username);
    hexCandidate = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return `${ANON_PREFIX}${hexCandidate.slice(0, OBFUSCATED_LENGTH)}`;
};

interface ResolveCache {
  displayName: string;
  expiresAt: number;
}

const globalResolveCache = new Map<string, ResolveCache>();
const globalInflightRequests = new Map<string, Promise<string>>();

const getCachedDisplayName = (username: string): string | null => {
  const cached = globalResolveCache.get(username);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.displayName;
  }
  if (cached) {
    globalResolveCache.delete(username);
  }
  return null;
};

const setCachedDisplayName = (username: string, displayName: string): void => {
  globalResolveCache.set(username, {
    displayName,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });
  if (globalResolveCache.size > MAX_CACHE_SIZE) {
    const entries = [...globalResolveCache.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    const toRemove = Math.floor(MAX_CACHE_SIZE * 0.2);
    for (let i = 0; i < toRemove && i < entries.length; i++) {
      globalResolveCache.delete(entries[i][0]);
    }
  }
};

const withTimeout = <T>(promise: Promise<T>, timeoutMs: number): Promise<T> => {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error('RESOLVE_TIMEOUT')), timeoutMs);
    }),
  ]);
};

export function useUnifiedUsernameDisplay({
  username,
  getDisplayUsername,
  fallbackToOriginal = true,
  resolveTimeoutMs = DEFAULT_RESOLVE_TIMEOUT_MS,
}: UseUnifiedUsernameDisplayProps): UseUnifiedUsernameDisplayReturn {
  const sanitizedUsername = useMemo(() => sanitizeUsername(username) ?? '', [username]);
  const [displayName, setDisplayName] = useState(() => {
    if (!sanitizedUsername) return '';
    return fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rateLimitRef = useRef<{ windowStart: number; count: number }>({ windowStart: Date.now(), count: 0 });

  const resolveUsername = useCallback(async () => {
    if (!sanitizedUsername) {
      setDisplayName('');
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

    const existingRequest = globalInflightRequests.get(sanitizedUsername);
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
        const resolved = sanitizeUsername(resolvedRaw) ?? sanitizedUsername;
        
        let finalName: string;
        if (HEX_PATTERN.test(resolved) && resolved === sanitizedUsername) {
          finalName = fallbackToOriginal ? sanitizedUsername : anonymizeUsername(sanitizedUsername);
        } else if (HEX_PATTERN.test(resolved)) {
          finalName = `${ANON_PREFIX}${resolved.slice(0, OBFUSCATED_LENGTH)}`;
        } else {
          finalName = resolved;
        }
        
        setCachedDisplayName(sanitizedUsername, finalName);
        return finalName;
      } finally {
        globalInflightRequests.delete(sanitizedUsername);
      }
    })();

    globalInflightRequests.set(sanitizedUsername, requestPromise);

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
  }, [fallbackToOriginal, getDisplayUsername, sanitizedUsername, resolveTimeoutMs]);

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
          console.error('[useUnifiedUsernameDisplay] Prototype pollution attempt detected');
          return;
        }

        const mapping = sanitizeUsername(detail?.username ?? detail?.hashed);
        if (mapping && mapping === sanitizedUsername) {
          const original = sanitizeUsername(detail?.original);
          if (original && !HEX_PATTERN.test(original)) {
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

    window.addEventListener('username-mapping-updated', handler as EventListener);
    window.addEventListener('username-mapping-received', handler as EventListener);
    return () => {
      window.removeEventListener('username-mapping-updated', handler as EventListener);
      window.removeEventListener('username-mapping-received', handler as EventListener);
    };
  }, [resolveUsername, sanitizedUsername]);

  return {
    displayName,
    isLoading,
    error,
    retry,
  };
}

export function getImmediateDisplayName(
  username: string,
  getDisplayUsername?: (username: string) => Promise<string>,
): string {
  const sanitized = sanitizeUsername(username);
  if (!sanitized) return '';
  if (!getDisplayUsername) return anonymizeUsername(sanitized);
  return anonymizeUsername(sanitized);
}

/**
 * Pre-warm the username display cache with mappings from database
 */
export function prewarmUsernameCache(mappings: Array<{ hashed: string; original: string }>): void {
  for (const { hashed, original } of mappings) {
    const sanitizedHash = sanitizeUsername(hashed);
    const sanitizedOriginal = sanitizeUsername(original);
    if (sanitizedHash && sanitizedOriginal && !HEX_PATTERN.test(sanitizedOriginal)) {
      setCachedDisplayName(sanitizedHash, sanitizedOriginal);
    }
  }
}

export async function resolveMultipleUsernames(
  usernames: string[],
  getDisplayUsername?: (username: string) => Promise<string>,
): Promise<Record<string, string>> {
  const results: Record<string, string> = {};

  await Promise.allSettled(
    usernames.map(async (raw) => {
      const sanitized = sanitizeUsername(raw);
      if (!sanitized) {
        return;
      }

      if (!getDisplayUsername) {
        results[sanitized] = anonymizeUsername(sanitized);
        return;
      }

      try {
        const resolvedRaw = await getDisplayUsername(sanitized);
        const resolved = sanitizeUsername(resolvedRaw) ?? sanitized;
        
        if (HEX_PATTERN.test(resolved) && resolved === sanitized) {
          results[sanitized] = sanitized;
        } else if (HEX_PATTERN.test(resolved)) {
          results[sanitized] = `${ANON_PREFIX}${resolved.slice(0, OBFUSCATED_LENGTH)}`;
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
