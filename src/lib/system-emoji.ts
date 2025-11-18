import { SecureAuditLogger } from './secure-error-handler';

async function computeIntegrityHash(emojis: ReadonlyArray<string>): Promise<string> {
  const text = emojis.join('');

  if (typeof globalThis.crypto?.subtle === 'undefined') {
    let fallback = 0;
    for (let i = 0; i < text.length; i++) {
      fallback = Math.imul(31, fallback) + text.charCodeAt(i);
      fallback |= 0;
    }
    return fallback.toString(16);
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(digest));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyEmojiIntegrity(emojis: string[], hash: string | null): Promise<boolean> {
  if (!hash) return false;
  const computed = await computeIntegrityHash(emojis);
  return computed === hash;
}

function deepFreeze<T>(obj: T): Readonly<T> {
  if (obj === null || typeof obj !== 'object' || Object.isFrozen(obj)) {
    return obj as Readonly<T>;
  }
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const record = obj as Record<string, unknown>;
    const value = record[key];
    if (value && typeof value === 'object') {
      deepFreeze(value);
    }
  }
  return obj as Readonly<T>;
}

function sanitizeSearchQuery(query: string): string {
  return query
    .replace(/<[^>]*>/g, '')
    .replace(/[<>'"]/g, '')
    .slice(0, CONFIG.MAX_SEARCH_QUERY_LENGTH)
    .trim();
}
/**
 * System emoji management with security validation and caching
 */

interface SecureBridgeAPI {
  getSystemEmojis?: () => Promise<string[]>;
}

const CONFIG = Object.freeze({
  CACHE_TTL: 5 * 60 * 1000,
  MAX_EMOJI_LENGTH: 10,
  DEFAULT_CATEGORY_SIZE: 20,
  SEARCH_CACHE_LIMIT: 100,
  RATE_LIMIT_WINDOW: 1000,
  RATE_LIMIT_MAX_REQUESTS: 25,
  MAX_PAGE_SIZE: 100,
  MAX_PAGE_NUMBER: 1000,
  MAX_SEARCH_QUERY_LENGTH: 64,
  SEARCH_DEBOUNCE_MS: 150
} as const);

class LRUCache<K, V> {
  private cache = new Map<K, V>();

  constructor(private readonly maxSize: number) {}

  get(key: K): V | undefined {
    const value = this.cache.get(key);
    if (value !== undefined) {
      this.cache.delete(key);
      this.cache.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
      }
    }
    this.cache.set(key, value);
  }

  clear(): void {
    this.cache.clear();
  }
}

const FALLBACK_EMOJIS = deepFreeze([
  '😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😍',
  '😎', '🙂', '🙃', '😉', '🥰', '😘', '😗', '😚', '😋', '😛',
  '😜', '🤪', '😝', '🤗', '🤔', '🤨', '😐', '😑', '😶', '🙄',
  '😏', '🥳', '🤩', '🥺', '😭', '😤', '😡', '😠', '👍', '👎',
  '👏', '🙏', '🤝', '✋', '👌', '🤌', '🤏', '💪', '❤️', '💔',
  '💖', '💯', '✨', '🔥', '⭐', '⚡', '✅', '❌', '❓', '❗'
]) as ReadonlyArray<string>;

let fallbackEmojisHashPromise: Promise<string> | null = null;

function getFallbackEmojisHash(): Promise<string> {
  if (!fallbackEmojisHashPromise) {
    fallbackEmojisHashPromise = computeIntegrityHash(FALLBACK_EMOJIS);
  }
  return fallbackEmojisHashPromise;
}

const MINIMAL_EMOJIS = Object.freeze(['👍', '👎', '❤️', '✅', '❌'] as const);

const FALLBACK_GROUP_DEFINITIONS = deepFreeze({
  Popular: FALLBACK_EMOJIS.slice(0, CONFIG.DEFAULT_CATEGORY_SIZE),
  Smileys: ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😍'],
  Gestures: ['👍', '👎', '👏', '🙏', '🤝', '✋', '👌', '🤌', '🤏', '💪'],
  Hearts: ['❤️', '💔', '💖'],
  Symbols: ['💯', '✨', '🔥', '⭐', '⚡', '✅', '❌', '❓', '❗']
}) as Readonly<Record<string, ReadonlyArray<string>>>;

let emojiCache: string[] | null = null;
let cacheTimestamp = 0;
let emojiCacheHash: string | null = null;

const searchCache = new LRUCache<string, string[]>(CONFIG.SEARCH_CACHE_LIMIT);

const searchRateLimit = {
  windowStart: 0,
  count: 0
};

let searchDebounceTimer: ReturnType<typeof setTimeout> | null = null;

const EMOJI_REGEX = /^(\p{Emoji_Presentation}|\p{Extended_Pictographic})(\uFE0F?(\u200D(\p{Emoji_Presentation}|\p{Extended_Pictographic}))*)?$/u;

function logSecurityEvent(event: string, details?: Record<string, unknown>): void {
  SecureAuditLogger.error('system-emoji', 'security', event, {
    ...details
  });
}

function getSearchPenaltyMs(overLimitCount: number): number {
  const penalty = Math.min(overLimitCount * 100, 5000);
  return penalty;
}

class CircuitBreaker {
  private failureCount = 0;
  private lastFailureTime = 0;

  constructor(
    private readonly failureThreshold: number,
    private readonly resetTimeoutMs: number
  ) {}

  isOpen(): boolean {
    if (this.failureCount < this.failureThreshold) {
      return false;
    }
    const now = Date.now();
    return now - this.lastFailureTime < this.resetTimeoutMs;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.isOpen()) {
      throw new Error('Circuit breaker open - service unavailable');
    }

    try {
      const result = await operation();
      this.failureCount = 0;
      return result;
    } catch (_error) {
      this.failureCount += 1;
      this.lastFailureTime = Date.now();
      throw error;
    }
  }
}

const bridgeCircuitBreaker = new CircuitBreaker(5, 60_000);

function getSecureBridge(): SecureBridgeAPI | null {
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    const candidate = (window as any).edgeApi || (window as any).electronAPI;
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return null;
    }
    if (candidate !== Object.prototype.valueOf.call(candidate)) {
      return null;
    }
    const propNames = Object.getOwnPropertyNames(candidate);
    if (propNames.length > 5) {
      return null;
    }
    const proto = Object.getPrototypeOf(candidate);
    if (proto !== Object.prototype && proto !== null) {
      return null;
    }
    const forbiddenProps = ['__proto__', 'constructor', '__defineGetter__'];
    if (forbiddenProps.some((prop) => prop in candidate)) {
      return null;
    }
    try {
      Object.getOwnPropertyDescriptor(candidate, 'constructor');
    } catch {
      return null;
    }
    const fn = candidate.getSystemEmojis;
    if (typeof fn !== 'function') {
      return null;
    }
    const descriptor = Object.getOwnPropertyDescriptor(candidate, 'getSystemEmojis');
    if (descriptor && (descriptor.get || descriptor.set)) {
      return null;
    }
    const source = Function.prototype.toString.call(fn);
    const allowedPatterns = [
      /native\s*code/i,
      /Electron\.ipcRenderer/i,
      /postMessage/i
    ];
    if (!source.includes('[native code]') && !allowedPatterns.some((pattern) => pattern.test(source))) {
      return null;
    }
    try {
      const testResult = fn();
      if (testResult && typeof testResult.then !== 'function') {
        return null;
      }
    } catch {
      // Ignored on purpose; function may reject when called incorrectly.
    }
    return candidate as SecureBridgeAPI;
  } catch {
    return null;
  }
}

function isTorEnvironment(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }
  try {
    if (typeof (window as any).__TOR_MODE__ === 'boolean') {
      return (window as any).__TOR_MODE__ === true;
    }
    const hostname = window.location?.hostname ?? '';
    const isOnion = hostname.endsWith('.onion');
    const isTorBrowser = typeof navigator !== 'undefined' &&
      navigator.plugins?.length === 0 &&
      !(navigator as any).webkitTemporaryStorage;
    return isOnion || isTorBrowser;
  } catch {
    return false;
  }
}

export interface EmojiCategory {
  name: string;
  emojis: string[];
}

function isValidEmoji(candidate: unknown): candidate is string {
  if (typeof candidate !== 'string') return false;
  const trimmed = candidate.trim();
  if (trimmed.length === 0 || trimmed.length > CONFIG.MAX_EMOJI_LENGTH) return false;
  const codePoints = Array.from(trimmed).map((char) => char.codePointAt(0) ?? 0);
  if (codePoints.some((code) => code > 0x10ffff)) {
    return false;
  }
  return EMOJI_REGEX.test(trimmed);
}

export async function getSystemEmojis(): Promise<string[]> {
  if (isTorEnvironment()) {
    return FALLBACK_EMOJIS.slice();
  }

  const now = Date.now();
  if (emojiCache && (now - cacheTimestamp) < CONFIG.CACHE_TTL) {
    const integrityOk = await verifyEmojiIntegrity(emojiCache, emojiCacheHash);
    if (!integrityOk) {
      logSecurityEvent('Emoji cache integrity check failed');
      await clearEmojiCache();
      return MINIMAL_EMOJIS.slice();
    }
    return emojiCache.slice();
  }

  try {
    const bridge = getSecureBridge();
    if (bridge && typeof bridge.getSystemEmojis === 'function') {
      const list = await bridgeCircuitBreaker.execute(() => bridge.getSystemEmojis!());
      if (Array.isArray(list)) {
        const validated = list.filter(isValidEmoji);
        if (validated.length > 0) {
          const deduped = Array.from(new Set(validated));
          emojiCache = deduped;
          cacheTimestamp = now;
          emojiCacheHash = await computeIntegrityHash(deduped);
          return deduped.slice();
        }
      }
    }
  } catch (_err) {
    SecureAuditLogger.error('system-emoji', 'bridge', 'getSystemEmojis-failed', {
      error: _err instanceof Error ? _err.message : 'unknown',
      circuitOpen: bridgeCircuitBreaker.isOpen()
    });
  }

  emojiCache = FALLBACK_EMOJIS.slice();
  cacheTimestamp = now;
  emojiCacheHash = await getFallbackEmojisHash();
  return emojiCache.slice();
}

export async function getEmojiCategories(): Promise<EmojiCategory[]> {
  const emojis = await getSystemEmojis();
  return Object.entries(FALLBACK_GROUP_DEFINITIONS).map(([name, group]) => {
    const intersection = group.filter((emoji) => emojis.includes(emoji));
    return {
      name,
      emojis: intersection.length > 0 ? intersection : emojis.slice(0, Math.min(CONFIG.DEFAULT_CATEGORY_SIZE, emojis.length))
    };
  });
}

export function paginateEmojis(emojis: string[], page: number, pageSize: number): string[] {
  const currentPage = Number.isInteger(page) && page >= 0 && page <= CONFIG.MAX_PAGE_NUMBER ? page : 0;
  const currentPageSize = Number.isInteger(pageSize) && pageSize > 0 && pageSize <= CONFIG.MAX_PAGE_SIZE
    ? pageSize
    : Math.min(20, CONFIG.MAX_PAGE_SIZE);

  const start = currentPage * currentPageSize;
  if (start < 0 || start >= emojis.length) {
    return [];
  }

  return emojis.slice(start, Math.min(start + currentPageSize, emojis.length));
}

const EMOJI_KEYWORDS = deepFreeze({
  '😀': ['grin', 'smile', 'happy'],
  '😃': ['smile', 'happy'],
  '😄': ['laugh', 'happy'],
  '😁': ['grin', 'cheerful'],
  '😆': ['laughing', 'haha'],
  '😅': ['relief', 'sweat'],
  '😂': ['joy', 'tears', 'lol'],
  '🤣': ['rofl', 'rolling'],
  '😊': ['blush', 'smile'],
  '😍': ['love', 'hearts', 'eyes'],
  '😎': ['cool', 'sunglasses'],
  '🙂': ['smile'],
  '🙃': ['upside', 'playful'],
  '😉': ['wink'],
  '🥰': ['love', 'hearts'],
  '😘': ['kiss'],
  '😋': ['yum', 'delicious'],
  '😜': ['cheeky'],
  '🤪': ['wacky'],
  '😝': ['tongue'],
  '🤗': ['hug', 'embrace'],
  '🤔': ['think', 'question'],
  '😐': ['neutral'],
  '🙄': ['eyeroll'],
  '😏': ['smirk'],
  '🥳': ['party', 'celebrate'],
  '🤩': ['star', 'wow'],
  '🥺': ['plead'],
  '😭': ['cry', 'sad'],
  '😡': ['angry'],
  '😠': ['mad'],
  '👍': ['thumbs', 'up'],
  '👎': ['thumbs', 'down'],
  '👏': ['clap'],
  '🙏': ['pray', 'thanks'],
  '🤝': ['handshake'],
  '💪': ['muscle', 'strong'],
  '❤️': ['heart', 'love'],
  '💔': ['broken', 'heart'],
  '💖': ['sparkle', 'heart'],
  '💯': ['100', 'perfect'],
  '✨': ['sparkles'],
  '🔥': ['fire', 'lit'],
  '⭐': ['star'],
  '⚡': ['zap', 'power'],
  '✅': ['check', 'green'],
  '❌': ['cross', 'red'],
  '❓': ['question'],
  '❗': ['exclamation']
}) as Readonly<Record<string, ReadonlyArray<string>>>;

export function searchEmojis(query: string, emojis: string[]): string[] {
  const now = Date.now();
  if (now - searchRateLimit.windowStart > CONFIG.RATE_LIMIT_WINDOW) {
    searchRateLimit.windowStart = now;
    searchRateLimit.count = 0;
  }
  searchRateLimit.count += 1;
  if (searchRateLimit.count > CONFIG.RATE_LIMIT_MAX_REQUESTS) {
    const overage = searchRateLimit.count - CONFIG.RATE_LIMIT_MAX_REQUESTS;
    const penalty = getSearchPenaltyMs(overage);
    logSecurityEvent('Emoji search rate limit exceeded', { overage, penalty });
    throw new Error(`Too many requests. Try again in ${Math.ceil(penalty / 1000)} seconds.`);
  }

  const trimmed = sanitizeSearchQuery(query).toLowerCase();
  if (!trimmed) {
    return emojis;
  }

  const emojiSignature = emojis.length > 50
    ? `${emojis.length}:${emojis[0] ?? ''}:${emojis[emojis.length - 1] ?? ''}`
    : Array.from(new Set(emojis)).sort().join('|').substring(0, 200);
  const cacheKey = `${trimmed}:${emojiSignature}`;

  const cached = searchCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const seen = new Set<string>();
  const matches: string[] = [];

  for (const emoji of emojis) {
    if (seen.has(emoji)) continue;
    if (emoji.includes(trimmed)) {
      matches.push(emoji);
      seen.add(emoji);
      continue;
    }
    const keywords = EMOJI_KEYWORDS[emoji];
    if (keywords && keywords.some((word) => word.includes(trimmed))) {
      matches.push(emoji);
      seen.add(emoji);
    }
  }

  const result = matches.length > 0 ? matches : emojis;
  searchCache.set(cacheKey, result);
  return result;
}

export function searchEmojisDebounced(
  query: string,
  emojis: string[],
  callback: (results: string[]) => void,
  delay: number = CONFIG.SEARCH_DEBOUNCE_MS
): void {
  if (searchDebounceTimer) {
    clearTimeout(searchDebounceTimer);
  }

  if (typeof query !== 'string' || !Array.isArray(emojis) || typeof callback !== 'function') {
    SecureAuditLogger.error('system-emoji', 'search', 'invalid-parameters', {});
    callback(emojis);
    return;
  }

  const boundedDelay = Math.min(Math.max(delay, 0), 1000);

  searchDebounceTimer = setTimeout(() => {
    try {
      const results = searchEmojis(query, emojis);
      callback(results);
    } catch (error) {
      SecureAuditLogger.error('system-emoji', 'search', 'search-error', {
        error: error instanceof Error ? error.message : 'unknown',
        queryLength: query.length,
        emojiCount: emojis.length
      });
      callback(emojis);
    }
  }, boundedDelay);
}

export async function clearEmojiCache(): Promise<void> {
  emojiCache = null;
  cacheTimestamp = 0;
  emojiCacheHash = null;
  fallbackEmojisHashPromise = null;
  searchCache.clear();
}

export async function getEmojiCacheStatus(): Promise<{ cached: boolean; age: number }> {
  return {
    cached: emojiCache !== null,
    age: emojiCache ? Date.now() - cacheTimestamp : 0
  };
}

export async function getEmojiSystemHealth(): Promise<{
  status: 'healthy' | 'degraded' | 'failed';
  cacheStatus: { cached: boolean; age: number };
  bridgeAvailable: boolean;
  circuitBreaker: { open: boolean; failureCount: number };
  fallbackActive: boolean;
}> {
  try {
    const cacheStatus = await getEmojiCacheStatus();
    const bridge = getSecureBridge();
    const bridgeAvailable = Boolean(bridge?.getSystemEmojis);
    const fallbackActive = isTorEnvironment() || !cacheStatus.cached;

    let status: 'healthy' | 'degraded' | 'failed' = 'healthy';
    if (!bridgeAvailable && !cacheStatus.cached) {
      status = 'failed';
    } else if (!bridgeAvailable || bridgeCircuitBreaker.isOpen()) {
      status = 'degraded';
    }

    return {
      status,
      cacheStatus,
      bridgeAvailable,
      circuitBreaker: {
        open: bridgeCircuitBreaker.isOpen(),
        failureCount: (bridgeCircuitBreaker as any).failureCount ?? 0
      },
      fallbackActive
    };
  } catch {
    return {
      status: 'failed',
      cacheStatus: { cached: false, age: 0 },
      bridgeAvailable: false,
      circuitBreaker: { open: true, failureCount: 999 },
      fallbackActive: true
    };
  }
}


