/**
 * Utility functions for encrypted message handling
 */

const textEncoder = new TextEncoder();

export const MAX_MESSAGE_JSON_BYTES = 64 * 1024; // 64 KB
export const MAX_FILE_JSON_BYTES = 256 * 1024; // 256 KB
export const MAX_CALL_SIGNAL_BYTES = 256 * 1024; // 256 KB
export const MAX_INLINE_FILE_BYTES = 5 * 1024 * 1024; // 5 MB inline payloads
export const MAX_BLOB_URLS = 32;
export const BLOB_URL_TTL_MS = 15 * 60 * 1000; // 15 minutes
export const MESSAGE_RATE_LIMIT_WINDOW_MS = 5_000;
export const MESSAGE_RATE_LIMIT_MAX = 300;

export const BASE64_STANDARD_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;
export const BASE64_URLSAFE_REGEX = /^[A-Za-z0-9\-_]*={0,2}$/;

export type PlainObject = Record<string, unknown>;

export const isPlainObject = (value: unknown): value is PlainObject => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

export const exceedsBytes = (input: string, limit: number): boolean => {
  return textEncoder.encode(input).length > limit;
};

export type BlobEntry = { url: string; expiresAt: number };

export const createBlobCache = () => {
  const entries: BlobEntry[] = [];

  const revoke = (entry: BlobEntry | undefined) => {
    if (!entry) return;
    try { URL.revokeObjectURL(entry.url); } catch { }
  };

  const flush = () => {
    const now = Date.now();
    while (entries.length && entries[0].expiresAt <= now) {
      revoke(entries.shift());
    }
  };

  const enqueue = (url: string) => {
    const expiresAt = Date.now() + BLOB_URL_TTL_MS;
    entries.push({ url, expiresAt });
    flush();
    if (entries.length > MAX_BLOB_URLS) {
      revoke(entries.shift());
    }
  };

  const clearAll = () => {
    while (entries.length) {
      revoke(entries.shift());
    }
  };

  return { enqueue, flush, clearAll };
};

export type RateLimitConfig = { windowMs: number; max: number };

export const DEFAULT_RATE_LIMIT: RateLimitConfig = {
  windowMs: MESSAGE_RATE_LIMIT_WINDOW_MS,
  max: MESSAGE_RATE_LIMIT_MAX,
};

export const sanitizeRateLimitConfig = (input: any): RateLimitConfig => {
  if (!input || typeof input !== 'object') return DEFAULT_RATE_LIMIT;

  const rawWindow = Number((input.windowMs ?? input.window ?? input.windowMsMs));
  const rawMax = Number((input.max ?? input.maxMessages ?? input.limit));

  const windowMs = Number.isFinite(rawWindow)
    ? Math.min(Math.max(500, Math.floor(rawWindow)), 60_000)
    : DEFAULT_RATE_LIMIT.windowMs;
  const max = Number.isFinite(rawMax)
    ? Math.min(Math.max(50, Math.floor(rawMax)), 2000)
    : DEFAULT_RATE_LIMIT.max;

  return { windowMs, max };
};

export function createBlobUrlFromBase64(
  dataBase64: string,
  fileType: string | undefined,
  blobCache: ReturnType<typeof createBlobCache>
): string | null {
  try {
    let cleanBase64 = dataBase64.trim();

    const inlinePrefixIndex = cleanBase64.indexOf(',');
    if (inlinePrefixIndex > 0 && inlinePrefixIndex < 128) {
      cleanBase64 = cleanBase64.slice(inlinePrefixIndex + 1);
    }

    const isUrlSafe = BASE64_URLSAFE_REGEX.test(cleanBase64.replace(/=*$/, ''));
    const regex = isUrlSafe ? BASE64_URLSAFE_REGEX : BASE64_STANDARD_REGEX;

    if (!regex.test(cleanBase64)) return null;

    const byteLength = Math.floor((cleanBase64.length * 3) / 4) - (cleanBase64.endsWith('==') ? 2 : cleanBase64.endsWith('=') ? 1 : 0);
    if (byteLength > MAX_INLINE_FILE_BYTES) return null;

    const binary = Uint8Array.from(atob(cleanBase64), char => char.charCodeAt(0));
    const blob = new Blob([binary], { type: fileType || 'application/octet-stream' });
    if (blob.size !== byteLength) return null;

    const url = URL.createObjectURL(blob);
    blobCache.enqueue(url);
    return url;
  } catch {
    return null;
  }
}

export const safeJsonParse = (jsonString: string, maxBytes: number = MAX_MESSAGE_JSON_BYTES): any => {
  if (!jsonString || typeof jsonString !== 'string') return null;
  if (exceedsBytes(jsonString, maxBytes)) return null;
  const trimmed = jsonString.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;
  try {
    return JSON.parse(jsonString);
  } catch {
    return null;
  }
};

export const safeJsonParseForCallSignals = (jsonString: string): any => safeJsonParse(jsonString, MAX_CALL_SIGNAL_BYTES);
export const safeJsonParseForMessages = (jsonString: string): any => safeJsonParse(jsonString, MAX_MESSAGE_JSON_BYTES);

export const safeJsonParseForFileMessages = (jsonString: string): any => {
  const parsed = safeJsonParse(jsonString, MAX_FILE_JSON_BYTES);
  if (!parsed || !isPlainObject(parsed)) return null;

  const candidateFields = ['dataBase64', 'fileData', 'data', 'content'];
  for (const field of candidateFields) {
    const value = parsed[field];
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (!trimmed) continue;

    const inlinePrefixIndex = trimmed.indexOf(',');
    const base64Payload = inlinePrefixIndex > 0 ? trimmed.slice(inlinePrefixIndex + 1) : trimmed;
    const isUrlSafe = BASE64_URLSAFE_REGEX.test(base64Payload.replace(/=*$/, ''));
    const regex = isUrlSafe ? BASE64_URLSAFE_REGEX : BASE64_STANDARD_REGEX;
    if (!regex.test(base64Payload)) return null;
    const byteLength = Math.floor((base64Payload.length * 3) / 4) - (base64Payload.endsWith('==') ? 2 : base64Payload.endsWith('=') ? 1 : 0);
    if (byteLength > MAX_INLINE_FILE_BYTES) return null;
  }
  return parsed;
};

// Retry/backoff helpers
export const MAX_RETRY_ATTEMPTS = 3;
export const PENDING_QUEUE_TTL_MS = 120_000;
export const PENDING_QUEUE_MAX_PER_PEER = 50;
export const MAX_GLOBAL_PENDING_MESSAGES = 1000;
export const BUNDLE_REQUEST_COOLDOWN_MS = 2_000;
export const KEY_REQUEST_CACHE_DURATION = 5000;
export const PQ_KEY_REPLENISH_COOLDOWN_MS = 60_000;
export const MAX_RESETS_PER_PEER = 5;
export const RESET_WINDOW_MS = 60_000;

export const computeBackoffMs = (attempts: number): number => {
  if (attempts <= 0) return 1000;
  if (attempts === 1) return 3000;
  return 8000;
};
