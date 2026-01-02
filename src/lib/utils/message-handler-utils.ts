import { isPlainObject } from '../sanitizers';
import {
  MAX_MESSAGE_JSON_BYTES,
  MAX_FILE_JSON_BYTES,
  MAX_CALL_SIGNAL_BYTES,
  MAX_INLINE_FILE_BYTES,
  MAX_BLOB_URLS,
  BLOB_URL_TTL_MS,
  MESSAGE_RATE_LIMIT_WINDOW_MS,
  MESSAGE_RATE_LIMIT_MAX,
  BASE64_URLSAFE_REGEX,
  BASE64_STANDARD_REGEX
} from '../constants';

const textEncoder = new TextEncoder();

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

export const computeBackoffMs = (attempts: number): number => {
  if (attempts <= 0) return 1000;
  if (attempts === 1) return 3000;
  return 8000;
};
