import {
  MAX_MESSAGE_JSON_BYTES,
  MAX_CALL_SIGNAL_BYTES,
  MESSAGE_RATE_LIMIT_WINDOW_MS,
  MESSAGE_RATE_LIMIT_MAX
} from '../constants';

const textEncoder = new TextEncoder();

export const exceedsBytes = (input: string, limit: number): boolean => {
  return textEncoder.encode(input).length > limit;
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
