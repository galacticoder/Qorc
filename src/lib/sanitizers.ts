const DEFAULT_ALLOWED_KEYS = ['username', 'type', 'peer', 'at', 'callId', 'status', 'startTime', 'endTime', 'durationMs', 'direction'] as const;

type AllowedKey = typeof DEFAULT_ALLOWED_KEYS[number];

interface TextSanitizeOptions {
  maxLength?: number;
  allowNewlines?: boolean;
}

const CONTROL_CHARS_REGEX = /[\u0000-\u001F\u007F]/g;
const NEWLINE_REGEX = /[\r\n]+/g;

export const sanitizeTextInput = (input: string, options: TextSanitizeOptions = {}): string => {
  const { maxLength = 256, allowNewlines = true } = options;

  let sanitized = input.normalize('NFKC');
  sanitized = sanitized.replace(CONTROL_CHARS_REGEX, '');

  if (!allowNewlines) {
    sanitized = sanitized.replace(NEWLINE_REGEX, ' ');
  }

  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength);
  }

  return sanitized;
};

export const sanitizeEventPayload = (detail: Record<string, unknown>, allowedKeys?: string[]): Record<string, unknown> => {
  const allowed = new Set<string>(allowedKeys?.length ? allowedKeys : DEFAULT_ALLOWED_KEYS);
  const sanitized: Record<string, unknown> = {};

  for (const key of Object.keys(detail)) {
    if (!allowed.has(key)) {
      continue;
    }
    const value = detail[key];
    if (value === null || value === undefined) {
      continue;
    }
    if (typeof value === 'string') {
      sanitized[key] = sanitizeTextInput(value, { maxLength: 256, allowNewlines: false });
    } else if (typeof value === 'number') {
      sanitized[key] = Number.isFinite(value) ? value : 0;
    } else if (typeof value === 'boolean') {
      sanitized[key] = value;
    }
  }

  return sanitized;
};

const UNSAFE_FILENAME_CHARS_REGEX = /[\u0000-\u001F\u007F/\\:*?"<>|]+/g;
const WHITESPACE_COLLAPSE_REGEX = /\s+/g;

export const sanitizeFilename = (name: string, maxLength: number = 128): string => {
  if (typeof name !== 'string') return 'file';

  let out = name.normalize('NFKC');
  out = out.replace(UNSAFE_FILENAME_CHARS_REGEX, '_');
  out = out.replace(WHITESPACE_COLLAPSE_REGEX, ' ').trim();

  if (!out) out = 'file';
  if (out.length > maxLength) out = out.slice(0, maxLength);

  return out;
};

export const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

export const hasPrototypePollutionKeys = (obj: unknown): boolean => {
  if (obj == null || typeof obj !== 'object') return false;
  const keys = Object.keys(obj as Record<string, unknown>);
  return keys.some((key) => key === '__proto__' || key === 'constructor' || key === 'prototype');
};

export const isUnsafeObjectKey = (value: string): boolean => {
  return value === '__proto__' || value === 'constructor' || value === 'prototype';
};

export const sanitizeNonEmptyText = (value: unknown, maxLength: number, allowNewlines: boolean): string | null => {
  if (typeof value !== 'string') return null;
  const cleaned = sanitizeTextInput(value, { maxLength, allowNewlines }).trim();
  return cleaned.length ? cleaned : null;
};

export type { TextSanitizeOptions, AllowedKey };

