import { USERNAME_REGEX } from './constants';
import { SignalType } from './types/signal-types';
import { MAX_CONTENT_LENGTH, MAX_USERNAME_LENGTH } from './constants';

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

// Sanitize message content
export const sanitizeMessage = (input: string): string => {
  const MAX_LENGTH = 10000;

  let sanitized = input.normalize('NFC').trim();
  if (sanitized.length > MAX_LENGTH) {
    sanitized = sanitized.slice(0, MAX_LENGTH);
  }

  sanitized = sanitized
    .replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u2000-\u200F\u2028-\u202F\u205F-\u206F\uFEFF\uFFF0-\uFFFF]/g, '')
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, '')
    .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
    .replace(/[\u0300-\u036F]{5,}/g, '')
    .replace(/[\uD800-\uDFFF]/g, '')
    .replace(/[\uFDD0-\uFDEF]/g, '')
    .replace(/[\u0001-\u0008\u000E-\u001F\u007F]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

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
  if (typeof name !== 'string') return SignalType.FILE;

  let out = name.normalize('NFKC');
  out = out.replace(UNSAFE_FILENAME_CHARS_REGEX, '_');
  out = out.replace(WHITESPACE_COLLAPSE_REGEX, ' ').trim();

  if (!out) out = SignalType.FILE;
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

// Sanitize usernames
export const sanitizeUsername = (value: unknown, maxLen?: number): string | null => {
  if (typeof value !== 'string') return null;
  const maxLength = maxLen ?? MAX_USERNAME_LENGTH;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) return null;
  if (/[^\x20-\x7E]/.test(trimmed)) return null;
  return trimmed;
};


// Sanitize message ID values
export const sanitizeMessageId = (id: string | undefined) => {
  if (!id || typeof id !== 'string') return undefined;
  const trimmed = sanitizeTextInput(id, { maxLength: 256, allowNewlines: false });
  return trimmed.length ? trimmed : undefined;
};

// Sanitize event username values
export const sanitizeEventUsername = (value: unknown, maxLen: number): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLen) return null;
  const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
  if (!cleaned) return null;
  return cleaned.slice(0, maxLen);
};

// Sanitize message content values
export const sanitizeContent = (value: string | undefined) => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const normalized = trimmed.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  return normalized.slice(0, MAX_CONTENT_LENGTH);
};

// Check if username is valid according to app rules
export const isValidUsername = (username: unknown): username is string => {
  if (typeof username !== 'string') return false;
  if (!USERNAME_REGEX.test(username)) return false;
  const reserved = ['__proto__', 'constructor', 'prototype'];
  if (reserved.includes(username.toLowerCase())) return false;
  return true;
};

// Sanitize UI text by trimming, removing control chars, and truncating
export const sanitizeUiText = (value: unknown, maxLen: number): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
  if (!cleaned) return null;
  return cleaned.slice(0, maxLen);
};

// Sanitize generic event text values
export const sanitizeEventText = (value: unknown, maxLen: number): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const cleaned = trimmed.replace(/[\x00-\x1F\x7F]/g, '');
  if (!cleaned) return null;
  return cleaned.slice(0, maxLen);
};

export const sanitizeErrorMessage = (error: unknown): string => {
  if (!error) return 'UNKNOWN';
  if (typeof error === 'string') return error.slice(0, 80);
  if (error instanceof Error) return error.message.slice(0, 80);
  return 'UNRECOGNIZED_ERROR';
};

export type { TextSanitizeOptions, AllowedKey };
