import {
  isPlainObject,
  hasPrototypePollutionKeys,
  sanitizeUsername,
  sanitizeEventUsername,
  isValidUsername
} from '../lib/sanitizers';

export { isPlainObject, hasPrototypePollutionKeys, sanitizeUsername, sanitizeEventUsername, isValidUsername };

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