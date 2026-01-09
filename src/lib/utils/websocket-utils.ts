/**
 * WebSocket Utility Functions
 */


import { SANITIZE_REGEX } from '../constants';

export const estimateBase64DecodedBytes = (value: string): number => {
  const trimmed = value.trim();
  if (!trimmed) return 0;
  const pad = trimmed.endsWith('==') ? 2 : trimmed.endsWith('=') ? 1 : 0;
  return Math.floor((trimmed.length * 3) / 4) - pad;
};

export function sanitizeString(input: string | undefined | null): string | undefined {
  if (typeof input !== 'string') return undefined;
  const sanitized = input.replace(SANITIZE_REGEX, '').trim();
  return sanitized || undefined;
}