import { AUTH_USERNAME_REGEX } from '../constants';

export const shouldAttemptDiscovery = (
  handle: string | undefined | null
): boolean => {
  if (!handle || typeof handle !== 'string') return false;
  const trimmed = handle.trim();
  if (!trimmed) return false;

  return AUTH_USERNAME_REGEX.test(trimmed);
};
