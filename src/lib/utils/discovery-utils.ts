import { AUTH_USERNAME_REGEX } from '../constants';

const BLIND_HANDLE_REGEX = /^[a-f0-9]{64}$/i;
const RELAY_HASH_REGEX = /^[a-f0-9]{32}$/i;
const INBOX_ID_REGEX = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-a[a-f0-9]{3}-[a-f0-9]{12}$/i;

export const shouldAttemptDiscovery = (
  handle: string | undefined | null,
  knownUsernames?: Iterable<string>
): boolean => {
  if (!handle || typeof handle !== 'string') return false;
  const trimmed = handle.trim();
  if (!trimmed) return false;

  if (knownUsernames) {
    for (const name of knownUsernames) {
      if (name === trimmed) return true;
    }
  }

  if (BLIND_HANDLE_REGEX.test(trimmed)) return true;
  if (RELAY_HASH_REGEX.test(trimmed)) return false;
  if (INBOX_ID_REGEX.test(trimmed)) return false;

  return AUTH_USERNAME_REGEX.test(trimmed);
};
