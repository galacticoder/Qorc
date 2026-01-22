import type { SecureDB } from '../../lib/database/secureDB';
import type { User } from '../../components/chat/messaging/UserList';
import { EventType } from '../../lib/types/event-types';
import { isPlainObject, hasPrototypePollutionKeys } from '../../lib/sanitizers';
import { sanitizeDbUsername, sanitizeMappingPayload } from '../../lib/utils/database-utils';
import { validateEventDetail } from '../../lib/utils/shared-utils';
import { DB_RATE_LIMIT_WINDOW_MS, DB_RATE_LIMIT_MAX_EVENTS, DB_MAX_PENDING_MAPPINGS } from '../../lib/constants';
import type { RateLimitBucket, MappingPayload } from '../../lib/types/database-types';

// Handle username mapping received event
export const handleMappingReceived = async (
  detail: unknown,
  secureDB: SecureDB,
  rateLimitBucket: RateLimitBucket
): Promise<boolean> => {
  const now = Date.now();
  if (now - rateLimitBucket.windowStart > DB_RATE_LIMIT_WINDOW_MS) {
    rateLimitBucket.windowStart = now;
    rateLimitBucket.count = 0;
  }
  rateLimitBucket.count += 1;
  if (rateLimitBucket.count > DB_RATE_LIMIT_MAX_EVENTS) {
    return false;
  }

  if (!validateEventDetail(detail)) return false;

  const sanitized = sanitizeMappingPayload(detail);
  if (!sanitized) return false;

  await secureDB.storeUsernameMapping(sanitized.hashed, sanitized.original);
  try {
    window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, {
      detail: { username: sanitized.hashed, hashed: sanitized.hashed, original: sanitized.original }
    }));
  } catch { }

  return true;
};

// Handle user keys available event
export const handleUserKeysAvailable = (
  detail: unknown,
  users: User[],
  rateLimitBucket: RateLimitBucket
): User[] | null => {
  const now = Date.now();
  if (now - rateLimitBucket.windowStart > DB_RATE_LIMIT_WINDOW_MS) {
    rateLimitBucket.windowStart = now;
    rateLimitBucket.count = 0;
  }
  rateLimitBucket.count += 1;
  if (rateLimitBucket.count > DB_RATE_LIMIT_MAX_EVENTS) {
    return null;
  }

  if (!validateEventDetail(detail)) return null;

  const username = sanitizeDbUsername((detail as any).username);
  if (!username) return null;

  const hybridKeys = (detail as any).hybridKeys;
  if (!isPlainObject(hybridKeys) || hasPrototypePollutionKeys(hybridKeys)) return null;
  if (typeof hybridKeys.kyberPublicBase64 !== 'string' || typeof hybridKeys.dilithiumPublicBase64 !== 'string') {
    return null;
  }

  const idx = users.findIndex(u => u.username === username);
  if (idx === -1) return null;

  if (JSON.stringify(users[idx].hybridPublicKeys) === JSON.stringify(hybridKeys)) {
    return null;
  }

  const newUsers = [...users];
  newUsers[idx] = { ...users[idx], hybridPublicKeys: hybridKeys as User['hybridPublicKeys'] };
  return newUsers;
};

// Queue pending mapping before DB is initialized
export const queuePendingMapping = (
  detail: unknown,
  pendingMappings: MappingPayload[]
): MappingPayload[] | null => {
  if (!validateEventDetail(detail)) return null;

  const sanitized = sanitizeMappingPayload(detail);
  if (!sanitized) return null;

  if (pendingMappings.length >= DB_MAX_PENDING_MAPPINGS) {
    return null;
  }

  return [...pendingMappings, sanitized];
};

// Flush pending mappings to database
export const flushPendingMappings = async (
  secureDB: SecureDB,
  pendingMappings: MappingPayload[]
): Promise<void> => {
  for (const m of pendingMappings) {
    try {
      await secureDB.storeUsernameMapping(m.hashed, m.original);
      try {
        window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, {
          detail: { username: m.hashed, hashed: m.hashed, original: m.original }
        }));
      } catch { }
    } catch (err) {
      console.error('[flushPendingMappings] Failed to flush mapping:', err);
    }
  }
  try {
    window.dispatchEvent(new CustomEvent(EventType.USERNAME_MAPPING_UPDATED, {
      detail: { username: '__all__' }
    }));
  } catch { }
};
