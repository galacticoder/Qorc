import {
  USERNAME_DISPLAY_MAX_LENGTH,
  USERNAME_ANON_PREFIX,
  USERNAME_HEX_PATTERN,
  USERNAME_OBFUSCATED_LENGTH,
  USERNAME_DISPLAY_CACHE_TTL_MS,
  USERNAME_DISPLAY_MAX_CACHE_SIZE,
  SECURE_DB_MAX_FILE_SIZE,
  SECURE_DB_MAX_TOTAL_FILE_STORAGE,
  SECURE_DB_BLOCKED_MIME_TYPES,
} from '../constants';
import type { MappingPayload, ResolveCache } from '../types/database-types';

// Sanitize username for database operations
export const sanitizeDbUsername = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > USERNAME_DISPLAY_MAX_LENGTH) return null;
  if (/[\x00-\x1F\x7F]/.test(trimmed)) return null;
  return trimmed;
};

// Sanitize mapping payload
export const sanitizeMappingPayload = (value: unknown): MappingPayload | null => {
  if (!value || typeof value !== 'object') return null;
  const hashed = sanitizeDbUsername((value as any).hashed);
  const original = sanitizeDbUsername((value as any).original);
  if (!hashed || !original) return null;
  return { hashed, original };
};

// Anonymize username for display
export const anonymizeUsername = (username: string): string => {
  let hexCandidate: string;
  if (USERNAME_HEX_PATTERN.test(username)) {
    hexCandidate = username;
  } else {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(username);
    hexCandidate = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return `${USERNAME_ANON_PREFIX}${hexCandidate.slice(0, USERNAME_OBFUSCATED_LENGTH)}`;
};

// Global username display cache
const globalResolveCache = new Map<string, ResolveCache>();
const globalInflightRequests = new Map<string, Promise<string>>();

export const getCachedDisplayName = (username: string): string | null => {
  const cached = globalResolveCache.get(username);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.displayName;
  }
  if (cached) {
    globalResolveCache.delete(username);
  }
  return null;
};

export const setCachedDisplayName = (username: string, displayName: string): void => {
  globalResolveCache.set(username, {
    displayName,
    expiresAt: Date.now() + USERNAME_DISPLAY_CACHE_TTL_MS,
  });
  if (globalResolveCache.size > USERNAME_DISPLAY_MAX_CACHE_SIZE) {
    const entries = [...globalResolveCache.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    const toRemove = Math.floor(USERNAME_DISPLAY_MAX_CACHE_SIZE * 0.2);
    for (let i = 0; i < toRemove && i < entries.length; i++) {
      globalResolveCache.delete(entries[i][0]);
    }
  }
};

export const getInflightRequest = (username: string): Promise<string> | undefined => {
  return globalInflightRequests.get(username);
};

export const setInflightRequest = (username: string, promise: Promise<string>): void => {
  globalInflightRequests.set(username, promise);
};

export const deleteInflightRequest = (username: string): void => {
  globalInflightRequests.delete(username);
};

// Promise timeout wrapper
export const withTimeout = <T>(promise: Promise<T>, timeoutMs: number): Promise<T> => {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error('RESOLVE_TIMEOUT')), timeoutMs);
    }),
  ]);
};

// Pre-warm cache with mappings from database
export const prewarmUsernameCache = (mappings: Array<{ hashed: string; original: string }>): void => {
  for (const { hashed, original } of mappings) {
    const sanitizedHash = sanitizeDbUsername(hashed);
    const sanitizedOriginal = sanitizeDbUsername(original);
    if (sanitizedHash && sanitizedOriginal && !USERNAME_HEX_PATTERN.test(sanitizedOriginal)) {
      setCachedDisplayName(sanitizedHash, sanitizedOriginal);
    }
  }
};

// Validate file data
export const validateFileData = (data: ArrayBuffer | Blob, fileId: string): void => {
  const size = data instanceof Blob ? data.size : data.byteLength;

  if (size > SECURE_DB_MAX_FILE_SIZE) {
    throw new Error(`File too large: ${size} bytes (max: ${SECURE_DB_MAX_FILE_SIZE})`);
  }

  if (size === 0) {
    throw new Error('File is empty');
  }

  if (!fileId || typeof fileId !== 'string' || fileId.length === 0 || fileId.length > 255) {
    throw new Error('Invalid file ID');
  }

  if (data instanceof Blob && data.type) {
    const mimeType = data.type.toLowerCase();
    if (SECURE_DB_BLOCKED_MIME_TYPES.some(blocked => mimeType.includes(blocked))) {
      throw new Error(`Blocked file type: ${data.type}`);
    }
  }
}

// Get total storage used by all files in bytes
export const getFilesStorageUsage = async (kv: any): Promise<{ used: number; limit: number; available: number }> => {
  try {
    const entries = await kv.entriesForStore('files');
    let totalSize = 0;
    for (const { value } of entries) {
      if (value instanceof Uint8Array) {
        totalSize += value.byteLength;
      }
    }
    return {
      used: totalSize,
      limit: SECURE_DB_MAX_TOTAL_FILE_STORAGE,
      available: Math.max(0, SECURE_DB_MAX_TOTAL_FILE_STORAGE - totalSize)
    };
  } catch (err) {
    console.error('Failed to get files storage usage:', err);
    return { used: 0, limit: SECURE_DB_MAX_TOTAL_FILE_STORAGE, available: SECURE_DB_MAX_TOTAL_FILE_STORAGE };
  }
}
