import {
  LINK_PREVIEW_CACHE_TTL_MS,
  MAX_LINK_PREVIEW_CACHE_BYTES,
  MAX_LINK_PREVIEW_CACHE_ENTRIES,
  MAX_LINK_PREVIEW_IMAGE_DATA_URL_LENGTH,
  MAX_LINK_PREVIEW_RECORD_BYTES,
} from '../constants';
import { blake3 } from '@noble/hashes/blake3.js';
import type { NativeLinkPreview } from '../tauri-bindings';
import { hasExactObjectKeys } from '../sanitizers';
import type { SecureDB } from './secureDB';
import { STORAGE_KEYS, STORAGE_KEY_DOMAINS, STORAGE_STORES } from './storage-keys';
import { bytesToHex } from '../../../shared/bytes.js';

interface LinkPreviewCacheRecord {
  version: 1;
  fetchedAt: number;
  size: number;
  preview: NativeLinkPreview;
}

interface LinkPreviewCacheIndexEntry {
  key: string;
  fetchedAt: number;
  size: number;
}

interface LinkPreviewCacheIndex {
  version: 1;
  entries: LinkPreviewCacheIndexEntry[];
}

const cacheOperations = new WeakMap<SecureDB, Promise<void>>();
const reconciledCaches = new WeakSet<SecureDB>();
const encoder = new TextEncoder();

const cacheKey = (url: string): string => {
  const input = encoder.encode(`${STORAGE_KEY_DOMAINS.LINK_PREVIEW_CACHE}\0${url}`);
  const digest = blake3(input, { dkLen: 32 });
  try {
    return bytesToHex(digest);
  } finally {
    input.fill(0);
    digest.fill(0);
  }
};

const isBoundedString = (value: unknown, maxLength: number): value is string => (
  typeof value === 'string' && value.length > 0 && value.length <= maxLength
);

const isNullableBoundedString = (value: unknown, maxLength: number): value is string | null => (
  value === null || (typeof value === 'string' && value.length <= maxLength)
);

const parsePreview = (value: unknown, expectedUrl: string): NativeLinkPreview | null => {
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Partial<NativeLinkPreview>;
  if (
    candidate.url !== expectedUrl ||
    !isBoundedString(candidate.url, 2048) ||
    !isBoundedString(candidate.displayUrl, 2048) ||
    !isBoundedString(candidate.host, 253) ||
    !isNullableBoundedString(candidate.title, 120) ||
    !isNullableBoundedString(candidate.description, 240) ||
    !isNullableBoundedString(candidate.imageDataUrl, MAX_LINK_PREVIEW_IMAGE_DATA_URL_LENGTH) ||
    (candidate.imageDataUrl !== null && !/^data:image\/(?:png|jpeg|gif|webp);base64,/.test(candidate.imageDataUrl))
  ) {
    return null;
  }
  return {
    url: candidate.url,
    displayUrl: candidate.displayUrl,
    host: candidate.host,
    title: candidate.title,
    description: candidate.description,
    imageDataUrl: candidate.imageDataUrl,
  };
};

const parseIndex = (value: unknown): LinkPreviewCacheIndexEntry[] => {
  if (value === null || value === undefined) return [];
  if (!hasExactObjectKeys(value, ['entries', 'version'])) {
    throw new Error('Link preview cache index is invalid');
  }
  const candidate = value as unknown as LinkPreviewCacheIndex;
  if (candidate.version !== 1 || !Array.isArray(candidate.entries)) {
    throw new Error('Link preview cache index is invalid');
  }
  if (candidate.entries.length > MAX_LINK_PREVIEW_CACHE_ENTRIES) {
    throw new Error('Link preview cache index exceeds its fixed capacity');
  }
  const seen = new Set<string>();
  const entries: LinkPreviewCacheIndexEntry[] = [];
  for (const entry of candidate.entries) {
    if (
      !hasExactObjectKeys(entry, ['fetchedAt', 'key', 'size']) ||
      !/^[a-f0-9]{64}$/.test(entry.key) ||
      !Number.isSafeInteger(entry.fetchedAt) ||
      entry.fetchedAt <= 0 ||
      !Number.isSafeInteger(entry.size) ||
      entry.size <= 0 ||
      entry.size > MAX_LINK_PREVIEW_RECORD_BYTES ||
      seen.has(entry.key)
    ) {
      throw new Error('Link preview cache index is invalid');
    }
    seen.add(entry.key);
    entries.push({ key: entry.key, fetchedAt: entry.fetchedAt, size: entry.size });
  }
  return entries;
};

const enqueueCacheOperation = <T>(db: SecureDB, operation: () => Promise<T>): Promise<T> => {
  const previous = cacheOperations.get(db) ?? Promise.resolve();
  const result = previous.then(operation);
  const tail = result.then(() => undefined, () => undefined);
  cacheOperations.set(db, tail);
  void tail.then(() => {
    if (cacheOperations.get(db) === tail) cacheOperations.delete(db);
  });
  return result;
};

const loadIndex = async (db: SecureDB): Promise<LinkPreviewCacheIndexEntry[]> => (
  parseIndex(await db.retrieve(STORAGE_STORES.LINK_PREVIEWS, STORAGE_KEYS.LINK_PREVIEW_INDEX))
);

async function reconcileCache(db: SecureDB): Promise<void> {
  if (reconciledCaches.has(db)) return;
  const [index, keys] = await Promise.all([loadIndex(db), db.listLinkPreviewCacheKeys()]);
  const existing = new Set(keys.filter(key => key !== STORAGE_KEYS.LINK_PREVIEW_INDEX));
  const indexed = new Set(index.map(entry => entry.key));
  const orphans = [...existing].filter(key => !indexed.has(key));
  if (orphans.length) await db.removeUnindexedLinkPreviews(orphans);
  const cutoff = Date.now() - LINK_PREVIEW_CACHE_TTL_MS;
  const entries = index.filter(entry => existing.has(entry.key) && entry.fetchedAt >= cutoff);
  const kept = new Set(entries.map(entry => entry.key));
  const deletedKeys = index.flatMap(({ key }) => existing.has(key) && !kept.has(key) ? [key] : []);
  if (entries.length !== index.length) {
    await db.mutateLinkPreviewCache({ version: 1, entries } satisfies LinkPreviewCacheIndex, deletedKeys);
  }
  reconciledCaches.add(db);
}

export const loadLinkPreviewFromCache = async (
  db: SecureDB,
  url: string,
): Promise<NativeLinkPreview | null> => enqueueCacheOperation(db, async () => {
  await reconcileCache(db);
  const key = cacheKey(url);
  const value = await db.retrieve(STORAGE_STORES.LINK_PREVIEWS, key);
  if (value === null || value === undefined) return null;
  if (!hasExactObjectKeys(value, ['fetchedAt', 'preview', 'size', 'version'])) {
    throw new Error('Link preview cache record is invalid');
  }
  const record = value as Partial<LinkPreviewCacheRecord>;
  const preview = parsePreview(record.preview, url);
  const actualSize = preview ? encoder.encode(JSON.stringify(preview)).byteLength : 0;
  if (
    record.version !== 1 ||
    !Number.isSafeInteger(record.fetchedAt) ||
    record.fetchedAt! <= 0 ||
    !Number.isSafeInteger(record.size) ||
    record.size! <= 0 ||
    record.size! > MAX_LINK_PREVIEW_RECORD_BYTES ||
    record.size !== actualSize ||
    !preview
  ) {
    throw new Error('Link preview cache record is invalid');
  }
  if (Date.now() - record.fetchedAt! > LINK_PREVIEW_CACHE_TTL_MS) {
    const entries = (await loadIndex(db)).filter(entry => entry.key !== key);
    await db.mutateLinkPreviewCache({ version: 1, entries } satisfies LinkPreviewCacheIndex, [key]);
    return null;
  }
  return preview;
});

export const saveLinkPreviewToCache = async (
  db: SecureDB,
  preview: NativeLinkPreview,
): Promise<void> => {
  const normalized = parsePreview(preview, preview.url);
  if (!normalized) throw new Error('Link preview is invalid');
  const fetchedAt = Date.now();
  const serializedPreview = JSON.stringify(normalized);
  const size = encoder.encode(serializedPreview).byteLength;
  if (size <= 0 || size > MAX_LINK_PREVIEW_RECORD_BYTES) throw new Error('Link preview exceeds its fixed capacity');
  const key = cacheKey(normalized.url);
  const record: LinkPreviewCacheRecord = { version: 1, fetchedAt, size, preview: normalized };

  await enqueueCacheOperation(db, async () => {
    await reconcileCache(db);
    const expiredBefore = fetchedAt - LINK_PREVIEW_CACHE_TTL_MS;
    const expiredKeys: string[] = [];
    const entries = (await loadIndex(db)).filter((entry) => {
      const keep = entry.key !== key && entry.fetchedAt >= expiredBefore;
      if (!keep && entry.key !== key) expiredKeys.push(entry.key);
      return keep;
    });
    entries.sort((left, right) => right.fetchedAt - left.fetchedAt);
    entries.unshift({ key, fetchedAt, size });
    let totalBytes = entries.reduce((total, entry) => total + entry.size, 0);
    while (entries.length > MAX_LINK_PREVIEW_CACHE_ENTRIES || totalBytes > MAX_LINK_PREVIEW_CACHE_BYTES) {
      const evicted = entries.pop();
      if (!evicted) break;
      totalBytes -= evicted.size;
      if (evicted.key !== key) expiredKeys.push(evicted.key);
    }

    await db.mutateLinkPreviewCache(
      { version: 1, entries } satisfies LinkPreviewCacheIndex,
      expiredKeys,
      { key, value: record },
    );
  });
};
