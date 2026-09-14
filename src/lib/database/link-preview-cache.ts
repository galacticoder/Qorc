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

const CACHE_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const MAX_CACHE_ENTRIES = 48;
const MAX_CACHE_BYTES = 24 * 1024 * 1024;
const MAX_RECORD_BYTES = 3 * 1024 * 1024;
const MAX_IMAGE_DATA_URL_LENGTH = 2_100_000;
const writeChains = new WeakMap<SecureDB, Promise<void>>();
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
    !isNullableBoundedString(candidate.imageDataUrl, MAX_IMAGE_DATA_URL_LENGTH) ||
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
  if (candidate.entries.length > MAX_CACHE_ENTRIES) {
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
      entry.size > MAX_RECORD_BYTES ||
      seen.has(entry.key)
    ) {
      throw new Error('Link preview cache index is invalid');
    }
    seen.add(entry.key);
    entries.push({ key: entry.key, fetchedAt: entry.fetchedAt, size: entry.size });
  }
  return entries;
};

const enqueueWrite = (db: SecureDB, operation: () => Promise<void>): Promise<void> => {
  const previous = writeChains.get(db) || Promise.resolve();
  const next = previous.catch(() => undefined).then(operation);
  writeChains.set(db, next);
  void next.finally(() => {
    if (writeChains.get(db) === next) writeChains.delete(db);
  }).catch(() => undefined);
  return next;
};

const removeRecord = (db: SecureDB, key: string): Promise<void> => enqueueWrite(db, async () => {
  const rawIndex = await db.retrieve(STORAGE_STORES.LINK_PREVIEWS, STORAGE_KEYS.LINK_PREVIEW_INDEX);
  const entries = parseIndex(rawIndex).filter((entry) => entry.key !== key);
  await db.delete(STORAGE_STORES.LINK_PREVIEWS, key);
  await db.store(STORAGE_STORES.LINK_PREVIEWS, STORAGE_KEYS.LINK_PREVIEW_INDEX, {
    version: 1,
    entries,
  } satisfies LinkPreviewCacheIndex);
});

export const loadLinkPreviewFromCache = async (
  db: SecureDB,
  url: string,
): Promise<NativeLinkPreview | null> => {
  const pendingWrite = writeChains.get(db);
  if (pendingWrite) await pendingWrite;
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
    record.size! > MAX_RECORD_BYTES ||
    record.size !== actualSize ||
    !preview
  ) {
    throw new Error('Link preview cache record is invalid');
  }
  if (Date.now() - record.fetchedAt! > CACHE_TTL_MS) {
    await removeRecord(db, key);
    return null;
  }
  return preview;
};

export const saveLinkPreviewToCache = async (
  db: SecureDB,
  preview: NativeLinkPreview,
): Promise<void> => {
  const normalized = parsePreview(preview, preview.url);
  if (!normalized) throw new Error('Link preview is invalid');
  const fetchedAt = Date.now();
  const serializedPreview = JSON.stringify(normalized);
  const size = encoder.encode(serializedPreview).byteLength;
  if (size <= 0 || size > MAX_RECORD_BYTES) throw new Error('Link preview exceeds its fixed capacity');
  const key = cacheKey(normalized.url);
  const record: LinkPreviewCacheRecord = { version: 1, fetchedAt, size, preview: normalized };

  await enqueueWrite(db, async () => {
    const rawIndex = await db.retrieve(STORAGE_STORES.LINK_PREVIEWS, STORAGE_KEYS.LINK_PREVIEW_INDEX);
    const expiredBefore = fetchedAt - CACHE_TTL_MS;
    const expiredKeys: string[] = [];
    const entries = parseIndex(rawIndex).filter((entry) => {
      const keep = entry.key !== key && entry.fetchedAt >= expiredBefore;
      if (!keep && entry.key !== key) expiredKeys.push(entry.key);
      return keep;
    });
    entries.sort((left, right) => right.fetchedAt - left.fetchedAt);
    entries.unshift({ key, fetchedAt, size });
    let totalBytes = entries.reduce((total, entry) => total + entry.size, 0);
    while (entries.length > MAX_CACHE_ENTRIES || totalBytes > MAX_CACHE_BYTES) {
      const evicted = entries.pop();
      if (!evicted) break;
      totalBytes -= evicted.size;
      if (evicted.key !== key) expiredKeys.push(evicted.key);
    }

    await db.store(STORAGE_STORES.LINK_PREVIEWS, key, record);
    await db.store(STORAGE_STORES.LINK_PREVIEWS, STORAGE_KEYS.LINK_PREVIEW_INDEX, {
      version: 1,
      entries,
    } satisfies LinkPreviewCacheIndex);
    await Promise.all(expiredKeys.map((expiredKey) => (
      db.delete(STORAGE_STORES.LINK_PREVIEWS, expiredKey)
    )));
  });
};
