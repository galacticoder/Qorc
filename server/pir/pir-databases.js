import { DiscoveryDB } from '../database/database.js';
import {
  DISCOVERY_PIR_DATABASE_KIND,
  buildPirPageDatabase,
  getPirLayoutConfig,
  isPirDatabaseKind
} from './page-layout.js';
import { fetchPirWorkerPublicParams, getPirWorkerConfig, uploadPirDatabase } from './pir-worker-client.js';
import { buildOpaqueDiscoverySourceRecords } from './opaque-discovery-source-records.js';
import { logger as cryptoLogger } from '../crypto/crypto-logger.js';

const epochCache = new Map();
const epochHistory = new Map();
const PIR_WORKER_UPLOAD_RETRY_MS = envInt(
  'PIR_WORKER_UPLOAD_RETRY_MS',
  60_000,
  5_000,
  10 * 60 * 1000
);
const PIR_WORKER_UPLOAD_TRANSIENT_RETRY_MS = envInt(
  'PIR_WORKER_UPLOAD_TRANSIENT_RETRY_MS',
  5_000,
  500,
  60_000
);
const PIR_EPOCH_GRACE_MS = envInt(
  'PIR_EPOCH_GRACE_MS',
  10 * 60 * 1000,
  60 * 1000,
  6 * 60 * 60 * 1000
);
const PIR_EPOCH_HISTORY_MAX_ENTRIES = envInt(
  'PIR_EPOCH_HISTORY_MAX_ENTRIES',
  4,
  0,
  128
);
let lastEpochHistoryCleanupAt = 0;

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function envBool(name, fallback = false) {
  const raw = (process.env[name] || '').trim().toLowerCase();
  if (!raw) return fallback;
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function cacheKey(kind) {
  return `${kind}`;
}

function historyKey(kind, epochId) {
  return `${kind}:${epochId}`;
}

function msClass(ms) {
  if (!Number.isFinite(ms)) return 'unknown';
  const abs = Math.abs(ms);
  if (abs <= 1_000) return 'lte-1s';
  if (abs <= 10_000) return 'lte-10s';
  if (abs <= 60_000) return 'lte-1m';
  if (abs <= 5 * 60_000) return 'lte-5m';
  if (abs <= 30 * 60_000) return 'lte-30m';
  return 'gt-30m';
}

function historyEntryKeepUntil(database, now = Date.now()) {
  const expiresAt = Number(database?.manifest?.expiresAt);
  return Math.max(Number.isFinite(expiresAt) ? expiresAt : 0, now) + PIR_EPOCH_GRACE_MS;
}

function retainHistoricalDatabase(database) {
  if (!database?.manifest) return database;
  const {
    recordDigests: _recordDigests,
    payloadDigests: _payloadDigests,
    ...manifest
  } = database.manifest;
  const wasUploaded = database.uploadedToWorker === true;
  return {
    manifest,
    records: database.records,
    blobsByBucket: database.blobsByBucket,
    blobsBySlot: database.blobsBySlot,
    uploadedToWorker: wasUploaded,
    workerUpload: wasUploaded ? database.workerUpload : undefined,
    workerPublicParams: database.workerPublicParams
  };
}

function stripRuntimeDebugFields(database) {
  if (!database || envBool('PIR_RETAIN_RECORD_DIGESTS', false) || envBool('PIR_MANIFEST_INCLUDE_RECORD_DIGESTS', false)) {
    return database;
  }
  delete database.recordDigests;
  if (database.manifest) {
    delete database.manifest.recordDigests;
    delete database.manifest.payloadDigests;
  }
  if (!envBool('PIR_RETAIN_BLOBS_BY_SLOT', false)) {
    delete database.blobsBySlot;
  }
  return database;
}

function cleanupEpochHistory(now = Date.now(), force = false) {
  if (!force && (now - lastEpochHistoryCleanupAt) < 30_000) return;
  lastEpochHistoryCleanupAt = now;
  for (const [key, entry] of epochHistory.entries()) {
    if (!entry?.database?.manifest?.epochId || Number(entry.keepUntil) <= now) {
      epochHistory.delete(key);
    }
  }
  if (PIR_EPOCH_HISTORY_MAX_ENTRIES > 0 && epochHistory.size > PIR_EPOCH_HISTORY_MAX_ENTRIES) {
    const entries = Array.from(epochHistory.entries())
      .sort((a, b) => Number(a[1]?.keepUntil || 0) - Number(b[1]?.keepUntil || 0));
    for (const [key] of entries) {
      if (epochHistory.size <= PIR_EPOCH_HISTORY_MAX_ENTRIES) break;
      epochHistory.delete(key);
    }
  } else if (PIR_EPOCH_HISTORY_MAX_ENTRIES === 0) {
    epochHistory.clear();
  }
}

function rememberPirDatabase(kind, database, now = Date.now()) {
  const epochId = database?.manifest?.epochId;
  if (typeof epochId !== 'string' || !epochId) return;
  const key = historyKey(kind, epochId);
  const keepUntil = historyEntryKeepUntil(database, now);
  const existing = epochHistory.get(key);
  if (
    !existing ||
    Number(existing.keepUntil) < keepUntil ||
    (database.uploadedToWorker === true && existing.database?.uploadedToWorker !== true)
  ) {
    epochHistory.set(key, { database: retainHistoricalDatabase(database), keepUntil });
  }
  cleanupEpochHistory(now);
}

function cachePirDatabase(kind, database, now = Date.now()) {
  const previous = epochCache.get(cacheKey(kind));
  if (previous && previous !== database) {
    rememberPirDatabase(kind, previous, now);
  }
  epochCache.set(cacheKey(kind), database);
  rememberPirDatabase(kind, database, now);
}

function getRememberedPirDatabase(kind, epochId, now = Date.now()) {
  cleanupEpochHistory(now);
  const active = epochCache.get(cacheKey(kind));
  if (active?.manifest?.epochId === epochId) {
    rememberPirDatabase(kind, active, now);
    return active;
  }

  const entry = epochHistory.get(historyKey(kind, epochId));
  if (entry && Number(entry.keepUntil) > now) {
    return entry.database;
  }
  if (entry) {
    epochHistory.delete(historyKey(kind, epochId));
  }
  return null;
}

function epochCacheDiagnostic(kind, requestedEpochId) {
  const now = Date.now();
  cleanupEpochHistory(now);
  const active = epochCache.get(cacheKey(kind));
  const historyEntry = requestedEpochId ? epochHistory.get(historyKey(kind, requestedEpochId)) : undefined;
  const kindHistoryCount = Array.from(epochHistory.values())
    .filter((entry) => entry?.database?.manifest?.kind === kind)
    .length;
  const activeExpiresInMs = Number(active?.manifest?.expiresAt) - now;
  const historyKeepAliveMs = Number(historyEntry?.keepUntil) - now;
  return {
    requestedEpochId,
    activeEpochId: active?.manifest?.epochId,
    activeEpochMatches: active?.manifest?.epochId === requestedEpochId,
    activeExpiresInMs: Number.isFinite(activeExpiresInMs) ? activeExpiresInMs : undefined,
    activeExpiresInClass: msClass(activeExpiresInMs),
    rememberedEpochFound: !!historyEntry,
    rememberedKeepAliveMs: Number.isFinite(historyKeepAliveMs) ? historyKeepAliveMs : undefined,
    rememberedKeepAliveClass: msClass(historyKeepAliveMs),
    rememberedEpochCount: kindHistoryCount,
    epochGraceMs: PIR_EPOCH_GRACE_MS,
    epochGraceClass: msClass(PIR_EPOCH_GRACE_MS)
  };
}

function byteSizeClass(bytes) {
  const n = Math.max(0, Number(bytes) || 0);
  if (n <= 1024 * 1024) return 'lte-1m';
  if (n <= 4 * 1024 * 1024) return 'lte-4m';
  if (n <= 8 * 1024 * 1024) return 'lte-8m';
  if (n <= 16 * 1024 * 1024) return 'lte-16m';
  if (n <= 64 * 1024 * 1024) return 'lte-64m';
  return 'gt-64m';
}

function countClass(count) {
  const n = Math.max(0, Number(count) || 0);
  if (n === 0) return 'none';
  if (n === 1) return 'single';
  if (n <= 32) return 'lte-32';
  if (n <= 1024) return 'lte-1k';
  if (n <= 16384) return 'lte-16k';
  if (n <= 65536) return 'lte-64k';
  return 'gt-64k';
}

function estimateStringBytes(value) {
  return typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : 0;
}

function estimateStringCollectionBytes(value) {
  if (!value) return 0;
  if (typeof value === 'string') return estimateStringBytes(value);
  if (Array.isArray(value)) {
    return value.reduce((total, item) => total + estimateStringCollectionBytes(item), 0);
  }
  if (value instanceof Map) {
    let total = 0;
    for (const item of value.values()) total += estimateStringCollectionBytes(item);
    return total;
  }
  if (typeof value === 'object') {
    let total = 0;
    for (const item of Object.values(value)) total += estimateStringCollectionBytes(item);
    return total;
  }
  return estimateStringBytes(value);
}

function mb(bytes) {
  return Math.round(((Number(bytes) || 0) / 1024 / 1024) * 10) / 10;
}

function databaseCacheStats(database) {
  const manifest = database?.manifest || {};
  const rawBytes = Number(manifest.recordCount || 0) * Number(manifest.recordSize || 0);
  const blobBytes = estimateStringCollectionBytes(database?.blobsByBucket) +
    estimateStringCollectionBytes(database?.blobsBySlot);
  return {
    kind: manifest.kind,
    epochId: manifest.epochId,
    expiresAt: manifest.expiresAt,
    compacted: database?.compacted === true,
    recordCount: manifest.recordCount,
    recordSize: manifest.recordSize,
    rawDatabaseBytes: rawBytes,
    rawDatabaseMb: mb(rawBytes),
    retainedBlobBytes: blobBytes,
    retainedBlobMb: mb(blobBytes),
    hasRecords: Array.isArray(database?.records),
    recordsLength: Array.isArray(database?.records) ? database.records.length : 0,
    hasBlobsByBucket: !!database?.blobsByBucket,
    hasBlobsBySlot: !!database?.blobsBySlot,
    uploadedToWorker: database?.uploadedToWorker === true
  };
}

export function getPirCacheStats() {
  cleanupEpochHistory(Date.now(), true);
  return {
    activeCount: epochCache.size,
    historyCount: epochHistory.size,
    active: Array.from(epochCache.values()).map(databaseCacheStats),
    history: Array.from(epochHistory.values()).map((entry) => ({
      keepUntil: entry?.keepUntil,
      database: databaseCacheStats(entry?.database)
    }))
  };
}

export function clearPirDatabaseCaches() {
  const activeCleared = epochCache.size;
  const historyCleared = epochHistory.size;
  epochCache.clear();
  epochHistory.clear();
  return { activeCleared, historyCleared };
}

async function loadSourceRecords(kind) {
  // Discovery is the only computational-PIR kind. The global message spool is served as a
  // uniform per-epoch snapshot (server/routing/spool-snapshot-service.js), not through PIR.
  const config = getPirLayoutConfig(kind);
  const discoveryRows = await DiscoveryDB.snapshotActive(config.maxSourceRecords);
  return buildOpaqueDiscoverySourceRecords(discoveryRows, config, {
    maxRecords: config.maxSourceRecords
  });
}

async function ensureUploaded(database) {
  const manifest = database?.manifest;
  if (!manifest) return { uploaded: false, error: 'invalid_pir_database' };
  if (database.uploadedToWorker) return { uploaded: true };
  if (database.workerUploadPromise) {
    return database.workerUploadPromise;
  }

  if (
    database.workerUpload &&
    database.workerUpload.uploaded !== true &&
    Number.isFinite(database.workerUpload.checkedAt) &&
    (Date.now() - database.workerUpload.checkedAt) < (
      database.workerUpload.retryable === true
        ? PIR_WORKER_UPLOAD_TRANSIENT_RETRY_MS
        : PIR_WORKER_UPLOAD_RETRY_MS
    )
  ) {
    return database.workerUpload;
  }

  const config = getPirWorkerConfig();
  if (!config.configured) {
    return { uploaded: false, error: 'pir_worker_unavailable', checkedAt: Date.now() };
  }

  database.workerUploadPromise = (async () => {
    const upload = await uploadPirDatabase(database);
    upload.checkedAt = Date.now();
    if (upload.uploaded) {
      database.uploadedToWorker = true;
      if (upload.publicParams) {
        database.workerPublicParams = upload.publicParams;
      }
      cryptoLogger.info('[PIR] Worker database upload ok', {
        kind: manifest.kind,
        epochId: manifest.epochId,
        recordCountClass: countClass(manifest.recordCount),
        rawDatabaseSizeClass: byteSizeClass(Number(manifest.recordCount || 0) * Number(manifest.recordSize || 0)),
        hasPublicParams: !!upload.publicParams
      });
    }
    return upload;
  })();

  try {
    return await database.workerUploadPromise;
  } finally {
    delete database.workerUploadPromise;
  }
}

// Force a reupload of in memory epoch DB to the worker
export async function forcePirWorkerReupload(database) {
  if (!database?.manifest) return { uploaded: false, error: 'invalid_pir_database' };
  if (!Array.isArray(database.records) || database.records.length !== database.manifest.recordCount) {
    return { uploaded: false, error: 'pir_epoch_compacted' };
  }
  database.uploadedToWorker = false;
  database.workerUpload = undefined;
  database.workerUploadPromise = undefined;
  const upload = await ensureUploaded(database);
  database.workerUpload = upload;
  if (upload?.uploaded) {
    try { await ensurePublicParams(database); } catch { }
  }
  return upload;
}

async function ensurePublicParams(database) {
  if (database?.workerPublicParams?.publicParams) {
    return database.workerPublicParams;
  }
  const manifest = database?.manifest;
  if (!manifest) return null;
  const result = await fetchPirWorkerPublicParams({ kind: manifest.kind, epochId: manifest.epochId });
  if (result.success && result.publicParams) {
    database.workerPublicParams = result.publicParams;
    return result.publicParams;
  }
  return null;
}

export async function getPirDatabase(kind, options = {}) {
  if (!isPirDatabaseKind(kind)) {
    return { success: false, error: 'unsupported_pir_database_kind' };
  }

  const now = Date.now();
  if (options.epochId) {
    const remembered = getRememberedPirDatabase(kind, options.epochId, now);
    if (remembered) {
      if (options.ensureWorker) {
        remembered.workerUpload = await ensureUploaded(remembered);
        if (remembered.workerUpload?.uploaded) {
          await ensurePublicParams(remembered);
        }
      }
      return { success: true, database: remembered };
    }
    return {
      success: false,
      error: 'pir_epoch_expired',
      diagnostic: epochCacheDiagnostic(kind, options.epochId)
    };
  }

  const cached = epochCache.get(cacheKey(kind));
  if (cached && cached.manifest?.expiresAt > now) {
    rememberPirDatabase(kind, cached, now);
    if (options.ensureWorker) {
      cached.workerUpload = await ensureUploaded(cached);
      if (cached.workerUpload?.uploaded) {
        await ensurePublicParams(cached);
      }
    }
    return { success: true, database: cached };
  }

  if (cached) {
    rememberPirDatabase(kind, cached, now);
  }

  try {
    const workerConfig = getPirWorkerConfig();
    const sourceRecords = await loadSourceRecords(kind);
    const database = buildPirPageDatabase({
      kind,
      sourceRecords,
      schemeId: workerConfig.schemeId,
      parameterId: workerConfig.parameterId
    });
    stripRuntimeDebugFields(database);
    database.uploadedToWorker = false;
    cachePirDatabase(kind, database);
    cryptoLogger.info('[PIR] Fixed-size database built', {
      kind,
      epochId: database.manifest?.epochId,
      sourceCountClass: countClass(sourceRecords.length),
      recordCountClass: countClass(database.manifest?.recordCount),
      recordSizeClass: byteSizeClass(database.manifest?.recordSize),
      rawDatabaseSizeClass: byteSizeClass(Number(database.manifest?.recordCount || 0) * Number(database.manifest?.recordSize || 0))
    });

    if (options.ensureWorker) {
      database.workerUpload = await ensureUploaded(database);
      if (database.workerUpload?.uploaded) {
        await ensurePublicParams(database);
      }
    }

    return { success: true, database };
  } catch (error) {
    cryptoLogger.error('[PIR] Failed to build fixed-size database', {
      kind,
      error: error?.message
    });
    return { success: false, error: error?.message || 'pir_database_build_failed' };
  }
}

export function invalidatePirDatabase(kind) {
  if (!kind) return;
  if (kind === '*') {
    epochCache.clear();
    epochHistory.clear();
    return;
  }
  const cached = epochCache.get(cacheKey(kind));
  if (cached) {
    rememberPirDatabase(kind, cached);
  }
  epochCache.delete(cacheKey(kind));
}

export function publicManifest(database, options = {}) {
  const workerConfig = getPirWorkerConfig();
  const publicParams = database?.workerPublicParams;
  const workerReady = workerConfig.configured
    && database.uploadedToWorker === true
    && typeof publicParams?.publicParams === 'string';

  const includeRecordDigests = options.includeRecordDigests === true
    || envBool('PIR_MANIFEST_INCLUDE_RECORD_DIGESTS', false);
  const includePayloadDigests = options.includePayloadDigests === true
    || envBool('PIR_MANIFEST_INCLUDE_PAYLOAD_DIGESTS', false);
  const {
    recordDigests,
    payloadDigests,
    ...safeBaseManifest
  } = database.manifest || {};

  if (includeRecordDigests && Array.isArray(recordDigests)) {
    safeBaseManifest.recordDigests = recordDigests;
  } else if (Array.isArray(recordDigests)) {
    safeBaseManifest.recordDigestTransport = 'omitted';
  }

  if (includePayloadDigests && Array.isArray(payloadDigests)) {
    safeBaseManifest.payloadDigests = payloadDigests;
  } else if (Array.isArray(payloadDigests)) {
    safeBaseManifest.payloadDigestTransport = 'omitted';
  }

  return {
    ...safeBaseManifest,
    workerConfigured: workerConfig.configured,
    workerRequired: workerConfig.required,
    workerReady,
    workerScheme: workerConfig.schemeId,
    workerParameterId: workerConfig.parameterId,
    workerSourceCommit: workerConfig.expectedSourceCommit,
    workerPublicParams: workerReady ? publicParams.publicParams : undefined,
    workerDbRows: workerReady ? publicParams.dbRows : undefined,
    workerDbCols: workerReady ? publicParams.dbCols : undefined,
    queryPrivacy: workerReady ? 'computational-pir-worker' : 'computational-pir-required-unavailable'
  };
}
