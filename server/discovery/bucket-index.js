import { DiscoveryDB } from '../database/database.js';

import {
  buildDiscoveryBucketIndex,
  DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_DATABASE_KIND,
  DISCOVERY_MAX_SOURCE_BYTES,
  DISCOVERY_MAX_SOURCE_PUBLICATIONS,
  padDiscoveryBucket
} from './bucket-layout.js';
import { DISCOVERY_EPOCH_EXPIRED } from '../config/error-codes.js';
import { currentDiscoveryEpochId } from './epoch.js';

const paddedCacheSizeParsed = Number.parseInt(process.env.DISCOVERY_PADDED_BUCKET_CACHE_SIZE || '4', 10);
const PADDED_BUCKET_CACHE_SIZE = Number.isFinite(paddedCacheSizeParsed)
  ? Math.min(32, Math.max(0, paddedCacheSizeParsed))
  : 4;
const paddedBucketCaches = new WeakMap();
const paddedBucketBuilds = new WeakMap();
const paddedBucketWork = new Set();
const indexBuildWork = new Set();
let activeIndex = null;
let buildInFlight = null;
let indexRevision = 0;
let indexDestroyed = false;

async function buildCurrentIndex(now = Date.now()) {
  const rows = await DiscoveryDB.snapshotActiveMetadata(
    DISCOVERY_MAX_SOURCE_PUBLICATIONS,
    DISCOVERY_MAX_SOURCE_BYTES
  );

  return buildDiscoveryBucketIndex(rows, now);
}

export async function getDiscoveryBucketIndex(options = {}) {
  if (indexDestroyed) return { success: false, error: 'discovery_index_unavailable' };
  let now = Date.now();
  if (activeIndex?.refreshAt <= now) activeIndex = null;
  const requestedEpochId = typeof options.epochId === 'string' ? options.epochId : null;
  const requestedCurrentEpochId = currentDiscoveryEpochId(now);

  if (requestedEpochId && requestedEpochId !== requestedCurrentEpochId) {
    return { success: false, error: DISCOVERY_EPOCH_EXPIRED };
  }
  if (activeIndex?.manifest?.epochId === requestedCurrentEpochId) {
    return { success: true, index: activeIndex };
  }

  try {
    for (;;) {
      now = Date.now();
      const epochId = currentDiscoveryEpochId(now);
      if (activeIndex?.manifest?.epochId === epochId) {
        if (requestedEpochId && requestedEpochId !== epochId) {
          return { success: false, error: DISCOVERY_EPOCH_EXPIRED };
        }
        return { success: true, index: activeIndex };
      }

      const revision = indexRevision;
      if (!buildInFlight || buildInFlight.revision !== revision) {
        const pending = buildCurrentIndex(now);
        const holder = { revision, promise: pending };
        buildInFlight = holder;
        indexBuildWork.add(pending);
        void pending.finally(() => {
          indexBuildWork.delete(pending);
          if (buildInFlight === holder) buildInFlight = null;
        }).catch(() => {});
      }

      const holder = buildInFlight;
      const built = await holder.promise;
      if (indexDestroyed) return { success: false, error: 'discovery_index_unavailable' };
      if (revision !== indexRevision) continue;
      const completedAt = Date.now();
      if (built.manifest.epochId !== currentDiscoveryEpochId(completedAt) || built.refreshAt <= completedAt) {
        if (buildInFlight === holder) buildInFlight = null;
        continue;
      }
      activeIndex = built;
      if (requestedEpochId && built.manifest.epochId !== requestedEpochId) {
        return { success: false, error: DISCOVERY_EPOCH_EXPIRED };
      }
      return { success: true, index: built };
    }
  } catch (error) {
    console.error('[DISCOVERY] Bucket index build failed', { error: error?.message || String(error) });
    return { success: false, error: 'discovery_index_unavailable' };
  }
}

export function invalidateDiscoveryBucketIndex() {
  if (indexDestroyed) return;
  indexRevision += 1;
  activeIndex = null;
}

function clearDiscoveryBucketIndex() {
  const cleared = Number(activeIndex !== null);
  activeIndex = null;
  indexRevision += 1;
  return { cleared };
}

export async function destroyDiscoveryBucketIndex() {
  indexDestroyed = true;
  const pending = Array.from(new Set([
    ...indexBuildWork,
    ...paddedBucketWork
  ].filter(Boolean)));
  clearDiscoveryBucketIndex();
  buildInFlight = null;
  if (pending.length > 0) await Promise.allSettled(pending);
}

export function publicDiscoveryManifest(index) {
  const manifest = index?.manifest;
  if (!manifest || manifest.kind !== DISCOVERY_DATABASE_KIND) return null;
  return {
    version: manifest.version,
    kind: manifest.kind,
    epochId: manifest.epochId,
    createdAt: manifest.createdAt,
    expiresAt: manifest.expiresAt,
    bucketCount: manifest.bucketCount,
    bucketTargetSize: manifest.bucketTargetSize,
    publicationBucketCount: manifest.publicationBucketCount
  };
}

function readCachedPaddedBucket(cache, bucketId) {
  const cached = cache.get(bucketId);
  if (!cached) return null;
  cache.delete(bucketId);
  cache.set(bucketId, cached);
  return cached;
}

function cachePaddedBucket(cache, bucketId, padded) {
  if (PADDED_BUCKET_CACHE_SIZE <= 0) return;
  cache.set(bucketId, padded);
  while (cache.size > PADDED_BUCKET_CACHE_SIZE) {
    cache.delete(cache.keys().next().value);
  }
}

export async function getPaddedDiscoveryBuckets(index, bucketIds) {
  if (
    indexDestroyed ||
    !index ||
    !Array.isArray(index.publishIdsByBucket) ||
    !Array.isArray(bucketIds) ||
    bucketIds.length < 1 ||
    bucketIds.length > DISCOVERY_BUCKET_QUERY_COUNT ||
    new Set(bucketIds).size !== bucketIds.length ||
    bucketIds.some((bucketId) => (
      !Number.isInteger(bucketId) ||
      bucketId < 0 ||
      bucketId >= index.publishIdsByBucket.length ||
      !Array.isArray(index.publishIdsByBucket[bucketId])
    ))
  ) return null;

  let cache = paddedBucketCaches.get(index);
  if (!cache) {
    cache = new Map();
    paddedBucketCaches.set(index, cache);
  }

  const result = new Map();
  const missing = [];
  for (const bucketId of bucketIds) {
    const cached = readCachedPaddedBucket(cache, bucketId);
    if (cached) result.set(bucketId, cached);
    else missing.push(bucketId);
  }
  if (missing.length === 0) return result;

  let builds = paddedBucketBuilds.get(index);
  if (!builds) {
    builds = new Map();
    paddedBucketBuilds.set(index, builds);
  }
  const buildKey = missing.slice().sort((a, b) => a - b).join(',');
  let pending = builds.get(buildKey);
  if (!pending) {
    pending = (async () => {
      const selectedIds = Array.from(new Set(
        missing.flatMap((bucketId) => index.publishIdsByBucket[bucketId])
      ));
      const blobs = selectedIds.length > 0
        ? await DiscoveryDB.getActiveBlobsByPublishIds(selectedIds)
        : new Map();
      const built = new Map();
      for (const bucketId of missing) {
        const promisedIds = index.publishIdsByBucket[bucketId];
        const realBlobs = promisedIds
          .map((publishId) => blobs.get(publishId))
          .filter(Boolean);
          
        if (realBlobs.length !== promisedIds.length) {
          console.warn('[DISCOVERY] indexed publication missing from active blobs', {
            bucketId,
            epochId: index.manifest.epochId,
            indexed: promisedIds.length,
            resolved: realBlobs.length
          });
        }
        const padded = padDiscoveryBucket(realBlobs, {
          epochId: index.manifest.epochId,
          bucketId,
          targetSize: index.manifest.bucketTargetSize
        });
        built.set(bucketId, padded);
        cachePaddedBucket(cache, bucketId, padded);
      }
      return built;
    })();
    builds.set(buildKey, pending);
    paddedBucketWork.add(pending);
    void pending.finally(() => {
      paddedBucketWork.delete(pending);
    }).catch(() => { });
  }

  let built;
  try {
    built = await pending;
  } finally {
    if (builds.get(buildKey) === pending) builds.delete(buildKey);
  }
  for (const bucketId of missing) {
    const padded = readCachedPaddedBucket(cache, bucketId) || built.get(bucketId);
    if (!padded) return null;
    result.set(bucketId, padded);
  }
  return result;
}
