import crypto from 'crypto';
import { deriveAuthRootKey } from '../crypto/auth-root.js';
import {
  AES_256_CTR,
  AES_256_CTR_IV_BYTES,
  SHA_256_ALGORITHM
} from '../utils/crypto-consts.js';
import { envInt } from '../utils/env.js';
import { HEX_64_RE } from '../utils/patterns.js';
import { getDiscoveryEpochInfo } from './epoch.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import {
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_BUCKET_TARGET_SIZE,
  DISCOVERY_DATABASE_KIND,
  DISCOVERY_FIXED_BUCKET_COUNT,
  DISCOVERY_PUBLICATION_BUCKET_COUNT
} from '../../shared/discovery-constants.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';

export const DISCOVERY_MANIFEST_VERSION = PROTOCOL_KEYS.DISCOVERY_BUCKET_MANIFEST;
export {
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_BUCKET_TARGET_SIZE,
  DISCOVERY_DATABASE_KIND,
  DISCOVERY_FIXED_BUCKET_COUNT,
  DISCOVERY_PUBLICATION_BUCKET_COUNT
};

export const DISCOVERY_INDEX_MAX_STALENESS_MS = envInt(
  'DISCOVERY_INDEX_MAX_STALENESS_MS',
  30_000,
  1000,
  6 * 60 * 60 * 1000
);

export const DISCOVERY_MAX_SOURCE_PUBLICATIONS = envInt(
  'DISCOVERY_MAX_SOURCE_PUBLICATIONS',
  4096,
  1,
  100_000
);

export const DISCOVERY_MAX_SOURCE_BYTES = envInt(
  'DISCOVERY_MAX_SOURCE_BYTES',
  256 * 1024 * 1024,
  1024 * 1024,
  2 * 1024 * 1024 * 1024
);

export const DISCOVERY_STORED_PUBLICATION_CAP = Math.min(
  DISCOVERY_MAX_SOURCE_PUBLICATIONS,
  Math.floor(DISCOVERY_MAX_SOURCE_BYTES / DISCOVERY_BLOB_BASE64_CHARS)
);

const derivedDiscoveryDecoySecret = deriveAuthRootKey(PROTOCOL_KEYS.DISCOVERY_DECOY_PADDING_ROOT);
const DISCOVERY_DECOY_SECRET = Buffer.from(derivedDiscoveryDecoySecret);
derivedDiscoveryDecoySecret.fill(0);
let discoveryDecoySecretDestroyed = false;

function assertDiscoveryDecoySecretAvailable() {
  if (discoveryDecoySecretDestroyed) {
    throw new Error('Discovery bucket secrets have been destroyed');
  }
}

export function destroyDiscoveryBucketSecrets() {
  if (discoveryDecoySecretDestroyed) return;
  discoveryDecoySecretDestroyed = true;
  DISCOVERY_DECOY_SECRET.fill(0);
}

export function isCanonicalDiscoveryBlob(value) {
  return canonicalBase64Shape(value, {
    exactBytes: (DISCOVERY_BLOB_BASE64_CHARS / 4) * 3
  });
}

export function isCanonicalDiscoveryBucketIds(value) {
  return Array.isArray(value) &&
    value.length === DISCOVERY_PUBLICATION_BUCKET_COUNT &&
    new Set(value).size === value.length &&
    value.every((bucketId) => (
      Number.isInteger(bucketId) &&
      bucketId >= 0 &&
      bucketId < DISCOVERY_FIXED_BUCKET_COUNT
    ));
}

function deterministicBytes(domain, epochId, bucketId, value, bytes) {
  assertDiscoveryDecoySecretAvailable();
  const streamKey = crypto.createHmac(SHA_256_ALGORITHM, DISCOVERY_DECOY_SECRET)
    .update(domain)
    .update('\0')
    .update(epochId)
    .update('\0')
    .update(String(bucketId))
    .update('\0')
    .update(String(value))
    .digest();
  const ivMaterial = crypto.createHmac(SHA_256_ALGORITHM, DISCOVERY_DECOY_SECRET)
    .update(`${domain}-iv`)
    .update('\0')
    .update(epochId)
    .update('\0')
    .update(String(bucketId))
    .update('\0')
    .update(String(value))
    .digest();
  try {
    const cipher = crypto.createCipheriv(
      AES_256_CTR,
      streamKey,
      ivMaterial.subarray(0, AES_256_CTR_IV_BYTES)
    );
    return Buffer.concat([cipher.update(Buffer.alloc(bytes)), cipher.final()]);
  } finally {
    streamKey.fill(0);
    ivMaterial.fill(0);
  }
}

function deterministicDecoy(epochId, bucketId, index) {
  const bytes = (DISCOVERY_BLOB_BASE64_CHARS / 4) * 3;
  return deterministicBytes(PROTOCOL_KEYS.DISCOVERY_BUCKET_DECOY, epochId, bucketId, index, bytes).toString('base64');
}

function deterministicRank(epochId, bucketId, publishId) {
  assertDiscoveryDecoySecretAvailable();
  return crypto.createHmac(SHA_256_ALGORITHM, DISCOVERY_DECOY_SECRET)
    .update(PROTOCOL_KEYS.DISCOVERY_BUCKET_RANK)
    .update('\0')
    .update(epochId)
    .update('\0')
    .update(String(bucketId))
    .update('\0')
    .update(publishId)
    .digest('hex');
}

function deterministicOrder(length, epochId, bucketId) {
  return Array.from({ length }, (_, index) => ({
    index,
    rank: deterministicRank(epochId, bucketId, `position:${index}`)
  }))
    .sort((a, b) => a.rank.localeCompare(b.rank))
    .map((entry) => entry.index);
}

export function padDiscoveryBucket(realBlobs, { epochId, bucketId, targetSize = DISCOVERY_BUCKET_TARGET_SIZE }) {
  const target = Math.min(
    DISCOVERY_BUCKET_TARGET_SIZE,
    Math.max(1, Math.trunc(Number(targetSize) || DISCOVERY_BUCKET_TARGET_SIZE))
  );
  const entries = (Array.isArray(realBlobs) ? realBlobs : [])
    .filter(isCanonicalDiscoveryBlob)
    .slice(0, target);
  while (entries.length < target) {
    entries.push(deterministicDecoy(epochId, bucketId, entries.length));
  }
  const order = deterministicOrder(entries.length, epochId, bucketId);
  return order.map((index) => entries[index]);
}

function selectBucketEntries(entries, epochId, bucketId) {
  return entries
    .map((entry) => ({
      publishId: entry.publishId,
      rank: deterministicRank(epochId, bucketId, entry.publishId)
    }))
    .sort((a, b) => a.rank.localeCompare(b.rank))
    .slice(0, DISCOVERY_BUCKET_TARGET_SIZE)
    .map((entry) => entry.publishId);
}

export function buildDiscoveryBucketIndex(publications, now = Date.now()) {
  const epoch = getDiscoveryEpochInfo(now);
  const epochId = String(epoch.startedAt);
  const rows = Array.isArray(publications) ? publications : [];
  const grouped = Array.from({ length: DISCOVERY_FIXED_BUCKET_COUNT }, () => []);
  let refreshAt = Math.min(epoch.rotatesAt, now + DISCOVERY_INDEX_MAX_STALENESS_MS);

  for (const publication of rows) {
    if (
      typeof publication?.publishId !== 'string' ||
      !HEX_64_RE.test(publication.publishId) ||
      !isCanonicalDiscoveryBucketIds(publication.bucketIds) ||
      (publication.expiresAt !== undefined && (
        !Number.isSafeInteger(publication.expiresAt) ||
        publication.expiresAt <= now
      ))
    ) continue;
    if (Number.isSafeInteger(publication.expiresAt)) {
      refreshAt = Math.min(refreshAt, publication.expiresAt);
    }
    for (const bucketId of publication.bucketIds) {
      grouped[bucketId].push({ publishId: publication.publishId });
    }
  }

  const publishIdsByBucket = grouped.map((entries, bucketId) => (
    selectBucketEntries(entries, epochId, bucketId)
  ));

  return {
    manifest: {
      version: DISCOVERY_MANIFEST_VERSION,
      kind: DISCOVERY_DATABASE_KIND,
      epochId,
      createdAt: epoch.startedAt,
      expiresAt: epoch.rotatesAt,
      bucketCount: DISCOVERY_FIXED_BUCKET_COUNT,
      bucketTargetSize: DISCOVERY_BUCKET_TARGET_SIZE,
      publicationBucketCount: DISCOVERY_PUBLICATION_BUCKET_COUNT
    },
    publishIdsByBucket,
    refreshAt
  };
}
