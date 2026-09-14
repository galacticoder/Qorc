/** Fixed-shape k-anonymous discovery bucket client. */

import { anonymousHttpFetch } from '../transport/pq-anonymous-http';
import { runAnonymousRequestBatch } from '../transport/anonymous-request-lane';
import { createBucketProgress, type DiscoveryProgressObserver } from './progress';
import { ANONYMOUS_DISCOVERY_RESPONSE_BYTES } from '../../../shared/anonymous-transfer-policy.js';
import { blake3 } from '@noble/hashes/blake3.js';
import {
  assertCurrentServerContext,
  captureCurrentServerContext,
  type CurrentServerContext,
} from '../security/local-account-scope';
import { createAnonymousHttpPow } from '../cryptography/anonymous-http-pow';
import { hasExactPlainRecordKeys } from '../sanitizers';
import { PostQuantumRandom } from '../cryptography/random';
import { Base64 } from '../cryptography/base64';
import {
  DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_BUCKET_TARGET_SIZE,
  DISCOVERY_DATABASE_KIND,
  DISCOVERY_FIXED_BUCKET_COUNT,
  DISCOVERY_PUBLICATION_BUCKET_COUNT,
  DISCOVERY_BLOB_BASE64_CHARS,
  DISCOVERY_EPOCH_DURATION_MS,
} from '../../../shared/discovery-constants.js';
import { canonicalBase64Shape } from '../../../shared/canonical-base64.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';
import { DISCOVERY_BUCKET_AUDIENCE, DISCOVERY_MANIFEST_AUDIENCE } from '../config/audiences';

export {
  DISCOVERY_BUCKET_QUERY_COUNT,
  DISCOVERY_DATABASE_KIND,
  DISCOVERY_FIXED_BUCKET_COUNT,
  DISCOVERY_PUBLICATION_BUCKET_COUNT,
};

export interface DiscoveryBucketManifest {
  version: typeof PROTOCOL_KEYS.DISCOVERY_BUCKET_MANIFEST;
  kind: typeof DISCOVERY_DATABASE_KIND;
  epochId: string;
  createdAt: number;
  expiresAt: number;
  bucketCount: number;
  bucketTargetSize: number;
  publicationBucketCount: number;
}

type ManifestResponse = {
  success: boolean;
  manifest?: DiscoveryBucketManifest;
  error?: string;
};

const MAX_DECOY_BUCKET_DERIVATIONS = 1_024;
const DISCOVERY_BUCKET_POW_DIFFICULTY = 18;
const manifestCache = new Map<string, { manifest: DiscoveryBucketManifest; expiresAt: number }>();
const MANIFEST_CACHE_MAX_ENTRIES = 16;
const manifestContexts = new WeakMap<DiscoveryBucketManifest, CurrentServerContext>();

export interface DiscoveryBucketFetchResult {
  blobs: string[];
  context: CurrentServerContext;
}

function encodeHashParts(parts: Array<string | number>): Uint8Array {
  return new TextEncoder().encode(parts.map(String).join('\0'));
}

async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

function sanitizeManifest(value: unknown): DiscoveryBucketManifest | null {
  if (!hasExactPlainRecordKeys(value, [
    'version',
    'kind',
    'epochId',
    'createdAt',
    'expiresAt',
    'bucketCount',
    'bucketTargetSize',
    'publicationBucketCount',
  ])) return null;

  const localEpochStartedAt = Math.floor(Date.now() / DISCOVERY_EPOCH_DURATION_MS) *
    DISCOVERY_EPOCH_DURATION_MS;
  if (
    value.version !== PROTOCOL_KEYS.DISCOVERY_BUCKET_MANIFEST ||
    value.kind !== DISCOVERY_DATABASE_KIND ||
    typeof value.epochId !== 'string' ||
    !/^\d{10,16}$/.test(value.epochId) ||
    !Number.isSafeInteger(value.createdAt) ||
    (value.createdAt as number) % DISCOVERY_EPOCH_DURATION_MS !== 0 ||
    String(value.createdAt) !== value.epochId ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt !== (value.createdAt as number) + DISCOVERY_EPOCH_DURATION_MS ||
    value.createdAt !== localEpochStartedAt ||
    value.bucketCount !== DISCOVERY_FIXED_BUCKET_COUNT ||
    value.bucketTargetSize !== DISCOVERY_BUCKET_TARGET_SIZE ||
    value.publicationBucketCount !== DISCOVERY_PUBLICATION_BUCKET_COUNT
  ) return null;

  return value as unknown as DiscoveryBucketManifest;
}

function clearManifestCache(serverScope?: string): void {
  if (!serverScope) {
    manifestCache.clear();
    return;
  }
  manifestCache.delete(`${serverScope}:${DISCOVERY_DATABASE_KIND}`);
}

export async function requestDiscoveryManifest(
  options: { forceFresh?: boolean; signal?: AbortSignal } = {}
): Promise<ManifestResponse> {
  options.signal?.throwIfAborted();
  const context = await captureCurrentServerContext();
  const cacheKey = `${context.serverScope}:${DISCOVERY_DATABASE_KIND}`;
  if (!options.forceFresh) {
    const cached = manifestCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now() + 1000) {
      manifestContexts.set(cached.manifest, context);
      return { success: true, manifest: cached.manifest };
    }
  }

  try {
    const response: unknown = await anonymousHttpFetch(
      DISCOVERY_MANIFEST_AUDIENCE,
      { kind: DISCOVERY_DATABASE_KIND },
      context.serverUrl,
      { signal: options.signal },
    );
    await assertCurrentServerContext(context);
    if (!hasExactPlainRecordKeys(response, ['ok', 'manifest']) || response.ok !== true) {
      return { success: false, error: 'discovery_manifest_unavailable' };
    }
    const manifest = sanitizeManifest(response.manifest);
    if (!manifest) return { success: false, error: 'discovery_manifest_invalid' };
    manifestContexts.set(manifest, context);
    manifestCache.delete(cacheKey);
    while (manifestCache.size >= MANIFEST_CACHE_MAX_ENTRIES) {
      const oldest = manifestCache.keys().next().value;
      if (typeof oldest !== 'string') break;
      manifestCache.delete(oldest);
    }
    manifestCache.set(cacheKey, {
      manifest,
      expiresAt: manifest.expiresAt,
    });
    return { success: true, manifest };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'discovery_manifest_unavailable',
    };
  }
}

export async function deriveDiscoveryBucketKey(token: string): Promise<string> {
  const normalized = typeof token === 'string' ? token.trim().toLowerCase() : '';
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw new Error('invalid_discovery_token');
  const input = encodeHashParts([PROTOCOL_KEYS.DISCOVERY_BUCKET_KEY, normalized]);
  try {
    const digest = await sha256Bytes(input);
    try {
      return Base64.arrayBufferToBase64Url(digest);
    } finally {
      digest.fill(0);
    }
  } finally {
    input.fill(0);
  }
}

export async function deriveDiscoveryBucketId(bucketKey: string, bucketCount: number): Promise<number> {
  if (typeof bucketKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(bucketKey)) {
    throw new Error('invalid_discovery_bucket_key');
  }
  if (bucketCount !== DISCOVERY_FIXED_BUCKET_COUNT) {
    throw new Error('invalid_discovery_bucket_count');
  }
  const input = encodeHashParts([PROTOCOL_KEYS.DISCOVERY_BUCKET_ID, bucketKey]);
  try {
    const digest = await sha256Bytes(input);
    try {
      let value = 0;
      for (let index = 0; index < 6; index += 1) value = value * 256 + digest[index];
      return value % bucketCount;
    } finally {
      digest.fill(0);
    }
  } finally {
    input.fill(0);
  }
}

function deriveQueryDecoyBucketId(
  queryScope: string,
  token: string,
  epochId: string,
  counter: number,
  bucketCount: number,
): number {
  const scopeKey = new Uint8Array(32);
  for (let index = 0; index < scopeKey.length; index += 1) {
    scopeKey[index] = Number.parseInt(queryScope.slice(index * 2, index * 2 + 2), 16);
  }
  const input = encodeHashParts([
    PROTOCOL_KEYS.DISCOVERY_QUERY_DECOY,
    token,
    epochId,
    counter,
  ]);
  try {
    const digest = blake3(input, { key: scopeKey, dkLen: 32 });
    try {
      let value = 0;
      for (let index = 0; index < 6; index += 1) value = value * 256 + digest[index];
      return value % bucketCount;
    } finally {
      digest.fill(0);
    }
  } finally {
    scopeKey.fill(0);
    input.fill(0);
  }
}

function isCanonicalDiscoveryBlob(value: unknown): value is string {
  return canonicalBase64Shape(value, {
    exactBytes: (DISCOVERY_BLOB_BASE64_CHARS / 4) * 3
  });
}

async function fetchDiscoveryBlobsOnce(
  tokens: string[],
  forceFresh: boolean,
  queryScope: string,
  signal?: AbortSignal,
  onProgress?: DiscoveryProgressObserver,
): Promise<DiscoveryBucketFetchResult> {
  const manifestResponse = await requestDiscoveryManifest({ forceFresh, signal });
  const manifest = manifestResponse.success ? manifestResponse.manifest : null;
  if (!manifest) throw new Error(manifestResponse.error || 'discovery_manifest_unavailable');
  const context = manifestContexts.get(manifest);
  if (!context) throw new Error('discovery_manifest_server_context_missing');

  const bucketIds = new Set<number>();
  const realBucketDbg: Array<{ tok16: string; bucket: number }> = [];
  for (const token of tokens) {
    const bucket = await deriveDiscoveryBucketId(
      await deriveDiscoveryBucketKey(token),
      manifest.bucketCount
    );
    bucketIds.add(bucket);
    realBucketDbg.push({ tok16: token.slice(0, 16), bucket });
  }
  
  for (
    let counter = 0;
    bucketIds.size < DISCOVERY_BUCKET_QUERY_COUNT && counter < MAX_DECOY_BUCKET_DERIVATIONS;
    counter += 1
  ) {
    bucketIds.add(deriveQueryDecoyBucketId(
      queryScope,
      tokens[0],
      manifest.epochId,
      counter,
      manifest.bucketCount,
    ));
  }
  if (bucketIds.size !== DISCOVERY_BUCKET_QUERY_COUNT) {
    throw new Error('discovery_bucket_decoy_derivation_exhausted');
  }
  const ids = PostQuantumRandom.shuffleInPlace(Array.from(bucketIds));
  
  console.log('[DISCOVERY] bucket download started', {
    buckets: ids.length,
    responseBytes: ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
    totalBytes: ids.length * ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
  });
  const reportProgress = createBucketProgress(ids.length, ANONYMOUS_DISCOVERY_RESPONSE_BYTES, onProgress);
  const perBucket = await runAnonymousRequestBatch(ids.map((id, index) => async (signal: AbortSignal) => {
    const work = await createAnonymousHttpPow(
      PROTOCOL_KEYS.DISCOVERY_BUCKET_HTTP_POW,
      manifest.epochId,
      [String(id)],
      DISCOVERY_BUCKET_POW_DIFFICULTY,
      signal,
    );
    await assertCurrentServerContext(context);
    const response: unknown = await anonymousHttpFetch(
      DISCOVERY_BUCKET_AUDIENCE,
      { epochId: manifest.epochId, bucketIds: [id], ...work },
      context.serverUrl,
      { signal, onProgress: (receivedBytes) => reportProgress(index, receivedBytes) },
    );
    await assertCurrentServerContext(context);
    if (!hasExactPlainRecordKeys(response, ['ok', 'epochId', 'bucketCount', 'buckets'])) {
      const error = hasExactPlainRecordKeys(response, ['ok', 'error']) && typeof response.error === 'string'
        ? response.error
        : 'discovery_bucket_response_invalid';
      throw new Error(error);
    }
    if (
      response.ok !== true ||
      response.epochId !== manifest.epochId ||
      response.bucketCount !== manifest.bucketCount ||
      !response.buckets ||
      typeof response.buckets !== 'object' ||
      Array.isArray(response.buckets) ||
      Object.getPrototypeOf(response.buckets) !== Object.prototype
    ) throw new Error('discovery_bucket_response_invalid');

    const bucketMap = response.buckets as Record<string, unknown>;
    const keys = Object.keys(bucketMap);
    if (keys.length !== 1 || keys[0] !== String(id)) {
      throw new Error('discovery_bucket_response_invalid');
    }
    return { id, entries: bucketMap[String(id)] };
  }), signal);

  onProgress?.({
    phase: 'verifying',
    receivedBytes: ids.length * ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
    totalBytes: ids.length * ANONYMOUS_DISCOVERY_RESPONSE_BYTES,
  });

  const buckets: Record<string, unknown> = {};
  for (const { id, entries } of perBucket) buckets[String(id)] = entries;

  const blobs: string[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const entries = buckets[String(id)];
    if (!Array.isArray(entries) || entries.length !== manifest.bucketTargetSize) {
      throw new Error('discovery_bucket_response_invalid');
    }
    for (const blob of entries) {
      if (!isCanonicalDiscoveryBlob(blob)) throw new Error('discovery_bucket_response_invalid');
      if (!seen.has(blob)) {
        seen.add(blob);
        blobs.push(blob);
      }
    }
  }
  return { blobs, context };
}

export async function fetchDiscoveryBlobsForTokens(
  tokens: string[],
  queryScope: string,
  signal?: AbortSignal,
  onProgress?: DiscoveryProgressObserver,
): Promise<DiscoveryBucketFetchResult> {
  const normalized = Array.from(new Set(tokens.map((token) => (
    typeof token === 'string' ? token.trim().toLowerCase() : ''
  ))));
  if (
    normalized.length !== 1 ||
    normalized.some((token) => !/^[a-f0-9]{64}$/.test(token)) ||
    typeof queryScope !== 'string' ||
    !/^[a-f0-9]{64}$/.test(queryScope)
  ) {
    throw new Error('invalid_discovery_token_batch');
  }

  try {
    return await fetchDiscoveryBlobsOnce(normalized, false, queryScope, signal, onProgress);
  } catch (error) {
    if (!String(error instanceof Error ? error.message : error).includes('discovery_epoch_expired')) throw error;
    clearManifestCache();
    return fetchDiscoveryBlobsOnce(normalized, true, queryScope, signal, onProgress);
  }
}
