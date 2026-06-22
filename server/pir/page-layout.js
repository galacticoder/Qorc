/**
 * Fixed size discovery PIR page layout
 *
 * This module lays out the discovery PIR database for the reviewed hintless worker.
 *
 * HintlessPIR cost scales with record SIZE, not record count (a 1 KB record is
 * ~240 MB/query, while a 1,000,000-record database answers in ~0.43 s). So a
 * discovery record is NOT the inlined ~16 KB bundle blob it is a tiny fixed
 * pointer:
 *
 *     [ slotFingerprint(8) || blobHandle(16) ]   = 24 bytes
 *
 * The client privately retrieves this 24-byte record through PIR, confirms the
 * fingerprint (derived from its OPRF token), then obliviously fetches the full
 * encrypted bundle by its tier-1 slot via YPIR (server/pir/ypir-tier2.js). the
 * server never learns which slot/handle was fetched. The bundle content is
 * unchanged. only its delivery is oblivious.
 */

import crypto from 'crypto';

const MANIFEST_VERSION = 'qor-pir-manifest-v1';
const OPAQUE_PIR_DATABASE_KIND = 'opaque';
const DISCOVERY_PIR_DATABASE_KIND = 'discovery';

const FINGERPRINT_BYTES = 2;
const HANDLE_BYTES = 6;
const HANDLE_RECORD_BYTES = FINGERPRINT_BYTES + HANDLE_BYTES; // 8

const DEFAULT_RECORD_FLOOR = 1024;
const DEFAULT_MAX_SOURCE_RECORDS = 65536;
const DEFAULT_SLOT_LOAD_FACTOR = 1;
const SLOT_DERIVATION = 'qor-pir-slot-v1';
const SLOT_FINGERPRINT_DERIVATION = 'qor-pir-slot-fingerprint-v1';
const BLOB_HANDLE_DERIVATION = 'qor-discovery-blob-handle-v1';
const MAX_RECORD_COUNT = 4_000_000;

const KIND_CODES = Object.freeze({
  [DISCOVERY_PIR_DATABASE_KIND]: 2
});

export const PIR_DATABASE_KINDS = Object.freeze([DISCOVERY_PIR_DATABASE_KIND]);
export { OPAQUE_PIR_DATABASE_KIND, DISCOVERY_PIR_DATABASE_KIND, HANDLE_RECORD_BYTES };

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function nextPowerOfTwo(value) {
  let n = 1;
  const target = Math.max(1, Math.trunc(value || 1));
  while (n < target && n < MAX_RECORD_COUNT) n *= 2;
  return n;
}

function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function hashBytes(parts, bytes) {
  const hash = crypto.createHash('sha256');
  for (const part of parts) {
    hash.update(Buffer.isBuffer(part) ? part : Buffer.from(String(part)));
    hash.update('\0');
  }
  return hash.digest().subarray(0, bytes);
}

function hashBase64Url(parts, bytes = 32) {
  return base64url(hashBytes(parts, bytes));
}

function hashBigIntMod(parts, modulus) {
  if (!Number.isSafeInteger(modulus) || modulus <= 0) {
    throw new Error('invalid_pir_slot_modulus');
  }
  const digest = hashBytes(parts, 16);
  let value = 0n;
  for (const byte of digest) {
    value = (value << 8n) | BigInt(byte);
  }
  return Number(value % BigInt(modulus));
}

export function isPirDatabaseKind(kind) {
  return PIR_DATABASE_KINDS.includes(kind);
}

function defaultEpochMsForKind() {
  return 6 * 60 * 60 * 1000;
}

export function getPirLayoutConfig(kind) {
  if (!isPirDatabaseKind(kind)) {
    throw new Error(`Unsupported PIR database kind: ${kind}`);
  }
  const envPrefix = `PIR_${kind.toUpperCase().replace(/-/g, '_')}`;
  return {
    recordSize: HANDLE_RECORD_BYTES,
    paddingFloor: envInt(`${envPrefix}_RECORD_FLOOR`, DEFAULT_RECORD_FLOOR, 1, MAX_RECORD_COUNT),
    epochMs: envInt(`${envPrefix}_EPOCH_MS`, defaultEpochMsForKind(kind), 5_000, 24 * 60 * 60 * 1000),
    maxSourceRecords: envInt(`${envPrefix}_MAX_SOURCE_RECORDS`, DEFAULT_MAX_SOURCE_RECORDS, 1, MAX_RECORD_COUNT),
    slotProbeCount: envInt(`${envPrefix}_SLOT_PROBE_COUNT`, 96, 1, 4096),
    slotLoadFactor: envInt(`${envPrefix}_SLOT_LOAD_FACTOR`, DEFAULT_SLOT_LOAD_FACTOR, 1, 32)
  };
}

// Deterministic slot for a token-derived slotKey within an epoch. Client and server compute this identically and server never learns slotKey
export function derivePirRecordSlot({ kind, slotKey, epochStart, recordCount, probe = 0 }) {
  if (!isPirDatabaseKind(kind)) {
    throw new Error(`Unsupported PIR database kind: ${kind}`);
  }
  if (typeof slotKey !== 'string' || slotKey.length < 16) {
    throw new Error('invalid_pir_slot_key');
  }
  if (!Number.isSafeInteger(epochStart) || epochStart < 0) {
    throw new Error('invalid_pir_epoch_start');
  }
  if (!Number.isSafeInteger(recordCount) || recordCount <= 0) {
    throw new Error('invalid_pir_record_count');
  }
  if (!Number.isSafeInteger(probe) || probe < 0) {
    throw new Error('invalid_pir_probe');
  }
  return hashBigIntMod([SLOT_DERIVATION, kind, slotKey, epochStart, recordCount, probe], recordCount);
}

// 8-byte fingerprint
export function deriveSlotFingerprint({ kind, slotKey, epochStart }) {
  return hashBytes([SLOT_FINGERPRINT_DERIVATION, kind, slotKey, epochStart], FINGERPRINT_BYTES);
}

// Per epoch blob handle
export function deriveBlobHandle({ kind, epochStart, encryptedBlob }) {
  return hashBytes([BLOB_HANDLE_DERIVATION, kind, epochStart, encryptedBlob], HANDLE_BYTES);
}

function encodeHandleRecord(fingerprint, handle) {
  const record = Buffer.alloc(HANDLE_RECORD_BYTES);
  Buffer.from(fingerprint).copy(record, 0, 0, FINGERPRINT_BYTES);
  Buffer.from(handle).copy(record, FINGERPRINT_BYTES, 0, HANDLE_BYTES);
  return record;
}

// Decode a recovered 24 byte discovery record into its fingerprint and handle
export function decodeHandleRecord(recordBytes) {
  const buffer = Buffer.isBuffer(recordBytes) ? recordBytes : Buffer.from(recordBytes);
  if (buffer.length < HANDLE_RECORD_BYTES) {
    throw new Error('pir_record_too_small');
  }
  return {
    fingerprint: base64url(buffer.subarray(0, FINGERPRINT_BYTES)),
    handle: base64url(buffer.subarray(FINGERPRINT_BYTES, HANDLE_RECORD_BYTES))
  };
}

function placeSourceRecord({ slots, recordCount, kind, epochStart, sourceRecord, fallbackCursor }) {
  if (typeof sourceRecord?.slotKey === 'string' && sourceRecord.slotKey.length >= 16) {
    for (let probe = 0; probe < recordCount; probe += 1) {
      const index = derivePirRecordSlot({ kind, slotKey: sourceRecord.slotKey, epochStart, recordCount, probe });
      if (!slots[index]) {
        slots[index] = sourceRecord;
        return fallbackCursor;
      }
    }
  }
  let cursor = fallbackCursor;
  for (let attempts = 0; attempts < recordCount; attempts += 1) {
    const index = cursor % recordCount;
    cursor = (cursor + 1) % recordCount;
    if (!slots[index]) {
      slots[index] = sourceRecord;
      return cursor;
    }
  }
  return cursor;
}

// Build discovery PIR database for one epoch
export const DISCOVERY_BUCKET_TARGET_SIZE = Math.max(
  2, Number.parseInt(process.env.DISCOVERY_BUCKET_TARGET_SIZE || '32', 10) || 32
);

export const DISCOVERY_FIXED_BUCKET_COUNT = Math.max(
  1, Number.parseInt(process.env.DISCOVERY_BUCKET_COUNT || '256', 10) || 256
);
const BUCKET_DERIVATION = 'qor-discovery-bucket-v1';

export function discoveryBucketCount(recordCount) {
  return Math.max(1, Math.ceil((Number(recordCount) || 1) / DISCOVERY_BUCKET_TARGET_SIZE));
}

// bucketId for a record derivable identically by the client
export function deriveDiscoveryBucketId(slotKey, epochStart, bucketCount) {
  const count = Math.max(1, Number(bucketCount) || 1);
  const h = hashBytes([BUCKET_DERIVATION, epochStart, slotKey], 6);
  return h.readUIntBE(0, 6) % count;
}

function randomOpaqueString(len) {
  const n = Math.max(1, Math.trunc(Number(len) || 1));
  return crypto.randomBytes(Math.ceil(n * 0.75)).toString('base64').slice(0, n);
}

const DISCOVERY_DECOY_SECRET = crypto.createHash('sha256')
  .update(String(process.env.KEY_ENCRYPTION_SECRET || process.env.DB_FIELD_KEY || 'qor-discovery-decoy-fallback'))
  .update('\0qor-discovery-decoy-v1')
  .digest();

function deterministicDecoy(epochId, bucketId, index, len) {
  const need = Math.ceil((len * 3) / 4) + 4;
  const out = Buffer.alloc(need + 32);
  let filled = 0;
  let counter = 0;
  while (filled < need) {
    const block = crypto.createHmac('sha256', DISCOVERY_DECOY_SECRET)
      .update(`${epochId}\0${bucketId}\0${index}\0${counter}`)
      .digest();
    block.copy(out, filled);
    filled += block.length;
    counter += 1;
  }
  return out.subarray(0, need).toString('base64url').slice(0, len);
}

function deterministicOrder(n, seedStr) {
  const idx = Array.from({ length: n }, (_, i) => i);
  let pool = Buffer.alloc(0);
  let poolPos = 0;
  let counter = 0;
  const nextU32 = () => {
    if (poolPos + 4 > pool.length) {
      pool = crypto.createHmac('sha256', DISCOVERY_DECOY_SECRET).update(`shuffle\0${seedStr}\0${counter}`).digest();
      poolPos = 0;
      counter += 1;
    }
    const v = pool.readUInt32BE(poolPos);
    poolPos += 4;
    return v;
  };
  for (let i = n - 1; i > 0; i -= 1) {
    const j = nextU32() % (i + 1);
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  return idx;
}

export function padDiscoveryBucket(realBlobs, { epochId, bucketId, targetSize, medianBlobLen }) {
  const target = Math.max(1, Math.trunc(Number(targetSize) || DISCOVERY_BUCKET_TARGET_SIZE));
  const len = Math.max(1, Math.trunc(Number(medianBlobLen) || 1024));
  const entries = (Array.isArray(realBlobs) ? realBlobs : []).slice(0, target);
  let i = 0;
  while (entries.length < target) {
    entries.push(deterministicDecoy(epochId, bucketId, i, len));
    i += 1;
  }
  const order = deterministicOrder(entries.length, `${epochId}\0${bucketId}`);
  return order.map((k) => entries[k]);
}

export function buildPirPageDatabase({ kind, sourceRecords, schemeId = 'hintless-simplepir', parameterId = 'hintless-simplepir-rlwe64-v1' }) {
  if (!isPirDatabaseKind(kind)) {
    throw new Error(`Unsupported PIR database kind: ${kind}`);
  }

  const config = getPirLayoutConfig(kind);
  const bucketStart = Math.floor(Date.now() / config.epochMs) * config.epochMs;
  const source = (Array.isArray(sourceRecords) ? sourceRecords : [])
    .filter((row) => typeof row?.slotKey === 'string' && row.slotKey.length >= 16 &&
      typeof row?.encryptedBlob === 'string' && row.encryptedBlob.length > 0)
    .slice(0, config.maxSourceRecords);

  const privacyFloor = Math.max(config.paddingFloor, (source.length || 1) * config.slotLoadFactor);
  const recordCount = nextPowerOfTwo(privacyFloor);

  const placedSource = Array.from({ length: recordCount }, () => null);
  let fallbackCursor = 0;
  for (const sourceRecord of source) {
    fallbackCursor = placeSourceRecord({
      slots: placedSource, recordCount, kind, epochStart: bucketStart, sourceRecord, fallbackCursor
    });
  }

  const records = [];
  const recordDigests = [];
  const databaseHash = crypto.createHash('sha256');
  const blobsBySlot = [];

  for (let ordinal = 0; ordinal < recordCount; ordinal += 1) {
    const sourceRecord = placedSource[ordinal] || null;
    let record;
    if (sourceRecord) {
      const fingerprint = deriveSlotFingerprint({ kind, slotKey: sourceRecord.slotKey, epochStart: bucketStart });
      const handle = deriveBlobHandle({ kind, epochStart: bucketStart, encryptedBlob: sourceRecord.encryptedBlob });
      record = encodeHandleRecord(fingerprint, handle);
      blobsBySlot.push(sourceRecord.encryptedBlob);
    } else {
      record = crypto.randomBytes(HANDLE_RECORD_BYTES);
      blobsBySlot.push('');
    }
    const recordDigest = crypto.createHash('sha256').update(record).digest();
    recordDigests.push(base64url(recordDigest));
    databaseHash.update(recordDigest);
    records.push(record);
  }

  const bucketCount = DISCOVERY_FIXED_BUCKET_COUNT;
  const blobsByBucket = Array.from({ length: bucketCount }, () => []);
  for (const sourceRecord of source) {
    const raw = Number.isInteger(sourceRecord.bucketId) ? sourceRecord.bucketId : Number.parseInt(sourceRecord.bucketId, 10);
    if (!Number.isInteger(raw)) continue;
    const bid = ((raw % bucketCount) + bucketCount) % bucketCount;
    blobsByBucket[bid].push(sourceRecord.encryptedBlob);
  }
  const realLens = source.map((r) => r.encryptedBlob.length).filter((n) => n > 0).sort((a, b) => a - b);
  const medianBlobLen = realLens.length ? realLens[Math.floor(realLens.length / 2)] : 1024;

  const databaseDigest = base64url(databaseHash.digest());
  const epochId = hashBase64Url([MANIFEST_VERSION, kind, schemeId, parameterId, bucketStart, databaseDigest], 16);

  const manifest = {
    version: MANIFEST_VERSION,
    kind,
    epochId,
    schemeId,
    parameterId,
    recordSize: HANDLE_RECORD_BYTES,
    recordCount,
    paddingFloor: config.paddingFloor,
    databaseDigest,
    digestAlgorithm: 'sha256-record-digest-chain',
    recordEncoding: 'qor-discovery-handle-record-v1',
    fingerprintBytes: FINGERPRINT_BYTES,
    handleBytes: HANDLE_BYTES,
    createdAt: bucketStart,
    expiresAt: bucketStart + config.epochMs,
    sourceCountHidden: true,
    slotDerivation: SLOT_DERIVATION,
    slotFingerprintDerivation: SLOT_FINGERPRINT_DERIVATION,
    blobHandleDerivation: BLOB_HANDLE_DERIVATION,
    slotProbeCount: config.slotProbeCount,
    slotEpoch: bucketStart,
    bucketCount,
    bucketTargetSize: DISCOVERY_BUCKET_TARGET_SIZE,
    medianBlobLen,
    bucketDerivation: BUCKET_DERIVATION,
    recordDigests
  };

  return { manifest, records, recordDigests, blobsBySlot, blobsByBucket };
}
