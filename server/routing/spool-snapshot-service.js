/**
 * Uniform global spool snapshot
 */

import crypto from 'crypto';
import zlib from 'zlib';

export const SPOOL_SNAPSHOT_VERSION = 'qor-spool-snapshot-v1';
export const SPOOL_SNAPSHOT_WIRE_VERSION = 'qor-spool-snapshot-gzip-v1';

const DEFAULT_EPOCH_MS = 30 * 1000;
const DEFAULT_PADDING_FLOOR = 256;
const DEFAULT_MAX_ROWS = 256;
const DEFAULT_MAX_PLAINTEXT_BYTES = 16 * 1024 * 1024;
const MAX_PADDING_COUNT = 1_000_000;

function envInt(name, fallback, min, max) {
  const parsed = Number.parseInt(process.env[name] || String(fallback), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function nowMs(options = {}) {
  return Number.isFinite(options.now) ? Math.trunc(options.now) : Date.now();
}

function epochStartFor(timestamp, epochMs) {
  return Math.floor(timestamp / epochMs) * epochMs;
}

function nextPowerOfTwo(value) {
  let n = 1;
  const target = Math.max(1, Math.trunc(value || 1));
  while (n < target && n < MAX_PADDING_COUNT) n *= 2;
  return n;
}

function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function digestBase64Url(bytes) {
  return base64url(crypto.createHash('sha256').update(bytes).digest());
}

function shuffle(items) {
  const output = [...items];
  for (let i = output.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(0, i + 1);
    [output[i], output[j]] = [output[j], output[i]];
  }
  return output;
}

function isSealedEnvelope(envelope) {
  return !!envelope &&
    typeof envelope === 'object' &&
    typeof envelope.version === 'string' &&
    typeof envelope.ciphertext === 'string' &&
    typeof envelope.ephemeralKey === 'string' &&
    typeof envelope.nonce === 'string';
}

function medianFieldLength(envelopes, field) {
  const lengths = envelopes
    .map((envelope) => (typeof envelope?.[field] === 'string' ? envelope[field].length : 0))
    .filter((length) => length > 0)
    .sort((a, b) => a - b);
  if (lengths.length === 0) return 0;
  return lengths[Math.floor(lengths.length / 2)];
}

function dummySealedEnvelope(ciphertextChars, ephemeralChars, nonceChars) {
  const randB64 = (chars) => crypto
    .randomBytes(Math.ceil(Math.max(16, chars) * 0.75))
    .toString('base64')
    .slice(0, Math.max(16, chars));
  return {
    version: 'ss-v1',
    ciphertext: randB64(ciphertextChars || 1024),
    ephemeralKey: randB64(ephemeralChars || 44),
    nonce: randB64(nonceChars || 16)
  };
}

export function getSpoolSnapshotConfig() {
  return {
    epochMs: envInt('SPOOL_SNAPSHOT_EPOCH_MS', DEFAULT_EPOCH_MS, 5_000, 10 * 60 * 1000),
    paddingFloor: envInt('SPOOL_SNAPSHOT_PADDING_FLOOR', DEFAULT_PADDING_FLOOR, 1, MAX_PADDING_COUNT),
    maxRows: envInt('SPOOL_SNAPSHOT_MAX_ROWS', DEFAULT_MAX_ROWS, 1, MAX_PADDING_COUNT),
    maxPlaintextBytes: envInt('SPOOL_SNAPSHOT_MAX_PLAINTEXT_BYTES', DEFAULT_MAX_PLAINTEXT_BYTES, 1024 * 1024, 512 * 1024 * 1024),
    gzipLevel: envInt('SPOOL_SNAPSHOT_GZIP_LEVEL', 6, 1, 9)
  };
}

export function normalizeSpoolRows(rows, options = {}) {
  const maxRows = Number.isSafeInteger(options.maxRows)
    ? Math.max(1, Math.min(options.maxRows, MAX_PADDING_COUNT))
    : getSpoolSnapshotConfig().maxRows;
  return (Array.isArray(rows) ? rows : [])
    .filter((row) => isSealedEnvelope(row?.envelope))
    .slice(0, maxRows)
    .map((row) => row.envelope);
}

export function paddedSpoolCount(realCount, options = {}) {
  const config = { ...getSpoolSnapshotConfig(), ...options };
  return nextPowerOfTwo(Math.max(config.paddingFloor, realCount || 1));
}

export function buildSpoolSnapshotEnvelope(rows, options = {}) {
  const config = { ...getSpoolSnapshotConfig(), ...options };
  const now = nowMs(options);
  const epochStart = epochStartFor(now, config.epochMs);
  let realEnvelopes = normalizeSpoolRows(rows, { maxRows: config.maxRows });

  const ciphertextChars = Math.max(256, medianFieldLength(realEnvelopes, 'ciphertext'));
  const ephemeralChars = Math.max(32, medianFieldLength(realEnvelopes, 'ephemeralKey'));
  const nonceChars = Math.max(12, medianFieldLength(realEnvelopes, 'nonce'));
  const estimatedEntryBytes = Math.max(512, ciphertextChars + ephemeralChars + nonceChars + 128);
  let effectivePaddingFloor = Math.max(1, Math.trunc(config.paddingFloor || 1));
  let paddedCount = nextPowerOfTwo(Math.max(effectivePaddingFloor, realEnvelopes.length || 1));

  for (let attempt = 0; attempt < 32 && paddedCount * estimatedEntryBytes > config.maxPlaintextBytes; attempt += 1) {
    if (realEnvelopes.length > 1) {
      realEnvelopes = realEnvelopes.slice(0, Math.max(1, Math.floor(realEnvelopes.length / 2)));
    } else if (effectivePaddingFloor > 1) {
      effectivePaddingFloor = Math.max(1, Math.floor(effectivePaddingFloor / 2));
    } else {
      break;
    }
    paddedCount = nextPowerOfTwo(Math.max(effectivePaddingFloor, realEnvelopes.length || 1));
  }

  const entries = [...realEnvelopes];
  while (entries.length < paddedCount) {
    entries.push(dummySealedEnvelope(ciphertextChars, ephemeralChars, nonceChars));
  }

  const body = {
    version: SPOOL_SNAPSHOT_VERSION,
    epochId: digestBase64Url(Buffer.from(`${SPOOL_SNAPSHOT_VERSION}:${epochStart}`)).slice(0, 32),
    epochStart,
    epochEndsAt: epochStart + config.epochMs,
    generatedAt: now,
    entries: shuffle(entries),
    realCountHidden: true,
    sourceCountHidden: true,
    paddingStrategy: 'power-of-two-floor-with-shape-matched-decoys-v1',
    paddedEntryCount: entries.length
  };

  const plaintext = Buffer.from(JSON.stringify(body), 'utf8');
  const compressed = zlib.gzipSync(plaintext, { level: config.gzipLevel });
  return { body, plaintext, compressed };
}

export function buildSpoolSnapshotResponse(rows, options = {}) {
  const envelope = buildSpoolSnapshotEnvelope(rows, options);
  return {
    snapshot: {
      version: SPOOL_SNAPSHOT_WIRE_VERSION,
      encoding: 'base64url+gzip',
      compression: 'gzip',
      digestAlgorithm: 'sha256-uncompressed-snapshot',
      digest: digestBase64Url(envelope.plaintext),
      epochId: envelope.body.epochId,
      epochStart: envelope.body.epochStart,
      epochEndsAt: envelope.body.epochEndsAt,
      generatedAt: envelope.body.generatedAt,
      realCountHidden: true,
      sourceCountHidden: true,
      paddedEntryCount: envelope.body.paddedEntryCount,
      compressed: base64url(envelope.compressed)
    }
  };
}

export function decodeSpoolSnapshotResponse(snapshot) {
  if (!snapshot || snapshot.version !== SPOOL_SNAPSHOT_WIRE_VERSION) {
    throw new Error('unsupported_spool_snapshot_version');
  }
  if (snapshot.encoding !== 'base64url+gzip') {
    throw new Error('unsupported_spool_snapshot_encoding');
  }
  const compressed = Buffer.from(snapshot.compressed, 'base64url');
  const plaintext = zlib.gunzipSync(compressed);
  if (digestBase64Url(plaintext) !== snapshot.digest) {
    throw new Error('spool_snapshot_digest_mismatch');
  }
  const decoded = JSON.parse(plaintext.toString('utf8'));
  if (decoded.version !== SPOOL_SNAPSHOT_VERSION || !Array.isArray(decoded.entries)) {
    throw new Error('invalid_spool_snapshot_payload');
  }
  return decoded;
}
