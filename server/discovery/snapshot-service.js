/**
 * Target free discovery snapshot packaging
 */

import crypto from 'crypto';
import zlib from 'zlib';

export const DISCOVERY_SNAPSHOT_VERSION = 'qor-discovery-snapshot-v1';
export const DISCOVERY_SNAPSHOT_WIRE_VERSION = 'qor-discovery-snapshot-gzip-v1';

const DEFAULT_EPOCH_MS = 10 * 60 * 1000;
const DEFAULT_PADDING_FLOOR = 128;
const DEFAULT_MAX_ROWS = 200_000;
const DEFAULT_DUMMY_BLOB_CHARS = 2048;
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

function randomOpaqueString(chars) {
  const byteCount = Math.ceil(Math.max(32, chars) * 0.75);
  return crypto.randomBytes(byteCount).toString('base64url').slice(0, chars);
}

function shuffle(items) {
  const output = [...items];
  for (let i = output.length - 1; i > 0; i -= 1) {
    const j = crypto.randomInt(0, i + 1);
    [output[i], output[j]] = [output[j], output[i]];
  }
  return output;
}

function medianBlobLength(entries) {
  const lengths = entries
    .map((entry) => (typeof entry === 'string' ? entry.length : 0))
    .filter((length) => length > 0)
    .sort((a, b) => a - b);
  if (lengths.length === 0) return DEFAULT_DUMMY_BLOB_CHARS;
  return lengths[Math.floor(lengths.length / 2)];
}

export function getDiscoverySnapshotConfig() {
  return {
    epochMs: envInt('DISCOVERY_SNAPSHOT_EPOCH_MS', DEFAULT_EPOCH_MS, 30_000, 24 * 60 * 60 * 1000),
    paddingFloor: envInt('DISCOVERY_SNAPSHOT_PADDING_FLOOR', DEFAULT_PADDING_FLOOR, 1, MAX_PADDING_COUNT),
    maxRows: envInt('DISCOVERY_SNAPSHOT_MAX_ROWS', DEFAULT_MAX_ROWS, 1, MAX_PADDING_COUNT),
    dummyBlobChars: envInt('DISCOVERY_SNAPSHOT_DUMMY_BLOB_CHARS', DEFAULT_DUMMY_BLOB_CHARS, 512, 1024 * 1024),
    gzipLevel: envInt('DISCOVERY_SNAPSHOT_GZIP_LEVEL', 9, 1, 9)
  };
}

export function normalizeSnapshotRows(rows, options = {}) {
  const maxRows = Number.isSafeInteger(options.maxRows)
    ? Math.max(1, Math.min(options.maxRows, MAX_PADDING_COUNT))
    : getDiscoverySnapshotConfig().maxRows;
  return (Array.isArray(rows) ? rows : [])
    .filter((row) => typeof row?.encryptedBlob === 'string' && row.encryptedBlob.length > 0)
    .slice(0, maxRows)
    .map((row) => ({
      encryptedBlob: row.encryptedBlob,
      expiresAt: Number.isFinite(row.expiresAt) ? Math.trunc(row.expiresAt) : 0,
      publishedAt: Number.isFinite(row.publishedAt) ? Math.trunc(row.publishedAt) : 0
    }));
}

export function filterSnapshotRowsForDelta(rows, deltaSince) {
  if (!Number.isFinite(deltaSince) || deltaSince <= 0) return rows;
  const since = Math.trunc(deltaSince);
  return rows.filter((row) => Number(row.publishedAt || 0) > since);
}

export function paddedSnapshotCount(realCount, options = {}) {
  const config = { ...getDiscoverySnapshotConfig(), ...options };
  return nextPowerOfTwo(Math.max(config.paddingFloor, realCount || 1));
}

export function buildDiscoverySnapshotEnvelope(rows, options = {}) {
  const config = { ...getDiscoverySnapshotConfig(), ...options };
  const now = nowMs(options);
  const epochStart = epochStartFor(now, config.epochMs);
  const normalizedRows = normalizeSnapshotRows(rows, { maxRows: config.maxRows });
  const deltaSince = Number.isFinite(options.deltaSince) ? Math.trunc(options.deltaSince) : null;
  const mode = deltaSince && deltaSince >= epochStart - config.epochMs ? 'delta' : 'full';
  const selectedRows = mode === 'delta'
    ? filterSnapshotRowsForDelta(normalizedRows, deltaSince)
    : normalizedRows;

  const realEntries = selectedRows.map((row) => row.encryptedBlob);
  const paddedCount = paddedSnapshotCount(realEntries.length, config);
  const dummyLength = Math.max(config.dummyBlobChars, medianBlobLength(realEntries));
  const entries = [...realEntries];
  while (entries.length < paddedCount) {
    entries.push(randomOpaqueString(dummyLength));
  }

  const body = {
    version: DISCOVERY_SNAPSHOT_VERSION,
    mode,
    epochId: digestBase64Url(Buffer.from(`${DISCOVERY_SNAPSHOT_VERSION}:${epochStart}:${mode}`)).slice(0, 32),
    epochStart,
    epochEndsAt: epochStart + config.epochMs,
    generatedAt: now,
    entries: shuffle(entries),
    realCountHidden: true,
    sourceCountHidden: true,
    paddingStrategy: 'power-of-two-floor-with-opaque-decoys-v1',
    paddedEntryCount: entries.length,
    deltaSince: mode === 'delta' ? deltaSince : undefined
  };

  const plaintext = Buffer.from(JSON.stringify(body), 'utf8');
  const compressed = zlib.gzipSync(plaintext, { level: config.gzipLevel });
  return {
    body,
    plaintext,
    compressed
  };
}

export function buildDiscoverySnapshotResponse(rows, options = {}) {
  const envelope = buildDiscoverySnapshotEnvelope(rows, options);
  return {
    snapshot: {
      version: DISCOVERY_SNAPSHOT_WIRE_VERSION,
      encoding: 'base64url+gzip',
      compression: 'gzip',
      digestAlgorithm: 'sha256-uncompressed-snapshot',
      digest: digestBase64Url(envelope.plaintext),
      epochId: envelope.body.epochId,
      epochStart: envelope.body.epochStart,
      epochEndsAt: envelope.body.epochEndsAt,
      generatedAt: envelope.body.generatedAt,
      mode: envelope.body.mode,
      realCountHidden: true,
      sourceCountHidden: true,
      paddedEntryCount: envelope.body.paddedEntryCount,
      compressed: base64url(envelope.compressed)
    }
  };
}

export function decodeDiscoverySnapshotResponse(snapshot) {
  if (!snapshot || snapshot.version !== DISCOVERY_SNAPSHOT_WIRE_VERSION) {
    throw new Error('unsupported_discovery_snapshot_version');
  }
  if (snapshot.encoding !== 'base64url+gzip') {
    throw new Error('unsupported_discovery_snapshot_encoding');
  }
  const compressed = Buffer.from(snapshot.compressed, 'base64url');
  const plaintext = zlib.gunzipSync(compressed);
  const digest = digestBase64Url(plaintext);
  if (digest !== snapshot.digest) {
    throw new Error('discovery_snapshot_digest_mismatch');
  }
  const decoded = JSON.parse(plaintext.toString('utf8'));
  if (decoded.version !== DISCOVERY_SNAPSHOT_VERSION || !Array.isArray(decoded.entries)) {
    throw new Error('invalid_discovery_snapshot_payload');
  }
  return decoded;
}
