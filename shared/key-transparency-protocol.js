import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES
} from './crypto-sizes.js';
import { bytesToHex } from './bytes.js';

export const KEY_TRANSPARENCY_PROTOCOL = 'qorc-key-transparency-v2';
const KEY_TRANSPARENCY_HASH_BYTES = 64;
const KEY_TRANSPARENCY_HASH_HEX_CHARS = KEY_TRANSPARENCY_HASH_BYTES * 2;
export const KEY_TRANSPARENCY_ML_DSA_PUBLIC_KEY_BYTES = ML_DSA_87_PUBLIC_KEY_BYTES;
export const KEY_TRANSPARENCY_ML_DSA_SECRET_KEY_BYTES = ML_DSA_87_SECRET_KEY_BYTES;
export const KEY_TRANSPARENCY_ML_DSA_SIGNATURE_BYTES = ML_DSA_87_SIGNATURE_BYTES;

export const KEY_TRANSPARENCY_EPOCH_MS = 60 * 60 * 1000;
export const KEY_TRANSPARENCY_RECOVERY_DELAY_EPOCHS = 7 * 24;

export const KEY_TRANSPARENCY_POW_EPOCH_MS = 60 * 60 * 1000;
export const KEY_TRANSPARENCY_APPEND_POW_DIFFICULTY = 18;
export const KEY_TRANSPARENCY_SYNC_POW_DIFFICULTY = 14;
export const KEY_TRANSPARENCY_APPEND_POW_DOMAIN = 'qorc-key-transparency-append-pow-v2';
export const KEY_TRANSPARENCY_SYNC_POW_DOMAIN = 'qorc-key-transparency-sync-pow-v2';

export const KEY_TRANSPARENCY_MAX_LOG_SIZE = 10_000_000;
export const KEY_TRANSPARENCY_DELTA_MAX_RECORDS = 4096;
export const KEY_TRANSPARENCY_DELTA_MAX_EPOCHS = 720;

const encoder = new TextEncoder();

function normalizeCanonicalValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('Canonical number must be a safe integer');
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeCanonicalValue(entry));
  }
  if (value && typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error('Canonical value must be a plain object');
    }
    const normalized = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) throw new Error('Canonical value cannot contain undefined');
      normalized[key] = normalizeCanonicalValue(value[key]);
    }
    return normalized;
  }
  throw new Error('Unsupported canonical value');
}

function canonicalKeyTransparencyJson(value) {
  return JSON.stringify(normalizeCanonicalValue(value));
}

export function encodeKeyTransparencySignaturePayload(kind, payload) {
  if (typeof kind !== 'string' || !/^[a-z0-9-]{3,64}$/.test(kind)) {
    throw new Error('Invalid key-transparency signature kind');
  }
  return encoder.encode(canonicalKeyTransparencyJson({
    context: 'qorc-Key-Transparency-Signature-v2',
    kind,
    payload,
    protocol: KEY_TRANSPARENCY_PROTOCOL,
  }));
}

export function keyTransparencySignedUpdate(update) {
  if (!update || typeof update !== 'object' || Array.isArray(update)) {
    throw new Error('Invalid key-transparency update');
  }
  return normalizeCanonicalValue(update);
}

export function exactPlainObject(value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]);
}

export function isKeyTransparencyHash(value) {
  return typeof value === 'string' &&
    value.length === KEY_TRANSPARENCY_HASH_HEX_CHARS &&
    /^[a-f0-9]+$/.test(value);
}

export function isKeyTransparencyLabel(value) {
  return isKeyTransparencyHash(value);
}

export function keyTransparencyPowEpoch(now = Date.now()) {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid key-transparency time');
  return Math.floor(now / KEY_TRANSPARENCY_POW_EPOCH_MS);
}

export function keyTransparencyEpoch(now = Date.now()) {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid key-transparency time');
  return Math.floor(now / KEY_TRANSPARENCY_EPOCH_MS);
}

export function keyTransparencyRecoveryActivationEpoch(requestEpoch) {
  if (!Number.isSafeInteger(requestEpoch) || requestEpoch < 0) {
    throw new Error('Invalid key-transparency recovery epoch');
  }
  return requestEpoch + KEY_TRANSPARENCY_RECOVERY_DELAY_EPOCHS;
}

const KEY_TRANSPARENCY_RECORD_KEYS = Object.freeze([
  'epoch',
  'epochLabel',
  'recordHash',
  'version',
]);

export function isKeyTransparencyRecord(value) {
  return exactPlainObject(value, KEY_TRANSPARENCY_RECORD_KEYS) &&
    Number.isSafeInteger(value.epoch) &&
    value.epoch >= 0 &&
    isKeyTransparencyLabel(value.epochLabel) &&
    isKeyTransparencyHash(value.recordHash) &&
    Number.isSafeInteger(value.version) &&
    value.version >= 1 &&
    value.version <= KEY_TRANSPARENCY_MAX_LOG_SIZE;
}

export function keyTransparencyHeadPayload(head) {
  return {
    entryCount: head.entryCount,
    epoch: head.epoch,
    genesisEpoch: head.genesisEpoch,
    rootHash: head.rootHash,
  };
}

const LOG_ROOT_DOMAIN = 'qorc-key-transparency-log-root-v2';
const LOG_GENESIS_DOMAIN = 'qorc-key-transparency-log-genesis-v2';
const RECORD_HASH_DOMAIN = 'qorc-key-transparency-record-v2';

export function keyTransparencyGenesisRoot(sha3_512) {
  return bytesToHex(sha3_512(encoder.encode(LOG_GENESIS_DOMAIN)));
}

export function keyTransparencyFoldRecord(sha3_512, previousRoot, record) {
  if (!isKeyTransparencyHash(previousRoot)) {
    throw new Error('Invalid key-transparency log root');
  }
  if (!isKeyTransparencyRecord(record)) {
    throw new Error('Invalid key-transparency record');
  }
  return bytesToHex(sha3_512(encoder.encode(canonicalKeyTransparencyJson({
    domain: LOG_ROOT_DOMAIN,
    previousRoot,
    record,
  }))));
}

export function keyTransparencyFoldRecords(sha3_512, previousRoot, records) {
  let root = previousRoot;
  for (const record of records) root = keyTransparencyFoldRecord(sha3_512, root, record);
  return root;
}

// Hash over full signed transition
export function keyTransparencyRecordHash(sha3_512, signedUpdate, authorization) {
  return bytesToHex(sha3_512(encoder.encode(canonicalKeyTransparencyJson({
    authorization,
    domain: RECORD_HASH_DOMAIN,
    protocol: KEY_TRANSPARENCY_PROTOCOL,
    signedUpdate,
  }))));
}
