import {
  ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET,
  ANONYMOUS_HTTP_REQUEST_LARGE_BYTES,
  ANONYMOUS_HTTP_REQUEST_PIR_BYTES,
  ANONYMOUS_HTTP_RESPONSE_AVATAR_BYTES,
  ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET,
  ANONYMOUS_HTTP_RESPONSE_PIR_BYTES,
  ANONYMOUS_HTTP_RESPONSE_TAG_INDEX_BYTES,
  ANONYMOUS_HTTP_RESPONSE_TAG_UPDATE_BYTES,
} from './anonymous-http-layout.js';
import { ANONYMOUS_DISCOVERY_RESPONSE_BYTES } from './anonymous-transfer-policy.js';
import { DISCOVERY_BLOB_WIRE_BYTES, DISCOVERY_BUCKET_TARGET_SIZE } from './discovery-constants.js';
import { SPOOL_TAG_PROTOCOL, SPOOL_PIR_LAYOUT } from './protocol-keys.js';
import { POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES } from './crypto-sizes.js';
import { SPOOL_INDEX_MAX_ENTRIES, SPOOL_INDEX_UPDATE_MAX_BYTES, validateSpoolIndexUpdate } from './spool-index-updates.js';
import { SPOOL_DETECTION_PROBE_BYTES, SPOOL_TAG_HEX_CHARS, SPOOL_DETECTION_PROBE_HEX_CHARS } from './spool-tag-protocol.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const MAGIC = [81, 65, 66, 50];
const HEADER_BYTES = 16;
const MAX_PIR_COMPONENT_BYTES = 2 * 1024 * 1024;
const profiles = Object.freeze({
  'response:spool/tag-index-base': { id: 7, count: 2, maxBlobBytes: SPOOL_INDEX_MAX_ENTRIES * SPOOL_DETECTION_PROBE_BYTES, metaMax: 4096, bytes: ANONYMOUS_HTTP_RESPONSE_TAG_INDEX_BYTES, encoding: 'hex', allowEmpty: true },
  'response:spool/tag-index-update': { id: 8, count: 3, maxBlobBytes: SPOOL_INDEX_UPDATE_MAX_BYTES, metaMax: 4096, bytes: ANONYMOUS_HTTP_RESPONSE_TAG_UPDATE_BYTES, encoding: 'hex', allowEmpty: true },
  'request:avatar/blob/put': { id: 1, count: 1, blobBytes: 262244, metaMax: 4096, bytes: ANONYMOUS_HTTP_REQUEST_LARGE_BYTES },
  'request:spool/pir': { id: 2, count: 2, metaMax: 4096, bytes: ANONYMOUS_HTTP_REQUEST_PIR_BYTES },
  'response:discovery/bucket': { id: 3, count: DISCOVERY_BUCKET_TARGET_SIZE, blobBytes: DISCOVERY_BLOB_WIRE_BYTES, metaMax: 4096, bytes: ANONYMOUS_DISCOVERY_RESPONSE_BYTES },
  'response:avatar/blob/get': { id: 4, count: 10, blobBytes: 262244, metaMax: 4096, bytes: ANONYMOUS_HTTP_RESPONSE_AVATAR_BYTES },
  'response:spool/tag-index': { id: 6, count: 2, maxBlobBytes: SPOOL_INDEX_MAX_ENTRIES * SPOOL_DETECTION_PROBE_BYTES, metaMax: 4096, bytes: ANONYMOUS_HTTP_RESPONSE_TAG_INDEX_BYTES, encoding: 'hex', allowEmpty: true },
  'response:spool/pir': { id: 5, count: 1, maxBlobBytes: 760 * 1024, metaMax: 4096, bytes: ANONYMOUS_HTTP_RESPONSE_PIR_BYTES },
});

function fail() { throw new Error('Invalid anonymous binary body'); }
function plain(value) {
  return !!value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
}
function exact(value, keys) {
  return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function safeJson(value, depth = 0, budget = { nodes: 0 }) {
  if (++budget.nodes > 500000 || depth > 32) fail();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return;
  if (!Array.isArray(value) && !plain(value)) fail();
  for (const [key, child] of Object.entries(value)) {
    if (key.length > 256 || ['__proto__', 'prototype', 'constructor'].includes(key)) fail();
    safeJson(child, depth + 1, budget);
  }
}
function jsonBytes(value) { safeJson(value); return encoder.encode(JSON.stringify(value)); }
function parseJson(bytes) {
  const text = decoder.decode(bytes), value = JSON.parse(text);
  safeJson(value);
  if (JSON.stringify(value) !== text) fail();
  return value;
}
function base64(bytes) {
  if (typeof globalThis.Buffer?.from === 'function') {
    return globalThis.Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
function unbase64(value, profile) {
  const max = profile.blobBytes ?? profile.maxBlobBytes ?? MAX_PIR_COMPONENT_BYTES;
  if (typeof value !== 'string' || !value.length || value.length % 4 || value.length > 4 * Math.ceil(max / 3) || /[^A-Za-z0-9+/=]/.test(value)) fail();
  if (typeof globalThis.Buffer?.from === 'function') {
    const bytes = globalThis.Buffer.from(value, 'base64');
    if (!bytes.length || bytes.length > max || (profile.blobBytes && bytes.length !== profile.blobBytes) || bytes.toString('base64') !== value) {
      bytes.fill(0);
      fail();
    }
    return bytes;
  }
  let binary;
  try { binary = atob(value); } catch { fail(); }
  if (!binary.length || binary.length > max || (profile.blobBytes && binary.length !== profile.blobBytes) || btoa(binary) !== value) fail();
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function hex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}
function unhex(value, profile) {
  if (typeof value !== 'string' || value.length % 2 || value.length > profile.maxBlobBytes * 2 || /[^a-f0-9]/.test(value)) fail();
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function validIndex(payload, placeholders = false) {
  if (!exact(payload, ['ok', 'protocol', 'pirLayout', 'epoch', 'count', 'tags', 'probes']) ||
      payload.ok !== true || payload.protocol !== SPOOL_TAG_PROTOCOL || payload.pirLayout !== SPOOL_PIR_LAYOUT ||
      !Number.isSafeInteger(payload.epoch) || payload.epoch < 0 ||
      !Number.isSafeInteger(payload.count) || payload.count < 0 || payload.count > SPOOL_INDEX_MAX_ENTRIES) fail();
  for (const [key, width] of [['tags', SPOOL_TAG_HEX_CHARS], ['probes', SPOOL_DETECTION_PROBE_HEX_CHARS]]) {
    if (placeholders && payload[key] === null) continue;
    if (typeof payload[key] !== 'string' || payload[key].length !== payload.count * width || /[^a-f0-9]/.test(payload[key])) fail();
  }
}
function limit(direction, profile) {
  return profile.bytes - (direction === 'request' ? ANONYMOUS_HTTP_REQUEST_CIPHERTEXT_OFFSET : ANONYMOUS_HTTP_RESPONSE_CIPHERTEXT_OFFSET) - POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES - 4;
}

function transform(direction, operation, wrapper, replace) {
  if (direction === 'request') {
    if (!exact(wrapper, ['version', 'operation', 'body']) || wrapper.operation !== operation || !plain(wrapper.body)) fail();
    const body = { ...wrapper.body };
    if (operation === 'avatar/blob/put') {
      if (!exact(body, ['authorization', 'serverEntryAuthorization', 'blobId', 'data', 'powEpoch', 'powNonce', 'powSolution'])) fail();
      body.data = replace(body.data);
    } else {
      if (!exact(body, ['epoch', 'layout', 'pubParams', 'query'])) fail();
      body.pubParams = replace(body.pubParams); body.query = replace(body.query);
    }
    return { ...wrapper, body };
  }
  if (!exact(wrapper, ['version', 'payload']) || !plain(wrapper.payload)) fail();
  const payload = { ...wrapper.payload };
  if (payload.ok === false) return { ...wrapper, payload };
  if (payload.ok !== true) fail();
  if (operation === 'discovery/bucket') {
    if (!exact(payload, ['ok', 'epochId', 'bucketCount', 'buckets']) || !plain(payload.buckets) || Object.keys(payload.buckets).length !== 1) fail();
    const id = Object.keys(payload.buckets)[0], slots = payload.buckets[id];
    if (!/^(0|[1-9][0-9]{0,2})$/.test(id) || Number(id) >= 512 || !Array.isArray(slots) || slots.length !== 64) fail();
    payload.buckets = { [id]: slots.map(replace) };
  } else if (operation === 'avatar/blob/get') {
    if (!exact(payload, ['ok', 'blobs']) || !Array.isArray(payload.blobs) || payload.blobs.length !== 10) fail();
    payload.blobs = payload.blobs.map(item => {
      if (!exact(item, ['id', 'data']) || typeof item.id !== 'string' || !/^[a-f0-9]{64}$/.test(item.id)) fail();
      return { ...item, data: replace(item.data) };
    });
  } else if ((operation === 'spool/tag-index' || operation === 'spool/tag-index-base')) {
    validIndex(payload, true);
    payload.tags = replace(payload.tags);
    payload.probes = replace(payload.probes);
  } else if (operation === 'spool/tag-index-update') {
    validateSpoolIndexUpdate(payload, true);
    payload.order = replace(payload.order);
    payload.tags = replace(payload.tags);
    payload.probes = replace(payload.probes);
  } else {
    if (!exact(payload, ['ok', 'response'])) fail();
    payload.response = replace(payload.response);
  }
  return { ...wrapper, payload };
}
function encode(direction, operation, wrapper) {
  const profile = profiles[`${direction}:${operation}`];
  if (!profile) return encoder.encode(JSON.stringify(wrapper));
  const blobs = [];
  let metadata;
  try {
    metadata = jsonBytes(transform(direction, operation, wrapper, value => { blobs.push(profile.encoding === 'hex' ? unhex(value, profile) : unbase64(value, profile)); return null; }));
    const error = direction === 'response' && wrapper.payload.ok === false;
    if (blobs.length !== (error ? 0 : profile.count) || metadata.length > profile.metaMax) fail();
    const size = HEADER_BYTES + metadata.length + blobs.reduce((n, blob) => n + 4 + blob.length, 0);
    if (size > limit(direction, profile)) fail();
    const out = new Uint8Array(size), view = new DataView(out.buffer);
    out.set(MAGIC); out[4] = profile.id; out[5] = error ? 1 : 0;
    view.setUint32(8, metadata.length); view.setUint32(12, blobs.length);
    out.set(metadata, HEADER_BYTES);
    let at = HEADER_BYTES + metadata.length;
    for (const blob of blobs) { view.setUint32(at, blob.length); out.set(blob, at + 4); at += 4 + blob.length; }
    return out;
  } finally {
    metadata?.fill(0);
    for (const blob of blobs) blob.fill(0);
  }
}
function decode(direction, operation, bytes) {
  let profile = profiles[`${direction}:${operation}`];
  const binary = bytes.length >= 4 && MAGIC.every((byte, i) => bytes[i] === byte);
  if (!binary) {
    if (profile) fail();
    const value = JSON.parse(decoder.decode(bytes));
    if (direction === 'request' && profiles[`request:${value?.operation}`]) fail();
    return value;
  }
  if (bytes.length < HEADER_BYTES) fail();
  if (direction === 'request') profile = Object.entries(profiles).find(([key, p]) => key.startsWith('request:') && p.id === bytes[4])?.[1];
  if (!profile || profile.id !== bytes[4] || bytes[5] > 1 || bytes[6] || bytes[7] || bytes.length > limit(direction, profile)) fail();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength), n = view.getUint32(8), count = view.getUint32(12);
  if (n > profile.metaMax || HEADER_BYTES + n > bytes.length || count !== (bytes[5] ? 0 : profile.count) || (direction === 'request' && bytes[5])) fail();
  const metadata = parseJson(bytes.subarray(HEADER_BYTES, HEADER_BYTES + n));
  if (direction === 'request') {
    operation = metadata?.operation;
    if (profiles[`request:${operation}`] !== profile) fail();
  }
  if ((direction === 'response' && metadata?.payload?.ok === false) !== (bytes[5] === 1)) fail();
  let at = HEADER_BYTES + n, i = 0;
  const result = transform(direction, operation, metadata, placeholder => {
    if (placeholder !== null || ++i > count || at + 4 > bytes.length) fail();
    const size = view.getUint32(at); at += 4;
    if ((!size && !profile.allowEmpty) || size > (profile.blobBytes ?? profile.maxBlobBytes ?? MAX_PIR_COMPONENT_BYTES) || (profile.blobBytes && size !== profile.blobBytes) || size > bytes.length - at) fail();
    const raw = bytes.subarray(at, at + size);
    const value = profile.encoding === 'hex' ? hex(raw) : base64(raw); at += size; return value;
  });
  if (i !== count || at !== bytes.length) fail();
  if ((operation === 'spool/tag-index' || operation === 'spool/tag-index-base') && result.payload.ok === true) validIndex(result.payload);
  if (operation === 'spool/tag-index-update' && result.payload.ok === true) validateSpoolIndexUpdate(result.payload);
  return result;
}
export function encodeAnonymousRequest(wrapper) { return encode('request', wrapper.operation, wrapper); }
export function decodeAnonymousRequest(bytes) { return decode('request', null, bytes); }
export function encodeAnonymousResponse(operation, wrapper) { return encode('response', operation, wrapper); }
export function decodeAnonymousResponse(operation, bytes) { return decode('response', operation, bytes); }
