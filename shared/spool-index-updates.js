import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, isHex } from './bytes.js';
import { SPOOL_TAG_PROTOCOL, SPOOL_PIR_LAYOUT } from './protocol-keys.js';
import { SPOOL_TAG_BYTES, SPOOL_DETECTION_PROBE_BYTES, SPOOL_TAG_HEX_CHARS, SPOOL_DETECTION_PROBE_HEX_CHARS } from './spool-tag-protocol.js';
import { HASH_OUTPUT_BYTES } from './crypto-sizes.js';

export const SPOOL_INDEX_CHECKPOINT_MS = 60 * 60 * 1000;
export const SPOOL_INDEX_MAX_ENTRIES = 6061;
export const SPOOL_INDEX_UPDATE_MAX_BYTES = 24 * 1024;
export const SPOOL_INDEX_NEW_ENTRY = 0x8000;
const encoder = new TextEncoder();
const checkpointDigests = new WeakMap();

export function validateSpoolIndex(index) {
  if (!index || !Number.isSafeInteger(index.epoch) || index.epoch < 0 ||
      !Array.isArray(index.tags) || !Array.isArray(index.probes) ||
      index.tags.length !== index.probes.length || index.tags.length > SPOOL_INDEX_MAX_ENTRIES ||
      index.tags.some(tag => !isHex(tag, { exactBytes: SPOOL_TAG_BYTES })) ||
      index.probes.some(probe => !isHex(probe, { exactBytes: SPOOL_DETECTION_PROBE_BYTES }))) throw new Error('Invalid spool index');
  return index;
}

export function spoolIndexDigest(index) {
  const cached = checkpointDigests.get(index);
  if (cached !== undefined) return cached;
  validateSpoolIndex(index);
  const digest = bytesToHex(blake3(encoder.encode(`${index.epoch}\0${index.tags.join('')}\0${index.probes.join('')}`)));
  if (Object.isFrozen(index) && Object.isFrozen(index.tags) && Object.isFrozen(index.probes)) {
    checkpointDigests.set(index, digest);
  }
  return digest;
}

export function buildSpoolIndexUpdate(base, current, checkpoint) {
  validateSpoolIndex(base);
  validateSpoolIndex(current);
  const positions = new Map();
  for (let index = 0; index < base.tags.length; index++) {
    const key = base.tags[index] + base.probes[index];
    if (!positions.has(key)) positions.set(key, { entries: [], used: 0 });
    positions.get(key).entries.push(index);
  }
  const tags = [], probes = [], order = [];
  for (let index = 0; index < current.tags.length; index++) {
    const position = positions.get(current.tags[index] + current.probes[index]);
    if (position && position.used < position.entries.length) order.push(position.entries[position.used++]);
    else {
      order.push(SPOOL_INDEX_NEW_ENTRY + tags.length);
      tags.push(current.tags[index]);
      probes.push(current.probes[index]);
    }
  }
  const update = {
    ok: true, protocol: SPOOL_TAG_PROTOCOL, pirLayout: SPOOL_PIR_LAYOUT,
    checkpoint, baseDigest: spoolIndexDigest(base), epoch: current.epoch,
    count: current.tags.length, mode: 'delta',
    order: order.map(position => position.toString(16).padStart(4, '0')).join(''),
    tags: tags.join(''), probes: probes.join(''),
  };
  if (update.order.length / 2 + update.tags.length / 2 + update.probes.length / 2 > SPOOL_INDEX_UPDATE_MAX_BYTES) {
    return { ...update, mode: 'full', order: '', tags: '', probes: '' };
  }
  return update;
}

export function applySpoolIndexUpdate(base, update) {
  validateSpoolIndexUpdate(update);
  if (update.mode !== 'delta' || update.baseDigest !== spoolIndexDigest(base)) throw new Error('Invalid spool index update base');
  const tags = [], probes = [], used = new Set();
  let nextNew = 0;
  for (let index = 0; index < update.count; index++) {
    const position = Number.parseInt(update.order.slice(index * 4, index * 4 + 4), 16);
    if (used.has(position)) throw new Error('Duplicate spool index update entry');
    used.add(position);
    if (position >= SPOOL_INDEX_NEW_ENTRY) {
      const added = position - SPOOL_INDEX_NEW_ENTRY;
      if (added !== nextNew++ || added >= update.tags.length / SPOOL_TAG_HEX_CHARS) throw new Error('Invalid new spool index entry');
      tags.push(update.tags.slice(added * SPOOL_TAG_HEX_CHARS, (added + 1) * SPOOL_TAG_HEX_CHARS));
      probes.push(update.probes.slice(added * SPOOL_DETECTION_PROBE_HEX_CHARS, (added + 1) * SPOOL_DETECTION_PROBE_HEX_CHARS));
    } else {
      if (position >= base.tags.length) throw new Error('Invalid base spool index entry');
      tags.push(base.tags[position]);
      probes.push(base.probes[position]);
    }
  }
  if (nextNew !== update.tags.length / SPOOL_TAG_HEX_CHARS) throw new Error('Unused spool index update entries');
  return validateSpoolIndex({ epoch: update.epoch, tags, probes });
}

export function validateSpoolIndexUpdate(update, placeholders = false) {
  if (!update || Object.getPrototypeOf(update) !== Object.prototype ||
      Object.keys(update).sort().join(',') !== 'baseDigest,checkpoint,count,epoch,mode,ok,order,pirLayout,probes,protocol,tags' ||
      update.ok !== true || update.protocol !== SPOOL_TAG_PROTOCOL || update.pirLayout !== SPOOL_PIR_LAYOUT ||
      !Number.isSafeInteger(update.checkpoint) || update.checkpoint < 0 ||
      !Number.isSafeInteger(update.epoch) || update.epoch < 0 ||
      !Number.isSafeInteger(update.count) || update.count < 0 || update.count > SPOOL_INDEX_MAX_ENTRIES ||
      !['delta', 'full'].includes(update.mode) ||
      !isHex(update.baseDigest, { exactBytes: HASH_OUTPUT_BYTES })) throw new Error('Invalid spool index update');
  for (const key of ['order', 'tags', 'probes']) {
    if (placeholders && update[key] === null) continue;
    if (typeof update[key] !== 'string' || !/^[a-f0-9]*$/.test(update[key])) throw new Error('Invalid spool index update bytes');
  }
  if (placeholders) return update;
  if (update.mode === 'full') {
    if (update.order !== '' || update.tags !== '' || update.probes !== '') throw new Error('Invalid full spool index update');
  } else if (update.order.length !== update.count * 4 || update.tags.length % SPOOL_TAG_HEX_CHARS ||
      update.probes.length / SPOOL_DETECTION_PROBE_HEX_CHARS !== update.tags.length / SPOOL_TAG_HEX_CHARS ||
      (update.order.length + update.tags.length + update.probes.length) / 2 > SPOOL_INDEX_UPDATE_MAX_BYTES) {
    throw new Error('Invalid spool index update lengths');
  }
  return update;
}
