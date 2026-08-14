import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { blake3 } from '@noble/hashes/blake3.js';

import {
  SPOOL_PIR_LAYOUT,
  SPOOL_PIR_RECORD_BYTES,
  SPOOL_PIR_ROW_BYTES,
  SPOOL_PIR_ROWS_PER_RECORD,
  splitSpoolPirRecord
} from '../../shared/spool-pir-layout.js';
import { SPOOL_TAG_INDEX_POLL_INTERVAL_MS } from '../../shared/spool-tag-protocol.js';
import { INVALID_PIR_EPOCH_MESSAGE } from '../config/error-codes.js';
import { readGlobalMixPirSnapshot } from '../routing/blind-router.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { HASH_OUTPUT_BYTES } from '../utils/crypto-consts.js';
import { PirWorkerClient } from './pir-worker-client.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';

const PIR_SNAPSHOT_MIN_REFRESH_MS = Math.max(SPOOL_TAG_INDEX_POLL_INTERVAL_MS, 180_000);

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_WORKER_PATH = path.resolve(
  moduleDir,
  '../../workers/ypir/target/release/qor-pir-worker'
);

/**
 * Two fixed worker slots retain published snapshot and its predecessor
 */
let slots = [];
let publishedSlot = null;
let refreshPromise = null;
let lastRefreshAt = 0;
let started = false;

export function pirWorkerPath() {
  return process.env.QOR_PIR_WORKER_PATH || DEFAULT_WORKER_PATH;
}

function createSlot(worker) {
  return { worker, snapshot: null, building: false };
}

function snapshotEpoch(source) {
  const hasher = blake3.create({ dkLen: HASH_OUTPUT_BYTES });
  hasher.update(UTF8_ENCODER.encode(`${PROTOCOL_KEYS.PIR_SNAPSHOT}\0${SPOOL_PIR_LAYOUT}\0`));
  for (let index = 0; index < source.ids.length; index += 1) {
    hasher.update(UTF8_ENCODER.encode(source.ids[index]));
    hasher.update(UTF8_ENCODER.encode(source.tags[index]));
    hasher.update(UTF8_ENCODER.encode(source.probes[index]));
  }
  const digest = hasher.digest();
  try {
    const epoch = new DataView(digest.buffer, digest.byteOffset, digest.byteLength)
      .getUint32(0, false);
      
    return epoch === 0xFFFF_FFFF ? 0xFFFF_FFFE : epoch;
  } finally {
    digest.fill(0);
  }
}

function sameIndex(left, right) {
  if (!left || left.tags.length !== right.tags.length) return false;
  for (let index = 0; index < left.tags.length; index += 1) {
    if (
      left.tags[index] !== right.tags[index] ||
      left.probes[index] !== right.probes[index] ||
      left.ids[index] !== right.ids[index]
    ) return false;
  }
  return true;
}

function splitPirRecords(records) {
  const rows = [];
  for (const record of records) {
    if (!Buffer.isBuffer(record) || record.length !== SPOOL_PIR_RECORD_BYTES) {
      throw new Error('Invalid fixed-width PIR spool record');
    }
    for (const output of splitSpoolPirRecord(record)) {
      rows.push(Buffer.from(output.buffer, output.byteOffset, output.byteLength));
    }
  }
  return rows;
}

async function prepareBuildSlot(slot) {
  if (slot.worker.loadedEpoch === null) {
    await slot.worker.start();
    return;
  }
  
  await slot.worker.restart();
}

export async function startPirService() {
  if (started) return;
  const binaryPath = pirWorkerPath();
  const first = new PirWorkerClient(binaryPath);
  const second = new PirWorkerClient(binaryPath);
  try {
    await first.start();
    await second.start();
  } catch (error) {
    await first.stop().catch(() => { });
    await second.stop().catch(() => { });
    throw new Error(
      `PIR worker is unavailable at ${binaryPath}: ${error?.message ?? error}. ` +
      'Small spool entries are served only by PIR, so ongoing messages cannot be ' +
      'delivered until this is fixed. Build it with `pnpm build:pir` or set ' +
      'QOR_PIR_WORKER_PATH.'
    );
  }
  slots = [createSlot(first), createSlot(second)];
  publishedSlot = null;
  refreshPromise = null;
  lastRefreshAt = 0;
  started = true;
}

export async function stopPirService() {
  const workers = slots.map((slot) => slot.worker);
  slots = [];
  publishedSlot = null;
  refreshPromise = null;
  lastRefreshAt = 0;
  started = false;
  await Promise.all(workers.map((worker) => worker?.stop()));
}

function availableBuildSlot() {
  return slots.find((slot) => slot !== publishedSlot && !slot.building) || null;
}

async function buildAndPublishSnapshot(now) {
  const slot = publishedSlot === null ? slots[0] : availableBuildSlot();
  if (!slot) throw new Error('No PIR snapshot build slot is available');
  slot.building = true;
  
  slot.snapshot = null;
  try {
    const source = await readGlobalMixPirSnapshot(now);
    if (sameIndex(publishedSlot?.snapshot, source)) {
      await prepareBuildSlot(slot);
      lastRefreshAt = Date.now();
      return publishedSlot.snapshot.epoch;
    }

    const epoch = snapshotEpoch(source);
    const startedAt = Date.now();
    console.log('[PIR] Spool snapshot build started', {
      epoch,
      records: source.records.length,
      rows: source.records.length * SPOOL_PIR_ROWS_PER_RECORD
    });
    await prepareBuildSlot(slot);
    if (source.records.length > 0) {
      const rows = splitPirRecords(source.records);
      await slot.worker.build(epoch, rows, SPOOL_PIR_ROW_BYTES);
    }
    slot.snapshot = {
      epoch,
      ids: source.ids,
      tags: source.tags,
      probes: source.probes,
      records: source.records.length
    };
    publishedSlot = slot;
    lastRefreshAt = Date.now();
    console.log('[PIR] Spool snapshot published', {
      epoch,
      records: source.records.length,
      elapsedMs: Date.now() - startedAt
    });
    return epoch;
  } finally {
    slot.building = false;
  }
}

function refreshPirSnapshot(now = Date.now(), force = false) {
  if (!started) return null;
  if (refreshPromise) return refreshPromise;
  if (
    !force &&
    publishedSlot?.snapshot &&
    now - lastRefreshAt < PIR_SNAPSHOT_MIN_REFRESH_MS
  ) {
    return Promise.resolve(publishedSlot.snapshot.epoch);
  }

  const refresh = buildAndPublishSnapshot(now).finally(() => {
    if (refreshPromise === refresh) refreshPromise = null;
  });
  refreshPromise = refresh;
  return refresh;
}

// Builds the first requestable snapshot before the HTTPS listener opens
export function prebuildCurrentPirEpoch(now = Date.now()) {
  return refreshPirSnapshot(now, publishedSlot === null);
}

// Refreshes the spare slot without changing the index until it is complete
export function prebuildNextPirEpoch(now = Date.now()) {
  return refreshPirSnapshot(now, false);
}

// Returns the exact index backed by the currently published worker snapshot
export function readReadyPirTagIndex() {
  const snapshot = publishedSlot?.snapshot;
  if (!snapshot) throw new Error('PIR snapshot is unavailable');
  return {
    epoch: snapshot.epoch,
    tags: [...snapshot.tags],
    probes: [...snapshot.probes]
  };
}

export async function ensurePirEpoch(epoch) {
  if (!started) throw new Error('PIR service is not running');
  const slot = slots.find((candidate) => (
    !candidate.building && candidate.snapshot?.epoch === epoch
  ));
  if (!slot) throw new Error('PIR epoch is unavailable');
  return epoch;
}

export async function answerPirQuery(epoch, query, pubParams) {
  if (!started) throw new Error('PIR service is not running');
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error(INVALID_PIR_EPOCH_MESSAGE);
  const slot = slots.find((candidate) => (
    !candidate.building &&
    candidate.snapshot?.epoch === epoch &&
    candidate.snapshot.records > 0
  ));
  if (!slot) throw new Error('PIR epoch is unavailable');
  return slot.worker.answer(epoch, query, pubParams);
}

export function pirEpochWindowMs() {
  return PIR_SNAPSHOT_MIN_REFRESH_MS;
}

export function pirServiceState() {
  return {
    started,
    publishedEpoch: publishedSlot?.snapshot?.epoch ?? null,
    retainedEpochs: slots
      .map((slot) => slot.snapshot?.epoch)
      .filter(Number.isSafeInteger),
    building: refreshPromise !== null,
    epochMs: PIR_SNAPSHOT_MIN_REFRESH_MS
  };
}
