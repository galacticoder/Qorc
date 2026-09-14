import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PRIVATE_AUTH_ANONYMITY_SET_SIZE,
  PRIVATE_AUTH_PIR_RECORD_BYTES,
} from '../../shared/private-auth-protocol.js';
import { PirWorkerClient } from '../pir/pir-worker-client.js';
import { decodeCanonicalBase64 } from '../utils/encoding.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  OPAQUE_ENVELOPE_BYTES,
  OPAQUE_SALT_BYTES,
} from '../../shared/crypto-sizes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { throwIfAuthConnectionClosed } from './auth-utils.js';
import { PRIVATE_AUTH_PIR_RECORD_MAGIC } from '../../shared/protocol-keys.js';

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_WORKER_PATH = path.resolve(
  moduleDir,
  '../../workers/ypir/target/release/qorc-pir-worker'
);
const RECORD_MAGIC = Buffer.from(PRIVATE_AUTH_PIR_RECORD_MAGIC, 'ascii');
const RECORD_ENVELOPE_OFFSET = RECORD_MAGIC.length;
const RECORD_SALT_OFFSET = RECORD_ENVELOPE_OFFSET + OPAQUE_ENVELOPE_BYTES;
const STORED_RECORD_KEYS = Object.freeze(['authPublicKey', 'envelope', 'salt']);

let worker = null;
let currentFingerprint = null;
let currentEpoch = null;
let refreshPromise = null;
let answerOperationTail = Promise.resolve();

export function privateAuthPirWorkerPath() {
  return process.env.QORC_PIR_WORKER_PATH || DEFAULT_WORKER_PATH;
}

function wipeRows(rows) {
  if (!Array.isArray(rows)) return;
  for (const row of rows) row?.fill?.(0);
}

function parseStoredRecord(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).sort().join(',') !== STORED_RECORD_KEYS.join(',')
  ) {
    throw new Error('Invalid private-auth record in database');
  }

  let envelope = null;
  let salt = null;
  let authPublicKey = null;
  try {
    envelope = decodeCanonicalBase64(value.envelope, OPAQUE_ENVELOPE_BYTES);
    salt = decodeCanonicalBase64(value.salt, OPAQUE_SALT_BYTES);
    authPublicKey = decodeCanonicalBase64(value.authPublicKey, ML_DSA_87_PUBLIC_KEY_BYTES);
    return { envelope, salt, authPublicKey };
  } catch (error) {
    envelope?.fill(0);
    salt?.fill(0);
    authPublicKey?.fill(0);
    throw error;
  }
}

export function createPrivateAuthPirSnapshot(records) {
  if (!Array.isArray(records) || records.length > PRIVATE_AUTH_ANONYMITY_SET_SIZE) {
    throw new Error('Invalid private-auth record set');
  }

  const slab = crypto.randomBytes(
    PRIVATE_AUTH_ANONYMITY_SET_SIZE * PRIVATE_AUTH_PIR_RECORD_BYTES
  );
  const rows = Array.from({ length: PRIVATE_AUTH_ANONYMITY_SET_SIZE }, (_, index) => (
    slab.subarray(
      index * PRIVATE_AUTH_PIR_RECORD_BYTES,
      (index + 1) * PRIVATE_AUTH_PIR_RECORD_BYTES
    )
  ));
  const seenSlots = new Uint8Array(PRIVATE_AUTH_ANONYMITY_SET_SIZE);
  const hash = crypto.createHash('sha256');
  hash.update(PROTOCOL_KEYS.PRIVATE_AUTH_PIR_SNAPSHOT);

  try {
    for (const databaseRow of records) {
      if (
        !databaseRow ||
        typeof databaseRow !== 'object' ||
        Array.isArray(databaseRow) ||
        Object.getPrototypeOf(databaseRow) !== Object.prototype ||
        Object.keys(databaseRow).sort().join(',') !== 'credential_index,opaqueRecord'
      ) {
        throw new Error('Invalid private-auth database row');
      }
      const slot = Number(databaseRow.credential_index);
      if (
        !Number.isInteger(slot) ||
        slot < 0 ||
        slot >= PRIVATE_AUTH_ANONYMITY_SET_SIZE ||
        seenSlots[slot] !== 0 ||
        typeof databaseRow.opaqueRecord !== 'string' ||
        Buffer.byteLength(databaseRow.opaqueRecord, 'utf8') > 4096
      ) {
        throw new Error('Invalid private-auth slot in database');
      }
      seenSlots[slot] = 1;

      let decoded = null;
      try {
        decoded = JSON.parse(databaseRow.opaqueRecord);
      } catch {
        throw new Error('Invalid private-auth record in database');
      }

      const parsed = parseStoredRecord(decoded);
      try {
        const row = rows[slot];
        RECORD_MAGIC.copy(row, 0);
        parsed.envelope.copy(row, RECORD_ENVELOPE_OFFSET);
        parsed.salt.copy(row, RECORD_SALT_OFFSET);

        const slotBytes = Buffer.allocUnsafe(4);
        slotBytes.writeUInt32BE(slot, 0);
        hash.update(slotBytes);
        hash.update(parsed.envelope);
        hash.update(parsed.salt);
        hash.update(parsed.authPublicKey);
        slotBytes.fill(0);
      } finally {
        parsed.envelope.fill(0);
        parsed.salt.fill(0);
        parsed.authPublicKey.fill(0);
      }
    }

    const digest = hash.digest();
    const rawEpoch = digest.readUInt32BE(0);
    return {
      rows,
      fingerprint: digest.toString('base64'),
      epoch: rawEpoch === 0xFFFF_FFFF ? 0xFFFF_FFFE : rawEpoch,
    };
  } catch (error) {
    wipeRows(rows);
    throw error;
  }
}

async function ensureWorkerStarted() {
  if (!worker) worker = new PirWorkerClient(privateAuthPirWorkerPath());
  await worker.start();
  return worker;
}

export async function ensurePrivateAuthPirSnapshot(records, signal) {
  throwIfAuthConnectionClosed(signal);
  const prepared = createPrivateAuthPirSnapshot(records);
  try {
    if (
      prepared.fingerprint === currentFingerprint &&
      worker?.loadedEpoch === currentEpoch
    ) {
      return currentEpoch;
    }

    if (refreshPromise) {
      await refreshPromise;
      if (
        prepared.fingerprint === currentFingerprint &&
        worker?.loadedEpoch === currentEpoch
      ) {
        return currentEpoch;
      }
    }

    refreshPromise = (async () => {
      const target = await ensureWorkerStarted();
      throwIfAuthConnectionClosed(signal);
      await target.build(
        prepared.epoch,
        prepared.rows,
        PRIVATE_AUTH_PIR_RECORD_BYTES
      );
      currentFingerprint = prepared.fingerprint;
      currentEpoch = prepared.epoch;
      return currentEpoch;
    })();
    try {
      return await refreshPromise;
    } catch (error) {
      currentFingerprint = null;
      currentEpoch = null;
      throw error;
    } finally {
      refreshPromise = null;
    }
  } finally {
    wipeRows(prepared.rows);
  }
}

export async function answerPrivateAuthPir(records, query, pubParams, signal) {
  const run = async () => {
    const epoch = await ensurePrivateAuthPirSnapshot(records, signal);
    throwIfAuthConnectionClosed(signal);
    const response = await worker.answer(epoch, query, pubParams);
    throwIfAuthConnectionClosed(signal);
    return response;
  };
  const operation = answerOperationTail.then(run, run);
  answerOperationTail = operation.then(() => undefined, () => undefined);
  return operation;
}

export async function startPrivateAuthPirService(records = []) {
  await ensureWorkerStarted();
  await ensurePrivateAuthPirSnapshot(records);
}

export async function stopPrivateAuthPirService() {
  const target = worker;
  worker = null;
  currentFingerprint = null;
  currentEpoch = null;
  refreshPromise = null;
  answerOperationTail = Promise.resolve();
  await target?.stop();
}
