import crypto from 'node:crypto';
import { Worker } from 'node:worker_threads';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
} from '../../shared/crypto-sizes.js';
import {
  PRIVATE_AUTH_ANONYMITY_SET_SIZE,
  PRIVATE_AUTH_OT_RECORD_BYTES,
  PRIVATE_AUTH_TRANSCRIPT_BYTES,
} from '../../shared/private-auth-protocol.js';
import {
  AUTH_CRYPTO_CANCEL_STATE_INDEX,
  AUTH_CRYPTO_OPERATION,
} from './auth-crypto-worker-protocol.js';
import {
  AUTH_OPERATION_CANCELLED_MESSAGE,
  AUTH_OPERATION_FAILED_MESSAGE,
  AUTH_SERVER_BUSY,
} from '../config/error-codes.js';
import { wipeBytes as wipe } from '../utils/wipe.js';
import { authConnectionClosedError } from '../authentication/auth-utils.js';

const MAX_QUEUED_JOBS = 2;
const JOB_TIMEOUT_MS = 120_000;

let worker = null;
let currentJob = null;
const queuedJobs = [];

function exactStandaloneBytes(value, expectedLength) {
  return value instanceof Uint8Array &&
    value.length === expectedLength &&
    value.byteOffset === 0 &&
    value.byteLength === value.buffer.byteLength;
}

function wipePayload(payload) {
  if (!payload || typeof payload !== 'object') return;
  for (const value of Object.values(payload)) wipe(value);
}

function wipeResult(result) {
  if (!result || typeof result !== 'object') return;
  wipe(result.ciphertexts);
  wipe(result.maskedRecords);
  wipe(result.evaluatedTokens);
  wipe(result.proof);
}

function removeAbortListener(job) {
  job?.signal?.removeEventListener('abort', job.onAbort);
}

function rejectJob(job, error) {
  if (!job) return;
  if (job.timer) clearTimeout(job.timer);
  removeAbortListener(job);
  wipePayload(job.payload);
  if (job.settled) return;
  job.settled = true;
  job.reject(error);
}

function failWorker(error) {
  const failedWorker = worker;
  worker = null;
  if (failedWorker) {
    failedWorker.removeAllListeners();
    void failedWorker.terminate().catch(() => undefined);
  }

  const failedCurrent = currentJob;
  currentJob = null;
  rejectJob(failedCurrent, error);
  while (queuedJobs.length > 0) rejectJob(queuedJobs.shift(), error);
}

function validateWorkerResponse(message, job) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) return null;
  if (message.id !== job.id) return null;
  if (message.success === false) {
    const keys = Object.keys(message).sort().join(',');
    if (keys !== 'error,id,success') return null;
    if (message.error === AUTH_OPERATION_FAILED_MESSAGE) return { jobError: true };
    if (job.cancelled && message.error === AUTH_OPERATION_CANCELLED_MESSAGE) {
      return { jobCancelled: true };
    }
    return null;
  }
  if (message.success !== true) return null;
  if (job.type === AUTH_CRYPTO_OPERATION.VERIFY_ANONYMITY_SET) {
    const keys = Object.keys(message).sort().join(',');
    return keys === 'id,matched,success' && typeof message.matched === 'boolean'
      ? { matched: message.matched }
      : null;
  }

  if (job.type === AUTH_CRYPTO_OPERATION.ISSUE_PRIVACY_PASS) {
    const keys = Object.keys(message).sort().join(',');
    if (
      keys !== 'evaluatedTokens,id,proof,success' ||
      !exactStandaloneBytes(message.evaluatedTokens, job.payload.count * 32) ||
      !exactStandaloneBytes(message.proof, 64)
    ) {
      wipe(message.evaluatedTokens);
      wipe(message.proof);
      return null;
    }
    return { evaluatedTokens: message.evaluatedTokens, proof: message.proof };
  }

  const keys = Object.keys(message).sort().join(',');
  if (
    keys !== 'ciphertexts,id,maskedRecords,success' ||
    !exactStandaloneBytes(message.ciphertexts, PRIVATE_AUTH_ANONYMITY_SET_SIZE * ML_KEM_1024_CIPHERTEXT_BYTES) ||
    !exactStandaloneBytes(message.maskedRecords, PRIVATE_AUTH_ANONYMITY_SET_SIZE * PRIVATE_AUTH_OT_RECORD_BYTES)
  ) {
    wipe(message.ciphertexts);
    wipe(message.maskedRecords);
    return null;
  }
  return { ciphertexts: message.ciphertexts, maskedRecords: message.maskedRecords };
}

function ensureWorker() {
  if (worker) return worker;
  const created = new Worker(new URL('./auth-crypto-worker.js', import.meta.url), {
    type: 'module',
    execArgv: [],
    resourceLimits: {
      maxOldGenerationSizeMb: 256,
      maxYoungGenerationSizeMb: 32,
      stackSizeMb: 8,
    },
  });
  created.unref();
  created.on('message', (message) => {
    const job = currentJob;
    if (!job) {
      wipeResult(message);
      return;
    }
    const result = validateWorkerResponse(message, job);
    if (!result) {
      wipeResult(message);
      failWorker(new Error('Invalid auth crypto worker response'));
      return;
    }
    clearTimeout(job.timer);
    removeAbortListener(job);
    currentJob = null;
    if (job.cancelled || result.jobCancelled) {
      wipePayload(job.payload);
      wipeResult(result);
    } else if (result.jobError) {
      wipePayload(job.payload);
      job.settled = true;
      job.reject(Object.assign(new Error('Auth crypto operation rejected'), {
        code: 'AUTH_CRYPTO_REJECTED',
      }));
    } else {
      job.settled = true;
      job.resolve(result);
    }
    dispatchNext();
    if (!currentJob) created.unref();
  });
  created.on('messageerror', () => {
    failWorker(new Error('Auth crypto worker message failure'));
  });
  created.on('error', (error) => {
    console.error('[AUTH] Auth crypto worker failed', {
      name: error?.name,
      code: error?.code,
      message: error?.message,
    });
    failWorker(new Error('Auth crypto worker failure'));
  });
  created.on('exit', (code) => {
    if (worker !== created) return;
    failWorker(new Error(`Auth crypto worker exited (${code})`));
  });
  worker = created;
  return created;
}

function dispatchNext() {
  if (currentJob || queuedJobs.length === 0) return;
  const job = queuedJobs.shift();
  let target;
  try {
    target = ensureWorker();
    target.ref();
    currentJob = job;
    job.timer = setTimeout(() => {
      if (currentJob !== job) return;
      failWorker(new Error('Auth crypto worker timed out'));
    }, JOB_TIMEOUT_MS);
    target.postMessage(
      { id: job.id, type: job.type, payload: job.payload, cancelState: job.cancelState },
      job.transferList
    );
  } catch {
    if (currentJob === job) currentJob = null;
    rejectJob(job, new Error('Auth crypto worker unavailable'));
    console.error('[AUTH] Auth crypto worker dispatch failed');
    dispatchNext();
  }
}

function enqueueJob(type, payload, transferList, signal) {
  if (signal?.aborted) {
    wipePayload(payload);
    return Promise.reject(authConnectionClosedError());
  }
  if (queuedJobs.length >= MAX_QUEUED_JOBS) {
    wipePayload(payload);
    return Promise.reject(Object.assign(new Error('Auth crypto worker queue is full'), {
      code: AUTH_SERVER_BUSY,
    }));
  }

  return new Promise((resolve, reject) => {
    const job = {
      id: crypto.randomUUID(),
      type,
      payload,
      transferList,
      resolve,
      reject,
      timer: null,
      settled: false,
      cancelled: false,
      signal,
      onAbort: null,
      cancelState: new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT)),
    };
    job.onAbort = () => {
      if (job.settled) return;
      if (currentJob === job) {
        job.cancelled = true;
        Atomics.store(job.cancelState, AUTH_CRYPTO_CANCEL_STATE_INDEX, 1);
        removeAbortListener(job);
        job.settled = true;
        job.reject(authConnectionClosedError());
        return;
      }
      const index = queuedJobs.indexOf(job);
      if (index >= 0) queuedJobs.splice(index, 1);
      rejectJob(job, authConnectionClosedError());
    };
    queuedJobs.push(job);
    signal?.addEventListener('abort', job.onAbort, { once: true });
    if (signal?.aborted) {
      job.onAbort();
      return;
    }
    dispatchNext();
  });
}

export function verifyAuthProofAcrossAnonymitySet(authPublicKeys, signature, transcript, signal) {
  if (
    !exactStandaloneBytes(authPublicKeys, PRIVATE_AUTH_ANONYMITY_SET_SIZE * ML_DSA_87_PUBLIC_KEY_BYTES) ||
    !exactStandaloneBytes(signature, ML_DSA_87_SIGNATURE_BYTES) ||
    !exactStandaloneBytes(transcript, PRIVATE_AUTH_TRANSCRIPT_BYTES)
  ) {
    throw new Error('Invalid anonymity-set verification buffers');
  }
  return enqueueJob(
    AUTH_CRYPTO_OPERATION.VERIFY_ANONYMITY_SET,
    { authPublicKeys, signature, transcript },
    [authPublicKeys.buffer, signature.buffer, transcript.buffer],
    signal
  );
}

export function encryptPrivateAuthOtRecords(clientPublicKeys, paddedRecords, signal) {
  if (
    !exactStandaloneBytes(clientPublicKeys, PRIVATE_AUTH_ANONYMITY_SET_SIZE * ML_KEM_1024_PUBLIC_KEY_BYTES) ||
    !exactStandaloneBytes(paddedRecords, PRIVATE_AUTH_ANONYMITY_SET_SIZE * PRIVATE_AUTH_OT_RECORD_BYTES)
  ) {
    throw new Error('Invalid private-auth OT buffers');
  }
  return enqueueJob(
    AUTH_CRYPTO_OPERATION.ENCRYPT_OT_RECORDS,
    { clientPublicKeys, paddedRecords },
    [clientPublicKeys.buffer, paddedRecords.buffer],
    signal
  );
}

export function evaluatePrivacyPassBatch(blindedTokens, count, secretKey, publicKey, signal) {
  if (
    !Number.isInteger(count) || count < 1 || count > 1000 ||
    !exactStandaloneBytes(blindedTokens, count * 32) ||
    !exactStandaloneBytes(secretKey, 32) ||
    !exactStandaloneBytes(publicKey, 32)
  ) {
    throw new Error('Invalid Privacy Pass worker buffers');
  }
  return enqueueJob(
    AUTH_CRYPTO_OPERATION.ISSUE_PRIVACY_PASS,
    { blindedTokens, count, secretKey, publicKey },
    [blindedTokens.buffer, secretKey.buffer, publicKey.buffer],
    signal
  );
}

export async function shutdownAuthCryptoWorker() {
  const activeWorker = worker;
  worker = null;
  if (activeWorker) activeWorker.removeAllListeners();

  const error = new Error('Auth crypto worker shut down');
  const activeJob = currentJob;
  currentJob = null;
  rejectJob(activeJob, error);
  while (queuedJobs.length > 0) rejectJob(queuedJobs.shift(), error);

  if (activeWorker) {
    try {
      await activeWorker.terminate();
    } catch {
    }
  }
}
