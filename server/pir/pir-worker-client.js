import { spawn } from 'node:child_process';
import { access, constants } from 'node:fs/promises';
import { once } from 'node:events';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { INVALID_PIR_EPOCH_MESSAGE } from '../config/error-codes.js';
import { TEMP_DIRECTORY } from '../config/infrastructure.js';

const OP_BUILD = 1;
const OP_ANSWER = 2;
const OP_INFO = 3;
const OP_ANSWER_BATCH = 4;

const STATUS_OK = 0;

const MAX_FRAME_BYTES = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 120_000;
const BUILD_TIMEOUT_MS = 600_000;

export class PirWorkerClient {
  constructor(binaryPath, {
    requestTimeoutMs = REQUEST_TIMEOUT_MS,
    buildTimeoutMs = BUILD_TIMEOUT_MS,
  } = {}) {
    if (typeof binaryPath !== 'string' || binaryPath.length === 0) {
      throw new Error('PIR worker binary path is required');
    }
    this.binaryPath = binaryPath;
    this.child = null;
    this.buffer = Buffer.alloc(0);
    this.pending = null;
    this.queue = Promise.resolve();
    this.loadedEpoch = null;
    this.requestTimeoutMs = Math.min(REQUEST_TIMEOUT_MS, Math.max(10, Number(requestTimeoutMs) || REQUEST_TIMEOUT_MS));
    this.buildTimeoutMs = Math.min(BUILD_TIMEOUT_MS, Math.max(10, Number(buildTimeoutMs) || BUILD_TIMEOUT_MS));
  }

  async start() {
    if (this.child) return;
    
    await access(this.binaryPath, constants.X_OK);

    this.buffer = Buffer.alloc(0);
    const child = spawn(this.binaryPath, [], {
      stdio: ['pipe', 'pipe', 'inherit'],
      windowsHide: true
    });
    
    child.on('error', (error) => this.#fail(error, child));
    child.stdin.on('error', (error) => this.#fail(error, child));
    child.stdout.on('data', (chunk) => this.#consume(chunk));
    child.once('exit', (code, signal) => {
      if (this.child !== child) return;
      const detail = signal ? `signal ${signal}` : `code ${code}`;
      const error = new Error(`PIR worker exited with ${detail}`);
      this.child = null;
      this.loadedEpoch = null;
      this.buffer.fill(0);
      this.buffer = Buffer.alloc(0);
      if (this.pending) {
        const pending = this.pending;
        this.pending = null;
        pending.reject(error);
      }
    });
    this.child = child;
  }

  async stop() {
    const child = this.child;
    if (!child) return;
    this.child = null;
    this.loadedEpoch = null;
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
    const pending = this.pending;
    this.pending = null;
    pending?.reject(new Error('PIR worker stopped'));
    const exited = once(child, 'exit').then(() => true, () => true);
    child.stdin.end();
    const stopped = await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(resolve, 2000)).then(() => false)
    ]);
    if (!stopped) {
      child.kill('SIGKILL');
      await Promise.race([
        exited,
        new Promise((resolve) => setTimeout(resolve, 2000))
      ]);
    }
  }

  async restart() {
    await this.stop();
    await this.start();
  }

  #fail(error, child = this.child) {
    if (!child || this.child !== child) return;
    this.child = null;
    this.loadedEpoch = null;
    this.buffer.fill(0);
    this.buffer = Buffer.alloc(0);
    const pending = this.pending;
    this.pending = null;
    pending?.reject(error instanceof Error ? error : new Error(String(error)));
    try { child.kill('SIGKILL'); } catch { }
  }

  #consume(chunk) {
    const previous = this.buffer;
    const incoming = Buffer.from(chunk);
    this.buffer = Buffer.concat([previous, incoming]);
    previous.fill(0);
    incoming.fill(0);
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32LE(0);
      if (length === 0 || length > MAX_FRAME_BYTES) {
        this.#fail(new Error('PIR worker sent an invalid frame'));
        return;
      }
      if (this.buffer.length < 4 + length) return;
      const consumed = this.buffer;
      const status = consumed[4];
      const payload = Buffer.from(consumed.subarray(5, 4 + length));
      this.buffer = Buffer.from(consumed.subarray(4 + length));
      consumed.fill(0);
      const pending = this.pending;
      this.pending = null;
      if (!pending) {
        payload.fill(0);
        continue;
      }
      if (status === STATUS_OK) pending.resolve(payload);
      else {
        const message = payload.toString('utf8');
        payload.fill(0);
        pending.reject(new Error(`PIR worker: ${message}`));
      }
    }
  }

  #request(op, payload, timeoutMs) {
    const run = async () => {
      if (!this.child) throw new Error('PIR worker is not running');
      if (!Buffer.isBuffer(payload) || payload.length + 1 > MAX_FRAME_BYTES) {
        throw new Error('PIR worker request is too large');
      }
      const child = this.child;
      const frame = Buffer.allocUnsafe(5 + payload.length);
      frame.writeUInt32LE(payload.length + 1, 0);
      frame[4] = op;
      payload.copy(frame, 5);

      return await new Promise((resolve, reject) => {
        let pending;
        const timer = setTimeout(() => {
          if (this.pending === pending) {
            this.#fail(new Error('PIR worker timed out'), child);
          }
        }, timeoutMs);
        pending = {
          resolve: (value) => { clearTimeout(timer); resolve(value); },
          reject: (error) => { clearTimeout(timer); reject(error); }
        };
        this.pending = pending;
        try {
          child.stdin.write(frame, (error) => {
            frame.fill(0);
            if (error && this.pending === pending) this.#fail(error, child);
          });
        } catch (error) {
          frame.fill(0);
          this.#fail(error, child);
        }
      });
    };
    const result = this.queue.then(run, run);
    this.queue = result.then(() => { }, () => { });
    return result;
  }

  // Rebuilds the database for one epoch from records in spool order
  async build(epoch, records, entryBytes) {
    if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error(INVALID_PIR_EPOCH_MESSAGE);
    if (!Array.isArray(records) || records.length === 0) throw new Error('No PIR records');
    for (const record of records) {
      if (!Buffer.isBuffer(record) || record.length !== entryBytes) {
        throw new Error('PIR records must all be the fixed entry size');
      }
    }

    const suffix = crypto.randomBytes(16);
    let file;
    try {
      file = path.join(
        TEMP_DIRECTORY,
        `qorc-pir-${process.pid}-${suffix.toString('hex')}.bin`
      );
    } finally {
      suffix.fill(0);
    }
    const recordBytes = Buffer.concat(records);
    try {
      await fs.writeFile(file, recordBytes, { mode: 0o600, flag: 'wx' });
      const header = Buffer.allocUnsafe(12);
      header.writeUInt32LE(epoch >>> 0, 0);
      header.writeUInt32LE(records.length, 4);
      header.writeUInt32LE(entryBytes, 8);
      const payload = Buffer.concat([header, Buffer.from(file, 'utf8')]);
      header.fill(0);
      try {
        const response = await this.#request(OP_BUILD, payload, this.buildTimeoutMs);
        try {
          this.loadedEpoch = response.readUInt32LE(0);
          return {
            epoch: this.loadedEpoch,
            rows: response.readUInt32LE(4),
            cols: response.readUInt32LE(8),
            entryBytes: response.readUInt32LE(12)
          };
        } finally {
          response.fill(0);
        }
      } finally {
        payload.fill(0);
      }
    } finally {
      recordBytes.fill(0);
      await fs.rm(file, { force: true });
    }
  }

  async answer(epoch, query, pubParams) {
    if (!Buffer.isBuffer(query) || !Buffer.isBuffer(pubParams)) {
      throw new Error('Invalid PIR query');
    }
    const header = Buffer.allocUnsafe(8);
    header.writeUInt32LE(epoch >>> 0, 0);
    header.writeUInt32LE(query.length, 4);
    const payload = Buffer.concat([header, query, pubParams]);
    header.fill(0);
    try {
      return await this.#request(OP_ANSWER, payload, this.requestTimeoutMs);
    } finally {
      payload.fill(0);
    }
  }

  async answerBatch(epoch, queryBatch, pubParams) {
    if (!Buffer.isBuffer(queryBatch) || !Buffer.isBuffer(pubParams)) {
      throw new Error('Invalid PIR batch query');
    }
    const header = Buffer.allocUnsafe(8);
    header.writeUInt32LE(epoch >>> 0, 0);
    header.writeUInt32LE(queryBatch.length, 4);
    const payload = Buffer.concat([header, queryBatch, pubParams]);
    header.fill(0);
    try {
      return await this.#request(OP_ANSWER_BATCH, payload, this.requestTimeoutMs);
    } finally {
      payload.fill(0);
    }
  }

  async info() {
    const response = await this.#request(OP_INFO, Buffer.alloc(0), this.requestTimeoutMs);
    try {
      const epoch = response.readUInt32LE(0);
      if (epoch === 0xFFFFFFFF) return { epoch: null };
      return {
        epoch,
        rows: response.readUInt32LE(4),
        cols: response.readUInt32LE(8),
        entryBytes: response.readUInt32LE(12)
      };
    } finally {
      response.fill(0);
    }
  }
}
