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

const STATUS_OK = 0;

const MAX_FRAME_BYTES = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 120_000;
const BUILD_TIMEOUT_MS = 600_000;

export class PirWorkerClient {
  constructor(binaryPath) {
    if (typeof binaryPath !== 'string' || binaryPath.length === 0) {
      throw new Error('PIR worker binary path is required');
    }
    this.binaryPath = binaryPath;
    this.child = null;
    this.buffer = Buffer.alloc(0);
    this.pending = null;
    this.queue = Promise.resolve();
    this.loadedEpoch = null;
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
      const detail = signal ? `signal ${signal}` : `code ${code}`;
      const error = new Error(`PIR worker exited with ${detail}`);
      if (this.child === child) {
        this.child = null;
        this.loadedEpoch = null;
      }
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
    if (this.child === child) {
      this.child = null;
      this.loadedEpoch = null;
    }
    const pending = this.pending;
    this.pending = null;
    pending?.reject(error instanceof Error ? error : new Error(String(error)));
  }

  #consume(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32LE(0);
      if (length === 0 || length > MAX_FRAME_BYTES) {
        const pending = this.pending;
        this.pending = null;
        this.buffer = Buffer.alloc(0);
        pending?.reject(new Error('PIR worker sent an invalid frame'));
        return;
      }
      if (this.buffer.length < 4 + length) return;
      const frame = this.buffer.subarray(4, 4 + length);
      this.buffer = this.buffer.subarray(4 + length);
      const pending = this.pending;
      this.pending = null;
      if (!pending) continue;
      const status = frame[0];
      const payload = Buffer.from(frame.subarray(1));
      if (status === STATUS_OK) pending.resolve(payload);
      else pending.reject(new Error(`PIR worker: ${payload.toString('utf8')}`));
    }
  }

  #request(op, payload, timeoutMs) {
    const run = async () => {
      if (!this.child) throw new Error('PIR worker is not running');
      const frame = Buffer.allocUnsafe(5 + payload.length);
      frame.writeUInt32LE(payload.length + 1, 0);
      frame[4] = op;
      payload.copy(frame, 5);

      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          if (this.pending) {
            this.pending = null;
            reject(new Error('PIR worker timed out'));
          }
        }, timeoutMs);
        this.pending = {
          resolve: (value) => { clearTimeout(timer); resolve(value); },
          reject: (error) => { clearTimeout(timer); reject(error); }
        };
        this.child.stdin.write(frame, (error) => {
          if (error && this.pending) {
            this.pending = null;
            clearTimeout(timer);
            reject(error);
          }
        });
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

    const file = path.join(
      TEMP_DIRECTORY,
      `qor-pir-${process.pid}-${crypto.randomBytes(8).toString('hex')}.bin`
    );
    await fs.writeFile(file, Buffer.concat(records), { mode: 0o600 });
    try {
      const header = Buffer.allocUnsafe(12);
      header.writeUInt32LE(epoch >>> 0, 0);
      header.writeUInt32LE(records.length, 4);
      header.writeUInt32LE(entryBytes, 8);
      const payload = Buffer.concat([header, Buffer.from(file, 'utf8')]);
      const response = await this.#request(OP_BUILD, payload, BUILD_TIMEOUT_MS);
      this.loadedEpoch = response.readUInt32LE(0);
      return {
        epoch: this.loadedEpoch,
        rows: response.readUInt32LE(4),
        cols: response.readUInt32LE(8),
        entryBytes: response.readUInt32LE(12)
      };
    } finally {
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
    return this.#request(
      OP_ANSWER,
      Buffer.concat([header, query, pubParams]),
      REQUEST_TIMEOUT_MS
    );
  }

  async info() {
    const response = await this.#request(OP_INFO, Buffer.alloc(0), REQUEST_TIMEOUT_MS);
    const epoch = response.readUInt32LE(0);
    if (epoch === 0xFFFFFFFF) return { epoch: null };
    return {
      epoch,
      rows: response.readUInt32LE(4),
      cols: response.readUInt32LE(8),
      entryBytes: response.readUInt32LE(12)
    };
  }
}
