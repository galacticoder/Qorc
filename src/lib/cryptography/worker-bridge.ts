/**
* Post-Quantum Worker Bridge
* Handles communication with the post-quantum crypto worker
*/

import { PostQuantumRandom } from './random';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers'
import { PQ_WORKER_MAX_RESTART_ATTEMPTS } from '../constants';
import type { WorkerRequestMessage, KemKeyPairResult, Argon2HashResult } from '../types/crypto-types';
import { SignalType } from '../types/signal-types';

// @ts-ignore
import PQWorker from './post-quantum-worker?worker';
// @ts-ignore
import PQWorkerUrl from './post-quantum-worker?worker&url';

const EXPECTED_AUTH_TOKEN_BYTES = 32;

const parseAuthTokenHex = (hex: unknown): Uint8Array | null => {
  if (typeof hex !== 'string') {
    return null;
  }

  const normalized = hex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
    return null;
  }

  if (normalized.length !== EXPECTED_AUTH_TOKEN_BYTES * 2) {
    return null;
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    const byte = parseInt(normalized.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) {
      return null;
    }
    bytes[i / 2] = byte;
  }
  return bytes;
};

const isWorkerAuthTokenMessage = (
  data: Record<string, unknown>
): data is { type: SignalType.AUTH_TOKEN_INIT | SignalType.AUTH_TOKEN_ROTATED; token: string; timestamp: number } => {
  if (data.type !== SignalType.AUTH_TOKEN_INIT && data.type !== SignalType.AUTH_TOKEN_ROTATED) return false;
  if (typeof data.token !== 'string') return false;
  if (typeof data.timestamp !== 'number' || !Number.isFinite(data.timestamp)) return false;
  return true;
};

const isWorkerResponseFailureMessage = (data: Record<string, unknown>): data is { id: string; success: false; error: string } => {
  return (
    typeof data.id === 'string' &&
    data.id.length > 0 &&
    data.id.length <= 256 &&
    data.success === false &&
    typeof data.error === 'string'
  );
};

const isWorkerResponseSuccessMessage = (data: Record<string, unknown>): data is { id: string; success: true; result: unknown } => {
  return (
    typeof data.id === 'string' &&
    data.id.length > 0 &&
    data.id.length <= 256 &&
    data.success === true &&
    Object.prototype.hasOwnProperty.call(data, 'result')
  );
};

const isKemKeyPairResult = (result: unknown): result is KemKeyPairResult => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!(result.publicKey instanceof Uint8Array)) return false;
  if (!(result.secretKey instanceof Uint8Array)) return false;
  if (typeof result.keyId !== 'string' || result.keyId.length === 0 || result.keyId.length > 256) return false;
  if (result.keyId === '__proto__' || result.keyId === 'prototype' || result.keyId === 'constructor') return false;
  return true;
};

const isKemEncapsulateResult = (result: unknown): result is { ciphertext: Uint8Array; sharedSecret: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).ciphertext instanceof Uint8Array)) return false;
  if (!((result as any).sharedSecret instanceof Uint8Array)) return false;
  return true;
};

const isKemDecapsulateResult = (result: unknown): result is { sharedSecret: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).sharedSecret instanceof Uint8Array)) return false;
  return true;
};

const isSigKeyPairResult = (result: unknown): result is { publicKey: Uint8Array; secretKey: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!(result.publicKey instanceof Uint8Array)) return false;
  if (!(result.secretKey instanceof Uint8Array)) return false;
  return true;
};

const isSigSignResult = (result: unknown): result is { signature: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!(result.signature instanceof Uint8Array)) return false;
  return true;
};

const isSigVerifyResult = (result: unknown): result is { verified: boolean } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return typeof result.verified === 'boolean';
};

const isPPGenerateResult = (result: unknown): result is { blindedTokens: Uint8Array[]; tokenSecrets: any[] } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!Array.isArray((result as any).blindedTokens)) return false;
  if (!Array.isArray((result as any).tokenSecrets)) return false;
  return true;
};

const isPPUnblindResult = (result: unknown): result is { completedTokens: any[] } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!Array.isArray((result as any).completedTokens)) return false;
  return true;
};

const isOpaqueStartRegResult = (result: unknown): result is { blindedElement: Uint8Array; clientPublicKey: Uint8Array; blindingFactor: Uint8Array; clientSecretKey: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).blindedElement instanceof Uint8Array)) return false;
  if (!((result as any).clientPublicKey instanceof Uint8Array)) return false;
  if (!((result as any).blindingFactor instanceof Uint8Array)) return false;
  if (!((result as any).clientSecretKey instanceof Uint8Array)) return false;
  return true;
};

const isOpaqueFinishRegResult = (result: unknown): result is { envelope: Uint8Array; exportKey: Uint8Array; maskedResponse: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).envelope instanceof Uint8Array)) return false;
  if (!((result as any).exportKey instanceof Uint8Array)) return false;
  if (!((result as any).maskedResponse instanceof Uint8Array)) return false;
  return true;
};

const isOpaqueStartLoginResult = (result: unknown): result is { blindedElement: Uint8Array; blindingFactor: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).blindedElement instanceof Uint8Array)) return false;
  if (!((result as any).blindingFactor instanceof Uint8Array)) return false;
  return true;
};

const isOpaqueFinishLoginResult = (result: unknown): result is { success: boolean; sessionKey?: Uint8Array; exportKey?: Uint8Array; authMessage?: Uint8Array; clientSecretKey?: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (typeof (result as any).success !== 'boolean') return false;
  return true;
};

const isOpaqueFinishOTLoginResult = (result: unknown): result is {
  success: boolean;
  sessionKey?: Uint8Array;
  exportKey?: Uint8Array;
  authMessage?: Uint8Array;
  clientSecretKey?: Uint8Array;
  serverNonce: Uint8Array;
  credentialId: string;
} => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (typeof (result as any).success !== 'boolean') return false;
  if (!(result as any).serverNonce || !((result as any).serverNonce instanceof Uint8Array)) return false;
  if (typeof (result as any).credentialId !== 'string') return false;
  return true;
};

const isOpaqueStartOTLoginResult = (result: unknown): result is { pubKeys: Uint8Array[]; blindedElement: Uint8Array; blindingFactor: Uint8Array; myPrivKey: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!Array.isArray((result as any).pubKeys)) return false;
  if (!((result as any).blindedElement instanceof Uint8Array)) return false;
  if (!((result as any).blindingFactor instanceof Uint8Array)) return false;
  if (!((result as any).myPrivKey instanceof Uint8Array)) return false;
  return true;
};

const isDestroyKeyResult = (result: unknown): result is { destroyed: true } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return (result as Record<string, unknown>).destroyed === true;
};

const isArgon2HashResult = (result: unknown): result is Argon2HashResult => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!(result.hash instanceof Uint8Array)) return false;
  if (typeof result.encoded !== 'string' || result.encoded.length === 0 || result.encoded.length > 8192) return false;
  return true;
};

const isArgon2VerifyResult = (result: unknown): result is { verified: boolean } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return typeof result.verified === 'boolean';
};

const isAeadEncryptResult = (result: unknown): result is { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).ciphertext instanceof Uint8Array)) return false;
  if (!((result as any).nonce instanceof Uint8Array)) return false;
  if (!((result as any).tag instanceof Uint8Array)) return false;
  return true;
};

const isAeadDecryptResult = (result: unknown): result is { plaintext: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!((result as any).plaintext instanceof Uint8Array)) return false;
  return true;
};

const validateWorkerResult = (expectedType: WorkerRequestMessage['type'], result: unknown): boolean => {
  switch (expectedType) {
    case 'kem.generateKeyPair':
      return isKemKeyPairResult(result);
    case 'kem.encapsulate':
      return isKemEncapsulateResult(result);
    case 'kem.decapsulate':
      return isKemDecapsulateResult(result);
    case 'kem.destroyKey':
      return isDestroyKeyResult(result);
    case 'sig.generateKeyPair':
      return isSigKeyPairResult(result);
    case 'sig.sign':
      return isSigSignResult(result);
    case 'sig.verify':
      return isSigVerifyResult(result);
    case 'pp.generateTokenBatch':
      return isPPGenerateResult(result);
    case 'pp.unblindTokens':
      return isPPUnblindResult(result);
    case 'opaque.startRegistration':
      return isOpaqueStartRegResult(result);
    case 'opaque.finishRegistration':
      return isOpaqueFinishRegResult(result);
    case 'opaque.startLogin':
      return isOpaqueStartLoginResult(result);
    case 'opaque.finishLogin':
      return isOpaqueFinishLoginResult(result);
    case 'opaque.startOTLogin':
      return isOpaqueStartOTLoginResult(result);
    case 'opaque.finishOTLogin':
      return isOpaqueFinishOTLoginResult(result);
    case 'argon2.hash':
      return isArgon2HashResult(result);
    case 'argon2.verify':
      return isArgon2VerifyResult(result);
    case 'aead.encrypt':
      return isAeadEncryptResult(result);
    case 'aead.decrypt':
      return isAeadDecryptResult(result);
    default:
      return false;
  }
};

const PENDING_OPERATION_TIMEOUT_MS = 30_000;
const PENDING_SWEEP_INTERVAL_MS = 60_000;

/**
 * One isolated post-quantum worker thread plus its dispatch state
 */
class WorkerChannel {
  private worker: Worker | null = null;
  private pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
    expectedType: WorkerRequestMessage['type'];
    timeoutId: ReturnType<typeof setTimeout>;
    createdAt: number;
  }>();
  private authToken: Uint8Array | null = null;
  private restartAttempts = 0;
  private restarting = false;
  private pendingSweepTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly label: string) {}

  private ensureWorker(): void {
    if (this.worker || typeof Worker === 'undefined' || this.restarting) {
      return;
    }
    try {
      let worker: Worker;
      if (typeof window !== 'undefined' && (window as any)._workerPolicy) {
        try {
          const workerSource = (window as any)._workerPolicy.createScriptURL(PQWorkerUrl);
          worker = new Worker(workerSource, { type: 'module' });
        } catch (e) {
          console.error(`[WorkerChannel:${this.label}] Trusted Types worker spawn failed, trying direct constructor:`, e);
          worker = new PQWorker();
        }
      } else {
        worker = new PQWorker();
      }

      worker.addEventListener('message', (event: MessageEvent<unknown>) => {
        try {
          const data = event.data;
          if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
            return;
          }
          if (isWorkerAuthTokenMessage(data)) {
            const tokenBytes = parseAuthTokenHex(data.token);
            if (!tokenBytes) {
              console.error(`[WorkerChannel:${this.label}] Invalid auth token received from worker`);
              return;
            }
            this.authToken = tokenBytes;
            return;
          }
          if (isWorkerResponseFailureMessage(data)) {
            const pending = this.pending.get(data.id);
            if (!pending) return;
            clearTimeout(pending.timeoutId);
            this.pending.delete(data.id);
            const errorText = data.error.length > 2000 ? data.error.slice(0, 2000) : data.error;
            pending.reject(new Error(errorText));
            return;
          }
          if (!isWorkerResponseSuccessMessage(data)) {
            return;
          }
          const pending = this.pending.get(data.id);
          if (!pending) return;
          clearTimeout(pending.timeoutId);
          this.pending.delete(data.id);
          if (!validateWorkerResult(pending.expectedType, data.result)) {
            pending.reject(new Error('Invalid worker response'));
            return;
          }
          pending.resolve(data.result);
        } catch (err) {
          console.error(`[WorkerChannel:${this.label}] Message handler error:`, err);
        }
      });

      worker.addEventListener('error', (error) => {
        console.error(`[WorkerChannel:${this.label}] Worker script error event:`, error);
        this.handleWorkerFailure(error);
      });
      worker.addEventListener('messageerror', (error) => {
        console.error(`[WorkerChannel:${this.label}] Worker message error event:`, error);
        this.handleWorkerFailure(error);
      });

      this.worker = worker;
      this.restartAttempts = 0;
    } catch (spawnError) {
      console.error(`[WorkerChannel:${this.label}] FATAL: Failed to spawn worker thread:`, spawnError);
      this.worker = null;
    }
  }

  private handleWorkerFailure(error: unknown): void {
    for (const [id, pending] of this.pending.entries()) {
      clearTimeout(pending.timeoutId);
      pending.reject(error);
      this.pending.delete(id);
    }
    this.worker = null;
    this.authToken = null;
    if (!this.restarting) {
      this.restarting = true;
      this.scheduleRestart();
    }
  }

  private setPendingWithTimeout(
    id: string,
    resolve: (value: unknown) => void,
    reject: (reason: unknown) => void,
    expectedType: WorkerRequestMessage['type']
  ): void {
    const timeoutId = setTimeout(() => {
      const entry = this.pending.get(id);
      if (entry) {
        this.pending.delete(id);
        entry.reject(new Error(`Worker operation timed out after ${PENDING_OPERATION_TIMEOUT_MS}ms (${expectedType})`));
      }
    }, PENDING_OPERATION_TIMEOUT_MS);
    this.pending.set(id, { resolve, reject, expectedType, timeoutId, createdAt: Date.now() });
    if (!this.pendingSweepTimer) {
      this.pendingSweepTimer = setInterval(() => this.sweepStalePending(), PENDING_SWEEP_INTERVAL_MS);
    }
  }

  private sweepStalePending(): void {
    const cutoff = Date.now() - (PENDING_OPERATION_TIMEOUT_MS * 2);
    for (const [id, entry] of this.pending.entries()) {
      if (entry.createdAt < cutoff) {
        clearTimeout(entry.timeoutId);
        this.pending.delete(id);
        try { entry.reject(new Error(`Worker operation swept as stale (${entry.expectedType})`)); } catch { }
      }
    }
    if (this.pending.size === 0 && this.pendingSweepTimer) {
      clearInterval(this.pendingSweepTimer);
      this.pendingSweepTimer = null;
    }
  }

  private scheduleRestart(): void {
    if (this.restartAttempts >= PQ_WORKER_MAX_RESTART_ATTEMPTS) {
      console.error(`[WorkerChannel:${this.label}] Max restart attempts reached; channel disabled`);
      this.restarting = false;
      return;
    }
    const delay = Math.min(1000 * Math.pow(2, this.restartAttempts), 30_000);
    this.restartAttempts += 1;
    setTimeout(() => {
      try { this.ensureWorker(); }
      catch (error) { console.error(`[WorkerChannel:${this.label}] Restart attempt failed:`, error); }
      finally { this.restarting = false; }
    }, delay);
  }

  private async getAuthToken(): Promise<string> {
    if (!this.authToken) {
      if (typeof Worker === 'undefined' || this.restarting) {
        throw new Error('Worker not available or restarting');
      }
      const start = Date.now();
      while (!this.authToken && Date.now() - start < 2000) {
        if (!this.worker) throw new Error('Worker instance lost during authentication');
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
    if (!this.authToken) throw new Error('Worker auth token not initialized');
    return Array.from(this.authToken, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Dispatch one operation to channel's worker and await the validated result
  async request<T>(
    type: WorkerRequestMessage['type'],
    payload: Record<string, unknown>,
    expectedType: WorkerRequestMessage['type']
  ): Promise<T> {
    this.ensureWorker();
    if (!this.worker) {
      throw new Error('Worker not available');
    }
    const id = PostQuantumRandom.randomUUID();
    const auth = await this.getAuthToken();
    const request = { id, type, ...payload, auth } as unknown as WorkerRequestMessage;
    return await new Promise<T>((resolve, reject) => {
      this.setPendingWithTimeout(id, resolve as (value: unknown) => void, reject, expectedType);
      try {
        this.worker!.postMessage(request);
      } catch (error) {
        const entry = this.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        this.pending.delete(id);
        reject(error);
      }
    });
  }
}

export class PostQuantumWorker {
  private static readonly sigChannel = new WorkerChannel('signing');

  private static worker: Worker | null = null;
  private static pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
    expectedType: WorkerRequestMessage['type'];
    timeoutId: ReturnType<typeof setTimeout>;
    createdAt: number;
  }>();
  private static readonly trackedKeys = new Map<string, string>();
  private static restartAttempts = 0;
  private static readonly MAX_RESTART_ATTEMPTS = PQ_WORKER_MAX_RESTART_ATTEMPTS;
  private static restarting = false;
  private static authToken: Uint8Array | null = null;
  private static pendingSweepTimer: ReturnType<typeof setInterval> | null = null;

  static supportsWorkers(): boolean {
    return typeof Worker !== 'undefined';
  }

  private static ensureWorker(): void {
    if (PostQuantumWorker.worker || typeof Worker === 'undefined' || PostQuantumWorker.restarting) {
      return;
    }

    try {
      let worker: Worker;

      if (typeof window !== 'undefined' && (window as any)._workerPolicy) {
        try {
          const workerSource = (window as any)._workerPolicy.createScriptURL(PQWorkerUrl);
          worker = new Worker(workerSource, { type: 'module' });
        } catch (e) {
          console.error('[PostQuantumWorker] Trusted Types worker spawn failed, trying direct constructor:', e);
          worker = new PQWorker();
        }
      } else {
        worker = new PQWorker();
      }

      worker.addEventListener('message', (event: MessageEvent<unknown>) => {
        try {
          const data = event.data;
          if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
            return;
          }

          if (isWorkerAuthTokenMessage(data)) {
            const tokenBytes = parseAuthTokenHex(data.token);
            if (!tokenBytes) {
              console.error('[PostQuantumWorker] Invalid auth token received from worker');
              return;
            }
            PostQuantumWorker.authToken = tokenBytes;
            return;
          }

          if (isWorkerResponseFailureMessage(data)) {
            const pending = PostQuantumWorker.pending.get(data.id);
            if (!pending) {
              return;
            }
            clearTimeout(pending.timeoutId);
            PostQuantumWorker.pending.delete(data.id);
            const errorText = data.error.length > 2000 ? data.error.slice(0, 2000) : data.error;
            pending.reject(new Error(errorText));
            return;
          }

          if (!isWorkerResponseSuccessMessage(data)) {
            return;
          }

          const pending = PostQuantumWorker.pending.get(data.id);
          if (!pending) {
            return;
          }
          clearTimeout(pending.timeoutId);
          PostQuantumWorker.pending.delete(data.id);

          if (!validateWorkerResult(pending.expectedType, data.result)) {
            pending.reject(new Error('Invalid worker response'));
            return;
          }

          if (pending.expectedType === 'kem.generateKeyPair' && isKemKeyPairResult(data.result)) {
            PostQuantumWorker.trackedKeys.set(data.result.keyId, data.result.keyId);
          }
          pending.resolve(data.result);
        } catch (err) {
          console.error('[PostQuantumWorker] Message handler error:', err);
          return;
        }
      });

      worker.addEventListener('error', (error) => {
        console.error('[PostQuantumWorker] Worker script error event:', error);
        PostQuantumWorker.handleWorkerFailure(error);
      });

      worker.addEventListener('messageerror', (error) => {
        console.error('[PostQuantumWorker] Worker message error event:', error);
        PostQuantumWorker.handleWorkerFailure(error);
      });

      PostQuantumWorker.worker = worker;
      PostQuantumWorker.restartAttempts = 0;
    } catch (spawnError) {
      console.error('[PostQuantumWorker] FATAL: Failed to spawn worker thread:', spawnError);
      PostQuantumWorker.worker = null;
    }
  }

  private static handleWorkerFailure(error: unknown): void {
    for (const [id, pending] of PostQuantumWorker.pending.entries()) {
      clearTimeout(pending.timeoutId);
      pending.reject(error);
      PostQuantumWorker.pending.delete(id);
    }
    PostQuantumWorker.worker = null;
    PostQuantumWorker.authToken = null;
    PostQuantumWorker.trackedKeys.clear();
    if (!PostQuantumWorker.restarting) {
      PostQuantumWorker.restarting = true;
      PostQuantumWorker.scheduleRestart();
    }
  }

  /**
   * Register a pending operation
   */
  private static setPendingWithTimeout(
    id: string,
    resolve: (value: unknown) => void,
    reject: (reason: unknown) => void,
    expectedType: WorkerRequestMessage['type']
  ): void {
    const timeoutId = setTimeout(() => {
      const entry = PostQuantumWorker.pending.get(id);
      if (entry) {
        PostQuantumWorker.pending.delete(id);
        entry.reject(new Error(`Worker operation timed out after ${PENDING_OPERATION_TIMEOUT_MS}ms (${expectedType})`));
      }
    }, PENDING_OPERATION_TIMEOUT_MS);

    PostQuantumWorker.pending.set(id, { resolve, reject, expectedType, timeoutId, createdAt: Date.now() });

    // Start periodic sweep if not already running
    if (!PostQuantumWorker.pendingSweepTimer) {
      PostQuantumWorker.pendingSweepTimer = setInterval(() => {
        PostQuantumWorker.sweepStalePending();
      }, PENDING_SWEEP_INTERVAL_MS);
    }
  }

  /**
   * reject and remove any entries older than 2x the timeout
   */
  private static sweepStalePending(): void {
    const cutoff = Date.now() - (PENDING_OPERATION_TIMEOUT_MS * 2);
    for (const [id, entry] of PostQuantumWorker.pending.entries()) {
      if (entry.createdAt < cutoff) {
        clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        try {
          entry.reject(new Error(`Worker operation swept as stale (${entry.expectedType})`));
        } catch { }
      }
    }
    // Stop sweep timer if no pending operations remain
    if (PostQuantumWorker.pending.size === 0 && PostQuantumWorker.pendingSweepTimer) {
      clearInterval(PostQuantumWorker.pendingSweepTimer);
      PostQuantumWorker.pendingSweepTimer = null;
    }
  }

  private static scheduleRestart(): void {
    if (PostQuantumWorker.restartAttempts >= PostQuantumWorker.MAX_RESTART_ATTEMPTS) {
      console.error('[PostQuantum][Worker] Max restart attempts reached; worker disabled');
      PostQuantumWorker.restarting = false;
      return;
    }
    const delay = Math.min(1000 * Math.pow(2, PostQuantumWorker.restartAttempts), 30_000);
    PostQuantumWorker.restartAttempts += 1;
    setTimeout(() => {
      try {
        PostQuantumWorker.ensureWorker();
      } catch (error) {
        console.error('[PostQuantum][Worker] Restart attempt failed:', error);
      } finally {
        PostQuantumWorker.restarting = false;
      }
    }, delay);
  }

  private static async getAuthToken(): Promise<string> {
    if (!PostQuantumWorker.authToken) {
      if (!PostQuantumWorker.supportsWorkers() || PostQuantumWorker.restarting) {
        throw new Error('Worker not available or restarting');
      }

      const start = Date.now();
      while (!PostQuantumWorker.authToken && Date.now() - start < 2000) {
        if (!PostQuantumWorker.worker) {
          throw new Error('Worker instance lost during authentication');
        }
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
    if (!PostQuantumWorker.authToken) {
      throw new Error('Worker auth token not initialized');
    }
    return Array.from(PostQuantumWorker.authToken, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  static async generateKemKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    if (!PostQuantumWorker.supportsWorkers()) {
      throw new Error('Web Workers not supported');
    }

    try {
      PostQuantumWorker.ensureWorker();

      if (!PostQuantumWorker.worker) {
        throw new Error('Worker not available');
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'kem.generateKeyPair',
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      throw err;
    }
  }

  static async kemEncapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      const result = ml_kem1024.encapsulate(publicKey);
      return { ciphertext: result.cipherText, sharedSecret: result.sharedSecret };
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
        const result = ml_kem1024.encapsulate(publicKey);
        return { ciphertext: result.cipherText, sharedSecret: result.sharedSecret };
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'kem.encapsulate',
        publicKey,
        auth
      };

      const response = await new Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
      return response;
    } catch {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      const result = ml_kem1024.encapsulate(publicKey);
      return { ciphertext: result.cipherText, sharedSecret: result.sharedSecret };
    }
  }

  static async kemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      return ml_kem1024.decapsulate(ciphertext, secretKey);
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
        return ml_kem1024.decapsulate(ciphertext, secretKey);
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'kem.decapsulate',
        ciphertext,
        secretKey,
        auth
      };

      const response = await new Promise<{ sharedSecret: Uint8Array }>((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
      return response.sharedSecret;
    } catch {
      const { ml_kem1024 } = await import('@noble/post-quantum/ml-kem.js');
      return ml_kem1024.decapsulate(ciphertext, secretKey);
    }
  }

  static async generateSigKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const seed = PostQuantumRandom.randomBytes(32);
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      const kp = await ml_dsa87.keygen(seed);
      return { publicKey: new Uint8Array(kp.publicKey), secretKey: new Uint8Array(kp.secretKey) };
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const seed = PostQuantumRandom.randomBytes(32);
        const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
        const kp = await ml_dsa87.keygen(seed);
        return { publicKey: new Uint8Array(kp.publicKey), secretKey: new Uint8Array(kp.secretKey) };
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'sig.generateKeyPair',
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch {
      const seed = PostQuantumRandom.randomBytes(32);
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      const kp = await ml_dsa87.keygen(seed);
      return { publicKey: new Uint8Array(kp.publicKey), secretKey: new Uint8Array(kp.secretKey) };
    }
  }

  static async sigSign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      return await ml_dsa87.sign(message, secretKey);
    }

    try {
      // Route to the dedicated signing channel
      const response = await PostQuantumWorker.sigChannel.request<{ signature: Uint8Array }>(
        'sig.sign',
        { message, secretKey },
        'sig.sign'
      );
      return response.signature;
    } catch {
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      return await ml_dsa87.sign(message, secretKey);
    }
  }

  static async sigVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      return await ml_dsa87.verify(signature, message, publicKey);
    }

    try {
      const response = await PostQuantumWorker.sigChannel.request<{ verified: boolean }>(
        'sig.verify',
        { message, publicKey, signature },
        'sig.verify'
      );
      return response.verified;
    } catch {
      const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
      return await ml_dsa87.verify(signature, message, publicKey);
    }
  }

  static async ppGenerateTokenBatch(count: number, purpose: string = 'account-auth'): Promise<{ blindedTokens: Uint8Array[]; tokenSecrets: any[] }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        throw new Error('Worker not available');
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'pp.generateTokenBatch',
        count,
        purpose,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { PrivacyPassClient } = await import('./privacy-pass-client');
      const client = new PrivacyPassClient(purpose);
      return client.generateTokenBatchLocal(count);
    }
  }

  static async ppUnblindTokens(tokenSecrets: any[], signedBlindedTokens: Uint8Array[], proof: Uint8Array, serverPublicKey: Uint8Array): Promise<{ completedTokens: any[] }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        throw new Error('Worker not available');
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'pp.unblindTokens',
        tokenSecrets,
        signedBlindedTokens,
        proof,
        serverPublicKey,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { PrivacyPassClient } = await import('./privacy-pass-client');
      const client = new PrivacyPassClient();
      const tokens = await client.unblindTokensLocal(tokenSecrets, signedBlindedTokens, proof, serverPublicKey);
      return { completedTokens: tokens };
    }
  }

  static async opaqueStartRegistration(password: Uint8Array): Promise<{ blindedElement: Uint8Array; clientPublicKey: Uint8Array; blindingFactor: Uint8Array; clientSecretKey: Uint8Array }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) throw new Error('Worker not available');

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'opaque.startRegistration',
        passwordBytes: password,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { OPAQUEClient } = await import('./opaque-client');
      const client = new OPAQUEClient();
      const result = await client.startRegistrationLocal(password);
      return result;
    }
  }

  static async opaqueFinishRegistration(password: Uint8Array, blindingFactor: Uint8Array, clientSecretKey: Uint8Array, serverResponse: any): Promise<{ envelope: Uint8Array; exportKey: Uint8Array; maskedResponse: Uint8Array }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) throw new Error('Worker not available');

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'opaque.finishRegistration',
        passwordBytes: password,
        blindingFactor,
        clientSecretKey,
        serverResponse,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { OPAQUEClient } = await import('./opaque-client');
      const client = new OPAQUEClient();
      return client.finishRegistrationLocal(password, serverResponse, blindingFactor, clientSecretKey);
    }
  }

  static async opaqueStartLogin(password: Uint8Array): Promise<{ blindedElement: Uint8Array; blindingFactor: Uint8Array }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) throw new Error('Worker not available');

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'opaque.startLogin',
        passwordBytes: password,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { OPAQUEClient } = await import('./opaque-client');
      const client = new OPAQUEClient();
      const result = await client.startLoginLocal(password);
      return result;
    }
  }

  static async opaqueFinishLogin(password: Uint8Array, blindingFactor: Uint8Array, serverResponse: any): Promise<{ success: boolean; sessionKey?: Uint8Array; exportKey?: Uint8Array; authMessage?: Uint8Array; clientSecretKey?: Uint8Array }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) throw new Error('Worker not available');

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'opaque.finishLogin',
        passwordBytes: password,
        blindingFactor,
        serverResponse,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { OPAQUEClient } = await import('./opaque-client');
      const client = new OPAQUEClient();
      return client.finishLoginLocal(password, serverResponse, blindingFactor);
    }
  }

  static async opaqueStartOTLogin(password: Uint8Array, shardSize: number, myIndex: number): Promise<{ pubKeys: Uint8Array[]; blindedElement: Uint8Array; blindingFactor: Uint8Array; myPrivKey: Uint8Array }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) throw new Error('Worker not available');

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'opaque.startOTLogin',
        passwordBytes: password,
        shardSize,
        myIndex,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { OPAQUEClient } = await import('./opaque-client');
      const client = new OPAQUEClient();
      return client.startOTLoginLocalFallback(password, shardSize, myIndex);
    }
  }

  static async opaqueFinishOTLogin(
    password: Uint8Array,
    blindingFactor: Uint8Array,
    myPrivKey: Uint8Array,
    otRecords: { ct: Uint8Array; masked: Uint8Array }[],
    myIndex: number,
    evaluatedElement: Uint8Array,
    serverNonce: Uint8Array
  ): Promise<{
    success: boolean;
    sessionKey?: Uint8Array;
    exportKey?: Uint8Array;
    authMessage?: Uint8Array;
    clientSecretKey?: Uint8Array;
    serverNonce: Uint8Array;
    credentialId: string;
  }> {
    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) throw new Error('Worker not available');

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'opaque.finishOTLogin',
        passwordBytes: password,
        blindingFactor,
        myPrivKey,
        otRecords,
        myIndex,
        evaluatedElement,
        serverNonce,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch (err) {
      const { OPAQUEClient } = await import('./opaque-client');
      const client = new OPAQUEClient();
      return client.finishOTLoginLocalFallback(password, blindingFactor, myPrivKey, otRecords, myIndex, evaluatedElement, serverNonce);
    }
  }

  static async destroyKey(keyId: string): Promise<void> {
    if (!PostQuantumWorker.worker || !keyId || !PostQuantumWorker.trackedKeys.has(keyId)) {
      return;
    }

    const id = PostQuantumRandom.randomUUID();
    const auth = await PostQuantumWorker.getAuthToken();
    const request: WorkerRequestMessage = {
      id,
      type: 'kem.destroyKey',
      keyId,
      auth
    };

    try {
      PostQuantumWorker.worker.postMessage(request);
    } catch (error) {
      PostQuantumWorker.pending.delete(id);
      PostQuantumWorker.trackedKeys.delete(keyId);
      throw error;
    }
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        PostQuantumWorker.pending.delete(id);
        PostQuantumWorker.trackedKeys.delete(keyId);
        resolve();
      }, 5000);

      PostQuantumWorker.pending.set(id, {
        resolve: () => {
          clearTimeout(timeout);
          PostQuantumWorker.trackedKeys.delete(keyId);
          resolve();
        },
        reject: () => {
          clearTimeout(timeout);
          PostQuantumWorker.trackedKeys.delete(keyId);
          resolve();
        },
        expectedType: request.type,
        timeoutId: timeout,
        createdAt: Date.now()
      });
    });
  }

  static async argon2Hash(params: any): Promise<Argon2HashResult> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const argon2 = await import('argon2-wasm');
      const result = await argon2.hash(params);
      return { hash: result.hash, encoded: result.encoded };
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const argon2 = await import('argon2-wasm');
        const result = await argon2.hash(params);
        return { hash: result.hash, encoded: result.encoded };
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'argon2.hash',
        params,
        auth
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch {
      const argon2 = await import('argon2-wasm');
      const result = await argon2.hash(params);
      return { hash: result.hash, encoded: result.encoded };
    }
  }

  static async argon2Verify(params: any): Promise<boolean> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const argon2 = await import('argon2-wasm');
      const result = await argon2.verify(params);
      // @ts-ignore
      return result.verified === true;
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const argon2 = await import('argon2-wasm');
        const result = await argon2.verify(params);
        // @ts-ignore
        return result.verified === true;
      }

      const id = PostQuantumRandom.randomUUID();
      const auth = await PostQuantumWorker.getAuthToken();
      const request: WorkerRequestMessage = {
        id,
        type: 'argon2.verify',
        params,
        auth
      };

      const response = await new Promise<{ verified: boolean }>((resolve, reject) => {
        PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          const entry = PostQuantumWorker.pending.get(id);
          if (entry) clearTimeout(entry.timeoutId);
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
      return response.verified;
    } catch {
      const argon2 = await import('argon2-wasm');
      const result = await argon2.verify(params);
      // @ts-ignore
      return result.verified === true;
    }
  }

  static async aeadEncrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array,
    explicitNonce?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array }> {
    PostQuantumWorker.ensureWorker();
    if (!PostQuantumWorker.worker) {
      throw new Error('Worker not available for AEAD');
    }

    const id = PostQuantumRandom.randomUUID();
    const auth = await PostQuantumWorker.getAuthToken();
    const request: WorkerRequestMessage = {
      id,
      type: 'aead.encrypt',
      plaintext,
      key,
      additionalData,
      explicitNonce,
      auth
    };

    return await new Promise((resolve, reject) => {
      PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
      try {
        PostQuantumWorker.worker!.postMessage(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async aeadDecrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    PostQuantumWorker.ensureWorker();
    if (!PostQuantumWorker.worker) {
      throw new Error('Worker not available for AEAD');
    }

    const id = PostQuantumRandom.randomUUID();
    const auth = await PostQuantumWorker.getAuthToken();
    const request: WorkerRequestMessage = {
      id,
      type: 'aead.decrypt',
      ciphertext,
      nonce,
      tag,
      key,
      additionalData,
      auth
    };

    const response = await new Promise<{ plaintext: Uint8Array }>((resolve, reject) => {
      PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
      try {
        PostQuantumWorker.worker!.postMessage(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
    return response.plaintext;
  }
}
