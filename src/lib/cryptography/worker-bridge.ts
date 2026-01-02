/**
 * Post-Quantum Worker Bridge
 * Handles communication with the post-quantum crypto worker
 */

import * as argon2 from 'argon2-wasm';
import { PostQuantumKEM } from './kem';
import { PostQuantumRandom } from './random';
import { isPlainObject, hasPrototypePollutionKeys } from '../sanitizers'
import { PQ_WORKER_MAX_RESTART_ATTEMPTS } from '../constants';
import type { WorkerRequestMessage, KemKeyPairResult, Argon2HashResult } from '../types/crypto-types';
import { SignalType } from '../types/signal-types';
import { EventType } from '../types/event-types';

const parseAuthTokenHex = (hex: unknown): Uint8Array | null => {
  if (typeof hex !== 'string') {
    return null;
  }

  const normalized = hex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
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

const validateWorkerResult = (expectedType: WorkerRequestMessage['type'], result: unknown): boolean => {
  switch (expectedType) {
    case 'kem.generateKeyPair':
      return isKemKeyPairResult(result);
    case 'kem.destroyKey':
      return isDestroyKeyResult(result);
    case 'argon2.hash':
      return isArgon2HashResult(result);
    case 'argon2.verify':
      return isArgon2VerifyResult(result);
    default:
      return false;
  }
};

export class PostQuantumWorker {
  private static worker: Worker | null = null;
  private static pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
    expectedType: WorkerRequestMessage['type'];
  }>();
  private static readonly trackedKeys = new Map<string, string>();
  private static restartAttempts = 0;
  private static readonly MAX_RESTART_ATTEMPTS = PQ_WORKER_MAX_RESTART_ATTEMPTS;
  private static restarting = false;
  private static authToken: Uint8Array | null = null;

  static supportsWorkers(): boolean {
    return typeof Worker !== 'undefined';
  }

  private static ensureWorker(): void {
    if (PostQuantumWorker.worker || typeof Worker === 'undefined') {
      return;
    }

    let workerUrl: URL;
    try {
      workerUrl = new URL('./post-quantum-worker.ts', (import.meta as any).url);
    } catch {
      const base = typeof window !== 'undefined' && typeof window.location?.href === 'string' ? window.location.href : '';
      if (!base) {
        throw new Error('Unable to resolve post-quantum worker URL');
      }
      workerUrl = new URL('./post-quantum-worker.ts', base);
    }

    const worker = new Worker(workerUrl, { type: 'module' });
    worker.addEventListener(EventType.MESSAGE, (event: MessageEvent<unknown>) => {
      try {
        const data = event.data;
        if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
          return;
        }

        if (isWorkerAuthTokenMessage(data)) {
          const tokenBytes = parseAuthTokenHex(data.token);
          if (!tokenBytes) {
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
        PostQuantumWorker.pending.delete(data.id);

        if (!validateWorkerResult(pending.expectedType, data.result)) {
          pending.reject(new Error('Invalid worker response'));
          return;
        }

        if (pending.expectedType === 'kem.generateKeyPair' && isKemKeyPairResult(data.result)) {
          PostQuantumWorker.trackedKeys.set(data.result.keyId, data.result.keyId);
        }
        pending.resolve(data.result);
      } catch {
        return;
      }
    });
    worker.addEventListener(SignalType.ERROR, (error) => {
      PostQuantumWorker.handleWorkerFailure(error);
    });
    worker.addEventListener('messageerror', (error) => {
      PostQuantumWorker.handleWorkerFailure(error);
    });

    PostQuantumWorker.worker = worker;
    PostQuantumWorker.restartAttempts = 0;
  }

  private static handleWorkerFailure(error: unknown): void {
    for (const [id, pending] of PostQuantumWorker.pending.entries()) {
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

  private static getAuthToken(): string {
    if (!PostQuantumWorker.authToken) {
      throw new Error('Worker auth token not initialized');
    }
    return Array.from(PostQuantumWorker.authToken, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  static async generateKemKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    if (!PostQuantumWorker.supportsWorkers()) {
      return PostQuantumKEM.generateKeyPair();
    }

    try {
      try {
        PostQuantumWorker.ensureWorker();
      } catch {
        return PostQuantumKEM.generateKeyPair();
      }
      if (!PostQuantumWorker.worker) {
        return PostQuantumKEM.generateKeyPair();
      }

      const id = PostQuantumRandom.randomUUID();
      const request: WorkerRequestMessage = { 
        id, 
        type: 'kem.generateKeyPair',
        auth: PostQuantumWorker.getAuthToken()
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.pending.set(id, { resolve, reject, expectedType: request.type });
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch {
      return PostQuantumKEM.generateKeyPair();
    }
  }

  static async destroyKey(keyId: string): Promise<void> {
    if (!PostQuantumWorker.worker || !keyId || !PostQuantumWorker.trackedKeys.has(keyId)) {
      return;
    }

    const id = PostQuantumRandom.randomUUID();
    const request: WorkerRequestMessage = { 
      id, 
      type: 'kem.destroyKey', 
      keyId,
      auth: PostQuantumWorker.getAuthToken()
    };

    PostQuantumWorker.pending.set(id, {
      resolve: () => {
        PostQuantumWorker.trackedKeys.delete(keyId);
      },
      reject: () => {
        PostQuantumWorker.trackedKeys.delete(keyId);
      },
      expectedType: request.type
    });

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
        expectedType: request.type
      });
    });
  }

  static async argon2Hash(params: any): Promise<Argon2HashResult> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const result = await argon2.hash(params);
      return { hash: result.hash, encoded: result.encoded };
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
         const result = await argon2.hash(params);
         return { hash: result.hash, encoded: result.encoded };
      }

      const id = PostQuantumRandom.randomUUID();
      const request: WorkerRequestMessage = {
        id,
        type: 'argon2.hash',
        params,
        auth: PostQuantumWorker.getAuthToken()
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.pending.set(id, { resolve, reject, expectedType: request.type });
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch {
      const result = await argon2.hash(params);
      return { hash: result.hash, encoded: result.encoded };
    }
  }

  static async argon2Verify(params: any): Promise<boolean> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const result = await argon2.verify(params);
      // @ts-ignore
      return result.verified === true;
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const result = await argon2.verify(params);
        // @ts-ignore
        return result.verified === true;
      }

      const id = PostQuantumRandom.randomUUID();
      const request: WorkerRequestMessage = {
        id,
        type: 'argon2.verify',
        params,
        auth: PostQuantumWorker.getAuthToken()
      };

      const response = await new Promise<{ verified: boolean }>((resolve, reject) => {
        PostQuantumWorker.pending.set(id, { resolve, reject, expectedType: request.type });
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
      return response.verified;
    } catch {
      const result = await argon2.verify(params);
      // @ts-ignore
      return result.verified === true;
    }
  }
}
