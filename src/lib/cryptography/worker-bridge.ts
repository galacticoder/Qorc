/**
* Post-Quantum Worker Bridge
* Handles communication with the post-quantum crypto worker
*/

import { sleep } from '../runtime/sleep';
import { PostQuantumRandom } from './random';
import { hasExactKeys, isPlainObject, hasPrototypePollutionKeys } from '../sanitizers'
import {
  PQ_WORKER_MAX_RESTART_ATTEMPTS,
  ARGON2_MAX_QUEUED_OPERATIONS,
  EXPECTED_AUTH_TOKEN_BYTES,
  MAIN_WORKER_MAX_PENDING,
  SIGNING_WORKER_MAX_PENDING,
  WORKER_AEAD_MAX_AAD_BYTES,
  WORKER_AEAD_MAX_INPUT_BYTES,
  WORKER_READY_TIMEOUT_MS,
  WORKER_RECOVERY_COOLDOWN_MS,
  WORKER_STABILITY_WINDOW_MS,
  WORKER_BRIDGE_WAIT_FOR_WORKER_AUTHENTICATION_DELAY_MS,
  WORKER_BRIDGE_IS_WORKER_RESPONSE_FAILURE_MESSAGE_DATA_ID_LENGTH_MINIMUM,
  WORKER_BRIDGE_IS_WORKER_RESPONSE_SUCCESS_MESSAGE_DATA_ID_LENGTH_MINIMUM,
  WORKER_BRIDGE_IS_PPGENERATE_RESULT_RESULT_BLINDED_TOKENS_LENGTH_LIMIT,
  WORKER_BRIDGE_TOKEN_LENGTH_EXPECTED,
  WORKER_BRIDGE_TOKEN_TOKEN_SECRET_LENGTH_EXPECTED,
  WORKER_BRIDGE_TOKEN_BLINDING_FACTOR_LENGTH_EXPECTED,
  WORKER_BRIDGE_TOKEN_BLINDED_ELEMENT_LENGTH_EXPECTED,
  WORKER_BRIDGE_TOKEN_ID_LENGTH_MINIMUM,
  WORKER_BRIDGE_IS_PPUNBLIND_RESULT_RESULT_COMPLETED_TOKENS_LENGTH_LIMIT,
  WORKER_BRIDGE_TOKEN_UNBLINDED_TOKEN_LENGTH_EXPECTED,
  WORKER_BRIDGE_IS_OPAQUE_START_REG_RESULT_RESULT_BLINDED_ELEMENT_LENGTH_EXPECTED,
  WORKER_BRIDGE_IS_OPAQUE_START_REG_RESULT_RESULT_BLINDING_FACTOR_LENGTH_EXPECTED,
  WORKER_BRIDGE_IS_OPAQUE_FINISH_REG_RESULT_RESULT_ENVELOPE_LENGTH_EXPECTED,
  WORKER_BRIDGE_IS_OPAQUE_FINISH_REG_RESULT_RESULT_EXPORT_KEY_LENGTH_EXPECTED,
  WORKER_BRIDGE_IS_OPAQUE_FINISH_LOGIN_RESULT_RESULT_EXPORT_KEY_LENGTH_EXPECTED,
  WORKER_BRIDGE_IS_OPAQUE_FINISH_LOGIN_RESULT_RESULT_ERROR_LENGTH_MINIMUM,
  WORKER_BRIDGE_IS_ARGON2_HASH_RESULT_RESULT_HASH_LENGTH_MINIMUM,
  WORKER_BRIDGE_IS_ARGON2_HASH_RESULT_RESULT_HASH_LENGTH_LIMIT,
  WORKER_BRIDGE_IS_ARGON2_HASH_RESULT_RESULT_ENCODED_LENGTH_LIMIT,
  WORKER_BRIDGE_VALIDATE_WORKER_DATA_ERROR_LENGTH_LIMIT,
  WORKER_BRIDGE_AUTH_CHANNEL_BINDING_LENGTH_EXPECTED,
  WORKER_BRIDGE_TIMEOUT_MS_MINIMUM,
  WORKER_BRIDGE_KEY_LENGTH_EXPECTED,
  WORKER_RESTART_BASE_DELAY_MS,
  WORKER_RESTART_MAX_DELAY_MS,
} from '../constants';
import type { WorkerRequestMessage, Argon2HashResult } from '../types/crypto-types';
import { SignalType } from '../types/signal-types';
import { ACCOUNT_AUTH_PURPOSE, SERVER_ENTRY_PURPOSE } from '../config/audiences';
import {
  validateArgon2HashParams,
  validateArgon2VerifyParams,
  validateOpaqueLoginResponse,
  validateOpaquePassword,
  validateOpaqueRegistrationResponse,
  validateWorkerRequest,
} from './worker-request-validation';
import { wipeBinaryValues } from './wipe';

// @ts-ignore
import PQWorker from './post-quantum-worker?worker';
// @ts-ignore
import PQWorkerUrl from './post-quantum-worker?worker&url';
import {
  HASH_OUTPUT_BYTES,
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SECRET_KEY_BYTES,
  ML_KEM_1024_SHARED_SECRET_BYTES,
  POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES,
} from '../../../shared/crypto-sizes.js';
import { constantTimeBytesEqual } from '../../../shared/bytes.js';

function spawnPostQuantumWorker(): Worker {
  const trustedTypesAvailable = !!(window as any).trustedTypes;
  if (!trustedTypesAvailable) return new PQWorker();

  const workerPolicy = (window as any)._workerPolicy;
  if (!workerPolicy || typeof workerPolicy.createScriptURL !== 'function') {
    throw new PostQuantumWorkerInfrastructureError('Trusted Types worker policy is unavailable');
  }
  const workerSource = workerPolicy.createScriptURL(PQWorkerUrl);
  return new Worker(workerSource, { type: 'module' });
}

function authTokenHex(token: Uint8Array): string {
  return Array.from(token, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function waitForWorkerAuthentication(
  validate: () => void,
  state: () => { worker: Worker | null; token: Uint8Array | null; disabled: boolean },
  label: string,
): Promise<string> {
  const deadline = performance.now() + WORKER_READY_TIMEOUT_MS;
  while (true) {
    validate();
    const current = state();
    if (current.worker && current.token) return authTokenHex(current.token);
    if (current.disabled) throw new PostQuantumWorkerInfrastructureError(`Worker recovery cooling down (${label})`);
    if (performance.now() >= deadline) throw new PostQuantumWorkerInfrastructureError(`Worker recovery timed out (${label})`);
    await sleep(WORKER_BRIDGE_WAIT_FOR_WORKER_AUTHENTICATION_DELAY_MS);
  }
}

export class PostQuantumWorkerInfrastructureError extends Error {
  readonly code = 'PQ_WORKER_INFRASTRUCTURE';

  constructor(message: string) {
    super(message);
    this.name = 'PostQuantumWorkerInfrastructureError';
  }
}

export function isPostQuantumWorkerInfrastructureError(
  error: unknown
): error is PostQuantumWorkerInfrastructureError {
  return error instanceof PostQuantumWorkerInfrastructureError;
}

function workerInfrastructureError(message: string, cause?: unknown): PostQuantumWorkerInfrastructureError {
  if (cause instanceof PostQuantumWorkerInfrastructureError) return cause;
  const detail = cause instanceof Error && cause.message ? `: ${cause.message}` : '';
  return new PostQuantumWorkerInfrastructureError(`${message}${detail}`);
}

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
): data is { type: SignalType.AUTH_TOKEN_INIT; token: string; timestamp: number } => {
  if (data.type !== SignalType.AUTH_TOKEN_INIT) return false;
  if (typeof data.token !== 'string') return false;
  if (typeof data.timestamp !== 'number' || !Number.isFinite(data.timestamp)) return false;
  return true;
};

const isWorkerResponseFailureMessage = (data: Record<string, unknown>): data is { id: string; success: false; error: string } => {
  return (
    typeof data.id === 'string' &&
    data.id.length > 0 &&
    data.id.length <= WORKER_BRIDGE_IS_WORKER_RESPONSE_FAILURE_MESSAGE_DATA_ID_LENGTH_MINIMUM &&
    data.success === false &&
    typeof data.error === 'string'
  );
};

const isWorkerResponseSuccessMessage = (data: Record<string, unknown>): data is { id: string; success: true; result: unknown } => {
  return (
    typeof data.id === 'string' &&
    data.id.length > 0 &&
    data.id.length <= WORKER_BRIDGE_IS_WORKER_RESPONSE_SUCCESS_MESSAGE_DATA_ID_LENGTH_MINIMUM &&
    data.success === true &&
    Object.prototype.hasOwnProperty.call(data, 'result')
  );
};

const isKemKeyPairResult = (result: unknown): result is { publicKey: Uint8Array; secretKey: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['publicKey', 'secretKey'])
    && result.publicKey instanceof Uint8Array
    && result.publicKey.length === ML_KEM_1024_PUBLIC_KEY_BYTES
    && result.secretKey instanceof Uint8Array
    && result.secretKey.length === ML_KEM_1024_SECRET_KEY_BYTES;
};

const isKemEncapsulateResult = (result: unknown): result is { ciphertext: Uint8Array; sharedSecret: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['ciphertext', 'sharedSecret'])
    && result.ciphertext instanceof Uint8Array
    && result.ciphertext.length === ML_KEM_1024_CIPHERTEXT_BYTES
    && result.sharedSecret instanceof Uint8Array
    && result.sharedSecret.length === ML_KEM_1024_SHARED_SECRET_BYTES;
};

const isKemDecapsulateResult = (result: unknown): result is { sharedSecret: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['sharedSecret'])
    && result.sharedSecret instanceof Uint8Array
    && result.sharedSecret.length === ML_KEM_1024_SHARED_SECRET_BYTES;
};

const isSigKeyPairResult = (result: unknown): result is { publicKey: Uint8Array; secretKey: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['publicKey', 'secretKey'])
    && result.publicKey instanceof Uint8Array
    && result.publicKey.length === ML_DSA_87_PUBLIC_KEY_BYTES
    && result.secretKey instanceof Uint8Array
    && result.secretKey.length === ML_DSA_87_SECRET_KEY_BYTES;
};

const isSigSignResult = (result: unknown): result is { signature: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['signature'])
    && result.signature instanceof Uint8Array
    && result.signature.length === ML_DSA_87_SIGNATURE_BYTES;
};

const isSigVerifyResult = (result: unknown): result is { verified: boolean } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['verified']) && typeof result.verified === 'boolean';
};

const isPPGenerateResult = (result: unknown): result is { blindedTokens: Uint8Array[]; tokenSecrets: any[] } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!hasExactKeys(result, ['blindedTokens', 'tokenSecrets'])) return false;
  if (!Array.isArray(result.blindedTokens) || !Array.isArray(result.tokenSecrets)) return false;
  if (result.blindedTokens.length < 1 || result.blindedTokens.length > WORKER_BRIDGE_IS_PPGENERATE_RESULT_RESULT_BLINDED_TOKENS_LENGTH_LIMIT || result.blindedTokens.length !== result.tokenSecrets.length) return false;
  if (!result.blindedTokens.every((token) => token instanceof Uint8Array && token.length === WORKER_BRIDGE_TOKEN_LENGTH_EXPECTED)) return false;
  return result.tokenSecrets.every((token) =>
    isPlainObject(token)
    && !hasPrototypePollutionKeys(token)
    && token.tokenSecret instanceof Uint8Array
    && token.tokenSecret.length === WORKER_BRIDGE_TOKEN_TOKEN_SECRET_LENGTH_EXPECTED
    && token.blindingFactor instanceof Uint8Array
    && token.blindingFactor.length === WORKER_BRIDGE_TOKEN_BLINDING_FACTOR_LENGTH_EXPECTED
    && token.blindedElement instanceof Uint8Array
    && token.blindedElement.length === WORKER_BRIDGE_TOKEN_BLINDED_ELEMENT_LENGTH_EXPECTED
    && typeof token.id === 'string'
    && token.id.length <= WORKER_BRIDGE_TOKEN_ID_LENGTH_MINIMUM
    && (token.purpose === ACCOUNT_AUTH_PURPOSE || token.purpose === SERVER_ENTRY_PURPOSE)
    && Number.isSafeInteger(token.issuedAt)
    && token.used === false
    && token.pending === false
  );
};

const isPPUnblindResult = (result: unknown): result is { completedTokens: any[] } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!hasExactKeys(result, ['completedTokens']) || !Array.isArray(result.completedTokens)) return false;
  if (result.completedTokens.length < 1 || result.completedTokens.length > WORKER_BRIDGE_IS_PPUNBLIND_RESULT_RESULT_COMPLETED_TOKENS_LENGTH_LIMIT) return false;
  return result.completedTokens.every((token) =>
    isPlainObject(token)
    && !hasPrototypePollutionKeys(token)
    && token.tokenSecret instanceof Uint8Array
    && token.tokenSecret.length === WORKER_BRIDGE_TOKEN_TOKEN_SECRET_LENGTH_EXPECTED
    && token.unblindedToken instanceof Uint8Array
    && token.unblindedToken.length === WORKER_BRIDGE_TOKEN_UNBLINDED_TOKEN_LENGTH_EXPECTED
    && token.blindingFactor === undefined
    && token.blindedElement === undefined
    && typeof token.id === 'string'
    && token.id.length <= WORKER_BRIDGE_TOKEN_ID_LENGTH_MINIMUM
    && (token.purpose === ACCOUNT_AUTH_PURPOSE || token.purpose === SERVER_ENTRY_PURPOSE)
    && Number.isSafeInteger(token.issuedAt)
    && typeof token.used === 'boolean'
    && typeof token.pending === 'boolean'
  );
};

const isOpaqueStartRegResult = (result: unknown): result is { blindedElement: Uint8Array; blindingFactor: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['blindedElement', 'blindingFactor'])
    && result.blindedElement instanceof Uint8Array
    && result.blindedElement.length === WORKER_BRIDGE_IS_OPAQUE_START_REG_RESULT_RESULT_BLINDED_ELEMENT_LENGTH_EXPECTED
    && result.blindingFactor instanceof Uint8Array
    && result.blindingFactor.length === WORKER_BRIDGE_IS_OPAQUE_START_REG_RESULT_RESULT_BLINDING_FACTOR_LENGTH_EXPECTED;
};

const isOpaqueFinishRegResult = (result: unknown): result is { envelope: Uint8Array; exportKey: Uint8Array; authPublicKey: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['envelope', 'exportKey', 'authPublicKey'])
    && result.envelope instanceof Uint8Array
    && result.envelope.length === WORKER_BRIDGE_IS_OPAQUE_FINISH_REG_RESULT_RESULT_ENVELOPE_LENGTH_EXPECTED
    && result.exportKey instanceof Uint8Array
    && result.exportKey.length === WORKER_BRIDGE_IS_OPAQUE_FINISH_REG_RESULT_RESULT_EXPORT_KEY_LENGTH_EXPECTED
    && result.authPublicKey instanceof Uint8Array
    && result.authPublicKey.length === ML_DSA_87_PUBLIC_KEY_BYTES;
};

const isOpaqueStartLoginResult = (result: unknown): result is { blindedElement: Uint8Array; blindingFactor: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return isOpaqueStartRegResult(result);
};

const isOpaqueFinishLoginResult = (result: unknown): result is { success: boolean; exportKey?: Uint8Array; authMessage?: Uint8Array; error?: string } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (result.success === true) {
    return hasExactKeys(result, ['success', 'exportKey', 'authMessage'])
      && result.exportKey instanceof Uint8Array
      && result.exportKey.length === WORKER_BRIDGE_IS_OPAQUE_FINISH_LOGIN_RESULT_RESULT_EXPORT_KEY_LENGTH_EXPECTED
      && result.authMessage instanceof Uint8Array
      && result.authMessage.length === ML_DSA_87_SIGNATURE_BYTES;
  }
  return result.success === false
    && (hasExactKeys(result, ['success']) || (
      hasExactKeys(result, ['success', 'error'])
      && typeof result.error === 'string'
      && result.error.length <= WORKER_BRIDGE_IS_OPAQUE_FINISH_LOGIN_RESULT_RESULT_ERROR_LENGTH_MINIMUM
    ));
};

const isArgon2HashResult = (result: unknown): result is Argon2HashResult => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!hasExactKeys(result, ['hash', 'encoded'])) return false;
  if (!(result.hash instanceof Uint8Array) || result.hash.length < WORKER_BRIDGE_IS_ARGON2_HASH_RESULT_RESULT_HASH_LENGTH_MINIMUM || result.hash.length > WORKER_BRIDGE_IS_ARGON2_HASH_RESULT_RESULT_HASH_LENGTH_LIMIT) return false;
  if (typeof result.encoded !== 'string' || result.encoded.length === 0 || result.encoded.length > WORKER_BRIDGE_IS_ARGON2_HASH_RESULT_RESULT_ENCODED_LENGTH_LIMIT) return false;
  return true;
};

const isArgon2VerifyResult = (result: unknown): result is { verified: boolean } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['verified']) && typeof result.verified === 'boolean';
};

const isAeadEncryptResult = (result: unknown): result is { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['ciphertext', 'nonce', 'tag'])
    && result.ciphertext instanceof Uint8Array
    && result.ciphertext.length >= POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES
    && result.ciphertext.length <= WORKER_AEAD_MAX_INPUT_BYTES + POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES
    && result.nonce instanceof Uint8Array
    && result.nonce.length === POST_QUANTUM_AEAD_NONCE_BYTES
    && result.tag instanceof Uint8Array
    && result.tag.length === HASH_OUTPUT_BYTES;
};

const isAeadDecryptResult = (result: unknown): result is { plaintext: Uint8Array } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return hasExactKeys(result, ['plaintext'])
    && result.plaintext instanceof Uint8Array
    && result.plaintext.length <= WORKER_AEAD_MAX_INPUT_BYTES;
};

const validateWorkerResult = (expectedType: WorkerRequestMessage['type'], result: unknown): boolean => {
  switch (expectedType) {
    case 'kem.generateKeyPair':
      return isKemKeyPairResult(result);
    case 'kem.encapsulate':
      return isKemEncapsulateResult(result);
    case 'kem.decapsulate':
      return isKemDecapsulateResult(result);
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

function operationTimeoutMs(type: WorkerRequestMessage['type']): number {
  switch (type) {
    case 'argon2.hash':
    case 'argon2.verify':
      return 300_000;
    case 'pp.generateTokenBatch':
    case 'pp.unblindTokens':
    case 'aead.encrypt':
    case 'aead.decrypt':
      return 120_000;
    default:
      return 60_000;
  }
}

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
  }>();
  private authToken: Uint8Array | null = null;
  private restartAttempts = 0;
  private restarting = false;
  private disabled = false;
  private stabilityTimer: ReturnType<typeof setTimeout> | null = null;
  private ready: Promise<string> | null = null;
  private readyWaiters = 0;
  private recoveryAfter = 0;

  constructor(
    private readonly label: string,
    private readonly maxPending: number
  ) {}

  private validateWorker(): void {
    if (this.disabled && performance.now() >= this.recoveryAfter) {
      this.disabled = false;
      this.restartAttempts = 0;
    }
    if (this.worker || this.restarting || this.disabled) {
      return;
    }
    try {
      const worker = spawnPostQuantumWorker();

      worker.addEventListener('message', (event: MessageEvent<unknown>) => {
        if (this.worker !== worker) {
          if (isPlainObject(event.data)) wipeBinaryValues(event.data.result);
          return;
        }
        try {
          const data = event.data;
          if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
            return;
          }
          if (isWorkerAuthTokenMessage(data)) {
            const tokenBytes = parseAuthTokenHex(data.token);
            if (!tokenBytes) {
              console.error(`[WorkerChannel:${this.label}] Invalid auth token received from worker`);
              this.handleWorkerFailure(new PostQuantumWorkerInfrastructureError('Invalid worker auth token'));
              return;
            }
            this.authToken?.fill(0);
            this.authToken = tokenBytes;
            if (this.stabilityTimer) clearTimeout(this.stabilityTimer);
            this.stabilityTimer = setTimeout(() => {
              this.restartAttempts = 0;
              this.stabilityTimer = null;
            }, WORKER_STABILITY_WINDOW_MS);
            return;
          }
          if (isWorkerResponseFailureMessage(data)) {
            const pending = this.pending.get(data.id);
            if (!pending) return;
            clearTimeout(pending.timeoutId);
            this.pending.delete(data.id);
            const errorText = data.error.length > WORKER_BRIDGE_VALIDATE_WORKER_DATA_ERROR_LENGTH_LIMIT ? data.error.slice(0, 2000) : data.error;
            pending.reject(new Error(errorText));
            return;
          }
          if (!isWorkerResponseSuccessMessage(data)) {
            return;
          }
          const pending = this.pending.get(data.id);
          if (!pending) {
            wipeBinaryValues(data.result);
            return;
          }
          clearTimeout(pending.timeoutId);
          this.pending.delete(data.id);
          if (!validateWorkerResult(pending.expectedType, data.result)) {
            wipeBinaryValues(data.result);
            pending.reject(new PostQuantumWorkerInfrastructureError('Invalid worker response'));
            return;
          }
          pending.resolve(data.result);
        } catch (err) {
          console.error(`[WorkerChannel:${this.label}] Message handler error:`, err);
        }
      });

      worker.addEventListener('error', (error) => {
        if (this.worker !== worker) return;
        console.error(`[WorkerChannel:${this.label}] Worker script error event:`, error);
        this.handleWorkerFailure(error);
      });
      worker.addEventListener('messageerror', (error) => {
        if (this.worker !== worker) return;
        console.error(`[WorkerChannel:${this.label}] Worker message error event:`, error);
        this.handleWorkerFailure(error);
      });

      this.worker = worker;
    } catch (spawnError) {
      console.error(`[WorkerChannel:${this.label}] FATAL: Failed to spawn worker thread:`, spawnError);
      this.worker = null;
      if (!this.restarting && !this.disabled) {
        this.restarting = true;
        this.scheduleRestart();
      }
    }
  }

  private handleWorkerFailure(error: unknown): void {
    const failure = workerInfrastructureError(`Worker channel failed (${this.label})`, error);
    for (const [id, pending] of this.pending.entries()) {
      clearTimeout(pending.timeoutId);
      pending.reject(failure);
      this.pending.delete(id);
    }
    try { this.worker?.terminate(); } catch { }
    this.worker = null;
    this.authToken?.fill(0);
    this.authToken = null;
    if (this.stabilityTimer) {
      clearTimeout(this.stabilityTimer);
      this.stabilityTimer = null;
    }
    if (!this.restarting && !this.disabled) {
      this.restarting = true;
      this.scheduleRestart();
    }
  }

  private setPendingWithTimeout(
    id: string,
    resolve: (value: unknown) => void,
    reject: (reason: unknown) => void,
    expectedType: WorkerRequestMessage['type'],
    timeoutOverrideMs?: number
  ): void {
    if (this.pending.size >= this.maxPending) {
      throw new PostQuantumWorkerInfrastructureError(`Worker channel is at capacity (${this.label})`);
    }
    const timeoutMs = timeoutOverrideMs ?? operationTimeoutMs(expectedType);
    const timeoutId = setTimeout(() => {
      if (!this.pending.has(id)) return;
      this.handleWorkerFailure(new PostQuantumWorkerInfrastructureError(
        `Worker operation timed out after ${timeoutMs}ms (${expectedType})`
      ));
    }, timeoutMs);
    this.pending.set(id, { resolve, reject, expectedType, timeoutId });
  }

  private scheduleRestart(): void {
    if (this.restartAttempts >= PQ_WORKER_MAX_RESTART_ATTEMPTS) {
      console.error(`[WorkerChannel:${this.label}] Max restart attempts reached; channel cooling down`);
      this.restarting = false;
      this.disabled = true;
      this.recoveryAfter = performance.now() + WORKER_RECOVERY_COOLDOWN_MS;
      return;
    }
    const delay = Math.min(WORKER_RESTART_BASE_DELAY_MS * Math.pow(2, this.restartAttempts), WORKER_RESTART_MAX_DELAY_MS);
    this.restartAttempts += 1;
    setTimeout(() => {
      this.restarting = false;
      try {
        this.validateWorker();
      } catch (error) {
        console.error(`[WorkerChannel:${this.label}] Restart attempt failed:`, error);
      }
    }, delay);
  }

  private async getAuthToken(): Promise<string> {
    if (this.pending.size + this.readyWaiters >= this.maxPending) {
      throw new PostQuantumWorkerInfrastructureError(`Worker channel is at capacity (${this.label})`);
    }
    this.readyWaiters++;
    try {
      if (!this.ready) {
        const ready = waitForWorkerAuthentication(
          () => this.validateWorker(),
          () => ({ worker: this.worker, token: this.authToken, disabled: this.disabled }),
          this.label,
        ).catch(error => {
          if (this.worker && !this.authToken) this.handleWorkerFailure(error);
          throw error;
        });
        this.ready = ready;
        const clear = () => { if (this.ready === ready) this.ready = null; };
        void ready.then(clear, clear);
      }
      return await this.ready;
    } finally { this.readyWaiters--; }
  }

  // Dispatch one operation to channel's worker and await the validated result
  async request<T>(
    type: WorkerRequestMessage['type'],
    payload: Record<string, unknown>,
    expectedType: WorkerRequestMessage['type'],
    timeoutOverrideMs?: number
  ): Promise<T> {
    const id = PostQuantumRandom.randomUUID();
    const auth = await this.getAuthToken();
    const request = { id, type, ...payload, auth } as unknown as WorkerRequestMessage;
    validateWorkerRequest(request);
    return await new Promise<T>((resolve, reject) => {
      this.setPendingWithTimeout(id, resolve as (value: unknown) => void, reject, expectedType, timeoutOverrideMs);
      try {
        if (!this.worker || !this.authToken || auth !== authTokenHex(this.authToken)) {
          throw new PostQuantumWorkerInfrastructureError('Worker restarted before request dispatch');
        }
        this.worker.postMessage(request);
      } catch (error) {
        const entry = this.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        this.pending.delete(id);
        reject(workerInfrastructureError('Worker request dispatch failed', error));
      }
    });
  }

  terminateWhenIdle(): void {
    if (this.pending.size !== 0 || this.restarting || this.readyWaiters !== 0) return;
    try { this.worker?.terminate(); } catch { }
    this.worker = null;
    this.authToken?.fill(0);
    this.authToken = null;
    if (this.stabilityTimer) clearTimeout(this.stabilityTimer);
    this.stabilityTimer = null;
    this.restartAttempts = 0;
  }
}

export class PostQuantumWorker {
  private static readonly sigChannel = new WorkerChannel('signing', SIGNING_WORKER_MAX_PENDING);
  private static readonly argon2Channel = new WorkerChannel('argon2', 1);
  private static argon2QueueDepth = 0;
  private static argon2QueueTail: Promise<void> = Promise.resolve();

  private static worker: Worker | null = null;
  private static pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
    expectedType: WorkerRequestMessage['type'];
    timeoutId: ReturnType<typeof setTimeout>;
  }>();
  private static restartAttempts = 0;
  private static restarting = false;
  private static disabled = false;
  private static authToken: Uint8Array | null = null;
  private static stabilityTimer: ReturnType<typeof setTimeout> | null = null;
  private static ready: Promise<string> | null = null;
  private static readyWaiters = 0;
  private static recoveryAfter = 0;

  private static validateWorker(): void {
    if (PostQuantumWorker.disabled && performance.now() >= PostQuantumWorker.recoveryAfter) {
      PostQuantumWorker.disabled = false;
      PostQuantumWorker.restartAttempts = 0;
    }
    if (PostQuantumWorker.worker || PostQuantumWorker.restarting || PostQuantumWorker.disabled) {
      return;
    }

    try {
      const worker = spawnPostQuantumWorker();

      worker.addEventListener('message', (event: MessageEvent<unknown>) => {
        if (PostQuantumWorker.worker !== worker) {
          if (isPlainObject(event.data)) wipeBinaryValues(event.data.result);
          return;
        }
        try {
          const data = event.data;
          if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
            return;
          }

          if (isWorkerAuthTokenMessage(data)) {
            const tokenBytes = parseAuthTokenHex(data.token);
            if (!tokenBytes) {
              console.error('[PostQuantumWorker] Invalid auth token received from worker');
              PostQuantumWorker.handleWorkerFailure(
                new PostQuantumWorkerInfrastructureError('Invalid worker auth token')
              );
              return;
            }
            PostQuantumWorker.authToken?.fill(0);
            PostQuantumWorker.authToken = tokenBytes;
            if (PostQuantumWorker.stabilityTimer) clearTimeout(PostQuantumWorker.stabilityTimer);
            PostQuantumWorker.stabilityTimer = setTimeout(() => {
              PostQuantumWorker.restartAttempts = 0;
              PostQuantumWorker.stabilityTimer = null;
            }, WORKER_STABILITY_WINDOW_MS);
            return;
          }

          if (isWorkerResponseFailureMessage(data)) {
            const pending = PostQuantumWorker.pending.get(data.id);
            if (!pending) {
              return;
            }
            clearTimeout(pending.timeoutId);
            PostQuantumWorker.pending.delete(data.id);
            const errorText = data.error.length > WORKER_BRIDGE_VALIDATE_WORKER_DATA_ERROR_LENGTH_LIMIT ? data.error.slice(0, 2000) : data.error;
            pending.reject(new Error(errorText));
            return;
          }

          if (!isWorkerResponseSuccessMessage(data)) {
            return;
          }

          const pending = PostQuantumWorker.pending.get(data.id);
          if (!pending) {
            wipeBinaryValues(data.result);
            return;
          }
          clearTimeout(pending.timeoutId);
          PostQuantumWorker.pending.delete(data.id);

          if (!validateWorkerResult(pending.expectedType, data.result)) {
            wipeBinaryValues(data.result);
            pending.reject(new PostQuantumWorkerInfrastructureError('Invalid worker response'));
            return;
          }

          pending.resolve(data.result);
        } catch (err) {
          console.error('[PostQuantumWorker] Message handler error:', err);
          return;
        }
      });

      worker.addEventListener('error', (error) => {
        if (PostQuantumWorker.worker !== worker) return;
        console.error('[PostQuantumWorker] Worker script error event:', error);
        PostQuantumWorker.handleWorkerFailure(error);
      });

      worker.addEventListener('messageerror', (error) => {
        if (PostQuantumWorker.worker !== worker) return;
        console.error('[PostQuantumWorker] Worker message error event:', error);
        PostQuantumWorker.handleWorkerFailure(error);
      });

      PostQuantumWorker.worker = worker;
    } catch (spawnError) {
      console.error('[PostQuantumWorker] FATAL: Failed to spawn worker thread:', spawnError);
      PostQuantumWorker.worker = null;
      if (!PostQuantumWorker.restarting && !PostQuantumWorker.disabled) {
        PostQuantumWorker.restarting = true;
        PostQuantumWorker.scheduleRestart();
      }
    }
  }

  private static handleWorkerFailure(error: unknown): void {
    const failure = workerInfrastructureError('Post-quantum worker failed', error);
    for (const [id, pending] of PostQuantumWorker.pending.entries()) {
      clearTimeout(pending.timeoutId);
      pending.reject(failure);
      PostQuantumWorker.pending.delete(id);
    }
    try { PostQuantumWorker.worker?.terminate(); } catch { }
    PostQuantumWorker.worker = null;
    PostQuantumWorker.authToken?.fill(0);
    PostQuantumWorker.authToken = null;
    if (PostQuantumWorker.stabilityTimer) {
      clearTimeout(PostQuantumWorker.stabilityTimer);
      PostQuantumWorker.stabilityTimer = null;
    }
    if (!PostQuantumWorker.restarting && !PostQuantumWorker.disabled) {
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
    expectedType: WorkerRequestMessage['type'],
    timeoutOverrideMs?: number
  ): void {
    if (PostQuantumWorker.pending.size >= MAIN_WORKER_MAX_PENDING) {
      throw new PostQuantumWorkerInfrastructureError('Post-quantum worker is at capacity');
    }
    const timeoutMs = timeoutOverrideMs ?? operationTimeoutMs(expectedType);
    const timeoutId = setTimeout(() => {
      if (!PostQuantumWorker.pending.has(id)) return;
      PostQuantumWorker.handleWorkerFailure(
        new PostQuantumWorkerInfrastructureError(
          `Worker operation timed out after ${timeoutMs}ms (${expectedType})`
        )
      );
    }, timeoutMs);

    PostQuantumWorker.pending.set(id, { resolve, reject, expectedType, timeoutId });
  }

  private static postRequest(request: WorkerRequestMessage): void {
    validateWorkerRequest(request);
    if (!PostQuantumWorker.worker || !PostQuantumWorker.authToken || request.auth !== authTokenHex(PostQuantumWorker.authToken)) {
      throw new PostQuantumWorkerInfrastructureError('Worker restarted before request dispatch');
    }
    try {
      PostQuantumWorker.worker.postMessage(request);
    } catch (error) {
      throw workerInfrastructureError('Worker request dispatch failed', error);
    }
  }

  private static async runSerializedArgon2<T>(operation: () => Promise<T>): Promise<T> {
    if (PostQuantumWorker.argon2QueueDepth >= ARGON2_MAX_QUEUED_OPERATIONS) {
      throw new Error('Argon2id worker queue is at capacity');
    }
    PostQuantumWorker.argon2QueueDepth += 1;

    let release!: () => void;
    const turn = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previous = PostQuantumWorker.argon2QueueTail.catch(() => undefined);
    PostQuantumWorker.argon2QueueTail = previous.then(() => turn);
    await previous;

    try {
      return await operation();
    } finally {
      PostQuantumWorker.argon2QueueDepth -= 1;
      release();
      if (PostQuantumWorker.argon2QueueDepth === 0) {
        PostQuantumWorker.argon2Channel.terminateWhenIdle();
      }
    }
  }

  private static scheduleRestart(): void {
    if (PostQuantumWorker.restartAttempts >= PQ_WORKER_MAX_RESTART_ATTEMPTS) {
      console.error('[PostQuantum][Worker] Max restart attempts reached; worker cooling down');
      PostQuantumWorker.restarting = false;
      PostQuantumWorker.disabled = true;
      PostQuantumWorker.recoveryAfter = performance.now() + WORKER_RECOVERY_COOLDOWN_MS;
      return;
    }
    const delay = Math.min(WORKER_RESTART_BASE_DELAY_MS * Math.pow(2, PostQuantumWorker.restartAttempts), WORKER_RESTART_MAX_DELAY_MS);
    PostQuantumWorker.restartAttempts += 1;
    setTimeout(() => {
      PostQuantumWorker.restarting = false;
      try {
        PostQuantumWorker.validateWorker();
      } catch (error) {
        console.error('[PostQuantum][Worker] Restart attempt failed:', error);
      }
    }, delay);
  }

  private static async getAuthToken(): Promise<string> {
    if (PostQuantumWorker.pending.size + PostQuantumWorker.readyWaiters >= MAIN_WORKER_MAX_PENDING) {
      throw new PostQuantumWorkerInfrastructureError('Post-quantum worker is at capacity');
    }
    PostQuantumWorker.readyWaiters++;
    try {
      if (!PostQuantumWorker.ready) {
        const ready = waitForWorkerAuthentication(
          () => PostQuantumWorker.validateWorker(),
          () => ({ worker: PostQuantumWorker.worker, token: PostQuantumWorker.authToken, disabled: PostQuantumWorker.disabled }),
          'main',
        ).catch(error => {
          if (PostQuantumWorker.worker && !PostQuantumWorker.authToken) PostQuantumWorker.handleWorkerFailure(error);
          throw error;
        });
        PostQuantumWorker.ready = ready;
        const clear = () => { if (PostQuantumWorker.ready === ready) PostQuantumWorker.ready = null; };
        void ready.then(clear, clear);
      }
      return await PostQuantumWorker.ready;
    } finally { PostQuantumWorker.readyWaiters--; }
  }

  static async generateKemKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async kemEncapsulate(publicKey: Uint8Array): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {

    const id = PostQuantumRandom.randomUUID();
    const auth = await PostQuantumWorker.getAuthToken();
    const request: WorkerRequestMessage = {
      id,
      type: 'kem.encapsulate',
      publicKey,
      auth
    };

    return await new Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>((resolve, reject) => {
      PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
      try {
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async kemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {

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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
    return response.sharedSecret;
  }

  static async generateSigKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async sigSign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    const response = await PostQuantumWorker.sigChannel.request<{ signature: Uint8Array }>(
      'sig.sign',
      { message, secretKey },
      'sig.sign'
    );
    return response.signature;
  }

  static async sigVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    const response = await PostQuantumWorker.sigChannel.request<{ verified: boolean }>(
      'sig.verify',
      { message, publicKey, signature },
      'sig.verify'
    );
    return response.verified;
  }

  static async ppGenerateTokenBatch(count: number, purpose: string): Promise<{ blindedTokens: Uint8Array[]; tokenSecrets: any[] }> {

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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async ppUnblindTokens(tokenSecrets: any[], signedBlindedTokens: Uint8Array[], proof: Uint8Array, serverPublicKey: Uint8Array): Promise<{ completedTokens: any[] }> {

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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async opaqueStartRegistration(password: Uint8Array): Promise<{ blindedElement: Uint8Array; blindingFactor: Uint8Array }> {
    validateOpaquePassword(password);

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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async opaqueFinishRegistration(password: Uint8Array, blindingFactor: Uint8Array, serverResponse: any): Promise<{ envelope: Uint8Array; exportKey: Uint8Array; authPublicKey: Uint8Array }> {
    validateOpaquePassword(password);
    validateOpaqueRegistrationResponse(serverResponse);
    const boundedServerResponse = {
      evaluatedElement: serverResponse.evaluatedElement,
      serverNonce: serverResponse.serverNonce,
    };

    const id = PostQuantumRandom.randomUUID();
    const auth = await PostQuantumWorker.getAuthToken();
    const request: WorkerRequestMessage = {
      id,
      type: 'opaque.finishRegistration',
      passwordBytes: password,
      blindingFactor,
      serverResponse: boundedServerResponse,
      auth
    };

    return await new Promise((resolve, reject) => {
      PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
      try {
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async opaqueStartLogin(password: Uint8Array): Promise<{ blindedElement: Uint8Array; blindingFactor: Uint8Array }> {
    validateOpaquePassword(password);

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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async opaqueFinishLogin(
    password: Uint8Array,
    blindingFactor: Uint8Array,
    serverResponse: any,
    authChannelBinding: Uint8Array
  ): Promise<{ success: boolean; exportKey?: Uint8Array; authMessage?: Uint8Array; error?: string }> {
    validateOpaquePassword(password);
    validateOpaqueLoginResponse(serverResponse);
    if (!(authChannelBinding instanceof Uint8Array) || authChannelBinding.length !== WORKER_BRIDGE_AUTH_CHANNEL_BINDING_LENGTH_EXPECTED) {
      throw new Error('Invalid authentication channel binding');
    }
    const boundedServerResponse = {
      evaluatedElement: serverResponse.evaluatedElement,
      envelope: serverResponse.envelope,
      serverNonce: serverResponse.serverNonce,
      salt: serverResponse.salt,
    };

    const id = PostQuantumRandom.randomUUID();
    const auth = await PostQuantumWorker.getAuthToken();
    const request: WorkerRequestMessage = {
      id,
      type: 'opaque.finishLogin',
      passwordBytes: password,
      blindingFactor,
      serverResponse: boundedServerResponse,
      authChannelBinding,
      auth
    };

    return await new Promise((resolve, reject) => {
      PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
      try {
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
  }

  static async argon2Hash(params: unknown, timeoutMs?: number): Promise<Argon2HashResult> {
    validateArgon2HashParams(params);
    if (timeoutMs !== undefined && (
      !Number.isInteger(timeoutMs) || timeoutMs < WORKER_BRIDGE_TIMEOUT_MS_MINIMUM || timeoutMs > operationTimeoutMs('argon2.hash')
    )) throw new Error('Invalid Argon2id timeout');
    return await PostQuantumWorker.runSerializedArgon2(() => (
      PostQuantumWorker.argon2Channel.request<Argon2HashResult>(
        'argon2.hash',
        { params },
        'argon2.hash',
        timeoutMs
      )
    ));
  }

  static async argon2Verify(params: unknown, timeoutMs?: number): Promise<boolean> {
    validateArgon2VerifyParams(params);
    if (timeoutMs !== undefined && (
      !Number.isInteger(timeoutMs) || timeoutMs < WORKER_BRIDGE_TIMEOUT_MS_MINIMUM || timeoutMs > operationTimeoutMs('argon2.verify')
    )) throw new Error('Invalid Argon2id timeout');
    const response = await PostQuantumWorker.runSerializedArgon2(() => (
      PostQuantumWorker.argon2Channel.request<{ verified: boolean }>(
        'argon2.verify',
        { params },
        'argon2.verify',
        timeoutMs
      )
    ));
    return response.verified;
  }

  static async aeadEncrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array,
    explicitNonce?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array }> {
    if (!(plaintext instanceof Uint8Array) || plaintext.length > WORKER_AEAD_MAX_INPUT_BYTES) {
      throw new Error('Invalid AEAD plaintext');
    }
    if (!(key instanceof Uint8Array) || key.length !== WORKER_BRIDGE_KEY_LENGTH_EXPECTED) throw new Error('Invalid AEAD key');
    if (additionalData !== undefined && (
      !(additionalData instanceof Uint8Array) || additionalData.length > WORKER_AEAD_MAX_AAD_BYTES
    )) throw new Error('Invalid AEAD additional data');
    if (explicitNonce !== undefined && (
      !(explicitNonce instanceof Uint8Array) || explicitNonce.length !== POST_QUANTUM_AEAD_NONCE_BYTES
    )) throw new Error('Invalid AEAD nonce');

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

    const response = await new Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array }>((resolve, reject) => {
      PostQuantumWorker.setPendingWithTimeout(id, resolve, reject, request.type);
      try {
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
    if (
      response.ciphertext.length !== plaintext.length + POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES ||
      (explicitNonce && !constantTimeBytesEqual(response.nonce, explicitNonce))
    ) {
      wipeBinaryValues(response);
      throw new Error('Invalid AEAD worker result');
    }
    return response;
  }

  static async aeadDecrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    if (
      !(ciphertext instanceof Uint8Array) ||
      ciphertext.length < POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES ||
      ciphertext.length > WORKER_AEAD_MAX_INPUT_BYTES + POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES
    ) throw new Error('Invalid AEAD ciphertext');
    if (!(nonce instanceof Uint8Array) || nonce.length !== POST_QUANTUM_AEAD_NONCE_BYTES) throw new Error('Invalid AEAD nonce');
    if (!(tag instanceof Uint8Array) || tag.length !== HASH_OUTPUT_BYTES) throw new Error('Invalid AEAD tag');
    if (!(key instanceof Uint8Array) || key.length !== WORKER_BRIDGE_KEY_LENGTH_EXPECTED) throw new Error('Invalid AEAD key');
    if (additionalData !== undefined && (
      !(additionalData instanceof Uint8Array) || additionalData.length > WORKER_AEAD_MAX_AAD_BYTES
    )) throw new Error('Invalid AEAD additional data');

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
        PostQuantumWorker.postRequest(request);
      } catch (error) {
        const entry = PostQuantumWorker.pending.get(id);
        if (entry) clearTimeout(entry.timeoutId);
        PostQuantumWorker.pending.delete(id);
        reject(error);
      }
    });
    if (response.plaintext.length !== ciphertext.length - POST_QUANTUM_AEAD_CIPHERTEXT_OVERHEAD_BYTES) {
      response.plaintext.fill(0);
      throw new Error('Invalid AEAD worker result');
    }
    return response.plaintext;
  }
}
