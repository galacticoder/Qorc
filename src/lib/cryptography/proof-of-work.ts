/**
 * Client-side proof of work solver for the adaptive auth throttle
 */

import { Base64 } from './base64';
import { authPow } from '../tauri-bindings';

export interface PowChallenge {
  seed?: string;
  difficulty?: number;
}

const MAX_DIFFICULTY_BITS = 28;
const MAX_SOLVE_MS = 60_000;
const NATIVE_BATCH_ITERATIONS = 0x40000;

// Solve a PoW challenge
export async function solvePowChallenge(
  challenge: PowChallenge | null | undefined,
  abortSignal?: AbortSignal
): Promise<string> {
  const throwIfAborted = () => {
    if (!abortSignal?.aborted) return;
    const error = new Error('Proof-of-work cancelled');
    error.name = 'AbortError';
    throw error;
  };
  throwIfAborted();
  const difficulty = challenge?.difficulty ?? 0;
  if (!challenge || !challenge.seed || difficulty <= 0) return '';
  if (!Number.isInteger(difficulty) || difficulty > MAX_DIFFICULTY_BITS) {
    throw new Error('Invalid proof-of-work difficulty');
  }

  const seed = Base64.base64ToUint8Array(challenge.seed);
  if (seed.length !== 16 || Base64.arrayBufferToBase64(seed) !== challenge.seed) {
    seed.fill(0);
    throw new Error('Invalid proof-of-work seed');
  }
  const counter = new Uint8Array(8);
  crypto.getRandomValues(counter);
  let nextNonce = Base64.arrayBufferToBase64(counter);

  const started = Date.now();
  let lastProgressLog = started;

  try {
    for (;;) {
      throwIfAborted();
      const batch = await authPow.solveBatch(
        challenge.seed,
        difficulty,
        nextNonce,
        NATIVE_BATCH_ITERATIONS
      );
      if (batch.solution) {
        return batch.solution;
      }
      nextNonce = batch.nextNonce;

      const elapsed = Date.now() - started;
      if (elapsed > MAX_SOLVE_MS) {
        throw new Error('Proof-of-work timed out');
      }
      if (elapsed - (lastProgressLog - started) >= 10_000) {
        lastProgressLog = Date.now();
      }
    }
  } finally {
    seed.fill(0);
    counter.fill(0);
    nextNonce = '';
  }
}
