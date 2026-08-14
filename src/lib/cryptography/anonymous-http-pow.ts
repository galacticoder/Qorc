import { Base64 } from './base64';
import { solvePowChallenge } from './proof-of-work';

export interface AnonymousHttpPow {
  powNonce: string;
  powSolution: string;
}

function encodePowSeedInput(
  domain: string,
  epoch: string | number,
  powNonce: string,
  parts: readonly string[],
): Uint8Array {
  return new TextEncoder().encode([
    domain,
    String(epoch),
    powNonce,
    ...parts,
  ].join('\0'));
}

export async function createAnonymousHttpPow(
  domain: string,
  epoch: string | number,
  parts: readonly string[],
  difficulty: number,
  abortSignal?: AbortSignal,
): Promise<AnonymousHttpPow> {
  if (!/^[a-z0-9-]{8,64}$/.test(domain)) throw new Error('Invalid proof-of-work domain');
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 28) {
    throw new Error('Invalid proof-of-work difficulty');
  }
  if (parts.some((part) => typeof part !== 'string' || part.includes('\0'))) {
    throw new Error('Invalid proof-of-work request binding');
  }

  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const powNonce = Base64.arrayBufferToBase64(nonceBytes);
  const seedInput = encodePowSeedInput(domain, epoch, powNonce, parts);
  let seed = new Uint8Array(0);
  try {
    seed = new Uint8Array(await crypto.subtle.digest('SHA-256', seedInput as BufferSource));
    const challengeSeed = seed.subarray(0, 16).slice();
    try {
      const powSolution = await solvePowChallenge({
        seed: Base64.arrayBufferToBase64(challengeSeed),
        difficulty,
      }, abortSignal);
      return { powNonce, powSolution };
    } finally {
      challengeSeed.fill(0);
    }
  } finally {
    nonceBytes.fill(0);
    seedInput.fill(0);
    seed.fill(0);
  }
}
