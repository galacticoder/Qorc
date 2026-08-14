import crypto from 'node:crypto';

export function randomDelay(minMs, maxMs) {
  const min = Math.max(0, Math.trunc(minMs));
  const max = Math.max(min, Math.trunc(maxMs));
  return crypto.randomInt(min, max + 1);
}
