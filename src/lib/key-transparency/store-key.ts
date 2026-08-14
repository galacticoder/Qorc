import { sha3_512 } from '@noble/hashes/sha3.js';

export function keyTransparencyStoreKey(
  prefix: string,
  domain: string,
  accountScope: string,
  ...parts: readonly string[]
): string {
  const input = new TextEncoder().encode([domain, accountScope, ...parts].join('\0'));
  const digest = sha3_512(input);
  try {
    let value = '';
    for (const byte of digest.subarray(0, 32)) value += byte.toString(16).padStart(2, '0');
    return `${prefix}${value}`;
  } finally {
    input.fill(0);
    digest.fill(0);
  }
}
