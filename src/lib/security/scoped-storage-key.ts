import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '../../../shared/bytes.js';

export function deriveScopedStorageKey(
  prefix: string,
  domain: string,
  accountScope: string,
  ...parts: readonly string[]
): string {
  const input = new TextEncoder().encode([domain, accountScope, ...parts].join('\0'));
  const digest = blake3(input, { dkLen: 32 });
  try {
    return `${prefix}${bytesToHex(digest)}`;
  } finally {
    input.fill(0);
    digest.fill(0);
  }
}
