import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '../../../shared/bytes.js';
import { rememberScopedStorageContext } from './scoped-storage-context';

export function deriveScopedStorageKey(
  prefix: string,
  domain: string,
  accountScope: string,
  ...parts: readonly string[]
): string {
  const input = new TextEncoder().encode([domain, accountScope, ...parts].join('\0'));
  const digest = blake3(input, { dkLen: 32 });
  try {
    const key = `${prefix}${bytesToHex(digest)}`;
    rememberScopedStorageContext(key, { accountOwner: accountScope, domain, parts });
    return key;
  } finally {
    input.fill(0);
    digest.fill(0);
  }
}
