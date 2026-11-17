import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '../../../shared/bytes.js';
import { PinnedServer, safeDecodeB64 } from '../utils/auth-utils';

export interface SavedServerIdentity {
  readonly fingerprint: string;
  readonly keyFingerprints: readonly { algorithm: string; purpose: string; fingerprint: string }[];
}

export async function readSavedServerIdentity(url: string): Promise<SavedServerIdentity | null> {
  const pin = await PinnedServer.inspect(url);
  if (!pin) return null;

  const encoded = JSON.stringify({
    kyberPublicBase64: pin.kyberPublicBase64,
    dilithiumPublicBase64: pin.dilithiumPublicBase64,
    x25519PublicBase64: pin.x25519PublicBase64,
  });
  const keyFingerprints = [
    { algorithm: 'ML-DSA-87', purpose: 'Signing key', key: pin.dilithiumPublicBase64 },
    { algorithm: 'ML-KEM-1024', purpose: 'Post-quantum key agreement', key: pin.kyberPublicBase64 },
    { algorithm: 'X25519', purpose: 'Classical key agreement', key: pin.x25519PublicBase64 },
  ].map(({ algorithm, purpose, key }) => {
    const bytes = safeDecodeB64(key);
    if (!bytes) throw new Error('Saved server identity is invalid');
    try { return { algorithm, purpose, fingerprint: bytesToHex(blake3(bytes)) }; }
    finally { bytes.fill(0); }
  });
  return { fingerprint: bytesToHex(blake3(new TextEncoder().encode(encoded))), keyFingerprints };
}
