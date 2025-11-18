import { CryptoUtils } from './unified-crypto';
import { PostQuantumKEM, PostQuantumSignature } from './post-quantum-crypto';

export function isValidKyberPublicKeyBase64(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    const normalized = value.trim();
    const bytes = CryptoUtils.Base64.base64ToUint8Array(normalized);
    return bytes.length === PostQuantumKEM.sizes.publicKey;
  } catch {
    return false;
  }
}

export function isValidDilithiumPublicKeyBase64(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const bytes = CryptoUtils.Base64.base64ToUint8Array(value);
    return bytes.length === PostQuantumSignature.sizes.publicKey;
  } catch {
    return false;
  }
}

export function isValidX25519PublicKeyBase64(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const bytes = CryptoUtils.Base64.base64ToUint8Array(value);
    return bytes.length === 32;
  } catch {
    return false;
  }
}

// Return a sanitized copy of input hybrid keys, only keeping fields that validate
export function sanitizeHybridKeys<T extends Record<string, any> | undefined | null>(keys: T): Partial<T> {
  if (!keys || typeof keys !== 'object') return {} as Partial<T>;
  const out: Record<string, any> = {};
  
  if (isValidKyberPublicKeyBase64((keys as any).kyberPublicBase64)) {
    out.kyberPublicBase64 = (keys as any).kyberPublicBase64;
  }
  
  if (isValidDilithiumPublicKeyBase64((keys as any).dilithiumPublicBase64)) {
    out.dilithiumPublicBase64 = (keys as any).dilithiumPublicBase64;
  }
  
  if (isValidX25519PublicKeyBase64((keys as any).x25519PublicBase64)) {
    out.x25519PublicBase64 = (keys as any).x25519PublicBase64;
  }
  
  return out as Partial<T>;
}
