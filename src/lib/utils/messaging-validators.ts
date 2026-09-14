import { CryptoUtils } from './crypto-utils';
import { PostQuantumSignature } from '../cryptography/signature';
import { hasPrototypePollutionKeys, isPlainObject } from '../sanitizers';
import { ML_KEM_1024_PUBLIC_KEY_BYTES } from '../../../shared/crypto-sizes.js';

export function isCanonicalBase64OfLength(value: unknown, expectedBytes: number): value is string {
  if (
    typeof value !== 'string' ||
    value.length !== 4 * Math.ceil(expectedBytes / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    return false;
  }
  let bytes: Uint8Array | null = null;
  try {
    bytes = CryptoUtils.Base64.base64ToUint8Array(value);
    return bytes.length === expectedBytes && CryptoUtils.Base64.arrayBufferToBase64(bytes) === value;
  } catch {
    return false;
  } finally {
    bytes?.fill(0);
  }
}

export function isValidKyberPublicKeyBase64(value: unknown): value is string {
  return isCanonicalBase64OfLength(value, ML_KEM_1024_PUBLIC_KEY_BYTES);
}

export function isValidDilithiumPublicKeyBase64(value: unknown): value is string {
  return isCanonicalBase64OfLength(value, PostQuantumSignature.sizes.publicKey);
}

export function isValidDilithiumSignatureBase64(value: unknown): value is string {
  return isCanonicalBase64OfLength(value, PostQuantumSignature.sizes.signature);
}

export function isValidX25519PublicKeyBase64(value: unknown): value is string {
  return isCanonicalBase64OfLength(value, 32);
}

// Return a sanitized copy of input hybrid keys, only keeping fields that validate
export function sanitizeHybridKeys<T extends Record<string, any> | undefined | null>(keys: T): Partial<T> {
  if (
    !isPlainObject(keys) ||
    hasPrototypePollutionKeys(keys) ||
    Object.keys(keys).sort().join(',') !== 'dilithiumPublicBase64,kyberPublicBase64,x25519PublicBase64'
  ) return {} as Partial<T>;
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
