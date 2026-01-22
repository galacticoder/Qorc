import { CryptoUtils } from './crypto-utils';
import { PostQuantumSignature } from '../cryptography/signature';
import { PQ_KEM_PUBLIC_KEY_SIZE } from '../constants';

export function isValidKyberPublicKeyBase64(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    const normalized = value.trim();
    const bytes = CryptoUtils.Base64.base64ToUint8Array(normalized);
    if (bytes.length !== PQ_KEM_PUBLIC_KEY_SIZE) {
      console.warn(`[Validator] Kyber length mismatch. Expected ${PQ_KEM_PUBLIC_KEY_SIZE}, got ${bytes.length}`);
      return false;
    }
    return true;
  } catch (e) {
    console.warn('[Validator] Kyber decode failed:', e);
    return false;
  }
}

export function isValidDilithiumPublicKeyBase64(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const bytes = CryptoUtils.Base64.base64ToUint8Array(value);
    if (bytes.length !== PostQuantumSignature.sizes.publicKey) {
      console.warn(`[Validator] Dilithium length mismatch. Expected ${PostQuantumSignature.sizes.publicKey}, got ${bytes.length}`);
      return false;
    }
    return true;
  } catch (e) {
    console.warn('[Validator] Dilithium decode failed:', e);
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
