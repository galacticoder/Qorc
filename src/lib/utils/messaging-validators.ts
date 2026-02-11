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

export function isValidBlindPublicKey(value: unknown): value is {
  kid: string;
  n: string;
  e: string;
  modulusLength: number;
  hash: string;
  saltLength: number;
  scheme: string;
} {
  if (!value || typeof value !== 'object') return false;
  const key = value as any;
  if (key.scheme !== 'RSABSSA-PSS' || key.hash !== 'SHA-256') return false;
  if (typeof key.kid !== 'string' || key.kid.length < 8) return false;
  if (typeof key.n !== 'string' || typeof key.e !== 'string') return false;
  if (!Number.isFinite(key.modulusLength) || key.modulusLength < 2048) return false;
  if (!Number.isFinite(key.saltLength) || key.saltLength < 16) return false;
  try {
    const nBytes = CryptoUtils.Base64.base64ToUint8Array(key.n);
    const eBytes = CryptoUtils.Base64.base64ToUint8Array(key.e);
    const expectedLen = Math.ceil(key.modulusLength / 8);
    if (nBytes.length !== expectedLen) return false;
    if (eBytes.length === 0 || eBytes.length > 8) return false;
    return true;
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

  // Preserve blind signature public key metadata
  if (isValidBlindPublicKey((keys as any).blindPublicKey)) {
    out.blindPublicKey = (keys as any).blindPublicKey;
  }

  // Preserve inboxId
  if (typeof (keys as any).inboxId === 'string') {
    out.inboxId = (keys as any).inboxId;
  }

  return out as Partial<T>;
}
