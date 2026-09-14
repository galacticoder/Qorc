import { RefObject } from "react";
import { blake3 } from '@noble/hashes/blake3.js';
import { storage } from '../tauri-bindings';
import { STORAGE_KEYS, STORAGE_KEY_DOMAINS } from '../database/storage-keys';
import { CryptoUtils } from './crypto-utils';
import { bytesToHex } from '../../../shared/bytes.js';

export const clearStringRef = (ref: RefObject<string>) => {
  ref.current = "";
};

/**
 * Compute a stable blind user ID
 */
export const computeBlindUserId = (username: string): string => {
  const normalized = (username || "").toLowerCase().trim();
  if (!normalized) return "";
  const hash = blake3(new TextEncoder().encode(normalized), { dkLen: 32 });
  return bytesToHex(hash);
};

export const computePrivateAuthStorageId = (username: string, serverScope: string): string => {
  const normalizedUsername = (username || '').toLowerCase().trim();
  const normalizedServer = (serverScope || '').trim();
  if (!normalizedUsername || !normalizedServer) throw new Error('Private auth storage scope unavailable');
  const input = new TextEncoder().encode(
    `${STORAGE_KEY_DOMAINS.PRIVATE_AUTH_SLOT}\0${normalizedServer}\0${normalizedUsername}`
  );
  const digest = blake3(input, { dkLen: 32 });
  try {
    return bytesToHex(digest);
  } finally {
    input.fill(0);
    digest.fill(0);
  }
};

// Safely decode a base64 string into Uint8Array, with length and format validation
export const safeDecodeB64 = (b64?: string): Uint8Array | null => {
  try {
    if (!b64 || typeof b64 !== 'string' || b64.length > 10000) return null;
    const bytes = CryptoUtils.Base64.base64ToUint8Array(b64);
    if (CryptoUtils.Base64.arrayBufferToBase64(bytes) !== b64) {
      bytes.fill(0);
      return null;
    }
    return bytes;
  } catch { return null; }
};

// Validate server key structure and lengths
export const validateServerKeys = (val: any): boolean => {
  if (!val || typeof val !== 'object' || Array.isArray(val)) return false;
  const prototype = Object.getPrototypeOf(val);
  if (prototype !== Object.prototype && prototype !== null) return false;
  if (Object.keys(val).sort().join(',') !== 'dilithiumPublicBase64,kyberPublicBase64,x25519PublicBase64') return false;

  const hasX = !!val.x25519PublicBase64;
  const hasK = !!val.kyberPublicBase64;
  const hasD = !!val.dilithiumPublicBase64;

  if (!hasX || !hasK || !hasD) {
    console.warn('[Validator] Missing server keys');
    return false;
  }

  const x = safeDecodeB64(val.x25519PublicBase64);
  const k = safeDecodeB64(val.kyberPublicBase64);
  const d = safeDecodeB64(val.dilithiumPublicBase64);

  try {
    if (!x || !k || !d) return false;
    return x.length === 32 && k.length === 1568 && d.length === 2592;
  } finally {
    x?.fill(0);
    k?.fill(0);
    d?.fill(0);
  }
};

type PinnedServerKeys = {
  kyberPublicBase64: string;
  dilithiumPublicBase64: string;
  x25519PublicBase64: string;
};

let cachedServerPin: PinnedServerKeys | null = null;
let serverPinLoaded = false;
let serverPinLoadPromise: Promise<PinnedServerKeys | null> | null = null;
let serverPinMutationTail: Promise<void> = Promise.resolve();

async function withServerPinMutation<T>(operation: () => Promise<T>): Promise<T> {
  const previous = serverPinMutationTail;
  let release!: () => void;
  serverPinMutationTail = new Promise<void>((resolve) => { release = resolve; });
  await previous;
  try {
    return await operation();
  } finally {
    release();
  }
}

function normalizeServerKeys(val: any): PinnedServerKeys {
  const normalized = {
    kyberPublicBase64: val?.kyberPublicBase64,
    dilithiumPublicBase64: val?.dilithiumPublicBase64,
    x25519PublicBase64: val?.x25519PublicBase64
  };
  if (!validateServerKeys(normalized)) throw new Error('Invalid server identity key material');
  return normalized;
}

function serverKeysEqual(left: PinnedServerKeys, right: PinnedServerKeys): boolean {
  return left.kyberPublicBase64 === right.kyberPublicBase64 &&
    left.dilithiumPublicBase64 === right.dilithiumPublicBase64 &&
    left.x25519PublicBase64 === right.x25519PublicBase64;
}

export const PinnedServer = {
  async load(): Promise<PinnedServerKeys | null> {
    if (serverPinLoadPromise) return serverPinLoadPromise;
    serverPinLoadPromise = withServerPinMutation(async () => {
      if (serverPinLoaded) return cachedServerPin ? { ...cachedServerPin } : null;
      const raw = await storage.get(STORAGE_KEYS.SERVER_PQ_PIN);
      if (raw === null) {
        cachedServerPin = null;
        serverPinLoaded = true;
        return null;
      }
      if (raw.length === 0) throw new Error('Pinned server identity record is invalid');
      if (raw.length > 10_000) throw new Error('Pinned server identity record is oversized');
      cachedServerPin = normalizeServerKeys(JSON.parse(raw));
      serverPinLoaded = true;
      return { ...cachedServerPin };
    });
    try {
      return await serverPinLoadPromise;
    } finally {
      serverPinLoadPromise = null;
    }
  },
  get(): PinnedServerKeys | null {
    return cachedServerPin ? { ...cachedServerPin } : null;
  },
  async establish(val: any, isCurrent: () => boolean): Promise<void> {
    const normalized = normalizeServerKeys(val);
    const serialized = JSON.stringify(normalized);
    await withServerPinMutation(async () => {
      const previousRaw = await storage.get(STORAGE_KEYS.SERVER_PQ_PIN);
      if (previousRaw !== null && typeof previousRaw !== 'string') {
        throw new Error('Pinned server identity record is invalid');
      }
      if (previousRaw === '') throw new Error('Pinned server identity record is invalid');
      if (typeof previousRaw === 'string' && previousRaw.length > 10_000) {
        throw new Error('Pinned server identity record is oversized');
      }
      const previousPin = previousRaw
        ? normalizeServerKeys(JSON.parse(previousRaw))
        : null;
      if (!isCurrent()) throw new Error('Server identity pin operation is no longer current');

      if (previousPin) {
        if (!serverKeysEqual(previousPin, normalized)) {
          throw new Error('Pinned server identity changed');
        }
        cachedServerPin = previousPin;
        serverPinLoaded = true;
        return;
      }

      if (!await storage.set(STORAGE_KEYS.SERVER_PQ_PIN, serialized)) {
        throw new Error('Failed to persist server identity pin');
      }
      const stored = await storage.get(STORAGE_KEYS.SERVER_PQ_PIN);
      if (stored !== serialized) throw new Error('Server identity pin verification failed');

      if (!isCurrent()) {
        const restored = previousRaw === null
          ? await storage.remove(STORAGE_KEYS.SERVER_PQ_PIN)
          : await storage.set(STORAGE_KEYS.SERVER_PQ_PIN, previousRaw);
        if (!restored) throw new Error('Stale server identity pin could not be rolled back');
        const restoredRaw = await storage.get(STORAGE_KEYS.SERVER_PQ_PIN);
        if (restoredRaw !== previousRaw) {
          throw new Error('Stale server identity pin rollback could not be verified');
        }
        cachedServerPin = previousPin;
        serverPinLoaded = true;
        throw new Error('Server identity pin operation is no longer current');
      }

      cachedServerPin = normalized;
      serverPinLoaded = true;
    });
  }
};
