import { RefObject } from "react";
import { CryptoUtils } from "../utils/crypto-utils";
import { PostQuantumUtils } from "../utils/pq-utils";
import { syncEncryptedStorage } from "../database/encrypted-storage";
import { blake3 } from '@noble/hashes/blake3.js';
import { loadVaultKeyRaw, deriveInboxId, currentInboxEpoch } from "../cryptography/vault-key";
import { blindMessage } from "../crypto/blind-credentials";
import { deriveRendezvousRouteId } from "../transport/rendezvous-routing";

// Securely wipe string reference
export const secureWipeStringRef = (ref: RefObject<string>) => {
  try {
    const len = ref.current?.length || 0;
    if (len > 0) {
      for (let pass = 0; pass < 2; pass++) {
        const randomBytes = PostQuantumUtils.randomBytes(len);
        const filler = Array.from(randomBytes)
          .map((byte) => String.fromCharCode(32 + (byte % 95)))
          .join("");
        ref.current = filler;
      }
    }
    ref.current = "";
  } catch { }
};

/**
 * Compute a stable blind user ID
 */
export const computeBlindUserId = (username: string): string => {
  const normalized = (username || "").toLowerCase().trim();
  if (!normalized) return "";
  const hash = blake3(new TextEncoder().encode(normalized), { dkLen: 32 });
  return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
};

// Safely decode a base64 string into Uint8Array, with length and format validation
export const safeDecodeB64 = (b64?: string): Uint8Array | null => {
  try {
    if (!b64 || typeof b64 !== 'string' || b64.length > 10000) return null;
    return CryptoUtils.Base64.base64ToUint8Array(b64);
  } catch { return null; }
};

// Validate server key structure and lengths
export const validateServerKeys = (val: any): boolean => {
  if (!val || typeof val !== 'object') return false;

  const hasX = !!val.x25519PublicBase64;
  const hasK = !!val.kyberPublicBase64;
  const hasD = !!val.dilithiumPublicBase64;
  const hasB = !!val.blindPublicKey;

  if (!hasX || !hasK || !hasD || !hasB) {
    console.warn('[Validator] Missing server keys:', { hasX, hasK, hasD, hasB });
    return false;
  }

  const x = safeDecodeB64(val.x25519PublicBase64);
  const k = safeDecodeB64(val.kyberPublicBase64);
  const d = safeDecodeB64(val.dilithiumPublicBase64);

  if (!x || !k || !d) {
    console.warn('[Validator] Failed to decode server keys:', { x: !!x, k: !!k, d: !!d });
    return false;
  }

  if (x.length !== 32 || k.length !== 1568 || d.length !== 2592) {
    console.warn('[Validator] Server key length mismatch:', { x: x.length, k: k.length, d: d.length });
    return false;
  }

  // Validate blind signature public key metadata
  const blind = (val as any).blindPublicKey;
  if (!blind || typeof blind !== 'object') {
    console.warn('[Validator] Invalid blind public key metadata');
    return false;
  }
  if (blind.scheme !== 'RSABSSA-PSS' || blind.hash !== 'SHA-256') {
    console.warn('[Validator] Unsupported blind key parameters');
    return false;
  }
  if (!blind.n || !blind.e || !blind.kid) {
    console.warn('[Validator] Missing blind key fields');
    return false;
  }
  if (!Number.isFinite(blind.modulusLength) || blind.modulusLength < 2048) {
    console.warn('[Validator] Invalid blind key modulus length');
    return false;
  }
  if (!Number.isFinite(blind.saltLength) || blind.saltLength < 16) {
    console.warn('[Validator] Invalid blind key salt length');
    return false;
  }
  try {
    const nBytes = CryptoUtils.Base64.base64ToUint8Array(blind.n);
    const eBytes = CryptoUtils.Base64.base64ToUint8Array(blind.e);
    const expectedLen = Math.ceil(blind.modulusLength / 8);
    if (nBytes.length !== expectedLen || eBytes.length === 0) {
      console.warn('[Validator] Invalid blind key size');
      return false;
    }
  } catch {
    console.warn('[Validator] Invalid blind key encoding');
    return false;
  }

  return true;
};

// Manage pinned server configuration
export const PinnedServer = {
  get() {
    try {
      const storedStr = syncEncryptedStorage.getItem('qorchat_server_pin_v2');
      if (!storedStr || storedStr.length > 4096) return null;

      const parsed = JSON.parse(storedStr);
      if (!validateServerKeys(parsed)) return null;
      return parsed;
    } catch { return null; }
  },
  set(val: any) {
    try {
      if (!validateServerKeys(val)) return;
      syncEncryptedStorage.setItem('qorchat_server_pin_v2', JSON.stringify(val));
    } catch { }
  }
};

// Derive a combined secret input from username, password, and passphrase
export const deriveCombinedSecretInput = (username: string, password: string, passphrase: string): string => {
  const u = (username || "").trim();
  const p = password || "";
  const pp = passphrase || "";

  if (!u || !p || !pp) {
    throw new Error('[Auth] Missing username, password, or passphrase for key derivation');
  }

  return `${u}\u0000${p}\u0000${pp}`;
};

export interface BlindCredentialResult {
  message: string;
  inboxId: string;
  routeId: string;
  blindedMsg: string;
  blindingFactor: string;
  n: string;
  kid: string;
  modulusLength: number;
  hash: string;
  saltLength: number;
  scheme: string;
}

/**
 * Generate a blind credential for given username using server public key
 */
export const generateBlindCredential = async (
  username: string,
  serverBlindPublicKey: any
): Promise<BlindCredentialResult | null> => {
  try {
    const rawVaultKey = await loadVaultKeyRaw(username);
    if (!rawVaultKey || rawVaultKey.length !== 32) {
      console.warn('[Auth] Vault key not found or invalid for blinding');
      return null;
    }

    const vaultKey = await CryptoUtils.AES.importAesKey(rawVaultKey);
    const inboxId = await deriveInboxId(vaultKey, currentInboxEpoch());

    if (!inboxId) {
      console.warn('[Auth] Failed to derive inboxId');
      return null;
    }

    const routeId = deriveRendezvousRouteId(inboxId);
    const blindResult = await blindMessage(routeId, serverBlindPublicKey);

    return {
      message: routeId,
      inboxId,
      routeId,
      blindedMsg: blindResult.blindedMsg,
      blindingFactor: blindResult.blindingFactor,
      n: blindResult.n,
      kid: blindResult.kid,
      modulusLength: blindResult.modulusLength,
      hash: blindResult.hash,
      saltLength: blindResult.saltLength,
      scheme: blindResult.scheme
    };
  } catch (err) {
    console.warn('[Auth] Failed to generate blind credential:', err);
    return null;
  }
};
