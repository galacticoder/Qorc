import { RefObject } from "react";
import { CryptoUtils } from "../unified-crypto";
import { PostQuantumUtils } from "../post-quantum-crypto";
import { syncEncryptedStorage } from "../encrypted-storage";

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

export const safeDecodeB64 = (b64?: string): Uint8Array | null => {
  try {
    if (!b64 || typeof b64 !== 'string' || b64.length > 10000) return null;
    return CryptoUtils.Base64.base64ToUint8Array(b64);
  } catch { return null; }
};

export const validateServerKeys = (val: any): boolean => {
  if (!val || typeof val !== 'object') return false;
  if (!val.x25519PublicBase64 || !val.kyberPublicBase64 || !val.dilithiumPublicBase64) return false;
  if (typeof val.x25519PublicBase64 !== 'string' ||
    typeof val.kyberPublicBase64 !== 'string' ||
    typeof val.dilithiumPublicBase64 !== 'string') return false;
  const expB64Len = (n: number) => 4 * Math.ceil(n / 3);
  if (val.x25519PublicBase64.length > expB64Len(32) + 8) return false;
  if (val.kyberPublicBase64.length > expB64Len(1568) + 8) return false;
  if (val.dilithiumPublicBase64.length > expB64Len(2592) + 8) return false;

  const x = safeDecodeB64(val.x25519PublicBase64);
  const k = safeDecodeB64(val.kyberPublicBase64);
  const d = safeDecodeB64(val.dilithiumPublicBase64);
  if (!x || !k || !d) return false;
  if (x.length !== 32 || k.length !== 1568 || d.length !== 2592) return false;
  return true;
};

export const PinnedServer = {
  get() {
    try {
      const storedStr = syncEncryptedStorage.getItem('securechat_server_pin_v2');
      if (!storedStr || storedStr.length > 4096) return null;

      const parsed = JSON.parse(storedStr);
      if (!validateServerKeys(parsed)) return null;
      return parsed;
    } catch { return null; }
  },
  set(val: any) {
    try {
      if (!validateServerKeys(val)) return;
      syncEncryptedStorage.setItem('securechat_server_pin_v2', JSON.stringify(val));
    } catch { }
  }
};

export const deriveCombinedSecretInput = (username: string, password: string, passphrase: string): string => {
  const u = (username || "").trim();
  const p = password || "";
  const pp = passphrase || "";

  if (!u || !p || !pp) {
    throw new Error('[Auth] Missing username, password, or passphrase for key derivation');
  }

  return `${u}\u0000${p}\u0000${pp}`;
};
