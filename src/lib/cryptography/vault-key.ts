import { AES } from '../utils/crypto-utils';
import { PostQuantumAEAD } from './aead';

function sanitizeId(value: string): string {
  return (value || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function getVaultKeyName(username: string): string {
  return `vault:${sanitizeId(username)}`;
}

function getWrappedMasterKeyName(username: string): string {
  return `wmk:${sanitizeId(username)}`;
}

export async function loadVaultKeyRaw(username: string): Promise<Uint8Array | null> {
  try {
    const api = (window as any).electronAPI;
    if (!api?.secureStore?.get) return null;
    await api.secureStore.init?.();
    const b64 = await api.secureStore.get(getVaultKeyName(username));
    if (!b64 || typeof b64 !== 'string') return null;
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

export async function saveVaultKeyRaw(username: string, keyBytes: Uint8Array): Promise<boolean> {
  try {
    const api = (window as any).electronAPI;
    if (!api?.secureStore?.set) return false;
    await api.secureStore.init?.();
    const b64 = btoa(String.fromCharCode.apply(null, Array.from(keyBytes)));
    await api.secureStore.set(getVaultKeyName(username), b64);
    return true;
  } catch {
    return false;
  }
}

export async function ensureVaultKeyCryptoKey(username: string): Promise<CryptoKey> {
  const existing = await loadVaultKeyRaw(username);
  if (existing && existing.length === 32) {
    return await AES.importAesKey(existing);
  }
  const fresh = crypto.getRandomValues(new Uint8Array(32));
  const _saved = await saveVaultKeyRaw(username, fresh);
  const cryptoKey = await AES.importAesKey(fresh);
  fresh.fill(0);
  return cryptoKey;
}

export async function removeVaultKey(username: string): Promise<void> {
  try {
    const api = (window as any).electronAPI;
    await api?.secureStore?.remove?.(getVaultKeyName(username));
  } catch {}
}

function b64FromBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(bytes)));
}
function bytesFromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function saveWrappedMasterKey(username: string, masterKeyBytes: Uint8Array, vaultKey: CryptoKey): Promise<boolean> {
  try {
    const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
    if (!subtle) {
      return false;
    }

    const rawVaultKey = new Uint8Array(await subtle.exportKey('raw', vaultKey));
    try {
      const aad = new TextEncoder().encode(`vault-wrapped-master-v2:${username}`);
      const { ciphertext, nonce, tag } = PostQuantumAEAD.encrypt(masterKeyBytes, rawVaultKey, aad);
      const payload = JSON.stringify({
        v: 2,
        nonce: b64FromBytes(nonce),
        tag: b64FromBytes(tag),
        ct: b64FromBytes(ciphertext)
      });
      const api = (window as any).electronAPI;
      await api?.secureStore?.set?.(getWrappedMasterKeyName(username), payload);
      return true;
    } finally {
      rawVaultKey.fill(0);
    }
  } catch {
    return false;
  }
}

export async function loadWrappedMasterKey(username: string, vaultKey: CryptoKey): Promise<Uint8Array | null> {
  try {
    const api = (window as any).electronAPI;
    const raw = await api?.secureStore?.get?.(getWrappedMasterKeyName(username));
    if (!raw || typeof raw !== 'string') return null;
    let parsed: any;
    try { parsed = JSON.parse(raw); } catch { return null; }

    const subtle = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
    if (!subtle) {
      return null;
    }

    if (parsed && parsed.v === 2 && typeof parsed.nonce === 'string' && typeof parsed.tag === 'string' && typeof parsed.ct === 'string') {
      const rawVaultKey = new Uint8Array(await subtle.exportKey('raw', vaultKey));
      try {
        const aad = new TextEncoder().encode(`vault-wrapped-master-v2:${username}`);
        const nonce = bytesFromB64(parsed.nonce);
        const tag = bytesFromB64(parsed.tag);
        const ct = bytesFromB64(parsed.ct);
        const plaintext = PostQuantumAEAD.decrypt(ct, nonce, tag, rawVaultKey, aad);
        return new Uint8Array(plaintext);
      } finally {
        rawVaultKey.fill(0);
      }
    }

    return null;
  } catch {
    return null;
  }
}
