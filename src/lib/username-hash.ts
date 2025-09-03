import { CryptoUtils } from "@/lib/unified-crypto";

// Public, fixed salt (base64 for "pseudonym-v1-global-salt") for deterministic pseudonyms across clients.
// This salt is NOT secret; it just ensures cross-device determinism without leaking the original username.
const PSEUDONYM_SALT_BASE64 = "cHNldWRvbnltLXYxLWdsb2JhbC1zYWx0";

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

async function pseudonymArgon2id(normalized: string, memoryCost?: number): Promise<string> {
  // Argon2id via unified-crypto (argon2-wasm) — memory hard and strong
  // Default to 64 MiB, allow configuration for resource-constrained environments
  const defaultMemoryCost = 1 << 16; // 64 MiB
  const minMemoryCost = 1 << 12; // 4 MiB minimum
  const maxMemoryCost = 1 << 20; // 1 GiB maximum
  
  let actualMemoryCost = memoryCost ?? defaultMemoryCost;
  actualMemoryCost = Math.max(minMemoryCost, Math.min(maxMemoryCost, actualMemoryCost));
  
  const encoded = await CryptoUtils.Hash.hashDataUsingInfo(normalized, {
    algorithm: 'argon2id',
    salt: PSEUDONYM_SALT_BASE64,
    timeCost: 3,
    memoryCost: actualMemoryCost,
    parallelism: 1,
    version: 0x13
  });
  const parsed = CryptoUtils.Hash.parseArgon2Hash(encoded);
  const hex = toHex(parsed.hash);
  return hex.slice(0, 32);
}

async function pseudonymBlake3(normalized: string): Promise<string> {
  // Deterministic BLAKE3 keyed MAC fallback (not memory-hard, but robust as backup)
  const key = CryptoUtils.Base64.base64ToUint8Array(PSEUDONYM_SALT_BASE64);
  const msg = new TextEncoder().encode(normalized);
  const mac = await CryptoUtils.Hash.generateBlake3Mac(msg, key);
  const hex = toHex(mac);
  return hex.slice(0, 32);
}

// Deterministic, memory-hard pseudonymization using Argon2id, with robust fallback.
// Output: 32-char lowercase hex suitable for existing username constraints on the server.
export async function pseudonymizeUsername(original: string, memoryCost?: number): Promise<string> {
  if (!original || typeof original !== 'string') {
    throw new Error('Invalid username');
  }
  const normalized = original.trim().toLowerCase();
  if (!normalized) throw new Error('Invalid username');

  try {
    const out = await pseudonymArgon2id(normalized, memoryCost);
    if (out && out.length >= 8) return out; // sanity check
  } catch (_) {}

  // Fallback to BLAKE3 keyed MAC if Argon2id fails or returns unexpected output
  try {
    const out = await pseudonymBlake3(normalized);
    if (out && out.length >= 8) return out;
  } catch (_) {}

  // As last resort, use plain SHA-512 via WebCrypto and truncate
  try {
    const enc = new TextEncoder().encode(normalized);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', enc));
    const hex = toHex(digest);
    return hex.slice(0, 32);
  } catch (_) {
    // Should never happen; return a hardcoded non-empty pseudonym to avoid empty username
    return 'deadbeefdeadbeefdeadbeefdeadbeef';
  }
}

// Simple in-memory cache to avoid recomputing expensive Argon2id per username
const PSEUDONYM_CACHE = new Map<string, string>();

export async function pseudonymizeUsernameWithCache(original: string): Promise<string> {
  const norm = (original || '').trim().toLowerCase();
  if (!norm) throw new Error('Invalid username');
  const cached = PSEUDONYM_CACHE.get(norm);
  if (cached) return cached;
  const out = await pseudonymizeUsername(norm);
  PSEUDONYM_CACHE.set(norm, out);
  return out;
}
