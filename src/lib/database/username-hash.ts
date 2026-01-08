import { CryptoUtils } from "@/lib/utils/crypto-utils";
import { PseudonymizationConfig, DEFAULT_PSEUDONYMIZATION_CONFIG  } from "../types/username-types";
import { VALID_USERNAME_PATTERN, PSEUDONYM_SALT_BASE64 } from "../constants";
import { toHex } from "../utils/username-utils";

type CacheEntry = { value: string; timestamp: number };

const PSEUDONYM_CACHE = new Map<string, CacheEntry>();
const PSEUDONYM_PENDING = new Map<string, Promise<string>>();

// Configuration class for pseudonymization settings
class PseudonymizationConfiguration {
  private static config: Required<PseudonymizationConfig> = { ...DEFAULT_PSEUDONYMIZATION_CONFIG };

  static configure(options: PseudonymizationConfig = {}): void {
    if (!options || typeof options !== 'object') {
      return;
    }

    const next = { ...PseudonymizationConfiguration.config, ...options } as Required<PseudonymizationConfig>;

    next.cacheSize = Math.max(1, Math.min(50000, Math.floor(next.cacheSize)));
    next.cacheTTL = Math.max(1000, Math.floor(next.cacheTTL));
    next.defaultMemoryCost = Math.max(1 << 12, Math.min(1 << 20, next.defaultMemoryCost));
    next.maxUsernameLength = Math.max(1, Math.min(200, Math.floor(next.maxUsernameLength)));
    next.slowOperationThreshold = Math.max(0, Math.floor(next.slowOperationThreshold));

    PseudonymizationConfiguration.config = next;
  }

  static get(): Required<PseudonymizationConfig> {
    return { ...PseudonymizationConfiguration.config };
  }
}

// Sanitizes and validates the original username
function sanitizeOriginalUsername(input: string): string {
  if (!input || typeof input !== 'string') {
    return '';
  }

  const trimmed = input.trim();
  if (!trimmed) {
    return '';
  }

  const { maxUsernameLength } = PseudonymizationConfiguration.get();
  if (trimmed.length > maxUsernameLength) {
    return '';
  }

  if (!VALID_USERNAME_PATTERN.test(trimmed)) {
    return '';
  }

  return trimmed.toLowerCase();
}

// Argon2id pseudonymization
async function pseudonymArgon2id(normalized: string, memoryCost?: number): Promise<string> {
  try {
    const config = PseudonymizationConfiguration.get();
    const minMemoryCost = 1 << 12;
    const maxMemoryCost = 1 << 20;

    let actualMemoryCost = memoryCost ?? config.defaultMemoryCost;
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
    const hex = toHex(parsed.hash).slice(0, 32);
    if (!/^[a-f0-9]{32}$/i.test(hex)) {
      throw new Error('Unexpected Argon2id output');
    }

    return hex;
  }
  catch (error) {
    console.error('Error in pseudonymArgon2id:', error);
    throw error;
  }
}

// BLAKE3 pseudonymization
async function pseudonymBlake3(normalized: string): Promise<string> {
  try {
    const key = CryptoUtils.Base64.base64ToUint8Array(PSEUDONYM_SALT_BASE64);
    const msg = new TextEncoder().encode(normalized);
    const mac = await CryptoUtils.Hash.generateBlake3Mac(msg, key);

    const hex = toHex(mac).slice(0, 32);
    if (!/^[a-f0-9]{32}$/i.test(hex)) {
      throw new Error('Unexpected BLAKE3 output');
    }

    return hex;
  }
  catch (error) {
    console.error('Error in pseudonymBlake3:', error);
    throw error;
  }
}

// SHA-512 pseudonymization
async function pseudonymSha512(normalized: string): Promise<string> {
  try {
    const enc = new TextEncoder().encode(normalized);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', enc));
    const hex = toHex(digest).slice(0, 32);

    if (!/^[a-f0-9]{32}$/i.test(hex)) {
      throw new Error('Unexpected SHA-512 output');
    }

    return hex;
  }
  catch (error) {
    console.error('Error in pseudonymSha512:', error);
    throw error;
  }
}

// Deterministic pseudonymization Argon2id
export async function pseudonymizeUsername(original: string, memoryCost?: number): Promise<string> {
  const sanitized = sanitizeOriginalUsername(original);

  if (!sanitized) {
    throw new Error('Invalid username');
  }

  try {
    const result = await pseudonymArgon2id(sanitized, memoryCost);
    return result;
  } catch {
    try {
      return await pseudonymBlake3(sanitized);
    } catch {
      try {
        return await pseudonymSha512(sanitized);
      } catch {
        throw new Error('All pseudonymization methods failed');
      }
    }
  }
}

// Evicts oldest cache entries if the cache exceeds its configured size
function evictCacheIfNeeded(): void {
  const { cacheSize } = PseudonymizationConfiguration.get();
  while (PSEUDONYM_CACHE.size > cacheSize) {
    const oldestKey = PSEUDONYM_CACHE.keys().next().value;
    if (!oldestKey) break;
    PSEUDONYM_CACHE.delete(oldestKey);
  }
}

// Pseudonymizes a username
export async function pseudonymizeUsernameWithCache(original: string, secureDB?: any): Promise<string> {
  const sanitized = sanitizeOriginalUsername(original);

  if (!sanitized) {
    throw new Error('Invalid username');
  }

  const config = PseudonymizationConfiguration.get();
  const cached = PSEUDONYM_CACHE.get(sanitized);
  const now = Date.now();

  if (cached && now - cached.timestamp < config.cacheTTL) {
    return cached.value;
  }

  if (cached) {
    PSEUDONYM_CACHE.delete(sanitized);
  }

  if (secureDB) {
    try {
      const dbCached = await secureDB.getCachedUsernameHash(sanitized);
      if (dbCached && typeof dbCached === 'string') {
        PSEUDONYM_CACHE.set(sanitized, { value: dbCached, timestamp: Date.now() });
        evictCacheIfNeeded();
        return dbCached;
      }
    } catch { }
  }

  if (PSEUDONYM_PENDING.has(sanitized)) {
    return PSEUDONYM_PENDING.get(sanitized)!;
  }

  const pendingPromise = (async () => {
    try {
      const pseudonym = await pseudonymizeUsername(sanitized);
      PSEUDONYM_CACHE.set(sanitized, { value: pseudonym, timestamp: Date.now() });
      evictCacheIfNeeded();

      if (secureDB) {
        try {
          await secureDB.cacheUsernameHash(sanitized, pseudonym);
          await secureDB.storeUsernameMapping(pseudonym, sanitized);
        } catch { }
      }

      return pseudonym;
    } finally {
      PSEUDONYM_PENDING.delete(sanitized);
    }
  })();

  PSEUDONYM_PENDING.set(sanitized, pendingPromise);
  return pendingPromise;
}