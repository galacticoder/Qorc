import { CryptoUtils } from "@/lib/unified-crypto";

export interface PseudonymizationConfig {
  cacheSize?: number;
  cacheTTL?: number;
  defaultMemoryCost?: number;
  maxUsernameLength?: number;
  slowOperationThreshold?: number;
  enableAuditLogging?: boolean;
}

const DEFAULT_PSEUDONYMIZATION_CONFIG: Required<PseudonymizationConfig> = {
  cacheSize: 10000,
  cacheTTL: 24 * 60 * 60 * 1000,
  defaultMemoryCost: 1 << 16,
  maxUsernameLength: 100,
  slowOperationThreshold: 5000,
  enableAuditLogging: true
};

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

class PseudonymizationMonitor {
  private static readonly MAX_SAMPLES = 1000;
  private static timings = new Map<string, number[]>();
  private static failureCount = 0;

  static record(operation: string, duration: number, success: boolean): void {
    if (!Number.isFinite(duration) || duration < 0) {
      return;
    }

    if (!success) {
      PseudonymizationMonitor.failureCount += 1;
    }

    if (!PseudonymizationMonitor.timings.has(operation)) {
      PseudonymizationMonitor.timings.set(operation, []);
    }

    const samples = PseudonymizationMonitor.timings.get(operation)!;
    samples.push(duration);
    if (samples.length > PseudonymizationMonitor.MAX_SAMPLES) {
      samples.shift();
    }

    const threshold = PseudonymizationConfiguration.get().slowOperationThreshold;
    if (duration > threshold) {
    }
  }

  static getStats(): {
    methods: Record<string, { avg: number; min: number; max: number; count: number; p95: number }>;
    failures: number;
    errorRate: number;
  } {
    const methods: Record<string, { avg: number; min: number; max: number; count: number; p95: number }> = {};
    let totalCount = 0;

    for (const [method, samples] of PseudonymizationMonitor.timings.entries()) {
      const sorted = [...samples].sort((a, b) => a - b);
      const count = sorted.length;
      totalCount += count;
      const avg = count > 0 ? sorted.reduce((sum, value) => sum + value, 0) / count : 0;
      const min = count > 0 ? sorted[0] : 0;
      const max = count > 0 ? sorted[count - 1] : 0;
      const p95 = count > 0 ? sorted[Math.min(count - 1, Math.floor(count * 0.95))] : 0;

      methods[method] = { avg, min, max, count, p95 };
    }

    const failures = PseudonymizationMonitor.failureCount;
    const errorRate = totalCount + failures > 0 ? failures / (totalCount + failures) : 0;

    return { methods, failures, errorRate };
  }
}

class PseudonymizationAuditLogger {
  private static readonly MAX_LOG_ENTRIES = 10000;
  private static entries: Array<{
    timestamp: number;
    operation: string;
    originalUsername: string;
    pseudonym: string;
    method: string;
    success: boolean;
    duration: number;
  }> = [];

  static log(operation: string, originalUsername: string, pseudonym: string, method: string, success: boolean, duration: number): void {
    if (!PseudonymizationConfiguration.get().enableAuditLogging) {
      return;
    }

    const entry = {
      timestamp: Date.now(),
      operation,
      originalUsername: originalUsername.slice(0, 50),
      pseudonym: pseudonym.slice(0, 50),
      method,
      success,
      duration
    };

    PseudonymizationAuditLogger.entries.push(entry);
    if (PseudonymizationAuditLogger.entries.length > PseudonymizationAuditLogger.MAX_LOG_ENTRIES) {
      PseudonymizationAuditLogger.entries = PseudonymizationAuditLogger.entries.slice(-PseudonymizationAuditLogger.MAX_LOG_ENTRIES);
    }

    if (!success) {
    }
  }

  static getRecentLogs(count = 100): typeof PseudonymizationAuditLogger.entries {
    return PseudonymizationAuditLogger.entries.slice(-count);
  }

  static getStats(): { total: number; failed: number; avgDuration: number; methods: Record<string, number> } {
    const total = PseudonymizationAuditLogger.entries.length;
    const failed = PseudonymizationAuditLogger.entries.filter(entry => !entry.success).length;
    const avgDuration = total > 0
      ? PseudonymizationAuditLogger.entries.reduce((sum, entry) => sum + entry.duration, 0) / total
      : 0;

    const methods: Record<string, number> = {};
    for (const entry of PseudonymizationAuditLogger.entries) {
      methods[entry.method] = (methods[entry.method] || 0) + 1;
    }

    return { total, failed, avgDuration, methods };
  }
}

const PSEUDONYM_SALT_BASE64 = "cHNldWRvbnltLXYxLWdsb2JhbC1zYWx0";
const VALID_USERNAME_PATTERN = /^[\w\-_.@]+$/i;

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    hex += (byte < 16 ? '0' : '') + byte.toString(16);
  }
  return hex;
}

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

async function pseudonymArgon2id(normalized: string, memoryCost?: number): Promise<string> {
  const startTime = Date.now();
  let success = false;
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
    success = true;
    return hex;
  } finally {
    PseudonymizationMonitor.record('argon2id', Date.now() - startTime, success);
  }
}

async function pseudonymBlake3(normalized: string): Promise<string> {
  const startTime = Date.now();
  let success = false;
  try {
    const key = CryptoUtils.Base64.base64ToUint8Array(PSEUDONYM_SALT_BASE64);
    const msg = new TextEncoder().encode(normalized);
    const mac = await CryptoUtils.Hash.generateBlake3Mac(msg, key);
    const hex = toHex(mac).slice(0, 32);
    if (!/^[a-f0-9]{32}$/i.test(hex)) {
      throw new Error('Unexpected BLAKE3 output');
    }
    success = true;
    return hex;
  } finally {
    PseudonymizationMonitor.record('blake3', Date.now() - startTime, success);
  }
}

async function pseudonymSha512(normalized: string): Promise<string> {
  const startTime = Date.now();
  let success = false;
  try {
    const enc = new TextEncoder().encode(normalized);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-512', enc));
    const hex = toHex(digest).slice(0, 32);
    if (!/^[a-f0-9]{32}$/i.test(hex)) {
      throw new Error('Unexpected SHA-512 output');
    }
    success = true;
    return hex;
  } finally {
    PseudonymizationMonitor.record('sha512', Date.now() - startTime, success);
  }
}

function logPseudonymization(operation: string, original: string, pseudonym: string, method: string, duration: number, success: boolean): void {
  PseudonymizationAuditLogger.log(operation, original, pseudonym, method, success, duration);
}

// Deterministic pseudonymization Argon2id
export async function pseudonymizeUsername(original: string, memoryCost?: number): Promise<string> {
  const overallStart = Date.now();
  const sanitized = sanitizeOriginalUsername(original);

  if (!sanitized) {
    logPseudonymization('pseudonymize', original ?? '', '', 'invalid-input', Date.now() - overallStart, false);
    throw new Error('Invalid username');
  }

  try {
    const result = await pseudonymArgon2id(sanitized, memoryCost);
    logPseudonymization('pseudonymize', sanitized, result, 'argon2id', Date.now() - overallStart, true);
    return result;
  } catch (_argonError) {
    try {
      const result = await pseudonymBlake3(sanitized);
      logPseudonymization('pseudonymize', sanitized, result, 'blake3', Date.now() - overallStart, true);
      return result;
    } catch (_blakeError) {
      try {
        const result = await pseudonymSha512(sanitized);
        logPseudonymization('pseudonymize', sanitized, result, 'sha512', Date.now() - overallStart, true);
        return result;
      } catch {
        logPseudonymization('pseudonymize', sanitized, '', 'none', Date.now() - overallStart, false);
        throw new Error('All pseudonymization methods failed - cryptographic system unavailable');
      }
    }
  }
}

type CacheEntry = { value: string; timestamp: number };

const PSEUDONYM_CACHE = new Map<string, CacheEntry>();
const PSEUDONYM_PENDING = new Map<string, Promise<string>>();

function evictCacheIfNeeded(): void {
  const { cacheSize } = PseudonymizationConfiguration.get();
  while (PSEUDONYM_CACHE.size > cacheSize) {
    const oldestKey = PSEUDONYM_CACHE.keys().next().value;
    if (!oldestKey) break;
    PSEUDONYM_CACHE.delete(oldestKey);
  }
}

export async function pseudonymizeUsernameWithCache(original: string, secureDB?: any): Promise<string> {
  const startTime = Date.now();
  const sanitized = sanitizeOriginalUsername(original);

  if (!sanitized) {
    logPseudonymization('cache-miss', original ?? '', '', 'invalid-input', Date.now() - startTime, false);
    throw new Error('Invalid username');
  }

  const config = PseudonymizationConfiguration.get();
  const cached = PSEUDONYM_CACHE.get(sanitized);
  const now = Date.now();
  if (cached && now - cached.timestamp < config.cacheTTL) {
    PseudonymizationMonitor.record('cache-hit', Date.now() - startTime, true);
    logPseudonymization('cache-hit', sanitized, cached.value, 'memory-cache', Date.now() - startTime, true);
    return cached.value;
  }

  if (cached) {
    PSEUDONYM_CACHE.delete(sanitized);
    PseudonymizationMonitor.record('cache-expired', Date.now() - startTime, false);
    logPseudonymization('cache-expired', sanitized, cached.value, 'memory-cache', Date.now() - startTime, false);
  }

  if (secureDB) {
    try {
      const dbCached = await secureDB.getCachedUsernameHash(sanitized);
      if (dbCached && typeof dbCached === 'string') {
        PSEUDONYM_CACHE.set(sanitized, { value: dbCached, timestamp: Date.now() });
        evictCacheIfNeeded();
        PseudonymizationMonitor.record('db-cache-hit', Date.now() - startTime, true);
        logPseudonymization('db-cache-hit', sanitized, dbCached, 'indexeddb', Date.now() - startTime, true);
        return dbCached;
      }
    } catch (_e) {
    }
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
        } catch (_e) {
        }
      }

      PseudonymizationMonitor.record('cache-miss', Date.now() - startTime, true);
      logPseudonymization('cache-miss', sanitized, pseudonym, 'calculated', Date.now() - startTime, true);
      return pseudonym;
    } finally {
      PSEUDONYM_PENDING.delete(sanitized);
    }
  })();

  PSEUDONYM_PENDING.set(sanitized, pendingPromise);
  return pendingPromise;
}

export function clearPseudonymCache(): void {
  PSEUDONYM_CACHE.clear();
  PSEUDONYM_PENDING.clear();
}

export function getPseudonymCacheStats(): { size: number; oldestEntryAge?: number } {
  const size = PSEUDONYM_CACHE.size;
  if (size === 0) {
    return { size };
  }

  const oldestTimestamp = Math.min(...Array.from(PSEUDONYM_CACHE.values()).map(entry => entry.timestamp));
  return { size, oldestEntryAge: Date.now() - oldestTimestamp };
}

export function configurePseudonymization(options: PseudonymizationConfig): void {
  PseudonymizationConfiguration.configure(options);
}

export function getPseudonymizationStats(): ReturnType<typeof PseudonymizationMonitor.getStats> {
  return PseudonymizationMonitor.getStats();
}

export function getPseudonymizationLogs(count = 100): ReturnType<typeof PseudonymizationAuditLogger.getRecentLogs> {
  return PseudonymizationAuditLogger.getRecentLogs(count);
}

export function getPseudonymizationAuditStats(): ReturnType<typeof PseudonymizationAuditLogger.getStats> {
  return PseudonymizationAuditLogger.getStats();
}
