import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import * as argon2 from "argon2-wasm";

type WorkerRequestMessage = {
  id: string;
  type: 'kem.generateKeyPair' | 'kem.destroyKey' | 'argon2.hash' | 'argon2.verify';
  auth: string;
  keyId?: string;
  params?: any;
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

const hasPrototypePollutionKeys = (obj: Record<string, unknown>): boolean => {
  return ['__proto__', 'prototype', 'constructor'].some((key) => Object.prototype.hasOwnProperty.call(obj, key));
};

const isHexString = (value: unknown, expectedBytes: number): value is string => {
  if (typeof value !== 'string') return false;
  if (value.length !== expectedBytes * 2) return false;
  return /^[0-9a-fA-F]+$/.test(value);
};

const parseAuthTokenHex = (value: string): Uint8Array | null => {
  if (!isHexString(value, 32)) return null;
  const tokenBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    tokenBytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return tokenBytes;
};

const isWorkerAuthTokenMessage = (
  data: Record<string, unknown>
): data is { type: 'auth-token-init' | 'auth-token-rotated'; token: string; timestamp: number } => {
  if (data.type !== 'auth-token-init' && data.type !== 'auth-token-rotated') return false;
  if (typeof data.token !== 'string') return false;
  if (typeof data.timestamp !== 'number' || !Number.isFinite(data.timestamp)) return false;
  return true;
};

const isWorkerResponseFailureMessage = (data: Record<string, unknown>): data is { id: string; success: false; error: string } => {
  return (
    typeof data.id === 'string' &&
    data.id.length > 0 &&
    data.id.length <= 256 &&
    data.success === false &&
    typeof data.error === 'string'
  );
};

const isWorkerResponseSuccessMessage = (data: Record<string, unknown>): data is { id: string; success: true; result: unknown } => {
  return (
    typeof data.id === 'string' &&
    data.id.length > 0 &&
    data.id.length <= 256 &&
    data.success === true &&
    Object.prototype.hasOwnProperty.call(data, 'result')
  );
};

const isKemKeyPairResult = (result: unknown): result is { publicKey: Uint8Array; secretKey: Uint8Array; keyId: string } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!(result.publicKey instanceof Uint8Array)) return false;
  if (!(result.secretKey instanceof Uint8Array)) return false;
  if (typeof result.keyId !== 'string' || result.keyId.length === 0 || result.keyId.length > 256) return false;
  if (result.keyId === '__proto__' || result.keyId === 'prototype' || result.keyId === 'constructor') return false;
  return true;
};

const isDestroyKeyResult = (result: unknown): result is { destroyed: true } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return (result as Record<string, unknown>).destroyed === true;
};

const isArgon2HashResult = (result: unknown): result is { hash: Uint8Array; encoded: string } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  if (!(result.hash instanceof Uint8Array)) return false;
  if (typeof result.encoded !== 'string' || result.encoded.length === 0 || result.encoded.length > 8192) return false;
  return true;
};

const isArgon2VerifyResult = (result: unknown): result is { verified: boolean } => {
  if (!isPlainObject(result) || hasPrototypePollutionKeys(result)) return false;
  return typeof result.verified === 'boolean';
};

const validateWorkerResult = (expectedType: WorkerRequestMessage['type'], result: unknown): boolean => {
  switch (expectedType) {
    case 'kem.generateKeyPair':
      return isKemKeyPairResult(result);
    case 'kem.destroyKey':
      return isDestroyKeyResult(result);
    case 'argon2.hash':
      return isArgon2HashResult(result);
    case 'argon2.verify':
      return isArgon2VerifyResult(result);
    default:
      return false;
  }
};

/**
 * Security audit logger for tracking security events across the application.
 * Keeps recent security events in memory for debugging and monitoring.
 */
export class SecurityAuditLogger {
  private static readonly MAX_LOG_ENTRIES = 1000;
  private static logEntries: Array<{
    timestamp: number;
    level: 'info' | 'warn' | 'error';
    event: string;
    details: Record<string, unknown>;
  }> = [];

  static log(level: 'info' | 'warn' | 'error', event: string, details: Record<string, unknown> = {}): void {
    const timestamp = Date.now();
    const entry = {
      timestamp,
      level,
      event,
      details: { ...details }
    };

    SecurityAuditLogger.logEntries.push(entry);
    if (SecurityAuditLogger.logEntries.length > SecurityAuditLogger.MAX_LOG_ENTRIES) {
      SecurityAuditLogger.logEntries = SecurityAuditLogger.logEntries.slice(-SecurityAuditLogger.MAX_LOG_ENTRIES);
    }
  }

  static getRecentLogs(count: number = 100): Array<{
    timestamp: number;
    level: 'info' | 'warn' | 'error';
    event: string;
    details: Record<string, unknown>;
  }> {
    if (!Number.isInteger(count) || count <= 0) {
      count = 100;
    }
    return SecurityAuditLogger.logEntries.slice(-count);
  }
}

export class PostQuantumCrypto {
  static configure(options: {
    security?: { maxMessageAgeMs?: number; maxRandomBytes?: number; sessionTimeoutMs?: number };
  }): void {
    if (options.security?.maxMessageAgeMs !== undefined) {
      ClientServerProtocol.setMaxMessageAge(options.security.maxMessageAgeMs);
    }

    if (options.security?.maxRandomBytes !== undefined) {
      PostQuantumRandom.setMaxRandomBytes(options.security.maxRandomBytes);
    }

    if (options.security?.sessionTimeoutMs !== undefined) {
      PostQuantumSession.setSessionTimeout(options.security.sessionTimeoutMs);
    }
  }
}

export class PostQuantumKEM {
  private static readonly kyber = ml_kem1024;
  static readonly SIZES = { publicKey: 1568, secretKey: 3168, ciphertext: 1568, sharedSecret: 32 } as const;

  static generateKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const kp = this.kyber.keygen();
    const publicKey = PostQuantumUtils.asUint8Array(kp.publicKey);
    const secretKey = PostQuantumUtils.asUint8Array(kp.secretKey);
    if (publicKey.length !== this.SIZES.publicKey) {
      throw new Error('Invalid public key size generated');
    }
    if (secretKey.length !== this.SIZES.secretKey) {
      throw new Error('Invalid secret key size generated');
    }
    return { publicKey, secretKey };
  }

  static generateKeyPairFromSeed(_seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
    throw new Error('Deterministic ML-KEM key generation is not supported by the underlying library');
  }

  static encapsulate(publicKey: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
    if (!publicKey) throw new Error('Public key required');
    if (publicKey.length !== this.SIZES.publicKey) throw new Error(`Invalid public key size: ${publicKey.length}`);
    const result = this.kyber.encapsulate(publicKey);
    try {
      if (result.cipherText.length !== this.SIZES.ciphertext) throw new Error('Invalid ciphertext size');
      if (result.sharedSecret.length !== this.SIZES.sharedSecret) throw new Error('Invalid shared secret size');
      const ciphertext = new Uint8Array(result.cipherText);
      const sharedSecret = new Uint8Array(result.sharedSecret);
      return { ciphertext, sharedSecret };
    } finally {
      PostQuantumUtils.clearMemory(result.cipherText);
      PostQuantumUtils.clearMemory(result.sharedSecret);
    }
  }

  static decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (!ciphertext || !secretKey) throw new Error('Ciphertext and secret key required');
    if (ciphertext.length !== this.SIZES.ciphertext) throw new Error(`Invalid ciphertext size: ${ciphertext.length}`);
    if (secretKey.length !== this.SIZES.secretKey) throw new Error(`Invalid secret key size: ${secretKey.length}`);
    const sharedSecret = this.kyber.decapsulate(ciphertext, secretKey);
    try {
      if (sharedSecret.length !== this.SIZES.sharedSecret) throw new Error('Invalid shared secret size');
      return new Uint8Array(sharedSecret);
    } finally {
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }

  static get sizes() {
    return this.SIZES;
  }
}

export class PostQuantumSignature {
  private static readonly dilithium = ml_dsa87;

  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const seed = PostQuantumRandom.randomBytes(32);
    const { publicKey, secretKey } = await this.dilithium.keygen(seed);
    return {
      publicKey: PostQuantumUtils.asUint8Array(publicKey),
      secretKey: PostQuantumUtils.asUint8Array(secretKey)
    };
  }

  static sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(secretKey instanceof Uint8Array) || secretKey.length !== PostQuantumSignature.sizes.secretKey) {
      throw new Error('Invalid secret key for Dilithium');
    }
    
    return this.dilithium.sign(message, secretKey);
  }

  static verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
    if (!(signature instanceof Uint8Array) || signature.length !== PostQuantumSignature.sizes.signature) {
      throw new Error('Invalid signature size for Dilithium');
    }
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== PostQuantumSignature.sizes.publicKey) {
      throw new Error('Invalid public key for Dilithium');
    }
    
    return this.dilithium.verify(signature, message, publicKey);
  }

  static get sizes() {
    return { publicKey: 2592, secretKey: 4896, signature: 4627 };
  }
}

export class PostQuantumHash {
  static blake3(data: Uint8Array, options?: { dkLen?: number }): Uint8Array { return blake3(data, options); }
  static deriveKey(inputKey: Uint8Array, salt: Uint8Array, info: string, length: number = 32): Uint8Array {
    const infoBytes = new TextEncoder().encode(info || '');
    return hkdf(blake3, inputKey, salt, infoBytes, length);
  }
}

export class PostQuantumAEAD {
  private static readonly KEY_SIZE = 64; // 512-bit key (2x 256-bit keys)
  private static readonly NONCE_SIZE = 36; // 12-byte GCM IV + 24-byte XChaCha nonce
  private static readonly GCM_IV_SIZE = 12;
  private static readonly XCHACHA_NONCE_SIZE = 24;
  private static readonly MAC_SIZE = 32;

  static extractNonceContext(nonce: Uint8Array): Uint8Array {
    if (nonce.length !== PostQuantumAEAD.NONCE_SIZE) {
      throw new Error(`Nonce must be ${PostQuantumAEAD.NONCE_SIZE} bytes`);
    }
    return nonce.slice(PostQuantumAEAD.GCM_IV_SIZE);
  }

  /**
   * Derive 64-byte encryption key from 32-byte input using quantum-resistant KDF
   */
  private static deriveDoubleKey(inputKey: Uint8Array): { k1: Uint8Array; k2: Uint8Array; macKey: Uint8Array } {
    if (inputKey.length !== 32) {
      throw new Error('Input key must be 32 bytes');
    }
    // Use SHA3-512 to derive 64-byte key material (quantum-resistant hash)
    const expanded = sha3_512(inputKey);
    const k1 = expanded.slice(0, 32); // AES-256-GCM key
    const k2 = expanded.slice(32, 64); // XChaCha20-Poly1305 key
    
    // Derive separate MAC key using BLAKE3 with domain separation
    const macKey = blake3(PostQuantumUtils.concatBytes(
      new TextEncoder().encode('quantum-secure-mac-v1'),
      inputKey
    ), { dkLen: 32 });
    
    return { k1, k2, macKey };
  }

  static encrypt(
    plaintext: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array,
    explicitNonce?: Uint8Array
  ): { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array } {
    const nonce = explicitNonce ?? PostQuantumAEAD.generateNonce();
    if (key.length !== 32) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    if (nonce.length !== PostQuantumAEAD.NONCE_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PostQuantumAEAD.NONCE_SIZE}-byte nonce`);
    }

    const aadBytes = additionalData || new Uint8Array(0);
    const { k1, k2, macKey } = PostQuantumAEAD.deriveDoubleKey(key);

    try {
      // Layer 1: AES-256-GCM encryption (provides ~128-bit post-quantum security via Grover)
      const iv = nonce.slice(0, PostQuantumAEAD.GCM_IV_SIZE);
      const cipher = gcm(k1, iv, aadBytes);
      const layer1 = cipher.encrypt(plaintext);
      
      // Layer 2: XChaCha20-Poly1305 encryption (quantum-resistant stream cipher)
      const xnonce = nonce.slice(PostQuantumAEAD.GCM_IV_SIZE, PostQuantumAEAD.NONCE_SIZE);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      const layer2 = xchacha.encrypt(layer1);
      
      // Layer 3: BLAKE3 MAC for post-quantum authentication
      const macInput = PostQuantumUtils.concatBytes(layer2, aadBytes, nonce);
      const mac = blake3(macInput, { key: macKey });
      
      // Return ciphertext and MAC as separate components
      return { ciphertext: layer2, nonce, tag: mac };
    } finally {
      // Wipe derived keys from memory
      PostQuantumUtils.clearMemory(k1);
      PostQuantumUtils.clearMemory(k2);
      PostQuantumUtils.clearMemory(macKey);
    }
  }

  private static generateNonce(): Uint8Array {
    // Generate full 36-byte nonce: 12 bytes for AES-GCM IV + 24 bytes for XChaCha20
    const nonce = new Uint8Array(PostQuantumAEAD.NONCE_SIZE);
    const randomBytes = PostQuantumRandom.randomBytes(PostQuantumAEAD.NONCE_SIZE);
    nonce.set(randomBytes, 0);
    return nonce;
  }

  static decrypt(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    tag: Uint8Array,
    key: Uint8Array,
    additionalData?: Uint8Array
  ): Uint8Array {
    if (key.length !== 32) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    if (nonce.length !== PostQuantumAEAD.NONCE_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PostQuantumAEAD.NONCE_SIZE}-byte nonce`);
    }
    if (tag.length !== PostQuantumAEAD.MAC_SIZE) {
      throw new Error(`PostQuantumAEAD requires a ${PostQuantumAEAD.MAC_SIZE}-byte authentication tag`);
    }

    const aadBytes = additionalData || new Uint8Array(0);
    const { k1, k2, macKey } = PostQuantumAEAD.deriveDoubleKey(key);

    try {
      // Verify BLAKE3 MAC
      const macInput = PostQuantumUtils.concatBytes(ciphertext, aadBytes, nonce);
      const expectedMac = blake3(macInput, { key: macKey });
      
      if (!PostQuantumUtils.timingSafeEqual(tag, expectedMac)) {
        throw new Error('BLAKE3 MAC verification failed');
      }
      
      // Layer 2: Decrypt XChaCha20-Poly1305 (reverse order)
      const xnonce = nonce.slice(PostQuantumAEAD.GCM_IV_SIZE, PostQuantumAEAD.NONCE_SIZE);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      const layer1 = xchacha.decrypt(ciphertext);
      
      // Layer 1: Decrypt AES-256-GCM
      const iv = nonce.slice(0, PostQuantumAEAD.GCM_IV_SIZE);
      const decipher = gcm(k1, iv, aadBytes);
      const plaintext = decipher.decrypt(layer1);
      
      return plaintext;
    } finally {
      // Wipe derived keys from memory
      PostQuantumUtils.clearMemory(k1);
      PostQuantumUtils.clearMemory(k2);
      PostQuantumUtils.clearMemory(macKey);
    }
  }
}

export class PostQuantumRandom {
  private static readonly MAX_RANDOM_BYTES_LIMIT = 100 * 1024 * 1024; // 100MB absolute cap
  private static maxRandomBytes = 1_048_576; // Default 1MB limit

  private static ensureSecureRandom(): void {
    if (typeof globalThis === 'undefined' || !globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
      throw new Error('Secure random number generator not available. Requires a secure context (HTTPS).');
    }
  }

  static setMaxRandomBytes(maxBytes: number): void {
    if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
      throw new Error('maxRandomBytes must be a positive integer');
    }
    if (maxBytes > PostQuantumRandom.MAX_RANDOM_BYTES_LIMIT) {
      throw new Error(`maxRandomBytes must not exceed ${PostQuantumRandom.MAX_RANDOM_BYTES_LIMIT} bytes`);
    }
    PostQuantumRandom.maxRandomBytes = maxBytes;
  }

  static randomBytes(length: number): Uint8Array {
    if (!Number.isInteger(length) || length <= 0) {
      throw new Error('Length must be a positive integer');
    }
    if (length > PostQuantumRandom.maxRandomBytes) {
      throw new Error(`Requested random byte length exceeds ${PostQuantumRandom.maxRandomBytes} byte limit`);
    }
    PostQuantumRandom.ensureSecureRandom();

    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }

  static randomUUID(): string {
    PostQuantumRandom.ensureSecureRandom();
    if (typeof globalThis.crypto?.randomUUID === 'function') {
      return globalThis.crypto.randomUUID();
    }

    const base = PostQuantumRandom.randomBytes(32);
    const uuidBytes = blake3(base, { dkLen: 16 });
    uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40;
    uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80;
    const hex = Array.from(uuidBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  }
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const lenA = a?.length || 0; const lenB = b?.length || 0; const maxLen = Math.max(lenA, lenB, 1);
  let result = 0;
  for (let i = 0; i < maxLen; i++) { const av = i < lenA ? a[i] : 0; const bv = i < lenB ? b[i] : 0; result |= av ^ bv; }
  result |= (lenA ^ lenB);
  return result === 0;
}

export class PostQuantumUtils {
  private static readonly MAX_DATA_SIZE = 10 * 1024 * 1024; // 10MB

  static timingSafeEqual = timingSafeEqual;

  static asUint8Array(value: Uint8Array | ArrayBuffer | Buffer | ArrayLike<number>): Uint8Array {
    if (value instanceof Uint8Array) {
      return value;
    }
    if (typeof Buffer !== 'undefined' && value instanceof Buffer) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (Array.isArray(value)) {
      return Uint8Array.from(value);
    }
    throw new Error('Uint8Array-compatible input required');
  }

  static clearMemory(data: Uint8Array): void {
    if (data) {
      data.fill(0);
    }
  }

  /**
   * Best-effort deep zeroization of sensitive data structures.
   */
  static deepClearSensitiveData(root: unknown, seen: Set<unknown> = new Set()): void {
    if (root === null || root === undefined) {
      return;
    }

    const rootType = typeof root;
    if (rootType !== 'object') {
      return;
    }

    if (seen.has(root)) {
      return;
    }
    seen.add(root);

    // Direct byte containers first
    if (root instanceof Uint8Array) {
      PostQuantumUtils.clearMemory(root);
      return;
    }

    if (ArrayBuffer.isView(root)) {
      const view = root as ArrayBufferView;
      const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      PostQuantumUtils.clearMemory(bytes);
      return;
    }

    if (root instanceof ArrayBuffer) {
      const bytes = new Uint8Array(root);
      PostQuantumUtils.clearMemory(bytes);
      return;
    }

    const maybeZeroize = (root as any).zeroize;
    if (typeof maybeZeroize === 'function') {
      try {
        maybeZeroize.call(root);
      } catch {
      }
    }

    if (Array.isArray(root)) {
      for (const item of root) {
        PostQuantumUtils.deepClearSensitiveData(item, seen);
      }
      return;
    }

    if (root instanceof Map) {
      for (const [k, v] of root.entries()) {
        PostQuantumUtils.deepClearSensitiveData(k, seen);
        PostQuantumUtils.deepClearSensitiveData(v, seen);
      }
      return;
    }

    if (root instanceof Set) {
      for (const v of root.values()) {
        PostQuantumUtils.deepClearSensitiveData(v, seen);
      }
      return;
    }

    const obj = root as Record<string | symbol, unknown>;
    for (const key of Object.keys(obj)) {
      try {
        PostQuantumUtils.deepClearSensitiveData(obj[key], seen);
      } catch {
      }
    }

    for (const sym of Object.getOwnPropertySymbols(obj)) {
      try {
        PostQuantumUtils.deepClearSensitiveData(obj[sym], seen);
      } catch {
      }
    }
  }

  static stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
  }

  static bytesToString(bytes: Uint8Array): string {
    return new TextDecoder().decode(bytes);
  }

  static bytesToHex(bytes: Uint8Array | ArrayBuffer | Buffer): string {
    bytes = PostQuantumUtils.asUint8Array(bytes);
    if (bytes.length > PostQuantumUtils.MAX_DATA_SIZE) {
      throw new Error(`Data too large: ${bytes.length} bytes exceeds limit`);
    }
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  static hexToBytes(hex: string): Uint8Array {
    if (typeof hex !== 'string') {
      throw new Error('Hex input must be a string');
    }
    const clean = hex.replace(/\s+/g, '');
    if (!/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error('Invalid hex characters');
    }
    if (clean.length % 2 !== 0) {
      throw new Error('Hex string must have even length');
    }
    if (clean.length > PostQuantumUtils.MAX_DATA_SIZE * 2) {
      throw new Error(`Hex string too long: ${clean.length} chars exceeds limit`);
    }

    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      const byteStr = clean.slice(i, i + 2);
      const val = parseInt(byteStr, 16);
      if (Number.isNaN(val)) {
        throw new Error(`Invalid hex byte: ${byteStr}`);
      }
      bytes[i / 2] = val;
    }
    return bytes;
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    if (typeof base64 !== 'string' || base64.length === 0) {
      throw new Error('Base64 input must be a non-empty string');
    }

    const sanitized = base64.replace(/\s+/g, '');
    if (!/^[-A-Za-z0-9_+/=]*$/.test(sanitized)) {
      throw new Error('Invalid base64 characters');
    }

    try {
      const binary = atob(sanitized);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch {
      throw new Error('Failed to decode base64');
    }
  }

  static uint8ArrayToBase64(bytes: Uint8Array | ArrayBuffer | Buffer): string {
    bytes = PostQuantumUtils.asUint8Array(bytes);

    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  static concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  static randomBytes(length: number): Uint8Array {
    return PostQuantumRandom.randomBytes(length);
  }
}

type SessionRecord = {
  keys: unknown;
  created: number;
  lastUsed: number;
};

export class PostQuantumSession {
  private static readonly DEFAULT_TIMEOUT = 30 * 60 * 1000; // 30 minutes
  private static readonly sessions = new Map<string, SessionRecord>();
  private static sessionTimeout = PostQuantumSession.DEFAULT_TIMEOUT;

  static createSession<T>(sessionId: string, keys: T, timeoutMs: number = PostQuantumSession.sessionTimeout): void {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new Error('Session ID must be a non-empty string');
    }
    const now = Date.now();
    PostQuantumSession.sessions.set(sessionId, {
      keys,
      created: now,
      lastUsed: now
    });
    PostQuantumSession.cleanup(timeoutMs ?? PostQuantumSession.sessionTimeout);
  }

  static getSession<T>(sessionId: string, timeoutMs: number = PostQuantumSession.sessionTimeout): T | null {
    const record = PostQuantumSession.sessions.get(sessionId);
    if (!record) {
      return null;
    }
    const now = Date.now();
    if (now - record.created > timeoutMs) {
      PostQuantumSession.destroySession(sessionId);
      return null;
    }
    record.lastUsed = now;
    return record.keys as T;
  }

  private static securelyEraseKeys(keys: unknown): void {
    try {
      PostQuantumUtils.deepClearSensitiveData(keys);
    } catch {
      // Zeroization is best-effort; never let it throw
    }
  }

  static destroySession(sessionId: string): void {
    const record = PostQuantumSession.sessions.get(sessionId);
    if (!record) {
      return;
    }

    try {
      PostQuantumSession.securelyEraseKeys(record.keys);
    } finally {
      PostQuantumSession.sessions.delete(sessionId);
    }
  }

  private static cleanup(timeoutMs: number): void {
    const now = Date.now();
    for (const [sessionId, record] of PostQuantumSession.sessions.entries()) {
      if (now - record.lastUsed > timeoutMs) {
        PostQuantumSession.destroySession(sessionId);
      }
    }
  }

  static getSessionCount(): number {
    return PostQuantumSession.sessions.size;
  }

  static setSessionTimeout(timeoutMs: number): void {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
      throw new Error('sessionTimeout must be a non-negative finite number');
    }
    PostQuantumSession.sessionTimeout = timeoutMs;
  }

  static getSessionTimeout(): number {
    return PostQuantumSession.sessionTimeout;
  }
}

export class PostQuantumWorker {
  private static worker: Worker | null = null;
  private static pending = new Map<string, {
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
    expectedType: WorkerRequestMessage['type'];
  }>();
  private static readonly trackedKeys = new Map<string, string>();
  private static restartAttempts = 0;
  private static readonly MAX_RESTART_ATTEMPTS = 5;
  private static restarting = false;
  private static authToken: Uint8Array | null = null;

  static supportsWorkers(): boolean {
    return typeof Worker !== 'undefined';
  }

  private static ensureWorker(): void {
    if (PostQuantumWorker.worker || typeof Worker === 'undefined') {
      return;
    }

    let workerUrl: URL;
    try {
      workerUrl = new URL('./post-quantum-worker.ts', (import.meta as any).url);
    } catch {
      const base = typeof window !== 'undefined' && typeof window.location?.href === 'string' ? window.location.href : '';
      if (!base) {
        throw new Error('Unable to resolve post-quantum worker URL');
      }
      workerUrl = new URL('./post-quantum-worker.ts', base);
    }

    const worker = new Worker(workerUrl, { type: 'module' });
    worker.addEventListener('message', (event: MessageEvent<unknown>) => {
      try {
        const data = event.data;
        if (!isPlainObject(data) || hasPrototypePollutionKeys(data)) {
          return;
        }

        if (isWorkerAuthTokenMessage(data)) {
          const tokenBytes = parseAuthTokenHex(data.token);
          if (!tokenBytes) {
            return;
          }
          PostQuantumWorker.authToken = tokenBytes;
          return;
        }

        if (isWorkerResponseFailureMessage(data)) {
          const pending = PostQuantumWorker.pending.get(data.id);
          if (!pending) {
            return;
          }
          PostQuantumWorker.pending.delete(data.id);
          const errorText = data.error.length > 2000 ? data.error.slice(0, 2000) : data.error;
          pending.reject(new Error(errorText));
          return;
        }

        if (!isWorkerResponseSuccessMessage(data)) {
          return;
        }

        const pending = PostQuantumWorker.pending.get(data.id);
        if (!pending) {
          return;
        }
        PostQuantumWorker.pending.delete(data.id);

        if (!validateWorkerResult(pending.expectedType, data.result)) {
          pending.reject(new Error('Invalid worker response'));
          return;
        }

        if (pending.expectedType === 'kem.generateKeyPair' && isKemKeyPairResult(data.result)) {
          PostQuantumWorker.trackedKeys.set(data.result.keyId, data.result.keyId);
        }
        pending.resolve(data.result);
      } catch {
        return;
      }
    });
    worker.addEventListener('error', (error) => {
      PostQuantumWorker.handleWorkerFailure(error);
    });
    worker.addEventListener('messageerror', (error) => {
      PostQuantumWorker.handleWorkerFailure(error);
    });

    PostQuantumWorker.worker = worker;
    PostQuantumWorker.restartAttempts = 0;
  }

  private static handleWorkerFailure(error: unknown): void {
    for (const [id, pending] of PostQuantumWorker.pending.entries()) {
      pending.reject(error);
      PostQuantumWorker.pending.delete(id);
    }
    PostQuantumWorker.worker = null;
    PostQuantumWorker.authToken = null;
    PostQuantumWorker.trackedKeys.clear();
    if (!PostQuantumWorker.restarting) {
      PostQuantumWorker.restarting = true;
      PostQuantumWorker.scheduleRestart();
    }
  }

  private static scheduleRestart(): void {
    if (PostQuantumWorker.restartAttempts >= PostQuantumWorker.MAX_RESTART_ATTEMPTS) {
      console.error('[PostQuantum][Worker] Max restart attempts reached; worker disabled');
      PostQuantumWorker.restarting = false;
      return;
    }
    const delay = Math.min(1000 * Math.pow(2, PostQuantumWorker.restartAttempts), 30_000);
    PostQuantumWorker.restartAttempts += 1;
    setTimeout(() => {
      try {
        PostQuantumWorker.ensureWorker();
      } catch (error) {
        console.error('[PostQuantum][Worker] Restart attempt failed:', error);
      } finally {
        PostQuantumWorker.restarting = false;
      }
    }, delay);
  }

  private static getAuthToken(): string {
    if (!PostQuantumWorker.authToken) {
      throw new Error('Worker auth token not initialized');
    }
    return Array.from(PostQuantumWorker.authToken, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  static async generateKemKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    if (!PostQuantumWorker.supportsWorkers()) {
      return PostQuantumKEM.generateKeyPair();
    }

    try {
      try {
        PostQuantumWorker.ensureWorker();
      } catch {
        return PostQuantumKEM.generateKeyPair();
      }
      if (!PostQuantumWorker.worker) {
        return PostQuantumKEM.generateKeyPair();
      }

      const id = PostQuantumRandom.randomUUID();
      const request: WorkerRequestMessage = { 
        id, 
        type: 'kem.generateKeyPair',
        auth: PostQuantumWorker.getAuthToken()
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.pending.set(id, { resolve, reject, expectedType: request.type });
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch {
      return PostQuantumKEM.generateKeyPair();
    }
  }

  static async destroyKey(keyId: string): Promise<void> {
    if (!PostQuantumWorker.worker || !keyId || !PostQuantumWorker.trackedKeys.has(keyId)) {
      return;
    }

    const id = PostQuantumRandom.randomUUID();
    const request: WorkerRequestMessage = { 
      id, 
      type: 'kem.destroyKey', 
      keyId,
      auth: PostQuantumWorker.getAuthToken()
    };

    PostQuantumWorker.pending.set(id, {
      resolve: () => {
        PostQuantumWorker.trackedKeys.delete(keyId);
      },
      reject: () => {
        PostQuantumWorker.trackedKeys.delete(keyId);
      },
      expectedType: request.type
    });

    try {
      PostQuantumWorker.worker.postMessage(request);
    } catch (error) {
      PostQuantumWorker.pending.delete(id);
      PostQuantumWorker.trackedKeys.delete(keyId);
      throw error;
    }
    await new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        PostQuantumWorker.pending.delete(id);
        PostQuantumWorker.trackedKeys.delete(keyId);
        resolve();
      }, 5000);

      PostQuantumWorker.pending.set(id, {
        resolve: () => {
          clearTimeout(timeout);
          PostQuantumWorker.trackedKeys.delete(keyId);
          resolve();
        },
        reject: () => {
          clearTimeout(timeout);
          PostQuantumWorker.trackedKeys.delete(keyId);
          resolve();
        },
        expectedType: request.type
      });
    });
  }

  static async argon2Hash(params: any): Promise<{ hash: Uint8Array; encoded: string }> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const result = await argon2.hash(params);
      return { hash: result.hash, encoded: result.encoded };
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
         const result = await argon2.hash(params);
         return { hash: result.hash, encoded: result.encoded };
      }

      const id = PostQuantumRandom.randomUUID();
      const request: WorkerRequestMessage = {
        id,
        type: 'argon2.hash',
        params,
        auth: PostQuantumWorker.getAuthToken()
      };

      return await new Promise((resolve, reject) => {
        PostQuantumWorker.pending.set(id, { resolve, reject, expectedType: request.type });
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
    } catch {
      const result = await argon2.hash(params);
      return { hash: result.hash, encoded: result.encoded };
    }
  }

  static async argon2Verify(params: any): Promise<boolean> {
    if (!PostQuantumWorker.supportsWorkers()) {
      const result = await argon2.verify(params);
      // @ts-ignore
      return result.verified === true;
    }

    try {
      PostQuantumWorker.ensureWorker();
      if (!PostQuantumWorker.worker) {
        const result = await argon2.verify(params);
        // @ts-ignore
        return result.verified === true;
      }

      const id = PostQuantumRandom.randomUUID();
      const request: WorkerRequestMessage = {
        id,
        type: 'argon2.verify',
        params,
        auth: PostQuantumWorker.getAuthToken()
      };

      const response = await new Promise<{ verified: boolean }>((resolve, reject) => {
        PostQuantumWorker.pending.set(id, { resolve, reject, expectedType: request.type });
        try {
          PostQuantumWorker.worker!.postMessage(request);
        } catch (error) {
          PostQuantumWorker.pending.delete(id);
          reject(error);
        }
      });
      return response.verified;
    } catch {
      const result = await argon2.verify(params);
      // @ts-ignore
      return result.verified === true;
    }
  }
}

export {
  PostQuantumKEM as KEM,
  PostQuantumSignature as Signature,
  PostQuantumHash as Hash,
  PostQuantumAEAD as AEAD,
  PostQuantumRandom as Random,
  PostQuantumUtils as Utils
};

export interface EncryptedMessagePayload {
  version: number;
  kemCiphertext: Uint8Array;
  aeadCiphertext: Uint8Array;
  aeadNonce: Uint8Array;
  aeadTag: Uint8Array;
  timestamp: number;
}

export class ClientServerProtocol {
  private static MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes (mutable via configure)
  private static readonly MAX_SEEN_ENTRIES = 10_000;
  private static readonly SEEN_BUFFER_RATIO = 0.9; // Evict down to 90% of capacity
  private static readonly SHARED_SECRET_SALT_BYTES = Object.freeze([
    0x45, 0x6e, 0x64, 0x32, 0x45, 0x6e, 0x64, 0x2d,
    0x43, 0x68, 0x61, 0x74, 0x2d, 0x50, 0x51, 0x2d,
    0x48, 0x79, 0x62, 0x72, 0x69, 0x64, 0x2d, 0x4b,
    0x45, 0x4d, 0x2d, 0x4b, 0x65, 0x79, 0x2d, 0x31
  ]);
  private static readonly seenCiphertexts = new Map<string, number>();

  private static getSharedSecretSalt(): Uint8Array {
    return Uint8Array.from(ClientServerProtocol.SHARED_SECRET_SALT_BYTES);
  }

  static async encryptForServer(
    message: Uint8Array,
    serverPublicKey: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<EncryptedMessagePayload> {
    if (!(message instanceof Uint8Array)) {
      throw new Error('Message must be a Uint8Array');
    }
    const { ciphertext: kemCiphertext, sharedSecret } = PostQuantumKEM.encapsulate(serverPublicKey);

    try {
      const contextInfo = `client-to-server-v1:length:${message.length}:ts:${Date.now()}`;
      const encryptionKey = PostQuantumHash.deriveKey(
        sharedSecret,
        ClientServerProtocol.getSharedSecretSalt(),
        contextInfo,
        32
      );

      const { ciphertext: aeadCiphertext, nonce: aeadNonce, tag: aeadTag } = PostQuantumAEAD.encrypt(
        message,
        encryptionKey,
        additionalData
      );

      return {
        version: 1,
        kemCiphertext,
        aeadCiphertext,
        aeadNonce,
        aeadTag,
        timestamp: Date.now()
      };
    } finally {
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }

  static async decryptFromServer(
    encryptedMessage: EncryptedMessagePayload,
    mySecretKey: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    if (!encryptedMessage || typeof encryptedMessage !== 'object') {
      throw new Error('Encrypted message payload required');
    }

    if (encryptedMessage.version !== 1) {
      throw new Error(`Unsupported encrypted payload version: ${encryptedMessage.version}`);
    }

    const age = Date.now() - encryptedMessage.timestamp;
    if (age > ClientServerProtocol.MAX_MESSAGE_AGE_MS) {
      throw new Error('Message too old; possible replay attack');
    }

    const sharedSecret = PostQuantumKEM.decapsulate(encryptedMessage.kemCiphertext, mySecretKey);
    try {
      ClientServerProtocol.recordCiphertext(encryptedMessage.kemCiphertext);
      const contextInfo = `server-to-client-v1:length:${encryptedMessage.aeadCiphertext.length}:ts:${encryptedMessage.timestamp}`;
      const decryptionKey = PostQuantumHash.deriveKey(
        sharedSecret,
        ClientServerProtocol.getSharedSecretSalt(),
        contextInfo,
        32
      );

      return PostQuantumAEAD.decrypt(
        encryptedMessage.aeadCiphertext,
        encryptedMessage.aeadNonce,
        encryptedMessage.aeadTag,
        decryptionKey,
        additionalData
      );
    } finally {
      PostQuantumUtils.clearMemory(sharedSecret);
    }
  }

  private static recordCiphertext(ciphertext: Uint8Array): void {
    const now = Date.now();
    const hash = blake3(ciphertext, { dkLen: 32 });
    const key = PostQuantumUtils.bytesToHex(hash);
    PostQuantumUtils.clearMemory(hash);

    if (ClientServerProtocol.seenCiphertexts.has(key)) {
      throw new Error('Replay detected: ciphertext already processed');
    }

    ClientServerProtocol.seenCiphertexts.set(key, now);
    ClientServerProtocol.evictOldCiphertexts(now);
  }

  private static evictOldCiphertexts(now: number): void {
    const cutoffTime = now - ClientServerProtocol.MAX_MESSAGE_AGE_MS;

    if (ClientServerProtocol.seenCiphertexts.size > ClientServerProtocol.MAX_SEEN_ENTRIES) {
      const entries = Array.from(ClientServerProtocol.seenCiphertexts.entries()).sort((a, b) => a[1] - b[1]);
      const targetSize = Math.floor(ClientServerProtocol.MAX_SEEN_ENTRIES * ClientServerProtocol.SEEN_BUFFER_RATIO);
      const maxToRemove = ClientServerProtocol.seenCiphertexts.size - targetSize;
      let removedCount = 0;

      for (const [key, timestamp] of entries) {
        if (timestamp < cutoffTime || removedCount < maxToRemove) {
          ClientServerProtocol.seenCiphertexts.delete(key);
          removedCount += 1;
          continue;
        }

        if (ClientServerProtocol.seenCiphertexts.size <= ClientServerProtocol.MAX_SEEN_ENTRIES && timestamp >= cutoffTime) {
          break;
        }
      }
    } else {
      for (const [key, timestamp] of Array.from(ClientServerProtocol.seenCiphertexts.entries())) {
        if (timestamp < cutoffTime) {
          ClientServerProtocol.seenCiphertexts.delete(key);
        }
      }
    }
  }

  static getSeenCiphertextsSize(): number {
    return ClientServerProtocol.seenCiphertexts.size;
  }

  static setMaxMessageAge(ageMs: number): void {
    if (!Number.isFinite(ageMs) || ageMs < 0) {
      throw new Error('maxMessageAgeMs must be a non-negative finite number');
    }
    ClientServerProtocol.MAX_MESSAGE_AGE_MS = ageMs;
  }

  static getMaxMessageAge(): number {
    return ClientServerProtocol.MAX_MESSAGE_AGE_MS;
  }
}
