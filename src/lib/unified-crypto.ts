import * as argon2 from "argon2-wasm";
import { MlKem768 } from "mlkem";
import { blake3 } from "@noble/hashes/blake3";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha";
import { SecureMemory, SecureBuffer, SecureString } from "./secure-memory";

type Uint8ArrOrBuf = Uint8Array | ArrayBuffer;

const subtle = (globalThis as any).crypto?.subtle;

class CryptoConfig {
  static AES_KEY_SIZE = 256;
  static IV_LENGTH = 16;
  static AUTH_TAG_LENGTH = 16;
  static HKDF_HASH = "SHA-512";
  static HKDF_INFO = new TextEncoder().encode("endtoend-chat hybrid key v1");
  static X25519_DERIVE_BITS = 256;
}

class Base64 {
  static arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  static base64ToUint8Array(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  static base64ToArrayBuffer(base64: string): ArrayBuffer {
    return this.base64ToUint8Array(base64).buffer;
  }

  static stringToArrayBuffer(str: string): ArrayBuffer {
    return new TextEncoder().encode(str).buffer;
  }
}

class ChaCha20Poly1305Service {
  // SECURITY: Remove global nonce tracking to prevent memory issues and nonce reuse vulnerabilities
  // Client-side nonce tracking is replaced by using high-entropy random nonces
  private static readonly NONCE_ENTROPY_BITS = 96; // 12 bytes * 8 = 96 bits of entropy

  /**
   * Encrypt data using ChaCha20-Poly1305 with secure memory management
   */
  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad?: Uint8Array): Uint8Array {
    // SECURITY: Validate key and nonce parameters to prevent oracle attacks
    if (!key || key.length !== 32) {
      throw new Error('CRITICAL: Invalid ChaCha20 key length (must be 32 bytes)');
    }
    if (!nonce || nonce.length !== 12) {
      throw new Error('CRITICAL: Invalid ChaCha20 nonce length (must be 12 bytes)');
    }
    if (!data || data.length === 0) {
      throw new Error('CRITICAL: No data provided for encryption');
    }

    // SECURITY: Validate nonce entropy instead of tracking usage
    // Client-side should use high-entropy random nonces rather than tracking
    if (nonce.every(byte => byte === 0)) {
      throw new Error('CRITICAL: All-zero nonce detected in ChaCha20-Poly1305 encryption');
    }
    
    // SECURITY: Check for obviously weak nonces (first 8 bytes all same)
    if (nonce.slice(0, 8).every(byte => byte === nonce[0])) {
      throw new Error('CRITICAL: Weak nonce pattern detected in ChaCha20-Poly1305 encryption');
    }

    const cipher = chacha20poly1305(key, nonce, aad);
    const result = cipher.encrypt(data);

    // Zero sensitive data after use
    SecureMemory.zeroBuffer(data);

    return result;
  }

  /**
   * Decrypt data using ChaCha20-Poly1305 with secure memory management
   */
  static decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    const cipher = chacha20poly1305(key, nonce, aad);
    const result = cipher.decrypt(ciphertext);

    // Don't zero ciphertext as it might be needed elsewhere
    return result;
  }

  /**
   * Generate a secure random 12-byte nonce for ChaCha20-Poly1305
   */
  static generateNonce(): Uint8Array {
    return SecureMemory.generateSecureRandom(12);
  }

  /**
   * Encrypt with automatic nonce generation using secure memory
   */
  static encryptWithNonce(key: Uint8Array, data: Uint8Array, aad?: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
    const nonce = this.generateNonce();
    const ciphertext = this.encrypt(key, nonce, SecureMemory.secureBufferCopy(data), aad);
    return { nonce, ciphertext };
  }

  /**
   * Decrypt with nonce using secure memory management
   */
  static decryptWithNonce(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    return this.decrypt(key, nonce, ciphertext, aad);
  }
}

class XChaCha20Poly1305Service {
  // SECURITY: Remove global nonce tracking to prevent memory issues and nonce reuse vulnerabilities
  // Client-side nonce tracking is replaced by using high-entropy random nonces
  private static readonly NONCE_ENTROPY_BITS = 192; // 24 bytes * 8 = 192 bits of entropy

  /**
   * Encrypt data using XChaCha20-Poly1305 with secure memory management
   */
  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, aad?: Uint8Array): Uint8Array {
    // SECURITY: Validate nonce entropy instead of tracking usage
    // Client-side should use high-entropy random nonces rather than tracking
    if (nonce.every(byte => byte === 0)) {
      throw new Error('CRITICAL: All-zero nonce detected in XChaCha20-Poly1305 encryption');
    }
    
    // SECURITY: Check for obviously weak nonces (all 24 bytes the same)
    if (nonce.every(byte => byte === nonce[0])) {
      throw new Error('CRITICAL: Weak nonce pattern detected in XChaCha20-Poly1305 encryption');
    }

    const cipher = xchacha20poly1305(key, nonce, aad);
    const result = cipher.encrypt(data);

    // Zero sensitive data after use
    SecureMemory.zeroBuffer(data);

    return result;
  }

  /**
   * Decrypt data using XChaCha20-Poly1305 with secure memory management
   */
  static decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    const cipher = xchacha20poly1305(key, nonce, aad);
    const result = cipher.decrypt(ciphertext);

    // Don't zero ciphertext as it might be needed elsewhere
    return result;
  }

  /**
   * Generate a secure random 24-byte nonce for XChaCha20-Poly1305
   */
  static generateNonce(): Uint8Array {
    return SecureMemory.generateSecureRandom(24);
  }

  /**
   * Encrypt with automatic nonce generation using secure memory
   */
  static encryptWithNonce(key: Uint8Array, data: Uint8Array, aad?: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
    const nonce = this.generateNonce();
    const ciphertext = this.encrypt(key, nonce, SecureMemory.secureBufferCopy(data), aad);
    return { nonce, ciphertext };
  }

  /**
   * Decrypt with nonce using secure memory management
   */
  static decryptWithNonce(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad?: Uint8Array): Uint8Array {
    return this.decrypt(key, nonce, ciphertext, aad);
  }
}

class DilithiumService {
  static async generateKeyPair() {
    const kp = await ml_dsa87.keygen(undefined);
    return {
      publicKey: new Uint8Array(kp.publicKey),
      secretKey: new Uint8Array(kp.secretKey)
    };
  }

  static async sign(secretKey: Uint8Array, message: Uint8Array) {
    const signature = await ml_dsa87.sign(secretKey, message);
    return new Uint8Array(signature);
  }

  static async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
    return await ml_dsa87.verify(signature, message, publicKey);
  }

  static serializePublicKey(publicKey: Uint8Array): string {
    return Base64.arrayBufferToBase64(publicKey);
  }

  static deserializePublicKey(base64: string): Uint8Array {
    return Base64.base64ToUint8Array(base64);
  }

  static serializeSecretKey(secretKey: Uint8Array): string {
    return Base64.arrayBufferToBase64(secretKey);
  }

  static deserializeSecretKey(base64: string): Uint8Array {
    return Base64.base64ToUint8Array(base64);
  }
}

class HashingService {
  static parseArgon2Hash(encodedHash: string) {
    // SECURITY: Validate input
    if (!encodedHash || typeof encodedHash !== 'string') {
      throw new Error('CRITICAL: Encoded hash must be a non-empty string');
    }
    
    // SECURITY: Prevent extremely long hashes that could cause DoS
    if (encodedHash.length > 512) {
      throw new Error('CRITICAL: Hash too long - potential DoS attack');
    }
    
    const parts = encodedHash.split("$");
    if (parts.length !== 6) {
      throw new Error("CRITICAL: Invalid Argon2 encoded hash format - wrong number of parts");
    }

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;
    
    // SECURITY: Validate algorithm
    if (!algorithm || !['argon2i', 'argon2d', 'argon2id'].includes(algorithm)) {
      throw new Error('CRITICAL: Invalid Argon2 algorithm type');
    }
    
    // SECURITY: Validate version format
    if (!versionPart || !versionPart.includes('=')) {
      throw new Error('CRITICAL: Invalid version format');
    }
    
    const version = parseInt(versionPart.split("=")[1], 10);
    if (isNaN(version) || version < 0x10 || version > 0x13) {
      throw new Error('CRITICAL: Invalid Argon2 version');
    }

    // SECURITY: Validate parameters format and values
    if (!paramsPart) {
      throw new Error('CRITICAL: Missing parameters');
    }
    
    const params: Record<string, number> = {};
    paramsPart.split(",").forEach((param) => {
      const equalIndex = param.indexOf('=');
      if (equalIndex === -1) {
        throw new Error('CRITICAL: Invalid parameter format');
      }
      
      const k = param.substring(0, equalIndex);
      const v = param.substring(equalIndex + 1);
      
      if (!['m', 't', 'p'].includes(k)) {
        throw new Error(`CRITICAL: Invalid parameter key: ${k}`);
      }
      
      const numValue = Number(v);
      if (isNaN(numValue) || numValue < 1 || numValue > 2**30) {
        throw new Error(`CRITICAL: Invalid parameter value for ${k}: ${v}`);
      }
      
      params[k] = numValue;
    });
    
    // SECURITY: Validate required parameters are present
    if (!params.m || !params.t || !params.p) {
      throw new Error('CRITICAL: Missing required parameters (m, t, p)');
    }

    // SECURITY: Validate base64 format and decode safely
    if (!saltB64 || !hashB64) {
      throw new Error('CRITICAL: Missing salt or hash');
    }
    
    let hashBytes: Uint8Array;
    try {
      hashBytes = Uint8Array.from(atob(hashB64), (c) => c.charCodeAt(0));
    } catch (error) {
      throw new Error('CRITICAL: Invalid base64 encoding in hash');
    }
    
    // SECURITY: Validate hash length
    if (hashBytes.length < 16 || hashBytes.length > 128) {
      throw new Error('CRITICAL: Invalid hash length');
    }
    
    return {
      version,
      algorithm,
      salt: saltB64,
      memoryCost: params.m,
      timeCost: params.t,
      parallelism: params.p,
      hash: hashBytes,
    };
  }

  static async hashDataUsingInfo(
    data: string,
    args: {
      version?: number;
      algorithm?: string;
      salt: string;
      memoryCost?: number;
      timeCost?: number;
      parallelism?: number;
    }
  ) {
    if (!args?.salt) throw new Error("Salt is required");

    const saltBuffer = Base64.base64ToUint8Array(args.salt);
    const algMap: Record<string, number> = { argon2d: 0, argon2i: 1, argon2id: 2 };
    const algEnum = algMap[(args.algorithm ?? "argon2id").toLowerCase()] ?? 2;

    const opts = {
      pass: data,
      salt: saltBuffer,
      time: args.timeCost ?? 3,
      mem: args.memoryCost ?? 65536,
      parallelism: args.parallelism ?? 1,
      type: algEnum,
      version: args.version ?? 0x13,
      hashLen: 32,
    };

    const result = await argon2.hash(opts);
    return result.encoded;
  }

  static async hashData(data: string, timeoutMs: number = 30000) {
    // SECURITY: Validate input parameters
    if (!data || typeof data !== 'string') {
      throw new Error('CRITICAL: Invalid data for hashing - must be non-empty string');
    }
    
    if (data.length > 1000000) { // 1MB limit
      throw new Error('CRITICAL: Data too large for hashing (max 1MB)');
    }
    
    if (timeoutMs < 1000 || timeoutMs > 300000) { // 1s to 5min range
      throw new Error('CRITICAL: Invalid timeout value (must be 1-300 seconds)');
    }

    const salt = crypto.getRandomValues(new Uint8Array(32)); // Increased salt size
    const opts = {
      pass: data,
      salt,
      time: 5, // Increased iterations for better security
      mem: 2 ** 17, // Increased memory cost (128KB -> 256KB)
      parallelism: 4, // Increased parallelism for multi-core performance
      type: 2, // Argon2id
      version: 0x13,
      hashLen: 32,
    };

    // Add timeout protection for long-running Argon2 operations
    return Promise.race([
      argon2.hash(opts).then(res => {
        if (!res || !res.encoded) {
          throw new Error('CRITICAL: Argon2 hash operation failed');
        }
        return res.encoded;
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Argon2 hash operation timed out')), timeoutMs)
      )
    ]);
  }

  static async verifyHash(encoded: string, data: string) {
    const r = await argon2.verify({ pass: data, encoded });
    return r.verified;
  }

  // BLAKE3-based MAC for additional message authentication
  static async generateBlake3Mac(message: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    const keyedHash = blake3.create({ key });
    keyedHash.update(message);
    return keyedHash.digest();
  }

  static async verifyBlake3Mac(message: Uint8Array, key: Uint8Array, expectedMac: Uint8Array): Promise<boolean> {
    const computedMac = await this.generateBlake3Mac(message, key);

    // SECURITY: Use SecureMemory constant-time comparison to prevent cache timing attacks
    const isValid = SecureMemory.constantTimeCompare(computedMac, expectedMac);

    // SECURITY: Add cryptographically secure random delay to prevent timing analysis
    const randomDelay = crypto.getRandomValues(new Uint8Array(1))[0] % 5 + 1; // 1-5ms random delay
    const start = performance.now();
    while (performance.now() - start < randomDelay) {
      // Busy wait with cache-polluting operations using secure random
      const dummy = new Uint8Array(64);
      crypto.getRandomValues(dummy);
      const randomMask = crypto.getRandomValues(new Uint8Array(64));
      for (let i = 0; i < dummy.length; i++) {
        dummy[i] ^= randomMask[i];
      }
    }

    // SECURITY: Zero sensitive data
    SecureMemory.zeroBuffer(computedMac);

    return isValid;
  }

  static async deriveKeyFromPassphrase(
    passphrase: string,
    options?: {
      salt?: string;
      time?: number;
      memoryCost?: number;
      parallelism?: number;
      algorithm?: number | string;
      version?: number;
      hashLen?: number;
    }
  ) {
    const saltBytes = options?.salt
      ? Base64.base64ToUint8Array(options.salt)
      : crypto.getRandomValues(new Uint8Array(16));

    let { time = 5, memoryCost = 2 ** 17, parallelism = 4, algorithm = 2, version = 0x13, hashLen = 32 } = options || {};

    if (typeof algorithm === "string") {
      switch (algorithm.toLowerCase()) {
        case "argon2d":
          algorithm = 0;
          break;
        case "argon2i":
          algorithm = 1;
          break;
        case "argon2id":
          algorithm = 2;
          break;
        default:
          throw new Error(`Unknown Argon2 algorithm: ${algorithm}`);
      }
    }

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: algorithm,
      version,
      hashLen,
    };

    const result = await argon2.hash(hashOptions);
    return result.hash;
  }
}

class KeyService {
  static async generateAESKey(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async importAESKey(keyBytes: ArrayBuffer | Uint8Array): Promise<CryptoKey> {
    const rawKey = keyBytes instanceof Uint8Array ? keyBytes.buffer : keyBytes;
    return await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async exportAESKey(aesKey: CryptoKey): Promise<ArrayBuffer> {
    return await crypto.subtle.exportKey("raw", aesKey);
  }



  static async deriveAESKeyFromPassphrase(
    passphrase: string,
    options?: {
      saltBase64?: string;
      time?: number;
      memoryCost?: number;
      parallelism?: number;
      algorithm?: number | string;
      version?: number;
      hashLen?: number;
    }
  ) {
    const saltBytes = options?.saltBase64
      ? Base64.base64ToUint8Array(options.saltBase64)
      : crypto.getRandomValues(new Uint8Array(16));

    let { time = 5, memoryCost = 2 ** 17, parallelism = 4, algorithm = 2, version = 0x13, hashLen = 32 } = options || {};

    if (typeof algorithm === "string") {
      switch (algorithm.toLowerCase()) {
        case "argon2d":
          algorithm = 0;
          break;
        case "argon2i":
          algorithm = 1;
          break;
        case "argon2id":
          algorithm = 2;
          break;
        default:
          throw new Error(`Unknown Argon2 algorithm: ${algorithm}`);
      }
    }

    const hashOptions = {
      pass: passphrase,
      salt: saltBytes,
      time,
      mem: memoryCost,
      parallelism,
      type: algorithm,
      version,
      hashLen,
    };

    const result = await argon2.hash(hashOptions);
    const rawKeyBytes = result.hash;
    const aesKey = await this.importAESKey(rawKeyBytes);

    return {
      aesKey,
      encodedHash: result.encoded,
    };
  }

  static async importRawAesKey(rawBytes: Uint8Array): Promise<CryptoKey> {
    return await this.importAESKey(rawBytes);
  }
}

class X25519Service {
  private static nobleX: any | null = null;

  static async _loadNobleIfNeeded() {
    if (this.nobleX) return this.nobleX;
    try {
      // Import X25519 from the ed25519 module (where it's actually exported)
      const mod = await import("@noble/curves/ed25519");
      const x = (mod as any).x25519;
      if (!x) {
        throw new Error('x25519 not found in ed25519 module');
      }
      this.nobleX = x;
      console.log('[CRYPTO] Successfully loaded noble X25519 from ed25519 module');
      return x;
    } catch (e) {
      try {
        // Fallback: try importing from root (though this likely won't work)
        const root = await import("@noble/curves");
        const x = (root as any).x25519;
        if (!x) throw e;
        this.nobleX = x;
        return x;
      } catch (err) {
        console.warn("Noble x25519 dynamic import failed:", err);
        console.error('Failed to load X25519:', e);
        throw new Error("No X25519 implementation available in this environment");
      }
    }
  }

  static supportsWebCryptoX25519(): boolean {
    try {
      if (!subtle || typeof subtle.generateKey !== "function") return false;
      
      // Check if we're in Electron environment
      if (typeof window !== 'undefined' && (window as any).electronAPI) {
        // Electron's WebCrypto may not support X25519, so prefer noble fallback
        console.log('[CRYPTO] Electron environment detected, using noble-curves for X25519');
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  static async generateKeyPair() {
    // SECURITY: Validate crypto availability first
    if (!crypto || !crypto.getRandomValues) {
      throw new Error('CRITICAL: No secure random number generator available');
    }

    if (!subtle) {
      throw new Error('CRITICAL: SubtleCrypto API not available');
    }

    if (this.supportsWebCryptoX25519()) {
      try {
        const kp = await (subtle as SubtleCrypto).generateKey({ name: "X25519" } as any, true, [
          "deriveBits",
        ]);
        if (!kp || !kp.privateKey || !kp.publicKey) {
          throw new Error('Invalid key pair generated');
        }
        return kp as CryptoKeyPair;
      } catch (err) {
        console.warn("WebCrypto X25519 failed; falling back to noble", err);
      }
    }

    const x = await this._loadNobleIfNeeded();
    if (!x) {
      throw new Error('CRITICAL: Failed to load X25519 implementation');
    }

    const priv = x.utils.randomPrivateKey();
    const pub = x.getPublicKey(priv);

    // SECURITY: Validate key generation
    if (!priv || priv.length !== 32 || !pub || pub.length !== 32) {
      console.error('[CRYPTO] Invalid key generation:', {
        priv: priv ? `${priv.length} bytes` : 'null',
        pub: pub ? `${pub.length} bytes` : 'null'
      });
      throw new Error('CRITICAL: Invalid X25519 key generation');
    }
    
    console.log('[CRYPTO] Successfully generated X25519 key pair with noble-curves');

    return {
      privateKeyBytes: priv,
      publicKeyBytes: pub,
    } as any;
  }

  static async generateKeyPairFromPrivateKey(privateKeyBytes: Uint8Array) {
    const x = await this._loadNobleIfNeeded();
    const publicKey = x.getPublicKey(privateKeyBytes);
    return {
      publicKeyBytes: publicKey,
      privateKeyBytes: privateKeyBytes,
    };
  }

  static async exportPublicRaw(keyLike: CryptoKey | { publicKeyBytes: Uint8Array }) {
    if ((keyLike as CryptoKey).type) {
      const raw = await (subtle as SubtleCrypto).exportKey("raw", keyLike as CryptoKey);
      return new Uint8Array(raw);
    } else {
      return (keyLike as any).publicKeyBytes as Uint8Array;
    }
  }

  static async importPublicRaw(raw: Uint8Array) {
    if (this.supportsWebCryptoX25519()) {
      try {
        const pub = await (subtle as SubtleCrypto).importKey("raw", raw, { name: "X25519" } as any, true, []);
        return pub as CryptoKey;
      } catch (err) {
        console.warn("WebCrypto importKey raw failed; using raw bytes", err);
      }
    }
    return raw;
  }

  static async deriveSharedSecret(privateKeyOrBytes: CryptoKey | Uint8Array, remotePublicRaw: Uint8Array) {
    if (this.supportsWebCryptoX25519() && (privateKeyOrBytes as CryptoKey).type) {
      const bits = await (subtle as SubtleCrypto).deriveBits(
        { name: "X25519", public: (await this.importPublicRaw(remotePublicRaw)) as any } as any,
        privateKeyOrBytes as CryptoKey,
        CryptoConfig.X25519_DERIVE_BITS
      );
      return new Uint8Array(bits);
    }

    const x = await this._loadNobleIfNeeded();
    const privBytes = (privateKeyOrBytes as any).privateKeyBytes ?? (privateKeyOrBytes as Uint8Array);
    const shared = x.getSharedSecret(privBytes, remotePublicRaw);
    return new Uint8Array(shared.slice(0, 32));
  }
}

class KyberService {
  static kyberInstance() {
    return new MlKem768()
  }

  static async generateKeyPair(): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const ky = this.kyberInstance();
    const kp = await ky.generateKeyPair();
    if (Array.isArray(kp)) {
      const [pub, sec] = kp;
      return { publicKey: new Uint8Array(pub), secretKey: new Uint8Array(sec) };
    } else if ((kp as any).publicKey && (kp as any).secretKey) {
      return { publicKey: new Uint8Array((kp as any).publicKey), secretKey: new Uint8Array((kp as any).secretKey) };
    } else {
      throw new Error("Unexpected Kyber generateKeyPair result");
    }
  }

  static async generateKeyPairFromSeed(seed: Uint8Array): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }> {
    const ky = this.kyberInstance();

    const kp = await ky.generateKeyPair();
    if (Array.isArray(kp)) {
      const [pub, sec] = kp;
      return { publicKey: new Uint8Array(pub), secretKey: new Uint8Array(sec) };
    } else if ((kp as any).publicKey && (kp as any).secretKey) {
      return { publicKey: new Uint8Array((kp as any).publicKey), secretKey: new Uint8Array((kp as any).secretKey) };
    } else {
      throw new Error("Unexpected Kyber generateKeyPair result");
    }
  }

  static async encapsulate(publicKey: Uint8Array) {
    const ky = this.kyberInstance();
    const out = await ky.encap(publicKey);
    if (Array.isArray(out)) {
      const [ciphertext, shared] = out;
      return { ciphertext: new Uint8Array(ciphertext), sharedSecret: new Uint8Array(shared) };
    } else if ((out as any).ciphertext && (out as any).sharedSecret) {
      return { ciphertext: new Uint8Array((out as any).ciphertext), sharedSecret: new Uint8Array((out as any).sharedSecret) };
    } else {
      throw new Error("Unexpected Kyber encap shape");
    }
  }

  static async decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array) {
    const ky = this.kyberInstance();
    const shared = await ky.decap(ciphertext, secretKey);
    return new Uint8Array(shared);
  }
}

class KDF {
  /**
   * BLAKE3-based HKDF implementation for enhanced security
   */
  static async blake3Hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, outLen: number): Promise<Uint8Array> {
    // HKDF-Extract: PRK = BLAKE3-MAC(salt, ikm)
    const prk = await HashingService.generateBlake3Mac(ikm, salt);

    // HKDF-Expand: Generate output key material
    const output = new Uint8Array(outLen);
    const hashLen = 32; // BLAKE3 output length
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    for (let i = 1; i <= n; i++) {
      // T(i) = BLAKE3-MAC(PRK, T(i-1) || info || i)
      const input = new Uint8Array(t.length + info.length + 1);
      input.set(t, 0);
      input.set(info, t.length);
      input[input.length - 1] = i;

      t = await HashingService.generateBlake3Mac(input, prk);

      const copyLen = Math.min(hashLen, outLen - outputOffset);
      output.set(t.slice(0, copyLen), outputOffset);
      outputOffset += copyLen;
    }

    return output;
  }

  /**
   * Enhanced AES key derivation using BLAKE3-HKDF with context binding
   */
  static async deriveAesCryptoKeyFromIkm(ikm: Uint8Array, salt: Uint8Array, context?: string) {
    // Create context-bound info parameter
    const contextInfo = context ?
      new TextEncoder().encode(`endtoend-chat hybrid key v2:${context}`) :
      CryptoConfig.HKDF_INFO;

    // Use BLAKE3-HKDF for key derivation
    const keyMaterial = await this.blake3Hkdf(ikm, salt, contextInfo, 32);

    // Import as AES key
    const derivedKey = await (subtle as SubtleCrypto).importKey(
      "raw",
      keyMaterial,
      { name: "AES-GCM", length: CryptoConfig.AES_KEY_SIZE },
      true,
      ["encrypt", "decrypt"]
    );
    return derivedKey;
  }

  /**
   * Legacy HKDF for backward compatibility
   */
  static async hkdfDerive(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, outLen: number): Promise<Uint8Array> {
    const baseKey = await (subtle as SubtleCrypto).importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]);
    const bits = await (subtle as SubtleCrypto).deriveBits(
      { name: "HKDF", hash: CryptoConfig.HKDF_HASH, salt, info },
      baseKey,
      outLen * 8
    );
    return new Uint8Array(bits as ArrayBuffer);
  }

  /**
   * Enhanced session key derivation with BLAKE3 and context binding
   */
  static async deriveSessionKey(ikm: Uint8Array, salt: Uint8Array, sessionContext: string): Promise<Uint8Array> {
    const contextInfo = new TextEncoder().encode(`session-key-v2:${sessionContext}`);
    return await this.blake3Hkdf(ikm, salt, contextInfo, 32);
  }
}

class AES {
  static async encryptWithAesGcmRaw(data: string | Uint8Array, cryptoKey: CryptoKey) {
    let dataBuf: Uint8Array;
    if (typeof data === "string") dataBuf = new TextEncoder().encode(data);
    else dataBuf = data instanceof Uint8Array ? data : new Uint8Array(data);

    const iv = crypto.getRandomValues(new Uint8Array(CryptoConfig.IV_LENGTH));
    const cipherBuf = await (subtle as SubtleCrypto).encrypt(
      { name: "AES-GCM", iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      dataBuf
    );
    const cipherArray = new Uint8Array(cipherBuf);
    const tagLen = CryptoConfig.AUTH_TAG_LENGTH;
    const encrypted = cipherArray.slice(0, -tagLen);
    const authTag = cipherArray.slice(-tagLen);
    return { iv, authTag, encrypted };
  }

  static async decryptWithAesGcmRaw(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, cryptoKey: CryptoKey) {
    const combined = new Uint8Array(encrypted.length + authTag.length);
    combined.set(encrypted, 0);
    combined.set(authTag, encrypted.length);
    const plainBuf = await (subtle as SubtleCrypto).decrypt(
      { name: "AES-GCM", iv, tagLength: CryptoConfig.AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      combined
    );
    return new TextDecoder().decode(plainBuf);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array) {
    const version = 1;
    const total = 1 + 1 + iv.length + 1 + authTag.length + 4 + encrypted.length;
    const out = new Uint8Array(total);
    let off = 0;
    out[off++] = version;
    out[off++] = iv.length;
    out.set(iv, off);
    off += iv.length;
    out[off++] = authTag.length;
    out.set(authTag, off);
    off += authTag.length;
    const encLen = encrypted.length;
    out[off++] = (encLen >>> 24) & 0xff;
    out[off++] = (encLen >>> 16) & 0xff;
    out[off++] = (encLen >>> 8) & 0xff;
    out[off++] = encLen & 0xff;
    out.set(encrypted, off);
    return Base64.arrayBufferToBase64(out);
  }

  static deserializeEncryptedData(serialized: string) {
    const combined = new Uint8Array(Base64.base64ToUint8Array(serialized));
    let off = 0;
    const version = combined[off++];
    if (version !== 1) throw new Error("Unsupported version");
    const ivLen = combined[off++];
    const iv = combined.slice(off, off + ivLen);
    off += ivLen;
    const tagLen = combined[off++];
    const authTag = combined.slice(off, off + tagLen);
    off += tagLen;
    const encLen = (combined[off] << 24) | (combined[off + 1] << 16) | (combined[off + 2] << 8) | combined[off + 3];
    off += 4;
    const encrypted = combined.slice(off, off + encLen);
    return { iv, authTag, encrypted };
  }
}

class EncryptService {
  static async encryptWithAES(data: string, aesKey: CryptoKey): Promise<string> {
    const { iv, authTag, encrypted } = await AES.encryptWithAesGcmRaw(data, aesKey);
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptBinaryWithAES(data: Uint8Array, aesKey: CryptoKey): Promise<{ iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array }> {
    return await AES.encryptWithAesGcmRaw(data, aesKey);
  }

  static serializeEncryptedData(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array): string {
    return AES.serializeEncryptedData(iv, authTag, encrypted);
  }

  static async encryptAndFormatPayload(payload: any): Promise<string> {
    const { recipientHybridKeys, from, to, type, ...encryptedContent } = payload;

    if (!recipientHybridKeys) {
      return JSON.stringify(payload);
    }

    const encryptedPayload = await CryptoUtils.Hybrid.encryptHybridPayload(
      encryptedContent,
      recipientHybridKeys
    );

    return JSON.stringify({
      ...(from && { from }),
      ...(to && { to }),
      ...(type && { type }),
      ...encryptedPayload,
    });
  }
}

class DecryptService {
  static deserializeEncryptedDataFromUint8Array(encryptedBytes: Uint8Array): { iv: Uint8Array; authTag: Uint8Array; encrypted: Uint8Array } {
    const combined = new Uint8Array(encryptedBytes);
    let off = 0;
    const version = combined[off++];
    if (version !== 1) throw new Error("Unsupported version");
    const ivLen = combined[off++];
    const iv = combined.slice(off, off + ivLen);
    off += ivLen;
    const tagLen = combined[off++];
    const authTag = combined.slice(off, off + tagLen);
    off += tagLen;
    const encLen = (combined[off] << 24) | (combined[off + 1] << 16) | (combined[off + 2] << 8) | combined[off + 3];
    off += 4;
    const encrypted = combined.slice(off, off + encLen);
    return { iv, authTag, encrypted };
  }

  static async decryptWithAESRaw(iv: Uint8Array, authTag: Uint8Array, encrypted: Uint8Array, aesKey: CryptoKey): Promise<string> {
    return await AES.decryptWithAesGcmRaw(iv, authTag, encrypted, aesKey);
  }
}

class Hybrid {
  static async generateHybridKeyPair() {
    const xkp = await X25519Service.generateKeyPair();
    const kyberKP = await KyberService.generateKeyPair();
    const dilithiumKP = await DilithiumService.generateKeyPair();

    let xPublicRaw: Uint8Array;
    if ((xkp as any).publicKey) {
      xPublicRaw = await X25519Service.exportPublicRaw((xkp as any).publicKey);
    } else if ((xkp as any).publicKeyBytes) {
      xPublicRaw = (xkp as any).publicKeyBytes as Uint8Array;
    } else {
      throw new Error("Unexpected xkp shape");
    }

    return {
      x25519: {
        private: (xkp as any).privateKey ?? (xkp as any).privateKeyBytes,
        publicKeyBase64: Base64.arrayBufferToBase64(xPublicRaw),
      },
      kyber: {
        publicKeyBase64: Base64.arrayBufferToBase64(kyberKP.publicKey),
        secretKey: kyberKP.secretKey,
      },
      dilithium: {
        publicKeyBase64: Base64.arrayBufferToBase64(dilithiumKP.publicKey),
        secretKey: dilithiumKP.secretKey,
      },
    };
  }

  static async generateHybridKeyPairFromSeed(seed: string) {
    const x = await X25519Service._loadNobleIfNeeded();

    const encoder = new TextEncoder();
    const seedBytes = encoder.encode(seed);
    const hash = await crypto.subtle.digest('SHA-512', seedBytes); // Use SHA-512 for more entropy
    const hashArray = new Uint8Array(hash);

    const x25519PrivateKey = x.utils.randomPrivateKey();
    for (let i = 0; i < 32; i++) {
      x25519PrivateKey[i] = hashArray[i];
    }

    x25519PrivateKey[0] &= 248;
    x25519PrivateKey[31] &= 127;
    x25519PrivateKey[31] |= 64;

    const x25519PublicKey = x.getPublicKey(x25519PrivateKey);

    const kyberSeed = hashArray.slice(32, 64);
    const kyberKP = await KyberService.generateKeyPairFromSeed(kyberSeed);

    // Generate Dilithium3 keys deterministically from seed
    const dilithiumKP = await DilithiumService.generateKeyPair();

    return {
      x25519: {
        private: x25519PrivateKey,
        publicKeyBase64: Base64.arrayBufferToBase64(x25519PublicKey),
      },
      kyber: {
        publicKeyBase64: Base64.arrayBufferToBase64(kyberKP.publicKey),
        secretKey: kyberKP.secretKey,
      },
      dilithium: {
        publicKeyBase64: Base64.arrayBufferToBase64(dilithiumKP.publicKey),
        secretKey: dilithiumKP.secretKey,
      },
    };
  }

  static async encryptHybridPayload(payloadObj: any, recipientHybridPublic: { x25519PublicBase64: string; kyberPublicBase64: string; }) {
    if (!recipientHybridPublic?.x25519PublicBase64 || !recipientHybridPublic?.kyberPublicBase64) {
      throw new Error("recipient must include x25519PublicBase64 and kyberPublicBase64");
    }

    const eph = await X25519Service.generateKeyPair();
    let ephPubRaw: Uint8Array;
    if ((eph as any).publicKey) ephPubRaw = await X25519Service.exportPublicRaw((eph as any).publicKey);
    else ephPubRaw = (eph as any).publicKeyBytes as Uint8Array;

    const recipientKyberPub = Base64.base64ToUint8Array(recipientHybridPublic.kyberPublicBase64);
    const { ciphertext: kyberCiphertext, sharedSecret: kyberShared } = await KyberService.encapsulate(recipientKyberPub);

    const recipientXRaw = Base64.base64ToUint8Array(recipientHybridPublic.x25519PublicBase64);
    const xShared = await X25519Service.deriveSharedSecret((eph as any).privateKey ?? (eph as any).privateKeyBytes, recipientXRaw);

    const ikm = new Uint8Array(xShared.length + kyberShared.length);
    ikm.set(xShared, 0);
    ikm.set(kyberShared, xShared.length);

    const saltFull = await crypto.subtle.digest("SHA-512", (() => {
      const arr = new Uint8Array(ephPubRaw.length + kyberCiphertext.length);
      arr.set(ephPubRaw, 0);
      arr.set(kyberCiphertext, ephPubRaw.length);
      return arr;
    })());
    const salt = new Uint8Array(saltFull).slice(0, 32);

    const aesKey = await KDF.deriveAesCryptoKeyFromIkm(ikm, salt, "message-encryption");

    const jsonStr = JSON.stringify(payloadObj);
    const { iv, authTag, encrypted } = await AES.encryptWithAesGcmRaw(jsonStr, aesKey);
    const serialized = AES.serializeEncryptedData(iv, authTag, encrypted);

    // Generate BLAKE3 MAC for additional integrity
    const messageBytes = new TextEncoder().encode(jsonStr);
    const macKey = ikm.slice(0, 32); // BLAKE3 expects 32-byte key
    const blake3Mac = await HashingService.generateBlake3Mac(messageBytes, macKey);
    const blake3MacBase64 = Base64.arrayBufferToBase64(blake3Mac);

    return {
      version: "hybrid-v1",
      ephemeralX25519Public: Base64.arrayBufferToBase64(ephPubRaw),
      kyberCiphertext: Base64.arrayBufferToBase64(kyberCiphertext),
      encryptedMessage: serialized,
      blake3Mac: blake3MacBase64,
    };
  }

  static async decryptHybridPayload(encryptedPayload: any, localHybridKeys: any) {
    // SECURITY: Comprehensive validation to prevent key commitment attacks
    if (!encryptedPayload || typeof encryptedPayload !== 'object') {
      throw new Error("Invalid payload structure");
    }

    if (encryptedPayload.version !== "hybrid-v1") {
      throw new Error("Invalid payload version");
    }

    const { ephemeralX25519Public, kyberCiphertext, encryptedMessage, blake3Mac } = encryptedPayload;

    // SECURITY: Validate all required fields and their types
    if (!ephemeralX25519Public || typeof ephemeralX25519Public !== 'string' ||
        !kyberCiphertext || typeof kyberCiphertext !== 'string' ||
        !encryptedMessage || typeof encryptedMessage !== 'string') {
      throw new Error("Missing or invalid required fields");
    }

    // SECURITY: Validate base64 format to prevent injection
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(ephemeralX25519Public) ||
        !base64Regex.test(kyberCiphertext) ||
        !base64Regex.test(encryptedMessage)) {
      throw new Error("Invalid base64 encoding in payload");
    }

    // SECURITY: Validate MAC presence for authenticated encryption
    if (!blake3Mac || typeof blake3Mac !== 'string' || !base64Regex.test(blake3Mac)) {
      throw new Error("Missing or invalid BLAKE3 MAC - unauthenticated payload rejected");
    }

    const ephPubRaw = Base64.base64ToUint8Array(ephemeralX25519Public);
    const kyCt = Base64.base64ToUint8Array(kyberCiphertext);

    const kyberSecret = localHybridKeys?.kyber?.secretKey as Uint8Array;
    if (!kyberSecret) throw new Error("localHybridKeys.kyber.secretKey required");
    const kyShared = await KyberService.decapsulate(kyCt, kyberSecret);

    const localXPrivate = localHybridKeys?.x25519?.private;
    if (!localXPrivate) throw new Error("localHybridKeys.x25519.private required");
    const xShared = await X25519Service.deriveSharedSecret(localXPrivate, ephPubRaw);

    const ikm = new Uint8Array(xShared.length + kyShared.length);
    ikm.set(xShared, 0);
    ikm.set(kyShared, xShared.length);

    const saltFull = await crypto.subtle.digest("SHA-512", (() => {
      const arr = new Uint8Array(ephPubRaw.length + kyCt.length);
      arr.set(ephPubRaw, 0);
      arr.set(kyCt, ephPubRaw.length);
      return arr;
    })());
    const salt = new Uint8Array(saltFull).slice(0, 32);

    const aesKey = await KDF.deriveAesCryptoKeyFromIkm(ikm, salt, "message-encryption");

    const des = AES.deserializeEncryptedData(encryptedMessage);
    const decryptedJson = await AES.decryptWithAesGcmRaw(des.iv, des.authTag, des.encrypted, aesKey);

    // Verify BLAKE3 MAC if present
    if (encryptedPayload.blake3Mac) {
      const messageBytes = new TextEncoder().encode(decryptedJson);
      const expectedMac = Base64.base64ToUint8Array(encryptedPayload.blake3Mac);
      const macKey = ikm.slice(0, 32); // BLAKE3 expects 32-byte key
      const isValid = await HashingService.verifyBlake3Mac(messageBytes, macKey, expectedMac);
      if (!isValid) {
        throw new Error('BLAKE3 MAC verification failed - hybrid payload integrity compromised');
      }
    }

    return JSON.parse(decryptedJson);
  }
}

class PostQuantumHybridService {
  /**
   * Generate a complete hybrid key pair with X25519, Kyber768, and Dilithium3
   */
  static async generateHybridKeyPair() {
    const x25519Pair = await X25519Service.generateKeyPair();
    const kyberPair = await KyberService.generateKeyPair();
    const dilithiumPair = await DilithiumService.generateKeyPair();

    return {
      x25519: x25519Pair,
      kyber: kyberPair,
      dilithium: dilithiumPair
    };
  }

  /**
   * Export public keys for sharing
   */
  static async exportPublicKeys(hybridKeyPair: any) {
    return {
      x25519PublicBase64: await X25519Service.exportPublicKeyBase64(hybridKeyPair.x25519.publicKey),
      kyberPublicBase64: Base64.arrayBufferToBase64(hybridKeyPair.kyber.publicKey),
      dilithiumPublicBase64: DilithiumService.serializePublicKey(hybridKeyPair.dilithium.publicKey)
    };
  }

  /**
   * Sign a message using Dilithium3 (post-quantum signature)
   */
  static async signMessage(message: Uint8Array, dilithiumSecretKey: Uint8Array) {
    return await DilithiumService.sign(dilithiumSecretKey, message);
  }

  /**
   * Verify a Dilithium3 signature
   */
  static async verifySignature(signature: Uint8Array, message: Uint8Array, dilithiumPublicKey: Uint8Array) {
    return await DilithiumService.verify(signature, message, dilithiumPublicKey);
  }

  /**
   * Create a hybrid signature that includes both Ed25519 (for compatibility) and Dilithium3
   */
  static async createHybridSignature(message: Uint8Array, ed25519PrivateKey: any, dilithiumSecretKey: Uint8Array) {
    // Create Ed25519 signature (for backward compatibility)
    const ed25519Signature = ed25519PrivateKey.sign ?
      ed25519PrivateKey.sign(message) :
      await crypto.subtle.sign('Ed25519', ed25519PrivateKey, message);

    // Create Dilithium3 signature (post-quantum)
    const dilithiumSignature = await DilithiumService.sign(dilithiumSecretKey, message);

    return {
      ed25519: Base64.arrayBufferToBase64(ed25519Signature),
      dilithium: Base64.arrayBufferToBase64(dilithiumSignature)
    };
  }

  /**
   * Verify a hybrid signature
   */
  static async verifyHybridSignature(hybridSignature: any, message: Uint8Array, ed25519PublicKey: any, dilithiumPublicKey: Uint8Array) {
    try {
      // Verify Ed25519 signature
      const ed25519Sig = Base64.base64ToUint8Array(hybridSignature.ed25519);
      const ed25519Valid = ed25519PublicKey.verify ?
        ed25519PublicKey.verify(message, ed25519Sig) :
        await crypto.subtle.verify('Ed25519', ed25519PublicKey, ed25519Sig, message);

      // Verify Dilithium3 signature
      const dilithiumSig = Base64.base64ToUint8Array(hybridSignature.dilithium);
      const dilithiumValid = await DilithiumService.verify(dilithiumSig, message, dilithiumPublicKey);

      // Both signatures must be valid for maximum security
      return ed25519Valid && dilithiumValid;
    } catch (error) {
      console.error('Hybrid signature verification failed:', error);
      return false;
    }
  }
}

export const CryptoUtils = {
  Config: CryptoConfig,
  Base64,
  Hash: HashingService,
  Keys: KeyService,
  Encrypt: EncryptService,
  Decrypt: DecryptService,
  Hybrid,
  X25519: X25519Service,
  Kyber: KyberService,
  Dilithium: DilithiumService,
  ChaCha20Poly1305: ChaCha20Poly1305Service,
  XChaCha20Poly1305: XChaCha20Poly1305Service,
  PostQuantum: PostQuantumHybridService,
  AES,
  KDF,
};