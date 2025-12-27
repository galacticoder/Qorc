import crypto, { webcrypto } from 'crypto';
import argon2 from 'argon2';
import { MlKem1024 } from 'mlkem';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha3_512, shake256, shake128 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { randomUUID } from 'crypto';
import { logger } from './crypto-logger.js';
import { canonicalizeRoutingHeader as canonicalizeRoutingHeaderHelper, buildRoutingHeader as buildRoutingHeaderHelper, computeRoutingDigest as computeRoutingDigestHelper, normalizePayload as normalizePayloadHelper, signRoutingHeader as signRoutingHeaderHelper, verifyRoutingHeader as verifyRoutingHeaderHelper, base64ToUint8Array, uint8ArrayToBase64 } from './helpers.js';
import { PostQuantumHash } from './post-quantum-hash.js';

function ensureUint8Array(value, label) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === 'string') {
    try {
      return QuantumHashService.base64ToUint8Array(value);
    } catch {
      throw new Error(`${label} must be base64 or Uint8Array`);
    }
  }
  throw new Error(`${label} must be Uint8Array, ArrayBuffer view, or base64 string`);
}


function concatUint8Arrays(...arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

function deriveInnerKeyMaterial(pqSharedSecret, classicalSharedSecret, salt, routingDigest) {
  const combined = new Uint8Array(pqSharedSecret.length + classicalSharedSecret.length);
  combined.set(pqSharedSecret, 0);
  combined.set(classicalSharedSecret, pqSharedSecret.length);

  const info = `inner-envelope:${QuantumHashService.arrayBufferToBase64(routingDigest)}`;
  const okm = PostQuantumHash.deriveKey(combined, salt, info, 64);
  const encKey = okm.slice(0, 32);
  const macKey = okm.slice(32, 64);
  SecureMemory.wipe(okm);
  SecureMemory.wipe(combined);
  return { encKey, macKey };
}

// Minimum/maximum password length for security
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 1024;

// Secure memory utilities for wiping sensitive buffers
class SecureMemory {
  static wipe(buf) {
    try {
      if (buf instanceof Uint8Array || Buffer.isBuffer(buf)) {
        crypto.randomFillSync(buf);
        buf.fill(0);
      }
    } catch { }
  }
  static wipeAll(...buffers) {
    for (const b of buffers) this.wipe(b);
  }
}

class PostQuantumAEAD {
  constructor(key) {
    if (!key || key.length !== 32) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    this.key = key;
  }

  // Derive 64-byte key material from 32-byte input
  _deriveDoubleKey(inputKey) {
    const expanded = sha3_512(inputKey);
    const k1 = expanded.slice(0, 32);
    const k2 = expanded.slice(32, 64);
    const macKey = blake3(Buffer.concat([
      Buffer.from('quantum-secure-mac-v1'),
      inputKey
    ]), { dkLen: 32 });

    return { k1, k2, macKey };
  }

  encrypt(plaintext, nonce, aad) {
    if (!plaintext || !nonce) {
      throw new Error('Plaintext and nonce are required');
    }
    if (nonce.length !== 36) {
      throw new Error('Nonce must be 36 bytes for PostQuantumAEAD (12 AES-GCM + 24 XChaCha20)');
    }

    const aadBytes = aad || Buffer.alloc(0);
    const { k1, k2, macKey } = this._deriveDoubleKey(this.key);

    try {
      // Layer 1: AES-256-GCM encryption
      const iv = nonce.slice(0, 12);
      const cipher = gcm(k1, iv, aadBytes);
      const layer1 = cipher.encrypt(plaintext);

      // Layer 2: XChaCha20-Poly1305 encryption
      const xnonce = nonce.slice(12, 36);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      const layer2 = xchacha.encrypt(layer1);

      // Layer 3: BLAKE3 MAC for post-quantum authentication
      const macInput = Buffer.concat([layer2, aadBytes, nonce]);
      const mac = blake3(macInput, { key: macKey });

      return {
        ciphertext: Buffer.from(layer2),
        tag: Buffer.from(mac)
      };
    } finally {
      SecureMemory.wipeAll(k1, k2, macKey);
    }
  }

  decrypt(ciphertext, nonce, tag, aad) {
    if (!ciphertext || !nonce || !tag) {
      throw new Error('Ciphertext, nonce, and tag are required');
    }
    if (nonce.length !== 36) {
      throw new Error('Nonce must be 36 bytes for PostQuantumAEAD (12 AES-GCM + 24 XChaCha20)');
    }
    if (tag.length !== 32) {
      throw new Error('Tag must be 32 bytes (BLAKE3 MAC)');
    }

    const aadBytes = aad || Buffer.alloc(0);
    const { k1, k2, macKey } = this._deriveDoubleKey(this.key);

    try {
      const macInput = Buffer.concat([ciphertext, aadBytes, nonce]);
      const expectedMac = blake3(macInput, { key: macKey });

      if (!QuantumHashService.constantTimeCompare(tag, expectedMac)) {
        throw new Error('BLAKE3 MAC verification failed');
      }

      // Layer 2: Decrypt XChaCha20-Poly1305
      const xnonce = nonce.slice(12, 36);
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      const layer1 = xchacha.decrypt(ciphertext);

      // Layer 1: Decrypt AES-256-GCM
      const iv = nonce.slice(0, 12);
      const decipher = gcm(k1, iv, aadBytes);
      const plaintext = decipher.decrypt(layer1);

      return Buffer.from(plaintext);
    } catch (error) {
      throw new Error(`PostQuantumAEAD decryption failed: ${error.message}`);
    } finally {
      SecureMemory.wipeAll(k1, k2, macKey);
    }
  }

  static encrypt(plaintext, key, aad, explicitNonce) {
    const keyBytes = ensureUint8Array(key, 'PostQuantumAEAD.encrypt.key');
    const nonce = explicitNonce
      ? ensureUint8Array(explicitNonce, 'PostQuantumAEAD.encrypt.nonce')
      : QuantumRandomGenerator.generateRandomBytes(36);
    const aadBytes = aad ? ensureUint8Array(aad, 'PostQuantumAEAD.encrypt.aad') : undefined;
    const aead = new PostQuantumAEAD(keyBytes);
    const { ciphertext, tag } = aead.encrypt(ensureUint8Array(plaintext, 'PostQuantumAEAD.encrypt.plaintext'), nonce, aadBytes);
    return { ciphertext: ensureUint8Array(ciphertext, 'PostQuantumAEAD.encrypt.ciphertext'), nonce, tag: ensureUint8Array(tag, 'PostQuantumAEAD.encrypt.tag') };
  }

  static decrypt(ciphertext, nonce, tag, key, aad) {
    const keyBytes = ensureUint8Array(key, 'PostQuantumAEAD.decrypt.key');
    const nonceBytes = ensureUint8Array(nonce, 'PostQuantumAEAD.decrypt.nonce');
    const tagBytes = ensureUint8Array(tag, 'PostQuantumAEAD.decrypt.tag');
    const cipherBytes = ensureUint8Array(ciphertext, 'PostQuantumAEAD.decrypt.ciphertext');
    const aadBytes = aad ? ensureUint8Array(aad, 'PostQuantumAEAD.decrypt.aad') : undefined;
    const aead = new PostQuantumAEAD(keyBytes);
    return aead.decrypt(cipherBytes, nonceBytes, tagBytes, aadBytes);
  }
}

export function generateDeterministicId(prefix, ...parts) {
  const input = parts.filter(Boolean).join('::');
  const hash = blake3(Buffer.from(input || randomUUID())).slice(0, 16);
  return `${prefix}_${Buffer.from(hash).toString('hex')}`;
}

export function anonymizeIdentifier(identifier) {
  if (!identifier || typeof identifier !== 'string') {
    throw new Error('anonymizeIdentifier requires a valid string identifier');
  }
  const bytes = blake3(Buffer.from(identifier)).slice(0, 12);
  return Buffer.from(bytes).toString('hex');
}


// Cryptographic configuration
class CryptoConfig {
  // Security levels
  static SECURITY_LEVEL = 256;              // 256-bit quantum security
  static CLASSICAL_SECURITY_LEVEL = 256;    // Classical security level
  static POST_QUANTUM_SECURITY_LEVEL = 256; // Post-quantum security level

  // Advanced encryption standards
  static AES_KEY_SIZE = 256;                // AES-256 
  static XCHACHA20_KEY_SIZE = 32;           // XChaCha20 key size (256-bit)
  static XCHACHA20_NONCE_SIZE = 24;         // XChaCha20 nonce size (192-bit)

  // Enhanced authentication
  static AUTH_TAG_LENGTH = 16;              // 128-bit authentication tags
  static IV_LENGTH = 16;                    // 128-bit IVs
  static SALT_LENGTH = 64;                  // 512-bit salts
  static X25519_DERIVE_BITS = 256;          // Derive 256-bit shared secret

  // Post-quantum key exchange
  static ML_KEM_LEVEL = 1024;               // ML-KEM-1024
  static ML_DSA_LEVEL = 87;                 // ML-DSA-87

  // Advanced key derivation
  static HKDF_HASH = 'SHA-512';              // SHA-512 for HKDF
  static HKDF_INFO = new TextEncoder().encode('Qor-chat hybrid key v2');
  static HKDF_INFO_CLIENT_COMPATIBLE = new TextEncoder().encode('Qor-chat post-quantum v1');
  static SCRYPT_N = 65536;
  static SCRYPT_R = 16;
  static SCRYPT_P = 2;

  // Argon2id parameters
  static get ARGON2_TIME() {
    const MIN_TIME = 3;
    const DEFAULT_TIME = 4;
    const MAX_TIME = 10;
    const envValue = parseInt(process.env.ARGON2_TIME, 10);
    if (Number.isInteger(envValue)) {
      if (envValue < MIN_TIME) return MIN_TIME;
      if (envValue > MAX_TIME) return MAX_TIME;
      return envValue;
    }
    return DEFAULT_TIME;
  }

  static get ARGON2_MEMORY() {
    const MIN = 1 << 17; // 128 MiB
    const DEF = 1 << 18; // 256 MiB
    const MAX = 1 << 20; // 1 GiB
    const envValue = parseInt(process.env.ARGON2_MEMORY, 10);
    if (Number.isInteger(envValue)) {
      if (envValue < MIN) return MIN;
      if (envValue > MAX) return MAX;
      return envValue;
    }
    return DEF;
  }

  static get ARGON2_PARALLELISM() {
    return 4;
  }

  static ENTROPY_BITS = 512;
  static TIMING_ROUNDS = 10;
  static PROTOCOL_VERSION = 'quantum-v2';
}

class QuantumRandomGenerator {
  // Generate random bytes using multiple entropy sources
  static async generateSecureRandom(length, useTimingEntropy = false) {
    if (!Number.isInteger(length) || length < 0) {
      throw new Error(`Invalid random length: ${length} - must be non-negative integer`);
    }

    if (length > 1048576) {
      throw new Error(`Random length too large: ${length} - maximum 1MB`);
    }

    try {
      const systemRandom = new Uint8Array(crypto.randomBytes(length));

      if (!useTimingEntropy) {
        return systemRandom;
      }

      const timingEntropy = await this.generateTimingEntropy(Math.min(32, length));

      const combinedEntropy = new Uint8Array(systemRandom.length + timingEntropy.length);
      combinedEntropy.set(systemRandom, 0);
      combinedEntropy.set(timingEntropy, systemRandom.length);

      return shake256(combinedEntropy, { dkLen: length });
    } catch (error) {
      logger.error('Failed to generate quantum-resistant random bytes', error);
      throw new Error('Failed to generate quantum-resistant random bytes');
    }
  }

  // Generate timing-based entropy
  static async generateTimingEntropy(length = 32) {
    const measurements = [];
    const loopSchedule = await QuantumRandomGenerator.generateSecureRandom(CryptoConfig.TIMING_ROUNDS);

    for (let i = 0; i < CryptoConfig.TIMING_ROUNDS; i++) {
      const start = process.hrtime.bigint();

      const iterationCount = 512 + (loopSchedule[i] % 768);
      for (let j = 0; j < iterationCount; j++) {
        const data = Buffer.from(String(j + i * 1000));
        if (j % 4 === 0) blake3(data);
        else if (j % 4 === 1) sha3_512(data);
        else if (j % 4 === 2) shake256(data, { dkLen: 16 });
        else shake128(data, 16);
      }

      const end = process.hrtime.bigint();
      measurements.push(end - start);

      const delayMs = loopSchedule[i] % 10;
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }

    const timingData = Buffer.from(measurements.map(m => m.toString(16)).join(''));
    return shake256(timingData, { dkLen: length });
  }

  // Generate random bytes
  static generateRandomBytes(length) {
    if (!Number.isInteger(length) || length < 0) {
      throw new Error(`Invalid random length: ${length} - must be non-negative integer`);
    }
    return new Uint8Array(crypto.randomBytes(length));
  }

  // Generate cryptographically secure salt
  static generateSalt(length = CryptoConfig.SALT_LENGTH) {
    return this.generateRandomBytes(length);
  }

  // Generate quantum-resistant nonce
  static generateNonce(length = CryptoConfig.XCHACHA20_NONCE_SIZE) {
    return this.generateRandomBytes(length);
  }

  // Generate UUID v4
  static generateUUID() {
    return randomUUID();
  }

}

class QuantumHashService {
  static stringToUint8Array(str) {
    return new TextEncoder().encode(str);
  }

  static arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Buffer.from(bytes).toString('base64');
  }

  static base64ToUint8Array(base64) {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }

  static toUint8Array(value, name) {
    if (value instanceof Uint8Array) {
      return value;
    }
    if (Buffer.isBuffer(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (typeof value === 'string') {
      return this.stringToUint8Array(value);
    }
    throw new TypeError(`${name} must be a byte array or convertible to Uint8Array`);
  }

  // Quantum-resistant hash using multiple algorithms
  static async digestQuantumResistant(...parts) {
    const arrays = parts.map(p => (p instanceof Uint8Array ? p : new Uint8Array(p)));
    const totalLen = arrays.reduce((s, a) => s + a.length, 0);
    const joined = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) { joined.set(a, offset); offset += a.length; }
    return shake256(joined, { dkLen: 64 });
  }


  // BLAKE3-based MAC with quantum-resistant key derivation
  static async generateBlake3Mac(message, key) {
    if (!key || key.length < 16) {
      throw new Error('BLAKE3 MAC requires key length >= 16 bytes');
    }
    const messageBytes = QuantumHashService.toUint8Array(message, 'message');
    const keyBytes = QuantumHashService.toUint8Array(key, 'key');

    // Normalize key to 32 bytes if needed
    let normalizedKey = keyBytes;
    if (keyBytes.length !== 32) {
      normalizedKey = blake3(keyBytes, { dkLen: 32 });
    }

    return blake3(messageBytes, { key: normalizedKey });
  }

  // SHA-512 digest for a single byte array
  static async digestSHA512(data) {
    if (!data) {
      throw new Error('digestSHA512: data parameter must be defined');
    }
    if (!data.length) {
      throw new Error('digestSHA512: data parameter must have length > 0');
    }
    return new Uint8Array(await webcrypto.subtle.digest('SHA-512', data));
  }

  // SHA-512 digest for combining two byte arrays
  static async digestSHA512Bytes(a, b) {
    if (!a || !b) {
      throw new Error('digestSHA512Bytes: both parameters must be defined');
    }
    if (!a.length || !b.length) {
      throw new Error('digestSHA512Bytes: both parameters must have length > 0');
    }
    const combined = new Uint8Array(a.length + b.length);
    combined.set(a, 0);
    combined.set(b, a.length);
    return new Uint8Array(await webcrypto.subtle.digest('SHA-512', combined));
  }

  // BLAKE3 hash function
  static blake3(data) {
    return blake3(data);
  }

  // BLAKE3 keyed hash
  static blake3Keyed(data, key) {
    const dataBytes = QuantumHashService.toUint8Array(data, 'data');
    const keyBytes = QuantumHashService.toUint8Array(key, 'key');
    const normalizedKey = keyBytes.length === 32 ? keyBytes : blake3(keyBytes, { dkLen: 32 });
    return blake3(dataBytes, { key: normalizedKey });
  }

  // SHA3-512 hash
  static sha3_512(data) {
    const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    return sha3_512(dataBytes);
  }

  // SHAKE256 XOF
  static shake256(data, dkLen) {
    const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    return shake256(dataBytes, { dkLen });
  }

  // Hash data using Argon2id
  static async hashData(data) {
    const salt = new Uint8Array(crypto.randomBytes(16));
    const hash = await argon2.hash(Buffer.from(data), {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
      salt,
    });
    return hash;
  }

  // Hash data using provided Argon2 parameters
  static async hashDataUsingInfo(data, params) {
    const salt = params.salt ?
      (typeof params.salt === 'string' ? Buffer.from(params.salt, 'base64') : Buffer.from(params.salt)) :
      new Uint8Array(crypto.randomBytes(16));
    const hash = await argon2.hash(Buffer.from(data), {
      type: argon2.argon2id,
      memoryCost: params.memoryCost || 65536,
      timeCost: params.timeCost || 3,
      parallelism: params.parallelism || 4,
      salt,
    });
    return hash;
  }

  // Parse Argon2 hash string
  static async parseArgon2Hash(encodedHash) {
    const parts = encodedHash.split("$");
    if (parts.length !== 6) {
      throw new Error("Invalid Argon2 encoded hash format");
    }

    const [, algorithm, versionPart, paramsPart, saltB64, hashB64] = parts;

    let version;
    if (typeof versionPart === 'string') {
      const eqIndex = versionPart.indexOf('=');
      version = eqIndex >= 0 ? parseInt(versionPart.slice(eqIndex + 1), 10) : parseInt(versionPart, 10);
    } else {
      version = NaN;
    }

    const params = paramsPart.split(',');
    const memoryCost = parseInt(params[0].split('=')[1]);
    const timeCost = parseInt(params[1].split('=')[1]);
    const parallelism = parseInt(params[2].split('=')[1]);

    return {
      algorithm,
      version,
      memoryCost,
      timeCost,
      parallelism,
      salt: Buffer.from(saltB64, 'base64'),
      hash: Buffer.from(hashB64, 'base64')
    };
  }

  // BLAKE3-based HKDF
  static async blake3Hkdf(ikm, salt, info, outLen) {
    const prk = await this.generateBlake3Mac(ikm, salt);

    const output = new Uint8Array(outLen);
    const hashLen = 32;
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    for (let i = 1; i <= n; i++) {
      const input = new Uint8Array(t.length + info.length + 1);
      input.set(t, 0);
      input.set(info, t.length);
      input[input.length - 1] = i;

      t = await this.generateBlake3Mac(input, prk);

      const copyLen = Math.min(hashLen, outLen - outputOffset);
      output.set(t.slice(0, copyLen), outputOffset);
      outputOffset += copyLen;
    }

    return output;
  }

  // Generate a fingerprint for a key
  static async fingerprintKey(key) {
    const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(key);
    return blake3(keyBytes).slice(0, 16);
  }

  // Constant-time comparison to prevent timing attacks
  static constantTimeCompare(a, b) {
    if (!a || !b) {
      return false;
    }

    const aBuf = Buffer.from(a);
    const bBuf = Buffer.from(b);

    if (aBuf.length !== bBuf.length) {
      const maxLen = Math.max(aBuf.length, bBuf.length);
      const paddedA = Buffer.alloc(maxLen);
      const paddedB = Buffer.alloc(maxLen);
      aBuf.copy(paddedA, 0, 0, Math.min(aBuf.length, maxLen));
      bBuf.copy(paddedB, 0, 0, Math.min(bBuf.length, maxLen));

      try {
        crypto.timingSafeEqual(paddedA, paddedB);
      } catch { }
      return false;
    }

    try {
      return crypto.timingSafeEqual(aBuf, bBuf);
    } catch {
      return false;
    }
  }

  // Verify BLAKE3 concatenation MAC
  static async verifyBlake3ConcatMac(message, key, expectedMac) {
    const computedMac = await this.generateBlake3ConcatMac(message, key);
    return QuantumHashService.safeCompare(computedMac, expectedMac);
  }

  static async generateBlake3ConcatMac(message, key) {
    const messageBytes = QuantumHashService.toUint8Array(message, 'message');
    const keyBytes = QuantumHashService.toUint8Array(key, 'key');
    const enhancedKey = shake256(keyBytes, { dkLen: 64 });
    const macKey = enhancedKey.slice(0, 32);
    return blake3(messageBytes, { key: macKey });
  }

  // Quantum-resistant MAC using multiple algorithms
  static async generateQuantumMAC(message, key) {
    const messageBytes = QuantumHashService.toUint8Array(message, 'message');
    const keyBytes = QuantumHashService.toUint8Array(key, 'key');
    const blake3Mac = await this.generateBlake3Mac(messageBytes, keyBytes);
    const sha3Mac = sha3_512(Buffer.concat([keyBytes.slice(0, 64), messageBytes]));
    const shakeKey = shake256(keyBytes, { dkLen: 32 });
    const shakeMac = shake256(Buffer.concat([shakeKey, messageBytes]), { dkLen: 32 });

    const combined = new Uint8Array(blake3Mac.length + sha3Mac.length + shakeMac.length);
    combined.set(blake3Mac, 0);
    combined.set(sha3Mac, blake3Mac.length);
    combined.set(shakeMac, blake3Mac.length + sha3Mac.length);

    return blake3(combined);
  }

  static async verifyBlake3Mac(message, key, expectedMac) {
    const computedMac = await this.generateBlake3Mac(message, key);
    return QuantumHashService.safeCompare(computedMac, expectedMac);
  }

  static async verifyQuantumMAC(message, key, expectedMac) {
    const computedMac = await this.generateQuantumMAC(message, key);
    return QuantumHashService.safeCompare(computedMac, expectedMac);
  }

  // Quantum-resistant HMAC using BLAKE3
  static async hmacBlake3(key, message) {
    const messageBytes = QuantumHashService.toUint8Array(message, 'message');
    const keyBytes = QuantumHashService.toUint8Array(key, 'key');
    const enhancedKey = shake256(keyBytes, { dkLen: 32 });
    return blake3(messageBytes, { key: enhancedKey });
  }

  // Constant-time comparison
  static constantTimeCompare(a, b) {
    return QuantumHashService.safeCompare(a, b);
  }

  static safeCompare(a, b) {
    if (!a || !b) return false;
    const aBuf = Buffer.from(a);
    const bBuf = Buffer.from(b);
    const maxLen = Math.max(aBuf.length, bBuf.length, 1);
    const pa = Buffer.alloc(maxLen);
    const pb = Buffer.alloc(maxLen);
    aBuf.copy(pa);
    bBuf.copy(pb);
    let isEqual = false;
    try { isEqual = crypto.timingSafeEqual(pa, pb); } catch { isEqual = false; }
    return isEqual && aBuf.length === bBuf.length;
  }

}

class QuantumKyberService {
  static kyberInstance() {
    return new MlKem1024();
  }

  // Generate ML-KEM-1024 key pair
  static async generateKeyPair() {
    const kyber = this.kyberInstance();
    const additionalEntropy = await QuantumRandomGenerator.generateSecureRandom(64);
    const result = await kyber.generateKeyPair(additionalEntropy);

    if (Array.isArray(result)) {
      const [publicKey, secretKey] = result;
      const keyPair = {
        publicKey: new Uint8Array(publicKey),
        secretKey: new Uint8Array(secretKey),
        algorithm: 'ML-KEM-1024',
        securityLevel: CryptoConfig.POST_QUANTUM_SECURITY_LEVEL,
        timestamp: Date.now()
      };

      // Add integrity protection to keys
      keyPair.publicKeyHash = await QuantumHashService.fingerprintKey(keyPair.publicKey);
      keyPair.secretKeyHash = await QuantumHashService.fingerprintKey(keyPair.secretKey);

      return keyPair;
    }

    throw new Error('Failed to generate ML-KEM-1024 key pair');
  }

  // Encapsulation with shared secret derivation
  static async encapsulate(publicKeyBytes) {
    if (!publicKeyBytes || publicKeyBytes.length === 0) {
      throw new Error('Invalid public key for encapsulation');
    }

    const kyber = this.kyberInstance();
    const additionalEntropy = await QuantumRandomGenerator.generateSecureRandom(32);
    const result = await kyber.encap(publicKeyBytes, additionalEntropy);
    const [ciphertext, rawSharedSecret] = result;

    return {
      ciphertext: new Uint8Array(ciphertext),
      sharedSecret: new Uint8Array(rawSharedSecret),
      algorithm: 'ML-KEM-1024',
      timestamp: Date.now()
    };
  }

  // Decapsulation with quantum-resistant shared secret derivation
  static async decapsulate(ciphertextBytes, secretKeyBytes) {
    if (!ciphertextBytes || !secretKeyBytes) {
      throw new Error('Invalid parameters for decapsulation');
    }
    const kyber = this.kyberInstance();
    const rawSharedSecret = await kyber.decap(ciphertextBytes, secretKeyBytes);

    return new Uint8Array(rawSharedSecret);
  }

  // Derive enhanced shared secret
  static async deriveEnhancedSharedSecret(rawSharedSecret, publicKeyBytes) {
    const salt = await QuantumHashService.digestQuantumResistant(publicKeyBytes);
    const info = new TextEncoder().encode('ML-KEM-1024-enhanced-shared-secret-v2');
    return await QuantumKDFService.quantumHKDF(rawSharedSecret, salt.slice(0, 64), info, 64);
  }

  // Validate ML-KEM-1024 key pair integrity with caching
  static async validateKeyPair(keyPair, forceRevalidation = false) {
    if (!keyPair.publicKey || !keyPair.secretKey) {
      return false;
    }

    const cacheTTL = 5 * 60 * 1000;

    if (!forceRevalidation && keyPair._validation) {
      const { valid, ts } = keyPair._validation;
      if (valid !== undefined && (Date.now() - ts) < cacheTTL) {
        return valid;
      }
    }

    // Verify key fingerprints if available
    if (keyPair.publicKeyHash) {
      const computedHash = await QuantumHashService.fingerprintKey(keyPair.publicKey);
      if (!QuantumHashService.constantTimeCompare(keyPair.publicKeyHash, computedHash)) {
        keyPair._validation = { valid: false, ts: Date.now() };
        return false;
      }
    }

    // Test encapsulation/decapsulation only if no cached result
    try {
      const encapResult = await this.encapsulate(keyPair.publicKey);
      const decapSecret = await this.decapsulate(encapResult.ciphertext, keyPair.secretKey, keyPair.publicKey);
      const isValid = QuantumHashService.constantTimeCompare(encapResult.sharedSecret, decapSecret);

      keyPair._validation = { valid: isValid, ts: Date.now() };
      return isValid;
    } catch {
      keyPair._validation = { valid: false, ts: Date.now() };
      return false;
    }
  }

}

class DilithiumService {
  static async generateKeyPair() {
    const { publicKey, secretKey } = await ml_dsa87.keygen();
    return {
      publicKey: publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey),
      secretKey: secretKey instanceof Uint8Array ? secretKey : new Uint8Array(secretKey)
    };
  }

  static async sign(message, secretKey) {
    return ml_dsa87.sign(message, secretKey);
  }

  static async verify(signature, message, publicKey) {
    return ml_dsa87.verify(signature, message, publicKey);
  }
}

class QuantumKDFService {
  // Quantum-resistant HKDF using multiple hash functions
  static async quantumHKDF(ikm, salt, info, outLen) {
    const blake3Prk = await QuantumHashService.generateBlake3Mac(ikm, salt);
    const sha3Prk = sha3_512(Buffer.concat([salt.slice(0, 64), ikm]));
    const shakePrk = shake256(Buffer.concat([salt.slice(0, 32), ikm]), { dkLen: 64 });

    const combinedPrk = new Uint8Array(blake3Prk.length + sha3Prk.length + shakePrk.length);
    combinedPrk.set(blake3Prk, 0);
    combinedPrk.set(sha3Prk, blake3Prk.length);
    combinedPrk.set(shakePrk, blake3Prk.length + sha3Prk.length);

    const masterPrk = blake3(combinedPrk);
    const output = new Uint8Array(outLen);
    const hashLen = 64;
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    for (let i = 1; i <= n; i++) {
      const input = new Uint8Array(t.length + info.length + 1);
      input.set(t, 0);
      input.set(info, t.length);
      input[input.length - 1] = i;

      const blake3T = await QuantumHashService.generateBlake3Mac(input, masterPrk);
      const sha3T = sha3_512(Buffer.concat([masterPrk.slice(0, 64), input]));
      const shakeT = shake256(Buffer.concat([masterPrk.slice(0, 32), input]), { dkLen: 32 });

      const combined = new Uint8Array(blake3T.length + sha3T.length + shakeT.length);
      combined.set(blake3T, 0);
      combined.set(sha3T, blake3T.length);
      combined.set(shakeT, blake3T.length + sha3T.length);

      t = shake256(combined, { dkLen: hashLen });

      const copyLen = Math.min(hashLen, outLen - outputOffset);
      output.set(t.slice(0, copyLen), outputOffset);
      outputOffset += copyLen;
    }

    return output;
  }

  // Derive a KEK from username+password using Argon2id + quantumHKDF.
  static async deriveUsernamePasswordKEK(username, password, options = {}) {
    if (!username || typeof username !== 'string' || username.length < 3) {
      throw new Error('deriveUsernamePasswordKEK: username must be at least 3 characters');
    }
    if (!password || typeof password !== 'string' || password.trim().length < 16) {
      throw new Error('deriveUsernamePasswordKEK: password must be at least 16 characters');
    }

    const pwd = password.trim();
    const usernameBytes = new TextEncoder().encode(String(username));

    const {
      salt,
      timeCost = CryptoConfig.ARGON2_TIME + 1,
      memoryCost = Math.min(CryptoConfig.ARGON2_MEMORY * 2, 1 << 20),
      parallelism = CryptoConfig.ARGON2_PARALLELISM,
      hashLength = 64,
    } = options;

    let saltBuf;
    if (salt) {
      if (salt instanceof Uint8Array || Buffer.isBuffer(salt)) {
        saltBuf = Buffer.from(salt);
      } else if (typeof salt === 'string') {
        saltBuf = Buffer.from(salt, 'base64');
      } else {
        throw new Error('deriveUsernamePasswordKEK: salt must be a Uint8Array, Buffer, or base64 string');
      }
      if (saltBuf.length < 16) {
        throw new Error('deriveUsernamePasswordKEK: salt must be at least 16 bytes');
      }
    } else {
      saltBuf = crypto.randomBytes(32);
    }

    const baseKey = await argon2.hash(pwd, {
      type: argon2.argon2id,
      timeCost,
      memoryCost,
      parallelism,
      hashLength,
      salt: saltBuf,
      raw: true,
    });

    const usernameHash = blake3(usernameBytes);
    const ikm = new Uint8Array(baseKey.length + usernameHash.length);
    ikm.set(baseKey, 0);
    ikm.set(usernameHash, baseKey.length);

    const hkSalt = shake256(saltBuf, { dkLen: 64 });
    const info = new TextEncoder().encode('username-password-kek-v1');

    const kek = await this.quantumHKDF(ikm, hkSalt, info, 32);
    return { kek, salt: new Uint8Array(saltBuf) };
  }

  // AES key derivation using BLAKE3-HKDF
  static async deriveAesKeyFromIkm(ikmUint8Array, saltUint8Array, context) {
    try {
      const contextInfo = context ?
        new TextEncoder().encode(`Qor-chat hybrid key v2:${context}`) :
        CryptoConfig.HKDF_INFO;

      const keyMaterial = await QuantumHashService.blake3Hkdf(ikmUint8Array, saltUint8Array, contextInfo, 32);

      if (!keyMaterial || keyMaterial.length !== 32) {
        throw new Error(`Invalid key material length: ${keyMaterial?.length}`);
      }

      return keyMaterial;
    } catch (error) {
      logger.error('AES key derivation failed', error);
      throw new Error(`AES key derivation failed: ${error.message}`);
    }
  }

  // Session key derivation with BLAKE3 and context binding
  static async deriveSessionKey(ikm, salt, sessionContext) {
    const contextInfo = new TextEncoder().encode(`session-key-v2:${sessionContext}`);
    return await QuantumHashService.blake3Hkdf(ikm, salt, contextInfo, 32);
  }

  // Simple HKDF wrapper for tests using BLAKE3
  static deriveKey(ikm, salt, info, outLen) {
    return PostQuantumHash.deriveKey(ikm, salt, info, outLen);
  }

  // Derive multiple keys with different context strings
  static deriveMultipleKeys(ikm, salt, contexts, outLen) {
    const out = {};
    for (const ctx of contexts) {
      out[ctx] = PostQuantumHash.deriveKey(ikm, salt, ctx, outLen);
    }
    return out;
  }
}

class PostQuantumAESService {
  static async encryptWithPostQuantumAead(data, key) {
    let dataBuf;
    if (typeof data === 'string') dataBuf = new TextEncoder().encode(data);
    else if (data instanceof ArrayBuffer) dataBuf = new Uint8Array(data);
    else if (data instanceof Uint8Array) dataBuf = data;
    else throw new Error('Unsupported data type for PostQuantum encrypt');

    const pqAead = new PostQuantumAEAD(key);
    const nonce = await QuantumRandomGenerator.generateSecureRandom(36);

    const { ciphertext, tag } = pqAead.encrypt(dataBuf, nonce, new TextEncoder().encode('server-aes-service'));

    const encrypted = Buffer.concat([ciphertext, tag]);
    return { nonce, encrypted };
  }

  static async decryptWithPostQuantumAead(nonce, encrypted, key, aad) {
    try {
      if (!nonce || nonce.length !== 36) {
        throw new Error(`Invalid nonce length: ${nonce?.length}, expected 36 bytes`);
      }
      if (!encrypted || encrypted.length < 32) {
        throw new Error('No encrypted data provided or too short');
      }
      if (!key) {
        throw new Error('No key provided');
      }

      const ciphertext = encrypted.slice(0, -32);
      const tag = encrypted.slice(-32);

      const pqAead = new PostQuantumAEAD(key);
      const plainBuf = pqAead.decrypt(ciphertext, nonce, tag, aad);

      return new TextDecoder().decode(plainBuf);
    } catch (error) {
      const errMsg = error?.message || String(error);
      logger.error('PostQuantum decryption failed', {
        nonceLength: nonce?.length,
        encryptedLength: encrypted?.length,
        hasKey: !!key,
        errorMessage: errMsg,
      });
      throw new Error(`PostQuantum decryption failed: ${errMsg}`);
    }
  }

  // Password-based encryption using PostQuantumAEAD
  static async encryptData(data, password) {
    if (typeof password !== 'string' || password.trim().length < MIN_PASSWORD_LENGTH) {
      throw new Error('Password must be a non-empty string with sufficient length');
    }
    const pwdBytes = new TextEncoder().encode(password.trim());
    const salt = QuantumRandomGenerator.generateSalt(32);
    const info = new TextEncoder().encode('pq-password-aead-v1');
    const key = await QuantumHashService.blake3Hkdf(pwdBytes, salt, info, 32);
    const aead = new PostQuantumAEAD(key);
    const nonce = QuantumRandomGenerator.generateNonce(36);
    const plain = data instanceof Uint8Array ? data : new Uint8Array(data);
    const { ciphertext: ct, tag } = aead.encrypt(plain, nonce);
    const ciphertext = Buffer.concat([ct, tag]);

    return { ciphertext, salt, nonce };
  }

  static async decryptData(encrypted, password) {
    if (!encrypted || !encrypted.ciphertext || !encrypted.salt || !encrypted.nonce) {
      throw new Error('Invalid encrypted payload');
    }
    const pwdBytes = new TextEncoder().encode(String(password ?? ''));
    const info = new TextEncoder().encode('pq-password-aead-v1');
    const key = await QuantumHashService.blake3Hkdf(pwdBytes, encrypted.salt, info, 32);
    const aead = new PostQuantumAEAD(key);
    const ct = encrypted.ciphertext.slice(0, -32);
    const tag = encrypted.ciphertext.slice(-32);

    return aead.decrypt(ct, encrypted.nonce, tag);
  }


  static serializeEncryptedData(iv, authTag, encrypted) {
    const version = 1;
    const encryptedLength = encrypted.length;

    const result = new Uint8Array(
      1 +
      1 + iv.length +
      1 + authTag.length +
      4 +
      encrypted.length
    );

    let offset = 0;
    result[offset++] = version;

    result[offset++] = iv.length;
    result.set(iv, offset);
    offset += iv.length;

    result[offset++] = authTag.length;
    result.set(authTag, offset);
    offset += authTag.length;

    result[offset++] = (encryptedLength >> 24) & 0xff;
    result[offset++] = (encryptedLength >> 16) & 0xff;
    result[offset++] = (encryptedLength >> 8) & 0xff;
    result[offset++] = encryptedLength & 0xff;

    result.set(encrypted, offset);

    return Buffer.from(result).toString('base64');
  }

  static deserializeEncryptedData(base64Data) {
    const buffer = Buffer.from(base64Data, 'base64');
    let offset = 0;

    const version = buffer[offset++];
    if (version !== 1) throw new Error(`Unsupported version: ${version}`);

    const ivLength = buffer[offset++];
    const iv = new Uint8Array(buffer.slice(offset, offset + ivLength));
    offset += ivLength;

    const authTagLength = buffer[offset++];
    const authTag = new Uint8Array(buffer.slice(offset, offset + authTagLength));
    offset += authTagLength;

    const encryptedLength =
      (buffer[offset++] << 24) |
      (buffer[offset++] << 16) |
      (buffer[offset++] << 8) |
      buffer[offset++];

    const encrypted = new Uint8Array(buffer.slice(offset, offset + encryptedLength));
    return { iv, authTag, encrypted };
  }
}


function generateX25519PrivateKey() {
  const key = crypto.randomBytes(32);
  key[0] &= 248;
  key[31] &= 127;
  key[31] |= 64;
  return new Uint8Array(key);
}

function createX25519KeyPair() {
  const secretKey = generateX25519PrivateKey();
  const publicKey = x25519.getPublicKey(secretKey);
  return {
    publicKey: new Uint8Array(publicKey),
    secretKey
  };
}

class HybridService {
  static async generateHybridKeyPair() {
    const xPair = createX25519KeyPair();
    const kyberKP = await QuantumKyberService.generateKeyPair();
    const dilithiumKP = await DilithiumService.generateKeyPair();
    return {
      mlKemPublicKey: new Uint8Array(kyberKP.publicKey),
      mlKemSecretKey: new Uint8Array(kyberKP.secretKey),
      x25519PublicKey: new Uint8Array(xPair.publicKey),
      x25519SecretKey: new Uint8Array(xPair.secretKey),
      mlDsaPublicKey: new Uint8Array(dilithiumKP.publicKey),
      mlDsaSecretKey: new Uint8Array(dilithiumKP.secretKey)
    };
  }

  static async createSecureEnvelope(payload, routing, recipientKeys, senderKeys) {
    const kyberPublicBase64 = uint8ArrayToBase64(recipientKeys.mlKemPublicKey);
    const opts = { recipientX25519PublicKey: recipientKeys.x25519PublicKey };
    const routingParams = {
      ...routing,
      senderDilithiumSecretKey: senderKeys?.mlDsaSecretKey,
      senderDilithiumPublicKey: senderKeys?.mlDsaPublicKey
    };
    const env = await this.encryptForClient(payload, { kyberPublicBase64 }, routingParams, opts);
    return {
      version: env.version,
      routing: env.routing,
      pqCiphertext: env.kemCiphertext,
      outerLayer: env.outer,
      signature: env.routingSignature,
      metadata: env.metadata
    };
  }

  static async openSecureEnvelope(envelope, ownKeys, senderDilithiumPublicKey) {
    const internal = {
      version: envelope.version,
      routing: envelope.routing,
      routingSignature: envelope.signature,
      kemCiphertext: envelope.pqCiphertext,
      outer: envelope.outerLayer,
      metadata: envelope.metadata
    };
    const result = await this.decryptIncoming(internal, {
      kyberPublicKey: ensureUint8Array(ownKeys.mlKemPublicKey, 'kyberPublicKey'),
      kyberSecretKey: ensureUint8Array(ownKeys.mlKemSecretKey, 'kyberSecretKey'),
      x25519SecretKey: ensureUint8Array(ownKeys.x25519SecretKey, 'x25519SecretKey')
    }, { senderDilithiumPublicKey });
    return result;
  }

  static exportX25519PublicBase64(publicKey) {
    return QuantumHashService.arrayBufferToBase64(publicKey);
  }

  static exportKyberPublicBase64(publicKey) {
    return QuantumHashService.arrayBufferToBase64(publicKey);
  }

  static exportDilithiumPublicBase64(publicKey) {
    return QuantumHashService.arrayBufferToBase64(publicKey);
  }

  static canonicalizeRoutingHeader(header) {
    return canonicalizeRoutingHeaderHelper(header);
  }

  static computeRoutingDigest(header) {
    return computeRoutingDigestHelper(header);
  }

  static buildRoutingHeader(input) {
    return buildRoutingHeaderHelper(input);
  }

  static normalizePayload(payload) {
    return normalizePayloadHelper(payload);
  }

  static async signRoutingHeader(header, dilithiumSecretKey) {
    return signRoutingHeaderHelper(header, dilithiumSecretKey);
  }

  static async verifyRoutingHeader(header, signatureBase64, dilithiumPublicKey) {
    return verifyRoutingHeaderHelper(header, signatureBase64, dilithiumPublicKey);
  }

  static generateEphemeralX25519() {
    return createX25519KeyPair();
  }

  static computeClassicalSharedSecret(privateKey, publicKey) {
    const shared = x25519.getSharedSecret(privateKey, publicKey);
    return new Uint8Array(shared.slice(0, 32));
  }

  static async createInnerLayer(payload, routingDigest, pqSharedSecret, recipientX25519) {
    if (!recipientX25519) {
      throw new Error('Recipient X25519 public key is required for inner layer');
    }
    const ephemeral = await createX25519KeyPair();
    const classicalShared = this.computeClassicalSharedSecret(ephemeral.secretKey, recipientX25519);
    const innerSalt = crypto.randomBytes(32);
    const innerNonce = QuantumRandomGenerator.generateRandomBytes(36);
    const { encKey, macKey } = deriveInnerKeyMaterial(pqSharedSecret, classicalShared, innerSalt, routingDigest);

    try {
      const aad = new TextEncoder().encode(payload.type);
      const aead = new PostQuantumAEAD(encKey);
      const { ciphertext, tag } = aead.encrypt(payload.bytes, innerNonce, aad);
      const macInput = concatUint8Arrays(innerNonce, ciphertext, tag, routingDigest, ephemeral.publicKey, aad);
      const mac = await QuantumHashService.generateBlake3Mac(macInput, macKey);

      return {
        version: 'inner-envelope-v1',
        salt: QuantumHashService.arrayBufferToBase64(innerSalt),
        ephemeralX25519: QuantumHashService.arrayBufferToBase64(ephemeral.publicKey),
        nonce: QuantumHashService.arrayBufferToBase64(innerNonce),
        ciphertext: QuantumHashService.arrayBufferToBase64(ciphertext),
        tag: QuantumHashService.arrayBufferToBase64(tag),
        mac: QuantumHashService.arrayBufferToBase64(mac),
        payloadType: payload.type,
        metadata: { contentLength: payload.bytes.length }
      };
    } finally {
      SecureMemory.wipe(ephemeral.secretKey);
      SecureMemory.wipe(classicalShared);
      SecureMemory.wipe(encKey);
      SecureMemory.wipe(macKey);
    }
  }

  static deriveOuterKeys(sharedSecret, salt, routingDigest) {
    const info = `outer-envelope:${QuantumHashService.arrayBufferToBase64(routingDigest)}`;
    const okm = PostQuantumHash.deriveKey(sharedSecret, salt, info, 64);
    const outerKey = okm.slice(0, 32);
    const outerMacKey = okm.slice(32, 64);
    SecureMemory.wipe(okm);
    return { outerKey, outerMacKey };
  }

  static async encryptForClient(payload, recipientKeys, routingParams, options = {}) {
    if (!recipientKeys?.kyberPublicBase64) {
      throw new Error('Recipient Kyber public key is required');
    }
    if (!options.recipientX25519PublicKey) {
      throw new Error('Recipient X25519 public key is required');
    }

    const recipientX25519 = ensureUint8Array(options.recipientX25519PublicKey, 'recipientX25519PublicKey');
    const normalizedPayload = this.normalizePayload(payload);
    const header = this.buildRoutingHeader({ ...routingParams, size: normalizedPayload.bytes.length });
    const signatureBase64 = await this.signRoutingHeader(header, routingParams.senderDilithiumSecretKey);
    const routingDigest = this.computeRoutingDigest(header);

    const recipientKyber = QuantumHashService.base64ToUint8Array(recipientKeys.kyberPublicBase64);
    const { ciphertext: kemCiphertext, sharedSecret: pqSharedSecret } = await QuantumKyberService.encapsulate(recipientKyber);

    const innerLayer = await this.createInnerLayer(normalizedPayload, routingDigest, pqSharedSecret, recipientX25519);

    const outerSalt = crypto.randomBytes(32);
    const { outerKey, outerMacKey } = this.deriveOuterKeys(pqSharedSecret, outerSalt, routingDigest);
    try {
      const innerPayloadBytes = new TextEncoder().encode(JSON.stringify(innerLayer));
      const outerNonce = crypto.randomBytes(24);
      const outerCipher = gcm(outerKey, outerNonce.slice(0, 12), routingDigest);
      const outerEncrypted = outerCipher.encrypt(innerPayloadBytes);
      const outerCiphertext = outerEncrypted.slice(0, -16);
      const outerTag = outerEncrypted.slice(-16);

      const outerMacInput = new Uint8Array(outerCiphertext.length + outerTag.length + routingDigest.length);
      let offset = 0;
      outerMacInput.set(outerCiphertext, offset);
      offset += outerCiphertext.length;
      outerMacInput.set(outerTag, offset);
      offset += outerTag.length;
      outerMacInput.set(routingDigest, offset);
      const outerMac = await QuantumHashService.generateBlake3Mac(outerMacInput, outerMacKey);

      const envelope = {
        version: 'hybrid-envelope-v1',
        routing: header,
        routingSignature: { algorithm: 'dilithium3', signature: signatureBase64 },
        algorithms: { outer: 'mlkem1024', inner: 'x25519', aead: 'aes-256-gcm', mac: 'blake3' },
        kemCiphertext: QuantumHashService.arrayBufferToBase64(kemCiphertext),
        outer: {
          salt: QuantumHashService.arrayBufferToBase64(outerSalt),
          nonce: QuantumHashService.arrayBufferToBase64(outerNonce),
          ciphertext: QuantumHashService.arrayBufferToBase64(outerCiphertext),
          tag: QuantumHashService.arrayBufferToBase64(outerTag),
          mac: QuantumHashService.arrayBufferToBase64(outerMac)
        },
        metadata: options.metadata
      };

      if (routingParams.senderDilithiumPublicKey) {
        envelope.metadata = {
          ...envelope.metadata,
          sender: {
            ...(envelope.metadata?.sender ?? {}),
            dilithiumPublicKey: QuantumHashService.arrayBufferToBase64(
              ensureUint8Array(routingParams.senderDilithiumPublicKey, 'senderDilithiumPublicKey')
            )
          }
        };
      }

      if (options.context ?? routingParams.context) {
        envelope.metadata = {
          ...envelope.metadata,
          context: options.context ?? routingParams.context
        };
      }

      return envelope;
    } finally {
      SecureMemory.wipe(pqSharedSecret);
      SecureMemory.wipe(outerKey);
      SecureMemory.wipe(outerMacKey);
    }
  }

  static async encryptForServer(payload, serverKeys, options = {}) {
    const routing = {
      to: 'server',
      from: 'client',
      type: 'server',
      senderDilithiumSecretKey: options.senderDilithiumSecretKey,
      timestamp: Date.now()
    };
    if (!routing.senderDilithiumSecretKey) {
      throw new Error('Sender Dilithium secret key required for server encryption');
    }
    return this.encryptForClient(payload, serverKeys, routing, options);
  }

  static async decryptIncoming(envelope, ownKeys, options = {}) {
    if (!envelope || envelope.version !== 'hybrid-envelope-v1') {
      throw new Error('Unsupported envelope version');
    }

    const header = envelope.routing;
    const routingDigest = this.computeRoutingDigest(header);

    const senderPublicBase64 = envelope.metadata?.sender?.dilithiumPublicKey || options.senderDilithiumPublicKey;
    if (!senderPublicBase64) {
      throw new Error('Sender Dilithium public key required for verification');
    }
    const senderPublicKey = base64ToUint8Array(senderPublicBase64, 'senderDilithiumPublicKey');
    const signatureValid = await verifyRoutingHeaderHelper(header, envelope.routingSignature.signature, senderPublicKey);
    if (!signatureValid) {
      throw new Error('Routing header signature verification failed');
    }

    const kyberSecret = ensureUint8Array(ownKeys.kyberSecretKey, 'kyberSecretKey');
    const kemCiphertext = QuantumHashService.base64ToUint8Array(envelope.kemCiphertext);
    const pqSharedSecret = await QuantumKyberService.decapsulate(kemCiphertext, kyberSecret, ownKeys.kyberPublicKey);

    const outerSalt = QuantumHashService.base64ToUint8Array(envelope.outer.salt);
    const { outerKey, outerMacKey } = this.deriveOuterKeys(pqSharedSecret, outerSalt, routingDigest);

    try {
      const outerCiphertext = QuantumHashService.base64ToUint8Array(envelope.outer.ciphertext);
      const outerTag = QuantumHashService.base64ToUint8Array(envelope.outer.tag);
      const outerNonce = QuantumHashService.base64ToUint8Array(envelope.outer.nonce);
      const expectedMac = QuantumHashService.base64ToUint8Array(envelope.outer.mac);

      const outerMacInput = concatUint8Arrays(outerCiphertext, outerTag, routingDigest);

      const outerMacValid = await QuantumHashService.verifyBlake3Mac(outerMacInput, outerMacKey, expectedMac);
      if (!outerMacValid) {
        throw new Error('Outer envelope MAC verification failed');
      }

      const outerCipher = gcm(outerKey, outerNonce.slice(0, 12), routingDigest);
      const outerPlain = outerCipher.decrypt(new Uint8Array([...outerCiphertext, ...outerTag]));
      const innerLayer = JSON.parse(Buffer.from(outerPlain).toString());

      if (innerLayer.version !== 'inner-envelope-v1') {
        throw new Error('Unsupported inner envelope version');
      }

      const innerSalt = QuantumHashService.base64ToUint8Array(innerLayer.salt);
      const innerNonce = QuantumHashService.base64ToUint8Array(innerLayer.nonce);
      const innerCiphertext = QuantumHashService.base64ToUint8Array(innerLayer.ciphertext);
      const innerTag = QuantumHashService.base64ToUint8Array(innerLayer.tag);
      const innerMac = QuantumHashService.base64ToUint8Array(innerLayer.mac);
      const ephemeralPublic = QuantumHashService.base64ToUint8Array(innerLayer.ephemeralX25519);

      if (!ownKeys.x25519SecretKey) {
        throw new Error('x25519SecretKey required to decrypt inner envelope');
      }
      const x25519Secret = ensureUint8Array(ownKeys.x25519SecretKey, 'x25519SecretKey');
      const classicalShared = this.computeClassicalSharedSecret(x25519Secret, ephemeralPublic);
      const { encKey, macKey } = await deriveInnerKeyMaterial(pqSharedSecret, classicalShared, innerSalt, routingDigest);

      try {
        const macInput = concatUint8Arrays(
          innerNonce,
          innerCiphertext,
          innerTag,
          routingDigest,
          ephemeralPublic,
          new TextEncoder().encode(innerLayer.payloadType)
        );
        const innerMacValid = await QuantumHashService.verifyBlake3Mac(macInput, macKey, innerMac);
        if (!innerMacValid) {
          throw new Error('Inner envelope MAC verification failed');
        }

        const aad = new TextEncoder().encode(innerLayer.payloadType);
        const aead = new PostQuantumAEAD(encKey);
        const plaintextBytes = aead.decrypt(innerCiphertext, innerNonce, innerTag, aad);
        let payloadJson;
        if (innerLayer.payloadType === 'json') {
          payloadJson = JSON.parse(Buffer.from(plaintextBytes).toString());
        }

        return {
          routing: header,
          payload: plaintextBytes,
          payloadJson,
          metadata: envelope.metadata,
          senderDilithiumPublicKey: senderPublicBase64
        };
      } finally {
        SecureMemory.wipe(classicalShared);
        SecureMemory.wipe(macKey);
      }
    } finally {
      SecureMemory.wipe(pqSharedSecret);
      SecureMemory.wipe(outerKey);
      SecureMemory.wipe(outerMacKey);
    }
  }
}

class PasswordService {
  static async hashPassword(password) {
    if (typeof password !== 'string') {
      throw new Error('Password must be a string');
    }
    const trimmed = password.trim();
    if (trimmed.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
    }
    if (trimmed.length > MAX_PASSWORD_LENGTH) {
      throw new Error(`Password must be no more than ${MAX_PASSWORD_LENGTH} characters`);
    }
    return await argon2.hash(trimmed, {
      type: argon2.argon2id,
      memoryCost: CryptoConfig.ARGON2_MEMORY,
      timeCost: CryptoConfig.ARGON2_TIME,
      parallelism: CryptoConfig.ARGON2_PARALLELISM,
      hashLength: 64
    });
  }

  static async verifyPassword(hash, password) {
    if (!hash || typeof hash !== 'string') {
      return false;
    }
    if (typeof password !== 'string') {
      return false;
    }
    try {
      return await argon2.verify(hash, password.trim());
    } catch (error) {
      logger.error('Password verification failed', { error: error.message });
      return false;
    }
  }

  static async parseArgon2Hash(hash) {
    if (!hash || typeof hash !== 'string' || !hash.startsWith('$argon2')) {
      throw new Error('Invalid Argon2 hash format');
    }
    return await QuantumHashService.parseArgon2Hash(hash);
  }
}

export const CryptoUtils = {
  Hash: QuantumHashService,
  KDF: QuantumKDFService,
  Random: QuantumRandomGenerator,
  Hybrid: HybridService,
  Kyber: QuantumKyberService,
  Dilithium: DilithiumService,
  AES: PostQuantumAESService,
  PostQuantumAEAD: PostQuantumAEAD,
  Config: CryptoConfig,
  Password: PasswordService
};
