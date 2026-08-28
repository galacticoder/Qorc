import crypto from 'crypto';
import argon2 from 'argon2';
import { MlKem1024 } from 'mlkem';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha3_512, shake256 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import {
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SECRET_KEY_BYTES,
  ML_KEM_1024_SHARED_SECRET_BYTES,
} from '../../shared/crypto-sizes.js';
import {
  AES_GCM_NONCE_BYTES,
  HASH_OUTPUT_BYTES,
  ML_KEM_1024_ALGORITHM,
  POST_QUANTUM_AEAD_KEY_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES,
  POST_QUANTUM_AEAD_TAG_BYTES,
  WIDE_HASH_OUTPUT_BYTES,
  X25519_KEY_BYTES,
  XCHACHA20_NONCE_BYTES
} from '../utils/crypto-consts.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { PostQuantumHash } from './post-quantum-hash.js';

const UNIFIED_CRYPTO_MAC_BYTES = UTF8_ENCODER.encode(PROTOCOL_KEYS.UNIFIED_CRYPTO_MAC);

function checkUint8Array(value, label) {
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

class SecureMemory {
  static wipe(buf) {
    try {
      if (buf instanceof Uint8Array || Buffer.isBuffer(buf)) {
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
    if (!key || key.length !== POST_QUANTUM_AEAD_KEY_BYTES) {
      throw new Error('PostQuantumAEAD requires a 32-byte key');
    }
    this.key = key;
  }

  // Derive 64 byte key material from 32 byte input
  _deriveDoubleKey(inputKey) {
    const expanded = sha3_512(inputKey);
    const macInput = new Uint8Array(UNIFIED_CRYPTO_MAC_BYTES.length + inputKey.length);
    try {
      macInput.set(UNIFIED_CRYPTO_MAC_BYTES, 0);
      macInput.set(inputKey, UNIFIED_CRYPTO_MAC_BYTES.length);
      return {
        k1: expanded.slice(0, POST_QUANTUM_AEAD_KEY_BYTES),
        k2: expanded.slice(POST_QUANTUM_AEAD_KEY_BYTES, WIDE_HASH_OUTPUT_BYTES),
        macKey: blake3(macInput, { dkLen: HASH_OUTPUT_BYTES })
      };
    } finally {
      SecureMemory.wipeAll(expanded, macInput);
    }
  }

  encrypt(plaintext, nonce, aad) {
    if (!plaintext || !nonce) {
      throw new Error('Plaintext and nonce are required');
    }
    if (nonce.length !== POST_QUANTUM_AEAD_NONCE_BYTES) {
      throw new Error('Nonce must be 36 bytes for PostQuantumAEAD (12 AES-GCM + 24 XChaCha20)');
    }

    const aadBytes = aad || Buffer.alloc(0);
    const { k1, k2, macKey } = this._deriveDoubleKey(this.key);

    let iv;
    let layer1;
    let xnonce;
    let layer2;
    let macInput;
    let mac;
    try {
      // AES-256-GCM encryption
      iv = Uint8Array.from(nonce.subarray(0, AES_GCM_NONCE_BYTES));
      const cipher = gcm(k1, iv, aadBytes);
      layer1 = cipher.encrypt(plaintext);

      // XChaCha20-Poly1305 encryption
      xnonce = Uint8Array.from(nonce.subarray(
        AES_GCM_NONCE_BYTES,
        AES_GCM_NONCE_BYTES + XCHACHA20_NONCE_BYTES
      ));
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      layer2 = xchacha.encrypt(layer1);

      // BLAKE3 MAC
      macInput = new Uint8Array(layer2.length + aadBytes.length + nonce.length);
      macInput.set(layer2, 0);
      macInput.set(aadBytes, layer2.length);
      macInput.set(nonce, layer2.length + aadBytes.length);
      mac = blake3(macInput, { key: macKey });

      return {
        ciphertext: Buffer.from(layer2),
        tag: Buffer.from(mac)
      };
    } finally {
      SecureMemory.wipeAll(k1, k2, macKey, iv, layer1, xnonce, layer2, macInput, mac);
    }
  }

  decrypt(ciphertext, nonce, tag, aad) {
    if (!ciphertext || !nonce || !tag) {
      throw new Error('Ciphertext, nonce, and tag are required');
    }
    if (nonce.length !== POST_QUANTUM_AEAD_NONCE_BYTES) {
      throw new Error('Nonce must be 36 bytes for PostQuantumAEAD (12 AES-GCM + 24 XChaCha20)');
    }
    if (tag.length !== POST_QUANTUM_AEAD_TAG_BYTES) {
      throw new Error('Tag must be 32 bytes (BLAKE3 MAC)');
    }

    const aadBytes = aad || Buffer.alloc(0);
    const { k1, k2, macKey } = this._deriveDoubleKey(this.key);

    let macInput;
    let expectedMac;
    let xnonce;
    let layer1;
    let iv;
    let plaintext;
    try {
      macInput = new Uint8Array(ciphertext.length + aadBytes.length + nonce.length);
      macInput.set(ciphertext, 0);
      macInput.set(aadBytes, ciphertext.length);
      macInput.set(nonce, ciphertext.length + aadBytes.length);
      expectedMac = blake3(macInput, { key: macKey });

      if (!QuantumHashService.constantTimeCompare(tag, expectedMac)) {
        throw new Error('BLAKE3 MAC verification failed');
      }

      // Decrypt XChaCha20-Poly1305
      xnonce = Uint8Array.from(nonce.subarray(
        AES_GCM_NONCE_BYTES,
        AES_GCM_NONCE_BYTES + XCHACHA20_NONCE_BYTES
      ));
      const xchacha = xchacha20poly1305(k2, xnonce, aadBytes);
      layer1 = xchacha.decrypt(ciphertext);

      // Decrypt AES-256-GCM
      iv = Uint8Array.from(nonce.subarray(0, AES_GCM_NONCE_BYTES));
      const decipher = gcm(k1, iv, aadBytes);
      plaintext = decipher.decrypt(layer1);

      return Buffer.from(plaintext);
    } catch (error) {
      throw new Error(`PostQuantumAEAD decryption failed: ${error.message}`);
    } finally {
      SecureMemory.wipeAll(k1, k2, macKey, macInput, expectedMac, xnonce, layer1, iv, plaintext);
    }
  }

  static encrypt(plaintext, key, aad, explicitNonce) {
    const keyBytes = checkUint8Array(key, 'PostQuantumAEAD.encrypt.key');
    const nonce = explicitNonce
      ? checkUint8Array(explicitNonce, 'PostQuantumAEAD.encrypt.nonce')
      : QuantumRandomGenerator.generateRandomBytes(POST_QUANTUM_AEAD_NONCE_BYTES);
    const aadBytes = aad ? checkUint8Array(aad, 'PostQuantumAEAD.encrypt.aad') : undefined;
    const aead = new PostQuantumAEAD(keyBytes);
    const { ciphertext, tag } = aead.encrypt(checkUint8Array(plaintext, 'PostQuantumAEAD.encrypt.plaintext'), nonce, aadBytes);
    return { ciphertext: checkUint8Array(ciphertext, 'PostQuantumAEAD.encrypt.ciphertext'), nonce, tag: checkUint8Array(tag, 'PostQuantumAEAD.encrypt.tag') };
  }

  static decrypt(ciphertext, nonce, tag, key, aad) {
    const keyBytes = checkUint8Array(key, 'PostQuantumAEAD.decrypt.key');
    const nonceBytes = checkUint8Array(nonce, 'PostQuantumAEAD.decrypt.nonce');
    const tagBytes = checkUint8Array(tag, 'PostQuantumAEAD.decrypt.tag');
    const cipherBytes = checkUint8Array(ciphertext, 'PostQuantumAEAD.decrypt.ciphertext');
    const aadBytes = aad ? checkUint8Array(aad, 'PostQuantumAEAD.decrypt.aad') : undefined;
    const aead = new PostQuantumAEAD(keyBytes);
    return aead.decrypt(cipherBytes, nonceBytes, tagBytes, aadBytes);
  }
}

// Cryptographic configuration
class CryptoConfig {
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
    const MIN = 1 << 17;
    const DEF = 1 << 18;
    const MAX = 1 << 20;
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

}

class QuantumRandomGenerator {
  static async generateSecureRandom(length) {
    if (!Number.isInteger(length) || length < 0) {
      throw new Error(`Invalid random length: ${length}`);
    }

    if (length > 1048576) {
      throw new Error(`Random length too large: ${length}`);
    }

    try {
      return this.generateRandomBytes(length);
    } catch (error) {
      console.error('Failed to generate random bytes', error);
      throw new Error('Failed to generate random bytes');
    }
  }

  // Generate random bytes
  static generateRandomBytes(length) {
    if (!Number.isInteger(length) || length < 0) {
      throw new Error(`Invalid random length: ${length}`);
    }
    const source = crypto.randomBytes(length);
    try {
      return new Uint8Array(source);
    } finally {
      source.fill(0);
    }
  }

}

class QuantumHashService {
  static stringToUint8Array(str) {
    return UTF8_ENCODER.encode(str);
  }

  static arrayBufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Buffer.from(bytes).toString('base64');
  }

  static base64ToUint8Array(base64) {
    const decoded = Buffer.from(base64, 'base64');
    try {
      return new Uint8Array(decoded);
    } finally {
      decoded.fill(0);
    }
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

  static async generateBlake3Mac(message, key) {
    if (!key || key.length < 16) {
      throw new Error('BLAKE3 MAC requires key length >= 16 bytes');
    }
    const messageBytes = QuantumHashService.toUint8Array(message, 'message');
    const keyBytes = QuantumHashService.toUint8Array(key, 'key');

    const derivedKey = keyBytes.length === HASH_OUTPUT_BYTES
      ? null
      : blake3(keyBytes, { dkLen: HASH_OUTPUT_BYTES });
    try {
      return blake3(messageBytes, { key: derivedKey || keyBytes });
    } finally {
      SecureMemory.wipe(derivedKey);
    }
  }

  // SHAKE256 XOF
  static shake256(data, dkLen) {
    const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    return shake256(dataBytes, { dkLen });
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
    try {
      let isEqual = false;
      try { isEqual = crypto.timingSafeEqual(pa, pb); } catch { isEqual = false; }
      return isEqual && aBuf.length === bBuf.length;
    } finally {
      SecureMemory.wipeAll(aBuf, bBuf, pa, pb);
    }
  }

}

class QuantumKyberService {
  static kyberInstance() {
    return new MlKem1024();
  }

  // Encapsulation with shared secret derivation
  static async encapsulate(publicKeyBytes) {
    if (!publicKeyBytes || publicKeyBytes.length !== ML_KEM_1024_PUBLIC_KEY_BYTES) {
      throw new Error('Invalid public key for encapsulation');
    }

    const kyber = this.kyberInstance();
    const additionalEntropy = await QuantumRandomGenerator.generateSecureRandom(HASH_OUTPUT_BYTES);
    let ciphertext;
    let rawSharedSecret;
    try {
      [ciphertext, rawSharedSecret] = await kyber.encap(publicKeyBytes, additionalEntropy);
      if (
        ciphertext?.length !== ML_KEM_1024_CIPHERTEXT_BYTES ||
        rawSharedSecret?.length !== ML_KEM_1024_SHARED_SECRET_BYTES
      ) {
        throw new Error('ML-KEM-1024 encapsulation returned invalid output sizes');
      }
      return {
        ciphertext: new Uint8Array(ciphertext),
        sharedSecret: new Uint8Array(rawSharedSecret),
        algorithm: ML_KEM_1024_ALGORITHM,
        timestamp: Date.now()
      };
    } finally {
      SecureMemory.wipeAll(additionalEntropy, ciphertext, rawSharedSecret);
    }
  }

  // Decapsulation with shared secret derivation
  static async decapsulate(ciphertextBytes, secretKeyBytes) {
    if (
      !ciphertextBytes || ciphertextBytes.length !== ML_KEM_1024_CIPHERTEXT_BYTES ||
      !secretKeyBytes || secretKeyBytes.length !== ML_KEM_1024_SECRET_KEY_BYTES
    ) {
      throw new Error('Invalid parameters for decapsulation');
    }
    const kyber = this.kyberInstance();
    const rawSharedSecret = await kyber.decap(ciphertextBytes, secretKeyBytes);
    try {
      if (rawSharedSecret?.length !== ML_KEM_1024_SHARED_SECRET_BYTES) {
        throw new Error('ML-KEM-1024 decapsulation returned an invalid shared secret');
      }
      return new Uint8Array(rawSharedSecret);
    } finally {
      SecureMemory.wipe(rawSharedSecret);
    }
  }

}

class DilithiumService {
  static async sign(message, secretKey) {
    if (!(message instanceof Uint8Array) || secretKey?.length !== ML_DSA_87_SECRET_KEY_BYTES) {
      throw new Error('Invalid ML-DSA-87 signing input');
    }
    const signature = ml_dsa87.sign(message, secretKey);
    if (signature?.length !== ML_DSA_87_SIGNATURE_BYTES) {
      SecureMemory.wipe(signature);
      throw new Error('ML-DSA-87 signer returned an invalid signature');
    }
    return signature;
  }
}

class QuantumKDFService {
  static async quantumHKDF(ikm, salt, info, outLen) {
    const blake3Prk = await QuantumHashService.generateBlake3Mac(ikm, salt);
    const sha3Prk = sha3_512(Buffer.concat([salt.slice(0, WIDE_HASH_OUTPUT_BYTES), ikm]));
    const shakePrk = shake256(
      Buffer.concat([salt.slice(0, HASH_OUTPUT_BYTES), ikm]),
      { dkLen: WIDE_HASH_OUTPUT_BYTES }
    );

    const combinedPrk = new Uint8Array(blake3Prk.length + sha3Prk.length + shakePrk.length);
    combinedPrk.set(blake3Prk, 0);
    combinedPrk.set(sha3Prk, blake3Prk.length);
    combinedPrk.set(shakePrk, blake3Prk.length + sha3Prk.length);

    const masterPrk = blake3(combinedPrk);
    const output = new Uint8Array(outLen);
    const hashLen = WIDE_HASH_OUTPUT_BYTES;
    const n = Math.ceil(outLen / hashLen);

    let t = new Uint8Array(0);
    let outputOffset = 0;

    for (let i = 1; i <= n; i++) {
      const input = new Uint8Array(t.length + info.length + 1);
      input.set(t, 0);
      input.set(info, t.length);
      input[input.length - 1] = i;

      const blake3T = await QuantumHashService.generateBlake3Mac(input, masterPrk);
      const sha3T = sha3_512(Buffer.concat([masterPrk.slice(0, WIDE_HASH_OUTPUT_BYTES), input]));
      const shakeT = shake256(
        Buffer.concat([masterPrk.slice(0, HASH_OUTPUT_BYTES), input]),
        { dkLen: HASH_OUTPUT_BYTES }
      );

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

  // Derive KEK from username+password for server admin side
  static async deriveUsernamePasswordKEK(username, password, options = {}) {
    if (!username || typeof username !== 'string' || username.length < 3) {
      throw new Error('deriveUsernamePasswordKEK: username must be at least 3 characters');
    }
    if (!password || typeof password !== 'string' || password.trim().length < 16) {
      throw new Error('deriveUsernamePasswordKEK: password must be at least 16 characters');
    }

    const pwd = password.trim();
    const usernameBytes = UTF8_ENCODER.encode(String(username));

    const {
      salt,
      timeCost = CryptoConfig.ARGON2_TIME + 1,
      memoryCost = Math.min(CryptoConfig.ARGON2_MEMORY * 2, 1 << 20),
      parallelism = CryptoConfig.ARGON2_PARALLELISM,
      hashLength = WIDE_HASH_OUTPUT_BYTES,
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
      saltBuf = crypto.randomBytes(HASH_OUTPUT_BYTES);
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

    const hkSalt = shake256(saltBuf, { dkLen: WIDE_HASH_OUTPUT_BYTES });
    const info = UTF8_ENCODER.encode(PROTOCOL_KEYS.USERNAME_PASSWORD_KEK);

    const kek = await this.quantumHKDF(ikm, hkSalt, info, HASH_OUTPUT_BYTES);
    return { kek, salt: new Uint8Array(saltBuf) };
  }
}

class HybridService {
  static async generateHybridKeyPairFromSeed(seedMaterial) {
    const seed = checkUint8Array(seedMaterial, 'serverTransportIdentitySeed');
    if (seed.length !== HASH_OUTPUT_BYTES) {
      throw new Error('Server transport identity seed must be exactly 32 bytes');
    }

    const derive = (domain, length) => {
      return PostQuantumHash.domainKdf(domain, seed, length);
    };

    const kemSeed = derive(PROTOCOL_KEYS.SERVER_TRANSPORT_ML_KEM_ROOT, WIDE_HASH_OUTPUT_BYTES);
    const dsaSeed = derive(PROTOCOL_KEYS.SERVER_TRANSPORT_ML_DSA_ROOT, HASH_OUTPUT_BYTES);
    const x25519SecretKey = derive(PROTOCOL_KEYS.SERVER_TRANSPORT_X25519_ROOT, X25519_KEY_BYTES);
    let kemKeyPair;
    let dsaKeyPair;
    let x25519PublicKey;
    try {
      kemKeyPair = ml_kem1024.keygen(kemSeed);
      dsaKeyPair = ml_dsa87.keygen(dsaSeed);
      x25519PublicKey = x25519.getPublicKey(x25519SecretKey);

      return {
        mlKemPublicKey: new Uint8Array(kemKeyPair.publicKey),
        mlKemSecretKey: new Uint8Array(kemKeyPair.secretKey),
        x25519PublicKey: new Uint8Array(x25519PublicKey),
        x25519SecretKey: new Uint8Array(x25519SecretKey),
        mlDsaPublicKey: new Uint8Array(dsaKeyPair.publicKey),
        mlDsaSecretKey: new Uint8Array(dsaKeyPair.secretKey)
      };
    } finally {
      SecureMemory.wipeAll(
        kemSeed,
        dsaSeed,
        x25519SecretKey,
        kemKeyPair?.publicKey,
        kemKeyPair?.secretKey,
        dsaKeyPair?.publicKey,
        dsaKeyPair?.secretKey,
        x25519PublicKey
      );
    }
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

  static computeClassicalSharedSecret(privateKey, publicKey) {
    if (privateKey?.length !== X25519_KEY_BYTES || publicKey?.length !== X25519_KEY_BYTES) {
      throw new Error('X25519 keys must be exactly 32 bytes');
    }
    const shared = x25519.getSharedSecret(privateKey, publicKey);
    try {
      const result = new Uint8Array(shared.subarray(0, X25519_KEY_BYTES));
      if (result.every((byte) => byte === 0)) {
        SecureMemory.wipe(result);
        throw new Error('Invalid all-zero X25519 shared secret');
      }
      return result;
    } finally {
      SecureMemory.wipe(shared);
    }
  }
}

export const CryptoUtils = {
  Hash: QuantumHashService,
  KDF: QuantumKDFService,
  Random: QuantumRandomGenerator,
  Hybrid: HybridService,
  Kyber: QuantumKyberService,
  Dilithium: DilithiumService,
  PostQuantumAEAD: PostQuantumAEAD
};
