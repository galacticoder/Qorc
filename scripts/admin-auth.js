#!/usr/bin/env node
/**
 * Hybrid Post-Quantum Cluster Admin Authentication
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { withRedisClient } from '../server/session/redis-client.js';
import { CryptoUtils } from '../server/crypto/unified-crypto.js';
import { canonicalBase64Shape } from '../shared/canonical-base64.js';
import {
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SECRET_KEY_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_CIPHERTEXT_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  ML_KEM_1024_SECRET_KEY_BYTES,
  HASH_OUTPUT_BYTES,
  POST_QUANTUM_AEAD_NONCE_BYTES,
  X25519_KEY_BYTES,
} from '../shared/crypto-sizes.js';
import { hasExactPlainObjectKeys, isSafeJsonTree } from '../server/utils/validation.js';
import { envInt } from '../server/utils/env.js';
import { PROTOCOL_KEYS } from '../server/config/protocol-keys.js';
import { REDIS_KEYS } from '../server/config/redis-keys.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ADMIN_KEYS_ENC_FILE = path.resolve(
  process.env.CLUSTER_ADMIN_KEYS_FILE || path.join(__dirname, '../server/config/.cluster-admin-keys.enc')
);

// Configuration constants
const ADMIN_CONFIG = {
  TOKEN_EXPIRATION: 3600000,
  MAX_FAILED_ATTEMPTS: 5,
  LOCKOUT_DURATION: 900000,
  TOKEN_VERSION: 3,
  ALGORITHM: 'ML-KEM-1024+X25519 | ML-DSA-87+Ed25519 | PostQuantumAEAD',
};
const ADMIN_TOKEN_MAX_CHARS = 14 * 1024;
const ADMIN_TOKEN_CIPHERTEXT_MAX_BYTES = 4 * 1024;
const ADMIN_METADATA_MAX_BYTES = 1024;
const ADMIN_KEYS_FILE_MAX_BYTES = 64 * 1024;
const ADMIN_KEYS_CIPHERTEXT_MAX_BYTES = 32 * 1024;
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_KEY_BYTES = 32;
const ADMIN_VERIFY_MAX_INFLIGHT = 2;
const ADMIN_VERIFY_MAX_PER_MINUTE = envInt('ADMIN_VERIFY_MAX_PER_MINUTE', 120, 10, 10_000);
let adminVerificationsInflight = 0;

function adminAuthStoreUnavailable() {
  return Object.assign(new Error('Admin authentication store unavailable'), {
    code: 'ADMIN_AUTH_STORE_UNAVAILABLE',
  });
}

function parseJsonOrThrow(raw, errorMessage) {
  try {
    const text = typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8');
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Invalid JSON');
    }
    return parsed;
  } catch {
    throw new Error(errorMessage);
  }
}

function parseCanonicalBase64UrlJson(value, errorMessage) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > ADMIN_TOKEN_MAX_CHARS ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) throw new Error(errorMessage);
  const decoded = Buffer.from(value, 'base64url');
  try {
    if (decoded.toString('base64url') !== value) throw new Error(errorMessage);
    return parseJsonOrThrow(decoded, errorMessage);
  } finally {
    decoded.fill(0);
  }
}

function validAdminMetadata(value) {
  if (!isSafeJsonTree(value, { maxDepth: 8, maxNodes: 256, maxKeyLength: 64 })) return false;
  return Buffer.byteLength(JSON.stringify(value), 'utf8') <= ADMIN_METADATA_MAX_BYTES;
}

function validAdminId(value) {
  return typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= 128 &&
    value === value.trim() &&
    !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value);
}

function adminTokenHash(tokenString) {
  return Buffer.from(blake3(Buffer.from(tokenString, 'utf8'))).toString('hex');
}

function wipeBytes(...values) {
  for (const value of values) value?.fill?.(0);
}

function wipeAdminKeypair(keypair) {
  for (const family of Object.values(keypair || {})) {
    wipeBytes(family?.publicKey, family?.secretKey);
  }
}

function decodeCanonicalBase64(value, options, errorMessage) {
  if (!canonicalBase64Shape(value, options)) throw new Error(errorMessage);
  return Buffer.from(value, 'base64');
}

function validateEncryptedAdminPackage(encryptedPackage) {
  if (
    !hasExactPlainObjectKeys(encryptedPackage, [
      'algorithm', 'createdAt', 'encryption', 'kdf', 'usernameHash', 'version'
    ]) ||
    !hasExactPlainObjectKeys(encryptedPackage.kdf, ['algorithm', 'salt']) ||
    !hasExactPlainObjectKeys(encryptedPackage.encryption, [
      'algorithm', 'ciphertext', 'nonce', 'tag'
    ]) ||
    encryptedPackage.version !== ADMIN_CONFIG.TOKEN_VERSION ||
    encryptedPackage.algorithm !== ADMIN_CONFIG.ALGORITHM ||
    encryptedPackage.kdf.algorithm !== 'argon2id+quantumHKDF' ||
    encryptedPackage.encryption.algorithm !== 'PostQuantumAEAD' ||
    !Number.isSafeInteger(encryptedPackage.createdAt) ||
    encryptedPackage.createdAt <= 0 ||
    encryptedPackage.createdAt > Date.now() + 30_000 ||
    !canonicalBase64Shape(encryptedPackage.kdf.salt, { exactBytes: HASH_OUTPUT_BYTES }) ||
    !canonicalBase64Shape(encryptedPackage.usernameHash, { exactBytes: HASH_OUTPUT_BYTES }) ||
    !canonicalBase64Shape(encryptedPackage.encryption.nonce, {
      exactBytes: POST_QUANTUM_AEAD_NONCE_BYTES,
    }) ||
    !canonicalBase64Shape(encryptedPackage.encryption.tag, {
      exactBytes: HASH_OUTPUT_BYTES,
    }) ||
    !canonicalBase64Shape(encryptedPackage.encryption.ciphertext, {
      maxBytes: ADMIN_KEYS_CIPHERTEXT_MAX_BYTES,
    })
  ) throw new Error('SECURITY: Invalid encrypted admin key package');
  return encryptedPackage;
}

function validateDecryptedAdminKeys(keys) {
  if (
    !hasExactPlainObjectKeys(keys, [
      'dilithiumPublicKey',
      'dilithiumSecretKey',
      'ed25519PublicKey',
      'ed25519SecretKey',
      'kyberPublicKey',
      'kyberSecretKey',
      'x25519PublicKey',
      'x25519SecretKey',
    ]) ||
    !canonicalBase64Shape(keys.kyberPublicKey, { exactBytes: ML_KEM_1024_PUBLIC_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.kyberSecretKey, { exactBytes: ML_KEM_1024_SECRET_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.dilithiumPublicKey, { exactBytes: ML_DSA_87_PUBLIC_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.dilithiumSecretKey, { exactBytes: ML_DSA_87_SECRET_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.x25519PublicKey, { exactBytes: X25519_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.x25519SecretKey, { exactBytes: X25519_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.ed25519PublicKey, { exactBytes: ED25519_KEY_BYTES }) ||
    !canonicalBase64Shape(keys.ed25519SecretKey, { exactBytes: ED25519_KEY_BYTES })
  ) throw new Error('SECURITY: Invalid decrypted admin keys');
  return keys;
}

function readEncryptedAdminPackage() {
  let descriptor;
  try {
    descriptor = fs.openSync(
      ADMIN_KEYS_ENC_FILE,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC
    );
    const stat = fs.fstatSync(descriptor);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.size < 1 ||
      stat.size > ADMIN_KEYS_FILE_MAX_BYTES ||
      (stat.mode & 0o077) !== 0 ||
      (currentUid !== null && stat.uid !== currentUid)
    ) throw new Error('SECURITY: Admin key file must be a private, owned regular file');
    return validateEncryptedAdminPackage(parseJsonOrThrow(
      fs.readFileSync(descriptor, 'utf8'),
      'SECURITY: Corrupted admin key file'
    ));
  } catch (_error) {
    throw new Error('SECURITY: Invalid admin key file');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writeEncryptedAdminPackage(encryptedPackage) {
  const serialized = Buffer.from(`${JSON.stringify(encryptedPackage, null, 2)}\n`, 'utf8');
  let descriptor;
  let completed = false;
  try {
    if (serialized.length > ADMIN_KEYS_FILE_MAX_BYTES) {
      throw new Error('SECURITY: Admin key package exceeds storage limit');
    }
    descriptor = fs.openSync(
      ADMIN_KEYS_ENC_FILE,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_CLOEXEC,
      0o600
    );
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
    completed = true;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (descriptor !== undefined && !completed) {
      try { fs.unlinkSync(ADMIN_KEYS_ENC_FILE); } catch { }
    }
    wipeBytes(serialized);
  }
}

// Derive Key Encryption Key from username + password
async function deriveKEK(username, password, salt) {
  if (typeof username !== 'string' || username.length < 3 || username.length > 128) {
    throw new Error('Username must be at least 3 characters');
  }
  if (typeof password !== 'string' || password.trim().length < 16 || password.length > 1024) {
    throw new Error('Password must be at least 16 characters for admin access');
  }

  const usernameBytes = new TextEncoder().encode(String(username));
  let derived;
  let usernameHash;
  try {
    derived = await CryptoUtils.KDF.deriveUsernamePasswordKEK(username, password, { salt });
    usernameHash = blake3(usernameBytes);
    return {
      kek: Buffer.from(derived.kek),
      usernameHash: Buffer.from(usernameHash),
      salt: Buffer.from(derived.salt),
    };
  } finally {
    wipeBytes(usernameBytes, usernameHash, derived?.kek, derived?.salt);
  }
}

// Generate hybrid admin keypair set (PQ + Classical)
function generateHybridKeypair() {
  // Post-quantum keys
  const kemKeypair = ml_kem1024.keygen();
  const mldsaSeed = crypto.randomBytes(32);
  let mldsaKeypair;
  try {
    mldsaKeypair = ml_dsa87.keygen(mldsaSeed);
  } finally {
    mldsaSeed.fill(0);
  }

  // Classical keys
  const x25519Secret = crypto.randomBytes(32);
  const x25519Public = x25519.getPublicKey(x25519Secret);
  const ed25519Secret = ed25519.utils.randomSecretKey();
  const ed25519Public = ed25519.getPublicKey(ed25519Secret);

  return {
    kyber: {
      publicKey: kemKeypair.publicKey,
      secretKey: kemKeypair.secretKey,
    },
    dilithium: {
      publicKey: mldsaKeypair.publicKey,
      secretKey: mldsaKeypair.secretKey,
    },
    x25519: {
      publicKey: x25519Public,
      secretKey: x25519Secret,
    },
    ed25519: {
      publicKey: ed25519Public,
      secretKey: ed25519Secret,
    },
  };
}

// Protect admin keypair with username+password KEK
async function protectKeypair(keypair, username, password) {
  let derived;
  let keysBlob;
  let nonce;
  let ciphertext;
  let tag;
  try {
    derived = await deriveKEK(username, password);
    keysBlob = Buffer.from(JSON.stringify({
      kyberPublicKey: Buffer.from(keypair.kyber.publicKey).toString('base64'),
      kyberSecretKey: Buffer.from(keypair.kyber.secretKey).toString('base64'),
      dilithiumPublicKey: Buffer.from(keypair.dilithium.publicKey).toString('base64'),
      dilithiumSecretKey: Buffer.from(keypair.dilithium.secretKey).toString('base64'),
      x25519PublicKey: Buffer.from(keypair.x25519.publicKey).toString('base64'),
      x25519SecretKey: Buffer.from(keypair.x25519.secretKey).toString('base64'),
      ed25519PublicKey: Buffer.from(keypair.ed25519.publicKey).toString('base64'),
      ed25519SecretKey: Buffer.from(keypair.ed25519.secretKey).toString('base64'),
    }), 'utf8');

    const aead = new CryptoUtils.PostQuantumAEAD(derived.kek);
    nonce = CryptoUtils.Random.generateRandomBytes(POST_QUANTUM_AEAD_NONCE_BYTES);
    const aad = new TextEncoder().encode(PROTOCOL_KEYS.ADMIN_KEYS_AAD);
    ({ ciphertext, tag } = aead.encrypt(keysBlob, nonce, aad));

    return validateEncryptedAdminPackage({
      version: ADMIN_CONFIG.TOKEN_VERSION,
      algorithm: ADMIN_CONFIG.ALGORITHM,
      kdf: {
        algorithm: 'argon2id+quantumHKDF',
        salt: derived.salt.toString('base64'),
      },
      usernameHash: derived.usernameHash.toString('base64'),
      encryption: {
        algorithm: 'PostQuantumAEAD',
        nonce: Buffer.from(nonce).toString('base64'),
        tag: Buffer.from(tag).toString('base64'),
        ciphertext: Buffer.from(ciphertext).toString('base64'),
      },
      createdAt: Date.now(),
    });
  } finally {
    wipeBytes(
      derived?.kek,
      derived?.usernameHash,
      derived?.salt,
      keysBlob,
      nonce,
      ciphertext,
      tag
    );
  }
}

// Unlock admin keypair with username+password
async function unlockKeypair(username, password, encryptedPackage) {
  validateEncryptedAdminPackage(encryptedPackage);
  let salt;
  let derived;
  let storedHash;
  let nonce;
  let tag;
  let ciphertext;
  let decrypted;
  let candidateKeypair;
  try {
    salt = decodeCanonicalBase64(
      encryptedPackage.kdf.salt,
      { exactBytes: HASH_OUTPUT_BYTES },
      'SECURITY: Invalid admin key salt'
    );
    derived = await deriveKEK(username, password, salt);
    storedHash = decodeCanonicalBase64(
      encryptedPackage.usernameHash,
      { exactBytes: HASH_OUTPUT_BYTES },
      'SECURITY: Invalid admin username hash'
    );
    if (!crypto.timingSafeEqual(derived.usernameHash, storedHash)) {
      throw new Error('SECURITY: Username does not match encrypted keyset');
    }

    nonce = decodeCanonicalBase64(
      encryptedPackage.encryption.nonce,
      { exactBytes: POST_QUANTUM_AEAD_NONCE_BYTES },
      'SECURITY: Invalid admin key nonce'
    );
    tag = decodeCanonicalBase64(
      encryptedPackage.encryption.tag,
      { exactBytes: HASH_OUTPUT_BYTES },
      'SECURITY: Invalid admin key tag'
    );
    ciphertext = decodeCanonicalBase64(
      encryptedPackage.encryption.ciphertext,
      { maxBytes: ADMIN_KEYS_CIPHERTEXT_MAX_BYTES },
      'SECURITY: Invalid encrypted admin keys'
    );

    const aead = new CryptoUtils.PostQuantumAEAD(derived.kek);
    const aad = new TextEncoder().encode(PROTOCOL_KEYS.ADMIN_KEYS_AAD);
    try {
      decrypted = aead.decrypt(ciphertext, nonce, tag, aad);
    } catch (_error) {
      throw new Error('SECURITY: Failed to decrypt admin keys - invalid credentials or corrupted data');
    }

    const keys = validateDecryptedAdminKeys(parseJsonOrThrow(
      decrypted,
      'SECURITY: Failed to parse decrypted admin keys'
    ));
    candidateKeypair = {
      kyber: {
        publicKey: Buffer.from(keys.kyberPublicKey, 'base64'),
        secretKey: Buffer.from(keys.kyberSecretKey, 'base64'),
      },
      dilithium: {
        publicKey: Buffer.from(keys.dilithiumPublicKey, 'base64'),
        secretKey: Buffer.from(keys.dilithiumSecretKey, 'base64'),
      },
      x25519: {
        publicKey: Buffer.from(keys.x25519PublicKey, 'base64'),
        secretKey: Buffer.from(keys.x25519SecretKey, 'base64'),
      },
      ed25519: {
        publicKey: Buffer.from(keys.ed25519PublicKey, 'base64'),
        secretKey: Buffer.from(keys.ed25519SecretKey, 'base64'),
      },
    };
    const result = candidateKeypair;
    candidateKeypair = null;
    return result;
  } finally {
    wipeAdminKeypair(candidateKeypair);
    wipeBytes(
      salt,
      derived?.kek,
      derived?.usernameHash,
      derived?.salt,
      storedHash,
      nonce,
      tag,
      ciphertext,
      decrypted
    );
  }
}

// Admin Authentication Class
class AdminAuth {
  constructor() {
    this.keypair = null;
    this.initialized = false;
    this.adminUsername = null;
  }

  // Initialize with admin credentials
  async initialize(username, password) {
    if (!username || !password) {
      throw new Error('Admin username and password required for initialization');
    }

    let candidateKeypair = null;
    try {
      if (fs.existsSync(ADMIN_KEYS_ENC_FILE)) {
        const encryptedPackage = readEncryptedAdminPackage();
        candidateKeypair = await unlockKeypair(username, password, encryptedPackage);
        console.log('[ADMIN] Unlocked existing admin keypair');
      } else {
        candidateKeypair = generateHybridKeypair();
        const encryptedPackage = await protectKeypair(candidateKeypair, username, password);

        writeEncryptedAdminPackage(encryptedPackage);
        console.log('[ADMIN] Generated and protected new admin keypair');
      }

      const previousKeypair = this.keypair;
      this.keypair = candidateKeypair;
      candidateKeypair = null;
      wipeAdminKeypair(previousKeypair);
      this.adminUsername = username;
      this.initialized = true;

      console.log('[ADMIN] Hybrid admin auth initialized', {
        algorithm: ADMIN_CONFIG.ALGORITHM,
        username: username,
      });
    } catch (error) {
      wipeAdminKeypair(candidateKeypair);
      console.error('[ADMIN] Failed to initialize', { error: error.message });
      throw error;
    }
  }

  destroy() {
    wipeAdminKeypair(this.keypair);
    this.keypair = null;
    this.adminUsername = null;
    this.initialized = false;
  }

  // Generate admin token
  async generateAdminToken(adminId, metadata = {}) {
    if (!this.initialized) {
      throw new Error('Admin auth not initialized - must unlock keys first');
    }

    let payloadBytes;
    let ephemeralX25519Secret;
    let ephemeralX25519Public;
    let x25519SharedSecret;
    let kyberSharedSecret;
    let kyberCiphertext;
    let rawSecret;
    let info;
    let kdfSalt;
    let aeadKey;
    let nonce;
    let aad;
    let ciphertext;
    let tag;
    let tokenBytes;
    let mldsaSignature;
    let ed25519Signature;
    try {
      if (
        !validAdminId(adminId) ||
        !validAdminMetadata(metadata)
      ) throw new Error('Invalid admin token claims');
      const payload = {
        version: ADMIN_CONFIG.TOKEN_VERSION,
        adminId,
        nonce: crypto.randomBytes(32).toString('base64'),
        issuedAt: Date.now(),
        expiresAt: Date.now() + ADMIN_CONFIG.TOKEN_EXPIRATION,
        metadata,
      };

      payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');

      ephemeralX25519Secret = crypto.randomBytes(32);
      ephemeralX25519Public = x25519.getPublicKey(ephemeralX25519Secret);

      x25519SharedSecret = x25519.getSharedSecret(ephemeralX25519Secret, this.keypair.x25519.publicKey);

      const kemResult = ml_kem1024.encapsulate(this.keypair.kyber.publicKey);
      kyberSharedSecret = kemResult.sharedSecret;
      kyberCiphertext = kemResult.cipherText;

      rawSecret = Buffer.concat([
        Buffer.from(kyberSharedSecret),
        Buffer.from(x25519SharedSecret),
      ]);
      info = new TextEncoder().encode(PROTOCOL_KEYS.ADMIN_TOKEN_ENCRYPTION);
      kdfSalt = CryptoUtils.Hash.shake256(rawSecret, 64);
      aeadKey = await CryptoUtils.KDF.quantumHKDF(
        new Uint8Array(rawSecret),
        kdfSalt,
        info,
        32
      );

      const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
      nonce = CryptoUtils.Random.generateRandomBytes(36);
      aad = new TextEncoder().encode(PROTOCOL_KEYS.ADMIN_TOKEN_AAD);
      ({ ciphertext, tag } = aead.encrypt(payloadBytes, nonce, aad));

      // Prepare token structure
      const tokenStructure = {
        version: ADMIN_CONFIG.TOKEN_VERSION,
        kyberCiphertext: Buffer.from(kyberCiphertext).toString('base64'),
        x25519EphemeralPublic: Buffer.from(ephemeralX25519Public).toString('base64'),
        nonce: Buffer.from(nonce).toString('base64'),
        ciphertext: Buffer.from(ciphertext).toString('base64'),
        tag: Buffer.from(tag).toString('base64'),
      };

      tokenBytes = Buffer.from(JSON.stringify(tokenStructure), 'utf8');
      mldsaSignature = ml_dsa87.sign(tokenBytes, this.keypair.dilithium.secretKey);
      ed25519Signature = ed25519.sign(tokenBytes, this.keypair.ed25519.secretKey);

      const token = {
        ...tokenStructure,
        signatures: {
          mldsa87: Buffer.from(mldsaSignature).toString('base64'),
          ed25519: Buffer.from(ed25519Signature).toString('base64'),
        },
      };

      const tokenString = Buffer.from(JSON.stringify(token)).toString('base64url');

      const tokenHash = adminTokenHash(tokenString);
      await withRedisClient(async (client) => {
        await client.hset(REDIS_KEYS.ADMIN_TOKENS, tokenHash, JSON.stringify({
          adminId,
          issuedAt: payload.issuedAt,
          expiresAt: payload.expiresAt,
          metadata,
          algorithm: ADMIN_CONFIG.ALGORITHM,
        }));
        await client.pexpire(REDIS_KEYS.ADMIN_TOKENS, ADMIN_CONFIG.TOKEN_EXPIRATION);
      });

      console.log('[ADMIN] Generated admin token', {
        adminId,
        algorithm: ADMIN_CONFIG.ALGORITHM,
        expiresAt: new Date(payload.expiresAt).toISOString(),
      });

      return tokenString;
    } catch (error) {
      console.error('[ADMIN] Failed to generate token', { error: error.message });
      throw error;
    } finally {
      wipeBytes(
        payloadBytes,
        ephemeralX25519Secret,
        ephemeralX25519Public,
        x25519SharedSecret,
        kyberSharedSecret,
        kyberCiphertext,
        rawSecret,
        info,
        kdfSalt,
        aeadKey,
        nonce,
        aad,
        ciphertext,
        tag,
        tokenBytes,
        mldsaSignature,
        ed25519Signature
      );
    }
  }

  // Verify admin token
  async verifyAdminToken(tokenString) {
    if (!this.initialized) {
      throw new Error('Admin auth not initialized - must unlock keys first');
    }

    let tokenBytes;
    let mldsaSignature;
    let ed25519Signature;
    let kyberCiphertext;
    let kyberSharedSecret;
    let x25519EphemeralPublic;
    let x25519SharedSecret;
    let rawSecret;
    let info;
    let kdfSalt;
    let aeadKey;
    let nonce;
    let ciphertext;
    let tag;
    let aad;
    let payloadBytes;
    try {
      const token = parseCanonicalBase64UrlJson(tokenString, 'Invalid admin token');

      if (
        !hasExactPlainObjectKeys(token, [
          'ciphertext',
          'kyberCiphertext',
          'nonce',
          'signatures',
          'tag',
          'version',
          'x25519EphemeralPublic',
        ]) ||
        !hasExactPlainObjectKeys(token.signatures, ['ed25519', 'mldsa87']) ||
        token.version !== ADMIN_CONFIG.TOKEN_VERSION ||
        !canonicalBase64Shape(token.kyberCiphertext, { exactBytes: ML_KEM_1024_CIPHERTEXT_BYTES }) ||
        !canonicalBase64Shape(token.x25519EphemeralPublic, { exactBytes: X25519_KEY_BYTES }) ||
        !canonicalBase64Shape(token.nonce, { exactBytes: POST_QUANTUM_AEAD_NONCE_BYTES }) ||
        !canonicalBase64Shape(token.ciphertext, { maxBytes: ADMIN_TOKEN_CIPHERTEXT_MAX_BYTES }) ||
        !canonicalBase64Shape(token.tag, { exactBytes: HASH_OUTPUT_BYTES }) ||
        !canonicalBase64Shape(token.signatures.mldsa87, { exactBytes: ML_DSA_87_SIGNATURE_BYTES }) ||
        !canonicalBase64Shape(token.signatures.ed25519, { exactBytes: ED25519_SIGNATURE_BYTES })
      ) {
        throw new Error('Invalid token version');
      }

      const tokenStructure = {
        version: token.version,
        kyberCiphertext: token.kyberCiphertext,
        x25519EphemeralPublic: token.x25519EphemeralPublic,
        nonce: token.nonce,
        ciphertext: token.ciphertext,
        tag: token.tag,
      };

      tokenBytes = Buffer.from(JSON.stringify(tokenStructure), 'utf8');
      mldsaSignature = Buffer.from(token.signatures.mldsa87, 'base64');
      const mldsaValid = ml_dsa87.verify(mldsaSignature, tokenBytes, this.keypair.dilithium.publicKey);

      if (!mldsaValid) {
        throw new Error('SECURITY: ML-DSA-87 signature verification failed');
      }

      ed25519Signature = Buffer.from(token.signatures.ed25519, 'base64');
      const ed25519Valid = ed25519.verify(ed25519Signature, tokenBytes, this.keypair.ed25519.publicKey);

      if (!ed25519Valid) {
        throw new Error('SECURITY: Ed25519 signature verification failed');
      }

      kyberCiphertext = Buffer.from(token.kyberCiphertext, 'base64');
      kyberSharedSecret = ml_kem1024.decapsulate(kyberCiphertext, this.keypair.kyber.secretKey);
      x25519EphemeralPublic = Buffer.from(token.x25519EphemeralPublic, 'base64');
      x25519SharedSecret = x25519.getSharedSecret(this.keypair.x25519.secretKey, x25519EphemeralPublic);

      rawSecret = Buffer.concat([
        Buffer.from(kyberSharedSecret),
        Buffer.from(x25519SharedSecret),
      ]);

      info = new TextEncoder().encode(PROTOCOL_KEYS.ADMIN_TOKEN_ENCRYPTION);
      kdfSalt = CryptoUtils.Hash.shake256(rawSecret, 64);
      aeadKey = await CryptoUtils.KDF.quantumHKDF(
        new Uint8Array(rawSecret),
        kdfSalt,
        info,
        32
      );

      nonce = Buffer.from(token.nonce, 'base64');
      ciphertext = Buffer.from(token.ciphertext, 'base64');
      tag = Buffer.from(token.tag, 'base64');
      const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
      aad = new TextEncoder().encode(PROTOCOL_KEYS.ADMIN_TOKEN_AAD);
      try {
        payloadBytes = aead.decrypt(ciphertext, nonce, tag, aad);
      } catch (_error) {
        throw new Error('SECURITY: Decryption failed - invalid token');
      }

      if (!payloadBytes) {
        throw new Error('SECURITY: Decryption failed - invalid token');
      }

      const payload = parseJsonOrThrow(
        Buffer.from(payloadBytes).toString('utf8'),
        'Invalid admin token payload'
      );

      if (
        !hasExactPlainObjectKeys(payload, [
          'adminId', 'expiresAt', 'issuedAt', 'metadata', 'nonce', 'version'
        ]) ||
        payload.version !== ADMIN_CONFIG.TOKEN_VERSION ||
        !validAdminId(payload.adminId) ||
        !canonicalBase64Shape(payload.nonce, { exactBytes: 32 }) ||
        !Number.isSafeInteger(payload.issuedAt) ||
        !Number.isSafeInteger(payload.expiresAt) ||
        payload.expiresAt - payload.issuedAt !== ADMIN_CONFIG.TOKEN_EXPIRATION ||
        payload.issuedAt > Date.now() + 30_000 ||
        !validAdminMetadata(payload.metadata)
      ) throw new Error('Invalid admin token payload');

      if (Date.now() > payload.expiresAt) {
        throw new Error('Token expired');
      }

      const tokenHash = adminTokenHash(tokenString);
      let tokenExists;
      try {
        tokenExists = await withRedisClient(async (client) => {
          return await client.hexists(REDIS_KEYS.ADMIN_TOKENS, tokenHash);
        });
      } catch {
        throw adminAuthStoreUnavailable();
      }

      if (!tokenExists) {
        throw new Error('Token revoked or invalid');
      }

      return {
        valid: true,
        adminId: payload.adminId,
        metadata: payload.metadata,
        issuedAt: payload.issuedAt,
        expiresAt: payload.expiresAt,
        algorithm: ADMIN_CONFIG.ALGORITHM,
      };
    } catch (error) {
      console.error('[ADMIN] Token verification failed', { error: error.message });
      throw error;
    } finally {
      wipeBytes(
        tokenBytes,
        mldsaSignature,
        ed25519Signature,
        kyberCiphertext,
        kyberSharedSecret,
        x25519EphemeralPublic,
        x25519SharedSecret,
        rawSecret,
        info,
        kdfSalt,
        aeadKey,
        nonce,
        ciphertext,
        tag,
        aad,
        payloadBytes
      );
    }
  }

  // Revoke admin token
  async revokeToken(tokenString) {
    try {
      const tokenHash = adminTokenHash(tokenString);
      await withRedisClient(async (client) => {
        const removed = await client.hdel(REDIS_KEYS.ADMIN_TOKENS, tokenHash);
        if (removed > 0) {
          console.log('[ADMIN] Token revoked', {
            tokenHash: tokenHash.substring(0, 16) + '...',
          });
        }
      });
    } catch (error) {
      console.error('[ADMIN] Failed to revoke token', error);
      throw error;
    }
  }

  // Rate limiting
  async admitVerification() {
    try {
      return await withRedisClient(async (client) => {
        const count = Number(await client.eval(
          `
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
            return count
          `,
          1,
          REDIS_KEYS.ADMIN_VERIFY_ADMISSION,
          60
        ));
        return Number.isSafeInteger(count) && count <= ADMIN_VERIFY_MAX_PER_MINUTE;
      });
    } catch {
      throw adminAuthStoreUnavailable();
    }
  }

  async checkRateLimit(identifier) {
    const key = `${REDIS_KEYS.ADMIN_RATE_LIMIT}:${identifier}`;

    return await withRedisClient(async (client) => {
      const count = await client.incr(key);
      if (count === 1) {
        await client.expire(key, 60);
      }
      if (count > 10) {
        throw new Error('Rate limit exceeded for admin operations');
      }
      return count;
    });
  }

  // Log failed authentication attempt
  async logFailedAttempt(identifier, reason, ip) {
    const failKey = `${REDIS_KEYS.ADMIN_FAILURES}:${identifier}`;

    return await withRedisClient(async (client) => {
      const failures = await client.incr(failKey);

      if (failures === 1) {
        await client.expire(failKey, 3600);
      }

      if (failures >= ADMIN_CONFIG.MAX_FAILED_ATTEMPTS) {
        const lockKey = `${REDIS_KEYS.ADMIN_FAILURES}:lock:${identifier}`;
        await client.set(lockKey, '1', 'PX', ADMIN_CONFIG.LOCKOUT_DURATION);

        console.error('[ADMIN] Account locked', {
          identifier,
          failures,
          lockoutMinutes: ADMIN_CONFIG.LOCKOUT_DURATION / 60000,
        });

        throw new Error(`Account locked for ${ADMIN_CONFIG.LOCKOUT_DURATION / 60000} minutes`);
      }

      await client.lpush(REDIS_KEYS.ADMIN_AUDIT, JSON.stringify({
        event: 'auth_failure',
        identifier,
        reason,
        ip,
        timestamp: Date.now(),
        failures,
      }));
      await client.ltrim(REDIS_KEYS.ADMIN_AUDIT, 0, 999);
    });
  }

  // Check if locked out
  async isLockedOut(identifier) {
    const lockKey = `${REDIS_KEYS.ADMIN_FAILURES}:lock:${identifier}`;
    return await withRedisClient(async (client) => {
      const ttl = await client.ttl(lockKey);
      return ttl > 0;
    });
  }

  // Audit log
  async auditLog(adminId, action, details, ip) {
    await withRedisClient(async (client) => {
      await client.lpush(REDIS_KEYS.ADMIN_AUDIT, JSON.stringify({
        event: 'admin_action',
        adminId,
        action,
        details,
        ip,
        timestamp: Date.now(),
      }));
      await client.ltrim(REDIS_KEYS.ADMIN_AUDIT, 0, 999);
    });

    console.log('[ADMIN] Admin action', { adminId, action });
  }
}

const adminAuth = new AdminAuth();

// Express middleware for admin authentication
export async function requireAdmin(req, res, next) {
  const ip = req.socket?.remoteAddress || 'unknown';
  let failureIdentifier = null;
  let verificationAdmitted = false;
  let credentialVerified = false;
  try {
    if (!adminAuth.initialized) {
      return res.status(503).json({ success: false, error: 'Admin authentication unavailable' });
    }

    const authHeader = req.headers.authorization;
    if (
      typeof authHeader !== 'string' ||
      !/^Bearer [A-Za-z0-9_-]+$/.test(authHeader) ||
      authHeader.length <= 7 ||
      authHeader.length > ADMIN_TOKEN_MAX_CHARS + 7
    ) {
      return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    const token = authHeader.substring(7);
    failureIdentifier = `token:${adminTokenHash(token)}`;
    let verificationAllowed;
    let lockedOut;
    try {
      [verificationAllowed, lockedOut] = await Promise.all([
        adminAuth.admitVerification(),
        adminAuth.isLockedOut(failureIdentifier),
      ]);
    } catch {
      return res.status(503).json({ success: false, error: 'Admin authentication unavailable' });
    }
    if (!verificationAllowed) {
      return res.status(429).json({ success: false, error: 'Admin authentication busy' });
    }
    if (lockedOut) {
      return res.status(429).json({ success: false, error: 'Too many failed attempts' });
    }
    if (adminVerificationsInflight >= ADMIN_VERIFY_MAX_INFLIGHT) {
      return res.status(429).json({ success: false, error: 'Admin authentication busy' });
    }
    adminVerificationsInflight += 1;
    verificationAdmitted = true;
    const result = await adminAuth.verifyAdminToken(token);
    credentialVerified = true;
    await adminAuth.checkRateLimit(result.adminId);

    req.admin = {
      id: result.adminId,
      metadata: result.metadata,
    };

    await adminAuth.auditLog(
      result.adminId,
      `${req.method} ${req.path}`,
      { params: req.params, query: req.query },
      ip
    );

    next();
  } catch (error) {
    const storeUnavailable = error?.code === 'ADMIN_AUTH_STORE_UNAVAILABLE';
    if (failureIdentifier && !credentialVerified && !storeUnavailable) {
      try {
        await adminAuth.logFailedAttempt(failureIdentifier, 'credential_rejected', ip);
      } catch (_logError) {
      }
    }

    const rateLimited = credentialVerified && String(error?.message || '').includes('Rate limit');
    const status = rateLimited ? 429 : credentialVerified || storeUnavailable ? 503 : 403;

    res.status(status).json({
      success: false,
      error: status === 429
        ? 'Admin request rate limit exceeded'
        : status === 503
          ? 'Admin authentication unavailable'
          : 'Forbidden',
    });
  } finally {
    if (verificationAdmitted) {
      adminVerificationsInflight = Math.max(0, adminVerificationsInflight - 1);
    }
  }
}

// Initialize admin auth with credentials
export async function initializeAdminAuth(username, password) {
  return await adminAuth.initialize(username, password);
}

// Generate admin token
export async function generateAdminToken(adminId, metadata = {}) {
  return await adminAuth.generateAdminToken(adminId, metadata);
}

// Revoke admin token
export async function revokeAdminToken(tokenString) {
  return await adminAuth.revokeToken(tokenString);
}

export function destroyAdminAuth() {
  adminAuth.destroy();
}

export { adminAuth };

function takeAdminCliCredentials() {
  const username = process.env.CLUSTER_ADMIN_USERNAME;
  const password = process.env.CLUSTER_ADMIN_PASSWORD;
  delete process.env.CLUSTER_ADMIN_PASSWORD;
  if (typeof username !== 'string' || username.trim().length === 0 || typeof password !== 'string' || password.length === 0) {
    throw new Error('CLUSTER_ADMIN_USERNAME and CLUSTER_ADMIN_PASSWORD must be set in the environment');
  }
  return { username: username.trim(), password };
}

function parseAdminCliMetadata(raw) {
  if (raw === undefined) return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('metadata must be a valid JSON object');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('metadata must be a valid JSON object');
  }
  return parsed;
}

// CLI mode
if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];

  (async () => {
    try {
      switch (command) {
        case 'setup': {
          if (process.argv.length !== 3) {
            console.error('Usage: CLUSTER_ADMIN_USERNAME=... CLUSTER_ADMIN_PASSWORD=... node admin-auth.js setup');
            console.error('');
            console.error('Load credentials from a protected environment file rather than command arguments.');
            process.exit(1);
          }

          const { username, password } = takeAdminCliCredentials();

          console.log('[ADMIN] Setting up admin authentication...');
          console.log('[ADMIN] Generating hybrid keypair (PQ + Classical)...');

          await initializeAdminAuth(username, password);

          console.log('');
          console.log('Admin authentication setup complete!');
          console.log('');
          console.log('Algorithm:', ADMIN_CONFIG.ALGORITHM);
          console.log('Username:', username);
          console.log('Encrypted keys saved to:', ADMIN_KEYS_ENC_FILE);
          console.log('');
          console.log('SECURITY WARNINGS:');
          console.log('  - Keep your username and password secure');
          console.log('  - Without these credentials, keys cannot be unlocked');
          console.log('  - Losing credentials means losing admin access permanently');
          console.log('  - Use a password manager for the credentials');
          console.log('');
          break;
        }

        case 'generate': {
          if (process.argv.length < 4 || process.argv.length > 5) {
            console.error('Usage: CLUSTER_ADMIN_USERNAME=... CLUSTER_ADMIN_PASSWORD=... node admin-auth.js generate <adminId> [metadata]');
            console.error('');
            console.error('Credentials must be loaded from a protected environment file.');
            process.exit(1);
          }

          const { username, password } = takeAdminCliCredentials();
          const adminId = process.argv[3];
          const metadata = parseAdminCliMetadata(process.argv[4]);

          console.log('[ADMIN] Unlocking admin keys...');
          await initializeAdminAuth(username, password);

          console.log('[ADMIN] Generating admin token...');
          const token = await generateAdminToken(adminId, metadata);

          console.log('');
          console.log(' Admin token generated successfully!');
          console.log('');
          console.log('Admin ID:', adminId);
          console.log('Algorithm:', ADMIN_CONFIG.ALGORITHM);
          console.log('Expires:', new Date(Date.now() + ADMIN_CONFIG.TOKEN_EXPIRATION).toISOString());
          console.log('');
          console.log('Token:');
          console.log(token);
          console.log('');
          console.log('Usage examples:');
          console.log('  POSIX (bash/zsh):');
          console.log('    curl -H "Authorization: Bearer $CLUSTER_ADMIN_TOKEN" https://your-server/api/cluster/status');
          console.log('  PowerShell (Windows):');
          console.log('    Invoke-RestMethod -Uri https://your-server/api/cluster/status -Headers @{ Authorization = "Bearer $env:CLUSTER_ADMIN_TOKEN" }');
          console.log('');
          break;
        }

        default:
          console.log('Admin Authentication');
          console.log('');
          console.log('Commands:');
          console.log('  setup');
          console.log('    - Initialize keys using CLUSTER_ADMIN_USERNAME and CLUSTER_ADMIN_PASSWORD');
          console.log('');
          console.log('  generate <adminId> [metadata]');
          console.log('    - Generate a token using the same environment credentials');
          console.log('');
          console.log('Security: ' + ADMIN_CONFIG.ALGORITHM);
          console.log('');
          process.exit(0);
      }
    } catch (error) {
      console.error('');
      console.error('Error:', error.message);
      console.error('');
      process.exit(1);
    }
  })();
}
