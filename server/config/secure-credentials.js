/**
 * Credentials Manager for HAProxy
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { canonicalBase64Shape } from '../../shared/canonical-base64.js';
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
} from '../../shared/crypto-sizes.js';
import { CryptoUtils } from '../crypto/unified-crypto.js';
import { deriveQuantumAeadKey } from '../crypto/aead-key-derivation.js';
import { UTF8_ENCODER } from '../utils/encoding.js';
import { hasExactPlainObjectKeys } from '../utils/validation.js';
import { wipeByteArrays } from '../utils/wipe.js';
import { PROTOCOL_KEYS } from './protocol-keys.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CREDS_FILE = path.resolve(
  process.env.HAPROXY_CREDENTIALS_FILE || path.join(__dirname, '.haproxy-stats-creds.pqc')
);
const KEY_ENC_FILE = path.resolve(
  process.env.HAPROXY_KEYS_FILE || path.join(__dirname, '.haproxy-keys.enc')
);
const CREDENTIAL_VERSION = 2;
const CREDENTIAL_ALGORITHM = 'ML-KEM-1024 + X25519 + PostQuantumAEAD + ML-DSA-87';
const PRIVATE_FILE_MAX_BYTES = 64 * 1024;
const KEY_CIPHERTEXT_MAX_BYTES = 32 * 1024;
const CREDENTIAL_CIPHERTEXT_MAX_BYTES = 4 * 1024;
const HAPROXY_USERNAME_RE = /^[A-Za-z0-9_.-]{3,64}$/;
const HAPROXY_PASSWORD_RE = /^[A-Za-z0-9_~!@$%^&*+=,.?/-]{16,128}$/;

function wipeKeypair(keypair) {
  for (const family of Object.values(keypair || {})) {
    wipeByteArrays([family?.publicKey, family?.secretKey]);
  }
}

function parsePlainJson(raw, message) {
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(message);
    return parsed;
  } catch {
    throw new Error(message);
  }
}

function privatePathExists(filePath) {
  return fs.lstatSync(filePath, { throwIfNoEntry: false }) !== undefined;
}

function readPrivateJson(filePath, validator, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_CLOEXEC
    );
    const stat = fs.fstatSync(descriptor);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.size < 1 ||
      stat.size > PRIVATE_FILE_MAX_BYTES ||
      (stat.mode & 0o077) !== 0 ||
      (currentUid !== null && stat.uid !== currentUid)
    ) throw new Error(label);
    return validator(parsePlainJson(fs.readFileSync(descriptor, 'utf8'), label));
  } catch {
    throw new Error(label);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writePrivateJsonExclusive(filePath, value) {
  const serialized = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  let descriptor;
  let completed = false;
  try {
    if (serialized.length > PRIVATE_FILE_MAX_BYTES) throw new Error('Encrypted credential file is too large');
    descriptor = fs.openSync(
      filePath,
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
      try { fs.unlinkSync(filePath); } catch { }
    }
    serialized.fill(0);
  }
}

function validateKeyPackage(data) {
  if (
    !hasExactPlainObjectKeys(data, ['enc', 'kdf', 'usernameHash', 'version']) ||
    !hasExactPlainObjectKeys(data.kdf, ['algorithm', 'salt']) ||
    !hasExactPlainObjectKeys(data.enc, ['ciphertext', 'nonce', 'tag']) ||
    data.version !== CREDENTIAL_VERSION ||
    data.kdf.algorithm !== 'argon2id+quantumHKDF' ||
    !canonicalBase64Shape(data.kdf.salt, { exactBytes: HASH_OUTPUT_BYTES }) ||
    !canonicalBase64Shape(data.usernameHash, { exactBytes: HASH_OUTPUT_BYTES }) ||
    !canonicalBase64Shape(data.enc.nonce, { exactBytes: POST_QUANTUM_AEAD_NONCE_BYTES }) ||
    !canonicalBase64Shape(data.enc.tag, { exactBytes: HASH_OUTPUT_BYTES }) ||
    !canonicalBase64Shape(data.enc.ciphertext, { maxBytes: KEY_CIPHERTEXT_MAX_BYTES })
  ) throw new Error('Invalid encrypted HAProxy key package');
  return data;
}

function validateSerializedKeypair(keys) {
  if (
    !hasExactPlainObjectKeys(keys, [
      'dilithiumPublicKey',
      'dilithiumSecretKey',
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
    !canonicalBase64Shape(keys.x25519SecretKey, { exactBytes: X25519_KEY_BYTES })
  ) throw new Error('Invalid decrypted HAProxy keypair');
  return keys;
}

function validateEncryptedCredentials(data) {
  if (
    !hasExactPlainObjectKeys(data, ['algorithm', 'encrypted', 'signature', 'version']) ||
    !hasExactPlainObjectKeys(data.encrypted, [
      'ciphertext', 'kyberCiphertext', 'nonce', 'tag', 'x25519EphemeralPublic'
    ]) ||
    data.version !== CREDENTIAL_VERSION ||
    data.algorithm !== CREDENTIAL_ALGORITHM ||
    !canonicalBase64Shape(data.signature, { exactBytes: ML_DSA_87_SIGNATURE_BYTES }) ||
    !canonicalBase64Shape(data.encrypted.kyberCiphertext, {
      exactBytes: ML_KEM_1024_CIPHERTEXT_BYTES,
    }) ||
    !canonicalBase64Shape(data.encrypted.x25519EphemeralPublic, {
      exactBytes: X25519_KEY_BYTES,
    }) ||
    !canonicalBase64Shape(data.encrypted.nonce, {
      exactBytes: POST_QUANTUM_AEAD_NONCE_BYTES,
    }) ||
    !canonicalBase64Shape(data.encrypted.tag, { exactBytes: HASH_OUTPUT_BYTES }) ||
    !canonicalBase64Shape(data.encrypted.ciphertext, {
      maxBytes: CREDENTIAL_CIPHERTEXT_MAX_BYTES,
    })
  ) throw new Error('Invalid encrypted HAProxy credential package');
  return data;
}

function validateCredentials(credentials) {
  if (
    !hasExactPlainObjectKeys(credentials, ['password', 'timestamp', 'username', 'version']) ||
    credentials.version !== CREDENTIAL_VERSION ||
    typeof credentials.username !== 'string' ||
    !HAPROXY_USERNAME_RE.test(credentials.username) ||
    typeof credentials.password !== 'string' ||
    !HAPROXY_PASSWORD_RE.test(credentials.password) ||
    !Number.isSafeInteger(credentials.timestamp) ||
    credentials.timestamp <= 0 ||
    credentials.timestamp > Date.now() + 30_000
  ) throw new Error('Invalid decrypted HAProxy credentials');
  return credentials;
}

async function deriveKEK(username, password, salt) {
  if (typeof username !== 'string' || !HAPROXY_USERNAME_RE.test(username)) {
    throw new Error('HAProxy stats username must contain 3 to 64 safe ASCII characters');
  }
  if (typeof password !== 'string' || !HAPROXY_PASSWORD_RE.test(password)) {
    throw new Error('HAProxy stats password must contain 16 to 128 safe ASCII characters');
  }
  const usernameBytes = Buffer.from(username, 'utf8');
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
    wipeByteArrays([usernameBytes, usernameHash, derived?.kek, derived?.salt]);
  }
}

async function generateAndProtectKeypair(username, password) {
  const kyber = ml_kem1024.keygen();
  const dilithiumSeed = crypto.randomBytes(32);
  let dilithium;
  try {
    dilithium = ml_dsa87.keygen(dilithiumSeed);
  } finally {
    dilithiumSeed.fill(0);
  }
  const x25519SecretKey = crypto.randomBytes(X25519_KEY_BYTES);
  const keypair = {
    kyber,
    dilithium,
    x25519: {
      publicKey: x25519.getPublicKey(x25519SecretKey),
      secretKey: x25519SecretKey,
    },
  };
  let derived;
  let keysBlob;
  let nonce;
  let ciphertext;
  let tag;
  try {
    derived = await deriveKEK(username, password);
    keysBlob = Buffer.from(JSON.stringify({
      kyberSecretKey: Buffer.from(keypair.kyber.secretKey).toString('base64'),
      dilithiumSecretKey: Buffer.from(keypair.dilithium.secretKey).toString('base64'),
      x25519SecretKey: Buffer.from(keypair.x25519.secretKey).toString('base64'),
      kyberPublicKey: Buffer.from(keypair.kyber.publicKey).toString('base64'),
      dilithiumPublicKey: Buffer.from(keypair.dilithium.publicKey).toString('base64'),
      x25519PublicKey: Buffer.from(keypair.x25519.publicKey).toString('base64'),
    }), 'utf8');
    const aead = new CryptoUtils.PostQuantumAEAD(derived.kek);
    nonce = CryptoUtils.Random.generateRandomBytes(POST_QUANTUM_AEAD_NONCE_BYTES);
    const aad = UTF8_ENCODER.encode(PROTOCOL_KEYS.HAPROXY_SECURE_CREDENTIALS_AAD);
    ({ ciphertext, tag } = aead.encrypt(keysBlob, nonce, aad));
    const payload = validateKeyPackage({
      version: CREDENTIAL_VERSION,
      kdf: {
        algorithm: 'argon2id+quantumHKDF',
        salt: derived.salt.toString('base64'),
      },
      usernameHash: derived.usernameHash.toString('base64'),
      enc: {
        nonce: Buffer.from(nonce).toString('base64'),
        tag: Buffer.from(tag).toString('base64'),
        ciphertext: Buffer.from(ciphertext).toString('base64'),
      },
    });
    writePrivateJsonExclusive(KEY_ENC_FILE, payload);
    console.log('[SECURE-CREDS] All keypairs generated and saved to:', KEY_ENC_FILE);
    return keypair;
  } catch (error) {
    wipeKeypair(keypair);
    throw error;
  } finally {
    wipeByteArrays([
      derived?.kek,
      derived?.usernameHash,
      derived?.salt,
      keysBlob,
      nonce,
      ciphertext,
      tag,
    ]);
  }
}

export async function unlockKeypair(username, password) {
  if (!privatePathExists(KEY_ENC_FILE)) throw new Error('Encrypted key file not found');
  const data = readPrivateJson(
    KEY_ENC_FILE,
    validateKeyPackage,
    'Invalid encrypted HAProxy key file'
  );
  let salt;
  let derived;
  let storedHash;
  let nonce;
  let tag;
  let ciphertext;
  let decrypted;
  let candidate;
  try {
    salt = Buffer.from(data.kdf.salt, 'base64');
    derived = await deriveKEK(username, password, salt);
    storedHash = Buffer.from(data.usernameHash, 'base64');
    if (!crypto.timingSafeEqual(derived.usernameHash, storedHash)) {
      throw new Error('Username does not match encrypted keyset');
    }
    nonce = Buffer.from(data.enc.nonce, 'base64');
    tag = Buffer.from(data.enc.tag, 'base64');
    ciphertext = Buffer.from(data.enc.ciphertext, 'base64');
    const aead = new CryptoUtils.PostQuantumAEAD(derived.kek);
    const aad = UTF8_ENCODER.encode(PROTOCOL_KEYS.HAPROXY_SECURE_CREDENTIALS_AAD);
    decrypted = aead.decrypt(ciphertext, nonce, tag, aad);
    const keys = validateSerializedKeypair(parsePlainJson(
      decrypted.toString('utf8'),
      'Invalid decrypted HAProxy keypair'
    ));
    candidate = {
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
    };
    const result = candidate;
    candidate = null;
    return result;
  } finally {
    wipeKeypair(candidate);
    wipeByteArrays([
      salt,
      derived?.kek,
      derived?.usernameHash,
      derived?.salt,
      storedHash,
      nonce,
      tag,
      ciphertext,
      decrypted,
    ]);
  }
}

async function encryptCredentials(username, password) {
  let keypair;
  const temporaryBytes = [];
  try {
    keypair = await generateAndProtectKeypair(username, password);
    const plaintext = Buffer.from(JSON.stringify({
      username,
      password,
      timestamp: Date.now(),
      version: CREDENTIAL_VERSION,
    }), 'utf8');
    temporaryBytes.push(plaintext);
    const ephemeralSecret = crypto.randomBytes(X25519_KEY_BYTES);
    const ephemeralPublic = x25519.getPublicKey(ephemeralSecret);
    const x25519Shared = x25519.getSharedSecret(ephemeralSecret, keypair.x25519.publicKey);
    const kem = ml_kem1024.encapsulate(keypair.kyber.publicKey);
    temporaryBytes.push(ephemeralSecret, ephemeralPublic, x25519Shared, kem.sharedSecret);
    const rawSecret = Buffer.concat([Buffer.from(kem.sharedSecret), Buffer.from(x25519Shared)]);
    const aeadKey = await deriveQuantumAeadKey(rawSecret, PROTOCOL_KEYS.HAPROXY_CREDENTIALS);
    temporaryBytes.push(rawSecret, aeadKey);
    const nonce = CryptoUtils.Random.generateRandomBytes(POST_QUANTUM_AEAD_NONCE_BYTES);
    const aad = UTF8_ENCODER.encode(PROTOCOL_KEYS.HAPROXY_CREDENTIALS);
    const { ciphertext, tag } = new CryptoUtils.PostQuantumAEAD(aeadKey)
      .encrypt(plaintext, nonce, aad);
    const kyberCiphertext = kem.cipherText;
    temporaryBytes.push(nonce, aad, ciphertext, tag, kyberCiphertext);
    const encrypted = {
      kyberCiphertext: Buffer.from(kyberCiphertext).toString('base64'),
      x25519EphemeralPublic: Buffer.from(ephemeralPublic).toString('base64'),
      nonce: Buffer.from(nonce).toString('base64'),
      tag: Buffer.from(tag).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
    };
    const packageBytes = Buffer.from(JSON.stringify(encrypted), 'utf8');
    const signature = ml_dsa87.sign(packageBytes, keypair.dilithium.secretKey);
    temporaryBytes.push(packageBytes, signature);
    return validateEncryptedCredentials({
      version: CREDENTIAL_VERSION,
      encrypted,
      signature: Buffer.from(signature).toString('base64'),
      algorithm: CREDENTIAL_ALGORITHM,
    });
  } finally {
    wipeKeypair(keypair);
    wipeByteArrays(temporaryBytes);
  }
}

async function decryptCredentials(encryptedObj, { username, password } = {}) {
  validateEncryptedCredentials(encryptedObj);
  let keypair;
  const temporaryBytes = [];
  try {
    keypair = await unlockKeypair(username, password);
    const encrypted = encryptedObj.encrypted;
    const packageBytes = Buffer.from(JSON.stringify(encrypted), 'utf8');
    const signature = Buffer.from(encryptedObj.signature, 'base64');
    temporaryBytes.push(packageBytes, signature);
    if (!ml_dsa87.verify(signature, packageBytes, keypair.dilithium.publicKey)) {
      throw new Error('SECURITY: Credential signature verification failed');
    }
    const kyberCiphertext = Buffer.from(encrypted.kyberCiphertext, 'base64');
    const ephemeralPublic = Buffer.from(encrypted.x25519EphemeralPublic, 'base64');
    const nonce = Buffer.from(encrypted.nonce, 'base64');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
    const tag = Buffer.from(encrypted.tag, 'base64');
    const kyberShared = ml_kem1024.decapsulate(kyberCiphertext, keypair.kyber.secretKey);
    const x25519Shared = x25519.getSharedSecret(keypair.x25519.secretKey, ephemeralPublic);
    temporaryBytes.push(
      kyberCiphertext,
      ephemeralPublic,
      nonce,
      ciphertext,
      tag,
      kyberShared,
      x25519Shared
    );
    const rawSecret = Buffer.concat([Buffer.from(kyberShared), Buffer.from(x25519Shared)]);
    const aeadKey = await deriveQuantumAeadKey(rawSecret, PROTOCOL_KEYS.HAPROXY_CREDENTIALS);
    temporaryBytes.push(rawSecret, aeadKey);
    const aad = UTF8_ENCODER.encode(PROTOCOL_KEYS.HAPROXY_CREDENTIALS);
    const plaintext = new CryptoUtils.PostQuantumAEAD(aeadKey)
      .decrypt(ciphertext, nonce, tag, aad);
    temporaryBytes.push(aad, plaintext);
    return validateCredentials(parsePlainJson(
      plaintext.toString('utf8'),
      'Invalid decrypted HAProxy credentials'
    ));
  } finally {
    wipeKeypair(keypair);
    wipeByteArrays(temporaryBytes);
  }
}

export async function saveCredentials(username, password) {
  if (privatePathExists(CREDS_FILE) || privatePathExists(KEY_ENC_FILE)) {
    throw new Error('HAProxy credential files already exist; refusing to overwrite them');
  }
  console.log('[SECURE-CREDS] Encrypting credentials...');
  try {
    const encrypted = await encryptCredentials(username, password);
    writePrivateJsonExclusive(CREDS_FILE, encrypted);
    console.log(`[SECURE-CREDS] Credentials encrypted and saved to: (${CREDS_FILE})`);
  } catch (error) {
    for (const filePath of [CREDS_FILE, KEY_ENC_FILE]) {
      try { fs.unlinkSync(filePath); } catch { }
    }
    throw error;
  }
}

export async function loadCredentials({ username, password } = {}) {
  if (!privatePathExists(CREDS_FILE)) return null;
  const encrypted = readPrivateJson(
    CREDS_FILE,
    validateEncryptedCredentials,
    'Invalid encrypted HAProxy credential file'
  );
  console.log('[SECURE-CREDS] Decrypting credentials...');
  const credentials = await decryptCredentials(encrypted, { username, password });
  console.log('[SECURE-CREDS] Credentials decrypted successfully');
  return credentials;
}

export async function verifyCredentials(username, password) {
  const stored = await loadCredentials({ username, password });
  if (!stored) throw new Error('No credentials stored');
  const candidateUsername = Buffer.from(String(username), 'utf8');
  const storedUsername = Buffer.from(String(stored.username), 'utf8');
  const candidatePassword = Buffer.from(String(password), 'utf8');
  const storedPassword = Buffer.from(String(stored.password), 'utf8');
  try {
    return candidateUsername.length === storedUsername.length &&
      candidatePassword.length === storedPassword.length &&
      crypto.timingSafeEqual(candidateUsername, storedUsername) &&
      crypto.timingSafeEqual(candidatePassword, storedPassword);
  } finally {
    wipeByteArrays([candidateUsername, storedUsername, candidatePassword, storedPassword]);
    stored.username = '';
    stored.password = '';
  }
}

export function deleteCredentials() {
  for (const [filePath, label] of [
    [CREDS_FILE, 'Credentials file'],
    [KEY_ENC_FILE, 'Encrypted key file'],
  ]) {
    if (!privatePathExists(filePath)) continue;
    try {
      const stat = fs.lstatSync(filePath);
      if (!stat.isFile() || stat.nlink !== 1) throw new Error(`Refusing to delete unsafe ${label}`);
      fs.unlinkSync(filePath);
      console.log(`[SECURE-CREDS] ${label} deleted`);
    } catch (error) {
      throw new Error(`Failed to delete ${label}: ${error.message}`);
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];
  (async () => {
    try {
      if (process.argv.length > 3) {
        throw new Error('Credentials must not be passed in process arguments');
      }
      const username = typeof process.env.HAPROXY_STATS_USERNAME === 'string'
        ? process.env.HAPROXY_STATS_USERNAME.trim()
        : '';
      const password = typeof process.env.HAPROXY_STATS_PASSWORD === 'string'
        ? process.env.HAPROXY_STATS_PASSWORD
        : '';
      const requireEnvironmentCredentials = () => {
        if (!username || !password) {
          throw new Error('HAPROXY_STATS_USERNAME and HAPROXY_STATS_PASSWORD are required');
        }
      };
      switch (command) {
        case 'save':
          requireEnvironmentCredentials();
          await saveCredentials(username, password);
          break;
        case 'load':
          console.error('Usage: node secure-credentials.js load-unlocked');
          process.exit(2);
          break;
        case 'load-unlocked': {
          requireEnvironmentCredentials();
          const credentials = await loadCredentials({
            username,
            password,
          });
          if (credentials) {
            console.log('');
            console.log('Credentials:');
            console.log('\tUsername:', credentials.username);
            console.log('\tPassword:', '********');
            console.log('\tStored:', new Date(credentials.timestamp).toISOString());
            credentials.username = '';
            credentials.password = '';
          } else {
            console.log('No credentials found');
          }
          break;
        }
        case 'delete':
          deleteCredentials();
          break;
        case 'verify':
          requireEnvironmentCredentials();
          if (await verifyCredentials(username, password)) {
            console.log('OK');
            process.exit(0);
          }
          console.log('MISMATCH');
          process.exit(1);
          break;
        default:
          console.log('Credentials Manager for HAProxy\n');
          console.log('Usage:');
          console.log('\tLoad HAPROXY_STATS_USERNAME and HAPROXY_STATS_PASSWORD from a protected environment file, then run:');
          console.log('\tnode secure-credentials.js save');
          console.log('\tnode secure-credentials.js load-unlocked');
          console.log('\tnode secure-credentials.js verify');
          console.log('\tnode secure-credentials.js delete');
          process.exit(1);
      }
    } catch (error) {
      console.error('[ERROR]', error.message);
      process.exit(1);
    }
  })();
}
