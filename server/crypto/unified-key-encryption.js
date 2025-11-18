/**
 * Unified Private Key Encryption System
 * 
 * Provides consistent, quantum-resistant encryption for server key material:
 * - Post-quantum private keys (ML-DSA, ML-KEM)
 * - Internal audit keys for key metadata integrity
 * 
 * Security Features:
 * - QuantumResistantAEAD v3 encryption (AES-256-GCM -> XChaCha20-Poly1305 cascade + BLAKE3 MAC)
 * - Argon2id v1.3 key derivation with quantum-resistant parameters
 * - Constant-time operations to prevent timing attacks
 * - Secure memory management with zeroing
 * - Domain-separated cryptographic keys via SHAKE256
 */

import crypto from 'crypto';
import argon2 from 'argon2';
import { blake3 } from '@noble/hashes/blake3.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import fs from 'fs/promises';
import path from 'path';
import { logger } from './crypto-logger.js';

const SUPPORTED_KEY_TYPES = new Set(['mldsa', 'mlkem']);

const isTypedArray = (value) => ArrayBuffer.isView(value) && !(value instanceof DataView);

const toUint8Array = (value, name) => {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (Buffer.isBuffer(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  throw new TypeError(`${name} must be a Uint8Array or Buffer-like object`);
};

const normalizeForSerialization = (value) => {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => normalizeForSerialization(item))
      .filter((item) => item !== undefined);
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value === 'object') {
    if (isTypedArray(value)) {
      return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64');
    }
    if (Buffer.isBuffer(value)) {
      return value.toString('base64');
    }
    const sortedKeys = Object.keys(value).sort();
    const normalized = {};
    for (const key of sortedKeys) {
      const normalizedValue = normalizeForSerialization(value[key]);
      if (normalizedValue !== undefined) {
        normalized[key] = normalizedValue;
      }
    }
    return normalized;
  }
  return value;
};

const stableStringify = (value) => JSON.stringify(normalizeForSerialization(value));


/**
 * Unified Key Encryption Configuration
 * Uses quantum-resistant parameters for maximum security
 */
const UNIFIED_KEY_CONFIG = {
  // QuantumResistantAEAD parameters
  NONCE_LENGTH: 24,           // 24-byte nonce  
  KEY_LENGTH: 64,             // 512-bit master/domain keys
  TAG_LENGTH: 16,             // 128-bit authentication tag
  QR_NONCE_LENGTH: 36,        // 12 (AES-GCM) + 24 (XChaCha20-Poly1305)
  
  // Argon2id parameters (quantum-resistant)
  ARGON2_MEMORY: Math.min(Math.max(parseInt(process.env.UNIFIED_ARGON2_MEMORY || '', 10) || 262144, 131072), 524288), // clamp 128MB-512MB in KiB
  ARGON2_TIME: Math.min(Math.max(parseInt(process.env.UNIFIED_ARGON2_TIME || '', 10) || 4, 2), 8),
  ARGON2_PARALLELISM: Math.min(Math.max(parseInt(process.env.UNIFIED_ARGON2_PARALLELISM || '', 10) || 2, 1), 8),
  ARGON2_VERSION: 0x13,       // Argon2 v1.3
  ARGON2_ALGORITHM: 2,        // argon2id
  
  // Salt and secret management
  SALT_LENGTH: 64,            // 512-bit salt
  SECRET_LENGTH: 64,          // 512-bit secret
  
  // Key versioning
  CURRENT_VERSION: 3,         // Current encryption scheme version (QuantumResistantAEAD)
  MIN_SUPPORTED_VERSION: 3,   // Enforce v3-only 
  
  // File permissions
  PRIVATE_KEY_MODE: 0o600,    // Owner read/write only
  PUBLIC_KEY_MODE: 0o644,     // Owner read/write, others read
  CONFIG_MODE: 0o600,         // Owner read/write only
};
Object.freeze(UNIFIED_KEY_CONFIG);


/**
 * QuantumResistantAEAD Implementation (v3)
 * AES-256-GCM -> XChaCha20-Poly1305 cascade + BLAKE3 MAC
 * Key: 64 bytes (32 for AES-256-GCM + 32 for XChaCha20)
 * Nonce: 36 bytes (12 for AES-GCM + 24 for XChaCha20)
 */
class QuantumResistantAEAD {
  constructor(key) {
    if (!key || key.length !== 64) {
      throw new Error('QuantumResistantAEAD requires a 64-byte key');
    }
    this.key1 = key.slice(0, 32);
    this.key2 = key.slice(32, 64);
    this.macKey = shake256(key, { dkLen: 64 });
  }

  encrypt(plaintext, nonce = null, aad = null) {
    if (!plaintext || plaintext.length === 0) {
      throw new Error('Plaintext cannot be empty');
    }
    const usedNonce = nonce || this.generateNonce();
    if (usedNonce.length !== UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH) {
      throw new Error(`Invalid nonce length: ${usedNonce.length}, expected ${UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH}`);
    }

    const aadBytes = aad || new Uint8Array(0);

    // Layer 1: AES-256-GCM
    const aesNonce = usedNonce.slice(0, 12);
    const aesCipher = gcm(this.key1, aesNonce, aadBytes);
    const aesResult = aesCipher.encrypt(plaintext);

    // Layer 2: XChaCha20-Poly1305
    const chachaNonce = usedNonce.slice(12, 36);
    const chachaCipher = xchacha20poly1305(this.key2, chachaNonce, aadBytes);
    const chachaResult = chachaCipher.encrypt(aesResult);

    // MAC: BLAKE3 keyed with first 32 bytes of macKey
    const macKey = this.macKey.slice(0, 32);
    const macInput = new Uint8Array(chachaResult.length + aadBytes.length + usedNonce.length);
    macInput.set(chachaResult, 0);
    macInput.set(aadBytes, chachaResult.length);
    macInput.set(usedNonce, chachaResult.length + aadBytes.length);
    const mac = blake3(macInput, { key: macKey });

    const combined = new Uint8Array(chachaResult.length + mac.length);
    combined.set(chachaResult, 0);
    combined.set(mac, chachaResult.length);

    return { nonce: usedNonce, ciphertext: combined };
  }

  decrypt(ciphertext, nonce, aad = null) {
    if (!ciphertext || ciphertext.length < 32) {
      throw new Error('Ciphertext too short for QuantumResistantAEAD');
    }
    if (!nonce || nonce.length !== UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH) {
      throw new Error(`Invalid nonce length: ${nonce?.length}, expected ${UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH}`);
    }
    const aadBytes = aad || new Uint8Array(0);

    const mac = ciphertext.slice(-32);
    const enc = ciphertext.slice(0, -32);

    const macKey = this.macKey.slice(0, 32);
    const macInput = new Uint8Array(enc.length + aadBytes.length + nonce.length);
    macInput.set(enc, 0);
    macInput.set(aadBytes, enc.length);
    macInput.set(nonce, enc.length + aadBytes.length);
    const expectedMac = blake3(macInput, { key: macKey });

    try {
      if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expectedMac))) {
        throw new Error('MAC verification failed');
      }
    } catch (_error) {
      throw new Error('MAC verification failed');
    }

    // Decrypt layer 2: XChaCha20-Poly1305
    const chachaNonce = nonce.slice(12, 36);
    const chachaCipher = xchacha20poly1305(this.key2, chachaNonce, aadBytes);
    const aesResult = chachaCipher.decrypt(enc);

    // Decrypt layer 1: AES-256-GCM
    const aesNonce = nonce.slice(0, 12);
    const aesCipher = gcm(this.key1, aesNonce, aadBytes);
    return aesCipher.decrypt(aesResult);
  }

  generateNonce() {
    const raw = crypto.randomBytes(UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH);
    return shake256(raw, { dkLen: UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH });
  }
}

/**
 * Unified Key Encryption Service
 * Handles encryption/decryption of all private key types
 */
class UnifiedKeyEncryption {
  constructor(keyPairPath) {
    if (!keyPairPath || typeof keyPairPath !== 'string') {
      throw new Error('keyPairPath must be a non-empty string');
    }
    this.keyPairPath = path.resolve(keyPairPath);
    this.masterKey = null;
    this.salt = null;
    this.initialized = false;
    this.domainKeys = new Map();
  }

  /**
   * Initialize the encryption service
   * @param {string} secret - Master secret for key derivation
   * @param {Uint8Array} salt - Salt for key derivation (optional)
   * @returns {Promise<void>}
   */
  async initialize(secret, salt = null) {
    if (this.initialized) return;

    if (!secret || typeof secret !== 'string') {
      throw new Error('Secret must be a non-empty string');
    }

    if (secret.length > 1024) {
      throw new Error('Secret length exceeds maximum allowed size');
    }


    // Ensure directory exists and is secure
    await this.createSecureDirectory(this.keyPairPath);

    // Load or create salt (persisted)
    const usedSalt = await this.getOrCreateSalt(salt);

    // Derive 64-byte master key using Node argon2id
    const argon2Result = await argon2.hash(secret, {
      type: argon2.argon2id,
      version: UNIFIED_KEY_CONFIG.ARGON2_VERSION,
      memoryCost: UNIFIED_KEY_CONFIG.ARGON2_MEMORY,
      timeCost: UNIFIED_KEY_CONFIG.ARGON2_TIME,
      parallelism: UNIFIED_KEY_CONFIG.ARGON2_PARALLELISM,
      hashLength: UNIFIED_KEY_CONFIG.KEY_LENGTH,
      salt: Buffer.from(usedSalt),
      raw: true
    });

    if (!argon2Result || argon2Result.length !== UNIFIED_KEY_CONFIG.KEY_LENGTH) {
      throw new Error('Argon2 key derivation failed');
    }

    this.masterKey = new Uint8Array(argon2Result);
    this.salt = usedSalt;

    // Initialize domain-separated keys
    await this.initializeDomainKeys();

    this.initialized = true;
    logger.info('UnifiedKeyEncryption initialized', { version: UNIFIED_KEY_CONFIG.CURRENT_VERSION });
  }

  /**
   * Encrypt a private key using QuantumResistantAEAD
   * @param {Uint8Array|Buffer|string} privateKey - Private key to encrypt
   * @param {string} keyType - Type of key (rsa, ec, postquantum, ed25519)
   * @param {Uint8Array} aad - Additional authenticated data (optional)
   * @returns {Promise<Object>} - Encrypted key data
   */
  async encryptPrivateKey(privateKey, keyType, aad = null) {
    if (!this.initialized) {
      throw new Error('UnifiedKeyEncryption not initialized');
    }

    if (!privateKey) {
      throw new Error('Private key cannot be empty');
    }

    if (!keyType || typeof keyType !== 'string') {
      throw new Error('keyType must be a non-empty string');
    }

    const normalizedKeyType = keyType.trim().toLowerCase();
    if (!SUPPORTED_KEY_TYPES.has(normalizedKeyType)) {
      throw new Error(`Unsupported key type: ${keyType}`);
    }


    // Convert to Uint8Array
    let keyBytes;
    if (typeof privateKey === 'string') {
      keyBytes = new TextEncoder().encode(privateKey);
    } else if (privateKey instanceof Uint8Array || Buffer.isBuffer(privateKey) || ArrayBuffer.isView(privateKey)) {
      keyBytes = toUint8Array(privateKey, 'privateKey');
    } else if (privateKey instanceof ArrayBuffer) {
      keyBytes = new Uint8Array(privateKey);
    } else {
      throw new Error('Unsupported private key format');
    }

    // Create authenticated AAD
    const contextAad = aad || this.createAAD(normalizedKeyType, {});

    // Use domain-separated key for AEAD
    const domainKey = this.getDomainKey(normalizedKeyType);
    const aead = new QuantumResistantAEAD(domainKey);
    const result = aead.encrypt(keyBytes, null, contextAad);

    const encryptedData = {
      version: UNIFIED_KEY_CONFIG.CURRENT_VERSION,
      keyType: normalizedKeyType,
      nonce: Buffer.from(result.nonce).toString('base64'),
      ciphertext: Buffer.from(result.ciphertext).toString('base64'),
      salt: Buffer.from(this.salt).toString('base64'),
      algorithm: 'QuantumResistantAEAD',
      quantumSecurityBits: 256,
      kdf: {
        algorithm: 'argon2id',
        memory: UNIFIED_KEY_CONFIG.ARGON2_MEMORY,
        time: UNIFIED_KEY_CONFIG.ARGON2_TIME,
        parallelism: UNIFIED_KEY_CONFIG.ARGON2_PARALLELISM,
        version: UNIFIED_KEY_CONFIG.ARGON2_VERSION
      }
    };

    // Add metadata MAC for integrity
    const macKey = this.getDomainKey('audit').slice(0, 32);
    const mac = blake3(Buffer.from(stableStringify(encryptedData)), { key: macKey });
    encryptedData.metadataMAC = Buffer.from(mac).toString('base64');

    return encryptedData;
  }

  /**
   * Decrypt a private key using QuantumResistantAEAD
   * @param {Object} encryptedKeyData - Encrypted key data
   * @param {string} expectedKeyType - Expected key type for validation
   * @returns {Promise<Uint8Array>} - Decrypted private key
   */
  async decryptPrivateKey(encryptedKeyData, expectedKeyType) {
    if (!this.initialized) {
      throw new Error('UnifiedKeyEncryption not initialized');
    }

    // Validate encrypted key data structure
    if (!encryptedKeyData || typeof encryptedKeyData !== 'object') {
      throw new Error('Invalid encrypted key data');
    }

    const { version, keyType, nonce, ciphertext, salt, algorithm, metadataMAC } = encryptedKeyData;

    // Validate required fields
    if (typeof version !== 'number') {
      throw new Error('Encrypted key data missing version');
    }
    if (typeof nonce !== 'string' || !nonce) {
      throw new Error('Encrypted key data missing nonce');
    }
    if (typeof ciphertext !== 'string' || !ciphertext) {
      throw new Error('Encrypted key data missing ciphertext');
    }
    if (typeof salt !== 'string' || !salt) {
      throw new Error('Encrypted key data missing salt');
    }
    if (typeof algorithm !== 'string' || !algorithm) {
      throw new Error('Encrypted key data missing algorithm');
    }

    // Version compatibility check
    if (version < UNIFIED_KEY_CONFIG.MIN_SUPPORTED_VERSION || version > UNIFIED_KEY_CONFIG.CURRENT_VERSION) {
      throw new Error(`Unsupported key version: ${version}`);
    }

    // Key type validation
    if (typeof keyType !== 'string') {
      throw new Error('Encrypted key data missing key type');
    }

    const normalizedKeyType = keyType.trim().toLowerCase();
    if (!SUPPORTED_KEY_TYPES.has(normalizedKeyType)) {
      throw new Error(`Unsupported key type: ${keyType}`);
    }

    if (expectedKeyType && normalizedKeyType !== expectedKeyType.trim().toLowerCase()) {
      throw new Error(`Key type mismatch: expected ${expectedKeyType}, got ${keyType}`);
    }

    // Decode base64 data
    const nonceBytes = Buffer.from(nonce, 'base64');
    const ciphertextBytes = Buffer.from(ciphertext, 'base64');
    const saltBytes = Buffer.from(salt, 'base64');

    // Validate lengths
    if (algorithm === 'QuantumResistantAEAD') {
      if (nonceBytes.length !== UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH) {
        throw new Error(`Invalid nonce length: ${nonceBytes.length}`);
      }
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    if (saltBytes.length !== UNIFIED_KEY_CONFIG.SALT_LENGTH) {
      throw new Error(`Invalid salt length: ${saltBytes.length}`);
    }

    // Enforce salt match
    if (!this.constantTimeCompare(saltBytes, this.salt)) {
      throw new Error('Salt mismatch: key encrypted under a different salt');
    }

    // Verify metadata integrity if present
    if (metadataMAC) {
      const macKey = this.getDomainKey('audit').slice(0, 32);
      const expectedMac = blake3(Buffer.from(stableStringify({
        version,
        keyType: normalizedKeyType,
        nonce,
        ciphertext,
        salt,
        algorithm,
        metadataMAC: undefined,
        kdf: encryptedKeyData.kdf,
        quantumSecurityBits: encryptedKeyData.quantumSecurityBits
      })), { key: macKey });
      const providedMac = Buffer.from(metadataMAC, 'base64');
      try {
        if (!crypto.timingSafeEqual(Buffer.from(expectedMac), providedMac)) {
          throw new Error('Metadata MAC mismatch');
        }
      } catch {
        throw new Error('Metadata MAC mismatch');
      }
    }

    // Create AAD
    const contextAad = this.createAAD(normalizedKeyType, {});

    // QuantumResistantAEAD v3
    const domainKey = this.getDomainKey(normalizedKeyType);
    const qaead = new QuantumResistantAEAD(domainKey);
    const decryptedKey = qaead.decrypt(ciphertextBytes, nonceBytes, contextAad);
    
    return decryptedKey;
  }

  /**
   * Encrypt and save a private key to file
   * @param {string} keyName - Name of the key file (without extension)
   * @param {Uint8Array|Buffer|string} privateKey - Private key to encrypt
   * @param {string} keyType - Type of key
   * @returns {Promise<void>}
   */
  async encryptAndSavePrivateKey(keyName, privateKey, keyType) {
    const safeName = this.sanitizeKeyName(keyName);
    const encryptedData = await this.encryptPrivateKey(privateKey, keyType);
    const filePath = path.join(this.keyPairPath, `${safeName}-private.enc`);

    const data = Buffer.from(JSON.stringify(encryptedData, null, 2), 'utf8');
    await this.atomicWrite(filePath, data, UNIFIED_KEY_CONFIG.PRIVATE_KEY_MODE);
    logger.info('Encrypted private key saved', { keyType, filePath });
  }

  /**
   * Load and decrypt a private key from file
   * @param {string} keyName - Name of the key file (without extension)
   * @param {string} keyType - Expected key type
   * @returns {Promise<Uint8Array>} - Decrypted private key
   */
  async loadAndDecryptPrivateKey(keyName, keyType) {
    const safeName = this.sanitizeKeyName(keyName);
    const filePath = path.join(this.keyPairPath, `${safeName}-private.enc`);

    try {
      const fileData = await fs.readFile(filePath, 'utf8');
      if (fileData.length > 5 * 1024 * 1024) {
        throw new Error('Encrypted key file too large');
      }
      const encryptedData = JSON.parse(fileData);
      return await this.decryptPrivateKey(encryptedData, keyType);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new Error(`Encrypted key file not found: ${filePath}`);
      }
      throw error;
    }
  }

  /**
   * Check if an encrypted key file exists
   * @param {string} keyName - Name of the key file (without extension)
   * @returns {Promise<boolean>}
   */
  async hasEncryptedKey(keyName) {
    const safeName = this.sanitizeKeyName(keyName);
    const filePath = path.join(this.keyPairPath, `${safeName}-private.enc`);
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Delete an encrypted key file
   * @param {string} keyName - Name of the key file (without extension)
   * @returns {Promise<void>}
   */
  async deleteEncryptedKey(keyName) {
    const safeName = this.sanitizeKeyName(keyName);
    const filePath = path.join(this.keyPairPath, `${safeName}-private.enc`);
    try {
      await fs.unlink(filePath);
      logger.info('Encrypted key file deleted', { filePath });
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }

  /**
   * Constant-time comparison to prevent timing attacks
   */
  constantTimeCompare(a, b) {
    const aBuf = a ? Buffer.from(a) : Buffer.alloc(0);
    const bBuf = b ? Buffer.from(b) : Buffer.alloc(0);
    const maxLen = Math.max(aBuf.length, bBuf.length, 1);
    const pa = Buffer.alloc(maxLen);
    const pb = Buffer.alloc(maxLen);
    aBuf.copy(pa);
    bBuf.copy(pb);
    try { return crypto.timingSafeEqual(pa, pb) && aBuf.length === bBuf.length; } catch { return false; }
  }

  /**
   * Securely zero sensitive data
   * @param {Uint8Array} data - Data to zero
   */
  secureZero(data) {
    if (data && data.length > 0) {
      try { crypto.randomFillSync(data); } catch {}
      data.fill(0);
    }
  }

  /**
   * Get encryption metadata
   * @returns {Object} - Encryption configuration metadata
   */
  getMetadata() {
    return {
      version: UNIFIED_KEY_CONFIG.CURRENT_VERSION,
      algorithm: 'QuantumResistantAEAD',
      keyLength: UNIFIED_KEY_CONFIG.KEY_LENGTH,
      nonceLength: UNIFIED_KEY_CONFIG.QR_NONCE_LENGTH,
      tagLength: UNIFIED_KEY_CONFIG.TAG_LENGTH,
      argon2Params: {
        memory: UNIFIED_KEY_CONFIG.ARGON2_MEMORY,
        time: UNIFIED_KEY_CONFIG.ARGON2_TIME,
        parallelism: UNIFIED_KEY_CONFIG.ARGON2_PARALLELISM,
        version: UNIFIED_KEY_CONFIG.ARGON2_VERSION,
        algorithm: 'argon2id'
      },
      quantumResistant: true
    };
  }

  /**
   * Get the salt used for key derivation
   * @returns {Uint8Array} The salt (defensive copy)
   */
  getSalt() {
    if (!this.initialized) {
      throw new Error('UnifiedKeyEncryption not initialized');
    }
    return new Uint8Array(this.salt);
  }

  destroy() {
    try {
      if (this.masterKey) this.secureZero(this.masterKey);
    } catch {}
    try {
      if (this.salt) this.secureZero(this.salt);
    } catch {}
    try {
      for (const [, v] of this.domainKeys) {
        this.secureZero(v);
      }
      this.domainKeys.clear();
    } catch {}
    this.masterKey = null;
    this.salt = null;
    this.initialized = false;
  }

  // ===== helpers for v3 =====
  async createSecureDirectory(dirPath) {
    const resolved = path.resolve(dirPath);
    await fs.mkdir(resolved, { recursive: true, mode: 0o700 });
    try {
      const stats = await fs.stat(resolved);
      if ((stats.mode & 0o777) !== 0o700) {
        await fs.chmod(resolved, 0o700);
      }
    } catch {}
  }

  async getOrCreateSalt(providedSalt) {
    if (providedSalt) {
      const saltBuf = Buffer.isBuffer(providedSalt) || providedSalt instanceof Uint8Array ? Buffer.from(providedSalt) : Buffer.from(providedSalt, 'base64');
      if (saltBuf.length !== UNIFIED_KEY_CONFIG.SALT_LENGTH) {
        throw new Error('Provided salt must be 512 bits');
      }
      await this.atomicWrite(path.join(this.keyPairPath, '.unified-salt'), saltBuf, UNIFIED_KEY_CONFIG.CONFIG_MODE);
      return new Uint8Array(saltBuf);
    }

    const saltPath = path.join(this.keyPairPath, '.unified-salt');
    try {
      const existing = await fs.readFile(saltPath);
      if (existing.length !== UNIFIED_KEY_CONFIG.SALT_LENGTH) {
        throw new Error('Invalid existing salt length');
      }
      return new Uint8Array(existing);
    } catch (e) {
      if (e && e.code !== 'ENOENT') throw e;
      const newSalt = crypto.randomBytes(UNIFIED_KEY_CONFIG.SALT_LENGTH);
      await this.atomicWrite(saltPath, newSalt, UNIFIED_KEY_CONFIG.CONFIG_MODE);
      return new Uint8Array(newSalt);
    }
  }

  async initializeDomainKeys() {
    const domains = ['mldsa', 'mlkem', 'audit'];
    for (const d of domains) {
      const info = new TextEncoder().encode(`unified-key-encryption:${d}:v1`);
      const dk = shake256(Buffer.concat([
        Buffer.from(this.masterKey),
        Buffer.from(this.salt),
        info
      ]), { dkLen: 64 });
      this.domainKeys.set(d, dk);
    }
  }

  getDomainKey(domain) {
    const dk = this.domainKeys.get(domain);
    if (!dk) throw new Error(`Unknown domain key: ${domain}`);
    return dk;
  }

  createAAD(keyType, metadata) {
    const normalizedMetadata = metadata && typeof metadata === 'object' ? metadata : {};
    const aadData = {
      domain: 'unified-key-encryption',
      keyType,
      version: UNIFIED_KEY_CONFIG.CURRENT_VERSION,
      salt: Buffer.from(this.salt).toString('base64'),
      metadata: normalizedMetadata
    };
    return new TextEncoder().encode(stableStringify(aadData));
  }

  sanitizeKeyName(name) {
    const safe = String(name || '').trim();
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(safe)) {
      throw new Error('Invalid key name');
    }
    return safe;
  }

  async atomicWrite(filePath, data, mode) {
    const dir = path.dirname(filePath);
    await this.createSecureDirectory(dir);
    const tmp = `${filePath}.tmp.${crypto.randomBytes(8).toString('hex')}`;
    const release = await this.acquireWriteLock(filePath);
    try {
      const handle = await fs.open(tmp, 'w', mode);
      try {
        await handle.writeFile(data);
        try { await handle.sync(); } catch {}
      } finally {
        try { await handle.close(); } catch {}
      }
      await fs.rename(tmp, filePath);
      try {
        const dirHandle = await fs.open(dir, 'r');
        try { await dirHandle.sync(); } finally { try { await dirHandle.close(); } catch {} }
      } catch {}
    } finally {
      try {
        await fs.rm(tmp, { force: true });
      } catch (error) {
        logger.warn('Failed to clean up temporary file', { filePath: tmp, error: error?.message });
      }
      release();
    }
  }

  async acquireWriteLock(filePath) {
    const lockPath = `${filePath}.lock`;
    let locked = false;
    const waitInterval = 25;
    const maxAttempts = 200;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const fh = await fs.open(lockPath, 'wx');
        await fh.close();
        locked = true;
        break;
      } catch (error) {
        if (error.code !== 'EEXIST') {
          throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, waitInterval));
      }
    }
    if (!locked) {
      throw new Error(`Timed out acquiring write lock for ${filePath}`);
    }
    return async () => {
      try {
        await fs.unlink(lockPath);
      } catch (error) {
        if (error.code !== 'ENOENT') {
          logger.warn('Failed to release write lock', { filePath: lockPath, error: error?.message });
        }
      }
    };
  }

}

export { UnifiedKeyEncryption, UNIFIED_KEY_CONFIG };
