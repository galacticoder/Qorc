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
import { withRedisClient } from '../server/presence/presence.js';
import { logger as cryptoLogger } from '../server/crypto/crypto-logger.js';
import { CryptoUtils } from '../server/crypto/unified-crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ADMIN_KEYS_ENC_FILE = path.join(__dirname, '../server/config/.cluster-admin-keys.enc');

// Configuration constants
const ADMIN_CONFIG = {
  TOKEN_EXPIRATION: 3600000,          // 1 hour
  MAX_FAILED_ATTEMPTS: 5,             // 5 failed attempts
  LOCKOUT_DURATION: 900000,           // 15 minutes lockout
  NONCE_EXPIRATION: 86400000,         // 24 hours nonce cache
  TOKEN_VERSION: 3,
  ALGORITHM: 'ML-KEM-1024+X25519 | ML-DSA-87+Ed25519 | PostQuantumAEAD',
};

// Redis keys
const REDIS_KEYS = {
  ADMIN_TOKENS: 'cluster:admin:tokens:v3',
  ADMIN_NONCES: 'cluster:admin:nonces:v3',
  ADMIN_RATE_LIMIT: 'cluster:admin:ratelimit',
  ADMIN_FAILURES: 'cluster:admin:failures',
  ADMIN_AUDIT: 'cluster:admin:audit',
};

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

// Derive Key Encryption Key from username + password
async function deriveKEK(username, password, salt) {
  if (!username || username.length < 3) {
    throw new Error('Username must be at least 3 characters');
  }
  if (!password || password.length < 16) {
    throw new Error('Password must be at least 16 characters for admin access');
  }

  const { kek, salt: usedSalt } = await CryptoUtils.KDF.deriveUsernamePasswordKEK(
    username,
    password,
    { salt }
  );

  const usernameBytes = new TextEncoder().encode(String(username));
  const usernameHash = blake3(usernameBytes);
  return {
    kek: Buffer.from(kek),
    usernameHash: Buffer.from(usernameHash),
    salt: Buffer.from(usedSalt),
  };
}

// Generate hybrid admin keypair set (PQ + Classical)
function generateHybridKeypair() {
  // Post-quantum keys
  const kemKeypair = ml_kem1024.keygen();
  const mldsaSeed = crypto.randomBytes(32);
  const mldsaKeypair = ml_dsa87.keygen(mldsaSeed);

  // Classical keys
  const x25519Secret = crypto.randomBytes(32);
  const x25519Public = x25519.getPublicKey(x25519Secret);
  const ed25519Secret = ed25519.utils.randomPrivateKey();
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
  const { kek, usernameHash, salt } = await deriveKEK(username, password);

  // Serialize all keys
  const keysBlob = Buffer.from(JSON.stringify({
    kyberPublicKey: Buffer.from(keypair.kyber.publicKey).toString('base64'),
    kyberSecretKey: Buffer.from(keypair.kyber.secretKey).toString('base64'),
    dilithiumPublicKey: Buffer.from(keypair.dilithium.publicKey).toString('base64'),
    dilithiumSecretKey: Buffer.from(keypair.dilithium.secretKey).toString('base64'),
    x25519PublicKey: Buffer.from(keypair.x25519.publicKey).toString('base64'),
    x25519SecretKey: Buffer.from(keypair.x25519.secretKey).toString('base64'),
    ed25519PublicKey: Buffer.from(keypair.ed25519.publicKey).toString('base64'),
    ed25519SecretKey: Buffer.from(keypair.ed25519.secretKey).toString('base64'),
  }), 'utf8');

  const aead = new CryptoUtils.PostQuantumAEAD(kek);
  const nonce = CryptoUtils.Random.generateRandomBytes(36);
  const aad = new TextEncoder().encode('cluster-admin-keys-v3');
  const { ciphertext, tag } = aead.encrypt(keysBlob, nonce, aad);

  // Create encrypted package
  const encryptedPackage = {
    version: 3,
    algorithm: ADMIN_CONFIG.ALGORITHM,
    kdf: {
      algorithm: 'argon2id+quantumHKDF',
      salt: salt.toString('base64'),
    },
    usernameHash: usernameHash.toString('base64'),
    encryption: {
      algorithm: 'PostQuantumAEAD',
      nonce: Buffer.from(nonce).toString('base64'),
      tag: Buffer.from(tag).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
    },
    createdAt: Date.now(),
  };

  return encryptedPackage;
}

// Unlock admin keypair with username+password
async function unlockKeypair(username, password, encryptedPackage) {
  if (!encryptedPackage || encryptedPackage.version !== 3) {
    throw new Error('Invalid or incompatible encrypted key package - please re-run admin setup');
  }

  const salt = Buffer.from(encryptedPackage.kdf.salt, 'base64');
  const { kek, usernameHash } = await deriveKEK(username, password, salt);

  const storedHash = Buffer.from(encryptedPackage.usernameHash, 'base64');
  if (usernameHash.length !== storedHash.length || !crypto.timingSafeEqual(usernameHash, storedHash)) {
    throw new Error('SECURITY: Username does not match encrypted keyset');
  }

  const nonce = Buffer.from(encryptedPackage.encryption.nonce, 'base64');
  const tag = Buffer.from(encryptedPackage.encryption.tag, 'base64');
  const ciphertext = Buffer.from(encryptedPackage.encryption.ciphertext, 'base64');

  const aead = new CryptoUtils.PostQuantumAEAD(kek);
  const aad = new TextEncoder().encode('cluster-admin-keys-v3');
  let decrypted;
  try {
    decrypted = aead.decrypt(ciphertext, nonce, tag, aad);
  } catch (_error) {
    throw new Error('SECURITY: Failed to decrypt admin keys - invalid credentials or corrupted data');
  }

  const keys = parseJsonOrThrow(
    Buffer.from(decrypted).toString('utf8'),
    'SECURITY: Failed to parse decrypted admin keys'
  );

  return {
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

    try {
      if (fs.existsSync(ADMIN_KEYS_ENC_FILE)) {
        const encryptedPackage = parseJsonOrThrow(
          fs.readFileSync(ADMIN_KEYS_ENC_FILE, 'utf8'),
          'SECURITY: Corrupted admin key file'
        );
        this.keypair = await unlockKeypair(username, password, encryptedPackage);
        cryptoLogger.info('[ADMIN] Unlocked existing admin keypair');
      } else {
        this.keypair = generateHybridKeypair();
        const encryptedPackage = await protectKeypair(this.keypair, username, password);

        fs.writeFileSync(ADMIN_KEYS_ENC_FILE, JSON.stringify(encryptedPackage, null, 2), { mode: 0o600 });
        cryptoLogger.info('[ADMIN] Generated and protected new admin keypair');
      }

      this.adminUsername = username;
      this.initialized = true;

      cryptoLogger.info('[ADMIN] Hybrid admin auth initialized', {
        algorithm: ADMIN_CONFIG.ALGORITHM,
        username: username,
      });
    } catch (error) {
      cryptoLogger.error('[ADMIN] Failed to initialize', { error: error.message });
      throw error;
    }
  }

  // Generate admin token
  async generateAdminToken(adminId, metadata = {}) {
    if (!this.initialized) {
      throw new Error('Admin auth not initialized - must unlock keys first');
    }

    try {
      const payload = {
        version: ADMIN_CONFIG.TOKEN_VERSION,
        adminId,
        nonce: crypto.randomBytes(32).toString('base64'),
        issuedAt: Date.now(),
        expiresAt: Date.now() + ADMIN_CONFIG.TOKEN_EXPIRATION,
        metadata,
      };

      const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf8');

      const ephemeralX25519Secret = crypto.randomBytes(32);
      const ephemeralX25519Public = x25519.getPublicKey(ephemeralX25519Secret);

      const x25519SharedSecret = x25519.getSharedSecret(ephemeralX25519Secret, this.keypair.x25519.publicKey);

      const kemResult = ml_kem1024.encapsulate(this.keypair.kyber.publicKey);
      const kyberSharedSecret = kemResult.sharedSecret;
      const kyberCiphertext = kemResult.ciphertext || kemResult.cipherText;

      const rawSecret = Buffer.concat([
        Buffer.from(kyberSharedSecret),
        Buffer.from(x25519SharedSecret),
      ]);
      const info = new TextEncoder().encode('admin-token-encryption-v3');
      const aeadKey = await CryptoUtils.KDF.quantumHKDF(
        new Uint8Array(rawSecret),
        CryptoUtils.Hash.shake256(rawSecret, 64),
        info,
        32
      );

      const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
      const nonce = CryptoUtils.Random.generateRandomBytes(36);
      const aad = new TextEncoder().encode('admin-token-v3');
      const { ciphertext, tag } = aead.encrypt(payloadBytes, nonce, aad);

      // Prepare token structure
      const tokenStructure = {
        version: ADMIN_CONFIG.TOKEN_VERSION,
        kyberCiphertext: Buffer.from(kyberCiphertext).toString('base64'),
        x25519EphemeralPublic: Buffer.from(ephemeralX25519Public).toString('base64'),
        nonce: Buffer.from(nonce).toString('base64'),
        ciphertext: Buffer.from(ciphertext).toString('base64'),
        tag: Buffer.from(tag).toString('base64'),
      };

      const tokenBytes = Buffer.from(JSON.stringify(tokenStructure), 'utf8');
      const mldsaSignature = ml_dsa87.sign(tokenBytes, this.keypair.dilithium.secretKey);
      const ed25519Signature = ed25519.sign(tokenBytes, this.keypair.ed25519.secretKey);

      const token = {
        ...tokenStructure,
        signatures: {
          mldsa87: Buffer.from(mldsaSignature).toString('base64'),
          ed25519: Buffer.from(ed25519Signature).toString('base64'),
        },
      };

      const tokenString = Buffer.from(JSON.stringify(token)).toString('base64url');

      const tokenHash = blake3(tokenString);
      await withRedisClient(async (client) => {
        await client.hset(REDIS_KEYS.ADMIN_TOKENS, tokenHash.toString('hex'), JSON.stringify({
          adminId,
          issuedAt: payload.issuedAt,
          expiresAt: payload.expiresAt,
          metadata,
          algorithm: ADMIN_CONFIG.ALGORITHM,
        }));
        await client.pexpire(REDIS_KEYS.ADMIN_TOKENS, ADMIN_CONFIG.TOKEN_EXPIRATION);
      });

      cryptoLogger.info('[ADMIN] Generated admin token', {
        adminId,
        algorithm: ADMIN_CONFIG.ALGORITHM,
        expiresAt: new Date(payload.expiresAt).toISOString(),
      });

      return tokenString;
    } catch (error) {
      cryptoLogger.error('[ADMIN] Failed to generate token', { error: error.message });
      throw error;
    }
  }

  // Verify admin token
  async verifyAdminToken(tokenString) {
    if (!this.initialized) {
      throw new Error('Admin auth not initialized - must unlock keys first');
    }

    try {
      const tokenJson = Buffer.from(tokenString, 'base64url').toString('utf8');
      const token = parseJsonOrThrow(tokenJson, 'Invalid admin token');

      if (token.version !== ADMIN_CONFIG.TOKEN_VERSION) {
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

      const tokenBytes = Buffer.from(JSON.stringify(tokenStructure), 'utf8');
      const mldsaSignature = Buffer.from(token.signatures.mldsa87, 'base64');
      const mldsaValid = ml_dsa87.verify(mldsaSignature, tokenBytes, this.keypair.dilithium.publicKey);

      if (!mldsaValid) {
        throw new Error('SECURITY: ML-DSA-87 signature verification failed');
      }

      const ed25519Signature = Buffer.from(token.signatures.ed25519, 'base64');
      const ed25519Valid = ed25519.verify(ed25519Signature, tokenBytes, this.keypair.ed25519.publicKey);

      if (!ed25519Valid) {
        throw new Error('SECURITY: Ed25519 signature verification failed');
      }

      const kyberCiphertext = Buffer.from(token.kyberCiphertext, 'base64');
      const kyberSharedSecret = ml_kem1024.decapsulate(kyberCiphertext, this.keypair.kyber.secretKey);
      const x25519EphemeralPublic = Buffer.from(token.x25519EphemeralPublic, 'base64');
      const x25519SharedSecret = x25519.getSharedSecret(this.keypair.x25519.secretKey, x25519EphemeralPublic);

      const rawSecret = Buffer.concat([
        Buffer.from(kyberSharedSecret),
        Buffer.from(x25519SharedSecret),
      ]);

      const info = new TextEncoder().encode('admin-token-encryption-v3');
      const aeadKey = await CryptoUtils.KDF.quantumHKDF(
        new Uint8Array(rawSecret),
        CryptoUtils.Hash.shake256(rawSecret, 64),
        info,
        32
      );

      const nonce = Buffer.from(token.nonce, 'base64');
      const ciphertext = Buffer.from(token.ciphertext, 'base64');
      const tag = Buffer.from(token.tag, 'base64');
      const aead = new CryptoUtils.PostQuantumAEAD(aeadKey);
      const aad = new TextEncoder().encode('admin-token-v3');
      let payloadBytes;
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

      if (Date.now() > payload.expiresAt) {
        throw new Error('Token expired');
      }

      const tokenHash = blake3(tokenString).toString('hex');
      const tokenExists = await withRedisClient(async (client) => {
        return await client.hexists(REDIS_KEYS.ADMIN_TOKENS, tokenHash);
      });

      if (!tokenExists) {
        throw new Error('Token revoked or invalid');
      }

      const nonceUsed = await withRedisClient(async (client) => {
        const exists = await client.hexists(REDIS_KEYS.ADMIN_NONCES, payload.nonce);
        if (!exists) {
          await client.hset(REDIS_KEYS.ADMIN_NONCES, payload.nonce, Date.now());
          await client.pexpire(REDIS_KEYS.ADMIN_NONCES, ADMIN_CONFIG.NONCE_EXPIRATION);
        }
        return exists;
      });

      if (nonceUsed) {
        throw new Error('SECURITY: Replay attack detected - nonce already used');
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
      cryptoLogger.error('[ADMIN] Token verification failed', { error: error.message });
      throw error;
    }
  }

  // Revoke admin token
  async revokeToken(tokenString) {
    try {
      const tokenHash = blake3(tokenString).toString('hex');
      await withRedisClient(async (client) => {
        const removed = await client.hdel(REDIS_KEYS.ADMIN_TOKENS, tokenHash);
        if (removed > 0) {
          cryptoLogger.info('[ADMIN] Token revoked', {
            tokenHash: tokenHash.substring(0, 16) + '...',
          });
        }
      });
    } catch (error) {
      cryptoLogger.error('[ADMIN] Failed to revoke token', error);
      throw error;
    }
  }

  // Rate limiting
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

        cryptoLogger.error('[ADMIN] Account locked', {
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

    cryptoLogger.info('[ADMIN] Admin action', { adminId, action });
  }
}

const adminAuth = new AdminAuth();

// Express middleware for admin authentication
export async function requireAdmin(req, res, next) {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const identifier = `ip:${ip}`;

    const lockedOut = await adminAuth.isLockedOut(identifier);
    if (lockedOut) {
      return res.status(429).json({
        success: false,
        error: 'Account locked due to failed authentication attempts',
      });
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      await adminAuth.logFailedAttempt(identifier, 'Missing authorization header', ip);
      return res.status(401).json({
        success: false,
        error: 'Unauthorized - Bearer token required',
      });
    }

    const token = authHeader.substring(7);
    const result = await adminAuth.verifyAdminToken(token);
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
    const ip = req.ip || req.connection.remoteAddress;
    const identifier = `ip:${ip}`;

    try {
      await adminAuth.logFailedAttempt(identifier, error.message, ip);
    } catch (_logError) {
    }

    const status = error.message.includes('Rate limit') ? 429 :
      error.message.includes('expired') ? 403 :
        error.message.includes('revoked') ? 403 :
          error.message.includes('Replay') ? 403 :
            error.message.includes('signature') ? 403 :
              error.message.includes('Unauthorized') ? 401 : 403;

    res.status(status).json({
      success: false,
      error: error.message,
    });
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

export { adminAuth };

// CLI mode
if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2];

  (async () => {
    try {
      switch (command) {
        case 'setup': {
          if (process.argv.length < 5) {
            console.error('Usage: node admin-auth.js setup <username> <password>');
            console.error('');
            console.error('Password must be at least 16 characters for maximum security.');
            process.exit(1);
          }

          const username = process.argv[3];
          const password = process.argv[4];

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
          if (process.argv.length < 6) {
            console.error('Usage: node admin-auth.js generate <username> <password> <adminId> [metadata]');
            console.error('');
            console.error('Example:');
            console.error('  node admin-auth.js generate admin secretpass admin@company.com \'{"role":"superadmin"}\'');
            process.exit(1);
          }

          const username = process.argv[3];
          const password = process.argv[4];
          const adminId = process.argv[5];
          const metadata = (() => {
            if (!process.argv[6]) return {};
            try {
              const parsed = JSON.parse(process.argv[6]);
              return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
            } catch {
              return {};
            }
          })();

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
          console.log(`    curl -H "Authorization: Bearer ${token}" https://your-server/api/cluster/status`);
          console.log('  PowerShell (Windows):');
          console.log(`    Invoke-RestMethod -Uri https://your-server/api/cluster/status -Headers @{ Authorization = "Bearer ${token}" }`);
          console.log('');
          break;
        }

        default:
          console.log('Admin Authentication');
          console.log('');
          console.log('Commands:');
          console.log('  setup <username> <password>');
          console.log('    - Initialize admin auth with username+password protected keys');
          console.log('');
          console.log('  generate <username> <password> <adminId> [metadata]');
          console.log('    - Generate admin token (requires unlocking keys)');
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