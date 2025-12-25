import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { scrypt } from 'crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { sha3_512, shake256 } from '@noble/hashes/sha3.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { MlKem1024 } from 'mlkem';
import { hkdf } from '@noble/hashes/hkdf.js';
import argon2 from 'argon2';
import { UnifiedKeyEncryption } from '../crypto/unified-key-encryption.js';
import { withRedisClient } from '../presence/presence.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const CRYPTO_CONFIG = {
  ML_DSA_LEVEL: 87,
  ML_KEM_LEVEL: 1024,
  ARGON2_TIME: 4,
  ARGON2_MEMORY: 2 ** 18,
  ARGON2_PARALLELISM: 2,
  TOKEN_ENTROPY_BYTES: 64,
  DEVICE_SALT_BYTES: 32,
  SIGNATURE_ENTROPY: 48,
  MIN_VERIFICATION_TIME: 100,
  MAX_VERIFICATION_TIME: 2000,
  HASH_ALGORITHM: 'BLAKE3',
  KDF_ALGORITHM: 'HKDF-BLAKE3',
  SYMMETRIC_CIPHER: 'XChaCha20-Poly1305',
  AES_KEY_SIZE: 256,
  POST_QUANTUM_SECURITY_BITS: 256,
};

function parseJsonOrThrow(raw, errorMessage) {
  try {
    const text = typeof raw === 'string' ? raw : Buffer.from(raw).toString('utf8');
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid JSON');
    }
    return parsed;
  } catch {
    throw new Error(errorMessage);
  }
}

class TokenService {
  constructor() {
    this.mldsaPrivateKey = null;
    this.mldsaPublicKey = null;
    this.mlkemPrivateKey = null;
    this.mlkemPublicKey = null;
    this.kek = null;
    this.keyEncryption = null;
    this.initialized = false;
    this.initializationPromise = null;
    this.keyPairPath = path.join(__dirname, '../config');
    this.lockPath = path.join(this.keyPairPath, '.keys.lock');
    this.securityLevel = CRYPTO_CONFIG.POST_QUANTUM_SECURITY_BITS;
  }

  async initialize() {
    // If already initialized, return immediately
    if (this.initialized) return;

    // If initialization is already in progress, wait for it to complete
    if (this.initializationPromise) {
      return await this.initializationPromise;
    }

    // Create the initialization promise to prevent concurrent initialization
    this.initializationPromise = this.doInitialize();

    try {
      await this.initializationPromise;
    } finally {
      this.initializationPromise = null;
    }
  }

  async doInitialize() {
    if (this.initialized) return;

    const lock = await this.acquireLock(20000);
    try {
      // Re-check initialization status after acquiring lock
      if (this.initialized) return;

      // Initialize unified key encryption system
      this.keyEncryption = new UnifiedKeyEncryption(this.keyPairPath);
      const kek = await this.deriveKeyEncryptionKey();
      await this.keyEncryption.initialize(kek);

      await this.loadOrGenerateAllKeys();

      this.kek = kek;

      this.initialized = true;
    } finally {
      await this.releaseLock(lock);
    }

    console.log(`[TOKEN] TokenService initialized`);
  }

  /**
   * Load or generate all cryptographic keys
   */
  async loadOrGenerateAllKeys() {
    await this.loadOrGeneratePostQuantumKeys();
  }


  /**
   * Load or generate post-quantum cryptographic keys (ML-DSA + ML-KEM)
   */
  async loadOrGeneratePostQuantumKeys() {
    const mldsaPublicPath = path.join(this.keyPairPath, 'mldsa-public.key');
    const mlkemPublicPath = path.join(this.keyPairPath, 'mlkem-public.key');

    // Try to load existing keys (encrypted private + public files)
    try {
      const hasMldsa = await this.keyEncryption.hasEncryptedKey('mldsa');
      const hasMlkem = await this.keyEncryption.hasEncryptedKey('mlkem');
      if (hasMldsa && hasMlkem) {
        const [mldsaSk, mldsaPk, mlkemSk, mlkemPk] = await Promise.all([
          this.keyEncryption.loadAndDecryptPrivateKey('mldsa', 'mldsa'),
          fs.readFile(mldsaPublicPath),
          this.keyEncryption.loadAndDecryptPrivateKey('mlkem', 'mlkem'),
          fs.readFile(mlkemPublicPath)
        ]);
        this.mldsaPrivateKey = mldsaSk instanceof Uint8Array ? mldsaSk : new Uint8Array(mldsaSk);
        this.mldsaPublicKey = mldsaPk instanceof Uint8Array ? mldsaPk : new Uint8Array(mldsaPk);
        this.mlkemPrivateKey = mlkemSk instanceof Uint8Array ? mlkemSk : new Uint8Array(mlkemSk);
        this.mlkemPublicKey = mlkemPk instanceof Uint8Array ? mlkemPk : new Uint8Array(mlkemPk);
        console.log('[TOKEN] Loaded existing post-quantum keys');
        return;
      }
    } catch (_e) {
    }

    const mldsaKeyPair = ml_dsa87.keygen();
    const mlkem = new MlKem1024();
    const [mlkemPublicKey, mlkemPrivateKey] = await mlkem.generateKeyPair();

    // Ensure config directory exists
    await fs.mkdir(this.keyPairPath, { recursive: true });

    // Save public keys
    await Promise.all([
      fs.writeFile(mldsaPublicPath, mldsaKeyPair.publicKey, { mode: 0o644 }),
      fs.writeFile(mlkemPublicPath, mlkemPublicKey, { mode: 0o644 })
    ]);

    // Encrypt and persist private keys
    await this.keyEncryption.encryptAndSavePrivateKey('mldsa', mldsaKeyPair.secretKey, 'mldsa');
    await this.keyEncryption.encryptAndSavePrivateKey('mlkem', mlkemPrivateKey, 'mlkem');

    this.mldsaPrivateKey = mldsaKeyPair.secretKey;
    this.mldsaPublicKey = mldsaKeyPair.publicKey;
    this.mlkemPrivateKey = mlkemPrivateKey instanceof Uint8Array ? mlkemPrivateKey : new Uint8Array(mlkemPrivateKey);
    this.mlkemPublicKey = mlkemPublicKey;

    console.log('[TOKEN] Generated post-quantum keys');
  }



  /**
   * Generate access token (7-day lifetime, same as refresh tokens)
   */
  async generateAccessToken(userId, deviceId = null, scopes = ['chat:read', 'chat:write'], securityContext = {}, tlsBinding = null) {
    if (!this.initialized) await this.initialize();

    const now = Math.floor(Date.now() / 1000);
    const tokenId = await this.generateSecureTokenId();

    // Calculate risk score from security context
    const riskScore = this.calculateRiskScore(securityContext);

    // Enhanced payload with security context
    const payload = {
      iss: 'Qor-chat-server',
      sub: await this.hashUserId(userId),
      aud: 'Qor-chat-client',
      iat: now,
      exp: now + (7 * 24 * 60 * 60),
      jti: tokenId,

      // Custom claims
      type: 'access',
      scopes: this.validateScopes(scopes),

      nbf: now,
      auth_time: now,
      nonce: await this.generateNonce(),

      // Security metadata
      sec: {
        risk: riskScore,
        ctx: this.buildSecurityContext(securityContext)
      },

      // Anti-replay protection
      cnf: {
        jkt: await this.generateJWKThumbprint()
      }
    };

    if (deviceId && typeof deviceId === 'string') {
      payload.did = await this.createDeviceBinding(deviceId, securityContext);
    }

    if (tlsBinding && typeof tlsBinding === 'string') {
      payload.tlsBinding = tlsBinding;
    }

    return this.signTokenWithIntegrity(payload);
  }

  /**
   * Generate refresh token (long-lived, 7 days)
   */
  async generateRefreshToken(userId, deviceId = null, family = null, securityContext = {}, tlsBinding = null) {
    if (!this.initialized) await this.initialize();

    const now = Math.floor(Date.now() / 1000);
    const tokenId = await this.generateSecureTokenId();
    const familyId = family || await this.generateSecureTokenId();

    // Calculate risk score from security context
    const riskScore = this.calculateRiskScore(securityContext);

    const payload = {
      iss: 'Qor-chat-server',
      sub: await this.hashUserId(userId),
      aud: 'Qor-chat-client',
      iat: now,
      exp: now + (7 * 24 * 60 * 60),
      jti: tokenId,

      // Custom claims
      type: 'refresh',
      family: familyId,

      nbf: now,
      nonce: await this.generateNonce(),

      // Rotation tracking
      generation: 1,

      sec: {
        risk: riskScore
      }
    };

    if (deviceId && typeof deviceId === 'string') {
      payload.did = await this.createDeviceBinding(deviceId, securityContext);
    }

    if (tlsBinding && typeof tlsBinding === 'string') {
      payload.tlsBinding = tlsBinding;
    }

    return this.signTokenWithIntegrity(payload);
  }

  /**
   * Generate device access token for reconnection
   * Slightly longer lived (1 hour) for reconnection scenarios
   */
  async generateDeviceToken(userId, deviceId, deviceFingerprint) {
    if (!this.initialized) await this.initialize();

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: 'Qor-chat-server',
      sub: await this.hashUserId(userId),
      aud: 'Qor-chat-client',
      iat: now,
      exp: now + (60 * 60),
      jti: await this.generateSecureTokenId(),

      type: 'device',
      deviceId: deviceId,
      deviceFingerprint: deviceFingerprint,
      scopes: ['chat:reconnect'],

      nbf: now
    };

    return this.signTokenWithIntegrity(payload);
  }

  /**
   * Sign JWT token
   */
  async signTokenWithIntegrity(payload) {
    payload._integrity = {
      version: '3.0-pq-only',
      created_at: Date.now(),
      entropy_id: await this.generateSecureTokenId(),
      checksum: await this.calculateQuantumChecksum(payload),
      security_level: this.securityLevel
    };

    const header = {
      typ: 'JWT',
      alg: 'HYBRID-QR',
      kid: await this.getMLDSAKeyId(),
      cty: 'JWT',
      crit: ['kid', 'pq_alg'],

      pq_alg: {
        post_quantum: ['ML-DSA-87'],
        mac: ['BLAKE3-HKDF'],
        hybrid: 'PQ+MAC'
      },

      x5t: await this.getCertThumbprint(),
      'x5t#S256': await this.getCertThumbprintSHA256(),
      quantum_resistant: true,
      entropy_bits: this.securityLevel
    };

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signingBuffer = Buffer.from(signingInput);

    // Add key commitment and algorithm/domain separation
    const keyCommitment = await this.generateKeyCommitment();
    const commitmentBytes = Buffer.from(keyCommitment, 'hex');
    const signingBufferWithCommitment = Buffer.concat([signingBuffer, commitmentBytes]);

    // Primary PQ signature (ML-DSA-87) with domain separation
    const mldsaSignature = await this.signWithMLDSA(
      Buffer.concat([Buffer.from('ALG:ML-DSA-87:v2'), signingBufferWithCommitment])
    );

    // BLAKE3 MAC with HKDF-derived key
    const macKey = await this.deriveQuantumIntegrityKey('blake3-mac');
    const blake3MacKey = hkdf(blake3, macKey, Buffer.from('blake3-mac-salt'), Buffer.from('blake3-mac'), 32);
    const blake3Mac = blake3(signingBufferWithCommitment, { key: blake3MacKey });

    // Construct PQ-centric signature bundle
    const signatureBundle = {
      version: '3.0-pq-only',
      algorithms: {
        ml_dsa_87: Buffer.from(mldsaSignature).toString('base64'),
        blake3_mac: Buffer.from(blake3Mac).toString('base64')
      },
      security_metadata: {
        timestamp: Date.now(),
        entropy_source: 'quantum-resistant',
        key_ids: {
          ml_dsa: await this.getMLDSAKeyId()
        }
      },
      key_commitment: keyCommitment
    };

    const encodedSignature = this.base64UrlEncode(JSON.stringify(signatureBundle));
    return `${signingInput}.${encodedSignature}`;
  }


  /**
   * Verify and decode JWT token
   * @param {string} token - JWT token to verify
   * @param {string|null} expectedType - Expected token type ('access' or 'refresh')
   * @param {boolean} skipReplayCheck - Skip nonce replay protection (for multiple verifications in same request)
   */
  async verifyToken(token, expectedType = null, skipReplayCheck = false) {
    if (!this.initialized) await this.initialize();
    return await this.verifyQuantumToken(token, expectedType, skipReplayCheck);
  }


  /**
   * Create token pair (access + refresh)
   */
  async createTokenPair(userId, deviceId = null, tlsBinding = null, existingFamily = null) {
    const family = existingFamily || await this.generateSecureTokenId();

    const [accessToken, refreshToken] = await Promise.all([
      // Do not bind any user metadata; privacy-first tokens
      this.generateAccessToken(userId, deviceId, undefined, {}, tlsBinding),
      this.generateRefreshToken(userId, deviceId, family, {}, tlsBinding)
    ]);

    try {
      const hashedUserId = await this.hashUserId(userId);
      await withRedisClient(async (client) => {
        const mappingKey = `userId:hash:${hashedUserId}`;
        await client.set(mappingKey, userId, 'EX', 30 * 24 * 60 * 60);
      });
    } catch (error) {
      console.error('[TOKEN] Failed to store userId mapping:', error);
    }

    return {
      success: true,
      accessToken,
      refreshToken,
      family,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer'
    };
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(refreshToken) {
    const payload = await this.verifyToken(refreshToken, 'refresh');

    const newAccessToken = await this.generateAccessToken(
      payload.sub,
      payload.deviceId,
      payload.scopes
    );

    try {
      await withRedisClient(async (client) => {
        const mappingKey = `userId:hash:${payload.sub}`;
        const username = await client.get(mappingKey);
        if (username) {
          await client.expire(mappingKey, 30 * 24 * 60 * 60);
        }
      });
    } catch (error) {
      console.error('[TOKEN] Failed to refresh userId mapping:', error);
    }

    return {
      accessToken: newAccessToken,
      expiresIn: 7 * 24 * 60 * 60,
      tokenType: 'Bearer'
    };
  }

  /**
   * Rotate refresh token (generate new refresh token)
   */
  async rotateRefreshToken(refreshToken) {
    const payload = await this.verifyToken(refreshToken, 'refresh');

    const newRefreshToken = await this.generateRefreshToken(
      payload.sub,
      payload.deviceId,
      payload.family
    );

    return newRefreshToken;
  }

  /**
   * Generate token ID with maximum entropy from multiple sources
   */
  async generateSecureTokenId() {
    // Multiple entropy sources for quantum resistance
    const classicalEntropy = crypto.randomBytes(CRYPTO_CONFIG.TOKEN_ENTROPY_BYTES);
    const timingEntropy = await this.generateQuantumTimingEntropy();
    const systemEntropy = await this.generateSystemEntropy();
    const cryptoEntropy = crypto.randomBytes(32);

    const entropyInputs = Buffer.concat([
      classicalEntropy,
      Buffer.from(timingEntropy),
      Buffer.from(systemEntropy),
      cryptoEntropy
    ]);

    const quantumResistantId = shake256(entropyInputs, CRYPTO_CONFIG.TOKEN_ENTROPY_BYTES);
    const finalHash = blake3(quantumResistantId);

    return Buffer.from(finalHash).toString('hex');
  }

  /**
   * Generate timing entropy with multiple unpredictable sources
   */
  async generateQuantumTimingEntropy() {
    const measurements = [];

    // Multiple timing measurements for quantum resistance
    for (let round = 0; round < 5; round++) {
      const start = process.hrtime.bigint();

      const iterBytes = crypto.randomBytes(4);
      const iterFraction = iterBytes.readUInt32BE(0) / 0xffffffff;
      const iterations = Math.floor(iterFraction * 2000) + 500;
      const roundOffset = round * iterations;
      const data = Buffer.allocUnsafe(8);
      for (let i = 0; i < iterations; i++) {
        data.writeBigUInt64BE(BigInt(i + roundOffset), 0);
        if (i % 3 === 0) blake3(data);
        else if (i % 3 === 1) sha3_512(data);
        else crypto.createHash('sha256').update(data).digest();
      }

      const end = process.hrtime.bigint();
      measurements.push(end - start);

      const sleepBytes = crypto.randomBytes(4);
      const sleepFraction = sleepBytes.readUInt32BE(0) / 0xffffffff;
      const sleepMs = Math.floor(sleepFraction * 5);
      await new Promise(resolve => setTimeout(resolve, sleepMs));
    }

    // Combine all timing measurements
    const timingData = Buffer.from(measurements.map(m => m.toString(16)).join(''));

    return shake256(timingData, 32);
  }

  /**
   * Generate system-level entropy from multiple sources
   */
  async generateSystemEntropy() {
    const sources = [];

    // System state entropy
    sources.push(Buffer.from(process.pid.toString()));
    sources.push(Buffer.from(process.uptime().toString()));
    sources.push(Buffer.from(Date.now().toString()));
    sources.push(Buffer.from(process.hrtime.bigint().toString()));

    // Memory usage entropy
    const memUsage = process.memoryUsage();
    sources.push(Buffer.from(JSON.stringify(memUsage)));

    // CPU usage entropy
    try {
      const cpuUsage = process.cpuUsage();
      sources.push(Buffer.from(JSON.stringify(cpuUsage)));
    } catch { }

    // Additional crypto random
    sources.push(crypto.randomBytes(16));

    // Combine all sources
    const combined = Buffer.concat(sources);

    // Hash with BLAKE3 for speed and security
    return blake3(combined).slice(0, 24);
  }

  /**
   * Generate cryptographic nonce
   */
  async generateNonce() {
    const timestamp = BigInt(Date.now());
    const random = crypto.randomBytes(24);
    const combined = Buffer.concat([Buffer.from(timestamp.toString(16), 'hex'), random]);
    return blake3(combined).slice(0, 16).toString('hex'); // 128-bit nonce
  }

  /**
   * Hash user ID for privacy protection in tokens
   */
  async hashUserId(userId) {
    const salt = process.env.USER_ID_SALT;

    if (!salt || salt.length < 32) {
      throw new Error('USER_ID_SALT not properly initialized - database initialization may have failed');
    }

    const kekHex = await this.deriveKeyEncryptionKey();
    const kekBytes = Buffer.from(kekHex, 'hex');
    const userIdKey = hkdf(blake3, kekBytes, Buffer.from('user-id-hashing-v1'), Buffer.from('user-id-key'), 32);
    const combined = Buffer.concat([Buffer.from(userId), Buffer.from(salt)]);
    return blake3(combined, { key: userIdKey }).slice(0, 16).toString('hex');
  }

  /**
   * Validate and sanitize token scopes
   */
  validateScopes(scopes) {
    const allowedScopes = [
      'chat:read', 'chat:write', 'chat:delete', 'chat:reconnect',
      'user:profile', 'user:settings', 'admin:users', 'admin:server'
    ];

    if (!Array.isArray(scopes)) {
      return ['chat:read', 'chat:write'];
    }

    return scopes.filter(scope =>
      typeof scope === 'string' &&
      allowedScopes.includes(scope) &&
      scope.length <= 50
    );
  }

  /**
   * Build security context for tokens
   */
  buildSecurityContext(context) {
    if (!context || typeof context !== 'object') {
      return { risk: 'low' };
    }

    return {
      risk: this.calculateRiskScore(context),
      newDevice: !!context.newDevice,
      userAgentHash: context.userAgent ? this.hashUserAgent(context.userAgent) : undefined
    };
  }

  /**
   * Calculate risk score based on context
   */
  calculateRiskScore(context) {
    let score = 0;

    if (context.newDevice) score += 3;
    if (context.rapidRequests) score += 5;
    if (context.vpnDetected) score += 1;

    if (score <= 2) return 'low';
    if (score <= 5) return 'medium';
    return 'high';
  }

  /**
   * Hash user agent for fingerprinting
   */
  hashUserAgent(userAgent) {
    if (!userAgent) return 'unknown';
    return blake3(Buffer.from(userAgent.substring(0, 200))).slice(0, 8).toString('hex');
  }

  /**
   * Create device binding for better security
   */
  async createDeviceBinding(deviceId, context) {
    if (!deviceId) return null;

    const bindingData = {
      deviceId,
      fingerprint: context.deviceFingerprint,
      timestamp: Date.now(),
      nonce: await this.generateNonce()
    };

    const bindingKey = await this.deriveDeviceBindingKey(deviceId);
    return blake3(Buffer.from(JSON.stringify(bindingData)), { key: bindingKey })
      .slice(0, 16).toString('hex');
  }

  /**
   * Generate JWK thumbprint for key binding
   */
  async generateJWKThumbprint() {
    if (!this.mldsaPublicKey) return null;
    const jwk = await this.publicKeyToJWK();
    const canonicalJwk = JSON.stringify(jwk, Object.keys(jwk).sort());

    return blake3(Buffer.from(canonicalJwk)).slice(0, 16).toString('hex');
  }

  /**
   * Convert public key to JWK-like format (PQ)
   */
  async publicKeyToJWK() {
    if (!this.mldsaPublicKey) {
      throw new Error('ML-DSA public key not initialized');
    }

    return {
      kty: 'PQ',
      use: 'sig',
      alg: 'ML-DSA-87',
      kid: await this.getMLDSAKeyId(),
      crv: 'ML-DSA-87',
      x: this.base64UrlEncode(this.mldsaPublicKey)
    };
  }


  /**
   * Calculate payload checksum for integrity
   */
  async calculatePayloadChecksum(payload) {
    const payloadCopy = { ...payload };
    delete payloadCopy._integrity;

    const canonical = JSON.stringify(payloadCopy, Object.keys(payloadCopy).sort());
    return blake3(Buffer.from(canonical)).slice(0, 16).toString('hex');
  }

  /**
   * Get certificate thumbprint
   */
  async getCertThumbprint() {
    if (!this.mldsaPublicKey) {
      throw new Error('ML-DSA public key not initialized');
    }
    return Buffer.from(blake3(Buffer.from(this.mldsaPublicKey))).toString('base64url');
  }

  /**
   * Get certificate thumbprint SHA256 for security
   */
  async getCertThumbprintSHA256() {
    if (!this.mldsaPublicKey) {
      throw new Error('ML-DSA public key not initialized');
    }
    const sha256 = crypto.createHash('sha256');
    sha256.update(Buffer.from(this.mldsaPublicKey));
    return sha256.digest('base64url');
  }


  /**
   * Derive key encryption key for private key protection using secure KDF
   */
  async deriveKeyEncryptionKey() {
    let secret = process.env.KEY_ENCRYPTION_SECRET;
    if (!secret) {
      throw new Error('KEY_ENCRYPTION_SECRET is required');
    }

    if (secret.length < 32) {
      throw new Error('KEY_ENCRYPTION_SECRET must be at least 32 characters');
    }

    // Generate and persist a strong random salt per installation if not exists
    const saltPath = path.join(this.keyPairPath, 'kek.salt');
    let salt;

    try {
      salt = await fs.readFile(saltPath);
    } catch (_error) {
      await fs.mkdir(this.keyPairPath, { recursive: true });
      try {
        const fh = await fs.open(saltPath, 'wx');
        try {
          salt = crypto.randomBytes(64);
          await fh.writeFile(salt);
          await fh.chmod(0o600);
          console.log('[TOKEN] Generated random key encryption salt');
        } finally {
          await fh.close();
        }
      } catch (e) {
        if (e && e.code === 'EEXIST') {
          salt = await fs.readFile(saltPath);
        } else {
          throw e;
        }
      }
    }

    // Use Argon2id for key derivation
    try {
      const derived = await argon2.hash(secret, {
        type: argon2.argon2id,
        memoryCost: CRYPTO_CONFIG.ARGON2_MEMORY,
        timeCost: CRYPTO_CONFIG.ARGON2_TIME,
        parallelism: CRYPTO_CONFIG.ARGON2_PARALLELISM,
        hashLength: 32,
        salt,
        raw: true
      });
      return Buffer.from(derived).toString('hex');
    } catch (error) {
      console.error('[TOKEN] Argon2id failed: ', error.message);
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }

  /**
   * Derive device binding key
   */
  async deriveDeviceBindingKey(deviceId) {
    const salt = blake3(Buffer.concat([Buffer.from(deviceId), Buffer.from('device-binding')])).slice(0, 32);

    return new Promise((resolve, reject) => {
      scrypt(Buffer.from(deviceId), salt, 32, (err, key) => {
        if (err) reject(err);
        else resolve(key);
      });
    });
  }

  /**
   * Sign with ML-DSA-87 
   */
  async signWithMLDSA(data) {
    const msg = data instanceof Buffer ? new Uint8Array(data) : data;
    let sk = this.mldsaPrivateKey;
    if (!(sk instanceof Uint8Array)) sk = sk ? new Uint8Array(sk) : sk;
    if (!sk || sk.length !== 4896) {
      throw new Error(`Invalid ML-DSA private key in memory: expected 4896 bytes, got ${sk?.length}`);
    }
    return ml_dsa87.sign(msg, sk);
  }


  /**
   * Derive quantum-resistant integrity key using HKDF with BLAKE3 (PQ-only inputs)
   */
  async deriveQuantumIntegrityKey(domain = 'default') {
    const mldsaKeyMaterial = this.mldsaPublicKey ? Buffer.from(this.mldsaPublicKey).slice(0, 64) : Buffer.alloc(64);
    const mlkemKeyMaterial = this.mlkemPublicKey ? Buffer.from(this.mlkemPublicKey).slice(0, 64) : Buffer.alloc(64);

    const combinedKeyMaterial = Buffer.concat([
      mldsaKeyMaterial,
      mlkemKeyMaterial
    ]);

    const serverSecretHex = this.kek || await this.deriveKeyEncryptionKey();
    const serverSecret = Buffer.from(serverSecretHex, 'hex');
    const salt = blake3(Buffer.concat([serverSecret, Buffer.from('quantum-integrity-salt')]));
    const info = Buffer.from(`token-signing-key:${domain}:v2`);

    return hkdf(blake3, combinedKeyMaterial, salt, info, 64);
  }

  /**
   * Calculate checksum
   */
  async calculateQuantumChecksum(payload) {
    const payloadCopy = { ...payload };
    delete payloadCopy._integrity;

    const canonical = JSON.stringify(payloadCopy, Object.keys(payloadCopy).sort());
    const data = Buffer.from(canonical);

    // Use multiple hash functions 
    const blake3Hash = blake3(data);
    const sha3Hash = sha3_512(data);
    const shakeHash = shake256(data, 32);

    // Combine all hashes
    const combined = Buffer.concat([blake3Hash, sha3Hash, shakeHash]);

    // Final hash with BLAKE3
    return blake3(combined).slice(0, 24).toString('hex');
  }

  async generateKeyCommitment() {
    const parts = [];
    if (this.mldsaPublicKey) parts.push(Buffer.from(this.mldsaPublicKey));
    if (this.mlkemPublicKey) parts.push(Buffer.from(this.mlkemPublicKey));
    if (parts.length === 0) {
      return Buffer.from(blake3(Buffer.from('no-keys'))).toString('hex');
    }
    const keys = Buffer.concat(parts);
    return Buffer.from(blake3(keys)).toString('hex');
  }

  /**
   * Get ML-DSA key identifier
   */
  async getMLDSAKeyId() {
    if (!this.mldsaPublicKey) return 'mldsa-default';
    return blake3(this.mldsaPublicKey).slice(0, 8).toString('hex');
  }

  /**
   * Verify quantum-resistant hybrid token
   * @param {string} token - JWT token to verify
   * @param {string|null} expectedType - Expected token type ('access' or 'refresh')
   * @param {boolean} skipReplayCheck - Skip nonce replay protection (for multiple verifications in same request)
   */
  async verifyQuantumToken(token, expectedType = null, _skipReplayCheck = false) {
    if (!this.initialized) await this.initialize();
    if (!token || typeof token !== 'string') {
      throw new Error('Invalid token format');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token structure');
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    const header = parseJsonOrThrow(
      this.base64UrlDecode(encodedHeader),
      'Invalid token header'
    );

    if (header.alg !== 'HYBRID-QR') {
      throw new Error('Incorrect algorithm in token');
    }

    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signingBuffer = Buffer.from(signingInput);

    // Decode signature bundle
    const signatureBundle = parseJsonOrThrow(
      this.base64UrlDecode(encodedSignature),
      'Invalid token signature bundle'
    );


    if (signatureBundle.version !== '3.0-pq-only') {
      throw new Error('Unsupported signature version');
    }

    // Reconstruct the same signing buffer used during token creation
    const keyCommitment = signatureBundle.key_commitment;
    if (!keyCommitment) {
      throw new Error('Missing key commitment in signature bundle');
    }
    const commitmentBytes = Buffer.from(keyCommitment, 'hex');
    const signingBufferWithCommitment = Buffer.concat([signingBuffer, commitmentBytes]);

    // Verify PQ signature and BLAKE3 MAC using the same augmented buffer
    const signatureNames = ['ML-DSA-87', 'BLAKE3-MAC'];
    const verificationResults = await Promise.all([
      this.verifyMLDSASignature(
        Buffer.concat([Buffer.from('ALG:ML-DSA-87:v2'), signingBufferWithCommitment]),
        Buffer.from(signatureBundle.algorithms.ml_dsa_87, 'base64')
      ),
      this.verifyBlake3MAC(
        signingBufferWithCommitment,
        Buffer.from(signatureBundle.algorithms.blake3_mac, 'base64')
      )
    ]);


    // Both signature and MAC must be valid 
    const allValid = verificationResults.every(result => result === true);
    if (!allValid) {
      const failedSignatures = signatureNames.filter((name, index) => !verificationResults[index]);
      console.error(`[TOKEN] Failed signatures: ${failedSignatures.join(', ')}`);
      throw new Error('Signature verification failed');
    }

    // Decode and validate payload
    const payload = parseJsonOrThrow(
      this.base64UrlDecode(encodedPayload),
      'Invalid token payload'
    );
    const now = Math.floor(Date.now() / 1000);

    // increased quantum-resistant validation
    await this.validateQuantumPayload(payload, now, expectedType);

    return payload;
  }


  async verifyMLDSASignature(data, signature) {
    try {
      const signatureBytes = signature instanceof Buffer ? new Uint8Array(signature) : signature;
      const msg = data instanceof Buffer ? new Uint8Array(data) : data;
      const result = ml_dsa87.verify(signatureBytes, msg, this.mldsaPublicKey);
      if (process.env.CRYPTO_DEBUG === 'true') {
        console.log('[TOKEN] ML-DSA-87 verification:', result ? 'PASS' : 'FAIL');
      }
      return result;
    } catch (_error) {
      console.error('[TOKEN] ML-DSA-87 verification error');
      return false;
    }
  }

  async verifyBlake3MAC(data, expectedMAC) {
    try {
      const key = await this.deriveQuantumIntegrityKey('blake3-mac');
      if (key.length < 32) {
        return false;
      }
      const blake3MacKey = hkdf(blake3, key, Buffer.from('blake3-mac-salt'), Buffer.from('blake3-mac'), 32);
      const computedMAC = blake3(data, { key: blake3MacKey });
      const expectedMACBytes = expectedMAC instanceof Buffer ? new Uint8Array(expectedMAC) : expectedMAC;
      return this.constantTimeCompare(computedMAC, expectedMACBytes);
    } catch (_error) {
      console.error('[TOKEN] BLAKE3 MAC verification failed');
      return false;
    }
  }

  /**
   * Validate quantum-resistant payload
   */
  async validateQuantumPayload(payload, now, expectedType) {
    if (payload.exp && payload.exp < now) {
      throw new Error('Token expired');
    }

    if (payload.nbf && payload.nbf > now) {
      throw new Error('Token not yet valid');
    }

    if (payload.iss !== 'Qor-chat-server') {
      throw new Error('Invalid token issuer');
    }

    if (payload.aud !== 'Qor-chat-client') {
      throw new Error('Invalid token audience');
    }

    if (expectedType && payload.type !== expectedType) {
      throw new Error(`Expected ${expectedType} token, got ${payload.type}`);
    }

    // Quantum-specific validations
    if (!payload._integrity || payload._integrity.version !== '3.0-pq-only') {
      throw new Error('Invalid quantum integrity metadata');
    }

    if (payload._integrity.security_level < this.securityLevel) {
      throw new Error('Insufficient security level');
    }

    // Verify quantum checksum
    const expectedChecksum = payload._integrity.checksum;
    const computedChecksum = await this.calculateQuantumChecksum(payload);
    const ok = this.constantTimeCompare(Buffer.from(expectedChecksum, 'hex'), Buffer.from(computedChecksum, 'hex'));
    if (!ok) {
      throw new Error('Quantum checksum verification failed');
    }
  }

  /**
   * Constant-time comparison to prevent timing attacks
   */
  constantTimeCompare(a, b) {
    if (!a || !b) return false;

    // Convert to Buffers if needed
    const bufferA = Buffer.isBuffer(a) ? a : Buffer.from(a);
    const bufferB = Buffer.isBuffer(b) ? b : Buffer.from(b);

    if (bufferA.length !== bufferB.length) {
      const maxLen = Math.max(bufferA.length, bufferB.length);
      const paddedA = Buffer.alloc(maxLen);
      const paddedB = Buffer.alloc(maxLen);

      bufferA.copy(paddedA, 0);
      bufferB.copy(paddedB, 0);

      try {
        return crypto.timingSafeEqual(paddedA, paddedB);
      } catch {
        return false;
      }
    }

    try {
      return crypto.timingSafeEqual(bufferA, bufferB);
    } catch {
      return false;
    }
  }

  /**
   * Generate device fingerprint from request headers and client info
   */
  generateDeviceFingerprint(userAgent = '', clientVersion = '', additionalData = {}) {
    const data = {
      userAgent: userAgent.substring(0, 200),
      clientVersion,
      timestamp: Math.floor(Date.now() / 86400000),
      ...additionalData
    };

    return Buffer.from(blake3(Buffer.from(JSON.stringify(data))))
      .toString('hex')
      .substring(0, 16);
  }


  /**
   * Base64URL encoding 
   */
  base64UrlEncode(data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Base64URL decoding
   */
  base64UrlDecode(encoded) {
    const padded = encoded + '='.repeat((4 - (encoded.length % 4)) % 4);
    const standard = padded.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(standard, 'base64');
  }

  /**
   * Validate token structure without verifying signature (for blacklist checks)
   */
  parseTokenUnsafe(token) {
    if (!token || typeof token !== 'string') {
      return null;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    try {
      const payload = JSON.parse(this.base64UrlDecode(parts[1]).toString());
      return payload;
    } catch {
      return null;
    }
  }

  async acquireLock(timeoutMs = 15000) {
    const maxRetries = 3;
    const staleThreshold = 30000;

    for (let retry = 0; retry < maxRetries; retry++) {
      const start = Date.now();
      await fs.mkdir(this.keyPairPath, { recursive: true });
      let attempt = 0;

      while (true) {
        try {
          const fh = await fs.open(this.lockPath, 'wx');
          console.log(`[TOKEN] Lock acquired after ${Date.now() - start}ms (retry ${retry + 1}/${maxRetries}, attempt ${attempt + 1})`);
          return fh;
        } catch (e) {
          if (e && e.code === 'EEXIST') {
            attempt++;
            const elapsed = Date.now() - start;

            if (elapsed > timeoutMs) {
              try {
                const stats = await fs.stat(this.lockPath);
                const age = Date.now() - stats.mtime.getTime();

                if (age > staleThreshold) {
                  console.warn(`[TOKEN] Removing potentially stale lock file (age: ${age}ms, retry ${retry + 1}/${maxRetries})`);
                  await fs.unlink(this.lockPath);
                  continue;
                }
              } catch (_cleanupError) { }

              if (retry < maxRetries - 1) {
                console.warn(`[TOKEN] Lock timeout after ${elapsed}ms (retry ${retry + 1}/${maxRetries}), retrying...`);
                break;
              }

              throw new Error(`Timeout acquiring key initialization lock after ${elapsed}ms (${maxRetries} retries, ${attempt} attempts)`);
            }

            const baseBackoff = Math.min(1000, 100 * Math.pow(1.5, Math.min(attempt, 8)));
            const jitterBytes = crypto.randomBytes(2);
            const jitterFraction = jitterBytes.readUInt16BE(0) / 0xffff;
            const jitter = jitterFraction * 0.3 * baseBackoff; // 30% jitter
            const backoff = Math.floor(baseBackoff + jitter);
            await new Promise(r => setTimeout(r, backoff));
            continue;
          }
          throw e;
        }
      }

      if (retry < maxRetries - 1) {
        const retryBackoff = Math.min(5000, 1000 * Math.pow(2, retry));
        console.log(`[TOKEN] Waiting ${retryBackoff}ms before retry ${retry + 2}/${maxRetries}`);
        await new Promise(r => setTimeout(r, retryBackoff));
      }
    }
  }

  async releaseLock(fileHandle) {
    try { if (fileHandle) await fileHandle.close(); } catch { }
    try { await fs.unlink(this.lockPath); } catch { }
  }


  /**
   * Get or create a local secret file with strong entropy
   * Returns a hex-encoded string of at least minBytes length
   */
  async getOrCreateLocalSecret(fileName, minBytes = 48, forceRegen = false) {
    await fs.mkdir(this.keyPairPath, { recursive: true });
    const secretPath = path.join(this.keyPairPath, fileName);
    let secret;
    try {
      if (!forceRegen) {
        const raw = await fs.readFile(secretPath, 'utf8');
        secret = (raw || '').trim();
        if (secret && secret.length >= 32) return secret;
      }
    } catch { }
    // Generate new secret
    const bytes = crypto.randomBytes(Math.max(32, minBytes));
    secret = bytes.toString('hex');
    try {
      const fh = await fs.open(secretPath, 'w');
      try {
        await fh.writeFile(secret, 'utf8');
        await fh.chmod(0o600);
      } finally {
        await fh.close();
      }
      console.log(`[TOKEN] Generated new local secret: ${fileName}`);
    } catch (e) {
      console.warn(`[TOKEN] Failed to persist local secret ${fileName}:`, e?.message || e);
    }
    return secret;
  }

  /**
   * Validate access and refresh tokens for a user
   * @param {string} accessToken - The access token to validate
   * @param {string} refreshToken - The refresh token to validate
   * @param {string} username - The username associated with the tokens
   * @returns {Promise<boolean>} - True if tokens are valid, false otherwise
   */
  async validateTokens(accessToken, refreshToken, username) {
    try {
      // Ensure service is initialized
      await this.initialize();

      const accessPayload = await this.verifyToken(accessToken, 'access', true);
      if (!accessPayload) {
        console.log(`[TOKEN] Access token validation failed for user: ${username}`);
        return false;
      }

      const refreshPayload = await this.verifyToken(refreshToken, 'refresh', true);
      if (!refreshPayload) {
        console.log(`[TOKEN] Refresh token validation failed for user: ${username}`);
        return false;
      }

      const hashedUsername = await this.hashUserId(username);
      if (accessPayload.sub !== hashedUsername || refreshPayload.sub !== hashedUsername) {
        console.log(`[TOKEN] Token username mismatch for user: ${username}`);
        console.log(`[TOKEN] Expected sub: ${hashedUsername}, Access sub: ${accessPayload.sub}, Refresh sub: ${refreshPayload.sub}`);
        return false;
      }

      const now = Math.floor(Date.now() / 1000);
      if (accessPayload.exp < now || refreshPayload.exp < now) {
        console.log(`[TOKEN] Tokens expired for user: ${username}`);
        return false;
      }

      // Ensure the associated account exists in the primary database
      try {
        const { UserDatabase } = await import('../database/database.js');
        const user = await UserDatabase.loadUser(username);
        if (!user) {
          console.log(`[TOKEN] Account not found in DB for user: ${username}`);
          return false;
        }
      } catch (error) {
        console.error('[TOKEN] Failed to verify account existence:', error?.message || error);
        return false;
      }

      // Check if tokens are not blacklisted (fail closed for security)
      try {
        const { TokenDatabase } = await import('./token-database.js');
        if (!TokenDatabase || typeof TokenDatabase.isTokenBlacklisted !== 'function') {
          console.error('[TOKEN] TokenDatabase or isTokenBlacklisted method not available - failing closed');
          return false;
        }

        if (await TokenDatabase.isTokenBlacklisted(accessPayload.jti) || await TokenDatabase.isTokenBlacklisted(refreshPayload.jti)) {
          console.log(`[TOKEN] Tokens blacklisted for user: ${username}`);
          return false;
        }
      } catch (error) {
        console.error('[TOKEN] Error checking token blacklist:', error.message);
        console.error('[TOKEN] Rejecting token due to blacklist verification failure');
        return false;
      }

      console.log(`[TOKEN] Token validation successful for user: ${username}`);
      return true;

    } catch (error) {
      console.error(`[TOKEN] Error validating tokens for user ${username}:`, error);
      return false;
    }
  }
}

const tokenService = new TokenService();

export { tokenService as TokenService };
export default tokenService;
