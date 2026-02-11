/**
 * OPRF-Based Discovery Service
 * 
 * Oblivious Pseudorandom Functions for anonymous user discovery that
 * uses an anytrust model where the discovery database cannot enumerate users without cooperation
 * from all OPRF key servers
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { logger } from './crypto-logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_DIR = path.join(__dirname, '..', 'config');

const OPRF_KEY_FILE = path.join(CONFIG_DIR, 'oprf-discovery-key.enc');
const OPRF_PUBLIC_FILE = path.join(CONFIG_DIR, 'oprf-discovery-public.key');

const OPRF_VERSION = 'oprf-discovery-v1';
const RATE_LIMIT_WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 30;

class OPRFRateLimiter {
  constructor() {
    this.requests = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  check(identifier) {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    if (!this.requests.has(identifier)) {
      this.requests.set(identifier, []);
    }

    const timestamps = this.requests.get(identifier).filter(t => t > windowStart);
    this.requests.set(identifier, timestamps);

    if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
      return false;
    }

    timestamps.push(now);
    return true;
  }

  cleanup() {
    const now = Date.now();
    const windowStart = now - RATE_LIMIT_WINDOW_MS;

    for (const [key, timestamps] of this.requests.entries()) {
      const valid = timestamps.filter(t => t > windowStart);
      if (valid.length === 0) {
        this.requests.delete(key);
      } else {
        this.requests.set(key, valid);
      }
    }
  }

  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

export class OPRFDiscoveryServer {
  constructor() {
    this.secretKey = null;
    this.publicKey = null;
    this.initialized = false;
    this.rateLimiter = new OPRFRateLimiter();
  }

  async initialize() {
    if (this.initialized) return;

    try {
      if (!fs.existsSync(CONFIG_DIR)) {
        fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
      }

      if (fs.existsSync(OPRF_PUBLIC_FILE) && fs.existsSync(OPRF_KEY_FILE)) {
        await this.loadKeys();
      } else {
        await this.generateAndSaveKeys();
      }

      this.initialized = true;
      logger.info('[OPRF-DISCOVERY] Initialized OPRF discovery server');
    } catch (error) {
      logger.error('[OPRF-DISCOVERY] Failed to initialize:', error.message);
      throw error;
    }
  }

  async loadKeys() {
    const kek = this.deriveKEK();

    const encryptedKey = fs.readFileSync(OPRF_KEY_FILE);
    const nonce = encryptedKey.slice(0, 12);
    const tag = encryptedKey.slice(12, 28);
    const ciphertext = encryptedKey.slice(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, nonce);
    decipher.setAuthTag(tag);
    decipher.setAAD(Buffer.from(OPRF_VERSION));

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    this.secretKey = new Uint8Array(decrypted);

    const publicKeyHex = fs.readFileSync(OPRF_PUBLIC_FILE, 'utf8').trim();
    this.publicKey = Buffer.from(publicKeyHex, 'hex');

    kek.fill(0);
    logger.info('[OPRF-DISCOVERY] Loaded existing OPRF keys');
  }

  async generateAndSaveKeys() {
    const keyPair = ristretto255_oprf.voprf.generateKeyPair();
    this.secretKey = keyPair.secretKey;
    this.publicKey = keyPair.publicKey;

    const kek = this.deriveKEK();
    const nonce = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', kek, nonce);
    cipher.setAAD(Buffer.from(OPRF_VERSION));

    const encrypted = Buffer.concat([cipher.update(Buffer.from(this.secretKey)), cipher.final()]);
    const tag = cipher.getAuthTag();

    fs.writeFileSync(OPRF_KEY_FILE, Buffer.concat([nonce, tag, encrypted]), { mode: 0o600 });
    fs.writeFileSync(OPRF_PUBLIC_FILE, Buffer.from(this.publicKey).toString('hex'), { mode: 0o644 });

    kek.fill(0);
    logger.info('[OPRF-DISCOVERY] Generated and saved new OPRF keys');
  }

  deriveKEK() {
    const kekSecret = process.env.KEY_ENCRYPTION_SECRET || process.env.DB_FIELD_KEY;
    if (!kekSecret) {
      throw new Error('KEY_ENCRYPTION_SECRET or DB_FIELD_KEY required for OPRF key encryption');
    }

    return blake3(Buffer.concat([
      Buffer.from(kekSecret, 'utf8'),
      Buffer.from('oprf-discovery-kek-v1')
    ]), { dkLen: 32 });
  }

  getPublicKey() {
    if (!this.initialized) {
      throw new Error('OPRF server not initialized');
    }
    return Buffer.from(this.publicKey).toString('hex');
  }

  blindEvaluate(blindedPointHex, clientId = 'anonymous') {
    if (!this.initialized) {
      throw new Error('OPRF server not initialized');
    }

    if (!this.rateLimiter.check(clientId)) {
      throw new Error('Rate limit exceeded for OPRF evaluations');
    }

    try {
      const blindedPoint = Buffer.from(blindedPointHex, 'hex');

      const result = ristretto255_oprf.voprf.blindEvaluate(
        this.secretKey,
        this.publicKey,
        blindedPoint
      );

      return {
        evaluated: Buffer.from(result.evaluated).toString('hex'),
        proof: Buffer.from(result.proof).toString('hex'),
        publicKey: Buffer.from(this.publicKey).toString('hex')
      };
    } catch (error) {
      logger.error('[OPRF-DISCOVERY] Blind evaluation failed:', error.message);
      throw new Error('OPRF evaluation failed');
    }
  }

  blindEvaluateBatch(blindedPointsHex, clientId = 'anonymous') {
    if (!this.initialized) {
      throw new Error('OPRF server not initialized');
    }

    if (!Array.isArray(blindedPointsHex) || blindedPointsHex.length === 0) {
      throw new Error('Expected non-empty array of blinded points');
    }

    if (blindedPointsHex.length > 10) {
      throw new Error('Batch size exceeds maximum of 10');
    }

    for (let i = 0; i < blindedPointsHex.length; i++) {
      if (!this.rateLimiter.check(`${clientId}:${i}`)) {
        throw new Error('Rate limit exceeded for OPRF evaluations');
      }
    }

    try {
      const blindedPoints = blindedPointsHex.map(hex => Buffer.from(hex, 'hex'));

      const result = ristretto255_oprf.voprf.blindEvaluateBatch(
        this.secretKey,
        this.publicKey,
        blindedPoints
      );

      return {
        evaluated: result.evaluated.map(e => Buffer.from(e).toString('hex')),
        proof: Buffer.from(result.proof).toString('hex'),
        publicKey: Buffer.from(this.publicKey).toString('hex')
      };
    } catch (error) {
      logger.error('[OPRF-DISCOVERY] Batch evaluation failed:', error.message);
      throw new Error('OPRF batch evaluation failed');
    }
  }

  destroy() {
    if (this.secretKey) {
      crypto.randomFillSync(this.secretKey);
      this.secretKey = null;
    }
    this.publicKey = null;
    this.initialized = false;
    this.rateLimiter.destroy();
  }
}

export const oprfDiscoveryServer = new OPRFDiscoveryServer();

export function deriveDiscoveryToken(oprfOutputHex, epoch) {
  const oprfOutput = Buffer.from(oprfOutputHex, 'hex');
  const epochBytes = Buffer.alloc(8);
  epochBytes.writeBigUInt64BE(BigInt(epoch));

  return blake3(Buffer.concat([
    Buffer.from('discovery-token-v1'),
    oprfOutput,
    epochBytes
  ]), { dkLen: 32 }).toString('hex');
}

export function deriveDiscoveryEncryptionKey(oprfOutputHex) {
  const oprfOutput = Buffer.from(oprfOutputHex, 'hex');

  return blake3(Buffer.concat([
    Buffer.from('discovery-encryption-key-v1'),
    oprfOutput
  ]), { dkLen: 32 });
}
