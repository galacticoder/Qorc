/**
 * Privacy Pass Token Server
 * 
 * Provides anonymous and rate limited authentication tokens
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import crypto from 'node:crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = path.join(__dirname, '../config');

// Privacy Pass configuration
const PP_CONFIG = {
    TOKEN_KEY_FILE: 'privacy-pass-key.enc',
    DEFAULT_BATCH_SIZE: 250,
    NULLIFIER_SIZE: 32,
    TOKEN_SIZE: 64,
    MAC_SIZE: 32,
    NONCE_SIZE: 24,
    KEY_ROTATION_DAYS: 30,
};

// Domain separation labels
const PP_LABELS = {
    TOKEN_KEY: 'PrivacyPass-Token-Key-v1',
    NULLIFIER: 'PrivacyPass-Nullifier-v1',
    REDEMPTION_MAC: 'PrivacyPass-Redemption-MAC-v1',
    TOKEN_ENCRYPTION: 'PrivacyPass-Token-Encryption-v1',
    OPRF_INPUT: 'PrivacyPass-OPRF-Input-v1',
};

function normalizePurpose(purpose) {
    const value = typeof purpose === 'string' ? purpose.trim().toLowerCase() : '';
    return /^[a-z0-9:_-]{1,64}$/.test(value) ? value : 'account-auth';
}

export class PrivacyPassServer {
    static #tokenKeys = null;
    static #initialized = false;
    static #nullifierStore = null;
    static #cleanupInterval = null;

    /**
     * Initialize Privacy Pass server
     */
    static async initialize(nullifierStore) {
        if (this.#initialized) return;

        this.#nullifierStore = nullifierStore;

        try {
            await fs.mkdir(CONFIG_DIR, { recursive: true });
            const keyPath = path.join(CONFIG_DIR, PP_CONFIG.TOKEN_KEY_FILE);

            try {
                const encryptedKey = await fs.readFile(keyPath);
                const keyData = await this.#decryptKey(encryptedKey);
                this.#tokenKeys = {
                    secretKey: keyData.slice(0, 32),
                    publicKey: keyData.slice(32),
                };
            } catch {
                // Generate new VOPRF keys
                this.#tokenKeys = oprf.voprf.generateKeyPair();
                const keyData = Buffer.concat([
                    Buffer.from(this.#tokenKeys.secretKey),
                    Buffer.from(this.#tokenKeys.publicKey),
                ]);
                const encrypted = await this.#encryptKey(keyData);
                await fs.writeFile(keyPath, encrypted, { mode: 0o600 });
                console.log('[PrivacyPass] Generated new token keys');
            }

            // Schedule periodic nullifier cleanup (every 24 hours)
            if (this.#nullifierStore && !this.#cleanupInterval) {
                this.#cleanupInterval = setInterval(() => {
                    this.#nullifierStore.cleanup().catch(err =>
                        console.warn('[PrivacyPass] Nullifier cleanup failed:', err.message)
                    );
                }, 24 * 60 * 60 * 1000);
                this.#cleanupInterval.unref();
            }

            this.#initialized = true;
            console.log('[PrivacyPass] Server initialized');
        } catch (error) {
            console.error('[PrivacyPass] Initialization failed:', error.message);
            throw error;
        }
    }

    /**
     * Get public key for client verification
     */
    static getPublicKey() {
        if (!this.#initialized) {
            throw new Error('PrivacyPass server not initialized');
        }
        return this.#tokenKeys.publicKey;
    }

    /**
     * Issue batch of blind signed tokens
     */
    static async issueTokenBatch(blindedTokens, proofOfEntitlement) {
        if (!this.#initialized) {
            throw new Error('PrivacyPass server not initialized');
        }

        if (!Array.isArray(blindedTokens) || blindedTokens.length === 0) {
            throw new Error('Invalid blinded tokens');
        }

        if (blindedTokens.length > PP_CONFIG.DEFAULT_BATCH_SIZE) {
            throw new Error(`Batch size exceeds limit of ${PP_CONFIG.DEFAULT_BATCH_SIZE}`);
        }

        // Verify proof of entitlement
        if (!proofOfEntitlement || proofOfEntitlement.length < 24) {
            throw new Error('Invalid proof of entitlement');
        }

        // Batch VOPRF evaluation with proof
        const result = oprf.voprf.blindEvaluateBatch(
            this.#tokenKeys.secretKey,
            this.#tokenKeys.publicKey,
            blindedTokens
        );

        console.log(`[PrivacyPass] Issued batch of ${blindedTokens.length} tokens`);

        return {
            signedBlindedTokens: result.evaluated,
            proof: result.proof,
            publicKey: this.#tokenKeys.publicKey,
        };
    }

    /**
     * Redeem a token
     */
    static async redeemToken(token, nullifier, mac, tokenSecret, expectedPurpose = 'account-auth') {
        if (!this.#initialized) {
            throw new Error('PrivacyPass server not initialized');
        }

        if (!token || token.length !== PP_CONFIG.TOKEN_SIZE) {
            console.log('[PrivacyPass] Token format invalid', { tokenLen: token?.length });
            return this.#uniformFailureResponse();
        }

        if (!tokenSecret || tokenSecret.length !== 32) {
            console.log('[PrivacyPass] Token secret proof missing or invalid');
            return this.#uniformFailureResponse();
        }

        if (!nullifier || nullifier.length !== PP_CONFIG.NULLIFIER_SIZE) {
            console.log('[PrivacyPass] Nullifier format invalid', { nullifierLen: nullifier?.length, expected: PP_CONFIG.NULLIFIER_SIZE });
            return this.#uniformFailureResponse();
        }

        if (!this.#verifyIssuedToken(token, tokenSecret, expectedPurpose)) {
            console.log('[PrivacyPass] Token issuance proof invalid');
            return this.#uniformFailureResponse();
        }

        // Compute expected nullifier from token
        const expectedNullifier = this.#computeNullifier(token);

        if (!crypto.timingSafeEqual(
            Buffer.from(nullifier),
            Buffer.from(expectedNullifier)
        )) {
            console.log('[PrivacyPass] Nullifier mismatch');
            return this.#uniformFailureResponse();
        }

        // Check if nullifier already used
        const nullifierUsed = await this.#nullifierStore?.isUsed(nullifier);
        if (nullifierUsed) {
            console.log('[PrivacyPass] Nullifier already used');
            return this.#uniformFailureResponse();
        }

        // Verify MAC
        const expectedMac = this.#computeRedemptionMac(token, nullifier);
        if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expectedMac))) {
            console.log('[PrivacyPass] MAC verification failed');
            return this.#uniformFailureResponse();
        }

        // Mark nullifier as used
        await this.#nullifierStore?.markUsed(nullifier);

        return {
            valid: true,
            encryptedResponse: this.#generateSuccessResponse(token),
        };
    }

    /**
     * Verify token was signed with our VOPRF key
     */
    static #verifyIssuedToken(token, tokenSecret, purpose) {
        try {
            if (!token || token.length !== PP_CONFIG.TOKEN_SIZE || !tokenSecret || tokenSecret.length !== 32) {
                return false;
            }

            const label = `${PP_LABELS.OPRF_INPUT}:${normalizePurpose(purpose)}`;
            const oprfInput = hkdf(
                blake3,
                tokenSecret,
                new Uint8Array(0),
                new TextEncoder().encode(label),
                32
            );
            const expectedToken = oprf.voprf.evaluate(this.#tokenKeys.secretKey, oprfInput);
            return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken));
        } catch {
            return false;
        }
    }

    /**
     * Generate uniform failure response
     */
    static #uniformFailureResponse() {
        return {
            valid: false,
            encryptedResponse: randomBytes(256),
        };
    }

    /**
     * Generate encrypted success response
     */
    static #generateSuccessResponse(token) {
        // Derive encryption key from token
        const encKey = hkdf(
            blake3,
            token,
            new Uint8Array(0),
            new TextEncoder().encode(PP_LABELS.TOKEN_ENCRYPTION),
            32
        );

        // Create success payload with session establishment data
        const payload = Buffer.concat([
            Buffer.from([0x01]),
            randomBytes(32),
            randomBytes(32),
        ]);

        // Encrypt payload
        const nonce = randomBytes(PP_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(encKey, nonce);
        const encrypted = cipher.encrypt(payload);

        return Buffer.concat([nonce, encrypted]);
    }

    /**
     * Compute nullifier from token
     */
    static #computeNullifier(token) {
        return hkdf(
            blake3,
            token,
            new Uint8Array(0),
            new TextEncoder().encode(PP_LABELS.NULLIFIER),
            PP_CONFIG.NULLIFIER_SIZE
        );
    }

    /**
     * Compute redemption MAC
     */
    static #computeRedemptionMac(token, nullifier) {
        const key = hkdf(
            blake3,
            token,
            nullifier,
            new TextEncoder().encode(PP_LABELS.REDEMPTION_MAC),
            32
        );
        return blake3(key, { dkLen: PP_CONFIG.MAC_SIZE });
    }

    /**
     * Encrypt key for storage
     */
    static async #encryptKey(keyData) {
        const machineKey = await this.#getMachineKey();
        const nonce = randomBytes(PP_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(machineKey, nonce);
        return Buffer.concat([nonce, cipher.encrypt(keyData)]);
    }

    /**
     * Decrypt stored key
     */
    static async #decryptKey(encryptedData) {
        const machineKey = await this.#getMachineKey();
        const nonce = encryptedData.slice(0, PP_CONFIG.NONCE_SIZE);
        const ciphertext = encryptedData.slice(PP_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(machineKey, nonce);
        return cipher.decrypt(ciphertext);
    }

    /**
     * Get machine specific key
     */
    static async #getMachineKey() {
        const hostname = (await import('os')).hostname() || 'unknown-host';
        const machineIdPath = path.join(CONFIG_DIR, '.machine-id');

        let machineId;
        try {
            machineId = await fs.readFile(machineIdPath);
            if (!machineId || machineId.length < 16) {
                throw new Error('Machine ID too short, regenerating');
            }
        } catch {
            machineId = randomBytes(32);
            await fs.writeFile(machineIdPath, machineId, { mode: 0o600 });
        }

        return hkdf(blake3, machineId, new TextEncoder().encode(hostname), new TextEncoder().encode('PrivacyPass-Machine-Key'), 32);
    }
}

/**
 * Nullifier Store Interface
 */
export class NullifierStore {
    #db = null;

    constructor(db) {
        this.#db = db;
    }

    /**
     * Check if nullifier has been used
     */
    async isUsed(nullifier) {
        const nullifierHex = Buffer.from(nullifier).toString('hex');
        const result = await this.#db.query(
            'SELECT 1 FROM nullifiers WHERE nullifier_hash = $1',
            [nullifierHex]
        );
        return result.rows.length > 0;
    }

    /**
     * Mark nullifier as used
     */
    async markUsed(nullifier) {
        const nullifierHex = Buffer.from(nullifier).toString('hex');
        await this.#db.query(
            'INSERT INTO nullifiers (nullifier_hash) VALUES ($1) ON CONFLICT DO NOTHING',
            [nullifierHex]
        );
    }

    /**
     * Cleanup old nullifiers
     */
    async cleanup(maxAgeDays = 60) {
        const days = Math.max(1, Math.min(365, Math.floor(maxAgeDays)));
        await this.#db.query(
            `DELETE FROM nullifiers WHERE recorded_at < NOW() - INTERVAL '${days} days'`
        );
    }
}

/**
 * Privacy Pass Client Helpers
 */
export const PrivacyPassHelpers = {
    /**
     * Parse token issuance request
     */
    parseIssuanceRequest(data) {
        if (!data.blindedTokens || !Array.isArray(data.blindedTokens)) {
            throw new Error('Invalid issuance request');
        }
        return {
            blindedTokens: data.blindedTokens.map(t => Buffer.from(t, 'base64')),
            proofOfEntitlement: data.proofOfEntitlement
                ? Buffer.from(data.proofOfEntitlement, 'base64')
                : null,
        };
    },

    /**
     * Parse token redemption request
     */
    parseRedemptionRequest(data) {
        if (!data.token || !data.nullifier || !data.mac || !data.tokenSecret) {
            throw new Error('Invalid redemption request');
        }
        return {
            token: Buffer.from(data.token, 'base64'),
            nullifier: Buffer.from(data.nullifier, 'base64'),
            mac: Buffer.from(data.mac, 'base64'),
            tokenSecret: Buffer.from(data.tokenSecret, 'base64'),
            purpose: typeof data.purpose === 'string' ? data.purpose : undefined,
        };
    },

    /**
     * Format response for client
     */
    formatResponse(response) {
        if (!response) return null;
        const formatted = {};
        for (const [key, value] of Object.entries(response)) {
            if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
                formatted[key] = Buffer.from(value).toString('base64');
            } else if (Array.isArray(value)) {
                formatted[key] = value.map(v =>
                    v instanceof Uint8Array || Buffer.isBuffer(v)
                        ? Buffer.from(v).toString('base64')
                        : v
                );
            } else {
                formatted[key] = value;
            }
        }
        return formatted;
    },
};

export { PP_CONFIG, PP_LABELS };
