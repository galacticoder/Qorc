/**
 * OPAQUE Protocol
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import crypto from 'node:crypto';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { ml_kem1024 as MlKem, xor } from './helpers.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = path.join(__dirname, '../config');

// OPAQUE configuration
const OPAQUE_CONFIG = {
    OPRF_SEED_FILE: 'oprf-seed.enc',
    KEY_ROTATION_DAYS: 90,
    NONCE_SIZE: 24,
    AUTH_TAG_SIZE: 16,
    CREDENTIAL_ID_SIZE: 32,
    EXPORT_KEY_SIZE: 32,
    SESSION_KEY_SIZE: 32,
    ENVELOPE_NONCE_SIZE: 24,
};

// Domain separation labels
const LABELS = {
    OPRF_KEY: 'OPAQUE-OPRF-Key-v1',
    ENVELOPE_KEY: 'OPAQUE-Envelope-Key-v1',
    EXPORT_KEY: 'OPAQUE-Export-Key-v1',
    SESSION_KEY: 'OPAQUE-Session-Key-v1',
    AUTH_KEY: 'OPAQUE-Auth-Key-v1',
    CREDENTIAL_ID: 'OPAQUE-Credential-ID-v1',
};

export class OPAQUEServer {
    static #oprfKeys = null;
    static #initialized = false;

    static #ensureUint8Array(val) {
        if (!val) return new Uint8Array(0);
        if (typeof val === 'string') return Buffer.from(val, 'base64');
        if (val instanceof Uint8Array || Buffer.isBuffer(val)) return new Uint8Array(val);
        return new Uint8Array(0);
    }

    /**
     * Initialize OPAQUE server with OPRF keys
     */
    static async initialize() {
        if (this.#initialized) return;

        try {
            await fs.mkdir(CONFIG_DIR, { recursive: true });
            const keyPath = path.join(CONFIG_DIR, OPAQUE_CONFIG.OPRF_SEED_FILE);

            try {
                const encryptedSeed = await fs.readFile(keyPath);
                const seed = await this.#decryptSeed(encryptedSeed);
                this.#oprfKeys = oprf.oprf.deriveKeyPair(seed, new TextEncoder().encode(LABELS.OPRF_KEY));
            } catch {
                // Generate new keys
                this.#oprfKeys = oprf.oprf.generateKeyPair();
                
                const seed = randomBytes(32);
                const encrypted = await this.#encryptSeed(seed);
                await fs.writeFile(keyPath, encrypted, { mode: 0o600 });
                console.log('[OPAQUE] Generated new OPRF keys');
            }

            this.#initialized = true;
            console.log('[OPAQUE] Server initialized');
        } catch (error) {
            console.error('[OPAQUE] Initialization failed:', error.message);
            throw error;
        }
    }

    /**
     * Encrypt OPRF seed for storage
     */
    static async #encryptSeed(seed) {
        const machineKey = await this.#getMachineKey();
        const nonce = randomBytes(OPAQUE_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(machineKey, nonce);
        const encrypted = cipher.encrypt(seed);
        return Buffer.concat([nonce, encrypted]);
    }

    /**
     * Decrypt stored OPRF seed
     */
    static async #decryptSeed(encryptedData) {
        const machineKey = await this.#getMachineKey();
        const nonce = encryptedData.slice(0, OPAQUE_CONFIG.NONCE_SIZE);
        const ciphertext = encryptedData.slice(OPAQUE_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(machineKey, nonce);
        return cipher.decrypt(ciphertext);
    }

    /**
     * Derive machine specific key for OPRF seed encryption
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

        return hkdf(blake3, machineId, new TextEncoder().encode(hostname), new TextEncoder().encode('OPAQUE-Machine-Key'), 32);
    }

    /**
     * Get public key for client to verify VOPRF proofs
     */
    static getPublicKey() {
        if (!this.#initialized) {
            throw new Error('OPAQUE server not initialized');
        }
        return this.#oprfKeys.publicKey;
    }

    /**
     * OPAQUE Registration
     */
    static async createRegistrationResponse(blindedElement, clientPublicKey) {
        if (!this.#initialized) {
            await this.initialize();
        }

        // Blind OPRF evaluation
        const evaluated = oprf.oprf.blindEvaluate(this.#oprfKeys.secretKey, blindedElement);

        // Generate server nonce for key derivation
        const serverNonce = randomBytes(32);

        // Generate server keypair for this registration
        const serverKeyPair = this.#generateServerKeyPair();

        return {
            evaluatedElement: evaluated,
            serverPublicKey: serverKeyPair.publicKey,
            serverNonce,
            serverPrivateKey: serverKeyPair.privateKey,
        };
    }

    /**
     * Create OPAQUE record for storage
     */
    static createRegistrationRecord(credentialId, envelope, serverPrivateKey, maskedResponse, salt) {
        return {
            credentialId: Buffer.from(credentialId).toString('base64'),
            envelope: Buffer.from(envelope).toString('base64'),
            serverPrivateKey: Buffer.from(serverPrivateKey).toString('base64'),
            maskedResponse: Buffer.from(maskedResponse).toString('base64'),
            salt: salt ? Buffer.from(salt).toString('base64') : undefined,
            createdAt: new Date().toISOString(),
        };
    }

    /**
     * OPAQUE Login
     */
    static createLoginResponseLocal(blindedElement) {
        if (!this.#initialized) return null;
        return oprf.oprf.blindEvaluate(this.#oprfKeys.secretKey, blindedElement);
    }

    /**
     * OPAQUE Login. Create login response with VOPRF evaluation
     */
    static async createLoginResponse(blindedElement, record) {
        if (!this.#initialized) {
            await this.initialize();
        }

        console.log(`[OPAQUE] createLoginResponse`);

        // Blind OPRF evaluation
        const secretKey = record.oprfSecretKey || this.#oprfKeys.secretKey;
        const evaluated = oprf.oprf.blindEvaluate(secretKey, blindedElement);

        // Generate server nonce
        const serverNonce = randomBytes(32);

        // Return the stored envelope and masked response
        return {
            evaluatedElement: evaluated,
            envelope: this.#ensureUint8Array(record.envelope),
            maskedResponse: this.#ensureUint8Array(record.maskedResponse),
            salt: this.#ensureUint8Array(record.salt),
            serverNonce,
        };
    }

    /**
     * Compute auth MAC for login verification
     */
    static #computeAuthMac(maskedResponse, serverNonce) {
        const key = hkdf(blake3, maskedResponse, serverNonce, new TextEncoder().encode(LABELS.AUTH_KEY), 32);

        const mac = blake3(key, { dkLen: 32 });
        return mac;
    }

    /**
     * Login finalization
     */
    static async finishLogin(clientAuthMessage, record, serverNonce) {
        if (!record || !record.maskedResponse) {
            return { success: false };
        }

        // Use the stored maskedResponse as the shared secret
        const maskedResponse = this.#ensureUint8Array(record.maskedResponse);
        const expectedMac = this.#computeAuthMac(maskedResponse, serverNonce);

        if (!crypto.timingSafeEqual(
            Buffer.from(clientAuthMessage),
            Buffer.from(expectedMac)
        )) {
            console.warn(`[OPAQUE] finishLogin: MAC mismatch. Client: ${Buffer.from(clientAuthMessage).toString('hex').slice(0, 8)}, Expected: ${Buffer.from(expectedMac).toString('hex').slice(0, 8)}`);
            return {
                success: false,
                encryptedSessionKey: randomBytes(OPAQUE_CONFIG.SESSION_KEY_SIZE + 16),
            };
        }

        // Use serverPrivateKey for session key encryption
        const authKey = this.#ensureUint8Array(record.serverPrivateKey);

        // Generate session key
        const sessionKey = randomBytes(OPAQUE_CONFIG.SESSION_KEY_SIZE);

        // Encrypt session key with derived key
        const encryptionKey = hkdf(
            blake3,
            authKey,
            serverNonce,
            new TextEncoder().encode(LABELS.SESSION_KEY),
            32
        );

        const nonce = randomBytes(OPAQUE_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const encryptedSessionKey = Buffer.concat([
            nonce,
            cipher.encrypt(sessionKey)
        ]);

        return {
            success: true,
            sessionKey,
            encryptedSessionKey,
        };
    }

    /**
     * Compute credential ID from blinded user ID
     */
    static computeCredentialId(userId) {
        const salt = this.#oprfKeys ? this.#oprfKeys.publicKey.slice(0, 16) : randomBytes(16);
        return hkdf(
            blake3,
            new TextEncoder().encode(userId),
            salt,
            new TextEncoder().encode(LABELS.CREDENTIAL_ID),
            OPAQUE_CONFIG.CREDENTIAL_ID_SIZE
        );
    }

    /**
     * Generate uniform response regardless of login outcome
     */
    static generateUniformResponse(actualResult, encryptionKey) {
        const PAYLOAD_SIZE = 512;
        const payload = new Uint8Array(PAYLOAD_SIZE);

        if (actualResult.success) {
            payload.set(actualResult.sessionKey, 0);
            payload.set(actualResult.capabilityToken || new Uint8Array(32), 32);
            payload.set(randomBytes(PAYLOAD_SIZE - 128), 128);
        } else {
            payload.set(randomBytes(PAYLOAD_SIZE), 0);
        }

        // Encrypt with provided key
        const nonce = randomBytes(OPAQUE_CONFIG.NONCE_SIZE);
        const cipher = xchacha20poly1305(encryptionKey, nonce);
        const encrypted = cipher.encrypt(payload);

        return Buffer.concat([nonce, encrypted]);
    }

    /**
     * Generate server keypair for OPAQUE
     */
    static #generateServerKeyPair() {
        const seed = randomBytes(32);
        return {
            privateKey: seed,
            publicKey: blake3(seed, { dkLen: 32 }),
        };
    }

    /**
     * Get maximum entries per shard
     */
    static getShardSize() {
        return 100;
    }

    /**
     * Oblivious Transfer
     */
    static async encryptShardForOT(records, clientPubKeys) {
        const shardSize = this.getShardSize();

        const promises = [];

        for (let i = 0; i < shardSize; i++) {
            const record = records.find(r => r.credential_index === i);
            const pubKey = clientPubKeys[i];

            promises.push((async () => {
                if (!record || !pubKey || !record.opaqueRecord) {
                    const dummy = crypto.randomBytes(256);
                    const { cipherText: ct, sharedSecret: ss } = await MlKem.encapsulate(this.#ensureUint8Array(pubKey || crypto.randomBytes(1568)));
                    const mask = blake3(ss, { dkLen: dummy.length });
                    return {
                        ct: Buffer.from(ct).toString('base64'),
                        masked: Buffer.from(xor(dummy, mask)).toString('base64')
                    };
                }

                // Real record
                const rawRecord = Buffer.from(record.opaqueRecord, 'utf8');
                const { cipherText: ct, sharedSecret: ss } = await MlKem.encapsulate(this.#ensureUint8Array(pubKey));
                const mask = blake3(ss, { dkLen: rawRecord.length });

                return {
                    ct: Buffer.from(ct).toString('base64'),
                    masked: Buffer.from(xor(rawRecord, mask)).toString('base64')
                };
            })());
        }

        const encrypted = await Promise.all(promises);
        return encrypted;
    }
}

/**
 * OPAQUE Client Helper Functions
 */
export const OPAQUEHelpers = {
    /**
     * Parse registration request from client
     */
    parseRegistrationRequest(data) {
        if (!data.blindedElement || !data.clientPublicKey) {
            throw new Error('Invalid registration request');
        }
        return {
            blindedElement: Buffer.from(data.blindedElement, 'base64'),
            clientPublicKey: Buffer.from(data.clientPublicKey, 'base64'),
        };
    },

    /**
     * Parse login request from client
     */
    parseLoginRequest(data) {
        if (!data.blindedElement || !data.credentialId) {
            throw new Error('Invalid login request');
        }
        return {
            blindedElement: Buffer.from(data.blindedElement, 'base64'),
            credentialId: Buffer.from(data.credentialId, 'base64'),
        };
    },

    /**
     * Format response for client
     */
    formatResponse(response) {
        const formatted = {};
        for (const [key, value] of Object.entries(response)) {
            if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
                formatted[key] = Buffer.from(value).toString('base64');
            } else {
                formatted[key] = value;
            }
        }
        return formatted;
    },
};

export { OPAQUE_CONFIG, LABELS };
