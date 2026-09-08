/**
 * Privacy Pass Token Server
 * 
 * Provides anonymous and rate limited authentication tokens
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import crypto from 'node:crypto';
import { deriveAuthRootKey } from '../crypto/auth-root.js';
import { evaluatePrivacyPassBatch } from '../crypto/auth-crypto-worker-service.js';
import {
    ACCOUNT_AUTH_PURPOSE,
    SERVER_ENTRY_PURPOSE
} from '../config/audiences.js';
import { decodeCanonicalBase64, encodeBase64AndWipeCopy, UTF8_ENCODER } from '../utils/encoding.js';
import { withTransaction } from '../database/core.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import { HASH_OUTPUT_BYTES } from '../utils/crypto-consts.js';
import { PRIVACY_PASS_CONFIG as PP_CONFIG } from '../../shared/privacy-pass-protocol.js';

// Domain separation labels
const PP_LABELS = {
    NULLIFIER: PROTOCOL_KEYS.PRIVACY_PASS_NULLIFIER,
    REDEMPTION_MAC: PROTOCOL_KEYS.PRIVACY_PASS_REDEMPTION_MAC,
    OPRF_INPUT: PROTOCOL_KEYS.PRIVACY_PASS_OPRF_INPUT,
};

const ALLOWED_PURPOSES = new Set([ACCOUNT_AUTH_PURPOSE, SERVER_ENTRY_PURPOSE]);

function normalizePurpose(purpose) {
    const value = typeof purpose === 'string' ? purpose.trim().toLowerCase() : '';
    if (!ALLOWED_PURPOSES.has(value)) throw new Error('Invalid Privacy Pass purpose');
    return value;
}

function currentTokenEpoch() {
    return Math.floor(Date.now() / 86_400_000);
}

function normalizeIssuanceEpoch(epoch) {
    const current = currentTokenEpoch();
    if (
        !Number.isSafeInteger(epoch) ||
        epoch < 0 ||
        epoch > 0xffffffff ||
        epoch > current ||
        current - epoch > PP_CONFIG.TOKEN_MAX_AGE_EPOCHS
    ) {
        throw new Error('Invalid Privacy Pass issuance epoch');
    }
    return epoch;
}

function readTokenEpoch(tokenSecret) {
    if (!(tokenSecret instanceof Uint8Array) || tokenSecret.length < 4) {
        throw new Error('Invalid Privacy Pass token secret');
    }
    return new DataView(
        tokenSecret.buffer,
        tokenSecret.byteOffset,
        tokenSecret.byteLength
    ).getUint32(0, false);
}

export class PrivacyPassServer {
    static #keysByPurpose = new Map();
    static #initialized = false;
    static #initializationPromise = null;
    static #nullifierStore = null;
    static #cleanupInterval = null;
    static #cleanupInFlight = null;
    static #lifecycleGeneration = 0;
    static #serverEntryIssuerSeed = null;
    static #serverEntryCredentialGeneration = 0;

    static validateIssuanceEpoch(epoch) {
        return normalizeIssuanceEpoch(epoch);
    }

    static isServerEntryCredentialGenerationCurrent(generation) {
        return Number.isSafeInteger(generation) &&
            generation === this.#serverEntryCredentialGeneration;
    }

    // Derive cluster wide issuer key
    static async #getKeysForPurpose(purpose, epoch = currentTokenEpoch()) {
        const norm = normalizePurpose(purpose);
        if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > 0xffffffff) {
            throw new Error('Invalid Privacy Pass epoch');
        }
        const credentialGeneration = norm === SERVER_ENTRY_PURPOSE
            ? this.#serverEntryCredentialGeneration
            : 0;
        const cacheKey = `${norm}:${credentialGeneration}:${epoch}`;
        const existing = this.#keysByPurpose.get(cacheKey);
        if (existing) return existing;

        const seed = norm === SERVER_ENTRY_PURPOSE
            ? this.#serverEntryIssuerSeed && new Uint8Array(this.#serverEntryIssuerSeed)
            : deriveAuthRootKey(`${PROTOCOL_KEYS.PRIVACY_PASS_VOPRF_ROOT}:${norm}`);
        if (!seed) {
            throw new Error('Server-entry issuer is not configured');
        }
        let keys;
        try {
            keys = oprf.voprf.deriveKeyPair(
                seed,
                UTF8_ENCODER.encode(`${PROTOCOL_KEYS.PRIVACY_PASS_ISSUER}:${norm}:${epoch}`)
            );
        } finally {
            seed.fill(0);
        }
        this.#validateKeyPair(keys);
        this.#keysByPurpose.set(cacheKey, keys);
        this.#pruneIssuerKeys();
        return keys;
    }

    static #pruneIssuerKeys() {
        const current = currentTokenEpoch();
        for (const [cacheKey, keys] of this.#keysByPurpose) {
            const epoch = Number(cacheKey.slice(cacheKey.lastIndexOf(':') + 1));
            if (
                Number.isSafeInteger(epoch) &&
                epoch >= current - PP_CONFIG.TOKEN_MAX_AGE_EPOCHS &&
                epoch <= current
            ) {
                continue;
            }
            keys?.secretKey?.fill(0);
            keys?.publicKey?.fill(0);
            this.#keysByPurpose.delete(cacheKey);
        }
    }

    static configureServerEntryPasswordSecret(passwordSecret) {
        if (!(passwordSecret instanceof Uint8Array) || passwordSecret.length !== HASH_OUTPUT_BYTES) {
            throw new Error('Invalid server-entry password secret');
        }

        const root = deriveAuthRootKey(PROTOCOL_KEYS.PRIVACY_PASS_SERVER_ENTRY_ROOT);
        let nextSeed = null;
        try {
            nextSeed = hkdf(
                blake3,
                passwordSecret,
                root,
                UTF8_ENCODER.encode(PROTOCOL_KEYS.PRIVACY_PASS_SERVER_ENTRY_BINDING),
                HASH_OUTPUT_BYTES
            );
        } finally {
            root.fill(0);
        }

        if (
            this.#serverEntryIssuerSeed &&
            crypto.timingSafeEqual(this.#serverEntryIssuerSeed, nextSeed)
        ) {
            nextSeed.fill(0);
            return false;
        }

        this.#serverEntryCredentialGeneration += 1;
        for (const [cacheKey, keys] of this.#keysByPurpose) {
            if (!cacheKey.startsWith(`${SERVER_ENTRY_PURPOSE}:`)) continue;
            keys?.secretKey?.fill(0);
            keys?.publicKey?.fill(0);
            this.#keysByPurpose.delete(cacheKey);
        }
        this.#serverEntryIssuerSeed?.fill(0);
        this.#serverEntryIssuerSeed = nextSeed;
        return true;
    }

    static #validateKeyPair(keys) {
        let input;
        let blind;
        let evaluated;
        let finalized;
        let expected;
        try {
            input = blake3(
                UTF8_ENCODER.encode(PROTOCOL_KEYS.PRIVACY_PASS_SELF_TEST),
                { dkLen: HASH_OUTPUT_BYTES }
            );
            blind = oprf.voprf.blind(input);
            evaluated = oprf.voprf.blindEvaluate(keys.secretKey, keys.publicKey, blind.blinded);
            finalized = oprf.voprf.finalize(input, blind.blind, evaluated.evaluated, blind.blinded, keys.publicKey, evaluated.proof);
            expected = oprf.voprf.evaluate(keys.secretKey, input);
            if (!crypto.timingSafeEqual(finalized, expected)) {
                throw new Error('Privacy Pass issuer key pair mismatch');
            }
        } finally {
            input?.fill(0);
            blind?.blind?.fill(0);
            blind?.blinded?.fill(0);
            evaluated?.evaluated?.fill(0);
            evaluated?.proof?.fill(0);
            finalized?.fill(0);
            expected?.fill(0);
        }
    }

    static #assertLifecycleGeneration(generation) {
        if (generation === this.#lifecycleGeneration) return;
        const error = new Error('Privacy Pass initialization cancelled');
        error.code = 'PRIVACY_PASS_INITIALIZATION_CANCELLED';
        throw error;
    }

    static #assertIssuanceGeneration(generation) {
        if (this.#initialized && generation === this.#lifecycleGeneration) return;
        const error = new Error('Privacy Pass issuance cancelled');
        error.code = 'PRIVACY_PASS_ISSUANCE_CANCELLED';
        throw error;
    }

    /**
     * Initialize Privacy Pass server
     */
    static async initialize(nullifierStore) {
        if (this.#initialized) return;
        if (this.#initializationPromise) return this.#initializationPromise;
        if (
            !nullifierStore ||
            typeof nullifierStore.cleanup !== 'function' ||
            typeof nullifierStore.markUsed !== 'function' ||
            typeof nullifierStore.markUsedBatch !== 'function'
        ) {
            throw new Error('Privacy Pass requires a complete nullifier store');
        }

        const generation = this.#lifecycleGeneration;
        const initialization = (async () => {
            this.#nullifierStore = nullifierStore;

            if (this.#serverEntryIssuerSeed) {
                await this.#getKeysForPurpose(SERVER_ENTRY_PURPOSE);
                this.#assertLifecycleGeneration(generation);
            }
            await this.#getKeysForPurpose(ACCOUNT_AUTH_PURPOSE);
            this.#assertLifecycleGeneration(generation);

            if (!this.#cleanupInterval) {
                await this.#runNullifierCleanup();
                this.#assertLifecycleGeneration(generation);
                this.#cleanupInterval = setInterval(() => {
                    this.#runNullifierCleanup().catch(() =>
                        console.warn('[PrivacyPass] Nullifier cleanup failed')
                    );
                }, 24 * 60 * 60 * 1000);
                this.#cleanupInterval.unref();
            }

            this.#assertLifecycleGeneration(generation);
            this.#initialized = true;
            console.log('[PrivacyPass] Server initialized');
        })();
        this.#initializationPromise = initialization;

        try {
            await initialization;
        } catch (error) {
            if (generation === this.#lifecycleGeneration) {
                this.#nullifierStore = null;
            }
            if (error?.code !== 'PRIVACY_PASS_INITIALIZATION_CANCELLED') {
                console.error('[PrivacyPass] Initialization failed', error);
            }
            throw error;
        } finally {
            if (this.#initializationPromise === initialization) {
                this.#initializationPromise = null;
            }
        }
    }

    static async #runNullifierCleanup() {
        if (this.#cleanupInFlight) return this.#cleanupInFlight;
        const store = this.#nullifierStore;
        if (!store) return;

        const pending = store.cleanup();
        this.#cleanupInFlight = pending;
        try {
            await pending;
        } finally {
            if (this.#cleanupInFlight === pending) this.#cleanupInFlight = null;
        }
    }

    static async destroy() {
        this.#lifecycleGeneration += 1;
        this.#initialized = false;
        if (this.#cleanupInterval) {
            clearInterval(this.#cleanupInterval);
            this.#cleanupInterval = null;
        }
        const initialization = this.#initializationPromise;
        const cleanupInFlight = this.#cleanupInFlight;
        this.#nullifierStore = null;
        await Promise.allSettled(
            [initialization, cleanupInFlight].filter(Boolean)
        );
        for (const keys of this.#keysByPurpose.values()) {
            keys?.secretKey?.fill(0);
            keys?.publicKey?.fill(0);
        }
        this.#keysByPurpose.clear();
        if (this.#initializationPromise === initialization) {
            this.#initializationPromise = null;
        }
        this.#cleanupInFlight = null;
        this.#serverEntryIssuerSeed?.fill(0);
        this.#serverEntryIssuerSeed = null;
        this.#serverEntryCredentialGeneration += 1;
    }

    /**
     * Issue batch of blind signed tokens
     */
    static async issueTokenBatch(blindedTokens, purpose, tokenEpoch, signal) {
        if (!this.#initialized) {
            throw new Error('PrivacyPass server not initialized');
        }
        const generation = this.#lifecycleGeneration;
        const normalizedPurpose = normalizePurpose(purpose);
        const credentialGeneration = normalizedPurpose === SERVER_ENTRY_PURPOSE
            ? this.#serverEntryCredentialGeneration
            : null;

        if (!Array.isArray(blindedTokens) || blindedTokens.length === 0) {
            throw new Error('Invalid blinded tokens');
        }

        if (blindedTokens.length > PP_CONFIG.MAX_BATCH_SIZE) {
            throw new Error(`Batch size exceeds limit of ${PP_CONFIG.MAX_BATCH_SIZE}`);
        }

        // sign with issuer key for this purpose
        if (!blindedTokens.every((token) => token instanceof Uint8Array && token.length === 32)) {
            throw new Error('Invalid blinded token');
        }

        const issuerEpoch = normalizeIssuanceEpoch(tokenEpoch);
        const keys = await this.#getKeysForPurpose(normalizedPurpose, issuerEpoch);
        this.#assertIssuanceGeneration(generation);
        if (
            credentialGeneration !== null &&
            credentialGeneration !== this.#serverEntryCredentialGeneration
        ) {
            const error = new Error('Server-entry token issuance cancelled by credential rotation');
            error.code = 'SERVER_ENTRY_ISSUANCE_CANCELLED';
            throw error;
        }
        let blindedTokenSlab = new Uint8Array(blindedTokens.length * 32);
        let secretKey = new Uint8Array(keys.secretKey);
        let publicKey = new Uint8Array(keys.publicKey);
        let evaluatedTokens = null;
        let proof = null;
        try {
            for (let index = 0; index < blindedTokens.length; index += 1) {
                blindedTokenSlab.set(blindedTokens[index], index * 32);
            }
            const evaluation = evaluatePrivacyPassBatch(
                blindedTokenSlab,
                blindedTokens.length,
                secretKey,
                publicKey,
                signal
            );
            blindedTokenSlab = null;
            secretKey = null;
            publicKey = null;
            ({ evaluatedTokens, proof } = await evaluation);
            this.#assertIssuanceGeneration(generation);
            if (
                credentialGeneration !== null &&
                credentialGeneration !== this.#serverEntryCredentialGeneration
            ) {
                const error = new Error('Server-entry token issuance cancelled by credential rotation');
                error.code = 'SERVER_ENTRY_ISSUANCE_CANCELLED';
                throw error;
            }

            const signedBlindedTokens = new Array(blindedTokens.length);
            for (let index = 0; index < signedBlindedTokens.length; index += 1) {
                signedBlindedTokens[index] = evaluatedTokens.subarray(index * 32, (index + 1) * 32);
            }
            return {
                signedBlindedTokens,
                proof,
                publicKey: keys.publicKey,
                issuerEpoch,
            };
        } catch (error) {
            evaluatedTokens?.fill(0);
            proof?.fill(0);
            throw error;
        } finally {
            blindedTokenSlab?.fill(0);
            secretKey?.fill(0);
            publicKey?.fill(0);
        }
    }

    static async issueAccountAuthTokenBatch(blindedTokens, tokenEpoch, signal) {
        return this.issueTokenBatch(blindedTokens, ACCOUNT_AUTH_PURPOSE, tokenEpoch, signal);
    }

    static async redeemToken(token, nullifier, mac, tokenSecret, expectedPurpose = ACCOUNT_AUTH_PURPOSE) {
        if (!this.#initialized) {
            throw new Error('PrivacyPass server not initialized');
        }
        const lifecycleGeneration = this.#lifecycleGeneration;
        const normalizedPurpose = normalizePurpose(expectedPurpose);
        const credentialGeneration = normalizedPurpose === SERVER_ENTRY_PURPOSE
            ? this.#serverEntryCredentialGeneration
            : null;

        if (
            !await this.#isRedemptionValid(token, nullifier, mac, tokenSecret, normalizedPurpose) ||
            !this.#initialized ||
            lifecycleGeneration !== this.#lifecycleGeneration
        ) {
            return this.#uniformFailureResponse();
        }
        if (
            credentialGeneration !== null &&
            credentialGeneration !== this.#serverEntryCredentialGeneration
        ) {
            return this.#uniformFailureResponse();
        }

        const tokenEpoch = readTokenEpoch(tokenSecret);
        const consumed = await this.#nullifierStore.markUsed(nullifier, tokenEpoch);
        if (
            !consumed ||
            !this.#initialized ||
            lifecycleGeneration !== this.#lifecycleGeneration ||
            (credentialGeneration !== null &&
                credentialGeneration !== this.#serverEntryCredentialGeneration)
        ) {
            return this.#uniformFailureResponse();
        }

        return {
            valid: true,
            ...(credentialGeneration === null
                ? {}
                : { serverEntryCredentialGeneration: credentialGeneration })
        };
    }

    /**
     * Verify and consume purpose proofs
     */
    static async redeemTokenBatch(redemptions) {
        if (!this.#initialized) {
            throw new Error('PrivacyPass server not initialized');
        }
        const lifecycleGeneration = this.#lifecycleGeneration;
        if (!Array.isArray(redemptions) || redemptions.length < 1 || redemptions.length > 4) {
            return this.#uniformFailureResponse();
        }
        const credentialGeneration = redemptions.some((redemption) => (
            typeof redemption?.expectedPurpose === 'string' &&
            redemption.expectedPurpose.trim().toLowerCase() === SERVER_ENTRY_PURPOSE
        )) ? this.#serverEntryCredentialGeneration : null;

        const nullifiers = await Promise.all(redemptions.map(async (redemption) => {
            if (!redemption || typeof redemption !== 'object') return null;
            try {
                const valid = await this.#isRedemptionValid(
                    redemption.token,
                    redemption.nullifier,
                    redemption.mac,
                    redemption.tokenSecret,
                    redemption.expectedPurpose
                );
                if (!valid) return null;
                return {
                    nullifier: redemption.nullifier,
                    tokenEpoch: readTokenEpoch(redemption.tokenSecret),
                };
            } catch {
                return null;
            }
        }));
        if (nullifiers.some((entry) => entry === null)) {
            return this.#uniformFailureResponse();
        }
        if (
            !this.#initialized ||
            lifecycleGeneration !== this.#lifecycleGeneration ||
            credentialGeneration !== null &&
            credentialGeneration !== this.#serverEntryCredentialGeneration
        ) {
            return this.#uniformFailureResponse();
        }

        const consumed = await this.#nullifierStore.markUsedBatch(nullifiers);
        return consumed &&
            this.#initialized &&
            lifecycleGeneration === this.#lifecycleGeneration && (
            credentialGeneration === null ||
            credentialGeneration === this.#serverEntryCredentialGeneration
        ) ? {
                valid: true,
                ...(credentialGeneration === null
                    ? {}
                    : { serverEntryCredentialGeneration: credentialGeneration })
            } : this.#uniformFailureResponse();
    }

    static async #isRedemptionValid(token, nullifier, mac, tokenSecret, expectedPurpose) {
        if (
            !token || token.length !== PP_CONFIG.TOKEN_SIZE ||
            !tokenSecret || tokenSecret.length !== PP_CONFIG.TOKEN_SECRET_SIZE ||
            !nullifier || nullifier.length !== PP_CONFIG.NULLIFIER_SIZE ||
            !mac || mac.length !== PP_CONFIG.MAC_SIZE
        ) {
            return false;
        }

        const tokenEpoch = readTokenEpoch(tokenSecret);
        const currentEpoch = currentTokenEpoch();
        if (tokenEpoch > currentEpoch || currentEpoch - tokenEpoch > PP_CONFIG.TOKEN_MAX_AGE_EPOCHS) {
            return false;
        }

        const purposeKeys = await this.#getKeysForPurpose(expectedPurpose, tokenEpoch);
        const tokenMatches = this.#verifyIssuedToken(token, tokenSecret, expectedPurpose, purposeKeys.secretKey);

        const expectedNullifier = this.#computeNullifier(token);
        let nullifierMatches;
        try {
            nullifierMatches = crypto.timingSafeEqual(nullifier, expectedNullifier);
        } finally {
            expectedNullifier.fill(0);
        }
        const expectedMac = this.#computeRedemptionMac(token, nullifier);
        let macMatches;
        try {
            macMatches = crypto.timingSafeEqual(mac, expectedMac);
        } finally {
            expectedMac.fill(0);
        }
        return tokenMatches && nullifierMatches && macMatches;
    }

    /**
     * Verify token was signed with our VOPRF key
     */
    static #verifyIssuedToken(token, tokenSecret, purpose, secretKey) {
        let oprfInput;
        let expectedToken;
        try {
            if (!token || token.length !== PP_CONFIG.TOKEN_SIZE || !tokenSecret || tokenSecret.length !== PP_CONFIG.TOKEN_SECRET_SIZE) {
                return false;
            }

            const label = `${PP_LABELS.OPRF_INPUT}:${normalizePurpose(purpose)}`;
            oprfInput = hkdf(
                blake3,
                tokenSecret,
                new Uint8Array(0),
                UTF8_ENCODER.encode(label),
                32
            );
            expectedToken = oprf.voprf.evaluate(secretKey, oprfInput);
            return crypto.timingSafeEqual(token, expectedToken);
        } catch {
            return false;
        } finally {
            oprfInput?.fill(0);
            expectedToken?.fill(0);
        }
    }

    /**
     * Generate uniform failure response
     */
    static #uniformFailureResponse() {
        return { valid: false };
    }

    /**
     * Compute nullifier from token
     */
    static #computeNullifier(token) {
        return hkdf(
            blake3,
            token,
            new Uint8Array(0),
            UTF8_ENCODER.encode(PP_LABELS.NULLIFIER),
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
            UTF8_ENCODER.encode(PP_LABELS.REDEMPTION_MAC),
            32
        );
        try {
            return blake3(key, { dkLen: PP_CONFIG.MAC_SIZE });
        } finally {
            key.fill(0);
        }
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
     * Mark nullifier as used
     */
    async markUsed(nullifier, tokenEpoch) {
        const nullifierHex = this.#hashNullifier(nullifier);
        const expiresEpoch = this.#expirationEpoch(tokenEpoch);
        const result = await this.#db.query(
            `INSERT INTO nullifiers (nullifier_hash, expires_epoch)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING`,
            [nullifierHex, expiresEpoch]
        );
        return (result?.rowCount ?? 0) > 0;
    }

    async markUsedBatch(entries) {
        if (!Array.isArray(entries) || entries.length < 1 || entries.length > 4) {
            return false;
        }
        const nullifierHashes = entries.map(({ nullifier }) => this.#hashNullifier(nullifier));
        const expirationEpochs = entries.map(({ tokenEpoch }) => this.#expirationEpoch(tokenEpoch));
        const client = await this.#db.connect();
        try {
            return await withTransaction(client, async ({ rollback }) => {
                const result = await client.query(
                    `INSERT INTO nullifiers (nullifier_hash, expires_epoch)
                 SELECT hash, expires_epoch
                 FROM unnest($1::text[], $2::integer[]) AS supplied(hash, expires_epoch)
                 ON CONFLICT DO NOTHING`,
                    [nullifierHashes, expirationEpochs]
                );
                if ((result?.rowCount ?? 0) !== nullifierHashes.length) return rollback(false);
                return true;
            });
        } finally {
            client.release();
        }
    }

    #hashNullifier(nullifier) {
        const nullifierKey = deriveAuthRootKey(PROTOCOL_KEYS.PRIVACY_PASS_NULLIFIER_DB_ROOT);
        let digest = null;
        try {
            digest = blake3(nullifier, { key: nullifierKey, dkLen: HASH_OUTPUT_BYTES });
            return Buffer.from(
                digest.buffer,
                digest.byteOffset,
                digest.byteLength
            ).toString('hex');
        } finally {
            digest?.fill(0);
            nullifierKey.fill(0);
        }
    }

    #expirationEpoch(tokenEpoch) {
        const current = currentTokenEpoch();
        if (
            !Number.isSafeInteger(tokenEpoch) ||
            tokenEpoch < 0 ||
            tokenEpoch > current ||
            current - tokenEpoch > PP_CONFIG.TOKEN_MAX_AGE_EPOCHS
        ) {
            throw new Error('Invalid Privacy Pass nullifier epoch');
        }
        return tokenEpoch + PP_CONFIG.TOKEN_MAX_AGE_EPOCHS;
    }

    /**
     * Cleanup old nullifiers
     */
    async cleanup() {
        await this.#db.query(
            'DELETE FROM nullifiers WHERE expires_epoch < $1',
            [currentTokenEpoch()]
        );
    }
}

/**
 * Privacy Pass Client Helpers
 */
export const PrivacyPassHelpers = {
    /**
     * Parse token redemption request
     */
    parseRedemptionRequest(data) {
        let token = null;
        let nullifier = null;
        let mac = null;
        let tokenSecret = null;
        try {
            token = decodeCanonicalBase64(data?.token, PP_CONFIG.TOKEN_SIZE, 128);
            nullifier = decodeCanonicalBase64(data?.nullifier, PP_CONFIG.NULLIFIER_SIZE, 64);
            mac = decodeCanonicalBase64(data?.mac, PP_CONFIG.MAC_SIZE, 64);
            tokenSecret = decodeCanonicalBase64(data?.tokenSecret, PP_CONFIG.TOKEN_SECRET_SIZE, 64);
            return { token, nullifier, mac, tokenSecret };
        } catch (error) {
            token?.fill(0);
            nullifier?.fill(0);
            mac?.fill(0);
            tokenSecret?.fill(0);
            throw error;
        }
    },

    /**
     * Format response for client
     */
    formatResponse(response) {
        if (!response) return null;
        const formatted = {};
        for (const [key, value] of Object.entries(response)) {
            if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
                formatted[key] = encodeBase64AndWipeCopy(value);
            } else if (Array.isArray(value)) {
                formatted[key] = value.map(v =>
                    v instanceof Uint8Array || Buffer.isBuffer(v)
                        ? encodeBase64AndWipeCopy(v)
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
