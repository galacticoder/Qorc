/**
 * OPAQUE Protocol Client
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { Base64 } from './base64';
import { PostQuantumWorker } from './worker-bridge';
import { computeBlindUserId } from '../utils/auth-utils';

// OPAQUE configuration
const OPAQUE_CONFIG = {
    NONCE_SIZE: 24,
    AUTH_TAG_SIZE: 16,
    EXPORT_KEY_SIZE: 32,
    SESSION_KEY_SIZE: 32,
    ENVELOPE_NONCE_SIZE: 24,
};

// Domain separation labels
const LABELS = {
    OPRF_INPUT: 'OPAQUE-OPRF-Input-v1',
    ENVELOPE_KEY: 'OPAQUE-Envelope-Key-v1',
    EXPORT_KEY: 'OPAQUE-Export-Key-v1',
    SESSION_KEY: 'OPAQUE-Session-Key-v1',
    AUTH_KEY: 'OPAQUE-Auth-Key-v1',
    CLIENT_SECRET: 'OPAQUE-Client-Secret-v1',
};

/**
 * OPAQUE Client
 * 
 * Handles password blinding, envelope creation/decryption, and session key derivation
 */
export class OPAQUEClient {
    private blindingFactor: Uint8Array | null = null;
    private clientSecretKey: Uint8Array | null = null;
    private clientPublicKey: Uint8Array | null = null;

    /**
     * Start registration
     */
    async startRegistration(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
        clientPublicKey: Uint8Array;
    }> {
        try {
            const result = await PostQuantumWorker.opaqueStartRegistration(password);
            this.blindingFactor = result.blindingFactor;
            this.clientSecretKey = result.clientSecretKey;
            this.clientPublicKey = result.clientPublicKey;

            return {
                blindedElement: result.blindedElement,
                clientPublicKey: result.clientPublicKey,
            };
        } catch (err) {
            console.warn('[OPAQUEClient] Worker startRegistration failed, falling back to local', err);
            return this.startRegistrationLocal(password);
        }
    }

    async startRegistrationLocal(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
        clientPublicKey: Uint8Array;
        blindingFactor: Uint8Array;
        clientSecretKey: Uint8Array;
    }> {
        // Derive OPRF input from password bytes
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            new TextEncoder().encode(LABELS.OPRF_INPUT),
            32
        );

        // Blind the OPRF input
        const blindResult = oprf.oprf.blind(oprfInput);
        this.blindingFactor = blindResult.blind;

        // Generate client keypair
        this.clientSecretKey = randomBytes(32);
        this.clientPublicKey = blake3(this.clientSecretKey, { dkLen: 32 });

        return {
            blindedElement: blindResult.blinded,
            clientPublicKey: this.clientPublicKey,
            blindingFactor: this.blindingFactor,
            clientSecretKey: this.clientSecretKey
        };
    }

    /**
     * Finish registration
     */
    async finishRegistration(
        password: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverPublicKey: Uint8Array;
            serverNonce: Uint8Array;
        }
    ): Promise<{
        envelope: Uint8Array;
        exportKey: Uint8Array;
        maskedResponse: Uint8Array;
    }> {
        if (!this.blindingFactor || !this.clientSecretKey) {
            throw new Error('Registration not started');
        }

        try {
            const result = await PostQuantumWorker.opaqueFinishRegistration(
                password,
                this.blindingFactor,
                this.clientSecretKey,
                serverResponse
            );

            this.blindingFactor = null;
            return result;
        } catch (err) {
            console.warn('[OPAQUEClient] Worker finishRegistration failed, falling back to local', err);
            return this.finishRegistrationLocal(password, serverResponse);
        }
    }

    async finishRegistrationLocal(
        password: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverPublicKey: Uint8Array;
            serverNonce: Uint8Array;
        },
        providedBlindingFactor?: Uint8Array,
        providedClientSecretKey?: Uint8Array
    ): Promise<{
        envelope: Uint8Array;
        exportKey: Uint8Array;
        maskedResponse: Uint8Array;
    }> {
        const blindingFactor = providedBlindingFactor || this.blindingFactor;
        const clientSecretKey = providedClientSecretKey || this.clientSecretKey;

        if (!blindingFactor || !clientSecretKey) {
            throw new Error('Registration not started');
        }

        // Derive OPRF input from password bytes
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            new TextEncoder().encode(LABELS.OPRF_INPUT),
            32
        );

        // Finalize OPRF
        const oprfOutput = oprf.oprf.finalize(
            oprfInput,
            blindingFactor,
            serverResponse.evaluatedElement
        );

        // Derive envelope key from OPRF output
        const envelopeKey = hkdf(
            blake3,
            oprfOutput,
            serverResponse.serverNonce,
            new TextEncoder().encode(LABELS.ENVELOPE_KEY),
            32
        );

        // Create envelope contents
        const envelopeContents = new Uint8Array([
            ...clientSecretKey,
            ...serverResponse.serverPublicKey,
        ]);

        // Encrypt envelope
        const envelopeNonce = randomBytes(OPAQUE_CONFIG.ENVELOPE_NONCE_SIZE);
        const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
        const encryptedEnvelope = cipher.encrypt(envelopeContents);

        const envelope = new Uint8Array([...envelopeNonce, ...encryptedEnvelope]);

        // Derive export key
        const exportKey = hkdf(
            blake3,
            oprfOutput,
            new Uint8Array(0),
            new TextEncoder().encode(LABELS.EXPORT_KEY),
            OPAQUE_CONFIG.EXPORT_KEY_SIZE
        );

        // Create masked response for server storage
        const maskedResponse = await this.createMaskedResponse(
            clientSecretKey,
            serverResponse.serverPublicKey
        );

        if (!providedBlindingFactor) this.blindingFactor = null;
        return { envelope, exportKey, maskedResponse };
    }

    /**
     * Start login
     */
    async startLogin(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
    }> {
        try {
            const result = await PostQuantumWorker.opaqueStartLogin(password);
            this.blindingFactor = result.blindingFactor;

            return {
                blindedElement: result.blindedElement,
            };
        } catch (err) {
            console.warn('[OPAQUEClient] Worker startLogin failed, falling back to local', err);
            return this.startLoginLocal(password);
        }
    }

    async startLoginLocal(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
        blindingFactor: Uint8Array;
    }> {
        // Derive OPRF input from password bytes
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            new TextEncoder().encode(LABELS.OPRF_INPUT),
            32
        );

        // Blind the OPRF input
        const blindResult = oprf.oprf.blind(oprfInput);
        this.blindingFactor = blindResult.blind;

        return {
            blindedElement: blindResult.blinded,
            blindingFactor: this.blindingFactor
        };
    }

    /**
     * Finish login
     */
    async finishLogin(
        password: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            envelope: Uint8Array;
            maskedResponse: Uint8Array;
            serverNonce: Uint8Array;
            salt?: Uint8Array;
        }
    ): Promise<{
        success: boolean;
        sessionKey?: Uint8Array;
        exportKey?: Uint8Array;
        authMessage?: Uint8Array;
    }> {
        if (!this.blindingFactor) {
            throw new Error('Login not started');
        }

        try {
            const result = await PostQuantumWorker.opaqueFinishLogin(
                password,
                this.blindingFactor,
                serverResponse
            );

            if (result.success && result.clientSecretKey) {
                this.clientSecretKey = result.clientSecretKey;
            }

            this.blindingFactor = null;
            return {
                success: result.success,
                sessionKey: result.sessionKey,
                exportKey: result.exportKey,
                authMessage: result.authMessage
            };
        } catch (err) {
            console.warn('[OPAQUEClient] Worker finishLogin failed, falling back to local', err);
            return this.finishLoginLocal(password, serverResponse);
        }
    }

    async finishLoginLocal(
        password: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            envelope: Uint8Array;
            maskedResponse: Uint8Array;
            serverNonce: Uint8Array;
            salt?: Uint8Array;
        },
        providedBlindingFactor?: Uint8Array
    ): Promise<{
        success: boolean;
        sessionKey?: Uint8Array;
        exportKey?: Uint8Array;
        authMessage?: Uint8Array;
        clientSecretKey?: Uint8Array;
    }> {
        const blindingFactor = providedBlindingFactor || this.blindingFactor;
        if (!blindingFactor) {
            throw new Error('Login not started');
        }

        try {
            // Derive OPRF input from password bytes
            const oprfInput = hkdf(
                blake3,
                password,
                new Uint8Array(0),
                new TextEncoder().encode(LABELS.OPRF_INPUT),
                32
            );

            // Finalize OPRF
            const oprfOutput = oprf.oprf.finalize(
                oprfInput,
                blindingFactor,
                serverResponse.evaluatedElement
            );

            // Derive envelope key
            const salt = serverResponse.salt;
            const envelopeKey = hkdf(
                blake3,
                oprfOutput,
                salt,
                new TextEncoder().encode(LABELS.ENVELOPE_KEY),
                32
            );

            // Try to decrypt envelope
            const envelopeNonce = serverResponse.envelope.slice(0, OPAQUE_CONFIG.ENVELOPE_NONCE_SIZE);
            const encryptedEnvelope = serverResponse.envelope.slice(OPAQUE_CONFIG.ENVELOPE_NONCE_SIZE);

            const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
            const envelopeContents = cipher.decrypt(encryptedEnvelope);

            // Extract credentials
            const clientSecretKey = envelopeContents.slice(0, 32);
            if (!providedBlindingFactor) this.clientSecretKey = clientSecretKey;
            const serverPublicKey = envelopeContents.slice(32, 64);

            // Re-derive maskedResponse to use as shared secret for auth MAC
            const maskedKey = hkdf(
                blake3,
                clientSecretKey,
                serverPublicKey,
                new TextEncoder().encode('OPAQUE-MaskedResponse-v1'),
                32
            );
            const recoveredMaskedResponse = blake3(maskedKey, { dkLen: 64 });

            // Derive session key
            const sessionKey = hkdf(
                blake3,
                oprfOutput,
                serverResponse.serverNonce,
                new TextEncoder().encode(LABELS.SESSION_KEY),
                OPAQUE_CONFIG.SESSION_KEY_SIZE
            );

            // Derive export key
            const exportKey = hkdf(
                blake3,
                oprfOutput,
                new Uint8Array(0),
                new TextEncoder().encode(LABELS.EXPORT_KEY),
                OPAQUE_CONFIG.EXPORT_KEY_SIZE
            );

            // Generate auth message for server using maskedResponse as shared secret
            const authKey = hkdf(
                blake3,
                recoveredMaskedResponse,
                serverResponse.serverNonce,
                new TextEncoder().encode(LABELS.AUTH_KEY),
                32
            );

            const authMessage = blake3(authKey, { dkLen: 32 });

            // Clear blinding factor
            if (!providedBlindingFactor) this.blindingFactor = null;

            return {
                success: true,
                sessionKey,
                exportKey,
                authMessage,
                clientSecretKey
            };
        } catch (error) {
            console.error('[OPAQUE] Login failed during crypto operations:', error);
            if (!providedBlindingFactor) this.blindingFactor = null;
            return { success: false };
        }
    }

    /**
     * Create masked response for server to store
     */
    private async createMaskedResponse(
        clientSecretKey: Uint8Array,
        serverPublicKey: Uint8Array
    ): Promise<Uint8Array> {
        const key = hkdf(
            blake3,
            clientSecretKey,
            serverPublicKey,
            new TextEncoder().encode('OPAQUE-MaskedResponse-v1'),
            32
        );
        return blake3(key, { dkLen: 64 });
    }

    /**
     * Compute credential ID from OPRF output
     */
    computeCredentialId(oprfOutput: Uint8Array): Uint8Array {
        return hkdf(
            blake3,
            oprfOutput,
            new Uint8Array(0),
            new TextEncoder().encode('OPAQUE-CredentialId-v1'),
            32
        );
    }

    /**
     * Start OT Registration
     */
    async startOTRegistration(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
        clientPublicKey: Uint8Array;
        blindingFactor: Uint8Array;
        clientSecretKey: Uint8Array;
    }> {
        return this.startRegistrationLocal(password);
    }

    /**
     * Finish OT Registration
     */
    async finishOTRegistration(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        clientSecretKey: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverPublicKey: Uint8Array;
            serverNonce: Uint8Array;
        }
    ): Promise<{
        envelope: Uint8Array;
        exportKey: Uint8Array;
        maskedResponse: Uint8Array;
        credentialId: Uint8Array;
    }> {
        // Derive OPRF input from password bytes
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            new TextEncoder().encode(LABELS.OPRF_INPUT),
            32
        );

        // Finalize OPRF
        const oprfOutput = oprf.oprf.finalize(
            oprfInput,
            blindingFactor,
            serverResponse.evaluatedElement
        );

        // Compute credential ID from OPRF output
        const credentialId = this.computeCredentialId(oprfOutput);

        // Derive envelope key from OPRF output
        const envelopeKey = hkdf(
            blake3,
            oprfOutput,
            serverResponse.serverNonce,
            new TextEncoder().encode(LABELS.ENVELOPE_KEY),
            32
        );

        // Create envelope contents
        const envelopeContents = new Uint8Array([
            ...clientSecretKey,
            ...serverResponse.serverPublicKey,
        ]);

        // Encrypt envelope
        const envelopeNonce = randomBytes(OPAQUE_CONFIG.ENVELOPE_NONCE_SIZE);
        const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
        const encryptedEnvelope = cipher.encrypt(envelopeContents);

        const envelope = new Uint8Array([...envelopeNonce, ...encryptedEnvelope]);

        // Derive export key
        const exportKey = hkdf(
            blake3,
            oprfOutput,
            new Uint8Array(0),
            new TextEncoder().encode(LABELS.EXPORT_KEY),
            OPAQUE_CONFIG.EXPORT_KEY_SIZE
        );

        // Create masked response for server storage
        const maskedResponse = await this.createMaskedResponse(
            clientSecretKey,
            serverResponse.serverPublicKey
        );

        return { envelope, exportKey, maskedResponse, credentialId };
    }

    /**
     * Start OT Login
     */
    async startOTLogin(password: Uint8Array, shardSize: number, myIndex: number): Promise<{
        pubKeys: Uint8Array[];
        blindedElement: Uint8Array;
    }> {
        try {
            const { pubKeys, blindedElement, blindingFactor, myPrivKey } = await PostQuantumWorker.opaqueStartOTLogin(password, shardSize, myIndex);

            (this as any).otState = { myIndex, myPrivKey, blindingFactor };

            return { pubKeys, blindedElement };
        } catch (err) {
            console.warn('[OPAQUEClient] Worker startOTLogin failed, falling back to local', err);
            return this.startOTLoginLocalFallback(password, shardSize, myIndex);
        }
    }

    async startOTLoginLocalFallback(password: Uint8Array, shardSize: number, myIndex: number): Promise<{
        pubKeys: Uint8Array[];
        blindedElement: Uint8Array;
        blindingFactor: Uint8Array;
        myPrivKey: Uint8Array;
    }> {
        const { OPAQUEOps } = await import('./crypto-ops');
        const result = OPAQUEOps.startOTLogin(password, shardSize, myIndex);

        (this as any).otState = {
            myIndex,
            myPrivKey: result.myPrivKey,
            blindingFactor: result.blindingFactor
        };

        return {
            pubKeys: result.pubKeys,
            blindedElement: result.blindedElement,
            blindingFactor: result.blindingFactor,
            myPrivKey: result.myPrivKey!
        };
    }

    /**
     * Finish OT Login
     */
    async finishOTLogin(
        password: Uint8Array,
        otRecords: any[],
        evaluatedElement: Uint8Array,
        serverNonce?: Uint8Array
    ): Promise<any> {
        const { myIndex, myPrivKey, blindingFactor } = (this as any).otState;

        const normalizedRecords = otRecords.map(r => ({
            ct: typeof r.ct === 'string' ? Base64.base64ToUint8Array(r.ct) : r.ct,
            masked: typeof r.masked === 'string' ? Base64.base64ToUint8Array(r.masked) : r.masked
        }));

        const nonce = serverNonce || randomBytes(32);

        try {
            const result = await PostQuantumWorker.opaqueFinishOTLogin(
                password,
                blindingFactor,
                myPrivKey,
                normalizedRecords,
                myIndex,
                evaluatedElement,
                nonce
            );

            (this as any).otState = null;
            return result;
        } catch (err) {
            console.warn('[OPAQUEClient] Worker finishOTLogin failed, falling back to local', err);
            return this.finishOTLoginLocalFallback(password, blindingFactor, myPrivKey, normalizedRecords, myIndex, evaluatedElement, nonce);
        }
    }

    async finishOTLoginLocalFallback(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        myPrivKey: Uint8Array,
        otRecords: { ct: Uint8Array; masked: Uint8Array }[],
        myIndex: number,
        evaluatedElement: Uint8Array,
        serverNonce: Uint8Array
    ): Promise<any> {
        const { OPAQUEOps } = await import('./crypto-ops');
        const result = OPAQUEOps.finishOTLogin(
            password,
            blindingFactor,
            myPrivKey,
            otRecords,
            myIndex,
            evaluatedElement,
            serverNonce
        );

        (this as any).otState = null;
        return result;
    }

    /**
     * Clear all sensitive state
     */
    clear(): void {
        if (this.blindingFactor) {
            this.blindingFactor.fill(0);
            this.blindingFactor = null;
        }
        if (this.clientSecretKey) {
            this.clientSecretKey.fill(0);
            this.clientSecretKey = null;
        }
        this.clientPublicKey = null;
        (this as any).otState = null;
    }
}

/**
 * Helper functions for encoding/decoding
 */
export const OPAQUEClientHelpers = {
    /**
     * Compute a blinded user ID from a username
     */
    computeBlindUserId(username: string): string {
        return computeBlindUserId(username);
    },

    /**
     * Encode request for sending to server
     */
    encodeRequest(data: Record<string, Uint8Array | string | number>): Record<string, string | number> {
        const encoded: Record<string, string | number> = {};
        for (const [key, value] of Object.entries(data)) {
            if (value !== null && (value instanceof Uint8Array || (typeof value === 'object' && 'buffer' in (value as any)))) {
                encoded[key] = Base64.arrayBufferToBase64(value as Uint8Array);
            } else if (typeof value === 'string' || typeof value === 'number') {
                encoded[key] = value;
            }
        }
        return encoded;
    },

    /**
     * Decode response from server
     */
    decodeResponse<T extends Record<string, unknown>>(
        data: Record<string, string | number>,
        uint8Fields: string[]
    ): T {
        const decoded: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(data)) {
            if (uint8Fields.includes(key) && typeof value === 'string' && value.length > 0) {
                decoded[key] = Base64.base64ToUint8Array(value);
            } else {
                decoded[key] = value;
            }
        }
        return decoded as T;
    },
};

export { OPAQUE_CONFIG, LABELS };
