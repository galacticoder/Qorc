/**
 * OPAQUE Protocol Client
 */

import { Base64 } from './base64';
import { PostQuantumWorker } from './worker-bridge';
import { computeBlindUserId } from '../utils/auth-utils';
import {
    PRIVATE_AUTH_ANONYMITY_SET_SIZE,
    PRIVATE_AUTH_PIR_RECORD_BYTES,
    PRIVATE_AUTH_PIR_RECORD_MAGIC
} from '../../../shared/private-auth-protocol.js';

// OPAQUE configuration
const OPAQUE_CONFIG = {
    PRIVATE_AUTH_ANONYMITY_SET_SIZE,
};

/**
 * OPAQUE Client
 */
export class OPAQUEClient {
    private blindingFactor: Uint8Array | null = null;
    private generation = 0;

    private wipeState(): void {
        this.blindingFactor?.fill(0);
        this.blindingFactor = null;
    }

    /**
     * Start registration
     */
    async startRegistration(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
    }> {
        this.wipeState();
        const generation = ++this.generation;
        const result = await PostQuantumWorker.opaqueStartRegistration(password);
        if (generation !== this.generation) {
            result.blindingFactor.fill(0);
            result.blindedElement.fill(0);
            throw new Error('Registration operation was cancelled');
        }
        this.blindingFactor = result.blindingFactor;
        return {
            blindedElement: result.blindedElement,
        };
    }

    /**
     * Finish registration
     */
    async finishRegistration(
        password: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverNonce: Uint8Array;
        }
    ): Promise<{
        envelope: Uint8Array;
        exportKey: Uint8Array;
        authPublicKey: Uint8Array;
    }> {
        const blindingFactor = this.blindingFactor;
        if (!blindingFactor) {
            throw new Error('Registration not started');
        }
        this.blindingFactor = null;
        const generation = this.generation;

        try {
            const result = await PostQuantumWorker.opaqueFinishRegistration(password, blindingFactor, serverResponse);
            if (generation !== this.generation) {
                result.envelope.fill(0);
                result.exportKey.fill(0);
                result.authPublicKey.fill(0);
                throw new Error('Registration operation was cancelled');
            }
            return result;
        } finally {
            blindingFactor.fill(0);
        }
    }

    /**
     * Start login
     */
    async startLogin(password: Uint8Array): Promise<{
        blindedElement: Uint8Array;
    }> {
        this.wipeState();
        const generation = ++this.generation;
        const result = await PostQuantumWorker.opaqueStartLogin(password);
        if (generation !== this.generation) {
            result.blindingFactor.fill(0);
            result.blindedElement.fill(0);
            throw new Error('Login operation was cancelled');
        }
        this.blindingFactor = result.blindingFactor;

        return {
            blindedElement: result.blindedElement,
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
            serverNonce: Uint8Array;
            salt: Uint8Array;
        },
        authChannelBinding: Uint8Array
    ): Promise<{
        success: boolean;
        exportKey?: Uint8Array;
        authMessage?: Uint8Array;
        error?: string;
    }> {
        const blindingFactor = this.blindingFactor;
        if (!blindingFactor) {
            throw new Error('Login not started');
        }
        this.blindingFactor = null;
        const generation = this.generation;

        try {
            const result = await PostQuantumWorker.opaqueFinishLogin(
                password,
                blindingFactor,
                serverResponse,
                authChannelBinding
            );
            if (generation !== this.generation) {
                result.exportKey?.fill(0);
                result.authMessage?.fill(0);
                throw new Error('Login operation was cancelled');
            }
            return {
                success: result.success,
                exportKey: result.exportKey,
                authMessage: result.authMessage,
                error: result.error
            };
        } finally {
            blindingFactor.fill(0);
        }
    }

    /**
     * Clear all sensitive state
     */
    clear(): void {
        this.generation += 1;
        this.wipeState();
    }
}

/**
 * Helper functions for encoding/decoding
 */
export const OPAQUEClientHelpers = {
    decodePrivateAuthPirRecord(record: Uint8Array): {
        envelope: Uint8Array;
        salt: Uint8Array;
    } {
        const magic = new TextEncoder().encode(PRIVATE_AUTH_PIR_RECORD_MAGIC);
        if (record.length !== PRIVATE_AUTH_PIR_RECORD_BYTES) {
            throw new Error('Invalid private-auth record');
        }
        let validMagic = magic.length === 8;
        for (let index = 0; index < magic.length; index += 1) {
            validMagic = validMagic && record[index] === magic[index];
        }
        magic.fill(0);
        if (!validMagic) throw new Error('Incorrect username, password, or passphrase.');
        const envelopeStart = PRIVATE_AUTH_PIR_RECORD_MAGIC.length;
        const envelope = record.slice(envelopeStart, envelopeStart + 72);
        const salt = record.slice(envelopeStart + 72, envelopeStart + 72 + 32);
        return { envelope, salt };
    },

    // Compute a blinded user ID from a username
    computeBlindUserId(username: string): string {
        return computeBlindUserId(username);
    },

    // Encode request for sending to server
    encodeRequest(data: Record<string, Uint8Array | string | number>): Record<string, string | number> {
        const encoded: Record<string, string | number> = {};
        for (const [key, value] of Object.entries(data)) {
            if (value instanceof Uint8Array) {
                encoded[key] = Base64.arrayBufferToBase64(value);
            } else if (typeof value === 'string' || typeof value === 'number') {
                encoded[key] = value;
            }
        }
        return encoded;
    },

    // Decode response from server
    decodeResponse<T extends Record<string, unknown>>(
        data: Record<string, string | number>,
        uint8Fields: Record<string, number>
    ): T {
        const decoded: Record<string, unknown> = {};
        const decodedBytes: Uint8Array[] = [];
        try {
            for (const [key, value] of Object.entries(data)) {
                const expectedLength = uint8Fields[key];
                if (expectedLength !== undefined) {
                    if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
                        throw new Error(`Invalid ${key} encoding`);
                    }
                    const bytes = Base64.base64ToUint8Array(value);
                    if (bytes.length !== expectedLength || Base64.arrayBufferToBase64(bytes) !== value) {
                        bytes.fill(0);
                        throw new Error(`Invalid ${key} encoding`);
                    }
                    decoded[key] = bytes;
                    decodedBytes.push(bytes);
                } else {
                    decoded[key] = value;
                }
            }
            for (const requiredField of Object.keys(uint8Fields)) {
                if (!(decoded[requiredField] instanceof Uint8Array)) {
                    throw new Error(`Missing ${requiredField}`);
                }
            }
            return decoded as T;
        } catch (error) {
            for (const bytes of decodedBytes) bytes.fill(0);
            throw error;
        }
    },
};

export { OPAQUE_CONFIG };
