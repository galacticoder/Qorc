/**
 * Privacy Pass Client
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { Base64, decodeCanonicalBase64 } from './base64';
import { PostQuantumWorker } from './worker-bridge';
import { normalizePrivacyPassPurpose } from './privacy-pass-purpose';
import { PRIVACY_PASS_CONFIG as PP_CONFIG } from '../../../shared/privacy-pass-protocol.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

export function getPrivacyPassTokenEpoch(tokenSecret: Uint8Array): number {
    if (!(tokenSecret instanceof Uint8Array) || tokenSecret.length !== PP_CONFIG.TOKEN_SECRET_SIZE) {
        throw new Error('Invalid Privacy Pass token secret');
    }
    return new DataView(
        tokenSecret.buffer,
        tokenSecret.byteOffset,
        tokenSecret.byteLength
    ).getUint32(0, false);
}

export function getPrivacyPassBatchEpoch(tokens: ReadonlyArray<{ tokenSecret: Uint8Array }>): number {
    if (!Array.isArray(tokens) || tokens.length < 1 || tokens.length > PP_CONFIG.MAX_BATCH_SIZE) {
        throw new Error('Invalid Privacy Pass token batch');
    }
    const epoch = getPrivacyPassTokenEpoch(tokens[0].tokenSecret);
    if (!tokens.every((token) => getPrivacyPassTokenEpoch(token.tokenSecret) === epoch)) {
        throw new Error('Privacy Pass token batch spans multiple epochs');
    }
    return epoch;
}

export function isPrivacyPassTokenEpochUsable(tokenSecret: Uint8Array): boolean {
    let tokenEpoch: number;
    try {
        tokenEpoch = getPrivacyPassTokenEpoch(tokenSecret);
    } catch {
        return false;
    }
    const currentEpoch = Math.floor(Date.now() / 86_400_000);
    return tokenEpoch <= currentEpoch && currentEpoch - tokenEpoch <= PP_CONFIG.TOKEN_MAX_AGE_EPOCHS;
}

export function isPrivacyPassTokenUsable(token: AnonymousToken, purpose: string): boolean {
    try {
        return Boolean(
            token &&
            !token.used &&
            token.unblindedToken?.length === PP_CONFIG.TOKEN_SIZE &&
            isPrivacyPassTokenEpochUsable(token.tokenSecret) &&
            normalizePrivacyPassPurpose(token.purpose) === normalizePrivacyPassPurpose(purpose)
        );
    } catch {
        return false;
    }
}

/**
 * Anonymous Token structure
 */
export interface AnonymousToken {
    id: string;
    tokenSecret: Uint8Array;
    blindingFactor?: Uint8Array;
    blindedElement?: Uint8Array;
    unblindedToken?: Uint8Array;
    purpose: string;
    issuedAt: number;
    used: boolean;
    pending: boolean;
}

/**
 * Privacy Pass Client
 * 
 * Manages the full lifecycle of anonymous authentication tokens
 */
export class PrivacyPassClient {
    private readonly purpose: string;

    constructor(purpose: string) {
        this.purpose = normalizePrivacyPassPurpose(purpose);
    }

    /**
     * Generate a batch of tokens to be signed by server
     */
    async generateTokenBatch(count: number): Promise<{
        blindedTokens: Uint8Array[];
        tokenSecrets: AnonymousToken[];
    }> {
        const result = await PostQuantumWorker.ppGenerateTokenBatch(count, this.purpose);
        return {
            blindedTokens: result.blindedTokens,
            tokenSecrets: result.tokenSecrets as AnonymousToken[]
        };
    }

    /**
     * Unblind server signed tokens
     */
    async unblindTokens(
        tokenSecrets: AnonymousToken[],
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array,
        issuerEpoch: number
    ): Promise<AnonymousToken[]> {
        if (!Number.isSafeInteger(issuerEpoch) || getPrivacyPassBatchEpoch(tokenSecrets) !== issuerEpoch) {
            throw new Error('Privacy Pass issuer epoch mismatch');
        }
        const result = await PostQuantumWorker.ppUnblindTokens(tokenSecrets, signedBlindedTokens, proof, serverPublicKey);
        return result.completedTokens as AnonymousToken[];
    }

    /**
     * Prepare a token for redemption
     */
    async prepareRedemption(token: AnonymousToken): Promise<{
        tokenSecret: Uint8Array;
        token: Uint8Array;
        nullifier: Uint8Array;
        mac: Uint8Array;
    }> {
        if (!token.unblindedToken) {
            throw new Error('Token not finalized');
        }

        if (token.used) {
            throw new Error('Token already used');
        }
        if (!isPrivacyPassTokenEpochUsable(token.tokenSecret)) {
            throw new Error('Token expired');
        }
        if (normalizePrivacyPassPurpose(token.purpose) !== this.purpose) {
            throw new Error('Token purpose mismatch');
        }

        let nullifier: Uint8Array | null = null;
        let macKey: Uint8Array | null = null;
        let mac: Uint8Array | null = null;
        try {
            nullifier = hkdf(
                blake3,
                token.unblindedToken,
                new Uint8Array(0),
                new TextEncoder().encode(PROTOCOL_KEYS.PRIVACY_PASS_NULLIFIER),
                PP_CONFIG.NULLIFIER_SIZE
            );

            macKey = hkdf(
                blake3,
                token.unblindedToken,
                nullifier,
                new TextEncoder().encode(PROTOCOL_KEYS.PRIVACY_PASS_REDEMPTION_MAC),
                32
            );
            mac = blake3(macKey, { dkLen: PP_CONFIG.MAC_SIZE });

            return {
                tokenSecret: token.tokenSecret,
                token: token.unblindedToken,
                nullifier,
                mac
            };
        } catch (error) {
            nullifier?.fill(0);
            mac?.fill(0);
            throw error;
        } finally {
            macKey?.fill(0);
        }
    }
}

function deserializeTokenObject(parsed: any): AnonymousToken {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid token record');
    if (Object.keys(parsed).sort().join(',') !== 'blindedElement,blindingFactor,id,issuedAt,pending,purpose,tokenSecret,unblindedToken,used') {
        throw new Error('Invalid token record shape');
    }
    if (typeof parsed.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(parsed.id)) {
        throw new Error('Invalid token ID');
    }
    if (!Number.isSafeInteger(parsed.issuedAt) || parsed.issuedAt <= 0) throw new Error('Invalid token timestamp');
    if (typeof parsed.used !== 'boolean' || typeof parsed.pending !== 'boolean') throw new Error('Invalid token state');

    let tokenSecret: Uint8Array | null = null;
    let blindingFactor: Uint8Array | undefined;
    let blindedElement: Uint8Array | undefined;
    let unblindedToken: Uint8Array | undefined;
    try {
        tokenSecret = decodeCanonicalBase64(parsed.tokenSecret, 'token encoding', { exactBytes: PP_CONFIG.TOKEN_SECRET_SIZE });
        blindingFactor = parsed.blindingFactor == null ? undefined : decodeCanonicalBase64(parsed.blindingFactor, 'token encoding', { exactBytes: 32 });
        blindedElement = parsed.blindedElement == null ? undefined : decodeCanonicalBase64(parsed.blindedElement, 'token encoding', { exactBytes: 32 });
        unblindedToken = parsed.unblindedToken == null ? undefined : decodeCanonicalBase64(parsed.unblindedToken, 'token encoding', { exactBytes: PP_CONFIG.TOKEN_SIZE });
        if (
            (!unblindedToken && (!blindedElement || !blindingFactor)) ||
            (unblindedToken && (blindedElement || blindingFactor))
        ) {
            throw new Error('Invalid token lifecycle state');
        }

        return {
            id: parsed.id,
            tokenSecret,
            blindingFactor,
            blindedElement,
            unblindedToken,
            purpose: normalizePrivacyPassPurpose(parsed.purpose),
            issuedAt: parsed.issuedAt,
            used: parsed.used,
            pending: parsed.pending,
        };
    } catch (error) {
        tokenSecret?.fill(0);
        blindingFactor?.fill(0);
        blindedElement?.fill(0);
        unblindedToken?.fill(0);
        throw error;
    }
}

function serializeTokenObject(token: AnonymousToken): Record<string, unknown> {
    normalizePrivacyPassPurpose(token.purpose);
    if (!isPrivacyPassTokenEpochUsable(token.tokenSecret)) throw new Error('Cannot persist expired token');
    if (
        (!token.unblindedToken && (!token.blindedElement || !token.blindingFactor)) ||
        (token.unblindedToken && (token.blindedElement || token.blindingFactor))
    ) {
        throw new Error('Cannot persist an invalid token lifecycle state');
    }
    return {
        id: token.id,
        tokenSecret: Base64.arrayBufferToBase64(token.tokenSecret),
        blindingFactor: token.blindingFactor ? Base64.arrayBufferToBase64(token.blindingFactor) : null,
        blindedElement: token.blindedElement ? Base64.arrayBufferToBase64(token.blindedElement) : null,
        unblindedToken: token.unblindedToken ? Base64.arrayBufferToBase64(token.unblindedToken) : null,
        purpose: token.purpose,
        issuedAt: token.issuedAt,
        used: token.used,
        pending: token.pending,
    };
}

/**
 * Token Serialization helpers
 */
export const TokenSerializer = {
    /**
     * Serialize token for storage
     */
    serialize(token: AnonymousToken): string {
        return JSON.stringify(serializeTokenObject(token));
    },

    /**
     * Deserialize token from storage
     */
    deserialize(data: string): AnonymousToken {
        return deserializeTokenObject(JSON.parse(data));
    },

    /**
     * Serialize batch for storage
     */
    async serializeBatch(tokens: AnonymousToken[]): Promise<string> {
        if (!Array.isArray(tokens) || tokens.length > 1000) throw new Error('Invalid token batch');
        const serialized = [];
        for (let i = 0; i < tokens.length; i++) {
            const t = tokens[i];
            if (isPrivacyPassTokenEpochUsable(t.tokenSecret)) serialized.push(serializeTokenObject(t));

            // Yield every 50 tokens
            if (i % 50 === 0 && i > 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        return JSON.stringify(serialized);
    },

    /**
     * Deserialize batch from storage
     */
    async deserializeBatch(data: string): Promise<AnonymousToken[]> {
        if (typeof data !== 'string' || data.length > 5 * 1024 * 1024) throw new Error('Invalid token batch');
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed) || parsed.length > 1000) throw new Error('Invalid token batch');
        const tokens: AnonymousToken[] = [];
        try {
            for (let i = 0; i < parsed.length; i++) {
                const token = deserializeTokenObject(parsed[i]);
                if (isPrivacyPassTokenEpochUsable(token.tokenSecret)) {
                    tokens.push(token);
                } else {
                    token.tokenSecret.fill(0);
                    token.blindingFactor?.fill(0);
                    token.blindedElement?.fill(0);
                    token.unblindedToken?.fill(0);
                }

                if (i % 50 === 0 && i > 0) {
                    await new Promise(resolve => setTimeout(resolve, 0));
                }
            }
            return tokens;
        } catch (error) {
            for (const token of tokens) {
                token.tokenSecret.fill(0);
                token.blindingFactor?.fill(0);
                token.blindedElement?.fill(0);
                token.unblindedToken?.fill(0);
            }
            throw error;
        }
    },
};

/**
 * Privacy Pass Client Helpers
 */
export const PrivacyPassHelpers = {
    /**
     * Format redemption request for server
     */
    formatResponse(data: Record<string, Uint8Array | string | number | boolean>): Record<string, string | number | boolean> {
        const encoded: Record<string, string | number | boolean> = {};
        for (const [key, value] of Object.entries(data)) {
            if (value instanceof Uint8Array) {
                encoded[key] = Base64.arrayBufferToBase64(value);
            } else {
                encoded[key] = value as string | number | boolean;
            }
        }
        return encoded;
    },

    /**
     * Decode issuance response from server
     */
    decodeResponse(data: Record<string, any>): {
        signedBlindedTokens: Uint8Array[];
        proof: Uint8Array;
        serverPublicKey: Uint8Array;
        issuerEpoch: number;
    } {
        const rawTokens = (data as any)?.signedBlindedTokens;
        if (!Array.isArray(rawTokens) || rawTokens.length === 0) {
            throw new Error('Missing or empty signedBlindedTokens in issuance response');
        }
        if (rawTokens.length > PP_CONFIG.MAX_BATCH_SIZE || !rawTokens.every((t) => typeof t === 'string')) {
            throw new Error('Invalid signed token batch');
        }

        const proofStr = typeof data.proof === 'string' ? data.proof : undefined;
        if (!proofStr) {
            throw new Error('Missing proof in issuance response');
        }

        const pubKeyStr = typeof data.publicKey === 'string' ? data.publicKey : undefined;
        if (!pubKeyStr) {
            throw new Error('Missing publicKey in issuance response');
        }
        const issuerEpoch = data.issuerEpoch;
        if (!Number.isSafeInteger(issuerEpoch) || issuerEpoch < 0 || issuerEpoch > 0xffffffff) {
            throw new Error('Invalid Privacy Pass issuer epoch');
        }

        const signedBlindedTokens: Uint8Array[] = [];
        let proof: Uint8Array | null = null;
        let serverPublicKey: Uint8Array | null = null;
        try {
            for (const token of rawTokens) {
                signedBlindedTokens.push(decodeCanonicalBase64(token, 'token encoding', { exactBytes: 32 }));
            }
            proof = decodeCanonicalBase64(proofStr, 'token encoding', { exactBytes: 64 });
            serverPublicKey = decodeCanonicalBase64(pubKeyStr, 'token encoding', { exactBytes: 32 });
            return { signedBlindedTokens, proof, serverPublicKey, issuerEpoch };
        } catch (error) {
            for (const token of signedBlindedTokens) token.fill(0);
            proof?.fill(0);
            serverPublicKey?.fill(0);
            throw error;
        }
    }
};

export { PP_CONFIG };
