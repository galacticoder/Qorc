/**
 * Privacy Pass Client
 * 
 * Generates, blinds, unblinds, and redeems anonymous tokens
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { Base64 } from './base64';
import { PostQuantumWorker } from './worker-bridge';
import { PrivacyPassOps } from './crypto-ops';

// Privacy Pass configuration
const PP_CONFIG = {
    DEFAULT_BATCH_SIZE: 250,
    NULLIFIER_SIZE: 32,
    TOKEN_SIZE: 64,
    MAC_SIZE: 32,
    NONCE_SIZE: 24,
};

// Domain separation labels
const PP_LABELS = {
    NULLIFIER: 'PrivacyPass-Nullifier-v1',
    REDEMPTION_MAC: 'PrivacyPass-Redemption-MAC-v1',
    TOKEN_ENCRYPTION: 'PrivacyPass-Token-Encryption-v1',
    OPRF_INPUT: 'PrivacyPass-OPRF-Input-v1',
};

/**
 * Anonymous Token structure
 */
export interface AnonymousToken {
    id: string;
    tokenSecret: Uint8Array;
    blindingFactor: Uint8Array;
    blindedElement?: Uint8Array;
    signature?: Uint8Array;
    unblindedToken?: Uint8Array;
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
    private pendingBlinds: Map<string, { blind: Uint8Array; input: Uint8Array }> = new Map();

    /**
     * Generate a batch of tokens to be signed by server
     */
    async generateTokenBatch(count: number = PP_CONFIG.DEFAULT_BATCH_SIZE): Promise<{
        blindedTokens: Uint8Array[];
        tokenSecrets: AnonymousToken[];
    }> {
        try {
            const result = await PostQuantumWorker.ppGenerateTokenBatch(count);
            return {
                blindedTokens: result.blindedTokens,
                tokenSecrets: result.tokenSecrets as AnonymousToken[]
            };
        } catch (err) {
            console.warn('[PrivacyPassClient] Worker failed, falling back to local generation', err);
            return this.generateTokenBatchLocal(count);
        }
    }

    async generateTokenBatchLocal(count: number = PP_CONFIG.DEFAULT_BATCH_SIZE): Promise<{
        blindedTokens: Uint8Array[];
        tokenSecrets: AnonymousToken[];
    }> {
        const result = PrivacyPassOps.generateTokenBatch(count);
        
        // Track pending blinds for unblinding
        for (const token of result.tokenSecrets) {
            const { hkdf } = await import('@noble/hashes/hkdf.js');
            const { blake3 } = await import('@noble/hashes/blake3.js');
            const oprfInput = hkdf(
                blake3,
                token.tokenSecret,
                new Uint8Array(0),
                new TextEncoder().encode(PP_LABELS.OPRF_INPUT),
                32
            );
            this.pendingBlinds.set(token.id, {
                blind: token.blindingFactor,
                input: oprfInput
            });
        }

        return result;
    }

    /**
     * Unblind server signed tokens
     */
    async unblindTokens(
        tokenSecrets: AnonymousToken[],
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array
    ): Promise<AnonymousToken[]> {
        try {
            const result = await PostQuantumWorker.ppUnblindTokens(tokenSecrets, signedBlindedTokens, proof, serverPublicKey);
            return result.completedTokens as AnonymousToken[];
        } catch (err) {
            console.warn('[PrivacyPassClient] Worker unblind failed, falling back to local', err);
            return this.unblindTokensLocal(tokenSecrets, signedBlindedTokens, proof, serverPublicKey);
        }
    }

    async unblindTokensLocal(
        tokenSecrets: AnonymousToken[],
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array
    ): Promise<AnonymousToken[]> {
        const completed = PrivacyPassOps.unblindTokens(tokenSecrets, signedBlindedTokens, proof, serverPublicKey);
        
        // Clear pending blinds
        for (const token of completed) {
            this.pendingBlinds.delete(token.id);
        }
        
        return completed;
    }

    /**
     * Prepare a token for redemption
     */
    async prepareRedemption(token: AnonymousToken): Promise<{
        token: Uint8Array;
        nullifier: Uint8Array;
        mac: Uint8Array;
        decryptionKey: Uint8Array;
    }> {
        if (!token.unblindedToken) {
            throw new Error('Token not finalized');
        }

        if (token.used) {
            throw new Error('Token already used');
        }

        // Compute nullifier
        const nullifier = hkdf(
            blake3,
            token.unblindedToken,
            new Uint8Array(0),
            new TextEncoder().encode(PP_LABELS.NULLIFIER),
            PP_CONFIG.NULLIFIER_SIZE
        );

        // Compute MAC proving we possess the token
        const macKey = hkdf(
            blake3,
            token.unblindedToken,
            nullifier,
            new TextEncoder().encode(PP_LABELS.REDEMPTION_MAC),
            32
        );
        const mac = blake3(macKey, { dkLen: PP_CONFIG.MAC_SIZE });

        // Derive key for decrypting server response
        const decryptionKey = hkdf(
            blake3,
            token.unblindedToken,
            new Uint8Array(0),
            new TextEncoder().encode(PP_LABELS.TOKEN_ENCRYPTION),
            32
        );

        return {
            token: token.unblindedToken,
            nullifier,
            mac,
            decryptionKey,
        };
    }

    /**
     * Process server redemption response
     */
    async processRedemptionResponse(
        encryptedResponse: Uint8Array,
        decryptionKey: Uint8Array
    ): Promise<{
        success: boolean;
        sessionNonce?: Uint8Array;
        capabilityTokenSeed?: Uint8Array;
    }> {
        try {
            const nonce = encryptedResponse.slice(0, PP_CONFIG.NONCE_SIZE);
            const ciphertext = encryptedResponse.slice(PP_CONFIG.NONCE_SIZE);

            const cipher = xchacha20poly1305(decryptionKey, nonce);
            const payload = cipher.decrypt(ciphertext);

            if (payload[0] !== 0x01) {
                return { success: false };
            }

            return {
                success: true,
                sessionNonce: payload.slice(1, 33),
                capabilityTokenSeed: payload.slice(33, 65),
            };
        } catch {
            return { success: false };
        }
    }

    /**
     * Clear pending blinds
     */
    clearPending(): void {
        for (const entry of this.pendingBlinds.values()) {
            entry.blind.fill(0);
            entry.input.fill(0);
        }
        this.pendingBlinds.clear();
    }
}

/**
 * Token Serialization helpers
 */
export const TokenSerializer = {
    /**
     * Serialize token for storage
     */
    serialize(token: AnonymousToken): string {
        return JSON.stringify({
            id: token.id,
            tokenSecret: Base64.arrayBufferToBase64(token.tokenSecret),
            blindingFactor: Base64.arrayBufferToBase64(token.blindingFactor),
            signature: token.signature ? Base64.arrayBufferToBase64(token.signature) : null,
            unblindedToken: token.unblindedToken
                ? Base64.arrayBufferToBase64(token.unblindedToken)
                : null,
            issuedAt: token.issuedAt,
            used: token.used,
            pending: token.pending,
        });
    },

    /**
     * Deserialize token from storage
     */
    deserialize(data: string): AnonymousToken {
        const parsed = JSON.parse(data);
        return {
            id: parsed.id,
            tokenSecret: Base64.base64ToUint8Array(parsed.tokenSecret),
            blindingFactor: Base64.base64ToUint8Array(parsed.blindingFactor),
            signature: parsed.signature
                ? Base64.base64ToUint8Array(parsed.signature)
                : undefined,
            unblindedToken: parsed.unblindedToken
                ? Base64.base64ToUint8Array(parsed.unblindedToken)
                : undefined,
            issuedAt: parsed.issuedAt,
            used: parsed.used,
            pending: parsed.pending,
        };
    },

    /**
     * Serialize batch for storage
     */
    async serializeBatch(tokens: AnonymousToken[]): Promise<string> {
        const serialized = [];
        for (let i = 0; i < tokens.length; i++) {
            const t = tokens[i];
            serialized.push({
                id: t.id,
                tokenSecret: Base64.arrayBufferToBase64(t.tokenSecret),
                blindingFactor: Base64.arrayBufferToBase64(t.blindingFactor),
                signature: t.signature ? Base64.arrayBufferToBase64(t.signature) : null,
                unblindedToken: t.unblindedToken
                    ? Base64.arrayBufferToBase64(t.unblindedToken)
                    : null,
                issuedAt: t.issuedAt,
                used: t.used,
                pending: t.pending,
            });

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
        const parsed = JSON.parse(data);
        const tokens: AnonymousToken[] = [];
        for (let i = 0; i < parsed.length; i++) {
            const p = parsed[i];
            tokens.push({
                id: p.id as string,
                tokenSecret: Base64.base64ToUint8Array(p.tokenSecret as string),
                blindingFactor: Base64.base64ToUint8Array(p.blindingFactor as string),
                signature: p.signature
                    ? Base64.base64ToUint8Array(p.signature as string)
                    : undefined,
                unblindedToken: p.unblindedToken
                    ? Base64.base64ToUint8Array(p.unblindedToken as string)
                    : undefined,
                issuedAt: p.issuedAt as number,
                used: p.used as boolean,
                pending: p.pending as boolean,
            });
            
            // Yield every 50 tokens
            if (i % 50 === 0 && i > 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
        return tokens;
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
    } {
        const rawTokens = (data as any)?.signedBlindedTokens;
        if (!Array.isArray(rawTokens) || rawTokens.length === 0) {
            throw new Error('Missing or empty signedBlindedTokens in issuance response');
        }
        const tokenList = rawTokens.filter((t): t is string => typeof t === 'string' && t.length > 0);
        if (tokenList.length === 0) {
            throw new Error('No valid token strings in signedBlindedTokens');
        }

        const proofStr = typeof data.proof === 'string' ? data.proof : undefined;
        if (!proofStr) {
            throw new Error('Missing proof in issuance response');
        }

        const pubKeyStr = typeof data.publicKey === 'string' ? data.publicKey
            : typeof data.serverPublicKey === 'string' ? data.serverPublicKey
            : undefined;
        if (!pubKeyStr) {
            throw new Error('Missing publicKey in issuance response');
        }

        return {
            signedBlindedTokens: tokenList.map(t => Base64.base64ToUint8Array(t)),
            proof: Base64.base64ToUint8Array(proofStr),
            serverPublicKey: Base64.base64ToUint8Array(pubKeyStr),
        };
    }
};

export { PP_CONFIG, PP_LABELS };
