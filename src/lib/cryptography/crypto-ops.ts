/**
 * Core Cryptographic Operations
 * Executed inside the dedicated post-quantum worker
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { v4 as uuidv4 } from 'uuid';
import { AUTH_CHANNEL_BINDING_BYTES } from '../../../shared/auth-channel-binding.js';
import { normalizePrivacyPassPurpose } from './privacy-pass-purpose';
import { PROTOCOL_KEYS } from '../config/protocol-keys';

const textEncoder = new TextEncoder();

function privacyPassOprfInfo(purpose: string): Uint8Array {
    return textEncoder.encode(`${PROTOCOL_KEYS.PRIVACY_PASS_OPRF_INPUT}:${normalizePrivacyPassPurpose(purpose)}`);
}

/**
 * Privacy Pass Operations
 */
export const PrivacyPassOps = {
    generateTokenBatch(count: number, purpose: string) {
        if (!Number.isInteger(count) || count < 1 || count > 1000) {
            throw new Error('Invalid Privacy Pass batch size');
        }
        const blindedTokens: Uint8Array[] = [];
        const tokenSecrets: any[] = [];
        const normalizedPurpose = normalizePrivacyPassPurpose(purpose);
        const epoch = Math.floor(Date.now() / 86_400_000);

        try {
            for (let i = 0; i < count; i++) {
                const tokenSecret = new Uint8Array(36);
                let tokenEntropy: Uint8Array | null = null;
                let oprfInput: Uint8Array | null = null;
                let blindResult: { blind: Uint8Array; blinded: Uint8Array } | null = null;
                try {
                    new DataView(tokenSecret.buffer).setUint32(0, epoch, false);
                    tokenEntropy = randomBytes(32);
                    tokenSecret.set(tokenEntropy, 4);
                    oprfInput = hkdf(
                        blake3,
                        tokenSecret,
                        new Uint8Array(0),
                        privacyPassOprfInfo(normalizedPurpose),
                        32
                    );
                    blindResult = oprf.voprf.blind(oprfInput);
                    const tokenId = uuidv4();

                    blindedTokens.push(new Uint8Array(blindResult.blinded));
                    tokenSecrets.push({
                        id: tokenId,
                        tokenSecret,
                        blindingFactor: blindResult.blind,
                        blindedElement: blindResult.blinded,
                        purpose: normalizedPurpose,
                        issuedAt: Date.now(),
                        used: false,
                        pending: false,
                    });
                } catch (error) {
                    tokenSecret.fill(0);
                    blindResult?.blind.fill(0);
                    blindResult?.blinded.fill(0);
                    throw error;
                } finally {
                    tokenEntropy?.fill(0);
                    oprfInput?.fill(0);
                }
            }
        } catch (error) {
            for (const token of tokenSecrets) {
                token.tokenSecret?.fill(0);
                token.blindingFactor?.fill(0);
                token.blindedElement?.fill(0);
            }
            for (const blinded of blindedTokens) blinded.fill(0);
            throw error;
        }

        return { blindedTokens, tokenSecrets };
    },

    unblindTokens(
        tokenSecrets: any[],
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array
    ) {
        if (
            !Array.isArray(tokenSecrets) ||
            tokenSecrets.length === 0 ||
            tokenSecrets.length !== signedBlindedTokens.length ||
            tokenSecrets.length > 1000 ||
            proof.length !== 64 ||
            serverPublicKey.length !== 32 ||
            !signedBlindedTokens.every((token) => token instanceof Uint8Array && token.length === 32)
        ) {
            throw new Error('Invalid Privacy Pass issuance response');
        }
        if (tokenSecrets.some((token) =>
            !(token?.tokenSecret instanceof Uint8Array) || token.tokenSecret.length !== 36 ||
            !(token.blindingFactor instanceof Uint8Array) || token.blindingFactor.length !== 32 ||
            !(token.blindedElement instanceof Uint8Array) || token.blindedElement.length !== 32
        )) {
            throw new Error('Invalid Privacy Pass token state');
        }

        const items: Array<{
            input: Uint8Array;
            blind: Uint8Array;
            blinded: Uint8Array;
            evaluated: Uint8Array;
        }> = [];
        let finalizedTokens;
        try {
            for (let i = 0; i < tokenSecrets.length; i++) {
                const token = tokenSecrets[i];
                items.push({
                    input: hkdf(
                        blake3,
                        token.tokenSecret,
                        new Uint8Array(0),
                        privacyPassOprfInfo(token.purpose),
                        32
                    ),
                    blind: token.blindingFactor,
                    blinded: token.blindedElement,
                    evaluated: signedBlindedTokens[i],
                });
            }
            finalizedTokens = oprf.voprf.finalizeBatch(items, serverPublicKey, proof);
        } finally {
            for (const item of items) item.input.fill(0);
        }

        const completedTokens: any[] = [];
        try {
            for (let i = 0; i < tokenSecrets.length; i++) {
                const source = tokenSecrets[i];
                const finalized = finalizedTokens[i];
                if (!(finalized instanceof Uint8Array) || finalized.length !== 64) {
                    throw new Error('Invalid finalized Privacy Pass token');
                }
                completedTokens.push({
                    ...source,
                    tokenSecret: new Uint8Array(source.tokenSecret),
                    unblindedToken: new Uint8Array(finalized),
                    blindingFactor: undefined,
                    blindedElement: undefined,
                });
            }
            return completedTokens;
        } catch (error) {
            for (const token of completedTokens) {
                token.tokenSecret?.fill(0);
                token.unblindedToken?.fill(0);
            }
            throw error;
        } finally {
            for (const finalized of finalizedTokens) finalized?.fill(0);
        }
    }
};

/**
 * OPAQUE Operations
 */
export const OPAQUEOps = {
    startRegistration(password: Uint8Array) {
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            textEncoder.encode(PROTOCOL_KEYS.OPAQUE_OPRF_INPUT),
            32
        );

        try {
            const blindResult = oprf.oprf.blind(oprfInput);
            return {
                blindedElement: blindResult.blinded,
                blindingFactor: blindResult.blind
            };
        } finally {
            oprfInput.fill(0);
        }
    },

    finishRegistration(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverNonce: Uint8Array;
        }
    ) {
        if (serverResponse.evaluatedElement.length !== 32 || serverResponse.serverNonce.length !== 32) {
            throw new Error('Invalid registration response');
        }
        let oprfInput: Uint8Array | null = null;
        let oprfOutput: Uint8Array | null = null;
        let envelopeKey: Uint8Array | null = null;
        let authSeed: Uint8Array | null = null;
        let envelopeNonce: Uint8Array | null = null;
        let encryptedEnvelope: Uint8Array | null = null;
        let authKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
        try {
            oprfInput = hkdf(
                blake3,
                password,
                new Uint8Array(0),
                textEncoder.encode(PROTOCOL_KEYS.OPAQUE_OPRF_INPUT),
                32
            );

            oprfOutput = oprf.oprf.finalize(
                oprfInput,
                blindingFactor,
                serverResponse.evaluatedElement
            );

            envelopeKey = hkdf(
                blake3,
                oprfOutput,
                serverResponse.serverNonce,
                textEncoder.encode(PROTOCOL_KEYS.OPAQUE_ENVELOPE_KEY),
                32
            );

            authSeed = randomBytes(32);
            authKeyPair = ml_dsa87.keygen(authSeed);
            const authPublicKey = new Uint8Array(authKeyPair.publicKey);

            envelopeNonce = randomBytes(24);
            const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
            encryptedEnvelope = cipher.encrypt(authSeed);
            const envelope = new Uint8Array(envelopeNonce.length + encryptedEnvelope.length);
            envelope.set(envelopeNonce, 0);
            envelope.set(encryptedEnvelope, envelopeNonce.length);

            const exportKey = hkdf(
                blake3,
                oprfOutput,
                new Uint8Array(0),
                textEncoder.encode(PROTOCOL_KEYS.OPAQUE_EXPORT_KEY),
                32
            );

            return { envelope, exportKey, authPublicKey };
        } finally {
            oprfInput?.fill(0);
            oprfOutput?.fill(0);
            envelopeKey?.fill(0);
            authSeed?.fill(0);
            authKeyPair?.publicKey.fill(0);
            authKeyPair?.secretKey.fill(0);
            envelopeNonce?.fill(0);
            encryptedEnvelope?.fill(0);
        }
    },

    startLogin(password: Uint8Array) {
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            textEncoder.encode(PROTOCOL_KEYS.OPAQUE_OPRF_INPUT),
            32
        );

        try {
            const blindResult = oprf.oprf.blind(oprfInput);
            return {
                blindedElement: blindResult.blinded,
                blindingFactor: blindResult.blind
            };
        } finally {
            oprfInput.fill(0);
        }
    },

    finishLogin(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            envelope: Uint8Array;
            serverNonce: Uint8Array;
            salt: Uint8Array;
        },
        authChannelBinding: Uint8Array
    ) {
        if (
            serverResponse.evaluatedElement.length !== 32 ||
            serverResponse.serverNonce.length !== 32 ||
            serverResponse.salt.length !== 32 ||
            serverResponse.envelope.length !== 72 ||
            authChannelBinding.length !== AUTH_CHANNEL_BINDING_BYTES
        ) {
            return { success: false };
        }
        let oprfInput: Uint8Array | null = null;
        let oprfOutput: Uint8Array | null = null;
        let envelopeKey: Uint8Array | null = null;
        let envelopeNonce: Uint8Array | null = null;
        let encryptedEnvelope: Uint8Array | null = null;
        let authSeed: Uint8Array | null = null;
        let authTranscript: Uint8Array | null = null;
        let authKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
        try {
            oprfInput = hkdf(
                blake3,
                password,
                new Uint8Array(0),
                textEncoder.encode(PROTOCOL_KEYS.OPAQUE_OPRF_INPUT),
                32
            );

            oprfOutput = oprf.oprf.finalize(
                oprfInput,
                blindingFactor,
                serverResponse.evaluatedElement
            );

            envelopeKey = hkdf(
                blake3,
                oprfOutput,
                serverResponse.salt,
                textEncoder.encode(PROTOCOL_KEYS.OPAQUE_ENVELOPE_KEY),
                32
            );

            envelopeNonce = serverResponse.envelope.slice(0, 24);
            encryptedEnvelope = serverResponse.envelope.slice(24);

            const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
            try {
                authSeed = cipher.decrypt(encryptedEnvelope);
            } catch {
                return { success: false };
            }

            if (authSeed.length !== 32) {
                return { success: false };
            }

            const exportKey = hkdf(
                blake3,
                oprfOutput,
                new Uint8Array(0),
                textEncoder.encode(PROTOCOL_KEYS.OPAQUE_EXPORT_KEY),
                32
            );

            const sigContext = textEncoder.encode(PROTOCOL_KEYS.OPAQUE_AUTH_SIGNATURE_CONTEXT);
            authTranscript = new Uint8Array(
                sigContext.length + serverResponse.serverNonce.length + authChannelBinding.length
            );
            authTranscript.set(sigContext, 0);
            authTranscript.set(serverResponse.serverNonce, sigContext.length);
            authTranscript.set(
                authChannelBinding,
                sigContext.length + serverResponse.serverNonce.length
            );
            authKeyPair = ml_dsa87.keygen(authSeed);
            const authMessage = ml_dsa87.sign(authTranscript, authKeyPair.secretKey);

            return {
                success: true,
                exportKey,
                authMessage
            };
        } finally {
            oprfInput?.fill(0);
            oprfOutput?.fill(0);
            envelopeKey?.fill(0);
            envelopeNonce?.fill(0);
            encryptedEnvelope?.fill(0);
            authSeed?.fill(0);
            authTranscript?.fill(0);
            authKeyPair?.publicKey.fill(0);
            authKeyPair?.secretKey.fill(0);
        }
    }
};
