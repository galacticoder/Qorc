/**
 * Core Cryptographic Operations
 * Shared between main thread fallbacks and worker thread
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ml_kem1024 as MlKem } from '@noble/post-quantum/ml-kem.js';
import { v4 as uuidv4 } from 'uuid';
import { Base64 } from './base64';

export const PP_LABELS = {
    NULLIFIER: 'PrivacyPass-Nullifier-v1',
    REDEMPTION_MAC: 'PrivacyPass-Redemption-MAC-v1',
    TOKEN_ENCRYPTION: 'PrivacyPass-Token-Encryption-v1',
    OPRF_INPUT: 'PrivacyPass-OPRF-Input-v1',
};

export const OPAQUE_LABELS = {
    OPRF_INPUT: 'OPAQUE-OPRF-Input-v1',
    ENVELOPE_KEY: 'OPAQUE-Envelope-Key-v1',
    EXPORT_KEY: 'OPAQUE-Export-Key-v1',
    SESSION_KEY: 'OPAQUE-Session-Key-v1',
    AUTH_KEY: 'OPAQUE-Auth-Key-v1',
    CLIENT_SECRET: 'OPAQUE-Client-Secret-v1',
    MASKED_RESPONSE: 'OPAQUE-MaskedResponse-v1'
};

const textEncoder = new TextEncoder();

/**
 * Privacy Pass Operations
 */
export const PrivacyPassOps = {
    generateTokenBatch(count: number) {
        const blindedTokens: Uint8Array[] = [];
        const tokenSecrets: any[] = [];

        for (let i = 0; i < count; i++) {
            const tokenSecret = randomBytes(32);
            const oprfInput = hkdf(
                blake3,
                tokenSecret,
                new Uint8Array(0),
                textEncoder.encode(PP_LABELS.OPRF_INPUT),
                32
            );
            const blindResult = oprf.voprf.blind(oprfInput);
            const tokenId = uuidv4();

            blindedTokens.push(blindResult.blinded);
            tokenSecrets.push({
                id: tokenId,
                tokenSecret,
                blindingFactor: blindResult.blind,
                blindedElement: blindResult.blinded,
                issuedAt: Date.now(),
                used: false,
                pending: false,
            });
        }

        return { blindedTokens, tokenSecrets };
    },

    unblindTokens(
        tokenSecrets: any[],
        signedBlindedTokens: Uint8Array[],
        proof: Uint8Array,
        serverPublicKey: Uint8Array
    ) {
        const items = tokenSecrets.map((token, i) => ({
            input: hkdf(
                blake3,
                token.tokenSecret,
                new Uint8Array(0),
                textEncoder.encode(PP_LABELS.OPRF_INPUT),
                32
            ),
            blind: token.blindingFactor,
            blinded: token.blindedElement!,
            evaluated: signedBlindedTokens[i],
        }));

        const finalizedTokens = oprf.voprf.finalizeBatch(
            items,
            serverPublicKey,
            proof
        );

        const completedTokens = [];
        for (let i = 0; i < tokenSecrets.length; i++) {
            const token = { ...tokenSecrets[i] };
            token.signature = signedBlindedTokens[i];
            token.unblindedToken = finalizedTokens[i];
            completedTokens.push(token);
        }
        return completedTokens;
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
            textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT),
            32
        );

        const blindResult = oprf.oprf.blind(oprfInput);
        const clientSecretKey = randomBytes(32);
        const clientPublicKey = blake3(clientSecretKey, { dkLen: 32 });

        return {
            blindedElement: blindResult.blinded,
            clientPublicKey,
            blindingFactor: blindResult.blind,
            clientSecretKey
        };
    },

    finishRegistration(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        clientSecretKey: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            serverPublicKey: Uint8Array;
            serverNonce: Uint8Array;
        }
    ) {
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT),
            32
        );

        const oprfOutput = oprf.oprf.finalize(
            oprfInput,
            blindingFactor,
            serverResponse.evaluatedElement
        );

        const envelopeKey = hkdf(
            blake3,
            oprfOutput,
            serverResponse.serverNonce,
            textEncoder.encode(OPAQUE_LABELS.ENVELOPE_KEY),
            32
        );

        const envelopeContents = new Uint8Array([
            ...clientSecretKey,
            ...serverResponse.serverPublicKey,
        ]);

        const envelopeNonce = randomBytes(24);
        const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
        const encryptedEnvelope = cipher.encrypt(envelopeContents);
        const envelope = new Uint8Array([...envelopeNonce, ...encryptedEnvelope]);

        const exportKey = hkdf(
            blake3,
            oprfOutput,
            new Uint8Array(0),
            textEncoder.encode(OPAQUE_LABELS.EXPORT_KEY),
            32
        );

        const maskedKey = hkdf(
            blake3,
            clientSecretKey,
            serverResponse.serverPublicKey,
            textEncoder.encode(OPAQUE_LABELS.MASKED_RESPONSE),
            32
        );
        const maskedResponse = blake3(maskedKey, { dkLen: 64 });

        return { envelope, exportKey, maskedResponse };
    },

    startLogin(password: Uint8Array) {
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT),
            32
        );

        const blindResult = oprf.oprf.blind(oprfInput);
        return {
            blindedElement: blindResult.blinded,
            blindingFactor: blindResult.blind
        };
    },

    finishLogin(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        serverResponse: {
            evaluatedElement: Uint8Array;
            envelope: Uint8Array;
            maskedResponse: Uint8Array;
            serverNonce: Uint8Array;
            salt?: Uint8Array;
        }
    ) {
        const oprfInput = hkdf(
            blake3,
            password,
            new Uint8Array(0),
            textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT),
            32
        );

        const oprfOutput = oprf.oprf.finalize(
            oprfInput,
            blindingFactor,
            serverResponse.evaluatedElement
        );

        const salt = serverResponse.salt || serverResponse.serverNonce;
        const envelopeKey = hkdf(
            blake3,
            oprfOutput,
            salt,
            textEncoder.encode(OPAQUE_LABELS.ENVELOPE_KEY),
            32
        );

        const envelopeNonce = serverResponse.envelope.slice(0, 24);
        const encryptedEnvelope = serverResponse.envelope.slice(24);

        const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
        const envelopeContents = cipher.decrypt(encryptedEnvelope);

        const clientSecretKey = envelopeContents.slice(0, 32);
        const serverPublicKey = envelopeContents.slice(32, 64);

        // Re-derive maskedResponse to use as shared secret for auth MAC
        const maskedKey = hkdf(
            blake3,
            clientSecretKey,
            serverPublicKey,
            textEncoder.encode(OPAQUE_LABELS.MASKED_RESPONSE),
            32
        );
        const recoveredMaskedResponse = blake3(maskedKey, { dkLen: 64 });

        const sessionKey = hkdf(
            blake3,
            oprfOutput,
            serverResponse.serverNonce,
            textEncoder.encode(OPAQUE_LABELS.SESSION_KEY),
            32
        );

        const exportKey = hkdf(
            blake3,
            oprfOutput,
            new Uint8Array(0),
            textEncoder.encode(OPAQUE_LABELS.EXPORT_KEY),
            32
        );

        // Generate auth message for server using maskedResponse as shared secret
        const authKey = hkdf(
            blake3,
            recoveredMaskedResponse,
            serverResponse.serverNonce,
            textEncoder.encode(OPAQUE_LABELS.AUTH_KEY),
            32
        );

        const authMessage = blake3(authKey, { dkLen: 32 });

        // Clear blinding factor
        this.blindingFactor = null;

        return {
            success: true,
            sessionKey,
            exportKey,
            authMessage,
            clientSecretKey
        };
    },

    /**
     * Start OT Login
     */
    startOTLogin(password: Uint8Array, shardSize: number, myIndex: number) {
        const pubKeys: Uint8Array[] = [];
        let myPrivKey: Uint8Array | null = null;

        for (let i = 0; i < shardSize; i++) {
            const pk = MlKem.keygen();
            pubKeys.push(pk.publicKey);
            if (i === myIndex) myPrivKey = pk.secretKey;
        }

        const loginStart = this.startLogin(password);

        return {
            pubKeys,
            blindedElement: loginStart.blindedElement,
            blindingFactor: loginStart.blindingFactor,
            myPrivKey
        };
    },

    /**
     * Finish OT Login
     */
    finishOTLogin(
        password: Uint8Array,
        blindingFactor: Uint8Array,
        myPrivKey: Uint8Array,
        otRecords: { ct: Uint8Array; masked: Uint8Array }[],
        myIndex: number,
        evaluatedElement: Uint8Array,
        serverNonce: Uint8Array
    ) {
        // Decrypt our specific record
        const record = otRecords[myIndex];
        const ss = MlKem.decapsulate(record.ct, myPrivKey);

        const mask = blake3(ss, { dkLen: record.masked.length });
        const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
            const len = Math.max(a.length, b.length);
            const out = new Uint8Array(len);
            for (let i = 0; i < len; i++) out[i] = (a[i] || 0) ^ (b[i] || 0);
            return out;
        };
        const rawRecord = xor(record.masked, mask);

        // Parse recovered OPAQUE record
        let recoveredRecord;
        try {
            recoveredRecord = JSON.parse(new TextDecoder().decode(rawRecord));
        } catch (e: any) {
            throw new Error(`Failed to parse OPAQUE record: ${e.message}. This usually means the wrong OT index was targeted or the record is corrupted.`);
        }

        // Finalize OPAQUE with recovered record
        const finalResult = this.finishLogin(password, blindingFactor, {
            ...recoveredRecord,
            evaluatedElement,
            serverNonce,
            envelope: Base64.base64ToUint8Array(recoveredRecord.envelope),
            maskedResponse: Base64.base64ToUint8Array(recoveredRecord.maskedResponse),
            salt: recoveredRecord.salt ? Base64.base64ToUint8Array(recoveredRecord.salt) : undefined
        });

        return {
            ...finalResult,
            serverNonce,
            credentialId: recoveredRecord.credentialId
        };
    }
};
