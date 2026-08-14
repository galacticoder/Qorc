/**
 * OPAQUE Protocol
 */

import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/hashes/utils.js';
import crypto from 'node:crypto';
import { deriveAuthRootKey } from './auth-root.js';
import {
    encryptPrivateAuthOtRecords,
    verifyAuthProofAcrossAnonymitySet,
} from './auth-crypto-worker-service.js';
import { throwIfAuthConnectionClosed } from '../authentication/auth-utils.js';
import { decodeCanonicalBase64, UTF8_ENCODER } from '../utils/encoding.js';
import {
    ML_DSA_87_PUBLIC_KEY_BYTES as ML_DSA_PUBLIC_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES as ML_DSA_SIGNATURE_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES as ML_KEM_CIPHERTEXT_BYTES,
    ML_KEM_1024_PUBLIC_KEY_BYTES as ML_KEM_PUBLIC_KEY_BYTES
} from '../../shared/crypto-sizes.js';
import {
    OPAQUE_AUTH_SIGNATURE_CONTEXT,
    PRIVATE_AUTH_ANONYMITY_SET_SIZE,
    PRIVATE_AUTH_OT_RECORD_BYTES
} from '../../shared/private-auth-protocol.js';

import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import {
    AUTH_CHANNEL_BINDING_BYTES,
    HASH_OUTPUT_BYTES,
    OPAQUE_ELEMENT_BYTES,
    OPAQUE_ENVELOPE_BYTES,
    OPAQUE_NONCE_BYTES,
    OPAQUE_SALT_BYTES,
    OPAQUE_SECRET_KEY_BYTES
} from '../utils/crypto-consts.js';

const PRIVATE_AUTH_RECORD_KEYS = Object.freeze(['authPublicKey', 'envelope', 'salt']);
const GATEKEEPER_RECORD_KEYS = Object.freeze(['authPublicKey', 'envelope', 'oprfSecretKey', 'salt']);
function throwIfAuthOperationAborted(signal) {
    throwIfAuthConnectionClosed(signal);
}

function createDummyAuthPublicKey() {
    const seed = crypto.randomBytes(HASH_OUTPUT_BYTES);
    let keyPair = null;
    try {
        keyPair = ml_dsa87.keygen(seed);
        return new Uint8Array(keyPair.publicKey);
    } finally {
        seed.fill(0);
        keyPair?.publicKey.fill(0);
        keyPair?.secretKey.fill(0);
    }
}

function verifyMlDsaSignature(signature, message, publicKey) {
    if (signature.length !== ML_DSA_SIGNATURE_BYTES || publicKey.length !== ML_DSA_PUBLIC_KEY_BYTES) return false;
    return ml_dsa87.verify(signature, message, publicKey);
}

// OPAQUE configuration
const OPAQUE_CONFIG = {
    PRIVATE_AUTH_ANONYMITY_SET_SIZE,
    OT_RECORD_PADDED_BYTES: PRIVATE_AUTH_OT_RECORD_BYTES,
    REGISTRATION_RECORD_MAX_BYTES: 4096,
};

// Domain separation labels
const LABELS = {
    OPRF_INPUT: PROTOCOL_KEYS.OPAQUE_OPRF_INPUT,
    OPRF_KEY: PROTOCOL_KEYS.OPAQUE_OPRF_KEY,
    ENVELOPE_KEY: PROTOCOL_KEYS.OPAQUE_ENVELOPE_KEY,
    EXPORT_KEY: PROTOCOL_KEYS.OPAQUE_EXPORT_KEY,
    AUTH_SIG_CONTEXT: OPAQUE_AUTH_SIGNATURE_CONTEXT,
};

export class OPAQUEServer {
    static #oprfKeys = null;
    static #initialized = false;
    static #dummyAuthPublicKey = createDummyAuthPublicKey();

    static #ensureUint8Array(val) {
        if (val instanceof Uint8Array) return new Uint8Array(val);
        return new Uint8Array(0);
    }

    /**
     * Initialize OPAQUE server with OPRF keys
     */
    static async initialize() {
        if (this.#initialized) return;

        try {
            const oprfKeyLabel = UTF8_ENCODER.encode(LABELS.OPRF_KEY);
            const seed = deriveAuthRootKey(PROTOCOL_KEYS.OPAQUE_OPRF_ROOT);
            try {
                this.#oprfKeys = oprf.oprf.deriveKeyPair(seed, oprfKeyLabel);
            } finally {
                seed.fill(0);
            }

            this.#initialized = true;
            console.log('[OPAQUE] Server initialized');
        } catch (error) {
            console.error('[OPAQUE] Initialization failed', error);
            throw error;
        }
    }

    static destroy() {
        this.#oprfKeys?.secretKey?.fill(0);
        this.#oprfKeys?.publicKey?.fill(0);
        this.#oprfKeys = null;
        this.#initialized = false;
    }

    /**
     * OPAQUE Registration
     */
    static async createRegistrationResponse(blindedElement) {
        if (!this.#initialized) {
            await this.initialize();
        }

        const evaluated = oprf.oprf.blindEvaluate(this.#oprfKeys.secretKey, blindedElement);

        const serverNonce = randomBytes(OPAQUE_NONCE_BYTES);

        return {
            evaluatedElement: evaluated,
            serverNonce,
        };
    }

    /**
     * Create OPAQUE record for storage
     */
    static createRegistrationRecord(envelope, authPublicKey, salt) {
        const envelopeBytes = this.#ensureUint8Array(envelope);
        const authPublicKeyBytes = this.#ensureUint8Array(authPublicKey);
        const saltBytes = this.#ensureUint8Array(salt);
        try {
            if (
                envelopeBytes.length !== OPAQUE_ENVELOPE_BYTES ||
                authPublicKeyBytes.length !== ML_DSA_PUBLIC_KEY_BYTES ||
                saltBytes.length !== OPAQUE_SALT_BYTES
            ) {
                throw new Error('Invalid private-auth registration record');
            }
            return {
                envelope: Buffer.from(envelopeBytes).toString('base64'),
                authPublicKey: Buffer.from(authPublicKeyBytes).toString('base64'),
                salt: Buffer.from(saltBytes).toString('base64')
            };
        } finally {
            envelopeBytes.fill(0);
            authPublicKeyBytes.fill(0);
            saltBytes.fill(0);
        }
    }

    static #parseStoredRecord(record) {
        if (!record || typeof record !== 'object' || Array.isArray(record)) {
            throw new Error('Invalid private-auth record');
        }
        const keys = Object.keys(record).sort();
        if (
            keys.length !== PRIVATE_AUTH_RECORD_KEYS.length ||
            keys.some((key, index) => key !== PRIVATE_AUTH_RECORD_KEYS[index])
        ) {
            throw new Error('Invalid private-auth record shape');
        }
        let envelope = null;
        let authPublicKey = null;
        let salt = null;
        try {
            envelope = decodeCanonicalBase64(record.envelope, OPAQUE_ENVELOPE_BYTES);
            authPublicKey = decodeCanonicalBase64(record.authPublicKey, ML_DSA_PUBLIC_KEY_BYTES);
            salt = decodeCanonicalBase64(record.salt, OPAQUE_SALT_BYTES);
            return { envelope, authPublicKey, salt };
        } catch (error) {
            envelope?.fill(0);
            authPublicKey?.fill(0);
            salt?.fill(0);
            throw error;
        }
    }

    /**
     * OPAQUE Login
     */
    static createLoginResponseLocal(blindedElement) {
        if (!this.#initialized) return null;
        return oprf.oprf.blindEvaluate(this.#oprfKeys.secretKey, blindedElement);
    }

    /**
     * OPAQUE Login
     */
    static async createGatekeeperLoginResponse(blindedElement, record) {
        if (!this.#initialized) {
            await this.initialize();
        }

        if (!record || typeof record !== 'object' || Array.isArray(record)) {
            throw new Error('Invalid server-entry authentication record');
        }
        const keys = Object.keys(record).sort();
        if (
            keys.length !== GATEKEEPER_RECORD_KEYS.length ||
            keys.some((key, index) => key !== GATEKEEPER_RECORD_KEYS[index])
        ) {
            throw new Error('Invalid server-entry authentication record');
        }

        const blinded = this.#ensureUint8Array(blindedElement);
        const secretKey = this.#ensureUint8Array(record.oprfSecretKey);
        const authPublicKey = this.#ensureUint8Array(record.authPublicKey);
        let envelope = this.#ensureUint8Array(record.envelope);
        let salt = this.#ensureUint8Array(record.salt);
        let evaluated = null;
        let serverNonce = null;
        let delivered = false;
        try {
            if (
                blinded.length !== OPAQUE_ELEMENT_BYTES ||
                secretKey.length !== OPAQUE_SECRET_KEY_BYTES ||
                authPublicKey.length !== ML_DSA_PUBLIC_KEY_BYTES ||
                envelope.length !== OPAQUE_ENVELOPE_BYTES ||
                salt.length !== OPAQUE_SALT_BYTES
            ) {
                throw new Error('Invalid server-entry authentication record');
            }

            evaluated = oprf.oprf.blindEvaluate(secretKey, blinded);
            serverNonce = randomBytes(OPAQUE_NONCE_BYTES);
            delivered = true;
            return { evaluatedElement: evaluated, envelope, salt, serverNonce };
        } finally {
            blinded.fill(0);
            secretKey.fill(0);
            authPublicKey.fill(0);
            if (!delivered) {
                envelope.fill(0);
                salt.fill(0);
                evaluated?.fill(0);
                serverNonce?.fill(0);
            }
            envelope = null;
            salt = null;
        }
    }

    /**
     * Transcript client signs and server verifies for login proof
     */
    static #authSigTranscript(serverNonce, authChannelBinding) {
        return Buffer.concat([
            Buffer.from(LABELS.AUTH_SIG_CONTEXT, 'utf8'),
            Buffer.from(serverNonce),
            Buffer.from(authChannelBinding)
        ]);
    }

    /**
     * Login finalization
     */
    static async finishLogin(clientAuthMessage, record, serverNonce, authChannelBinding) {
        let parsed;
        try {
            parsed = this.#parseStoredRecord(record);
        } catch {
            return { success: false };
        }

        try {
            return this.finishLoginWithPublicKey(
                clientAuthMessage,
                parsed.authPublicKey,
                serverNonce,
                authChannelBinding
            );
        } finally {
            parsed.envelope.fill(0);
            parsed.authPublicKey.fill(0);
            parsed.salt.fill(0);
        }

    }

    static finishLoginWithPublicKey(clientAuthMessage, authPublicKey, serverNonce, authChannelBinding) {
        const signature = this.#ensureUint8Array(clientAuthMessage);
        const publicKey = this.#ensureUint8Array(authPublicKey);
        const nonce = this.#ensureUint8Array(serverNonce);
        const channelBinding = this.#ensureUint8Array(authChannelBinding);
        let transcript = null;
        try {
            if (
                signature.length !== ML_DSA_SIGNATURE_BYTES ||
                publicKey.length !== ML_DSA_PUBLIC_KEY_BYTES ||
                nonce.length !== OPAQUE_NONCE_BYTES ||
                channelBinding.length !== AUTH_CHANNEL_BINDING_BYTES
            ) {
                return { success: false };
            }
            transcript = this.#authSigTranscript(nonce, channelBinding);
            return {
                success: verifyMlDsaSignature(
                    signature,
                    transcript,
                    publicKey
                )
            };
        } catch {
            return { success: false };
        } finally {
            signature.fill(0);
            publicKey.fill(0);
            nonce.fill(0);
            channelBinding.fill(0);
            transcript?.fill(0);
        }
    }

    // Verify login proof against entire anonymity set
    static async finishLoginAcrossAnonymitySet(
        anonymitySetRecords,
        clientAuthMessage,
        serverNonce,
        authChannelBinding,
        signal
    ) {
        const records = Array.isArray(anonymitySetRecords) ? anonymitySetRecords : [];
        const anonymitySetSize = this.getAnonymitySetSize();
        let authPublicKeys = new Uint8Array(anonymitySetSize * ML_DSA_PUBLIC_KEY_BYTES);
        let signature = null;
        let transcript = null;
        let nonce = null;
        let channelBinding = null;
        let invalidInput = false;
        try {
            if (records.length > anonymitySetSize) {
                throw new Error('Private authentication record set is too large');
            }
            for (let slot = 0; slot < anonymitySetSize; slot += 1) {
                throwIfAuthOperationAborted(signal);
                authPublicKeys.set(this.#dummyAuthPublicKey, slot * ML_DSA_PUBLIC_KEY_BYTES);
            }

            const seenSlots = new Uint8Array(anonymitySetSize);
            for (const row of records) {
                throwIfAuthOperationAborted(signal);
                const slot = Number(row?.credential_index);
                if (!Number.isInteger(slot) || slot < 0 || slot >= anonymitySetSize || seenSlots[slot] !== 0) {
                    throw new Error('Invalid private-auth slot in database');
                }
                seenSlots[slot] = 1;
                let rawRecord;
                try {
                    rawRecord = typeof row?.opaqueRecord === 'string'
                        ? JSON.parse(row.opaqueRecord)
                        : null;
                } catch {
                    throw new Error('Invalid private-auth record in database');
                }
                const parsed = this.#parseStoredRecord(rawRecord);
                try {
                    authPublicKeys.set(parsed.authPublicKey, slot * ML_DSA_PUBLIC_KEY_BYTES);
                } finally {
                    parsed.envelope.fill(0);
                    parsed.authPublicKey.fill(0);
                    parsed.salt.fill(0);
                }
            }

            signature = this.#ensureUint8Array(clientAuthMessage);
            if (signature.length !== ML_DSA_SIGNATURE_BYTES) {
                signature.fill(0);
                signature = new Uint8Array(ML_DSA_SIGNATURE_BYTES);
                invalidInput = true;
            }
            nonce = this.#ensureUint8Array(serverNonce);
            if (nonce.length !== OPAQUE_NONCE_BYTES) {
                nonce.fill(0);
                nonce = new Uint8Array(OPAQUE_NONCE_BYTES);
                invalidInput = true;
            }
            channelBinding = this.#ensureUint8Array(authChannelBinding);
            if (channelBinding.length !== AUTH_CHANNEL_BINDING_BYTES) {
                channelBinding.fill(0);
                channelBinding = new Uint8Array(AUTH_CHANNEL_BINDING_BYTES);
                invalidInput = true;
            }
            const transcriptBuffer = this.#authSigTranscript(nonce, channelBinding);
            try {
                transcript = new Uint8Array(transcriptBuffer);
            } finally {
                transcriptBuffer.fill(0);
            }

            const verification = verifyAuthProofAcrossAnonymitySet(authPublicKeys, signature, transcript, signal);
            authPublicKeys = null;
            signature = null;
            transcript = null;
            const result = await verification;
            return { success: !invalidInput && result.matched };
        } finally {
            authPublicKeys?.fill(0);
            signature?.fill(0);
            transcript?.fill(0);
            nonce?.fill(0);
            channelBinding?.fill(0);
        }
    }

    static getAnonymitySetSize() {
        return OPAQUE_CONFIG.PRIVATE_AUTH_ANONYMITY_SET_SIZE;
    }

    static getRegistrationRecordMaxBytes() {
        return OPAQUE_CONFIG.REGISTRATION_RECORD_MAX_BYTES;
    }

    /**
     * Oblivious Transfer
     */
    static async encryptAnonymitySetForOT(records, clientPubKeys, signal) {
        const anonymitySetSize = this.getAnonymitySetSize();
        if (
            !Array.isArray(clientPubKeys) ||
            clientPubKeys.length !== anonymitySetSize ||
            clientPubKeys.some((key) => !(key instanceof Uint8Array) || key.length !== ML_KEM_PUBLIC_KEY_BYTES)
        ) {
            throw new Error('Invalid private-auth KEM public-key set');
        }

        const sourceRecords = Array.isArray(records) ? records : [];
        if (sourceRecords.length > anonymitySetSize) {
            throw new Error('Private authentication record set is too large');
        }

        let publicKeySlab = new Uint8Array(anonymitySetSize * ML_KEM_PUBLIC_KEY_BYTES);
        let paddedRecordSlab = new Uint8Array(anonymitySetSize * OPAQUE_CONFIG.OT_RECORD_PADDED_BYTES);
        let ciphertexts = null;
        let maskedRecords = null;
        try {
            for (let slot = 0; slot < anonymitySetSize; slot += 1) {
                throwIfAuthOperationAborted(signal);
                publicKeySlab.set(clientPubKeys[slot], slot * ML_KEM_PUBLIC_KEY_BYTES);
            }
            crypto.randomFillSync(paddedRecordSlab);

            const seenSlots = new Uint8Array(anonymitySetSize);
            const paddedView = new DataView(paddedRecordSlab.buffer);
            for (const row of sourceRecords) {
                throwIfAuthOperationAborted(signal);
                const slot = Number(row?.credential_index);
                if (!Number.isInteger(slot) || slot < 0 || slot >= anonymitySetSize || seenSlots[slot] !== 0) {
                    throw new Error('Invalid private-auth slot in database');
                }
                seenSlots[slot] = 1;
                if (
                    typeof row.opaqueRecord !== 'string' ||
                    Buffer.byteLength(row.opaqueRecord, 'utf8') > this.getRegistrationRecordMaxBytes()
                ) {
                    throw new Error('Invalid private-auth record in database');
                }

                let rawRecord;
                try {
                    rawRecord = JSON.parse(row.opaqueRecord);
                } catch {
                    throw new Error('Invalid private-auth record in database');
                }
                const parsed = this.#parseStoredRecord(rawRecord);
                let clientRecord = null;
                try {
                    clientRecord = Buffer.from(JSON.stringify({
                        envelope: Buffer.from(parsed.envelope).toString('base64'),
                        salt: Buffer.from(parsed.salt).toString('base64')
                    }), 'utf8');
                    if (clientRecord.length + 4 > OPAQUE_CONFIG.OT_RECORD_PADDED_BYTES) {
                        throw new Error('OPAQUE record exceeds padded transfer size');
                    }
                    const offset = slot * OPAQUE_CONFIG.OT_RECORD_PADDED_BYTES;
                    paddedView.setUint32(offset, clientRecord.length, false);
                    paddedRecordSlab.set(clientRecord, offset + 4);
                } finally {
                    clientRecord?.fill(0);
                    parsed.envelope.fill(0);
                    parsed.authPublicKey.fill(0);
                    parsed.salt.fill(0);
                }
            }

            const encryption = encryptPrivateAuthOtRecords(publicKeySlab, paddedRecordSlab, signal);
            publicKeySlab = null;
            paddedRecordSlab = null;
            ({ ciphertexts, maskedRecords } = await encryption);

            const encrypted = new Array(anonymitySetSize);
            for (let slot = 0; slot < anonymitySetSize; slot += 1) {
                const ciphertextOffset = slot * ML_KEM_CIPHERTEXT_BYTES;
                const recordOffset = slot * OPAQUE_CONFIG.OT_RECORD_PADDED_BYTES;
                encrypted[slot] = {
                    ct: Buffer.from(ciphertexts.buffer, ciphertextOffset, ML_KEM_CIPHERTEXT_BYTES).toString('base64'),
                    masked: Buffer.from(
                        maskedRecords.buffer,
                        recordOffset,
                        OPAQUE_CONFIG.OT_RECORD_PADDED_BYTES
                    ).toString('base64')
                };
            }
            return encrypted;
        } finally {
            publicKeySlab?.fill(0);
            paddedRecordSlab?.fill(0);
            ciphertexts?.fill(0);
            maskedRecords?.fill(0);
        }
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
        return {
            blindedElement: decodeCanonicalBase64(data?.blindedElement, OPAQUE_ELEMENT_BYTES),
        };
    },

    /**
     * Format response for client
     */
    formatResponse(response) {
        const formatted = {};
        for (const [key, value] of Object.entries(response)) {
            if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
                const copy = Buffer.from(value);
                try {
                    formatted[key] = copy.toString('base64');
                } finally {
                    copy.fill(0);
                }
            } else {
                formatted[key] = value;
            }
        }
        return formatted;
    },
};

export { OPAQUE_CONFIG, LABELS };
