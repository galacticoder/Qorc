/**
 * Server Gatekeeper
 * 
 * Manages access to the server instance using Privacy Pass tokens
 */

import { OPAQUEServer, OPAQUEHelpers, LABELS } from '../crypto/opaque-service.js';
import { PrivacyPassServer, PrivacyPassHelpers } from './privacy-pass-server.js';
import { SignalType } from '../signals.js';
import {
    consumeVerifiedAuthChannelBinding,
    sendSecureMessage,
} from '../messaging/pq-envelope-handler.js';
import {
  applyAdaptiveAuthDelay,
  recordAuthFailure,
  getAuthPreflightDifficulty,
  getAuthVerificationDifficulty,
  recordAuthPreflightCompletion,
  createPowChallenge,
  verifyPowSolution,
  acquireExpensiveAuthVerificationSlot,
} from '../security/auth-throttle.js';
import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import argon2 from 'argon2';
import {
    decodeCanonicalBase64,
    decodeCanonicalBase64List,
    UTF8_ENCODER
} from '../utils/encoding.js';
import { hasExactPlainObjectKeys, requireUuidV4 } from '../utils/validation.js';
import {
    wipeByteArrays,
    wipeBytes,
    wipeIssuedTokenBatch
} from '../utils/wipe.js';
import {
    SERVER_ENTRY_PURPOSE
} from '../config/audiences.js';
import {
    AUTH_SERVER_BUSY,
    AUTH_SERVICE_BUSY_MESSAGE,
    AUTH_SERVICE_UNAVAILABLE_MESSAGE,
    INVALID_REQUEST,
    INVALID_TOKEN_BATCH_MESSAGE,
    POW_REQUIRED,
    PROOF_OF_WORK_REQUIRED_MESSAGE
} from '../config/error-codes.js';
import {
  ML_DSA_87_SIGNATURE_BYTES,
  HASH_OUTPUT_BYTES,
  OPAQUE_ELEMENT_BYTES,
  OPAQUE_SALT_BYTES,
  PRIVACY_PASS_BLINDED_TOKEN_BYTES,
  XCHACHA20_NONCE_BYTES,
} from '../../shared/crypto-sizes.js';
import { PROTOCOL_KEYS } from '../config/protocol-keys.js';
import {
    AccountAuthRefreshDecision,
    clearAccountAuthRefreshState,
    completeAccountAuthRefresh,
    hasLiveAccountAuthRefreshAuthorization,
    releaseFailedAccountAuthRefresh,
    reserveAccountAuthRefresh
} from './account-auth-refresh-state.js';
import { AUTH_CHANNEL_BINDING_BYTES } from '../../shared/auth-channel-binding.js';

const GATEKEEPER_CHALLENGE_TTL_MS = 2 * 60_000;
const GATEKEEPER_PREFLIGHT_TTL_MS = 60_000;
const GATEKEEPER_KDF_SALT = blake3(
    UTF8_ENCODER.encode(PROTOCOL_KEYS.GATEKEEPER_KDF),
    { dkLen: HASH_OUTPUT_BYTES }
);

async function deriveGatekeeperSecret(secret) {
    const passwordBytes = UTF8_ENCODER.encode(secret);
    const passwordBuffer = Buffer.from(passwordBytes);
    const saltBuffer = Buffer.from(GATEKEEPER_KDF_SALT);
    try {
        return new Uint8Array(await argon2.hash(passwordBuffer, {
            type: argon2.argon2id,
            memoryCost: 64 * 1024,
            timeCost: 3,
            parallelism: 1,
            hashLength: HASH_OUTPUT_BYTES,
            raw: true,
            salt: saltBuffer,
            version: 0x13
        }));
    } finally {
        passwordBytes.fill(0);
        passwordBuffer.fill(0);
        saltBuffer.fill(0);
    }
}

export class ServerGatekeeper {
    static #sharedRecord = null;
    static #passwordOperationTail = Promise.resolve();
    static #lifecycleGeneration = 0;
    static #serverEntryAuthorizationGeneration = 0;

    constructor() {
        this.opaqueServer = OPAQUEServer;
        this.ppServer = PrivacyPassServer;
    }

    static clearConnectionState(ws) {
        wipeBytes(ws?._gatekeeperNonce);
        if (!ws) return;
        delete ws._gatekeeperNonce;
        delete ws._gatekeeperNonceAt;
        delete ws._gatekeeperRequestId;
        wipeBytes(ws._gatekeeperAuthChannelBinding);
        delete ws._gatekeeperAuthChannelBinding;
        ws._gatekeeperPreflight = null;
        ws._entryPowSeed = null;
        ws._entryPowDifficulty = 0;
        clearAccountAuthRefreshState(ws);
    }

    static async destroy() {
        this.#lifecycleGeneration += 1;
        this.#serverEntryAuthorizationGeneration += 1;
        const initialization = this.#passwordOperationTail;
        await initialization?.catch(() => { });
        const record = this.#sharedRecord;
        this.#wipeRecord(record);
        this.#sharedRecord = null;
        this.#passwordOperationTail = Promise.resolve();
    }

    static getServerEntryAuthorizationGeneration() {
        return this.#serverEntryAuthorizationGeneration;
    }

    static isServerEntryAuthorizationGenerationCurrent(generation) {
        return Number.isSafeInteger(generation) &&
            generation === this.#serverEntryAuthorizationGeneration;
    }

    static #wipeRecord(record) {
        wipeBytes(record?.envelope);
        wipeBytes(record?.authPublicKey);
        wipeBytes(record?.oprfSecretKey);
        wipeBytes(record?.salt);
    }

    /**
     * Client request entry evaluation
     */
    async handleEntryRequest(ws, data) {
        let requestId;
        let blindedElementBytes = null;
        let loginResponse = null;
        let challengeDelivered = false;
        let authChannelBinding = null;
        try {
            try {
                requestId = requireUuidV4(data?.requestId, 'server-entry request identifier');
            } catch {
                return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Invalid server entry request', code: INVALID_REQUEST });
            }
            const requestKeys = Object.hasOwn(data, 'preflightPowSolution')
                ? ['authChannelBinding', 'blindedElement', 'preflightPowSolution', 'requestId', 'type']
                : ['authChannelBinding', 'blindedElement', 'requestId', 'type'];
            if (!hasExactPlainObjectKeys(data, requestKeys)) {
                ws._gatekeeperPreflight = null;
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Invalid server entry request',
                    code: INVALID_REQUEST
                });
            }
            blindedElementBytes = decodeCanonicalBase64(data?.blindedElement, OPAQUE_ELEMENT_BYTES);

            if (!ServerGatekeeper.#sharedRecord) {
                return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: 'Server entry unavailable', code: 'SERVER_ENTRY_UNAVAILABLE' });
            }

            if (ws._gatekeeperNonce) {
                wipeBytes(ws._gatekeeperNonce);
                delete ws._gatekeeperNonce;
                delete ws._gatekeeperNonceAt;
                delete ws._gatekeeperRequestId;
                wipeBytes(ws._gatekeeperAuthChannelBinding);
                delete ws._gatekeeperAuthChannelBinding;
                ws._entryPowSeed = null;
                ws._entryPowDifficulty = 0;
            }

            const commitment = Buffer.from(blake3(Buffer.concat([
                Buffer.from(PROTOCOL_KEYS.GATEKEEPER_PREFLIGHT),
                blindedElementBytes
            ]), { dkLen: HASH_OUTPUT_BYTES })).toString('base64');
            const pendingPreflight = ws._gatekeeperPreflight;
            const preflightAgeMs = Date.now() - Number(pendingPreflight?.createdAt);
            const pendingPreflightIsLive = Number.isSafeInteger(preflightAgeMs) &&
                preflightAgeMs >= 0 &&
                preflightAgeMs <= GATEKEEPER_PREFLIGHT_TTL_MS;
            if (pendingPreflightIsLive && pendingPreflight?.requestId !== requestId) {
                ws._gatekeeperPreflight = null;
            }
            ws._gatekeeperPreflight = null;
            const preflightValid = Boolean(
                pendingPreflight?.requestId === requestId &&
                pendingPreflight?.commitment === commitment &&
                pendingPreflightIsLive &&
                verifyPowSolution(
                    pendingPreflight.seed,
                    pendingPreflight.difficulty,
                    data?.preflightPowSolution
                )
            );
            if (!preflightValid) {
                const preflightChallenge = createPowChallenge(await getAuthPreflightDifficulty());
                ws._gatekeeperPreflight = {
                    requestId,
                    commitment,
                    seed: preflightChallenge.seed,
                    difficulty: preflightChallenge.difficulty,
                    createdAt: Date.now()
                };
                return await sendSecureMessage(ws, {
                    type: SignalType.SERVER_ENTRY_CHALLENGE,
                    requestId,
                    preflightRequired: true,
                    powChallenge: preflightChallenge
                });
            }
            await recordAuthPreflightCompletion();
            authChannelBinding = consumeVerifiedAuthChannelBinding(data);
            if (!authChannelBinding) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Invalid server entry request',
                    code: INVALID_REQUEST
                });
            }

            loginResponse = await this.opaqueServer.createGatekeeperLoginResponse(
                blindedElementBytes,
                ServerGatekeeper.#sharedRecord
            );

            ws._gatekeeperNonce = loginResponse.serverNonce;
            ws._gatekeeperNonceAt = Date.now();
            ws._gatekeeperRequestId = requestId;
            ws._gatekeeperAuthChannelBinding = authChannelBinding;
            authChannelBinding = null;

            const powChallenge = createPowChallenge(await getAuthVerificationDifficulty());
            ws._entryPowSeed = powChallenge.seed;
            ws._entryPowDifficulty = powChallenge.difficulty;

            const delivered = await sendSecureMessage(ws, {
                type: SignalType.SERVER_ENTRY_CHALLENGE,
                requestId,
                powChallenge,
                ...OPAQUEHelpers.formatResponse({
                    evaluatedElement: loginResponse.evaluatedElement,
                    envelope: loginResponse.envelope,
                    serverNonce: loginResponse.serverNonce,
                    salt: loginResponse.salt
                })
            });
            if (delivered === false) {
                throw new Error('Server-entry challenge was not delivered');
            }
            challengeDelivered = true;
        } finally {
            wipeBytes(blindedElementBytes);
            wipeBytes(loginResponse?.evaluatedElement);
            wipeBytes(loginResponse?.envelope);
            wipeBytes(loginResponse?.salt);
            if (
                loginResponse?.serverNonce &&
                !challengeDelivered &&
                ws._gatekeeperNonce === loginResponse.serverNonce
            ) {
                wipeBytes(ws._gatekeeperNonce);
                delete ws._gatekeeperNonce;
                delete ws._gatekeeperNonceAt;
                delete ws._gatekeeperRequestId;
                wipeBytes(ws._gatekeeperAuthChannelBinding);
                delete ws._gatekeeperAuthChannelBinding;
                ws._entryPowSeed = null;
                ws._entryPowDifficulty = 0;
            }
            wipeBytes(authChannelBinding);
        }
    }

    /**
     * Issue tokens after password proof
     */
    async handleTokenIssuance(ws, data) {
        let requestId;
        let gatekeeperAuthChannelBinding = null;
        try {
            requestId = requireUuidV4(data?.requestId, 'server-entry request identifier');
        } catch {
            return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Invalid server entry request', code: INVALID_REQUEST });
        }
        const { blindedTokens, proofOfKnowledge, powSolution, tokenEpoch } = data;
        if (ws._gatekeeperRequestId !== requestId) {
            return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: 'Server entry state mismatch', code: INVALID_REQUEST });
        }
        const challengeAgeMs = Date.now() - Number(ws._gatekeeperNonceAt || 0);
        if (
            !ws._gatekeeperNonce ||
            !ServerGatekeeper.#sharedRecord ||
            !Number.isSafeInteger(challengeAgeMs) ||
            challengeAgeMs < 0 ||
            challengeAgeMs > GATEKEEPER_CHALLENGE_TTL_MS
        ) {
            wipeBytes(ws._gatekeeperNonce);
            wipeBytes(ws._gatekeeperAuthChannelBinding);
            delete ws._gatekeeperNonce;
            delete ws._gatekeeperNonceAt;
            delete ws._gatekeeperRequestId;
            delete ws._gatekeeperAuthChannelBinding;
            ws._entryPowSeed = null;
            ws._entryPowDifficulty = 0;
            return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: 'Entry handshake expired' });
        }

        const gatekeeperNonce = ws._gatekeeperNonce;
        gatekeeperAuthChannelBinding = ws._gatekeeperAuthChannelBinding;
        delete ws._gatekeeperNonce;
        delete ws._gatekeeperNonceAt;
        delete ws._gatekeeperRequestId;
        delete ws._gatekeeperAuthChannelBinding;
        const powDifficulty = ws._entryPowDifficulty || 0;
        const powSeed = ws._entryPowSeed;
        ws._entryPowSeed = null;
        ws._entryPowDifficulty = 0;

        let proofBytes = null;
        let blindedTokenBytes = [];
        let issuedTokenBatch = null;
        let releaseVerificationSlot = null;
        let issuanceEpoch = null;
        try {
            if (!hasExactPlainObjectKeys(data, [
                'blindedTokens',
                'powSolution',
                'proofOfKnowledge',
                'requestId',
                'tokenEpoch',
                'type'
                ])) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Invalid server entry request',
                    code: INVALID_REQUEST
                });
            }
            if (
                !(gatekeeperAuthChannelBinding instanceof Uint8Array) ||
                gatekeeperAuthChannelBinding.length !== AUTH_CHANNEL_BINDING_BYTES
            ) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Server entry state mismatch',
                    code: INVALID_REQUEST
                });
            }
            try {
                if (!Array.isArray(blindedTokens) || blindedTokens.length !== 1000) {
                    throw new Error(INVALID_TOKEN_BATCH_MESSAGE);
                }
                issuanceEpoch = this.ppServer.validateIssuanceEpoch(tokenEpoch);
            } catch {
                return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: 'Invalid server entry request', code: INVALID_REQUEST });
            }

            if (powDifficulty > 0 && !verifyPowSolution(powSeed, powDifficulty, powSolution)) {
                return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: PROOF_OF_WORK_REQUIRED_MESSAGE, code: POW_REQUIRED });
            }

            try {
                proofBytes = decodeCanonicalBase64(
                    proofOfKnowledge,
                    ML_DSA_87_SIGNATURE_BYTES,
                    6200
                );
                blindedTokenBytes = decodeCanonicalBase64List(
                    blindedTokens,
                    PRIVACY_PASS_BLINDED_TOKEN_BYTES,
                    64
                );
            } catch {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Invalid server entry request',
                    code: INVALID_REQUEST
                });
            }

            await applyAdaptiveAuthDelay(ws._connectionAbortSignal);

            releaseVerificationSlot = await acquireExpensiveAuthVerificationSlot(ws._connectionAbortSignal);
            let loginResult;
            try {
                loginResult = this.opaqueServer.finishLoginWithPublicKey(
                    proofBytes,
                    ServerGatekeeper.#sharedRecord.authPublicKey,
                    gatekeeperNonce,
                    gatekeeperAuthChannelBinding
                );
                if (loginResult.success) {
                    issuedTokenBatch = await this.ppServer.issueTokenBatch(
                        blindedTokenBytes,
                        SERVER_ENTRY_PURPOSE,
                        issuanceEpoch,
                        ws._connectionAbortSignal
                    );
                }
            } finally {
                releaseVerificationSlot?.();
                releaseVerificationSlot = null;
            }
            if (!loginResult.success) {
                try {
                    return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, requestId, message: 'Invalid server password' });
                } finally {
                    try {
                        await recordAuthFailure();
                    } catch {
                        ws.close?.(1013, AUTH_SERVICE_UNAVAILABLE_MESSAGE);
                    }
                }
            }

            const formattedTokenBatch = PrivacyPassHelpers.formatResponse(issuedTokenBatch);
            await sendSecureMessage(ws, {
                type: SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
                requestId,
                ...formattedTokenBatch
            });
        } catch (error) {
            const busy = error?.code === AUTH_SERVER_BUSY;
            return await sendSecureMessage(ws, {
                type: SignalType.AUTH_ERROR,
                requestId,
                message: busy ? AUTH_SERVICE_BUSY_MESSAGE : 'Server entry failed',
                code: busy ? AUTH_SERVER_BUSY : 'SERVER_ENTRY_FAILED'
            });
        } finally {
            releaseVerificationSlot?.();
            wipeIssuedTokenBatch(issuedTokenBatch);
            wipeBytes(proofBytes);
            wipeByteArrays(blindedTokenBytes);
            wipeBytes(gatekeeperNonce);
            wipeBytes(gatekeeperAuthChannelBinding);
        }
    }

    /**
     * Replace account auth token consumed to authorize socket
     */
    async handleAccountAuthTokenRefresh(ws, data) {
        let requestId;
        let blindedTokenBytes = [];
        let issuedTokenBatch = null;
        let refreshCommitment = null;
        try {
            try {
                requestId = requireUuidV4(data?.requestId, 'server-entry request identifier');
            } catch {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    message: 'Invalid account-auth refresh request',
                    code: INVALID_REQUEST
                });
            }

            if (!hasLiveAccountAuthRefreshAuthorization(ws)) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Account authentication required',
                    code: 'ACCOUNT_AUTH_REQUIRED'
                });
            }
            if (!hasExactPlainObjectKeys(data, [
                'blindedTokens',
                'requestId',
                'tokenEpoch',
                'type'
            ])) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Invalid account-auth refresh request',
                    code: INVALID_REQUEST
                });
            }
            let issuanceEpoch;
            try {
                if (!Array.isArray(data.blindedTokens) || data.blindedTokens.length !== 1) {
                    throw new Error(INVALID_TOKEN_BATCH_MESSAGE);
                }
                blindedTokenBytes = decodeCanonicalBase64List(
                    data.blindedTokens,
                    PRIVACY_PASS_BLINDED_TOKEN_BYTES,
                    64
                );
                issuanceEpoch = this.ppServer.validateIssuanceEpoch(data.tokenEpoch);
            } catch {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Invalid account-auth refresh request',
                    code: INVALID_REQUEST
                });
            }

            refreshCommitment = Buffer.from(blake3(
                UTF8_ENCODER.encode(
                    `${PROTOCOL_KEYS.ACCOUNT_AUTH_REFRESH}${issuanceEpoch}\0${data.blindedTokens[0]}`
                ),
                { dkLen: HASH_OUTPUT_BYTES }
            )).toString('base64');
            const refreshReservation = reserveAccountAuthRefresh(ws, refreshCommitment);
            if (refreshReservation.decision === AccountAuthRefreshDecision.CONFLICT) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Account-auth credentials already refreshed',
                    code: 'REFRESH_ALREADY_ISSUED'
                });
            }
            if (refreshReservation.decision === AccountAuthRefreshDecision.IN_PROGRESS) {
                return await sendSecureMessage(ws, {
                    type: SignalType.AUTH_ERROR,
                    requestId,
                    message: 'Account-auth refresh is in progress',
                    code: 'AUTH_IN_PROGRESS'
                });
            }
            if (refreshReservation.decision === AccountAuthRefreshDecision.REPLAY) {
                return await sendSecureMessage(ws, {
                    ...refreshReservation.response,
                    requestId
                });
            }
            issuedTokenBatch = await this.ppServer.issueAccountAuthTokenBatch(
                blindedTokenBytes,
                issuanceEpoch,
                ws._connectionAbortSignal
            );

            const formattedTokenBatch = PrivacyPassHelpers.formatResponse(issuedTokenBatch);
            const response = {
                type: SignalType.ACCOUNT_AUTH_TOKEN_REFRESH_RESPONSE,
                ...formattedTokenBatch
            };
            if (!completeAccountAuthRefresh(ws, refreshCommitment, response)) {
                throw new Error('Account-auth refresh reservation was lost');
            }
            return await sendSecureMessage(ws, {
                ...response,
                requestId,
            });
        } catch (error) {
            if (refreshCommitment) releaseFailedAccountAuthRefresh(ws, refreshCommitment);
            const busy = error?.code === AUTH_SERVER_BUSY;
            return await sendSecureMessage(ws, {
                type: SignalType.AUTH_ERROR,
                ...(requestId ? { requestId } : {}),
                message: busy ? AUTH_SERVICE_BUSY_MESSAGE : 'Account-auth refresh failed',
                code: busy ? AUTH_SERVER_BUSY : 'ACCOUNT_AUTH_REFRESH_FAILED'
            });
        } finally {
            wipeIssuedTokenBatch(issuedTokenBatch);
            wipeByteArrays(blindedTokenBytes);
        }
    }

    /**
     * Verify entry token
     */
    async verifyEntryToken(tokenData) {
        const authorizationGeneration = ServerGatekeeper.#serverEntryAuthorizationGeneration;
        const parsed = PrivacyPassHelpers.parseRedemptionRequest(tokenData);
        try {
            const result = await this.ppServer.redeemToken(
                parsed.token,
                parsed.nullifier,
                parsed.mac,
                parsed.tokenSecret,
                SERVER_ENTRY_PURPOSE
            );
            return {
                valid: result.valid === true &&
                    authorizationGeneration === ServerGatekeeper.#serverEntryAuthorizationGeneration,
                authorizationGeneration
            };
        } finally {
            parsed.token.fill(0);
            parsed.nullifier.fill(0);
            parsed.mac.fill(0);
            parsed.tokenSecret.fill(0);
        }
    }

    /**
     * initialize gatekeeper shared record if plaintext available
     */
    static async #replaceExplicit(plaintextPassword, initializeOnly) {
        const secret = typeof plaintextPassword === 'string' ? plaintextPassword.trim() : '';
        if (secret.length < 12 || secret.length > 512) {
            throw new Error('SERVER_PASSWORD must contain between 12 and 512 characters');
        }

        const generation = this.#lifecycleGeneration;
        const operation = this.#passwordOperationTail.catch(() => { }).then(async () => {
            if (generation !== ServerGatekeeper.#lifecycleGeneration) {
                const error = new Error('Gatekeeper password operation cancelled');
                error.code = 'GATEKEEPER_PASSWORD_OPERATION_CANCELLED';
                throw error;
            }
            if (initializeOnly && ServerGatekeeper.#sharedRecord) return false;

            let passwordBytes = null;
            let oprfInput = null;
            let oprfKeys = null;
            let blindResult = null;
            let evaluated = null;
            let registrationSalt = null;
            let oprfOutput = null;
            let envelopeKey = null;
            let authSeed = null;
            let authKeyPair = null;
            let authPublicKey = null;
            let envelopeNonce = null;
            let encryptedEnvelope = null;
            let envelope = null;
            let candidateRecord = null;
            try {
                passwordBytes = await deriveGatekeeperSecret(secret);
                if (generation !== ServerGatekeeper.#lifecycleGeneration) {
                    const error = new Error('Gatekeeper password operation cancelled');
                    error.code = 'GATEKEEPER_PASSWORD_OPERATION_CANCELLED';
                    throw error;
                }
                oprfInput = hkdf(
                    blake3,
                    passwordBytes,
                    new Uint8Array(0),
                    UTF8_ENCODER.encode(LABELS.OPRF_INPUT),
                    HASH_OUTPUT_BYTES
                );

                oprfKeys = oprf.oprf.generateKeyPair();
                blindResult = oprf.oprf.blind(oprfInput);
                evaluated = oprf.oprf.blindEvaluate(oprfKeys.secretKey, blindResult.blinded);
                registrationSalt = randomBytes(OPAQUE_SALT_BYTES);
                oprfOutput = oprf.oprf.finalize(oprfInput, blindResult.blind, evaluated);
                envelopeKey = hkdf(
                    blake3,
                    oprfOutput,
                    registrationSalt,
                    UTF8_ENCODER.encode(LABELS.ENVELOPE_KEY),
                    HASH_OUTPUT_BYTES
                );
                authSeed = randomBytes(HASH_OUTPUT_BYTES);
                authKeyPair = ml_dsa87.keygen(authSeed);
                authPublicKey = new Uint8Array(authKeyPair.publicKey);

                envelopeNonce = randomBytes(XCHACHA20_NONCE_BYTES);
                const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
                encryptedEnvelope = cipher.encrypt(authSeed);
                envelope = new Uint8Array(envelopeNonce.length + encryptedEnvelope.length);
                envelope.set(envelopeNonce, 0);
                envelope.set(encryptedEnvelope, envelopeNonce.length);

                candidateRecord = {
                    envelope: new Uint8Array(envelope),
                    authPublicKey: new Uint8Array(authPublicKey),
                    oprfSecretKey: new Uint8Array(oprfKeys.secretKey),
                    salt: new Uint8Array(registrationSalt)
                };

                const issuerChanged = PrivacyPassServer.configureServerEntryPasswordSecret(passwordBytes);
                if (!issuerChanged && ServerGatekeeper.#sharedRecord) {
                    return false;
                }

                const previousRecord = ServerGatekeeper.#sharedRecord;
                ServerGatekeeper.#sharedRecord = candidateRecord;
                candidateRecord = null;
                ServerGatekeeper.#wipeRecord(previousRecord);
                ServerGatekeeper.#serverEntryAuthorizationGeneration += 1;
                return true;
            } finally {
                ServerGatekeeper.#wipeRecord(candidateRecord);
                wipeBytes(passwordBytes);
                wipeBytes(oprfInput);
                wipeBytes(oprfKeys?.secretKey);
                wipeBytes(blindResult?.blind);
                wipeBytes(blindResult?.blinded);
                wipeBytes(evaluated);
                wipeBytes(registrationSalt);
                wipeBytes(oprfOutput);
                wipeBytes(envelopeKey);
                wipeBytes(authSeed);
                wipeBytes(authKeyPair?.publicKey);
                wipeBytes(authKeyPair?.secretKey);
                wipeBytes(authPublicKey);
                wipeBytes(envelopeNonce);
                wipeBytes(encryptedEnvelope);
                wipeBytes(envelope);
            }
        });
        this.#passwordOperationTail = operation.then(() => undefined, () => undefined);
        return operation;
    }

    static async initializeExplicit(plaintextPassword) {
        return this.#replaceExplicit(plaintextPassword, true);
    }

    static async rotateExplicit(plaintextPassword) {
        return this.#replaceExplicit(plaintextPassword, false);
    }
}
