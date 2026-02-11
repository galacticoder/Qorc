/**
 * Server Gatekeeper
 * 
 * Manages access to the server instance using Privacy Pass tokens
 */

import { OPAQUEServer, OPAQUEHelpers, OPAQUE_CONFIG, LABELS } from '../crypto/opaque-service.js';
import { PrivacyPassServer, PrivacyPassHelpers } from './privacy-pass-server.js';
import { SignalType } from '../signals.js';
import { sendSecureMessage } from '../messaging/pq-envelope-handler.js';
import * as ServerConfig from '../config/config.js';
import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

export class ServerGatekeeper {
    static #sharedRecord = null;
    static #initializationPromise = null;

    constructor(db) {
        this.db = db;
        this.opaqueServer = OPAQUEServer;
        this.ppServer = PrivacyPassServer;
    }

    /**
     * Initialize shared server OPAQUE record if not already initialized
     */
    async #ensureInitialized() {
        if (ServerGatekeeper.#sharedRecord) return;

        if (ServerGatekeeper.#initializationPromise) {
            await ServerGatekeeper.#initializationPromise;
            return;
        }

        ServerGatekeeper.#initializationPromise = (async () => {
            if (ServerGatekeeper.#sharedRecord) return;

            let secret = process.env.SERVER_PASSWORD;

            if (!secret) {
                secret = ServerConfig.getServerPasswordHash();
            }

            if (!secret) {
                console.warn('[GATEKEEPER] Server password not configured. Gatekeeper disabled.');
                return;
            }

            console.log('[GATEKEEPER] Initializing shared OPAQUE record for server password');

            // Perform full self registration for the server password
            const passwordBytes = new TextEncoder().encode(secret);
            const oprfInput = hkdf(blake3, passwordBytes, new Uint8Array(0), new TextEncoder().encode('OPAQUE-OPRF-Input-v1'), 32);

            // OPRF Evaluation (Self)
            const blindResult = oprf.oprf.blind(oprfInput);
            const evaluation = await this.opaqueServer.createRegistrationResponse(blindResult.blinded, new Uint8Array(32));

            // Envelope Creation (Simulating Client)
            const oprfOutput = oprf.oprf.finalize(oprfInput, blindResult.blind, evaluation.evaluatedElement);
            const envelopeKey = hkdf(blake3, oprfOutput, evaluation.serverNonce, new TextEncoder().encode(LABELS.ENVELOPE_KEY), 32);

            const clientSecretKey = randomBytes(32);
            
            const envelopeContents = new Uint8Array([...clientSecretKey, ...evaluation.serverPublicKey]);
            const envelopeNonce = randomBytes(OPAQUE_CONFIG.ENVELOPE_NONCE_SIZE);
            const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
            const encryptedEnvelope = cipher.encrypt(envelopeContents);
            const envelope = new Uint8Array([...envelopeNonce, ...encryptedEnvelope]);

            // Masked Response (Simulating Client)
            const maskedKey = hkdf(blake3, clientSecretKey, evaluation.serverPublicKey, new TextEncoder().encode('OPAQUE-MaskedResponse-v1'), 32);
            const maskedResponse = blake3(maskedKey, { dkLen: 64 });

            // Create Final Record
            ServerGatekeeper.#sharedRecord = {
                envelope,
                maskedResponse,
                serverPrivateKey: evaluation.serverPrivateKey,
                serverPublicKey: evaluation.serverPublicKey,
                clientSecretKey,
                salt: evaluation.serverNonce,
                initialized: true
            };

            console.log('[GATEKEEPER] Shared OPAQUE record initialized successfully');
        })();

        try {
            await ServerGatekeeper.#initializationPromise;
        } finally {
            ServerGatekeeper.#initializationPromise = null;
        }
    }

    /**
     * Step 1: Client requests server entry evaluation
     */
    async handleEntryRequest(ws, blindedElement) {
        if (!blindedElement) {
            throw new Error('Missing blinded element');
        }

        await this.#ensureInitialized();
        if (!ServerGatekeeper.#sharedRecord) {
            return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Server entry disabled' });
        }

        console.log('[GATEKEEPER] Executing VOPRF evaluation for entry request');

        // Login Response using shared record
        const loginResponse = await this.opaqueServer.createLoginResponse(
            Buffer.from(blindedElement, 'base64'),
            ServerGatekeeper.#sharedRecord
        );

        // Store handshake state per session
        ws._gatekeeperNonce = loginResponse.serverNonce;

        await sendSecureMessage(ws, {
            type: SignalType.SERVER_ENTRY_CHALLENGE,
            ...OPAQUEHelpers.formatResponse({
                evaluatedElement: loginResponse.evaluatedElement,
                envelope: loginResponse.envelope,
                maskedResponse: loginResponse.maskedResponse,
                serverNonce: loginResponse.serverNonce,
                salt: loginResponse.salt
            })
        });
    }

    /**
     * Step 2: Issue tokens after password proof
     */
    async handleTokenIssuance(ws, blindedTokens, proofOfKnowledge) {
        if (!ws._gatekeeperNonce || !ServerGatekeeper.#sharedRecord) {
            console.error('[GATEKEEPER] Issuance failed: Handshake state missing');
            return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Entry handshake expired' });
        }

        console.log('[GATEKEEPER] Verifying entry proof of knowledge...');

        // Finish login
        const loginResult = await this.opaqueServer.finishLogin(
            Buffer.from(proofOfKnowledge, 'base64'),
            ServerGatekeeper.#sharedRecord,
            ws._gatekeeperNonce
        );

        if (!loginResult.success) {
            console.warn('[GATEKEEPER] Invalid entry password proof received');
            return await sendSecureMessage(ws, { type: SignalType.AUTH_ERROR, message: 'Invalid server password' });
        }

        console.log(`[GATEKEEPER] Proof verified. Issuing ${blindedTokens.length} anonymous tokens.`);

        // Issue Privacy Pass tokens
        const tokenBatch = await this.ppServer.issueTokenBatch(
            blindedTokens.map(t => Buffer.from(t, 'base64')),
            ws._gatekeeperNonce
        );

        delete ws._gatekeeperNonce;
        await sendSecureMessage(ws, {
            type: SignalType.SERVER_ENTRY_TOKEN_ISSUANCE,
            ...PrivacyPassHelpers.formatResponse(tokenBatch)
        });
    }

    /**
     * Verify entry token
     */
    async verifyEntryToken(tokenData) {
        const { token, nullifier, mac } = PrivacyPassHelpers.parseRedemptionRequest(tokenData);
        const result = await this.ppServer.redeemToken(token, nullifier, mac);
        return result.valid;
    }

    /**
     * Explicitly initialize the gatekeeper shared record if plaintext is available
     */
    static async initializeExplicit(plaintextPassword) {
        if (!plaintextPassword || this.#sharedRecord) return;

        console.log('[GATEKEEPER] performing explicit initialization with plaintext...');

        this.#initializationPromise = (async () => {
            console.log('[GATEKEEPER] Initializing shared OPAQUE record with provided password...');

            const passwordBytes = new TextEncoder().encode(plaintextPassword);
            const oprfInput = hkdf(blake3, passwordBytes, new Uint8Array(0), new TextEncoder().encode('OPAQUE-OPRF-Input-v1'), 32);

            // OPRF Evaluation (Self)
            const oprfKeys = oprf.oprf.generateKeyPair();
            const blindResult = oprf.oprf.blind(oprfInput);
            const evaluated = oprf.oprf.blindEvaluate(oprfKeys.secretKey, blindResult.blinded);

            // Envelope Creation (Simulating Client)
            const evaluation = { evaluatedElement: evaluated, serverPublicKey: blake3(randomBytes(32), { dkLen: 32 }), serverNonce: randomBytes(32), serverPrivateKey: randomBytes(32) };

            // Regenerating internal registration response shape
            const sSeed = randomBytes(32);
            evaluation.serverPrivateKey = sSeed;
            evaluation.serverPublicKey = blake3(sSeed, { dkLen: 32 });

            const oprfOutput = oprf.oprf.finalize(oprfInput, blindResult.blind, evaluation.evaluatedElement);
            const envelopeKey = hkdf(blake3, oprfOutput, evaluation.serverNonce, new TextEncoder().encode(LABELS.ENVELOPE_KEY), 32);

            const clientSecretKey = randomBytes(32);

            const envelopeContents = new Uint8Array([...clientSecretKey, ...evaluation.serverPublicKey]);
            const envelopeNonce = randomBytes(OPAQUE_CONFIG.ENVELOPE_NONCE_SIZE);
            const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
            const encryptedEnvelope = cipher.encrypt(envelopeContents);
            const envelope = new Uint8Array([...envelopeNonce, ...encryptedEnvelope]);

            const maskedKey = hkdf(blake3, clientSecretKey, evaluation.serverPublicKey, new TextEncoder().encode('OPAQUE-MaskedResponse-v1'), 32);
            const maskedResponse = blake3(maskedKey, { dkLen: 64 });

            ServerGatekeeper.#sharedRecord = {
                envelope,
                maskedResponse,
                serverPrivateKey: evaluation.serverPrivateKey,
                serverPublicKey: evaluation.serverPublicKey,
                oprfSecretKey: oprfKeys.secretKey,
                clientSecretKey,
                salt: evaluation.serverNonce,
                initialized: true
            };

            console.log('[GATEKEEPER] Shared OPAQUE record initialized successfully with plaintext');
        })();

        return this.#initializationPromise;
    }
}
