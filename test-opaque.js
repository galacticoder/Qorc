import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';
import crypto from 'crypto';

const OPAQUE_LABELS = {
    OPRF_INPUT: 'OPAQUE-OPRF-Input-v1',
    ENVELOPE_KEY: 'OPAQUE-Envelope-Key-v1',
    MASKED_RESPONSE: 'OPAQUE-MaskedResponse-v1',
    SESSION_KEY: 'OPAQUE-Session-Key-v1',
    AUTH_KEY: 'OPAQUE-Auth-Key-v1'
};

const textEncoder = new TextEncoder();

// SERVER init
const passwordBytes = new TextEncoder().encode('changeme');
const oprfInput = hkdf(blake3, passwordBytes, new Uint8Array(0), textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT), 32);

const serverKeys = oprf.oprf.generateKeyPair();
const blindResult = oprf.oprf.blind(oprfInput);
const evaluated = oprf.oprf.blindEvaluate(serverKeys.secretKey, blindResult.blinded);

const serverPublicKey = blake3(randomBytes(32), { dkLen: 32 });
const serverNonceInit = randomBytes(32);
const serverPrivateKey = randomBytes(32);

const oprfOutputInit = oprf.oprf.finalize(oprfInput, blindResult.blind, evaluated);
const envelopeKeyInit = hkdf(blake3, oprfOutputInit, serverNonceInit, textEncoder.encode(OPAQUE_LABELS.ENVELOPE_KEY), 32);

const clientSecretKeyInit = randomBytes(32);
const envelopeContents = new Uint8Array([...clientSecretKeyInit, ...serverPublicKey]);
const envelopeNonce = randomBytes(24);
const cipherInit = xchacha20poly1305(envelopeKeyInit, envelopeNonce);
const encryptedEnvelope = cipherInit.encrypt(envelopeContents);
const envelope = new Uint8Array([...envelopeNonce, ...encryptedEnvelope]);

const maskedKeyInit = hkdf(blake3, clientSecretKeyInit, serverPublicKey, textEncoder.encode(OPAQUE_LABELS.MASKED_RESPONSE), 32);
const maskedResponse = blake3(maskedKeyInit, { dkLen: 64 });

const sharedRecord = {
    envelope,
    maskedResponse,
    serverPrivateKey,
    serverPublicKey,
    oprfSecretKey: serverKeys.secretKey,
    salt: serverNonceInit,
};

// CLIENT wrong password
const wrongPw = new TextEncoder().encode('wrong');
const oprfInput1 = hkdf(blake3, wrongPw, new Uint8Array(0), textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT), 32);
const blind1 = oprf.oprf.blind(oprfInput1);

// SERVER evaluate 1
const eval1 = oprf.oprf.blindEvaluate(sharedRecord.oprfSecretKey, blind1.blinded);
const serverNonce1 = randomBytes(32);

// CLIENT finish 1
let success1 = true;
try {
    const oprfOut1 = oprf.oprf.finalize(oprfInput1, blind1.blind, eval1);
    const envKey1 = hkdf(blake3, oprfOut1, sharedRecord.salt, textEncoder.encode(OPAQUE_LABELS.ENVELOPE_KEY), 32);
    const cipher1 = xchacha20poly1305(envKey1, envelopeNonce);
    cipher1.decrypt(encryptedEnvelope);
} catch (e) {
    success1 = false;
    console.log("Attempt 1 failed as expected");
}

// CLIENT right password
const rightPw = new TextEncoder().encode('changeme');
const oprfInput2 = hkdf(blake3, rightPw, new Uint8Array(0), textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT), 32);
const blind2 = oprf.oprf.blind(oprfInput2);

// SERVER evaluate 2
const eval2 = oprf.oprf.blindEvaluate(sharedRecord.oprfSecretKey, blind2.blinded);
const serverNonce2 = randomBytes(32);

// CLIENT finish 2
let success2 = true;
try {
    const oprfOut2 = oprf.oprf.finalize(oprfInput2, blind2.blind, eval2);
    const envKey2 = hkdf(blake3, oprfOut2, sharedRecord.salt, textEncoder.encode(OPAQUE_LABELS.ENVELOPE_KEY), 32);
    const cipher2 = xchacha20poly1305(envKey2, envelopeNonce);
    cipher2.decrypt(encryptedEnvelope);
    console.log("Attempt 2 succeeded!");
} catch (e) {
    success2 = false;
    console.log("Attempt 2 failed!", e.message);
}

