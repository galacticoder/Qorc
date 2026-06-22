import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes } from '@noble/hashes/utils.js';

// Mimic crypto-ops.ts OPAQUEOps
const OPAQUE_LABELS = { OPRF_INPUT: 'OPAQUE-OPRF-Input-v1', ENVELOPE_KEY: 'OPAQUE-Envelope-Key-v1', MASKED_RESPONSE: 'OPAQUE-MaskedResponse-v1', SESSION_KEY: 'OPAQUE-Session-Key-v1', AUTH_KEY: 'OPAQUE-Auth-Key-v1' };
const textEncoder = new TextEncoder();

const OPAQUEOps = {
    startLogin(password) {
        const oprfInput = hkdf(blake3, password, new Uint8Array(0), textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT), 32);
        const blindResult = oprf.oprf.blind(oprfInput);
        return { blindedElement: blindResult.blinded, blindingFactor: blindResult.blind };
    },
    finishLogin(password, blindingFactor, serverResponse) {
        const oprfInput = hkdf(blake3, password, new Uint8Array(0), textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT), 32);
        const oprfOutput = oprf.oprf.finalize(oprfInput, blindingFactor, serverResponse.evaluatedElement);
        const salt = serverResponse.salt || serverResponse.serverNonce;
        const envelopeKey = hkdf(blake3, oprfOutput, salt, textEncoder.encode(OPAQUE_LABELS.ENVELOPE_KEY), 32);
        const envelopeNonce = serverResponse.envelope.slice(0, 24);
        const encryptedEnvelope = serverResponse.envelope.slice(24);
        const cipher = xchacha20poly1305(envelopeKey, envelopeNonce);
        const envelopeContents = cipher.decrypt(encryptedEnvelope);
        this.blindingFactor = null;
        return { success: true };
    }
};

// SERVER setup
const serverKeys = oprf.oprf.generateKeyPair();
const serverNonceInit = randomBytes(32);
const serverPrivateKey = randomBytes(32);
const serverPublicKey = blake3(serverPrivateKey, { dkLen: 32 });
const pwBytes = new TextEncoder().encode('changeme');
const oprfInput = hkdf(blake3, pwBytes, new Uint8Array(0), textEncoder.encode(OPAQUE_LABELS.OPRF_INPUT), 32);
const blindResult = oprf.oprf.blind(oprfInput);
const evaluated = oprf.oprf.blindEvaluate(serverKeys.secretKey, blindResult.blinded);
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
const sharedRecord = { envelope, maskedResponse, serverPrivateKey, serverPublicKey, oprfSecretKey: serverKeys.secretKey, salt: serverNonceInit };

// SIMULATE CLIENT
class OPAQUEClient {
    startLogin(password) {
        const result = OPAQUEOps.startLogin(password);
        this.blindingFactor = result.blindingFactor;
        return { blindedElement: result.blindedElement };
    }
    finishLogin(password, serverResponse) {
        try {
            const res = OPAQUEOps.finishLogin(password, this.blindingFactor, serverResponse);
            this.blindingFactor = null;
            return res;
        } catch(e) {
            this.blindingFactor = null;
            return { success: false, error: e.message };
        }
    }
}

const client = new OPAQUEClient();

// wrong password
let wrongPw = new TextEncoder().encode('wrong');
let { blindedElement: b1 } = client.startLogin(wrongPw);
let eval1 = oprf.oprf.blindEvaluate(sharedRecord.oprfSecretKey, b1);
let resp1 = { evaluatedElement: eval1, serverNonce: randomBytes(32), envelope: sharedRecord.envelope, maskedResponse: sharedRecord.maskedResponse, salt: sharedRecord.salt };
let proof1 = client.finishLogin(wrongPw, resp1);
console.log("Attempt 1:", proof1);

// right password
let rightPw = new TextEncoder().encode('changeme');
let { blindedElement: b2 } = client.startLogin(rightPw);
let eval2 = oprf.oprf.blindEvaluate(sharedRecord.oprfSecretKey, b2);
let resp2 = { evaluatedElement: eval2, serverNonce: randomBytes(32), envelope: sharedRecord.envelope, maskedResponse: sharedRecord.maskedResponse, salt: sharedRecord.salt };
let proof2 = client.finishLogin(rightPw, resp2);
console.log("Attempt 2:", proof2);

