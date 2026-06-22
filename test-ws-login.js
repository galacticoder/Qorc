import WebSocket from 'ws';
import { ristretto255_oprf as oprf } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf';
import { blake3 } from '@noble/hashes/blake3';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

const LABELS = {
    OPRF_INPUT: 'OPAQUE-OPRF-Input-v1',
    ENVELOPE_KEY: 'OPAQUE-Envelope-Key-v1',
    MASKED_RESPONSE: 'OPAQUE-MaskedResponse-v1',
    SESSION_KEY: 'OPAQUE-Session-Key-v1',
    AUTH_KEY: 'OPAQUE-Auth-Key-v1',
};
const textEncoder = new TextEncoder();

const ws = new WebSocket('ws://localhost:3000', {
    rejectUnauthorized: false
});

let password = 'someonesomeone';
let blindingFactor = null;

function startLogin(pw) {
    const pwBytes = textEncoder.encode(pw);
    const clientOprfInput = hkdf(blake3, pwBytes, new Uint8Array(0), textEncoder.encode(LABELS.OPRF_INPUT), 32);
    const clientBlindResult = oprf.oprf.blind(clientOprfInput);
    blindingFactor = clientBlindResult.blind;
    return clientBlindResult.blinded;
}

function finishLogin(pw, blindingFactor, serverResponse) {
    const pwBytes = textEncoder.encode(pw);
    const clientOprfInput = hkdf(blake3, pwBytes, new Uint8Array(0), textEncoder.encode(LABELS.OPRF_INPUT), 32);
    const clientOprfOutput = oprf.oprf.finalize(clientOprfInput, blindingFactor, serverResponse.evaluatedElement);

    const salt = serverResponse.salt || serverResponse.serverNonce;
    const clientEnvelopeKey = hkdf(blake3, clientOprfOutput, salt, textEncoder.encode(LABELS.ENVELOPE_KEY), 32);

    const clientEnvelopeNonce = serverResponse.envelope.slice(0, 24);
    const clientEncryptedEnvelope = serverResponse.envelope.slice(24);

    const clientCipher = xchacha20poly1305(clientEnvelopeKey, clientEnvelopeNonce);
    const clientEnvelopeContents = clientCipher.decrypt(clientEncryptedEnvelope);

    const recoveredClientSecretKey = clientEnvelopeContents.slice(0, 32);
    const recoveredServerPublicKey = clientEnvelopeContents.slice(32, 64);

    const recoveredMaskedKey = hkdf(blake3, recoveredClientSecretKey, recoveredServerPublicKey, textEncoder.encode(LABELS.MASKED_RESPONSE), 32);
    const recoveredMaskedResponse = blake3(recoveredMaskedKey, { dkLen: 64 });

    const authKey = hkdf(blake3, recoveredMaskedResponse, serverResponse.serverNonce, textEncoder.encode(LABELS.AUTH_KEY), 32);
    const authMessage = blake3(authKey, { dkLen: 32 });

    return { success: true, authMessage };
}

ws.on('open', () => {
    console.log('Connected to server');

    const blindedElement = startLogin(password);

    ws.send(JSON.stringify({
        type: 'server-entry-request',
        blindedElement: Buffer.from(blindedElement).toString('base64')
    }));
});

ws.on('message', (data) => {
    const msg = JSON.parse(data);
    console.log('Received:', msg.type);

    if (msg.type === 'server-entry-challenge') {
        const serverResp = {
            evaluatedElement: Buffer.from(msg.evaluatedElement, 'base64'),
            serverNonce: Buffer.from(msg.serverNonce, 'base64'),
            envelope: Buffer.from(msg.envelope, 'base64'),
            maskedResponse: Buffer.from(msg.maskedResponse, 'base64'),
            salt: msg.salt ? Buffer.from(msg.salt, 'base64') : undefined,
        };

        try {
            const result = finishLogin(password, blindingFactor, serverResp);
            console.log('Finish login SUCCESS');

            ws.send(JSON.stringify({
                type: 'server-entry-token-issuance',
                blindedTokens: [],
                proofOfKnowledge: Buffer.from(result.authMessage).toString('base64')
            }));

        } catch (e) {
            console.error('Finish login FAILED:', e.message);
            ws.close();
        }
    } else if (msg.type === 'privacy-pass-issuance' || msg.type === 'auth-error' || msg.type === 'ok') {
        console.log('Server replied to issuance:', msg);
        ws.close();
    }
});

ws.on('error', (err) => console.error('WS Error:', err));
ws.on('close', () => console.log('WS Closed'));
