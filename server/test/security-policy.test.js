import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  REQUIRED_WS_PQ_HANDSHAKE,
  validateFinalSenderIdentity,
  validateLayerAgreement,
  validateP2PServerEquivalence,
  validatePqHandshakePolicy,
  validateRingDeviceProofPolicy,
} from '../security/layer-agreement-policy.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function validHandshake(overrides = {}) {
  return {
    version: REQUIRED_WS_PQ_HANDSHAKE.version,
    algorithms: {
      kem: REQUIRED_WS_PQ_HANDSHAKE.kem,
      signature: REQUIRED_WS_PQ_HANDSHAKE.signature,
      classicalKeyAgreement: REQUIRED_WS_PQ_HANDSHAKE.classicalKeyAgreement,
      kdf: REQUIRED_WS_PQ_HANDSHAKE.kdf,
      aead: REQUIRED_WS_PQ_HANDSHAKE.aead,
    },
    sessionId: 'session',
    timestamp: Date.now(),
    clientNonce: 'nonce',
    kemCiphertext: 'ct',
    clientX25519PublicKey: 'x25519',
    clientSigningPublicKey: 'mldsa',
    fingerprint: 'server-fingerprint',
    ...overrides,
  };
}

test('PQ WebSocket handshake policy rejects downgraded or missing algorithms', () => {
  assert.equal(validatePqHandshakePolicy(validHandshake()).valid, true);
  assert.equal(validatePqHandshakePolicy(validHandshake({
    algorithms: { ...validHandshake().algorithms, kem: 'X25519-only' }
  })).valid, false);
  assert.equal(validatePqHandshakePolicy(validHandshake({
    algorithms: { ...validHandshake().algorithms, signature: 'none' }
  })).valid, false);
  assert.equal(validatePqHandshakePolicy(validHandshake({ clientX25519PublicKey: '' })).valid, false);
});

test('final sender identity has exactly one authority', () => {
  const accepted = validateFinalSenderIdentity({
    expectedSignalSender: 'alice',
    decryptedSignalSender: 'alice',
    outerSenderHint: 'alice',
    observedOuterDilithiumPublicKey: 'device-key',
    expectedDilithiumPublicKey: 'device-key',
  });
  assert.equal(accepted.valid, true);
  assert.equal(accepted.authority, 'signal');
  assert.equal(accepted.outerLayerAuthority, 'transport-capability-only');

  assert.equal(validateFinalSenderIdentity({
    expectedSignalSender: 'alice',
    decryptedSignalSender: 'bob',
    outerSenderHint: 'alice',
  }).valid, false);
  assert.equal(validateFinalSenderIdentity({
    expectedSignalSender: 'alice',
    decryptedSignalSender: 'alice',
    outerSenderHint: 'bob',
  }).valid, false);
});

test('layer disagreement fails closed and quietly', () => {
  const staleEnvelope = validateLayerAgreement({
    outerAccepted: true,
    signalAccepted: true,
    envelopeFresh: false,
    routeFresh: true,
    bundleFresh: true,
    duplicate: false,
  });
  assert.equal(staleEnvelope.valid, false);
  assert.equal(staleEnvelope.plaintextRelease, false);
  assert.equal(staleEnvelope.receiptAllowed, false);
  assert.equal(staleEnvelope.serverVisibleReason, 'generic_delivery_unavailable');

  assert.equal(validateLayerAgreement({
    outerAccepted: true,
    signalAccepted: true,
    envelopeFresh: true,
    routeFresh: true,
    bundleFresh: true,
    duplicate: false,
  }).plaintextRelease, true);
});

test('P2P and server paths must produce equivalent local validation decisions', () => {
  const serverDecision = {
    valid: true,
    finalSender: 'alice',
    signalIdentity: 'signal-fp',
    identityRootFingerprint: 'root-fp',
    plaintextRelease: true,
  };
  assert.equal(validateP2PServerEquivalence(serverDecision, {
    ...serverDecision,
  }).valid, true);
  assert.equal(validateP2PServerEquivalence(serverDecision, {
    ...serverDecision,
    signalIdentity: 'other-fp',
  }).valid, false);
});

test('ring device proof policy requires a large anonymity set and no sender identity authority', () => {
  assert.equal(validateRingDeviceProofPolicy({
    ringSize: 127,
    keyImageSeen: false,
    keyImageValid: true,
    proofVersion: 2,
    createsSenderIdentity: false,
  }).valid, false);

  assert.equal(validateRingDeviceProofPolicy({
    ringSize: 128,
    keyImageSeen: false,
    keyImageValid: true,
    proofVersion: 2,
    createsSenderIdentity: false,
  }).valid, true);

  assert.equal(validateRingDeviceProofPolicy({
    ringSize: 128,
    keyImageSeen: false,
    keyImageValid: true,
    proofVersion: 2,
    createsSenderIdentity: true,
  }).valid, false);
});

test('native Signal decrypt requires PQ envelope and exact algorithm binding', () => {
  const signalSource = fs.readFileSync(path.join(repoRoot, 'src-tauri/src/signal_protocol/mod.rs'), 'utf8');
  assert.equal(signalSource.includes('Post-quantum Signal envelope required'), true);
  assert.equal(signalSource.includes('SignalEncryptedMessage {\\n                message_type: encrypted.message_type'), false);
  assert.equal(signalSource.includes('SIGNAL_PQ_KEM_ALGORITHM'), true);
  assert.equal(signalSource.includes('KYBER_CIPHERTEXT_SIZE'), true);
  assert.equal(signalSource.includes('kem_ciphertext[1..]'), false);
});
